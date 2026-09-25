//! The session's event stream is well ordered and reproducible.
//!
//! Runs natively: the derivation is target independent, so the properties the
//! browser depends on are checked without a wasm toolchain.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_demo::{HostRole, Session, SessionConfig, ShardPath, TraceEvent, TraceKind};
use hyperscale_types::{ShardId, VIEW_CHANGE_TIMEOUT_DEFAULT};

fn config() -> SessionConfig {
    SessionConfig::default()
}

/// Drive a session for `steps` half-second steps, returning every event.
fn run(seed: u64, steps: usize) -> Vec<TraceEvent> {
    let mut session = Session::new(config(), seed);
    (0..steps).flat_map(|_| session.step(500)).collect()
}

#[test]
fn a_session_commits_blocks_and_reports_them_in_weighted_time_order() {
    let events = run(42, 40);

    assert!(
        events.len() > 10,
        "20s of simulated time should commit well past ten blocks, got {}",
        events.len(),
    );

    let stamps: Vec<u64> = events.iter().map(|event| event.wt).collect();
    let mut sorted = stamps.clone();
    sorted.sort_unstable();
    assert_eq!(stamps, sorted, "events must arrive in weighted-time order");

    // Heights are contiguous from the first reported block: the walk reports
    // every committed height exactly once, never skipping or repeating.
    let heights: Vec<u64> = events
        .iter()
        .filter_map(|event| match event.kind {
            TraceKind::BlockCommitted { height, .. } => Some(height),
            _ => None,
        })
        .collect();
    let first = heights[0];
    let expected: Vec<u64> = (first..first + heights.len() as u64).collect();
    assert_eq!(heights, expected, "reported heights must be contiguous");
}

#[test]
fn one_seed_replays_to_the_same_event_stream() {
    let first = run(42, 20);
    let second = run(42, 20);

    let render = |events: &[TraceEvent]| format!("{events:?}");
    assert_eq!(
        render(&first),
        render(&second),
        "a seeded session must replay identically",
    );
}

#[test]
fn a_submitted_transfer_settles_and_reports_every_transition() {
    let mut session = Session::new(config(), 42);
    let mut events = Vec::new();

    // Submit a few transfers early, then let them run to a terminal outcome.
    for _ in 0..3 {
        session.submit_transfer();
        events.extend(session.step(500));
    }
    for _ in 0..60 {
        events.extend(session.step(500));
    }

    let submitted = events
        .iter()
        .filter(|e| matches!(e.kind, TraceKind::TxSubmitted { .. }))
        .count();
    assert_eq!(submitted, 3, "every submission is reported");

    let statuses: Vec<&str> = events
        .iter()
        .filter_map(|e| match &e.kind {
            TraceKind::TxStatusChanged { status, .. } => Some(*status),
            _ => None,
        })
        .collect();

    assert!(
        statuses.contains(&"committed"),
        "a transfer must be ordered into a block, saw {statuses:?}",
    );
    assert!(
        statuses.contains(&"succeeded"),
        "a funded transfer must reach a terminal success, saw {statuses:?}",
    );

    // Every transaction reaches a terminal outcome — nothing is left in
    // flight once the tick deadline has long passed (INV-EXEC-5).
    let terminal = statuses
        .iter()
        .filter(|s| matches!(**s, "succeeded" | "aborted" | "rejected"))
        .count();
    assert_eq!(terminal, 3, "every submission terminates, saw {statuses:?}");

    // A single-shard topology opens no cross-shard ticks: that header field
    // exists to tell remote shards which certificates to expect.
    assert!(
        events.iter().all(|e| !matches!(
            e.kind,
            TraceKind::BlockCommitted {
                cross_shard_ticks: 1..,
                ..
            }
        )),
        "one shard means no cross-shard ticks",
    );
}

#[test]
fn the_root_shard_splits_while_the_session_is_being_watched() {
    let mut session = Session::new(
        SessionConfig {
            max_shards: 2,
            ..SessionConfig::default()
        },
        42,
    );

    // The session opens on a single ROOT shard — the split has not happened
    // yet, which is the whole point: a viewer sees it occur.
    assert_eq!(
        session
            .live_shards()
            .into_iter()
            .map(|s| ShardPath::from(s).0)
            .collect::<Vec<_>>(),
        vec![String::new()],
        "a session opens at genesis, on one shard",
    );

    // The split lands about six epochs in — trigger, admission, cohort
    // draw, snap-sync, readiness gate, flip — so give it headroom.
    let mut events = Vec::new();
    for _ in 0..600 {
        events.extend(session.step(500));
    }

    let splits: Vec<(Vec<String>, Vec<String>)> = events
        .iter()
        .filter_map(|e| match &e.kind {
            TraceKind::TopologyChanged {
                appeared, retired, ..
            } => Some((
                appeared.iter().map(|s| s.0.clone()).collect(),
                retired.iter().map(|s| s.0.clone()).collect(),
            )),
            _ => None,
        })
        .collect();

    assert_eq!(
        splits.len(),
        1,
        "exactly one partition change, saw {splits:?}"
    );
    let (appeared, retired) = &splits[0];
    assert_eq!(appeared, &["0".to_string(), "1".to_string()]);
    assert_eq!(
        retired,
        &[String::new()],
        "the root retires into its children"
    );

    // Blocks must be reported on the root before the split and on both
    // children after it — the timeline needs all three lanes.
    let mut per_shard: BTreeMap<String, u32> = BTreeMap::new();
    for event in &events {
        if let TraceKind::BlockCommitted { shard, .. } = &event.kind {
            *per_shard.entry(shard.0.clone()).or_default() += 1;
        }
    }
    assert_eq!(
        per_shard.len(),
        3,
        "root then both children, saw {per_shard:?}"
    );
    assert!(
        per_shard.values().all(|n| *n > 3),
        "every lane runs a real chain, saw {per_shard:?}",
    );
}

#[test]
fn transfers_reach_a_terminal_outcome_on_either_side_of_a_split() {
    // Status is per host and a host only tracks the shards it serves, so a
    // session that polls one host reports nothing for transactions routed to
    // the other child — they look stuck in flight forever when they in fact
    // settled. Every submission here must reach a terminal outcome.
    //
    // Submissions run on past the split, so a transfer whose prefix the trie
    // has handed to a child has to settle on that child. Each child takes
    // over at its parent's terminal crossing, so the shard the fanout
    // resolves is one with a live committee to gossip to.
    let mut session = Session::new(
        SessionConfig {
            max_shards: 2,
            ..SessionConfig::default()
        },
        42,
    );

    let mut events = Vec::new();
    for _ in 0..440 {
        events.extend(session.step(500));
    }
    assert!(
        events
            .iter()
            .any(|e| matches!(e.kind, TraceKind::TopologyChanged { .. })),
        "the split must have happened before transactions are submitted",
    );

    let mut submitted = 0;
    for i in 0..460 {
        if i % 25 == 0 {
            session.submit_transfer();
            submitted += 1;
        }
        events.extend(session.step(500));
    }
    // A settle tail for the last submission. A cross-shard transfer's payer
    // shard waits for every counterpart's engagement echo before it votes,
    // so the last one needs more than the gap between submissions to reach
    // a terminal outcome.
    for _ in 0..100 {
        events.extend(session.step(500));
    }

    let mut outcome: BTreeMap<String, String> = BTreeMap::new();
    for event in &events {
        match &event.kind {
            TraceKind::TxSubmitted { tx } => {
                outcome.insert(tx.0.clone(), "never reported".to_string());
            }
            TraceKind::TxStatusChanged { tx, status, .. } => {
                outcome.insert(tx.0.clone(), (*status).to_string());
            }
            _ => {}
        }
    }

    assert_eq!(outcome.len(), submitted, "every submission is reported");
    let unresolved: Vec<_> = outcome
        .iter()
        .filter(|(_, s)| !matches!(s.as_str(), "succeeded" | "aborted" | "rejected"))
        .collect();
    assert!(
        unresolved.is_empty(),
        "every transfer settles on whichever child owns it; unresolved: {unresolved:?}",
    );
}

/// Run a two-shard session past its split, then submit `count` transfers
/// spaced far enough apart to settle, returning every event observed.
fn run_past_split(seed: u64, count: usize) -> Vec<TraceEvent> {
    let mut session = Session::new(
        SessionConfig {
            max_shards: 2,
            ..SessionConfig::default()
        },
        seed,
    );
    let mut events = Vec::new();
    for _ in 0..440 {
        events.extend(session.step(500));
    }
    assert!(
        events
            .iter()
            .any(|e| matches!(e.kind, TraceKind::TopologyChanged { .. })),
        "the split must land before transfers are submitted",
    );
    for i in 0..(count * 20 + 100) {
        if i % 20 == 0 && i / 20 < count {
            session.submit_transfer();
        }
        events.extend(session.step(500));
    }
    events
}

/// The transactions an owed crossing of reached another shard's fold,
/// each with the shard it left and the shard that credited it.
fn credited(events: &[TraceEvent]) -> BTreeMap<String, (String, String)> {
    events
        .iter()
        .filter_map(|event| match &event.kind {
            TraceKind::CrossingCredited { from, to, txs, .. } if from != to => Some(
                txs.iter()
                    .map(|tx| (tx.0.clone(), (from.0.clone(), to.0.clone())))
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect()
}

#[test]
fn a_cross_shard_transfer_is_certified_on_the_payers_side_and_credited_on_the_other() {
    let events = run_past_split(42, 6);

    // Which shards signed a certificate covering each transaction.
    let mut certified: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // Which shards committed a finalization covering it, and who they
    // named as participants.
    let mut finalized: BTreeMap<String, BTreeSet<(String, Vec<String>)>> = BTreeMap::new();

    for event in &events {
        match &event.kind {
            TraceKind::ExecutionCertified {
                shard, outcomes, ..
            } => {
                for (tx, _) in outcomes {
                    certified
                        .entry(tx.0.clone())
                        .or_default()
                        .insert(shard.0.clone());
                }
            }
            TraceKind::TickFinalized {
                shard,
                participants,
                txs,
                ..
            } => {
                let named: Vec<String> = participants.iter().map(|p| p.0.clone()).collect();
                for tx in txs {
                    finalized
                        .entry(tx.0.clone())
                        .or_default()
                        .insert((shard.0.clone(), named.clone()));
                }
            }
            _ => {}
        }
    }

    // A transfer's record reaches the recipient's shard as a state claim,
    // whose fold credits it: the payer's shard certifies and finalizes
    // it alone, naming itself, and the recipient's certifies nothing.
    let crossed = credited(&events);
    assert!(
        !crossed.is_empty(),
        "a session past the split must produce cross-shard transfers",
    );
    for (tx, (payer, _)) in &crossed {
        assert_eq!(
            certified.get(tx),
            Some(&BTreeSet::from([payer.clone()])),
            "tx {tx} must be certified by its payer's shard alone",
        );
        let commits = finalized.get(tx).expect("a certified tx is finalized");
        assert_eq!(
            commits,
            &BTreeSet::from([(payer.clone(), vec![payer.clone()])]),
            "tx {tx} must finalize on its payer's shard alone, naming itself",
        );
    }
}

#[test]
fn every_cross_shard_arc_names_a_shard_and_height_the_timeline_can_place() {
    // An arc is drawn between two committed blocks, so both endpoints must
    // be heights the session also reported as blocks — otherwise the viewer
    // has a line with nowhere to attach it.
    let events = run_past_split(42, 6);

    let mut blocks: BTreeMap<(String, u64), u64> = BTreeMap::new();
    let mut endpoints: Vec<(String, u64)> = Vec::new();
    // The oldest endpoint each arc reaches back to, so the span an arc has
    // to cover can be checked against the window the viewer draws.
    let mut spans: Vec<(u64, String, u64)> = Vec::new();
    for event in &events {
        match &event.kind {
            TraceKind::BlockCommitted { shard, height, .. } => {
                blocks.insert((shard.0.clone(), *height), event.wt);
            }
            TraceKind::ProvisionsVerified {
                from,
                from_height,
                to,
                to_height,
                ..
            } => {
                endpoints.push((from.0.clone(), *from_height));
                endpoints.push((to.0.clone(), *to_height));
                spans.push((event.wt, from.0.clone(), *from_height));
            }
            TraceKind::ExecutionCertified {
                shard,
                height,
                into,
                into_height,
                ..
            } => {
                endpoints.push((shard.0.clone(), *height));
                endpoints.push((into.0.clone(), *into_height));
                spans.push((event.wt, shard.0.clone(), *height));
            }
            _ => {}
        }
    }

    assert!(!endpoints.is_empty(), "the run must produce arcs at all");
    let orphaned: Vec<_> = endpoints
        .iter()
        .filter(|e| !blocks.contains_key(*e))
        .cloned()
        .collect();
    assert!(
        orphaned.is_empty(),
        "every arc endpoint is a reported block; orphaned: {orphaned:?}",
    );

    // An arc is only drawn while both its blocks are still on screen. The
    // viewer's default window is 15s of attested time and it keeps blocks
    // for twice that, so a settlement round reaching further back than one
    // window would leave arcs that never render.
    let widest = spans
        .iter()
        .map(|(wt, shard, height)| wt - blocks[&(shard.clone(), *height)])
        .max()
        .expect("endpoints are non-empty");
    assert!(
        widest < 15_000,
        "an arc spans {widest}ms, wider than the window that draws it",
    );
}

#[test]
fn the_load_generator_picks_pairs_the_trie_routes_across_shards() {
    // A transfer is cross-shard only when payer and payee land on different
    // shards, which is a property of where the trie routes their addresses.
    // Rotating the payee by nonce alone leaves about half of them local,
    // and a local transfer draws nothing.
    let events = run_past_split(42, 8);

    let submitted: BTreeSet<String> = events
        .iter()
        .filter_map(|e| match &e.kind {
            TraceKind::TxSubmitted { tx } => Some(tx.0.clone()),
            _ => None,
        })
        .collect();
    // A transfer crosses shards when the recipient's shard credits its
    // record.
    let crossed: BTreeSet<String> = credited(&events).into_keys().collect();

    assert_eq!(submitted.len(), 8, "every submission is reported");
    let local: Vec<_> = submitted.difference(&crossed).collect();
    assert!(
        local.is_empty(),
        "every submission past a split must cross shards; local: {local:?}",
    );
}

#[test]
fn a_split_parent_reports_one_terminal_that_closes_its_handoff_window() {
    let mut session = Session::new(
        SessionConfig {
            max_shards: 2,
            ..SessionConfig::default()
        },
        42,
    );
    let mut events = Vec::new();
    for _ in 0..600 {
        events.extend(session.step(500));
    }

    let terminals: Vec<(String, u64, Option<u64>)> = events
        .iter()
        .filter_map(|e| match &e.kind {
            TraceKind::ShardTerminal {
                shard,
                height,
                handoff_from,
            } => Some((shard.0.clone(), *height, *handoff_from)),
            _ => None,
        })
        .collect();

    assert_eq!(
        terminals.len(),
        1,
        "only the retiring root terminates, saw {terminals:?}",
    );
    let (shard, height, handoff_from) = &terminals[0];
    assert_eq!(shard, "", "the root is what retires");
    let handoff_from = handoff_from.expect("a split parent certifies its own handoff");
    assert!(
        handoff_from < *height,
        "the handoff window opens before the last block, saw {handoff_from}..={height}",
    );

    // The terminal is past every block the timeline placed: the walk reports
    // a block only once a committing child carries its timestamp, and the
    // last block of a stopped chain never gets one.
    let last_drawn = events
        .iter()
        .filter_map(|e| match &e.kind {
            TraceKind::BlockCommitted { shard, height, .. } if shard.0.is_empty() => Some(*height),
            _ => None,
        })
        .max()
        .expect("the root committed blocks");
    assert!(
        *height > last_drawn,
        "terminal h{height} sits past the last drawn block h{last_drawn}",
    );
}

#[test]
fn a_terminal_status_never_turns_into_a_different_one() {
    // Status is polled from every host, and hosts reach a decision at
    // different times. Reducing their answers by "furthest progressed" alone
    // leaves every terminal decision tied with every other, so which one is
    // reported depends on the poll order — and a transaction shown as aborted
    // flips to succeeded the moment another host finishes. Whatever is
    // reported, it must not change out from under a viewer.
    let mut session = Session::new(
        SessionConfig {
            max_shards: 2,
            ..SessionConfig::default()
        },
        42,
    );
    // Submit hard, straight through the reshape: the disagreements that
    // exposed this only appear under sustained cross-shard load.
    let mut events = Vec::new();
    for i in 0..900 {
        if i % 3 == 0 {
            session.submit_transfer();
        }
        events.extend(session.step(500));
    }

    let terminal = |s: &str| matches!(s, "succeeded" | "aborted" | "rejected");
    let mut reported: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for event in &events {
        if let TraceKind::TxStatusChanged { tx, status, .. } = &event.kind {
            reported
                .entry(tx.0.clone())
                .or_default()
                .push((*status).to_string());
        }
    }
    assert!(!reported.is_empty(), "the run must report statuses at all");

    let mut flipped: Vec<(&String, &Vec<String>)> = Vec::new();
    for (tx, steps) in &reported {
        let mut latched: Option<&str> = None;
        for status in steps {
            match latched {
                Some(prev) if terminal(status) && prev != status => {
                    flipped.push((tx, steps));
                    break;
                }
                _ => {}
            }
            if terminal(status) {
                latched = Some(status);
            }
        }
    }
    assert!(
        flipped.is_empty(),
        "a settled transaction must keep its outcome; flipped: {flipped:?}",
    );
}

#[test]
fn traffic_totals_cover_every_delivery_the_sample_left_out() {
    // The viewer animates a bounded sample and reports unbounded totals, so
    // the two have to reconcile: whatever a step carried is either reported
    // individually or counted as dropped. A totals figure that only covered
    // the sample would make a busy network look quiet exactly when it is not.
    // Stepped wide on purpose. The sample budget is sized for the fastest
    // playback a viewer can ask for, so a step has to span a comparable
    // stretch of simulated time before it overruns — and a budget that never
    // overruns leaves the half of the reconciliation that matters untested.
    let mut session = Session::new(config(), 42);
    let mut steps = 0;
    let mut busy = 0;

    for _ in 0..40 {
        let events = session.step(4_000);
        let reported = u32::try_from(
            events
                .iter()
                .filter(|e| matches!(e.kind, TraceKind::MessageDelivered { .. }))
                .count(),
        )
        .expect("a step reports far fewer deliveries than u32 holds");
        let mut summaries = events.iter().filter_map(|e| match &e.kind {
            TraceKind::TrafficSampled {
                by_class,
                sampled,
                dropped,
            } => Some((by_class, *sampled, *dropped)),
            _ => None,
        });
        let Some((by_class, sampled, dropped)) = summaries.next() else {
            assert_eq!(
                reported, 0,
                "deliveries reported without a summary to account for them",
            );
            continue;
        };
        assert!(
            summaries.next().is_none(),
            "a step summarises its traffic once",
        );
        steps += 1;

        assert_eq!(
            reported, sampled,
            "the summary counts the deliveries the step actually reported",
        );
        let counted: u64 = by_class.iter().map(|(_, deliveries, _)| deliveries).sum();
        assert_eq!(
            counted,
            u64::from(sampled) + dropped,
            "every delivery is either sampled or counted as dropped",
        );
        assert!(
            by_class
                .iter()
                .all(|(_, deliveries, bytes)| *deliveries > 0 && *bytes > 0),
            "a class appears only when it carried something, saw {by_class:?}",
        );
        if dropped > 0 {
            busy += 1;
        }
    }

    assert!(steps > 0, "a running network carries traffic");
    assert!(
        busy > 0,
        "some step must exceed the sample budget, or the reconciliation is untested",
    );
}

#[test]
fn a_delivery_names_two_hosts_and_the_span_it_flew() {
    let mut session = Session::new(config(), 42);
    let hosts = u32::try_from(session.hosts().len()).expect("a demo cluster is small");
    let mut events = Vec::new();
    for _ in 0..20 {
        events.extend(session.step(500));
    }

    let deliveries: Vec<(u32, u32, &str, u64, u64)> = events
        .iter()
        .filter_map(|e| match &e.kind {
            TraceKind::MessageDelivered {
                from,
                to,
                class,
                sent_at,
                delivered_at,
                ..
            } => Some((*from, *to, *class, *sent_at, *delivered_at)),
            _ => None,
        })
        .collect();
    assert!(!deliveries.is_empty(), "the network delivered nothing");

    for (from, to, class, sent_at, delivered_at) in &deliveries {
        assert!(
            *from < hosts && *to < hosts,
            "a delivery names hosts in the roster, saw {from} -> {to} of {hosts}",
        );
        assert_ne!(from, to, "a host does not deliver to itself");
        assert!(
            delivered_at > sent_at,
            "a delivery lands after it was sent, saw {sent_at} -> {delivered_at}",
        );
        assert!(
            matches!(
                *class,
                "consensus" | "block_completion" | "cross_shard_progress" | "recovery" | "bulk"
            ),
            "a delivery carries a named class, saw {class:?}",
        );
    }

    // Consensus is what a running committee spends its traffic on, and it is
    // not the class a type gets by declaring nothing — so seeing it proves
    // the class survived the trip from the send site rather than defaulting.
    assert!(
        deliveries
            .iter()
            .any(|(_, _, class, ..)| *class == "consensus"),
        "a committee committing blocks exchanges consensus traffic",
    );
}

#[test]
fn a_split_moves_hosts_out_of_the_pool_and_into_the_children() {
    // The roster is what makes a reshape legible as staffing rather than as
    // a line on a timeline: the children's committees are drawn from hosts
    // that were sitting in the free pool, and this is where that shows.
    let mut session = Session::new(
        SessionConfig {
            max_shards: 2,
            ..SessionConfig::default()
        },
        42,
    );

    let opening = session.hosts();
    let pooled_at_open: Vec<u32> = opening
        .iter()
        .filter(|h| h.shards.is_empty() && h.pooled > 0)
        .map(|h| h.host)
        .collect();
    assert!(
        !pooled_at_open.is_empty(),
        "a session that can split opens with a free pool, saw {opening:?}",
    );

    let mut events = Vec::new();
    for _ in 0..600 {
        events.extend(session.step(500));
    }

    let rosters: Vec<&Vec<HostRole>> = events
        .iter()
        .filter_map(|e| match &e.kind {
            TraceKind::HostsChanged { hosts } => Some(hosts),
            _ => None,
        })
        .collect();
    assert!(
        !rosters.is_empty(),
        "growing the topology must move the roster",
    );

    // Every reported roster covers the whole cluster, so a viewer that joins
    // late still renders it without stitching deltas together.
    let hosts = opening.len();
    assert!(
        rosters.iter().all(|r| r.len() == hosts),
        "each roster names every host",
    );

    let seated = session
        .hosts()
        .iter()
        .any(|h| pooled_at_open.contains(&h.host) && !h.shards.is_empty());
    assert!(
        seated,
        "the split staffs its children from the pool; pool at open {pooled_at_open:?}, \
         final roster {:?}",
        session.hosts(),
    );

    // And the children are served by the end of it — the roster tracks the
    // partition rather than lagging it.
    let children: BTreeSet<String> = session
        .hosts()
        .iter()
        .flat_map(|h| h.shards.iter().map(|s| s.0.clone()))
        .collect();
    assert!(
        children.contains("0") && children.contains("1"),
        "both children are served, saw {children:?}",
    );
}

#[test]
fn shard_paths_spell_the_trie_so_a_parent_prefixes_its_children() {
    let root = ShardPath::from(ShardId::ROOT).0;
    let left = ShardPath::from(ShardId::leaf(1, 0)).0;
    let right = ShardPath::from(ShardId::leaf(1, 1)).0;
    let right_left = ShardPath::from(ShardId::leaf(2, 0b10)).0;
    let right_right = ShardPath::from(ShardId::leaf(2, 0b11)).0;

    assert_eq!(root, "");
    assert_eq!(left, "0");
    assert_eq!(right, "1");
    assert_eq!(right_left, "10");
    assert_eq!(right_right, "11");

    // The relation the viewer draws edges from.
    assert!(right_left.starts_with(&right));
    assert!(right_right.starts_with(&right));
    assert!(!right_left.starts_with(&left));
}

#[test]
fn a_different_seed_produces_a_different_run() {
    // Same length, different content: the chains diverge in timing even
    // though both make progress.
    let a = run(42, 20);
    let b = run(7, 20);
    assert!(!a.is_empty() && !b.is_empty());
    assert_ne!(format!("{a:?}"), format!("{b:?}"));
}

/// A committee rotation must not stall a lane. Holding the victim's seat
/// until its replacement is ready keeps the consensus subset at
/// `shard_size` through the whole sync window, so `quorum_threshold`
/// never tightens toward all-of-N: retiring first ran a four-member shard
/// at three for the window and cost a view-change timeout entering it and
/// another leaving.
///
/// The run has to reach the epoch that *seats* the entrant, which is a
/// full sync window past the one that admits it. A horizon covering only
/// the admission watches the half of a rotation that moves no seat: the
/// consensus committee, and with it the proposer rotation and the routing
/// every vote follows, changes at the flip.
#[test]
fn a_rotation_never_stalls_a_lane_for_a_view_change() {
    let mut session = Session::new(
        SessionConfig {
            max_shards: 2,
            pool_spares: 2,
            ..SessionConfig::default()
        },
        42,
    );

    let mut roster = session.hosts();
    let mut split_at = None;
    let mut rotation_at = None;
    let mut last: BTreeMap<String, u64> = BTreeMap::new();
    let mut worst: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for step in 0..1300 {
        for event in session.step(500) {
            match &event.kind {
                TraceKind::TopologyChanged { .. } => split_at = Some(step),
                TraceKind::BlockCommitted { shard, .. } => {
                    if let Some(previous) = last.insert(shard.0.clone(), event.wt) {
                        let gap = event.wt - previous;
                        let entry = worst.entry(shard.0.clone()).or_default();
                        if gap > entry.0 {
                            *entry = (gap, event.wt);
                        }
                    }
                }
                _ => {}
            }
        }
        let next = session.hosts();
        if next != roster && split_at.is_some_and(|at| at != step) {
            rotation_at.get_or_insert(step);
        }
        roster = next;
    }
    assert!(rotation_at.is_some(), "the run must cover a rotation");
    assert_eq!(worst.len(), 3, "root then both children, saw {worst:?}");
    let ceiling =
        u64::try_from(VIEW_CHANGE_TIMEOUT_DEFAULT.as_millis()).expect("timeout fits a u64");
    for (lane, (gap, at)) in &worst {
        assert!(
            *gap < ceiling,
            "lane {lane} stalled {gap}ms at wt {at}, a view change or worse",
        );
    }
}

#[test]
fn a_spare_stocked_session_rotates_a_validator_between_committees() {
    // Rotation refuses to run without a pool to backfill from, and a session
    // staffed only for its splits has spent every spare by the time they
    // execute. Two spares outlive the split, so the shuffle has somewhere to
    // draw from and somewhere to put the validator it takes.
    let mut session = Session::new(
        SessionConfig {
            max_shards: 2,
            pool_spares: 2,
            ..SessionConfig::default()
        },
        42,
    );

    // The first shuffle boundary is `shuffle_interval_epochs` in, which is far
    // enough past the split that the run has to cover both.
    let mut roster = session.hosts();
    let mut split_at = None;
    let mut rotation_at = None;
    let mut blocks_after: BTreeMap<String, u32> = BTreeMap::new();
    for step in 0..1200 {
        for event in session.step(500) {
            match &event.kind {
                TraceKind::TopologyChanged { .. } => split_at = Some(step),
                TraceKind::BlockCommitted { shard, .. } if rotation_at.is_some() => {
                    *blocks_after.entry(shard.0.clone()).or_default() += 1;
                }
                _ => {}
            }
        }
        let next = session.hosts();
        // A roster move that is not the split is a rotation: the split staffs
        // its children in one batch at the flip, and nothing else moves a host
        // between committees.
        if next != roster && split_at.is_some_and(|at| at != step) {
            rotation_at.get_or_insert(step);
        }
        roster = next;
    }

    let split_at = split_at.expect("the session splits");
    let rotation_at = rotation_at.expect("a validator rotates once the pool has a spare");
    assert!(
        rotation_at > split_at,
        "the rotation follows the split, not the staffing it does",
    );

    // A rotated seat has to be occupied, not just reassigned: the joiner
    // snap-syncs into the shard it was drawn onto, and the committee it left
    // keeps committing. A rotation the harness records but never staffs drops
    // both children below quorum and the chains stop.
    assert_eq!(
        blocks_after.len(),
        2,
        "both children stay live through the rotation, saw {blocks_after:?}",
    );
    assert!(
        blocks_after.values().all(|n| *n > 100),
        "neither child stalls after the rotation, saw {blocks_after:?}",
    );

    // The rotation is a relocation, not a host quietly picking up a second
    // shard. Retained parent stores are filtered out — a grown host lists the
    // retired root it still serves alongside the child it belongs to.
    let live: BTreeSet<String> = session
        .live_shards()
        .into_iter()
        .map(|s| ShardPath::from(s).0)
        .collect();
    let mut staffed: BTreeMap<String, u32> = BTreeMap::new();
    for host in &roster {
        let served: Vec<&ShardPath> = host.shards.iter().filter(|s| live.contains(&s.0)).collect();
        assert!(
            served.len() <= 1,
            "host {} serves {served:?}, more than one live shard",
            host.host,
        );
        for shard in served {
            *staffed.entry(shard.0.clone()).or_default() += 1;
        }
    }
    assert_eq!(
        staffed.len(),
        2,
        "both children are staffed, saw {staffed:?}"
    );
    // Both committees end at full strength, plus a rotation entrant on any
    // child whose victim has yet to retire — the seat the entrant syncs into
    // is one the shard still holds at consensus strength.
    assert!(
        staffed.values().all(|n| (4..=5).contains(n)),
        "a committee is off strength, saw {staffed:?} in {roster:?}",
    );
}
