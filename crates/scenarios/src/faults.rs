//! Portable network-fault scenarios.

use std::fmt::Write;
use std::sync::Arc;

use hyperscale_types::{
    BlockHeight, Epoch, HALT_THRESHOLD_EPOCHS, ShardId, StateRoot, TransactionDecision,
    TransactionStatus, TxHash,
};
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;

use crate::reshape::split_lifecycle;
use crate::straddler::{chain_settled, submit_straddler};
use crate::support::epochs;
use crate::support::faultable::FaultableCluster;
use crate::support::query::beacon_epoch;
use crate::support::tx::{
    HALT_STRADDLER_BATCH, account_from_seed, build_faucet_tx, build_transfer_tx,
    halt_straddler_setup, signer_from_seed, validity_around,
};
use crate::support::wait::{await_beacon_epoch, await_height, await_tx_terminal};

/// Dropping `transaction.gossip` still delivers a submitted transfer — via the
/// fetch fallback — with the drop rule firing and the fetch engaging.
///
/// The feasibility check for the libp2p gate: on the sim the drop is total at
/// delivery; on production the inbound `Ignore` filter suppresses the gossip on
/// every host, so a submitted transaction reaches the committee only by the
/// fetch fallback.
///
/// # Panics
///
/// Panics if the transfer does not accept within budget, the drop rule never
/// fired, or the fetch fallback never engaged.
pub fn gossip_drop_engages_fetch_fallback(c: &mut impl FaultableCluster) {
    let fetch_before = c.metric("fetch_items_sent", Some("transaction"));
    let dropped = c.drop_type("transaction.gossip");

    let signer = signer_from_seed(1);
    let to = account_from_seed(2);
    let transfer = build_faucet_tx(
        to,
        &signer,
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    let hash = transfer.hash();
    c.submit(Arc::new(transfer));

    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must still accept via the fetch fallback; status = {status:?}"
    );
    assert!(
        dropped.fired() >= 1,
        "the transaction.gossip drop rule must fire",
    );
    assert!(
        c.metric("fetch_items_sent", Some("transaction")) > fetch_before,
        "the transaction fetch fallback must engage (before={fetch_before})",
    );
}

/// A 2-2 host partition starves quorum (3 of 4), so consensus halts; healing it
/// resumes commits as the lagging half catches up.
///
/// Requires a four-host single-shard cluster. The heal exercises the catch-up
/// sync path: the lagging half resynchronises via block fetch, not gossip
/// re-delivery, so the resume budget covers a few sync rounds.
///
/// # Panics
///
/// Panics if consensus does not commit before the partition, progress fails to
/// halt under it, or commits do not resume after the heal.
pub fn partition_halts_and_heals(c: &mut impl FaultableCluster) {
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(4)),
        "consensus must commit a block before the partition",
    );
    let before = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height before the partition")
        .inner();

    // Neither half of a 2-2 split has the 3-of-4 quorum, so progress halts.
    c.partition(&[0, 1], &[2, 3]);
    c.run_until(epochs(1), |_| false);
    let during = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height during the partition")
        .inner();
    assert!(
        during <= before + 2,
        "a 2-2 partition has no quorum, so progress must halt: before={before}, during={during}",
    );

    // Healing lets the pacemaker resynchronise the lagging half; commits resume.
    c.heal_all();
    assert!(
        await_height(c, ShardId::ROOT, during + 3, epochs(6)),
        "consensus must resume committing once the partition heals (stalled at {during})",
    );
}

/// A transaction settles while one validator is isolated: the remaining 3-of-4
/// quorum holds, and the vote-retry rotation recovers any wave the isolated node
/// was leading.
///
/// Requires a four-host single-shard cluster. Submission routes to host 0, so a
/// different host is isolated — one that still proposes some rounds, exercising
/// the leader-failure fallback.
///
/// # Panics
///
/// Panics if consensus does not commit before the isolation or the transfer does
/// not complete while a validator is isolated.
pub fn isolated_validator_still_settles(c: &mut impl FaultableCluster) {
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(4)),
        "consensus must commit a block before isolating a validator",
    );
    c.isolate(3);

    let signer = signer_from_seed(1);
    let to = account_from_seed(2);
    let transfer = build_faucet_tx(
        to,
        &signer,
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    let hash = transfer.hash();
    c.submit(Arc::new(transfer));

    let status = await_tx_terminal(c, hash, epochs(6));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must complete despite an isolated validator; status = {status:?}",
    );
}

/// A shard halts when f+1 of its committee withhold their consensus
/// messages, and the beacon recovers it by re-drawing the whole committee
/// from the pool.
///
/// After the root grows, two members of the left child's four-member
/// committee go silent at the consensus layer only: their outbound
/// proposals, votes, and timeouts are dropped, and vote delivery to them
/// is cut (a silent member aggregates no QCs of its own), while every
/// other channel — beacon participation, pool ratification, block
/// serving — stays connected. The honest remainder is short of the 2f+1
/// quorum, so the shard freezes while its sibling and the beacon keep
/// committing. Once
/// the boundary watermark stalls past the halt threshold the beacon flags
/// the shard, seats a fresh committee from the pool spares, and retains
/// the replaced members in the routing view; the incomers sync the halted
/// tip from them, bridge the halt gap, and the shard resumes committing.
/// The first crossing under the fresh committee clears the recovery
/// record.
///
/// The reshape thresholds stay armed throughout — quiet (both children
/// hold in the stable band between the derived merge floor and the split
/// threshold), but forcing every proposal and vote through the reshape
/// predicate's substate walk. Across the recovery that walk crosses the
/// sync-admitted halted tip, whose byte total no fresh member can
/// resolve; the bridge blocks build and verify only because both sides
/// agree the assertion is out of play there, and that agreement is what
/// this scenario exercises.
///
/// Requires [`halt_recovery_genesis_balances`] at genesis, a dedicated
/// host per validator, and two committees' worth of pool surplus — one
/// grow cohort, one recovery committee.
///
/// [`halt_recovery_genesis_balances`]: crate::tx::halt_recovery_genesis_balances
///
/// # Panics
///
/// Panics if the shard fails to halt, the beacon or the sibling shard
/// stops committing through the halt, the recovery never fires, the shard
/// fails to resume under its fresh committee, or the recovery record
/// never clears.
pub fn halted_shard_recovers_by_committee_redraw(c: &mut impl FaultableCluster) {
    let (left, right) = ShardId::ROOT.children();
    split_lifecycle(c);
    let halt = freeze_shard(c, left, right, |_| {});
    await_halt_recovery(c, &halt);
}

/// Cross-shard waves stay atomic across a shard halt and its
/// committee-redraw recovery.
///
/// The grown left child freezes exactly as in
/// [`halted_shard_recovers_by_committee_redraw`], but with cross-child
/// transfers in flight at every phase of the cut: a settling batch
/// finalized on both children before any fault installs, a racing batch
/// submitted at the freeze edge — the last instant with any chance to
/// commit on the halting shard — and a doomed batch submitted against the
/// frozen shard. The surviving sibling must drive every in-flight wave to
/// a terminal verdict on its own deadline clock during the halt, never
/// hanging on the dead counterparty. After the recovery the two chains
/// must agree probe by probe: no wave applied on one side that the other
/// refused, with absence on the recovered chain counting as an abort (the
/// fresh committee resolves pre-halt waves from certificates alone and
/// commits no abort finalization of its own). Once the recovery record
/// clears, a fresh transfer per direction must settle — the recovered
/// shard's cross-shard rail serves again.
///
/// Requires [`halt_straddler_setup`] at genesis, a dedicated host per
/// validator, and two committees' worth of pool surplus.
///
/// [`halt_straddler_setup`]: crate::tx::halt_straddler_setup
///
/// # Panics
///
/// Panics if the halt or recovery misses a lifecycle budget, an in-flight
/// wave hangs, the chains disagree on any probe's fate, or the
/// post-recovery transfers fail to settle.
pub fn halted_shard_straddler_atomic(c: &mut impl FaultableCluster) {
    let (halted, survivor) = ShardId::ROOT.children();
    let setup = halt_straddler_setup();
    let network = NetworkDefinition::simulator();
    split_lifecycle(c);

    // Settling batch: finalized on both children before any fault
    // installs, so each chain records the accept.
    let mut probes: Vec<TxHash> = Vec::new();
    for (i, (key, from, to)) in setup.straddlers[..HALT_STRADDLER_BATCH].iter().enumerate() {
        let nonce = 100 + u32::try_from(i).unwrap_or(0);
        probes.push(submit_straddler(c, &network, key, *from, *to, nonce));
    }
    assert!(
        c.run_until(epochs(12), |c| {
            probes
                .iter()
                .all(|h| chain_settled(c, halted, *h) && chain_settled(c, survivor, *h))
        }),
        "the settling batch must finalize on both children before the halt",
    );

    // Racing batch: submitted at the freeze edge, inside the staged cut —
    // the shard commits at most a couple more heights, so each wave either
    // squeezes through or is left in flight when it freezes. No per-batch
    // assertion; each probe lands in whichever tally bucket it raced into.
    let halt = freeze_shard(c, halted, survivor, |c| {
        let racing = &setup.straddlers[HALT_STRADDLER_BATCH..2 * HALT_STRADDLER_BATCH];
        for (i, (key, from, to)) in racing.iter().enumerate() {
            let nonce = 200 + u32::try_from(i).unwrap_or(0);
            probes.push(submit_straddler(c, &network, key, *from, *to, nonce));
        }
    });

    // Doomed batch: submitted against the frozen shard. The survivor still
    // provisions to it — the topology seats the frozen committee until the
    // redraw — but nothing can commit there, so every wave is unsettleable.
    for (i, (key, from, to)) in setup.straddlers[2 * HALT_STRADDLER_BATCH..]
        .iter()
        .enumerate()
    {
        let nonce = 300 + u32::try_from(i).unwrap_or(0);
        probes.push(submit_straddler(c, &network, key, *from, *to, nonce));
    }

    // The survivor's deadline clock keeps running through the halt: every
    // in-flight wave must reach a terminal verdict well inside the
    // detection window, not hang on the dead counterparty.
    for hash in &probes[HALT_STRADDLER_BATCH..] {
        let status = await_tx_terminal(c, *hash, epochs(4));
        assert!(
            matches!(status, Some(TransactionStatus::Completed(_))),
            "an in-flight wave must reach a terminal verdict during the halt; status = {status:?}",
        );
    }

    // The frozen chain's fates are canonical for pre-halt heights: the
    // recovery bridges over the QC-attested tip, so nothing recorded here
    // is orphaned, while a fresh member's synced view may not reach below
    // its snap anchor.
    let fates_at_freeze: Vec<_> = probes.iter().map(|h| c.chain_fate(halted, *h).1).collect();

    await_halt_recovery(c, &halt);

    let mut consistent = 0u32;
    let mut aborted = 0u32;
    let mut halted_only = 0u32;
    let mut survivor_only = 0u32;
    let mut report = String::new();
    for (idx, hash) in probes.iter().enumerate() {
        let frozen_fate = fates_at_freeze[idx];
        let halted_now = c.chain_fate(halted, *hash).1;
        let survivor_fate = c.chain_fate(survivor, *hash).1;
        // An accept in either view of the halted chain is an apply: the
        // at-freeze snapshot covers heights a fresh member never synced,
        // the post-recovery walk covers anything finalized after resume.
        let halted_accept = [frozen_fate, halted_now]
            .iter()
            .any(|f| matches!(f, Some((_, TransactionDecision::Accept))));
        let survivor_accept = matches!(survivor_fate, Some((_, TransactionDecision::Accept)));
        let _ = write!(
            report,
            "\n  #{idx}: halted at-freeze={frozen_fate:?} now={halted_now:?}; survivor={survivor_fate:?}",
        );
        match (halted_accept, survivor_accept) {
            (true, true) => consistent += 1,
            (false, false) => aborted += 1,
            (true, false) => halted_only += 1,
            (false, true) => survivor_only += 1,
        }
    }
    assert_eq!(
        survivor_only, 0,
        "the survivor applied a wave the halted shard never did:{report}",
    );
    assert_eq!(
        halted_only, 0,
        "the halted chain holds an apply the survivor refused:{report}",
    );
    let batch = u32::try_from(HALT_STRADDLER_BATCH).unwrap_or(u32::MAX);
    assert!(
        consistent >= batch,
        "every settling probe must land accepted on both chains:{report}",
    );
    assert!(
        aborted >= batch,
        "every doomed probe must resolve without an apply on either chain:{report}",
    );

    // The recovered shard's cross-shard rail serves again: a fresh
    // transfer per direction settles on both chains.
    let mut revived: Vec<TxHash> = Vec::new();
    for (i, (key, from, to)) in setup.post_recovery.iter().enumerate() {
        let nonce = 400 + u32::try_from(i).unwrap_or(0);
        revived.push(submit_straddler(c, &network, key, *from, *to, nonce));
    }
    assert!(
        c.run_until(epochs(16), |c| {
            revived
                .iter()
                .all(|h| chain_settled(c, halted, *h) && chain_settled(c, survivor, *h))
        }),
        "a post-recovery transfer per direction must settle on both chains",
    );
}

/// A staged shard freeze: the fault rules are installed and the shard has
/// verifiably stopped committing. Carries the observations
/// [`await_halt_recovery`] asserts against.
struct StagedHalt {
    /// The frozen shard.
    shard: ShardId,
    /// Its live sibling, asserted to keep committing through the halt.
    sibling: ShardId,
    /// The frozen shard's settled height once in-flight rounds drained.
    frozen_at: u64,
    /// The beacon epoch when the freeze settled.
    epoch_at_halt: u64,
    /// The sibling's committed height when the freeze settled.
    sibling_at_halt: u64,
}

/// Freeze `shard` with a staged consensus cut against two of its four
/// committee members.
///
/// f+1 of the committee withhold: their outbound consensus messages stop
/// reaching everyone else. The honest remainder is 2f, short of quorum,
/// so the shard halts; nothing else is cut. Vote delivery TO the
/// withholding pair is cut too — a silent member collects no votes —
/// else the pair keeps aggregating QCs only it holds and privately
/// commits a suffix the recovery must orphan, and the faulted hosts
/// (honest code under a network fault) would panic on the commit-linkage
/// break instead of modeling adversaries that simply stop.
///
/// The cut is staged. Cutting everything at one instant leaves the same
/// private-commit race in the in-flight window: a pair member due to
/// aggregate the next rounds' votes can hold a QC no one else ever sees
/// and commit one height past the beacon-attested frontier — a suffix the
/// recovery orphans, and the linkage break kills the host. So first
/// starve aggregation (votes toward the pair), then drain an epoch — any
/// QC a pair member already holds is broadcast and becomes common
/// knowledge in this window, while consensus keeps committing through the
/// pair's timed-out leader rounds — and only then silence the pair's
/// outbound channels.
///
/// `at_freeze_edge` runs between the drain and the silencing — the last
/// instant new work enters the shard's pipeline with any chance to
/// commit.
fn freeze_shard<C: FaultableCluster>(
    c: &mut C,
    shard: ShardId,
    sibling: ShardId,
    at_freeze_edge: impl FnOnce(&mut C),
) -> StagedHalt {
    let committee = c.committee_hosts(shard);
    assert_eq!(
        committee.len(),
        4,
        "the halting shard must be served by a four-member committee",
    );
    let withholding = &committee[..2];
    let others: Vec<usize> = (0..c.host_count())
        .filter(|host| !withholding.contains(host))
        .collect();

    c.drop_type_between(&others, withholding, "block.vote");
    c.run_until(epochs(1), |_| false);
    at_freeze_edge(c);
    let votes_withheld = c.drop_type_between(withholding, &others, "block.vote");
    c.drop_type_between(withholding, &others, "block.header");
    c.drop_type_between(withholding, &others, "shard.timeout");

    // In-flight rounds drain, then the shard freezes.
    c.run_until(epochs(1), |_| false);
    let frozen = c
        .committed_height(shard)
        .expect("the halting shard committed during the grow")
        .inner();
    let epoch_at_halt = beacon_epoch(c).expect("a committed beacon epoch").inner();
    let sibling_at_halt = c
        .committed_height(sibling)
        .expect("the sibling shard serves")
        .inner();
    c.run_until(epochs(2), |_| false);
    let during = c
        .committed_height(shard)
        .expect("a committed height during the halt")
        .inner();
    assert!(
        during <= frozen + 2,
        "two of four withholding leaves no quorum, so the shard must halt: \
         frozen={frozen}, during={during}",
    );
    assert!(
        votes_withheld.fired() >= 1,
        "the withheld votes must actually be dropped",
    );
    StagedHalt {
        shard,
        sibling,
        frozen_at: during,
        epoch_at_halt,
        sibling_at_halt,
    }
}

/// Drive a staged freeze through detection, committee redraw, resume, and
/// record clear, asserting the beacon and the sibling shard stay live
/// throughout.
fn await_halt_recovery(c: &mut impl FaultableCluster, halt: &StagedHalt) {
    let shard = halt.shard;

    // The boundary watermark stalls past the threshold; the beacon flags
    // the shard and re-draws its committee from the pool spares.
    let threshold = u32::try_from(HALT_THRESHOLD_EPOCHS).expect("threshold fits u32");
    let recovered = c.run_until(epochs(threshold + 10), |c| {
        c.beacon_state()
            .is_some_and(|state| state.pending_recoveries.contains_key(&shard))
    });
    assert!(
        recovered,
        "the beacon must flag the halted shard and seat a fresh committee",
    );
    // Only the shard halted: the beacon and the sibling kept committing.
    let epoch_now = beacon_epoch(c).expect("a committed beacon epoch").inner();
    assert!(
        epoch_now > halt.epoch_at_halt,
        "the beacon must keep producing epochs through the halt \
         ({} -> {epoch_now})",
        halt.epoch_at_halt,
    );
    assert!(
        c.committed_height(halt.sibling)
            .expect("the sibling shard serves")
            .inner()
            > halt.sibling_at_halt,
        "the sibling shard must keep committing through the halt",
    );

    // The fresh committee syncs the halted tip from the retained members,
    // bridges the halt gap, and resumes committing past the frozen height.
    // The pool the recovery draws from holds exactly `shard_size` spares,
    // so the fresh committee is whatever the tenure shuffle rotated into
    // the pool — here one of the withholding hosts, cycled off the halted
    // shard before the flag and redrawn (the recovery is only as clean as
    // a fresh draw at the pool's corrupt fraction). The fresh committee
    // keeps its honest majority and recovers, but a lone isolated member
    // dropping a quarter of the views stretches the resume, so the budget
    // is generous — a ceiling on the wait, not the expected latency.
    assert!(
        await_height(c, shard, halt.frozen_at + 3, epochs(40)),
        "the recovered shard must resume committing under its fresh committee \
         (frozen at {})",
        halt.frozen_at,
    );
    // The first crossing under the fresh committee completes the recovery.
    let cleared = c.run_until(epochs(20), |c| {
        c.beacon_state()
            .is_some_and(|state| !state.pending_recoveries.contains_key(&shard))
    });
    assert!(
        cleared,
        "the shard's next boundary crossing must clear the recovery record",
    );
}

/// The committed state root that every host serving `shard` agrees on, or `None`
/// if any two disagree or one has not yet reported. The stall-not-fork check:
/// after a heal, this becoming `Some` means the shard's whole committee — the
/// rejoined dark hosts included — converged on one chain. A host still catching
/// up reports a different (or no) root, so it holds this at `None` until every
/// committee member is back in step. Scoped to the shard's committee so it works
/// in a multi-shard cluster, where only some hosts serve any given shard.
fn agreed_state_root(c: &impl FaultableCluster, shard: ShardId) -> Option<StateRoot> {
    let hosts = c.committee_hosts(shard);
    let first = c.host_committed_state_root(*hosts.first()?, shard)?;
    for &host in &hosts[1..] {
        if c.host_committed_state_root(host, shard)? != first {
            return None;
        }
    }
    Some(first)
}

/// A connected minority fragment partitions off, stays dark across an epoch
/// boundary, then rejoins as a group.
///
/// The regression shape behind the rejoin-wedge class, where fragment members
/// share stale state with each other while partitioned.
///
/// Requires a seven-host single-shard committee: quorum is five (strict >2/3),
/// so cutting the two-host fragment `{0, 1}` off the majority `{2..6}` leaves
/// both the shard and the beacon majority live — the majority keeps committing
/// and crossing epoch boundaries while the fragment is frozen. A full
/// bipartition, so both harnesses agree on the cut.
///
/// # Panics
///
/// Panics if consensus does not commit before the partition, the majority fails
/// to progress while the fragment is dark, the fragment advances while
/// partitioned, or the rejoined fragment fails to catch up and agree on the
/// committed root after the heal.
pub fn minority_fragment_rejoins_after_partition(c: &mut impl FaultableCluster) {
    assert_eq!(
        c.host_count(),
        7,
        "this scenario needs a seven-host committee so a two-host fragment leaves quorum live",
    );

    // Every host — the future fragment included — must be seated and committing
    // before the cut, so the fragment goes dark from a real synced state (not a
    // never-seated genesis host) and rejoins by catching up a bounded gap.
    let seated = c.run_until(epochs(6), |c| {
        (0..7).all(|host| {
            c.host_committed_height(host, ShardId::ROOT)
                .is_some_and(|h| h.inner() >= 1)
        })
    });
    assert!(
        seated,
        "every host must commit a block before the partition"
    );
    let start_epoch = beacon_epoch(c).expect("a committed beacon epoch").inner();

    c.partition(&[0, 1], &[2, 3, 4, 5, 6]);
    let before = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height before the partition")
        .inner();
    let frag_before: Vec<u64> = [0, 1]
        .iter()
        .map(|&host| {
            c.host_committed_height(host, ShardId::ROOT)
                .map_or(0, BlockHeight::inner)
        })
        .collect();

    // Keep the fragment dark across exactly one epoch boundary — the majority
    // (five of seven) keeps both shard and beacon consensus live, and bounding
    // the dark window to a single epoch keeps the fragment's catch-up gap inside
    // the block-retention window.
    assert!(
        await_beacon_epoch(c, start_epoch + 1, epochs(6)),
        "the five-host majority must cross an epoch boundary while the fragment is dark",
    );
    // Partition onset can transiently stall the majority: a replica missing a
    // pending ancestor body breaks the zero-slack five-of-five quorum until
    // the spin detector's sync recovers it, and rotating fetches past the two
    // dark peers costs a timeout each. Progress is the requirement, not
    // instantaneous progress — so give the sample a recovery budget.
    assert!(
        c.run_until(epochs(3), |c| c
            .committed_height(ShardId::ROOT)
            .is_some_and(|h| h.inner() > before + 2)),
        "the five-host majority must keep committing while the fragment is dark: \
         before={before}",
    );
    let during = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height during the partition")
        .inner();

    // The dark fragment has no quorum of its own, so neither of its hosts commits.
    for (&host, &frozen) in [0, 1].iter().zip(&frag_before) {
        let now = c
            .host_committed_height(host, ShardId::ROOT)
            .map_or(0, BlockHeight::inner);
        assert!(
            now <= frozen + 1,
            "fragment host {host} committed while partitioned (frozen={frozen}, now={now})",
        );
    }

    // Heal: the fragment resynchronises via block fetch, catches up to a tip past
    // the dark window, and every host — fragment included — agrees on the root.
    c.heal_all();
    let target = during + 2;
    let caught_up = c.run_until(epochs(10), |c| {
        [0, 1].iter().all(|&host| {
            c.host_committed_height(host, ShardId::ROOT)
                .is_some_and(|h| h.inner() >= target)
        }) && agreed_state_root(c, ShardId::ROOT).is_some()
    });
    assert!(
        caught_up,
        "the rejoined fragment must catch up past the dark window ({target}) and \
         every host must agree on the committed state root",
    );
}

/// Liveness needs a quorum, not the whole committee.
///
/// After a partition drops the cluster below quorum, restoring exactly a quorum
/// — with the remaining member still dark — must resume progress; the final
/// member then catches up.
///
/// Requires a four-host single-shard committee (quorum three). Hosts 0 and 1 are
/// isolated rather than split `{0,1} | {2,3}`, so host 0 is genuinely edgeless:
/// a plain partition would leave the 0–1 edge open, and production gossip would
/// relay across it once the staged heal reconnects host 1. `{2, 3}` alone is two
/// of four, below quorum, so consensus halts; reconnecting host 1 to hosts 2 and
/// 3 forms an exact three-of-four quorum that resumes progress before host 0 is
/// healed back in.
///
/// # Panics
///
/// Panics if consensus does not commit before the partition, progress fails to
/// halt under it, the exact-quorum heal fails to resume progress, or host 0 fails
/// to catch up and agree on the committed root after the final heal.
pub fn partition_heals_at_exact_quorum(c: &mut impl FaultableCluster) {
    assert_eq!(
        c.host_count(),
        4,
        "this scenario needs a four-host committee so three connected hosts are exactly quorum",
    );
    // Every host — host 0 included — must be seated and committing before the
    // isolation, so the host that stays dark rejoins from a real synced state.
    let seated = c.run_until(epochs(6), |c| {
        (0..4).all(|host| {
            c.host_committed_height(host, ShardId::ROOT)
                .is_some_and(|h| h.inner() >= 1)
        })
    });
    assert!(
        seated,
        "every host must commit a block before the partition"
    );

    // Isolate both 0 and 1 so the 0–1 edge is cut too; `{2, 3}` is below quorum.
    c.isolate(0);
    c.isolate(1);
    let before = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height before the partition")
        .inner();
    c.run_until(epochs(1), |_| false);
    let during = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height during the partition")
        .inner();
    assert!(
        during <= before + 2,
        "with only two of four connected there is no quorum, so progress must halt: \
         before={before}, during={during}",
    );

    // Reconnect host 1 to hosts 2 and 3 — an exact three-of-four quorum, host 0
    // still dark. Progress must resume before the final heal.
    c.heal_between(1, 2);
    c.heal_between(1, 3);
    let resumed = during + 3;
    assert!(
        await_height(c, ShardId::ROOT, resumed, epochs(6)),
        "an exact three-of-four quorum (host 0 still dark) must resume progress",
    );
    let host0 = c
        .host_committed_height(0, ShardId::ROOT)
        .map_or(0, BlockHeight::inner);
    assert!(
        host0 < resumed,
        "the still-dark host 0 must not have kept pace (host0={host0}, tip={resumed})",
    );

    // Heal host 0 back in; it catches up and every host agrees on the root.
    c.heal_all();
    let target = resumed + 2;
    let caught_up = c.run_until(epochs(8), |c| {
        c.host_committed_height(0, ShardId::ROOT)
            .is_some_and(|h| h.inner() >= target)
            && agreed_state_root(c, ShardId::ROOT).is_some()
    });
    assert!(
        caught_up,
        "host 0 must catch up to the tip ({target}) and every host must agree on \
         the committed state root after the final heal",
    );
}

/// Severing every edge between two shards forces their in-flight cross-shard
/// waves to abort at the wave deadline.
///
/// A deterministic, all-abort terminal — bounded, terminal damage (INV-EXEC-5),
/// never a speculative or split decision.
///
/// A two-shard cluster (`split_lifecycle`) whose committees sit on disjoint host
/// sets, so `partition(committee_hosts(left), committee_hosts(right))` cuts every
/// inter-shard edge in both directions while leaving intra-shard edges intact —
/// unlike the drop scenarios, which always leave a fetch route the wave recovers
/// through. The cut also splits the beacon quorum, so epoch production halts;
/// the shards coast on their `L = 1` lookahead committees, and the hold stays
/// well inside that runway (the wave deadline is a fraction of one epoch), so
/// neither shard's consensus wedges — that starvation is a separate scenario.
///
/// Cross-shard transfers move XRD between account `31` (left) and account `30`
/// (right); the single-shard controls run on the disjoint accounts `40` / `41`,
/// so they settle intra-shard without colliding with the severed waves' reserved
/// writes. Requires [`intershard_partition_genesis_balances`] at genesis.
///
/// [`intershard_partition_genesis_balances`]: crate::tx::intershard_partition_genesis_balances
///
/// # Panics
///
/// Panics if a shard wedges under the severance, a single-shard control fails to
/// settle, a severed cross-shard transfer settles or the two shards disagree on
/// its fate, not every in-flight transfer aborts, or a fresh cross-shard
/// transfer fails to settle after the heal.
#[allow(clippy::too_many_lines)] // one linear severance narrative: submit, sever, abort, heal
pub fn inter_shard_partition_aborts_waves_at_deadline(c: &mut impl FaultableCluster) {
    let (left, right) = ShardId::ROOT.children();
    split_lifecycle(c);

    let left_hosts = c.committee_hosts(left);
    let right_hosts = c.committee_hosts(right);
    assert!(
        !left_hosts.is_empty() && !right_hosts.is_empty(),
        "both split children must be served before the severance",
    );
    assert!(
        left_hosts.iter().all(|h| !right_hosts.contains(h)),
        "the two committees must sit on disjoint host sets: left={left_hosts:?}, right={right_hosts:?}",
    );

    let network = NetworkDefinition::simulator();
    let signer_left = signer_from_seed(31);
    let account_left = account_from_seed(31);
    let signer_right = signer_from_seed(30);
    let account_right = account_from_seed(30);

    let aborted_before = c.metric("transactions_aborted", None);
    let left_before = c
        .committed_height(left)
        .expect("left serves before the severance")
        .inner();
    let right_before = c
        .committed_height(right)
        .expect("right serves before the severance")
        .inner();

    // A cross-shard transfer in flight as the cut lands.
    let before_tx = build_transfer_tx(
        &signer_left,
        account_left,
        account_right,
        Decimal::from(500),
        &network,
        1,
        validity_around(c.now()),
    );
    let before_hash = before_tx.hash();
    c.submit(Arc::new(before_tx));

    // Sever every inter-shard edge (both directions), intra-shard edges intact.
    c.partition(&left_hosts, &right_hosts);

    // A second cross-shard transfer submitted under the severance.
    let during_tx = build_transfer_tx(
        &signer_right,
        account_right,
        account_left,
        Decimal::from(500),
        &network,
        1,
        validity_around(c.now()),
    );
    let during_hash = during_tx.hash();
    c.submit(Arc::new(during_tx));

    // A single-shard control per disjoint account — these must settle purely
    // intra-shard while the cross-shard waves are stranded.
    for seed in [40u8, 41] {
        let control = build_transfer_tx(
            &signer_from_seed(seed),
            account_from_seed(seed),
            account_from_seed(seed),
            Decimal::from(100),
            &network,
            1,
            validity_around(c.now()),
        );
        let hash = control.hash();
        c.submit(Arc::new(control));
        let status = await_tx_terminal(c, hash, epochs(2));
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "single-shard control from account {seed} must settle under the severance; \
             status = {status:?}",
        );
    }

    // Both shards kept committing locally throughout — the severance froze the
    // cross-shard waves, not either side's consensus.
    let left_during = c
        .committed_height(left)
        .expect("left serves during the severance")
        .inner();
    let right_during = c
        .committed_height(right)
        .expect("right serves during the severance")
        .inner();
    assert!(
        left_during > left_before,
        "the left shard wedged under the severance (before={left_before}, during={left_during})",
    );
    assert!(
        right_during > right_before,
        "the right shard wedged under the severance (before={right_before}, during={right_during})",
    );

    // Hold past the wave deadline: both stranded transfers reach a terminal
    // Abort. The deadline abort is a counterpart abort — it surfaces in the
    // terminal-verdict cache, not always as an on-chain execution outcome — so
    // the verdict is read from `tx_status` via `await_tx_terminal`.
    for (hash, label) in [(before_hash, "left→right"), (during_hash, "right→left")] {
        let verdict = await_tx_terminal(c, hash, epochs(3));
        assert!(
            matches!(
                verdict,
                Some(TransactionStatus::Completed(TransactionDecision::Aborted))
            ),
            "the {label} cross-shard transfer must reach a terminal Abort at the \
             wave deadline; status = {verdict:?}",
        );
        // Safety: no shard settled it Accept — the all-abort is deterministic,
        // never a split 2PC decision — and where both shards recorded an on-chain
        // fate, they agree.
        let left_fate = c.chain_fate(left, hash).1.map(|(_, decision)| decision);
        let right_fate = c.chain_fate(right, hash).1.map(|(_, decision)| decision);
        assert!(
            left_fate != Some(TransactionDecision::Accept)
                && right_fate != Some(TransactionDecision::Accept),
            "the {label} transfer settled Accept on a shard despite the severance: \
             left={left_fate:?}, right={right_fate:?}",
        );
        if let (Some(left_decision), Some(right_decision)) = (left_fate, right_fate) {
            assert_eq!(
                left_decision, right_decision,
                "the shards disagreed on the {label} transfer's fate: \
                 left={left_decision:?}, right={right_decision:?}",
            );
        }
    }
    // Both severed transfers are reflected in the cluster-wide abort metric.
    assert!(
        c.metric("transactions_aborted", None) >= aborted_before + 2,
        "the abort metric must count both severed transfers (before={aborted_before}, now={})",
        c.metric("transactions_aborted", None),
    );

    // Heal every edge; a fresh cross-shard transfer settles normally.
    c.heal_all();
    let fresh_tx = build_transfer_tx(
        &signer_left,
        account_left,
        account_right,
        Decimal::from(500),
        &network,
        2,
        validity_around(c.now()),
    );
    let fresh_hash = fresh_tx.hash();
    c.submit(Arc::new(fresh_tx));
    let fresh_status = await_tx_terminal(c, fresh_hash, epochs(10));
    assert!(
        matches!(
            fresh_status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "a fresh cross-shard transfer must settle once the severance heals; \
         status = {fresh_status:?}",
    );
}

/// A ratification pool partitioned below quorum halts epoch production, and the
/// shards defer at the schedule head rather than fork.
///
/// A disjoint two-shard cluster (eight hosts, one validator each).
/// `partition(committee_hosts(left), committee_hosts(right))` splits the beacon
/// pool 4|4 — neither side reaches quorum, so no beacon block commits and epoch
/// production halts — while each shard keeps its own four hosts together, so
/// shard consensus stays live. The partition then holds *past* the `L = 1`
/// lookahead runway. The shards coast on the committees the last committed beacon
/// epoch resolved, so their heights climb for the runway and then plateau once
/// the weighted timestamp crosses past the last resolved committee window —
/// stall, not fork. Healing restores the pool quorum, epoch production resumes,
/// and both shards commit on past their frozen heights.
///
/// # Panics
///
/// Panics if the partitioned pool advances the epoch, a shard fails to coast then
/// freeze, either shard keeps committing past its runway (a fork or a wedge
/// rather than a clean defer), or the heal fails to resume epochs, shard
/// progress, or cross-host root agreement.
pub fn beacon_pool_partition_stalls_epoch_production(c: &mut impl FaultableCluster) {
    let (left, right) = ShardId::ROOT.children();
    split_lifecycle(c);

    let left_hosts = c.committee_hosts(left);
    let right_hosts = c.committee_hosts(right);
    assert!(
        !left_hosts.is_empty() && !right_hosts.is_empty(),
        "both split children must be served before the partition",
    );
    assert!(
        left_hosts.iter().all(|h| !right_hosts.contains(h)),
        "the two committees must sit on disjoint host sets: left={left_hosts:?}, right={right_hosts:?}",
    );

    let start_epoch = beacon_epoch(c)
        .expect("a committed beacon epoch before the partition")
        .inner();
    let left_before = c.committed_height(left).expect("left serves").inner();
    let right_before = c.committed_height(right).expect("right serves").inner();

    // Split the beacon pool below quorum. Each shard keeps its own hosts, so
    // shard consensus survives; the pool spanning both shards does not.
    c.partition(&left_hosts, &right_hosts);

    // Coast past the L = 1 runway, then the shards defer at the schedule head.
    c.run_until(epochs(3), |_| false);
    let left_frozen = c.committed_height(left).expect("left serves").inner();
    let right_frozen = c.committed_height(right).expect("right serves").inner();
    assert_eq!(
        beacon_epoch(c).map(Epoch::inner),
        Some(start_epoch),
        "the pool partitioned below quorum must halt epoch production",
    );
    assert!(
        left_frozen > left_before && right_frozen > right_before,
        "both shards must coast the lookahead runway before deferring \
         (left {left_before}->{left_frozen}, right {right_before}->{right_frozen})",
    );

    // Hold longer: the deferred shards make no further progress — a stall, not a
    // fork, and not an unbounded run past the runway.
    c.run_until(epochs(2), |_| false);
    assert_eq!(
        c.committed_height(left).map(BlockHeight::inner),
        Some(left_frozen),
        "the left shard must defer at the schedule head, not commit past its runway",
    );
    assert_eq!(
        c.committed_height(right).map(BlockHeight::inner),
        Some(right_frozen),
        "the right shard must defer at the schedule head, not commit past its runway",
    );
    assert_eq!(
        beacon_epoch(c).map(Epoch::inner),
        Some(start_epoch),
        "epoch production must stay halted while the pool is partitioned",
    );

    // Heal: the pool reaches quorum again, epochs resume, and both shards commit
    // past their frozen heights on the one chain every serving host agrees on.
    c.heal_all();
    assert!(
        await_beacon_epoch(c, start_epoch + 1, epochs(8)),
        "epoch production must resume once the pool heals (stalled at epoch {start_epoch})",
    );
    assert!(
        await_height(c, left, left_frozen + 1, epochs(8))
            && await_height(c, right, right_frozen + 1, epochs(8)),
        "both shards must resume committing past their frozen heights after the heal \
         (left {left_frozen}, right {right_frozen})",
    );
    let agreed = c.run_until(epochs(8), |c| {
        agreed_state_root(c, left).is_some() && agreed_state_root(c, right).is_some()
    });
    assert!(
        agreed,
        "every serving host must agree on each shard's committed root after the heal",
    );
}

/// Grow to two shards, drop the `broadcast` message type, then run a cross-shard
/// transfer that must recover via the `fetch_kind` fetch fallback.
///
/// Works for any broadcast the cross-shard flow relies on — a unicast 2PC
/// delivery (`provisions.broadcast`, `execution.cert.batch`) suppressed at the
/// sender's gate, or a gossip broadcast (`transaction.gossip`, `block.committed`)
/// suppressed by the receiver's inbound filter. The transfer moves 500 XRD from
/// account `31` (left child) to `30` (right child), both funded at genesis.
/// Faults install after the split settles, so the grow rides its own broadcasts
/// cleanly. Asserts the transfer accepts, the drop fired, the fetch engaged, and
/// nothing aborted.
fn cross_shard_broadcast_drop(
    c: &mut impl FaultableCluster,
    broadcast: &'static str,
    fetch_kind: &'static str,
) {
    split_lifecycle(c);
    // Snapshot the fetch counter before the drop: the counter is cluster-wide
    // and monotonic, so measuring the increase isolates the fetches this outage
    // forces from any the split itself emitted (remote-header sync in particular
    // runs as normal machinery in a grown cluster, not only as a fallback).
    let fetch_before = c.metric("fetch_items_sent", Some(fetch_kind));
    let dropped = c.drop_type(broadcast);

    let payer = signer_from_seed(31);
    let from = account_from_seed(31);
    let to = account_from_seed(30);
    let transfer = build_transfer_tx(
        &payer,
        from,
        to,
        Decimal::from(500),
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    let hash = transfer.hash();
    c.submit(Arc::new(transfer));

    let status = await_tx_terminal(c, hash, epochs(10));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the cross-shard transfer must settle despite the dropped {broadcast}; status = {status:?}",
    );
    assert!(dropped.fired() >= 1, "the {broadcast} drop must fire");
    assert!(
        c.metric("fetch_items_sent", Some(fetch_kind)) > fetch_before,
        "the {fetch_kind} fetch fallback must engage (before={fetch_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the cross-shard transfer must not abort",
    );
}

/// Dropping `provisions.broadcast` still settles a cross-shard transfer — the
/// destination shard fetches the provisions rather than receiving them.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the provision
/// fetch never engages, or anything aborts.
pub fn cross_shard_provisions_drop_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "provisions.broadcast", "provision");
}

/// Dropping `execution.cert.batch` still settles a cross-shard transfer — the
/// destination shard fetches the execution certificates rather than receiving
/// them.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the exec-cert
/// fetch never engages, or anything aborts.
pub fn cross_shard_exec_cert_drop_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "execution.cert.batch", "exec_cert");
}

/// Dropping BOTH `provisions.broadcast` and `execution.cert.batch` at once
/// still settles a cross-shard transfer.
///
/// The two fallback fetches are gated on different timeouts and different fetch
/// instances, so this proves they compose without deadlock when both primary
/// cross-shard channels fail together: each shard fetches its provisions and
/// its execution certificates, and the wave finalizes within its timeout
/// rather than aborting.
///
/// # Panics
///
/// Panics if the transfer does not settle, either drop never fires, either
/// fetch never engages, or anything aborts.
pub fn cross_shard_compound_drop_fetch_fallback(c: &mut impl FaultableCluster) {
    split_lifecycle(c);
    let provision_before = c.metric("fetch_items_sent", Some("provision"));
    let exec_cert_before = c.metric("fetch_items_sent", Some("exec_cert"));
    let provisions_dropped = c.drop_type("provisions.broadcast");
    let exec_cert_dropped = c.drop_type("execution.cert.batch");

    let payer = signer_from_seed(31);
    let from = account_from_seed(31);
    let to = account_from_seed(30);
    let transfer = build_transfer_tx(
        &payer,
        from,
        to,
        Decimal::from(500),
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    let hash = transfer.hash();
    c.submit(Arc::new(transfer));

    let status = await_tx_terminal(c, hash, epochs(12));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle despite both channels dropped; status = {status:?}",
    );
    assert!(
        provisions_dropped.fired() >= 1,
        "the provisions.broadcast drop must fire",
    );
    assert!(
        exec_cert_dropped.fired() >= 1,
        "the execution.cert.batch drop must fire",
    );
    assert!(
        c.metric("fetch_items_sent", Some("provision")) > provision_before,
        "the provision fetch fallback must engage (before={provision_before})",
    );
    assert!(
        c.metric("fetch_items_sent", Some("exec_cert")) > exec_cert_before,
        "the exec-cert fetch fallback must engage (before={exec_cert_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the compound cross-shard transfer must not abort",
    );
}

/// Dropping `transaction.gossip` in a grown cluster still settles a cross-shard
/// transfer — the source committee fetches the transaction body (the DA
/// fallback) rather than receiving it by gossip.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the transaction
/// fetch never engages, or anything aborts.
pub fn cross_shard_transaction_da_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "transaction.gossip", "transaction");
}

/// Dropping `block.committed` still settles a cross-shard transfer — the shard
/// tracking its counterpart's committed headers fetches them via the
/// remote-header sync rather than receiving them by gossip.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the
/// remote-header fetch never engages, or anything aborts.
pub fn cross_shard_header_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "block.committed", "remote_header");
}

/// A cross-shard transfer settles under unreliable request RPC.
///
/// Provisions never broadcast — forcing the provision fetch fallback — AND half
/// of every `provision.request` leg is dropped, so each fetch attempt is a
/// coin-flip that must be retried until one gets through. Proves the
/// request-manager retry path recovers a fetch under probabilistic request
/// loss without aborting.
///
/// The 50% loss is exercised per attempt on both harnesses: the sim draws from
/// the engine's own seeded RNG at the request-drain site, and production
/// consults the same gate in the libp2p request pool per send, surfacing a
/// dropped leg as the timeout the retry loop rolls again.
///
/// Returns the cluster-wide `provision.request` drop count. Engagement is
/// deterministic on the sim — the wiring asserts it per seed — but not on
/// production, where the async retry path can settle the fetch on an undropped
/// first leg, so a caller there asserts only the liveness invariants this body
/// checks. All other invariants (settle, broadcast dropped, fetch engaged, zero
/// aborts) hold on both.
///
/// # Panics
///
/// Panics if the transfer fails to settle, the broadcast drop never fires, the
/// provision fetch never engages, or anything aborts.
pub fn cross_shard_provisions_fetch_with_request_loss(c: &mut impl FaultableCluster) -> u64 {
    split_lifecycle(c);
    let fetch_before = c.metric("fetch_items_sent", Some("provision"));
    let broadcast_dropped = c.drop_type("provisions.broadcast");
    let request_dropped = c.drop_type_with_probability("provision.request", 0.5);

    let payer = signer_from_seed(31);
    let from = account_from_seed(31);
    let to = account_from_seed(30);
    let transfer = build_transfer_tx(
        &payer,
        from,
        to,
        Decimal::from(500),
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    let hash = transfer.hash();
    c.submit(Arc::new(transfer));

    let status = await_tx_terminal(c, hash, epochs(12));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle despite 50% provision.request loss; status = {status:?}",
    );
    assert!(
        broadcast_dropped.fired() >= 1,
        "the provisions.broadcast drop must fire",
    );
    assert!(
        c.metric("fetch_items_sent", Some("provision")) > fetch_before,
        "the provision fetch fallback must engage (before={fetch_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the transfer must not abort under request loss",
    );

    request_dropped.fired()
}

/// A transient `provisions.broadcast` outage recovers even when the fault lifts
/// mid-flight.
///
/// Drop the broadcast, submit a cross-shard transfer, and wait until the outage
/// actually bites — the source shard's one-shot provision broadcast is
/// suppressed. Then lift the fault and confirm the transfer still settles via
/// the provision fetch fallback with nothing aborting. The dropped broadcast is
/// not re-emitted on lift, so the destination shard recovers by fetch either
/// way; the point is that removing a live drop rule mid-recovery is safe — the
/// fetch bridge completes and no wave wedges.
///
/// One transfer, not two: both spendable accounts (`31`, `30`) are declared
/// writes of every transfer between them, so a second overlapping cross-shard
/// transfer would race the first's conflict window rather than test recovery.
///
/// # Panics
///
/// Panics if the transfer fails to settle, the outage never fired, the
/// provision fetch never engaged, or anything aborts.
pub fn cross_shard_provisions_recovers_after_transient_outage(c: &mut impl FaultableCluster) {
    split_lifecycle(c);
    let fetch_before = c.metric("fetch_items_sent", Some("provision"));
    let dropped = c.drop_type("provisions.broadcast");

    let payer = signer_from_seed(31);
    let from = account_from_seed(31);
    let to = account_from_seed(30);
    let transfer = build_transfer_tx(
        &payer,
        from,
        to,
        Decimal::from(500),
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    let hash = transfer.hash();
    c.submit(Arc::new(transfer));

    // Let the outage bite: the source shard's provision broadcast is dropped
    // before we lift the fault, so the recovery genuinely spans a removal.
    let bit = c.run_until(epochs(8), |_| dropped.fired() >= 1);
    assert!(
        bit,
        "the provisions.broadcast drop must fire before the outage lifts",
    );
    c.clear_drops();

    let status = await_tx_terminal(c, hash, epochs(10));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle via the provision fetch despite the transient \
         outage; status = {status:?}",
    );
    assert!(
        c.metric("fetch_items_sent", Some("provision")) > fetch_before,
        "the provision fetch fallback must bridge the outage (before={fetch_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the transfer must not abort",
    );
}
