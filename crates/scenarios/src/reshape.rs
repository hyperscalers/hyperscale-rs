//! Reshape lifecycle scenarios.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_types::{
    BlockHeight, MAX_VALIDITY_RANGE, ShardId, TimestampRange, Transaction, WeightedTimestamp,
};

use crate::support::conservation::{Charges, probe_world};
use crate::support::query::{
    clock, committee_size, epoch_duration_ms, live_shards, scheduled_terminal_epoch,
};
use crate::support::tx::{build_probe_transfer_tx, validity_around};
use crate::support::wait::{
    assert_height_frozen, await_beacon_epoch, await_blocks, await_height, await_merge_keeper_count,
    await_root_matches_anchor, await_serves, await_serves_ahead_of_anchor, await_split_admitted,
    measure_blocks_per_epoch,
};
use crate::support::{Cluster, epochs, grow_to, vote_reshape_threshold};

/// Reshape `split_bytes` the vote installs after the grow. Its derived
/// `merge_bytes = split_bytes / 8` sits far above each cold child's byte total,
/// so both assert the merge once the change activates, while staying far above
/// them so neither re-splits.
const MERGE_VOTE_SPLIT_BYTES: u64 = 80_000_000;

/// Grow the single-shard root to a `target`-leaf partition and assert the
/// reached topology against the beacon's committed committees.
///
/// Drives the portable [`grow_to`] step, then checks that the live committees are
/// exactly the `target`-leaf partition with every leaf at the genesis committee's
/// full strength. Committee seating is the property: a split that seats an
/// under-strength child still commits past genesis (quorum can hold below full
/// strength), so [`grow_to`]'s own commit check alone would miss it. Requires a
/// config with `split_bytes = 0` and `(target - 1)` cohorts of pool surplus.
///
/// # Panics
///
/// Panics if the beacon does not fold before the grow, the grow misses its
/// budget, or the reached topology is not the full-strength `target` partition.
fn grow_reaches_topology(c: &mut impl Cluster, target: u32) {
    assert!(
        await_beacon_epoch(c, 1, epochs(6)),
        "the beacon must fold before the grow so the genesis committee strength is known",
    );
    let strength = committee_size(c, ShardId::ROOT).expect("genesis seats the root committee");

    grow_to(c, target);

    let depth = target.trailing_zeros();
    let leaves: Vec<ShardId> = (0..u64::from(target))
        .map(|path| ShardId::leaf(depth, path))
        .collect();
    let expected: BTreeSet<ShardId> = leaves.iter().copied().collect();
    assert!(
        c.run_until(epochs(8), |c| {
            live_shards(c) == expected
                && leaves
                    .iter()
                    .all(|&leaf| committee_size(c, leaf) == Some(strength))
        }),
        "the grow must seat exactly the {target}-leaf partition, each at full committee strength ({strength})",
    );
}

/// Grow the root into a two-leaf partition, both leaves at full committee
/// strength.
///
/// # Panics
///
/// Panics if the grow misses its budget or the reached topology is not the
/// full-strength two-leaf partition.
pub fn grow_reaches_two_shard_topology(c: &mut impl Cluster) {
    grow_reaches_topology(c, 2);
}

/// Grow the root into a four-leaf partition through two split generations, every
/// leaf at full committee strength.
///
/// # Panics
///
/// Panics if the grow misses its budget or the reached topology is not the
/// full-strength four-leaf partition.
pub fn grow_reaches_four_shard_topology(c: &mut impl Cluster) {
    grow_reaches_topology(c, 4);
}

/// Arm an organic split of the root shard and drive it to completion.
///
/// The beacon admits the split from the armed trigger, both children are served
/// and commit past genesis at the beacon-composed anchor root, and the parent
/// terminates. Requires a config with `split_bytes = 0` and one cohort of pool
/// surplus.
///
/// # Panics
///
/// Panics if any lifecycle stage misses its budget.
pub fn split_lifecycle(c: &mut impl Cluster) {
    let root = ShardId::ROOT;
    let (left, right) = root.children();

    assert!(
        await_split_admitted(c, root, epochs(8)),
        "beacon did not admit the root split within budget"
    );

    // Keep the parent committing through its final window: a real transfer
    // gives it activity so it coasts to its crossing and the fold seeds both
    // children from the terminal contribution.
    c.submit(Arc::new(build_probe_transfer_tx(validity_around(c.now()))));

    // Each child seats from the terminal crossing its members followed,
    // ahead of the fold that publishes its anchor. Serving alone would
    // also pass on the anchor fallback an epoch later, so the assertion
    // is on *when*: a child that seats only once its anchor exists has
    // taken the fallback, and the cut-over is not being exercised.
    for child in [left, right] {
        match await_serves_ahead_of_anchor(c, child, epochs(28)) {
            Some(true) => {}
            Some(false) => {
                panic!("split child {child} seated off its beacon anchor, not its parent's cut")
            }
            None => panic!("split child {child} was not served within budget"),
        }
    }
    assert!(
        await_height(c, left, 1, epochs(8)) && await_height(c, right, 1, epochs(8)),
        "split children did not commit past genesis within budget"
    );
    assert!(
        await_root_matches_anchor(c, left, epochs(8))
            && await_root_matches_anchor(c, right, epochs(8)),
        "split child roots did not match the beacon anchor within budget"
    );
    assert_height_frozen(c, root, epochs(2));
}

/// How many probes the replay train submits per epoch of the parent's
/// remaining life.
///
/// A probe is only a replay candidate while its own validity window still
/// contains the moment it is resubmitted, and `MAX_VALIDITY_RANGE` is
/// under an epoch, so one probe per epoch would leave gaps a cut can land
/// in. Four spaces them at a quarter of a window's reach even when an
/// epoch is the production five minutes.
const PROBES_PER_EPOCH: u64 = 4;

/// Upper bound on the train, and so on the funding
/// [`probe_train_genesis_accounts`] has to cover.
pub const MAX_REPLAY_PROBES: u32 = 48;

/// Whether `shard` is seated and committing past its own genesis.
fn shard_live<C: Cluster>(c: &C, shard: ShardId) -> bool {
    c.serves_shard(shard) && c.committed_height(shard).is_some_and(|h| h.inner() >= 1)
}

/// A transaction the terminating parent committed cannot commit again on
/// either child.
///
/// The parent's `CommitDedupIndex` dies with its chain and both children
/// construct their own empty, so nothing a child holds refuses the
/// resubmission: its QC chain is empty, its mempool holds no tombstone
/// from the parent's sweep, and the transaction's own validity window
/// still contains its anchor. The replay is refused only if a child
/// inherits what its parent committed.
///
/// Requires [`probe_train_genesis_accounts`] funding and a config with
/// `split_bytes = 0` and one cohort of pool surplus.
///
/// # Panics
///
/// Panics if any lifecycle stage misses its budget, if no probe survives
/// to be a replay candidate (which would make the assertion vacuous), or
/// if either child commits the replay.
pub fn split_boundary_refuses_a_replay(c: &mut impl Cluster) {
    let root = ShardId::ROOT;
    let (left, right) = root.children();

    let world = probe_world(c);
    let mut charges = Charges::default();
    let spacing = measure_probe_spacing(c, &mut charges, root);
    assert!(
        await_split_admitted(c, root, epochs(8)),
        "beacon did not admit the root split within budget"
    );
    let probes = run_probe_train(c, &mut charges, root, spacing, |c| {
        [left, right].iter().all(|&child| shard_live(c, child))
    });
    let replay = pick_replay(c, root, &probes);
    let replayed = replay.hash();

    c.submit(replay.clone());
    // A transaction commits only inside its validity window, so the
    // refusal is decided once the window has closed and each child has
    // committed a few blocks anchored past it.
    let closed = replay.validity_range().end_timestamp_exclusive;
    assert!(
        c.run_until(epochs(4), |c| clock(c) >= closed),
        "the replay's validity window must close within budget",
    );
    for child in [left, right] {
        assert!(
            await_blocks(c, child, REPLAY_TAIL_BLOCKS, epochs(1)),
            "child {child} must keep committing past the replay's window",
        );
        assert!(
            c.chain_fate(child, replayed).0.is_none(),
            "child {child} committed {replayed}, which its parent had already committed",
        );
    }
    // A refused replay charges nothing twice: the train's payer is out
    // one price per probe the parent committed, and the recipient holds
    // every payment.
    world.assert_settles_within(c, &charges, epochs(8), "a probe train and its replay");
}

/// Blocks each child commits past the replay's window before its refusal
/// is read — room for a block anchored inside the window to land after
/// the harness clock has left it.
const REPLAY_TAIL_BLOCKS: u64 = 8;

/// How many blocks `shard` should commit between consecutive probes.
///
/// Block cadence is activity-driven and scales with neither the epoch nor
/// the harness, so the train's spacing is measured rather than assumed.
/// One probe supplies the activity the sample prices in.
fn measure_probe_spacing(c: &mut impl Cluster, charges: &mut Charges, shard: ShardId) -> u64 {
    charges.submit(c, build_probe_transfer_tx(validity_around(c.now())));
    (measure_blocks_per_epoch(c, shard) / PROBES_PER_EPOCH).max(1)
}

/// Submit a train of probes across a terminating shard's remaining life
/// and return it, ordered by submission.
///
/// A train rather than one probe. A probe is only useful to a scenario
/// while its own validity window still contains the moment it is
/// resubmitted at, and admission to cut runs one to two epochs — longer
/// than any window a transaction is allowed to sign. A single probe
/// submitted at admission is expired by the time the successors accept
/// blocks, and would then be refused for expiry rather than for whatever
/// the scenario is about.
///
/// `handed_over` is what ends the train. It is the caller's because a
/// merge reclaims a shard id its own predecessor once held, so "the
/// successor is serving and committing" is already true of the departed
/// chain before the handover it is meant to detect.
fn run_probe_train<C: Cluster>(
    c: &mut C,
    charges: &mut Charges,
    terminating: ShardId,
    spacing: u64,
    handed_over: impl Fn(&C) -> bool,
) -> Vec<Arc<Transaction>> {
    let live = handed_over;
    let mut probes: Vec<Arc<Transaction>> = Vec::new();
    while probes.len() < MAX_REPLAY_PROBES as usize && !live(c) {
        let probe = Arc::new(build_probe_transfer_tx(validity_around(c.now())));
        charges.record(&probe);
        probes.push(Arc::clone(&probe));
        c.submit(probe);
        let from = committed_height(c, terminating);
        c.run_until(epochs(4), |c| {
            live(c) || committed_height(c, terminating) >= from + spacing
        });
    }

    assert!(
        live(c),
        "successors were not live within the train's budget"
    );
    probes
}

/// The train's replay candidate: committed on `terminating`, and still
/// signed for the instant it is about to be resubmitted at.
///
/// Read off the chain rather than inferred from when it was submitted, so
/// nothing here depends on where the cut fell. Being committed is also
/// what proves it opened before the cut — a shard commits nothing past
/// its terminal, so a transaction it committed opened before it.
///
/// # Panics
///
/// Panics when no probe qualifies, which would leave every assertion
/// resting on it vacuous.
fn pick_replay(
    c: &impl Cluster,
    terminating: ShardId,
    probes: &[Arc<Transaction>],
) -> Arc<Transaction> {
    let anchor = clock(c);
    probes
        .iter()
        .rev()
        .find(|probe| {
            probe.validity_range().contains(anchor)
                && c.chain_fate(terminating, probe.hash()).0.is_some()
        })
        .cloned()
        .expect(
            "no probe both committed on the terminating shard and outlived the cut — \
             the train is mis-spaced and the assertion would be vacuous",
        )
}

/// A transaction signed for a window that opened before `successor`'s
/// origin, built after the cut so no chain before it can have committed
/// it.
///
/// This is finding 2's population seen from the client side: a window
/// opened before the boundary, submitted where nothing that ran before
/// the boundary will ever include it. Constructed from the observed cut
/// rather than fished out of the probe train — a terminating shard packs
/// blocks right up to its terminal, so a train submitted across its life
/// is committed in full and yields no candidate at all.
///
/// The window opens [`PRECUT_LEAD`] before the cut, as late as it can
/// while still predating it, so the probe keeps the most of its
/// [`MAX_VALIDITY_RANGE`] budget for the successor to resolve it in.
///
/// # Panics
///
/// Panics if `successor` reports no origin, if its origin is network
/// genesis (nothing predates that, so the probe would not be pre-cut), or
/// if the built window no longer contains the current clock.
fn build_precut_probe(c: &impl Cluster, successor: ShardId) -> Arc<Transaction> {
    let cut = c
        .chain_origin_anchor(successor)
        .expect("the successor is live, so it reports the origin it started at");
    assert!(
        cut > WeightedTimestamp::ZERO,
        "{successor} was born at network genesis, so no window can open before it \
         and the admission assertion would be vacuous",
    );

    let opens = WeightedTimestamp::from_millis(cut.as_millis().saturating_sub(PRECUT_LEAD_MS));
    let range = TimestampRange::new(opens, opens.plus(PRECUT_PROBE_LIFE));
    let anchor = clock(c);
    assert!(
        range.contains(anchor),
        "a probe opening before the cut ({cut:?}) must still be signed for now ({anchor:?}) — \
         the successor came up more than a validity window after its predecessor terminated",
    );
    Arc::new(build_probe_transfer_tx(range))
}

/// How far before the cut [`build_precut_probe`] opens its window. Any
/// positive lead makes the probe pre-cut; a small one leaves the most of
/// the window for the successor to resolve it in.
const PRECUT_LEAD_MS: u64 = 1_000;

/// How long [`build_precut_probe`]'s window stays open — the validity
/// budget less the slack a window built against one clock needs to stay
/// well formed at an anchor trailing it.
const PRECUT_PROBE_LIFE: Duration = MAX_VALIDITY_RANGE.saturating_sub(Duration::from_secs(15));

/// A transaction the terminating shard never committed reaches an outcome
/// on a successor, while one it did commit is still refused.
///
/// Both candidates come from one train, so the successor is shown to
/// separate them rather than merely to refuse everything (which a
/// successor that never resolves anything also does) or admit everything
/// (which one with no rule at all does). Both opened before the cut: the
/// replay because its shard committed it, the stranded one because it was
/// submitted no later.
///
/// The stranded probe is the population the pre-cut rule strands. Nothing
/// the successor holds can tell it from a replay — its own chain never saw
/// either — so admitting it takes an absence proof against the
/// predecessor's `committed_txs_root`, fetched from the departed
/// committee. Without that the successor defers forever and the
/// transaction never reaches an outcome anywhere.
///
/// Requires [`probe_train_genesis_accounts`] funding and a config with
/// `split_bytes = 0` and one cohort of pool surplus.
///
/// # Panics
///
/// Panics if any lifecycle stage misses its budget, if the train yields
/// no candidate of either kind, if the stranded transaction reaches no
/// outcome, or if the replay commits.
pub fn split_boundary_admits_an_uncommitted_precut_tx(c: &mut impl Cluster) {
    let root = ShardId::ROOT;
    let (left, right) = root.children();

    let world = probe_world(c);
    let mut charges = Charges::default();
    let spacing = measure_probe_spacing(c, &mut charges, root);
    assert!(
        await_split_admitted(c, root, epochs(8)),
        "beacon did not admit the root split within budget"
    );
    let probes = run_probe_train(c, &mut charges, root, spacing, |c| {
        [left, right].iter().all(|&child| shard_live(c, child))
    });
    let replay = pick_replay(c, root, &probes);
    let stranded = build_precut_probe(c, left);
    let (replayed, stranded_hash) = (replay.hash(), charges.record(&stranded));

    c.submit(replay);
    c.submit(stranded);
    assert!(
        c.run_until(epochs(8), |c| [left, right]
            .iter()
            .any(|&child| c.chain_fate(child, stranded_hash).1.is_some())),
        "{stranded_hash} opened before the cut and no predecessor ever committed it, \
         so a successor proving it absent must carry it to an outcome",
    );

    for child in [left, right] {
        assert!(
            c.chain_fate(child, replayed).0.is_none(),
            "child {child} committed {replayed}, which its parent had already committed",
        );
    }
    world.assert_settles_within(
        c,
        &charges,
        epochs(8),
        "a probe train, a replay and a stranded probe",
    );
}

/// `shard`'s committed height as a plain number, zero before it commits.
fn committed_height<C: Cluster>(c: &C, shard: ShardId) -> u64 {
    c.committed_height(shard).map_or(0, BlockHeight::inner)
}

/// Grow the root into two shards, then merge the two cold children back into it.
///
/// Composes [`split_lifecycle`] for the grow, then votes the reshape threshold
/// up so the children fall under the derived merge threshold — a grown topology
/// can't merge under the frozen threshold that split it, so the vote is the
/// honest trigger. The beacon pairs the merge and draws the keeper committee,
/// the keepers seat the reformed parent, and its committed root reproduces the
/// beacon-composed anchor. Requires a config with `split_bytes = 0`, one cohort
/// of pool surplus, and a funded straddler account (`31`) to pay the vote.
///
/// # Panics
///
/// Panics if any lifecycle stage misses its budget.
pub fn merge_lifecycle(c: &mut impl Cluster) {
    let root = ShardId::ROOT;

    split_lifecycle(c);

    // Vote the reshape threshold up so the cold grown children fall under the
    // derived merge threshold. The straddler account `31`, funded at genesis and
    // seated on a child by the grow, pays the system-action fee.
    vote_reshape_threshold(c, MERGE_VOTE_SPLIT_BYTES);

    // The vote activates, both children assert the merge, and the beacon pairs
    // it — drawing a quorum (2f+1 of the four-validator merged committee).
    assert!(
        await_merge_keeper_count(c, root, 3, epochs(20)),
        "the merge did not pair a keeper quorum within budget"
    );
    // The keepers seat the reformed parent, which commits past its merged
    // genesis at the beacon-composed anchor root.
    assert!(
        await_serves(c, root, epochs(28)),
        "the merged parent was not served within budget"
    );
    assert!(
        await_height(c, root, 1, epochs(8)),
        "the merged parent did not commit past genesis within budget"
    );
    assert!(
        await_root_matches_anchor(c, root, epochs(8)),
        "the merged root did not match the beacon anchor within budget"
    );
}

/// A transaction a terminating shard admitted and never included still
/// reaches an outcome, without the client resubmitting it.
///
/// The terminal sweep reaches only what the chain *committed*, so a
/// `Pending` entry has nowhere left to go and its client's last word is
/// the `Pending` it got on submission.
///
/// The probe's window opens after the cut, so the parent admits it and
/// can never include it — its terminal precedes the window. That is a
/// `Pending` entry in a pool about to die, arrived at by construction
/// rather than by racing the terminal. Nothing here resubmits it, so the
/// only path from the parent's pool to a child's is the handback.
///
/// Deliberately *not* pre-cut: this isolates the handback from the
/// committed-set query, which resolves a different population.
///
/// Requires a config with `split_bytes = 0` and one cohort of pool
/// surplus, plus funding for one probe.
///
/// # Panics
///
/// Panics if the split misses its budget, if the parent included the
/// probe after all (which would make the assertion vacuous), or if the
/// probe reaches no outcome on either child.
pub fn split_boundary_hands_back_what_it_never_included(c: &mut impl Cluster) {
    let root = ShardId::ROOT;
    let (left, right) = root.children();

    assert!(
        await_split_admitted(c, root, epochs(8)),
        "beacon did not admit the root split within budget"
    );
    // Admission is not the cut. The readiness gate stamps which epoch the
    // parent terminates on, and only then can a window be built that the
    // parent provably cannot reach.
    assert!(
        c.run_until(epochs(12), |c| scheduled_terminal_epoch(c, root).is_some()),
        "the split's cut was not scheduled within budget",
    );

    let world = probe_world(c);
    let mut charges = Charges::default();
    let probe = build_post_cut_probe(c, root);
    let hash = charges.record(&probe);
    c.submit(probe);

    assert!(
        c.run_until(epochs(28), |c| [left, right]
            .iter()
            .all(|&child| shard_live(c, child))),
        "split children were not live within budget",
    );
    assert!(
        c.chain_fate(root, hash).0.is_none(),
        "the parent included {hash}, so it never sat unincluded in the dying pool \
         and the handback assertion would be vacuous",
    );

    assert!(
        c.run_until(epochs(12), |c| [left, right]
            .iter()
            .any(|&child| c.chain_fate(child, hash).1.is_some())),
        "{hash} was admitted to the parent's pool and never included, so the handback \
         must carry it to a successor — nothing else can, and nothing resubmitted it",
    );
    world.assert_settles_within(c, &charges, epochs(8), "a handed-back probe");
}

/// A probe whose validity window opens after `parent`'s scheduled cut, so
/// the parent admits it and can never include it.
///
/// Built from the cut the beacon has stamped rather than from a lead
/// guessed off the admitting epoch: a reshape runs however many epochs
/// its readiness gate takes, so no fixed lead clears the cut on every
/// topology.
///
/// # Panics
///
/// Panics if the beacon has not scheduled `parent`'s cut yet.
fn build_post_cut_probe(c: &impl Cluster, parent: ShardId) -> Arc<Transaction> {
    let terminal = scheduled_terminal_epoch(c, parent).expect("the cut is scheduled");
    let epoch_ms = epoch_duration_ms(c).expect("a scheduled cut implies a committed beacon");
    // The epoch after the parent's last: its chain has ended by then, and
    // its successors are the only thing that can include this.
    let opens = terminal.inner().saturating_add(1).saturating_mul(epoch_ms);
    let range = TimestampRange::new(
        WeightedTimestamp::from_millis(opens),
        WeightedTimestamp::from_millis(opens).plus(POST_CUT_PROBE_LIFE),
    );
    Arc::new(build_probe_transfer_tx(range))
}

/// How long [`build_post_cut_probe`]'s window stays open — the validity
/// budget less the slack a window needs to stay well formed against an
/// anchor trailing the clock it was built on.
const POST_CUT_PROBE_LIFE: Duration = MAX_VALIDITY_RANGE.saturating_sub(Duration::from_secs(15));

/// The same separation across a merge, where the successor has two
/// predecessors instead of one.
///
/// A merged parent may admit a pre-cut transaction only once it is absent
/// from **both** children's committed sets — a proof from one says nothing
/// about what the other committed. The probes land on whichever child
/// holds their payer, so the stranded one is answered by that child and by
/// its sibling, which never saw it at all; admitting it takes both.
///
/// Requires the [`merge_lifecycle`] preconditions plus
/// [`probe_train_genesis_accounts`] funding.
///
/// # Panics
///
/// Panics if any lifecycle stage misses its budget, if the train yields no
/// candidate of either kind, if the stranded transaction reaches no
/// outcome on the reformed parent, or if the replay commits there.
pub fn merge_boundary_admits_an_uncommitted_precut_tx(c: &mut impl Cluster) {
    let root = ShardId::ROOT;

    split_lifecycle(c);
    vote_reshape_threshold(c, MERGE_VOTE_SPLIT_BYTES);
    assert!(
        await_merge_keeper_count(c, root, 3, epochs(20)),
        "the merge did not pair a keeper quorum within budget"
    );

    // The probes all share a payer, so they land on one child; the
    // reformed parent succeeds both regardless, and the sibling that
    // never saw them is the second answer it has to collect.
    let world = probe_world(c);
    let mut charges = Charges::default();
    let payer_child = probe_payer_shard(c, &mut charges, root);
    let spacing = measure_probe_spacing(c, &mut charges, payer_child);
    // The reformed parent reclaims a shard id its own predecessor held,
    // so serving is no signal. Its height line continues from the taller
    // child, so passing the child it succeeds is: nothing the departed
    // root chain froze at can reach there.
    let probes = run_probe_train(c, &mut charges, payer_child, spacing, |c| {
        c.serves_shard(root) && committed_height(c, root) > committed_height(c, payer_child)
    });

    let replay = pick_replay(c, payer_child, &probes);
    let stranded = build_precut_probe(c, root);
    let (replayed, stranded_hash) = (replay.hash(), charges.record(&stranded));

    c.submit(replay);
    c.submit(stranded);
    assert!(
        c.run_until(epochs(8), |c| c.chain_fate(root, stranded_hash).1.is_some()),
        "{stranded_hash} opened before the cut and neither child committed it, \
         so the merged parent proving it absent from both must carry it to an outcome",
    );
    assert!(
        c.chain_fate(root, replayed).0.is_none(),
        "the merged parent committed {replayed}, which one of its children had already committed",
    );
    world.assert_settles_within(c, &charges, epochs(8), "a probe train across a merge");
}

/// Which of `parent`'s children the probe payer's account sits under.
///
/// Determined by where a probe actually commits rather than by deriving
/// the prefix, so it holds however the trie assigns the account.
///
/// # Panics
///
/// Panics if neither child commits a probe within budget.
fn probe_payer_shard(c: &mut impl Cluster, charges: &mut Charges, parent: ShardId) -> ShardId {
    let (left, right) = parent.children();
    let probe = Arc::new(build_probe_transfer_tx(validity_around(c.now())));
    let hash = charges.record(&probe);
    c.submit(probe);
    assert!(
        c.run_until(epochs(4), |c| [left, right]
            .iter()
            .any(|&child| c.chain_fate(child, hash).0.is_some())),
        "no child committed a probe, so the payer's shard cannot be located",
    );
    if c.chain_fate(left, hash).0.is_some() {
        left
    } else {
        right
    }
}

/// Merge two cold children back into the root and assert the reformed parent
/// seats a full keeper committee that keeps committing past its merged genesis.
///
/// Composes [`merge_lifecycle`] (grow → vote → keepers paired → reformed parent
/// served → anchor matched), then layers the seating outcome: the keeper set —
/// half of each child's committee — seats a full committee on the parent, which
/// then commits a real block past its merged genesis (the lifecycle's anchor
/// match only requires the merged genesis block itself). Requires the
/// [`merge_lifecycle`] preconditions.
///
/// # Panics
///
/// Panics if the merge misses its budget, the reformed parent is under committee
/// strength, or it stalls at its merged genesis.
pub fn merge_seats_full_keeper_committee(c: &mut impl Cluster) {
    assert!(
        await_beacon_epoch(c, 1, epochs(6)),
        "the beacon must fold before the grow so the genesis committee strength is known",
    );
    let strength = committee_size(c, ShardId::ROOT).expect("genesis seats the root committee");

    merge_lifecycle(c);

    let root = ShardId::ROOT;
    assert!(
        c.run_until(epochs(6), |c| committee_size(c, root) == Some(strength)),
        "the reformed parent must seat a full keeper committee of {strength}",
    );

    // A committed-height probe can transiently read `None` while a vnode's
    // serving surface hands over, so wait the height into view before
    // taking the base.
    assert!(
        c.run_until(epochs(2), |c| c.committed_height(root).is_some()),
        "the reformed parent must report a committed height",
    );
    let base = c
        .committed_height(root)
        .expect("the reformed parent commits");
    assert!(
        c.run_until(epochs(6), |c| c
            .committed_height(root)
            .is_some_and(|h| h > base)),
        "the reformed parent must keep committing past its merged genesis",
    );
}
