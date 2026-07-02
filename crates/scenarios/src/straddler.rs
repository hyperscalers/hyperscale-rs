//! Straddler atomicity scenarios.
//!
//! A *straddler* is a cross-shard wave whose source side commits on a shard that
//! terminates at a reshape boundary. The surviving counterpart must read the
//! terminating shard's beacon-attested settled set and settle the straddler only
//! when the terminating shard settled it by its terminal block — never one-sided,
//! and never holding a permanent lock on the ones it didn't.

use std::fmt::Write;
use std::sync::Arc;

use hyperscale_types::{
    BlockHeight, Ed25519PrivateKey, Epoch, ShardId, TransactionDecision, TransactionStatus, TxHash,
};
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;

use crate::reshape::split_lifecycle;
use crate::support::query::{beacon_epoch, committee_size, split_admitted};
use crate::support::tx::{
    MERGE_STRADDLER_LEFT, MERGE_STRADDLER_RIGHT, MERGE_STRADDLER_SURVIVOR, STRADDLER_SPLITTER,
    STRADDLER_SURVIVOR, build_reshape_threshold_vote_tx, build_transfer_tx, merge_straddler_setup,
    split_straddler_setup, validity_around,
};
use crate::support::wait::{
    await_beacon_epoch, await_merge_keeper_count, await_root_matches_anchor, await_serves,
    await_split_admitted, await_tx_terminal,
};
use crate::support::{Cluster, FaultHandle, FaultableCluster, epochs};

/// Cut every path by which `shard`'s committee obtains `peer_shard`'s execution
/// certificate, so a cross-shard wave the two share cannot finalize on `shard`'s
/// side.
///
/// Fault rules gate pushes (gossip) and request legs, never response legs, so EC
/// intake is cut on the push and on the pulls, with the correct direction per
/// leg: `peer_shard` pushes its EC by gossip (`execution.cert.batch`), and
/// `shard` pulls the EC and the finalized wave that bundles it
/// (`execution_cert.request`, `finalized_wave.request`). Provisions and headers
/// still flow, so `shard` still executes the wave and produces its own EC; it
/// just never receives `peer_shard`'s.
///
/// Faithful only with disjoint committees — if the two shards share a host, its
/// co-hosted vnodes hand the EC across in-process, which no network rule
/// intercepts.
#[must_use]
pub fn isolate_ec_intake(
    c: &mut impl FaultableCluster,
    shard: ShardId,
    peer_shard: ShardId,
) -> FaultHandle {
    let shard_hosts = c.committee_hosts(shard);
    let peer_hosts = c.committee_hosts(peer_shard);
    let handles = [
        c.drop_type_between(&peer_hosts, &shard_hosts, "execution.cert.batch"),
        c.drop_type_between(&shard_hosts, &peer_hosts, "execution_cert.request"),
        c.drop_type_between(&shard_hosts, &peer_hosts, "finalized_wave.request"),
    ];
    FaultHandle::new(move || handles.iter().map(FaultHandle::fired).sum())
}

/// Epochs of lead before the threshold vote activates.
const VOTE_ACTIVATE_LEAD: u64 = 4;

/// Reshape `split_bytes` the vote installs after the grow: between the survivor's
/// byte total and the splitter's, so only the heavier splitter crosses and
/// terminates while the survivor stays a live leaf.
const STRADDLER_SPLIT_BYTES: u64 = 500_000;

/// Verify a split straddler settles atomically across the reshape boundary.
///
/// Grows the root into two shards (the heavier `leaf(1,0)` splitter and the
/// lighter `leaf(1,1)` survivor), votes `split_bytes` down so only the splitter
/// crosses, then submits cross-shard transfers from the survivor into the
/// splitter spread across the splitter's grow — the earliest settle before its
/// terminal block, the latest name a splitter that has already terminated. After
/// the split the survivor must reach a terminal verdict on every straddler,
/// consistent with what the splitter settled: never applying one the splitter
/// never settled, never contradicting one it did, and aborting (not hanging) the
/// rest. Requires the [`split_straddler_setup`] genesis funding.
///
/// # Panics
///
/// Panics if the grow or split misses its budget, or the settled-waves fence is
/// breached (a one-sided application, a mismatch, or a hung straddler).
pub fn split_straddler_atomic(c: &mut impl Cluster) {
    let (probes, splitter, terminal_b) = split_straddler_run(c, |_| {});
    assert_fence_held(c, splitter, terminal_b, &probes);
}

/// Verify a split straddler settles atomically when the terminating splitter is
/// isolated from the survivor's execution certificate.
///
/// The same choreography as [`split_straddler_atomic`], but with the splitter's
/// EC intake cut ([`isolate_ec_intake`]) once committees stabilize: provisions
/// still flow, so the splitter executes each straddler and produces its own EC,
/// but never receives the survivor's and so settles none. The pre-boundary
/// settlement fence must hold atomicity anyway — the survivor cannot finalize a
/// straddler naming the splitter while the splitter has an admitted terminating
/// reshape, so no straddler resolves one-sided.
///
/// Requires disjoint splitter/survivor committees (no shared host), or a
/// co-hosted vnode bridges the EC across in-process, which no network rule
/// intercepts. The simulation seats these via dedicated pool hosts.
///
/// # Panics
///
/// Panics if the choreography misses its budget or any straddler resolves
/// one-sided (the survivor applies one the splitter never settled).
pub fn split_straddler_ec_partition_atomic(c: &mut impl FaultableCluster) {
    let (probes, splitter, terminal_b) = split_straddler_run(c, |c| {
        let _ = isolate_ec_intake(c, STRADDLER_SPLITTER, STRADDLER_SURVIVOR);
    });
    let one_sided = straddler_one_sided_count(c, splitter, terminal_b, &probes);
    assert_eq!(
        one_sided, 0,
        "the survivor applied {one_sided} straddler(s) one-sided the splitter never settled",
    );
}

/// The split-straddler choreography, minus the terminal assertion.
///
/// Grows, votes the threshold down, submits settling then straddling waves,
/// drives the split, and waits for every straddler to reach a terminal verdict.
/// Returns the probe hashes, the splitter shard, and its terminal block height
/// for the caller to judge. `before_settling` runs once after the split is
/// admitted (committees stable, splitter still live) and before the settling
/// waves are submitted — the seam a fault probe uses to install a rule keyed on
/// the live committees.
///
/// # Panics
///
/// Panics if the grow or split misses its budget, or a straddler never reaches
/// a terminal verdict.
pub fn split_straddler_run<C: Cluster>(
    c: &mut C,
    mut before_settling: impl FnMut(&mut C),
) -> (Vec<TxHash>, ShardId, BlockHeight) {
    let splitter = STRADDLER_SPLITTER;
    let survivor = STRADDLER_SURVIVOR;
    let (child_left, child_right) = splitter.children();
    let setup = split_straddler_setup();
    let network = NetworkDefinition::simulator();

    // Grow the root into the splitter and survivor siblings.
    split_lifecycle(c);
    assert!(
        c.serves_shard(splitter) && c.serves_shard(survivor),
        "the grow must seat both the splitter and the survivor",
    );

    // Vote the reshape threshold down so only the heavier splitter crosses.
    let payer = &setup.straddlers[0].0;
    let current = beacon_epoch(c).expect("post-grow beacon epoch");
    let vote = build_reshape_threshold_vote_tx(
        payer,
        STRADDLER_SPLIT_BYTES,
        Epoch::new(current.inner() + VOTE_ACTIVATE_LEAD),
        &network,
        1,
        validity_around(c.now()),
    );
    c.submit(Arc::new(vote));

    assert!(
        await_split_admitted(c, splitter, epochs(20)),
        "only the over-threshold splitter must admit a split",
    );
    assert!(
        !split_admitted(c, survivor),
        "the under-threshold survivor must not split",
    );

    let mut probes: Vec<TxHash> = Vec::new();

    // Fault-injection seam: committees are stable and the splitter is still
    // live, so a probe can key a rule on the live splitter/survivor committees
    // before any straddler EC crosses.
    before_settling(c);

    // Settling waves: submitted while the splitter still commits real blocks, so
    // it finalizes them before its terminal cut — they settle atomically.
    let half = setup.straddlers.len() / 2;
    for (i, (key, from, to)) in setup.straddlers.iter().take(half).enumerate() {
        let nonce = 100 + u32::try_from(i).unwrap_or(0);
        probes.push(submit_straddler(c, &network, key, *from, *to, nonce));
    }

    // Advance until the gate drains the splitter from `pending_reshapes`: the
    // settling waves finalize on it in this window, and it then coasts to its
    // terminal crossing committing only empty blocks.
    assert!(
        c.run_until(epochs(14), |c| !split_admitted(c, splitter)),
        "the splitter's split must gate within budget",
    );

    // Straddling waves: submitted all at once during the coast — the splitter is
    // still the active leaf, so the survivor provisions to it, but its empty
    // coast blocks settle nothing, leaving them in flight when it terminates.
    for (i, (key, from, to)) in setup.straddlers.iter().skip(half).enumerate() {
        let nonce = 200 + u32::try_from(i).unwrap_or(0);
        probes.push(submit_straddler(c, &network, key, *from, *to, nonce));
    }

    // The split executes: both children seat and commit past genesis.
    assert!(
        await_serves(c, child_left, epochs(28)) && await_serves(c, child_right, epochs(28)),
        "both splitter children must be served within budget",
    );

    // The splitter's terminal block sits one below the children's genesis.
    let terminal_b = c
        .beacon_state()
        .and_then(|s| s.boundaries.get(&child_left).map(|b| b.height))
        .and_then(BlockHeight::prev)
        .expect("the children's seeded genesis pins the splitter's terminal block");

    // Every straddler must reach a terminal verdict on the survivor.
    for hash in &probes {
        let status = await_tx_terminal(c, *hash, epochs(10));
        assert!(
            matches!(status, Some(TransactionStatus::Completed(_))),
            "a straddler hung on the settled-waves fence; status = {status:?}",
        );
    }

    (probes, splitter, terminal_b)
}

/// Verify a surviving sibling's second-generation split seats correctly.
///
/// Composes [`split_straddler_atomic`] (grow → vote the threshold down so only
/// the splitter crosses → settled-waves fence), then layers the seating outcome:
/// the splitter retires into two full-strength child committees while the survivor
/// keeps its own, each child's committed root reproduces the beacon-composed
/// anchor, and both children commit a real block past their seeded genesis.
/// Requires the [`split_straddler_setup`] genesis funding on a config grown from a
/// single root.
///
/// # Panics
///
/// Panics if the lifecycle misses its budget, a committee is under strength, the
/// splitter fails to retire, a child root diverges from the anchor, or a child
/// stalls at its seeded genesis.
pub fn surviving_sibling_split_seats_full_committees(c: &mut impl Cluster) {
    assert!(
        await_beacon_epoch(c, 1, epochs(6)),
        "the beacon must fold before the grow so the genesis committee strength is known",
    );
    let strength = committee_size(c, ShardId::ROOT).expect("genesis seats the root committee");

    split_straddler_atomic(c);

    let splitter = STRADDLER_SPLITTER;
    let survivor = STRADDLER_SURVIVOR;
    let (child_left, child_right) = splitter.children();
    assert!(
        c.run_until(epochs(6), |c| committee_size(c, survivor) == Some(strength)
            && committee_size(c, child_left) == Some(strength)
            && committee_size(c, child_right) == Some(strength)
            && committee_size(c, splitter).is_none()),
        "the survivor and both splitter children must seat full committees of {strength}, and the splitter must retire",
    );

    assert!(
        await_root_matches_anchor(c, child_left, epochs(8))
            && await_root_matches_anchor(c, child_right, epochs(8)),
        "both splitter children's roots must reproduce the beacon anchor",
    );

    let left_base = c
        .committed_height(child_left)
        .expect("the left child commits");
    let right_base = c
        .committed_height(child_right)
        .expect("the right child commits");
    assert!(
        c.run_until(epochs(6), |c| c
            .committed_height(child_left)
            .is_some_and(|h| h > left_base)
            && c.committed_height(child_right)
                .is_some_and(|h| h > right_base)),
        "both splitter children must keep committing past their seeded genesis",
    );
}

/// Verify a merge straddler settles atomically across the reshape boundary.
///
/// The cluster grows into four shards (the caller's `with_grown_balances`), then
/// the lighter `leaf(2, 2)`/`leaf(2, 3)` pair — funded below the derived merge
/// threshold — collapses into `leaf(1, 1)`, while the bulk-funded survivors
/// `leaf(2, 0)`/`leaf(2, 1)` stay above it and keep the left half alive: once the
/// topology is grown, the merge fires from the byte skew alone. Cross-shard
/// transfers run from the survivor `leaf(2, 0)` into the merging `leaf(2, 2)`, so
/// each wave names a shard that terminates at the merge. The first wave settles
/// before `leaf(2, 2)`'s terminal block; the second straddles it, in flight when
/// it terminates. After the merge the survivor must reach a terminal verdict on
/// every straddler, consistent with what `leaf(2, 2)` settled by its terminal
/// block — never one-sided, never contradicting a settlement, never hanging.
/// Exercises the merge-child terminal's settled-waves attestation, the path a
/// split child's terminal cannot cover. Requires the [`merge_straddler_setup`]
/// funding on a config grown to four shards.
///
/// # Panics
///
/// Panics if the merge misses its budget, the merged parent never seats, or the
/// settled-waves fence is breached (a one-sided application, a mismatch, or a
/// hung straddler).
pub fn merge_straddler_atomic(c: &mut impl Cluster) {
    let survivor = MERGE_STRADDLER_SURVIVOR;
    let merge_left = MERGE_STRADDLER_LEFT;
    let merge_right = MERGE_STRADDLER_RIGHT;
    let merge_parent = merge_left.parent().expect("a depth-2 leaf has a parent");
    let setup = merge_straddler_setup();
    let network = NetworkDefinition::simulator();

    // The cluster reaches this body grown to four shards; confirm every quarter
    // is seated and serving before driving the merge.
    assert!(
        await_serves(c, survivor, epochs(4))
            && await_serves(c, merge_left, epochs(4))
            && await_serves(c, merge_right, epochs(4))
            && await_serves(c, ShardId::leaf(2, 1), epochs(4)),
        "the grown four-shard topology must seat every quarter",
    );

    let mut probes: Vec<TxHash> = Vec::new();
    let half = setup.straddlers.len() / 2;

    // Settling waves: submitted while `leaf(2, 2)` still commits real blocks, so
    // their cross-shard 2PC can finalize at or below its terminal block and land
    // in the attested settled set. Submitted before the keeper pairing arms the
    // gate, then awaited to finalize on `leaf(2, 2)` so settlement can't lose the
    // race to the cut — a settler only needs to finalize before the terminal.
    let settling: Vec<TxHash> = setup
        .straddlers
        .iter()
        .take(half)
        .enumerate()
        .map(|(i, (key, from, to))| {
            let nonce = 100 + u32::try_from(i).unwrap_or(0);
            submit_straddler(c, &network, key, *from, *to, nonce)
        })
        .collect();
    probes.extend_from_slice(&settling);
    assert!(
        c.run_until(epochs(12), |c| settling
            .iter()
            .all(|hash| chain_settled(c, merge_left, *hash))),
        "the settling waves must finalize on the merging child before its terminal",
    );

    // The light merging pair asserts the merge from its genesis byte skew; the
    // beacon pairs it and draws a keeper quorum (2f+1 of the four-validator
    // reformed committee). The heavy survivor pair never pairs.
    assert!(
        await_merge_keeper_count(c, merge_parent, 3, epochs(24)),
        "the light merging pair must pair a keeper quorum within budget",
    );

    // Straddling waves: submitted once the merge has paired and `leaf(2, 2)` is
    // coasting to its terminal — the survivor still provisions to it, but its
    // coast blocks settle nothing, leaving them in flight when it terminates.
    for (i, (key, from, to)) in setup.straddlers.iter().skip(half).enumerate() {
        let nonce = 200 + u32::try_from(i).unwrap_or(0);
        probes.push(submit_straddler(c, &network, key, *from, *to, nonce));
    }

    // Drive the merge to fire: the keepers' ready signals collapse the children
    // into `leaf(1, 1)`, seating it in the lookahead. Gate on the reformed parent
    // appearing in the lookahead — not merely on the pending record clearing — so
    // a pairing that lapses and re-pairs under the seeded schedule isn't read as
    // the gate.
    assert!(
        c.run_until(epochs(16), |c| merge_executed(c, merge_parent)),
        "the merge must gate within budget",
    );

    // The merge executes: the reformed parent seats and commits past genesis.
    assert!(
        await_serves(c, merge_parent, epochs(28)),
        "the merged parent must be served within budget",
    );

    // The merged parent's composed boundary records its seeded genesis height,
    // folded from both children's terminals after the gate seats the placeholder
    // at `GENESIS`. Wait for the composed height (a real genesis above `GENESIS`,
    // so its predecessor — the merging child's terminal — exists).
    assert!(
        c.run_until(epochs(12), |c| merged_genesis_height(c, merge_parent)
            .and_then(BlockHeight::prev)
            .is_some()),
        "the merged parent's composed boundary must fold within budget",
    );

    // The merging child's terminal block sits one below the merged genesis.
    let terminal_b = merged_genesis_height(c, merge_parent)
        .and_then(BlockHeight::prev)
        .expect("the merged seeded genesis pins the merging child's terminal block");

    // Every straddler must reach a terminal verdict on the survivor.
    for hash in &probes {
        let status = await_tx_terminal(c, *hash, epochs(12));
        assert!(
            matches!(status, Some(TransactionStatus::Completed(_))),
            "a straddler hung on the settled-waves fence; status = {status:?}",
        );
    }

    assert_fence_held(c, merge_left, terminal_b, &probes);
}

/// Whether the merge into `parent` has executed: the reformed parent is seated
/// in the lookahead committee set and no longer pending.
fn merge_executed<C: Cluster>(c: &C, parent: ShardId) -> bool {
    c.beacon_state().is_some_and(|state| {
        !state.pending_reshapes.contains_key(&parent)
            && state.next_shard_committees.contains_key(&parent)
    })
}

/// The merged parent's seeded genesis height, from its composed boundary.
fn merged_genesis_height<C: Cluster>(c: &C, parent: ShardId) -> Option<BlockHeight> {
    c.beacon_state()
        .and_then(|state| state.boundaries.get(&parent).map(|b| b.height))
}

/// Whether `hash` finalized a non-abort decision on `shard`'s committed chain —
/// the source side of a cross-shard wave settling before a reshape terminal.
fn chain_settled<C: Cluster>(c: &C, shard: ShardId, hash: TxHash) -> bool {
    matches!(
        c.chain_fate(shard, hash).1,
        Some((_, decision)) if decision != TransactionDecision::Aborted
    )
}

/// Build a straddler transfer (survivor payer → splitter recipient) bracketing
/// the current clock, submit it, and return its hash.
fn submit_straddler<C: Cluster>(
    c: &mut C,
    network: &NetworkDefinition,
    key: &Ed25519PrivateKey,
    from: ComponentAddress,
    to: ComponentAddress,
    nonce: u32,
) -> TxHash {
    let tx = build_transfer_tx(
        key,
        from,
        to,
        Decimal::from(100),
        network,
        nonce,
        validity_around(c.now()),
    );
    let hash = tx.hash();
    c.submit(Arc::new(tx));
    hash
}

/// Assert the settled-waves fence held for `probes`: every straddler the
/// survivor reached agrees with what the splitter settled by `terminal_b`, none
/// applied one-sided or contradicted a settlement, and at least one settled
/// atomically.
fn assert_fence_held<C: Cluster>(
    c: &C,
    splitter: ShardId,
    terminal_b: BlockHeight,
    probes: &[TxHash],
) {
    let tally = straddler_tally(c, splitter, terminal_b, probes);

    assert_eq!(
        tally.one_sided, 0,
        "the survivor applied a straddler the splitter never settled — one-sided:{}",
        tally.report,
    );
    assert_eq!(
        tally.mismatch, 0,
        "the survivor's verdict contradicted the splitter's settlement:{}",
        tally.report,
    );
    assert!(
        tally.consistent > 0,
        "no straddler settled atomically — submission timing needs retuning:{}",
        tally.report,
    );
}

/// How each straddler resolved on the survivor versus what the splitter settled
/// by its terminal block.
struct StraddlerTally {
    /// Survivor verdict matched the splitter's settlement.
    consistent: u32,
    /// Splitter never settled it; survivor correctly aborted.
    doomed: u32,
    /// Survivor applied a decision the splitter never settled — a broken fence.
    one_sided: u32,
    /// Survivor's verdict contradicted the splitter's settlement.
    mismatch: u32,
    /// Per-probe detail for assertion messages.
    report: String,
}

fn straddler_tally<C: Cluster>(
    c: &C,
    splitter: ShardId,
    terminal_b: BlockHeight,
    probes: &[TxHash],
) -> StraddlerTally {
    let mut tally = StraddlerTally {
        consistent: 0,
        doomed: 0,
        one_sided: 0,
        mismatch: 0,
        report: String::new(),
    };

    for (idx, hash) in probes.iter().enumerate() {
        let (_, splitter_final) = c.chain_fate(splitter, *hash);
        // The splitter settled it iff it finalized a non-abort decision at or
        // before its terminal block.
        let settled = splitter_final
            .and_then(|(h, d)| (h <= terminal_b && d != TransactionDecision::Aborted).then_some(d));
        let verdict = match c.tx_status(*hash) {
            Some(TransactionStatus::Completed(d)) => Some(d),
            _ => None,
        };
        let _ = write!(
            tally.report,
            "\n  #{idx}: splitter settled={settled:?}; survivor verdict={verdict:?}",
        );
        match (settled, verdict) {
            (Some(t), Some(v)) if t == v => tally.consistent += 1,
            (Some(_), Some(_)) => tally.mismatch += 1,
            (None, Some(TransactionDecision::Aborted)) => tally.doomed += 1, // correctly aborted
            (None, Some(_)) => tally.one_sided += 1,
            (_, None) => {} // unresolved — the terminal-verdict gate caught it
        }
    }
    let _ = write!(
        tally.report,
        "\n  consistent={} doomed={}",
        tally.consistent, tally.doomed,
    );
    tally
}

/// The number of straddlers the survivor applied one-sided.
///
/// A one-sided straddler is one the survivor finalized on a decision the
/// splitter never settled by its terminal block. Zero when the fence holds; a
/// probe that cuts the survivor→splitter EC channel across the boundary watches
/// whether it goes positive.
#[must_use]
pub fn straddler_one_sided_count<C: Cluster>(
    c: &C,
    splitter: ShardId,
    terminal_b: BlockHeight,
    probes: &[TxHash],
) -> u32 {
    straddler_tally(c, splitter, terminal_b, probes).one_sided
}
