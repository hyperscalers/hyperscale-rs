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

use crate::query::{beacon_epoch, split_admitted};
use crate::reshape::split_lifecycle;
use crate::tx::{
    STRADDLER_SPLITTER, STRADDLER_SURVIVOR, build_reshape_threshold_vote_tx, build_transfer_tx,
    split_straddler_setup, validity_around,
};
use crate::wait::{await_serves, await_split_admitted, await_tx_terminal};
use crate::{Cluster, epochs};

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

    assert_fence_held(c, splitter, terminal_b, &probes);
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
    let mut consistent = 0u32;
    let mut doomed = 0u32;
    let mut one_sided = 0u32;
    let mut mismatch = 0u32;
    let mut report = String::new();

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
            report,
            "\n  #{idx}: splitter settled={settled:?}; survivor verdict={verdict:?}",
        );
        match (settled, verdict) {
            (Some(t), Some(v)) if t == v => consistent += 1,
            (Some(_), Some(_)) => mismatch += 1,
            (None, Some(TransactionDecision::Aborted)) => doomed += 1, // correctly aborted
            (None, Some(_)) => one_sided += 1,
            (_, None) => {} // unresolved — the terminal-verdict gate caught it
        }
    }
    let _ = write!(report, "\n  consistent={consistent} doomed={doomed}");

    assert_eq!(
        one_sided, 0,
        "the survivor applied a straddler the splitter never settled — one-sided:{report}",
    );
    assert_eq!(
        mismatch, 0,
        "the survivor's verdict contradicted the splitter's settlement:{report}",
    );
    assert!(
        consistent > 0,
        "no straddler settled atomically — submission timing needs retuning:{report}",
    );
}
