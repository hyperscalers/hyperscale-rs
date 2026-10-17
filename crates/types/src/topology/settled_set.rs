//! The split-boundary settled-set predicate.
//!
//! When a shard `P` splits, its chain terminates at a terminal block `B`.
//! A cross-shard transaction's `P`-half settles only if `P` committed the
//! certificate covering it by `B` — otherwise one side of the transaction
//! would apply without the other. `S_P` is the set of transactions `P`
//! settled by `B`; a surviving counterpart reconstructs it from `P`'s tail
//! chain.
//!
//! This module holds the shared predicate both sides apply: the shard
//! coordinator's pre-vote fence (a block carrying such a transaction votes
//! only if every past-terminal outcome is settled) and the execution
//! coordinator's finalize-hygiene gate (don't even produce a finalization
//! the fence would reject). Keeping one predicate keeps the two verdicts
//! from drifting — a disagreement would let a gate produce what the fence
//! rejects.

use std::collections::BTreeSet;

use crate::{
    BlockHash, BlockHeight, SettledTxsRoot, ShardId, TopologySchedule, TxHash, WeightedTimestamp,
    WindowLookup,
};

/// What a survivor needs to acquire a departed shard's settled set: the
/// terminal to ask for and the root the answer must recompute to.
///
/// Every field is read off the node's own beacon fold — the terminal
/// anchor's height, hash and attested root from the boundary record, the
/// cut from the schedule's window grid — so nothing here is fetched and
/// nothing here is trusted. It is the key the acquisition is tracked
/// under: a revised terminal is a different key, and how long the answer
/// stays wanted is decided by whoever derives the wanted set, not
/// stamped here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TerminalEvidence {
    /// The departed shard.
    pub shard: ShardId,
    /// Height of the departed shard's terminal block, naming the window
    /// end the serve reconstructs from.
    pub height: BlockHeight,
    /// Hash of the terminal block — which terminal this targets, so a
    /// revised one replaces rather than duplicates.
    pub block_hash: BlockHash,
    /// The terminal cut's weighted timestamp.
    pub terminal_wt: WeightedTimestamp,
    /// The beacon-attested `settled_txs_root` a fetched list must
    /// recompute to.
    pub attested_root: SettledTxsRoot,
}

/// A terminated shard's settled-transaction set.
///
/// `txs` are the **cross-shard** transactions whose certificate committed
/// in its chain at or before its terminal block — the only ones a
/// counterpart fence ever queries. `terminal_wt` is the weighted timestamp
/// at which the shard terminated. How long the set stays readable is not
/// carried here: the evidence window is derived from the schedule at each
/// judgment ([`TopologySchedule::terminal_evidence_readable`]), because a
/// value stamped at acquisition can differ between replicas that acquired
/// at different moments relative to the beacon's handoff-complete stamp.
#[derive(Clone, Debug)]
pub struct SettledTxSet {
    /// Cross-shard transactions the terminated shard settled by its
    /// terminal block.
    pub txs: BTreeSet<TxHash>,
    /// The terminal block's weighted timestamp.
    pub terminal_wt: WeightedTimestamp,
}

/// What a partner shard's evidence says at a judging anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// The shard is live, and `terminating` where it is scheduled to
    /// leave.
    Live {
        /// Whether an admitted reshape or a coast takes it out.
        terminating: bool,
    },
    /// It has departed and its settled set can still be read.
    Readable,
    /// Its settled set can never be read at this anchor: the anchor's
    /// window is evicted or carries no boundary record for it, or its
    /// handoff is stamped and aged past the evidence window.
    Unreadable,
    /// The judging anchor's window is not yet committed.
    Unknown,
}

/// What `shard`'s evidence says at `anchored_wt`.
///
/// Read off the anchor's own window and nothing older, so two replicas
/// answer alike however many windows each retains: the window's trie says
/// whether the shard is live, and its boundary record, where the beacon's
/// handoff-complete stamp lands, whether a departed one can still be
/// read. An anchor exactly on the shard's cut falls in the window the cut
/// opens and reads the shard as departed. The one reading behind the
/// settled-set fence and every licence that turns on a partner no longer
/// being able to answer.
#[must_use]
pub fn partner_evidence(
    topology_schedule: &TopologySchedule,
    shard: ShardId,
    anchored_wt: WeightedTimestamp,
) -> Evidence {
    let window = match topology_schedule.lookup(anchored_wt) {
        WindowLookup::Window(window) => window,
        WindowLookup::NotYetCommitted => return Evidence::Unknown,
        // Below the schedule floor nothing about the window is readable.
        WindowLookup::Evicted => return Evidence::Unreadable,
    };
    if window.shard_trie().contains(shard) {
        return Evidence::Live {
            terminating: topology_schedule.termination_scheduled(shard, anchored_wt),
        };
    }
    if window.evidence_readable(shard, anchored_wt, topology_schedule.windows()) {
        Evidence::Readable
    } else {
        Evidence::Unreadable
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::Arc;

    use super::*;
    use crate::{
        BeaconWitnessLeafCount, Epoch, EpochWindows, Hash, NetworkDefinition, ShardAnchor,
        StateRoot, TERMINAL_EVIDENCE_EPOCHS, TopologySnapshot, ValidatorSet,
    };

    const LOCAL: ShardId = ShardId::leaf(1, 0);
    const PEER: ShardId = ShardId::leaf(1, 1);

    const EPOCH_MS: u64 = 300_000;
    /// The cut PEER terminates at: the close of the window it last lives in.
    const CUT_MS: u64 = EPOCH_MS;

    fn wt(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    fn snap(leaves: &[ShardId], cut: &[(ShardId, u64)]) -> Arc<TopologySnapshot> {
        snap_departed(leaves, cut, &[])
    }

    /// [`snap`] carrying a terminal boundary record per departed shard, as
    /// every projected snapshot does while the beacon retains the record.
    /// `handoff_complete: None` is an open evidence window.
    fn snap_departed(
        leaves: &[ShardId],
        cut: &[(ShardId, u64)],
        departed: &[(ShardId, Option<Epoch>)],
    ) -> Arc<TopologySnapshot> {
        let boundaries: BTreeMap<ShardId, ShardAnchor> = departed
            .iter()
            .map(|(shard, handoff_complete)| {
                (
                    *shard,
                    ShardAnchor {
                        state_root: StateRoot::ZERO,
                        block_hash: BlockHash::from_raw(Hash::from_bytes(b"terminal")),
                        height: BlockHeight::new(9),
                        weighted_timestamp: wt(CUT_MS),
                        witness_base: BeaconWitnessLeafCount::ZERO,
                        terminal_settled_txs: None,
                        handoff_complete: *handoff_complete,
                        terminal_epoch: None,
                    },
                )
            })
            .collect();
        Arc::new(
            TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &ValidatorSet::new(Vec::new()),
                leaves.iter().map(|s| (*s, Vec::new())).collect(),
                HashMap::new(),
                boundaries,
                HashMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
            )
            .with_scheduled_terminals(cut.iter().map(|(s, e)| (*s, Epoch::new(*e))).collect()),
        )
    }

    /// PEER lives in window 0 and terminates at its close; its children hold
    /// the keyspace from window 1 on. The handoff stamp is the caller's:
    /// `None` holds the evidence window open.
    fn peer_terminated_stamped(handoff_complete: Option<Epoch>) -> TopologySchedule {
        let (left, right) = PEER.children();
        let mut sched =
            TopologySchedule::new(EPOCH_MS, Epoch::new(0), snap(&[LOCAL, PEER], &[(PEER, 0)]));
        // Retained well past the whole evidence window, so an anchor inside
        // it resolves a window rather than falling off the head.
        let post = snap_departed(&[LOCAL, left, right], &[], &[(PEER, handoff_complete)]);
        for epoch in 1..=TERMINAL_EVIDENCE_EPOCHS * 3 {
            sched.insert(Epoch::new(epoch), Arc::clone(&post));
        }
        sched
    }

    fn peer_terminated() -> TopologySchedule {
        peer_terminated_stamped(None)
    }

    /// A set for PEER carrying `txs`, readable for the terminal-evidence
    /// window past the cut — what the acquisition stamps on it.
    /// The window that decides counts from the beacon's handoff-complete
    /// stamp on the judging anchor's snapshot, not from the cut. Before the
    /// stamp the window is open — a slow seeding or a partition cannot age
    /// the evidence out from under the survivor still trying to read it —
    /// and once stamped it closes the evidence window later.
    #[test]
    fn the_evidence_window_counts_from_the_handoff_stamp() {
        assert_eq!(
            partner_evidence(
                &peer_terminated(),
                PEER,
                wt(CUT_MS + EPOCH_MS * (TERMINAL_EVIDENCE_EPOCHS + 2)),
            ),
            Evidence::Readable,
            "an open window reads however late the anchor",
        );

        let handoff = Epoch::new(2);
        let stamped = peer_terminated_stamped(Some(handoff));
        let expiry = EpochWindows::new(EPOCH_MS).handoff_evidence_expiry(handoff);
        assert_eq!(
            partner_evidence(&stamped, PEER, wt(expiry.as_millis())),
            Evidence::Readable,
            "readable to the last instant of the window",
        );
        assert_eq!(
            partner_evidence(&stamped, PEER, wt(expiry.as_millis() + 1)),
            Evidence::Unreadable,
            "and unreadable past it",
        );
    }

    /// A shard still live in the anchored window reads live, and
    /// terminating where its window carries an admitted terminal.
    #[test]
    fn a_shard_scheduled_to_terminate_reads_live_and_terminating() {
        assert_eq!(
            partner_evidence(&peer_terminated(), PEER, wt(0)),
            Evidence::Live { terminating: true },
            "PEER is live in window 0 and carries an admitted terminal",
        );
        assert_eq!(
            partner_evidence(&peer_terminated(), LOCAL, wt(0)),
            Evidence::Live { terminating: false },
        );
    }

    /// A departed shard is read off the judging anchor's own window, so a
    /// replica that still retains the window the shard last lived in and
    /// one that has evicted it read the same evidence.
    #[test]
    fn a_departed_shard_reads_alike_whatever_older_windows_are_retained() {
        let mut deep = peer_terminated();
        let mut shallow = peer_terminated();
        shallow.evict_below(Epoch::new(1));

        let inside = wt(CUT_MS + EPOCH_MS);
        for schedule in [&deep, &shallow] {
            assert_eq!(partner_evidence(schedule, PEER, inside), Evidence::Readable);
        }

        // A window carrying neither the shard nor its record says the
        // same on both: nothing can be read.
        let swept = snap(&[LOCAL], &[]);
        let later = Epoch::new(TERMINAL_EVIDENCE_EPOCHS * 3 + 1);
        deep.insert(later, Arc::clone(&swept));
        shallow.insert(later, swept);
        let past = wt(EPOCH_MS * later.inner());
        for schedule in [&deep, &shallow] {
            assert_eq!(partner_evidence(schedule, PEER, past), Evidence::Unreadable);
        }
    }

    /// An anchor ahead of every window this schedule holds is a lagging
    /// beacon, not a departed counterpart: the reading is unknown.
    #[test]
    fn an_anchor_in_a_window_not_yet_committed_reads_unknown() {
        let schedule = peer_terminated();
        let ahead = wt(EPOCH_MS * (TERMINAL_EVIDENCE_EPOCHS * 3 + 1));
        let (left, _) = PEER.children();

        for shard in [PEER, left] {
            assert_eq!(
                partner_evidence(&schedule, shard, ahead),
                Evidence::Unknown,
                "{shard:?}",
            );
        }
    }

    /// An anchor exactly on the cut falls in the window the cut opens,
    /// which no longer carries the shard: it reads that window's boundary
    /// record. A schedule holding only the closing window cannot say yet.
    #[test]
    fn an_anchor_on_the_cut_reads_the_boundary_record() {
        assert_eq!(
            partner_evidence(&peer_terminated(), PEER, wt(CUT_MS)),
            Evidence::Readable,
        );
        let closing_only =
            TopologySchedule::new(EPOCH_MS, Epoch::new(0), snap(&[LOCAL, PEER], &[(PEER, 0)]));
        assert_eq!(
            partner_evidence(&closing_only, PEER, wt(CUT_MS)),
            Evidence::Unknown,
        );
    }
}
