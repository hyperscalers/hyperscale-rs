//! Shard reshape (split/merge) trigger types.
//!
//! A shard reshapes automatically from its own attested load: when the
//! committed substate byte total crosses [`ReshapeThresholds::split_bytes`]
//! the shard asserts a split, and when it falls below the merge
//! threshold the shard asserts a merge with its sibling. The assertion
//! rides the block manifest as a [`ReshapeTrigger`] and projects into a
//! `ShardWitnessPayload` trigger leaf; replicas recompute the predicate
//! from their own state and reject a manifest whose claim diverges, so
//! a committed trigger carries the committee's quorum behind the load
//! fact. The beacon folds the witness and schedules the reshape.

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::BASIS_POINTS;

use crate::{Epoch, ShardId, ShardWitnessPayload};

/// The thresholds driving automatic shard reshaping: what a shard holds
/// and what its blocks have been spending.
///
/// Two ways to be too big, because there are two ways to be. A shard
/// holding more state than one committee should serve splits on
/// [`split_bytes`](Self::split_bytes); one whose blocks have been
/// running near their caps splits on
/// [`split_fullness`](Self::split_fullness), whatever it holds. The
/// second is the answer to a hot shard among idle ones, which the price
/// table cannot see: the level moves on the network's mean, so capacity
/// is what a hotspot is owed rather than a price every other sender
/// pays.
///
/// Ships disabled ([`Self::DISABLED`]) — neither predicate can fire —
/// until a network explicitly configures them. The merge threshold is
/// derived, not configured: at an eighth of the split threshold, a fresh
/// child (≈ half the split threshold) is far from merge-eligible and a
/// fresh merge (≤ a quarter of it) is far from split-eligible, so
/// reshapes cannot oscillate. Fullness has no merge side — a quiet shard
/// merges on what it holds, and merging on idleness would retire a shard
/// whose state still needs serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct ReshapeThresholds {
    /// Committed substate byte total at or above which a shard asserts a
    /// split. `u64::MAX` disables the byte predicate.
    pub split_bytes: u64,
    /// The share of its block caps a shard's blocks may average, in
    /// basis points, before it asserts a split. A figure past
    /// [`BASIS_POINTS`](hyperscale_vm_types::BASIS_POINTS) disables the
    /// fullness predicate.
    ///
    /// Read against the mean the beacon keeps per shard and per
    /// dimension, so what trips it is sustained load in any one
    /// dimension rather than a busy epoch in all of them.
    pub split_fullness: u32,
}

impl ReshapeThresholds {
    /// Reshaping disabled: no predicate can ever fire.
    pub const DISABLED: Self = Self {
        split_bytes: u64::MAX,
        split_fullness: u32::MAX,
    };

    /// Committed substate byte total below which a shard asserts a merge
    /// with its sibling. Zero (never fires) when reshaping is disabled
    /// — a byte total is never negative, so `bytes < 0` is unsatisfiable.
    #[must_use]
    pub(crate) const fn merge_bytes(&self) -> u64 {
        if self.split_bytes == u64::MAX {
            0
        } else {
            self.split_bytes / 8
        }
    }

    /// The share of its caps a shard's blocks must be under to assert a
    /// merge, on the terms [`merge_bytes`](Self::merge_bytes) states:
    /// the split threshold's eighth, so a shard does not merge at the
    /// load it would split at and oscillate.
    ///
    /// The whole range where the fullness predicate is disabled — a
    /// shard nobody measures traffic on merges on its bytes alone,
    /// which is what the byte predicate meant before there was a second
    /// one.
    ///
    /// Read beside the bytes and not instead of them: a merged parent
    /// starts at [`ShardFullness::IDLE`](crate::ShardFullness::IDLE), so
    /// it cannot assert a split back for `FULLNESS_EPOCHS` however hot
    /// it runs — and a compute-bound workload over a small account set
    /// is exactly the shape that is busy enough to matter and small
    /// enough to qualify on bytes.
    #[must_use]
    pub(crate) const fn merge_fullness(&self) -> u32 {
        if self.split_fullness > BASIS_POINTS {
            u32::MAX
        } else {
            self.split_fullness / 8
        }
    }
}

impl Default for ReshapeThresholds {
    fn default() -> Self {
        Self::DISABLED
    }
}

/// A block's reshape assertion, carried on the manifest.
///
/// The subject never rides the wire — it is always the asserting shard
/// itself, so the payload cannot be pointed at another shard. The epoch
/// does, because a reader reconstructing a past block's leaves has only
/// the block, and recovering which epoch it asserted in from its
/// ancestry would be a second derivation of a fact the block can simply
/// state. A proposer stating it wrongly is refused the same way a
/// proposer stating the wrong kind is: verifiers recompute the whole
/// assertion and reject anything but equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub enum ReshapeTrigger {
    /// The shard's committed substate byte total reached the split threshold.
    Split {
        /// The epoch the assertion was made in — see
        /// [`ShardWitnessPayload::ScheduleSplit`](crate::ShardWitnessPayload::ScheduleSplit).
        epoch: Epoch,
    },
    /// The shard's committed substate byte total fell below the merge
    /// threshold; the assertion targets the shard's parent (merging the
    /// shard with its sibling).
    Merge {
        /// The epoch the assertion was made in.
        epoch: Epoch,
    },
}

impl ReshapeTrigger {
    /// The epoch the assertion was made in.
    #[must_use]
    pub const fn epoch(self) -> Epoch {
        match self {
            Self::Split { epoch } | Self::Merge { epoch } => epoch,
        }
    }

    /// Project the assertion into its witness payload for `shard`.
    ///
    /// Returns `None` for a merge asserted by the root shard — it has
    /// no parent to merge under, so the assertion is structurally
    /// invalid and verification rejects it as a predicate mismatch.
    #[must_use]
    pub(crate) fn to_payload(self, shard: ShardId) -> Option<ShardWitnessPayload> {
        match self {
            Self::Split { epoch } => Some(ShardWitnessPayload::ScheduleSplit { shard, epoch }),
            Self::Merge { epoch } => shard
                .parent()
                .map(|parent| ShardWitnessPayload::ScheduleMerge { parent, epoch }),
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    #[test]
    fn disabled_thresholds_never_fire() {
        // Split needs count == u64::MAX (impossible); merge needs
        // count < 0 (unsatisfiable).
        assert_eq!(ReshapeThresholds::DISABLED.merge_bytes(), 0);
    }

    #[test]
    fn merge_threshold_is_an_eighth_of_split() {
        let t = ReshapeThresholds {
            split_bytes: 8_000,
            split_fullness: u32::MAX,
        };
        assert_eq!(t.merge_bytes(), 1_000);
    }

    #[test]
    fn split_payload_targets_the_asserting_shard() {
        let shard = ShardId::leaf(2, 0b10);
        let epoch = Epoch::new(4);
        assert_eq!(
            ReshapeTrigger::Split { epoch }.to_payload(shard),
            Some(ShardWitnessPayload::ScheduleSplit { shard, epoch }),
        );
    }

    #[test]
    fn merge_payload_targets_the_parent_and_root_has_none() {
        let shard = ShardId::leaf(2, 0b10);
        let epoch = Epoch::new(4);
        assert_eq!(
            ReshapeTrigger::Merge { epoch }.to_payload(shard),
            Some(ShardWitnessPayload::ScheduleMerge {
                parent: shard.parent().unwrap(),
                epoch,
            }),
        );
        assert_eq!(
            ReshapeTrigger::Merge { epoch }.to_payload(ShardId::ROOT),
            None
        );
    }

    #[test]
    fn one_assertion_per_epoch_is_a_distinct_leaf() {
        let shard = ShardId::leaf(2, 0b10);
        let at = |epoch: u64| {
            ReshapeTrigger::Split {
                epoch: Epoch::new(epoch),
            }
            .to_payload(shard)
            .expect("a split always projects")
            .leaf_hash()
        };
        assert_eq!(at(4), at(4), "one epoch's assertion is one leaf");
        assert_ne!(
            at(4),
            at(5),
            "an assertion the beacon did not act on must not silence the next epoch's",
        );
    }

    #[test]
    fn reshape_trigger_hbor_round_trip() {
        let epoch = Epoch::new(4);
        for t in [
            ReshapeTrigger::Split { epoch },
            ReshapeTrigger::Merge { epoch },
        ] {
            let bytes = hbor_to_vec(&t).unwrap();
            assert_eq!(hbor_from_slice::<ReshapeTrigger>(&bytes).unwrap(), t);
        }
    }
}
