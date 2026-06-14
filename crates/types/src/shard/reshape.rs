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

use sbor::prelude::*;

use crate::{ShardId, ShardWitnessPayload};

/// Substate-byte thresholds driving automatic shard reshaping.
///
/// Ships disabled ([`Self::DISABLED`]) — the predicate can never fire —
/// until a network explicitly configures a split threshold. The merge
/// threshold is derived, not configured: at an eighth of the split
/// threshold, a fresh child (≈ half the split threshold) is far from
/// merge-eligible and a fresh merge (≤ a quarter of it) is far from
/// split-eligible, so reshapes cannot oscillate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub struct ReshapeThresholds {
    /// Committed substate byte total at or above which a shard asserts a
    /// split. `u64::MAX` disables reshaping entirely.
    pub split_bytes: u64,
}

impl ReshapeThresholds {
    /// Reshaping disabled: neither trigger can ever fire.
    pub const DISABLED: Self = Self {
        split_bytes: u64::MAX,
    };

    /// Committed substate byte total below which a shard asserts a merge
    /// with its sibling. Zero (never fires) when reshaping is disabled
    /// — a byte total is never negative, so `bytes < 0` is unsatisfiable.
    #[must_use]
    pub const fn merge_bytes(&self) -> u64 {
        if self.split_bytes == u64::MAX {
            0
        } else {
            self.split_bytes / 8
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
/// Only the kind rides the wire — the subject is always the asserting
/// shard itself, so the full payload reconstructs from the shard id and
/// cannot be pointed at another shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub enum ReshapeTrigger {
    /// The shard's committed substate byte total reached the split threshold.
    Split,
    /// The shard's committed substate byte total fell below the merge
    /// threshold; the assertion targets the shard's parent (merging the
    /// shard with its sibling).
    Merge,
}

impl ReshapeTrigger {
    /// Project the assertion into its witness payload for `shard`.
    ///
    /// Returns `None` for a merge asserted by the root shard — it has
    /// no parent to merge under, so the assertion is structurally
    /// invalid and verification rejects it as a predicate mismatch.
    #[must_use]
    pub fn to_payload(self, shard: ShardId) -> Option<ShardWitnessPayload> {
        match self {
            Self::Split => Some(ShardWitnessPayload::ScheduleSplit { shard }),
            Self::Merge => shard
                .parent()
                .map(|parent| ShardWitnessPayload::ScheduleMerge { parent }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_thresholds_never_fire() {
        // Split needs count == u64::MAX (impossible); merge needs
        // count < 0 (unsatisfiable).
        assert_eq!(ReshapeThresholds::DISABLED.merge_bytes(), 0);
    }

    #[test]
    fn merge_threshold_is_an_eighth_of_split() {
        let t = ReshapeThresholds { split_bytes: 8_000 };
        assert_eq!(t.merge_bytes(), 1_000);
    }

    #[test]
    fn split_payload_targets_the_asserting_shard() {
        let shard = ShardId::leaf(2, 0b10);
        assert_eq!(
            ReshapeTrigger::Split.to_payload(shard),
            Some(ShardWitnessPayload::ScheduleSplit { shard }),
        );
    }

    #[test]
    fn merge_payload_targets_the_parent_and_root_has_none() {
        let shard = ShardId::leaf(2, 0b10);
        assert_eq!(
            ReshapeTrigger::Merge.to_payload(shard),
            Some(ShardWitnessPayload::ScheduleMerge {
                parent: shard.parent().unwrap(),
            }),
        );
        assert_eq!(ReshapeTrigger::Merge.to_payload(ShardId::ROOT), None);
    }

    #[test]
    fn reshape_trigger_sbor_round_trip() {
        for t in [ReshapeTrigger::Split, ReshapeTrigger::Merge] {
            let bytes = basic_encode(&t).unwrap();
            assert_eq!(basic_decode::<ReshapeTrigger>(&bytes).unwrap(), t);
        }
    }
}
