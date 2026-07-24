//! Live, governable network parameters and the votes that retune them.
//!
//! [`NetworkParams`] holds exactly the policy parameters a running
//! network may retune after genesis. It is seeded from the genesis
//! [`BeaconChainConfig`] and thereafter mutated only by the beacon fold
//! (a committed, stake-weighted parameter-change tally). Structural and
//! historical parameters — `genesis_timestamp_ms` — stay on the
//! immutable `chain_config` and never appear here.
//!
//! Every runtime read of a governable parameter resolves against
//! `BeaconState.params`, never `chain_config`: the genesis record and the
//! live value diverge once a parameter change folds in, so reading the
//! frozen copy would resurrect a stale threshold and fork the chain.
//!
//! A change is decided by stake pools voting. A [`ParamVote`] rides the
//! system-transaction rail as a [`BeaconWitnessEvent`](crate::BeaconWitnessEvent)
//! and folds into `BeaconState.param_votes`; each epoch the fold tallies
//! the votes and applies any [`ParamProposal`] backed by a majority of
//! total pool stake at its named activation epoch. The witness is taken
//! as ground truth — the stake pool owner's authority over the vote is
//! checked in the VM when stake pools land there, not at the beacon.

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BeaconChainConfig, Epoch, IMPOUND_EPOCHS_DEFAULT, ReshapeThresholds, StakePoolId,
    UNBONDING_WINDOW_EPOCHS,
};

/// The governable subset of a chain's parameters — the live values
/// every runtime read resolves against.
///
/// Seeded from [`BeaconChainConfig`] at genesis (see
/// [`Self::from_genesis`]) and mutated only by the fold. New rows are
/// added one at a time as each parameter's activation semantics are
/// worked out; today the set is `reshape_thresholds` alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BasicSbor)]
pub struct NetworkParams {
    /// Substate-byte thresholds driving automatic shard reshaping. The
    /// live source for the split/merge predicate; the genesis copy on
    /// `chain_config` is only the seed.
    pub reshape_thresholds: ReshapeThresholds,
    /// Epochs a convicted pool's withdrawals stay frozen past its
    /// conviction. Read at conviction time to stamp `lifts_at`; a
    /// later change never shortens an in-force impound.
    pub impound_epochs: u64,
}

impl NetworkParams {
    /// Seed the live params from the genesis chain config's governable
    /// subset. Called once, in `build_genesis_beacon_state`.
    #[must_use]
    pub const fn from_genesis(config: &BeaconChainConfig) -> Self {
        Self {
            reshape_thresholds: config.reshape_thresholds,
            impound_epochs: config.impound_epochs,
        }
    }

    /// Reject a parameter set the fold must never activate — each field
    /// validates its own bounds so a governance vote can't drive the
    /// network into an unrecoverable configuration.
    ///
    /// A zero `split_bytes` makes every shard split on its first byte (an
    /// unbounded cascade up to `MAX_SHARDS`) and can never merge back, so
    /// it is rejected; `u64::MAX` (reshaping disabled) and any positive
    /// threshold are accepted.
    ///
    /// # Errors
    ///
    /// Returns a [`ParamBoundsError`] naming the first field whose value
    /// is out of bounds.
    pub const fn validate(&self) -> Result<(), ParamBoundsError> {
        if self.reshape_thresholds.split_bytes == 0 {
            return Err(ParamBoundsError::ZeroSplitThreshold);
        }
        if self.impound_epochs < UNBONDING_WINDOW_EPOCHS {
            return Err(ParamBoundsError::ImpoundBelowUnbonding);
        }
        Ok(())
    }
}

impl Default for NetworkParams {
    /// The genesis-shaped defaults — every row's seed value, so a
    /// default params set always passes [`Self::validate`].
    fn default() -> Self {
        Self {
            reshape_thresholds: ReshapeThresholds::default(),
            impound_epochs: IMPOUND_EPOCHS_DEFAULT,
        }
    }
}

/// Why a [`NetworkParams`] value is out of bounds and must not activate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ParamBoundsError {
    /// `reshape_thresholds.split_bytes` is zero — every shard would split
    /// on its first byte and never merge back.
    #[error("reshape split_bytes is zero; every shard would split unboundedly")]
    ZeroSplitThreshold,
    /// `impound_epochs` is below the unbonding window — a conviction
    /// would then be cheaper than a voluntary exit.
    #[error("impound_epochs is below the unbonding window")]
    ImpoundBelowUnbonding,
}

/// A proposed parameter change: the target [`NetworkParams`] and the
/// epoch it activates.
///
/// A "proposal" is just this `(params, activate_at)` pair — pools
/// coordinate on it off-chain and each cast a [`ParamVote`] backing it.
/// The tally buckets votes by the exact pair, so two pools count toward
/// the same change only if they agree on both the value and the epoch.
/// `activate_at` doubles as the prepare window / timelock: the change
/// applies at that epoch iff it still holds a majority then.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BasicSbor)]
pub struct ParamProposal {
    /// The parameter values this proposal would install.
    pub params: NetworkParams,
    /// The epoch at which the change takes effect if it holds a majority.
    pub activate_at: Epoch,
}

/// One stake pool's parameter-change vote, carried on the
/// system-transaction rail and folded into `BeaconState.param_votes`.
///
/// A pool holds exactly one active vote. `proposal: Some(_)` casts or
/// replaces it; `proposal: None` clears it. The beacon takes the witness
/// as authoritative — that `pool` voted this way — and weights the tally
/// by `pool`'s stake; the signer's authority over the pool is enforced in
/// the VM, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub struct ParamVote {
    /// The stake pool casting the vote — the unit the tally weights by.
    pub pool: StakePoolId,
    /// The proposal this pool now backs, or `None` to clear its vote.
    pub proposal: Option<ParamProposal>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_reshape_thresholds_from_config() {
        let config = BeaconChainConfig {
            reshape_thresholds: ReshapeThresholds { split_bytes: 9_000 },
            ..BeaconChainConfig::default()
        };
        assert_eq!(
            NetworkParams::from_genesis(&config).reshape_thresholds,
            ReshapeThresholds { split_bytes: 9_000 },
        );
    }

    #[test]
    fn default_disables_reshaping() {
        assert_eq!(
            NetworkParams::default().reshape_thresholds,
            ReshapeThresholds::DISABLED,
        );
    }

    #[test]
    fn validate_rejects_zero_split_threshold() {
        let zero = NetworkParams {
            reshape_thresholds: ReshapeThresholds { split_bytes: 0 },
            ..NetworkParams::default()
        };
        assert_eq!(zero.validate(), Err(ParamBoundsError::ZeroSplitThreshold));

        // Disabled and any positive threshold are in bounds.
        assert!(NetworkParams::default().validate().is_ok());
        assert!(
            NetworkParams {
                reshape_thresholds: ReshapeThresholds { split_bytes: 1 },
                ..NetworkParams::default()
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn sbor_round_trip() {
        let params = NetworkParams {
            reshape_thresholds: ReshapeThresholds { split_bytes: 1_234 },
            ..NetworkParams::default()
        };
        let bytes = basic_encode(&params).unwrap();
        assert_eq!(basic_decode::<NetworkParams>(&bytes).unwrap(), params);
    }

    #[test]
    fn vote_sbor_round_trip() {
        let votes = [
            ParamVote {
                pool: StakePoolId::new(3),
                proposal: Some(ParamProposal {
                    params: NetworkParams {
                        reshape_thresholds: ReshapeThresholds { split_bytes: 7_000 },
                        ..NetworkParams::default()
                    },
                    activate_at: Epoch::new(12),
                }),
            },
            ParamVote {
                pool: StakePoolId::new(3),
                proposal: None,
            },
        ];
        for vote in votes {
            let bytes = basic_encode(&vote).unwrap();
            assert_eq!(basic_decode::<ParamVote>(&bytes).unwrap(), vote);
        }
    }
}
