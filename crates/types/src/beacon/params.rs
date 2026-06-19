//! Live, governable network parameters.
//!
//! [`NetworkParams`] holds exactly the policy parameters a running
//! network may retune after genesis. It is seeded from the genesis
//! [`BeaconChainConfig`] and thereafter mutated only by the beacon fold
//! (a committed, stake-weighted parameter-change tally). Structural and
//! historical parameters — `num_shards`, `genesis_timestamp_ms` — stay
//! on the immutable `chain_config` and never appear here.
//!
//! Every runtime read of a governable parameter resolves against
//! `BeaconState.params`, never `chain_config`: the genesis record and the
//! live value diverge once a parameter change folds in, so reading the
//! frozen copy would resurrect a stale threshold and fork the chain.

use sbor::prelude::*;

use crate::{BeaconChainConfig, ReshapeThresholds};

/// The governable subset of a chain's parameters — the live values
/// every runtime read resolves against.
///
/// Seeded from [`BeaconChainConfig`] at genesis (see
/// [`Self::from_genesis`]) and mutated only by the fold. New rows are
/// added one at a time as each parameter's activation semantics are
/// worked out; today the set is `reshape_thresholds` alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BasicSbor)]
pub struct NetworkParams {
    /// Substate-byte thresholds driving automatic shard reshaping. The
    /// live source for the split/merge predicate; the genesis copy on
    /// `chain_config` is only the seed.
    pub reshape_thresholds: ReshapeThresholds,
}

impl NetworkParams {
    /// Seed the live params from the genesis chain config's governable
    /// subset. Called once, in `build_genesis_beacon_state`.
    #[must_use]
    pub const fn from_genesis(config: &BeaconChainConfig) -> Self {
        Self {
            reshape_thresholds: config.reshape_thresholds,
        }
    }
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
    fn sbor_round_trip() {
        let params = NetworkParams {
            reshape_thresholds: ReshapeThresholds { split_bytes: 1_234 },
        };
        let bytes = basic_encode(&params).unwrap();
        assert_eq!(basic_decode::<NetworkParams>(&bytes).unwrap(), params);
    }
}
