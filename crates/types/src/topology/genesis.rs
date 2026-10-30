//! The validators a runner projects its initial
//! [`TopologySnapshot`](super::snapshot::TopologySnapshot) from at genesis.

use std::collections::BTreeMap;

use crate::{NetworkDefinition, ValidatorId, ValidatorSet};

/// The validators that exist at genesis: the network, the full registered
/// set (every validator, seated or pooled), and the genesis ROOT committee.
///
/// Genesis is always a single ROOT shard — the network launches at one shard and
/// reaches a multi-shard partition only by splitting — so there is nothing to
/// configure here beyond who exists and who seats the root. A runner builds the
/// genesis `BeaconState` from this and projects the `TopologySnapshot` from that
/// state, the same `BeaconState → TopologySnapshot` direction the runtime
/// `ArcSwap` update follows; the topology is always derived, never supplied
/// alongside a beacon state it has to be kept in agreement with.
#[derive(Clone, Debug)]
pub struct GenesisValidators {
    /// Network bound into the projected topology (the consensus-signature
    /// domain) and the genesis beacon config hash.
    pub network: NetworkDefinition,
    /// Every registered validator at genesis — the ROOT committee plus the
    /// pooled surplus a later reshape draws its child cohort from.
    pub validators: ValidatorSet,
    /// The genesis ROOT committee. Any registered validator absent from it
    /// starts `Pooled`; pass every validator id to seat the whole set.
    pub committee: Vec<ValidatorId>,
    /// The genesis stake pool seat each validator belongs to, by seat
    /// number. A validator absent here belongs to seat 0.
    pub seats: BTreeMap<ValidatorId, u32>,
}

impl GenesisValidators {
    /// Genesis validators with `committee` seating the single ROOT shard,
    /// every one in seat 0.
    #[must_use]
    pub const fn new(
        network: NetworkDefinition,
        validators: ValidatorSet,
        committee: Vec<ValidatorId>,
    ) -> Self {
        Self {
            network,
            validators,
            committee,
            seats: BTreeMap::new(),
        }
    }

    /// The seat number `validator` belongs to.
    #[must_use]
    pub fn seat_of(&self, validator: ValidatorId) -> u32 {
        self.seats.get(&validator).copied().unwrap_or(0)
    }
}
