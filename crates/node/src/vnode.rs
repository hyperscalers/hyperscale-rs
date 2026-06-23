//! Per-validator bundle hosted by the `NodeHost`.
//!
//! One [`Vnode`] per validator identity, owned by a [`ShardLoop`] in
//! the `NodeHost`'s `shards` map. Same-shard vnodes share the enclosing
//! `ShardLoop`'s `ShardIo`; cross-shard vnodes live in different
//! groups. The vnode's shard is implied by which group it lives in —
//! no denormalized field.
//!
//! Per-step scratch (emitted statuses, action counter, timer ops)
//! lives on the `NodeHost`, not here — those buffers are step-local
//! and carry the emitting vnode's `(shard, idx)` via the existing
//! action-dispatch threading.
//!
//! [`ShardLoop`]: crate::shard::ShardLoop

use std::sync::Arc;

use hyperscale_beacon::coordinator::{BeaconCoordinator, retention_floor};
use hyperscale_execution::{ExecCertStore, FinalizedWaveStore};
use hyperscale_mempool::{MempoolConfig, TxStore};
use hyperscale_provisions::{ProvisionConfig, ProvisionStore};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconStorage, RecoveredState};
use hyperscale_types::{
    BeaconState, Bls12381G1PrivateKey, GenesisConfigHash, LocalTimestamp, NetworkDefinition,
    ShardId, ValidatorId, WeightedTimestamp,
};

use crate::NodeStateMachine;

/// Caller-supplied bundle for constructing one [`Vnode`]. The
/// `NodeHost` constructor wraps each entry into a full [`Vnode`] and
/// shares one `ShardIo` across same-shard entries.
pub struct VnodeInit {
    /// Per-validator state machine, already populated with its
    /// `TopologyCoordinator` (the constructor reads `validator_id`
    /// and `local_shard` from there).
    pub state: NodeStateMachine,
    /// BLS signing key for this validator's votes and proposals.
    /// Shared with the validator-bind service (production) by `Arc`
    /// so the key has exactly one allocation regardless of how many
    /// off-thread consumers hold it.
    pub signing_key: Arc<Bls12381G1PrivateKey>,
}

impl VnodeInit {
    /// Wrap the init bundle into a hosted [`Vnode`].
    #[must_use]
    pub fn into_vnode(self) -> Vnode {
        Vnode {
            validator_id: self.state.validator_id(),
            state: self.state,
            signing_key: self.signing_key,
        }
    }
}

/// Everything one same-shard vnode group boots from at seat time —
/// startup, runtime join, or sim harness alike.
pub struct SeatVnodeGroup<'a> {
    /// Host beacon storage; the group's coordinators resume from its
    /// committed tip.
    pub beacon_storage: &'a dyn BeaconStorage,
    /// Radix network identity bound into beacon signatures.
    pub beacon_network: NetworkDefinition,
    /// Genesis config hash bound into beacon signatures alongside the
    /// network.
    pub beacon_config_hash: GenesisConfigHash,
    /// Wall clock (production) or sim time; bounds the resume floor.
    pub now: LocalTimestamp,
    /// Shard every vnode in the group targets.
    pub shard: ShardId,
    /// Boot state — loaded from retained storage, synthesized from a
    /// snap-synced anchor, or default for a genesis replay.
    pub recovered: &'a RecoveredState,
    /// Consensus knobs, shared by every vnode in the group.
    pub shard_config: &'a ShardConsensusConfig,
    /// Mempool knobs, cloned into each vnode's coordinator.
    pub mempool_config: MempoolConfig,
    /// Provision coordinator knobs.
    pub provision_config: ProvisionConfig,
    /// `(validator, signing key)` per seated vnode.
    pub vnodes: Vec<(ValidatorId, Arc<Bls12381G1PrivateKey>)>,
}

/// Build one [`VnodeInit`] per vnode in a same-shard group: a beacon
/// coordinator resumed from the host's committed beacon chain and a
/// `NodeStateMachine` booted from `recovered`.
///
/// The coordinators' schedule history is bounded by [`retention_floor`]
/// so every committee a consumer frontier still reaches stays
/// resolvable.
///
/// One fresh `ProvisionStore` + `TxStore` + `ExecCertStore` +
/// `FinalizedWaveStore` is shared across the group (and into the
/// `NodeHost`'s `SharedCaches`). Determinism guarantees same-shard
/// vnodes admit identical sets, but co-owning the stores makes the
/// canonical view explicit and gives the request/sync handlers one
/// place to read. Per-shard scoping matters for `ProvisionStore`:
/// under cross-shard packing the co-hosted source shard's
/// `OutboundProvisionTracker` evicts on every acknowledged EC, and a
/// host-wide store would let that eviction delete entries the inbound
/// coordinator on the target shard still needs to verify proposals
/// against.
///
/// # Panics
///
/// Panics if `beacon_storage` holds no committed beacon block — every
/// host commits the genesis pair before seating vnodes.
#[must_use]
pub fn seat_vnode_group(args: SeatVnodeGroup<'_>) -> Vec<VnodeInit> {
    let (latest_block, latest_state) = args
        .beacon_storage
        .latest_committed()
        .expect("beacon chain is non-empty after the genesis commit");
    let boot_floor = retention_floor(
        &latest_state,
        args.recovered.committee_anchor_ts(),
        args.now,
    );
    let beacon_history: Vec<BeaconState> = args
        .beacon_storage
        .states_since(boot_floor)
        .into_iter()
        .map(|state| state.as_ref().clone())
        .collect();

    let provision_store = Arc::new(ProvisionStore::new());
    let tx_store = Arc::new(TxStore::new());
    let exec_cert_store = Arc::new(ExecCertStore::new());
    let finalized_wave_store = Arc::new(FinalizedWaveStore::new());

    args.vnodes
        .into_iter()
        .map(|(validator, signing_key)| {
            let beacon_coordinator = BeaconCoordinator::new(
                Arc::clone(&latest_block),
                beacon_history.clone(),
                validator,
                args.shard,
                args.recovered.committee_anchor_ts(),
                args.beacon_network.clone(),
                args.beacon_config_hash,
            );
            let state = NodeStateMachine::new(
                validator,
                args.shard,
                args.shard_config,
                args.recovered.clone(),
                beacon_coordinator,
                args.mempool_config.clone(),
                args.provision_config,
                Arc::clone(&provision_store),
                Arc::clone(&tx_store),
                Arc::clone(&exec_cert_store),
                Arc::clone(&finalized_wave_store),
            );
            VnodeInit { state, signing_key }
        })
        .collect()
}

/// Caller-supplied bundle for constructing one shard-less beacon
/// follower — the pooled counterpart of [`SeatVnodeGroup`].
pub struct SeatFollower<'a> {
    /// Host beacon storage; the follower's coordinator resumes from its
    /// committed tip and stays warm by committing every block it folds.
    pub beacon_storage: &'a dyn BeaconStorage,
    /// Radix network identity bound into beacon signatures.
    pub beacon_network: NetworkDefinition,
    /// Genesis config hash bound into beacon signatures alongside the
    /// network.
    pub beacon_config_hash: GenesisConfigHash,
    /// Wall clock (production) or sim time; bounds the resume floor.
    pub now: LocalTimestamp,
    /// The validator this host follows the beacon for.
    pub validator: ValidatorId,
    /// Its signing key. A follower never signs (it is never
    /// `beacon_eligible`), but the bundle carries the real key so a later
    /// seat does not have to thread one in separately.
    pub signing_key: Arc<Bls12381G1PrivateKey>,
}

/// Build one shard-less beacon-follower [`VnodeInit`].
///
/// A beacon coordinator resumed from the host's committed beacon chain
/// wrapped in a `shard: None` [`NodeStateMachine`]. The coordinator carries
/// [`ShardId::ROOT`] as its placeholder home — it only seeds the retention
/// floor and has no consensus effect for a follower.
///
/// # Panics
///
/// Panics if `beacon_storage` holds no committed beacon block — every host
/// commits the genesis pair before it follows or seats.
#[must_use]
pub fn seat_follower(args: SeatFollower<'_>) -> VnodeInit {
    let (latest_block, latest_state) = args
        .beacon_storage
        .latest_committed()
        .expect("beacon chain is non-empty after the genesis commit");
    // A follower has no committed shard frontier, so the floor is bounded
    // by the chain tip and `now` alone.
    let boot_floor = retention_floor(&latest_state, WeightedTimestamp::ZERO, args.now);
    let beacon_history: Vec<BeaconState> = args
        .beacon_storage
        .states_since(boot_floor)
        .into_iter()
        .map(|state| state.as_ref().clone())
        .collect();
    let beacon_coordinator = BeaconCoordinator::new(
        latest_block,
        beacon_history,
        args.validator,
        ShardId::ROOT,
        WeightedTimestamp::ZERO,
        args.beacon_network,
        args.beacon_config_hash,
    );
    VnodeInit {
        state: NodeStateMachine::follower(args.validator, beacon_coordinator),
        signing_key: args.signing_key,
    }
}

/// Per-validator bundle hosted by the `NodeHost`.
pub struct Vnode {
    /// Identity this vnode votes as. Stable for the vnode's lifetime;
    /// keys the network adapter's bind handshake and the per-vnode
    /// metrics / status maps.
    pub validator_id: ValidatorId,

    /// Per-validator consensus state. Driven exclusively from the pinned
    /// `NodeHost` thread via `state.handle(now, event)`; off-thread closures
    /// never touch it.
    pub state: NodeStateMachine,

    /// BLS signing key for votes and proposals. Shared with
    /// `DispatchHandles` via `Arc` so delegated handlers running on
    /// thread pools can sign without re-entering the pinned thread.
    pub signing_key: Arc<Bls12381G1PrivateKey>,
}
