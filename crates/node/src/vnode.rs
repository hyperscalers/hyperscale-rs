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

use hyperscale_engine::CodeAvailability;
use hyperscale_execution::{CrossingIndexSlot, ExecCertStore, FinalizationStore};
use hyperscale_mempool::{MempoolConfig, TxStore};
use hyperscale_provisions::{ProvisionConfig, ProvisionStore};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::RecoveredState;
use hyperscale_types::{
    Derivation, Epoch, GenesisConfigHash, NetworkDefinition, ShardId, Signer, TopologySchedule,
    ValidatorId, Verifier,
};

use crate::NodeStateMachine;

/// Caller-supplied bundle for constructing one [`Vnode`]. The
/// `NodeHost` constructor wraps each entry into a full [`Vnode`] and
/// shares one `ShardIo` across same-shard entries.
pub struct VnodeInit {
    /// The validator the vnode signs for.
    pub validator: ValidatorId,
    /// Per-validator state machine.
    pub state: NodeStateMachine,
    /// Signing identity for this validator's votes and proposals.
    /// Shared with the validator-bind service (production) by `Arc`
    /// so the key has exactly one allocation regardless of how many
    /// off-thread consumers hold it.
    pub signer: Arc<dyn Signer>,
}

impl VnodeInit {
    /// Wrap the init bundle into a hosted [`Vnode`].
    #[must_use]
    pub fn into_vnode(self) -> Vnode {
        Vnode {
            validator_id: self.validator,
            state: self.state,
            signer: self.signer,
        }
    }
}

/// What every vnode a host seats is built with, whichever group it joins
/// and whenever it joins it, and what the host's fold is resumed with.
#[derive(Clone)]
pub struct SeatConfig {
    /// Scheme verifier shared by every coordinator the host builds.
    pub verifier: Arc<dyn Verifier>,
    /// What this node derives envelopes through — its own caches, held
    /// by its own engine.
    pub derivation: Arc<dyn Derivation>,
    /// Whether this node can run a package's code — the same engine's
    /// answer, asked at tick dispatch.
    pub code: Arc<dyn CodeAvailability>,
    /// The network identity bound into beacon signatures.
    pub beacon_network: NetworkDefinition,
    /// Genesis config hash bound into beacon signatures alongside the
    /// network.
    pub beacon_config_hash: GenesisConfigHash,
    /// Consensus knobs.
    pub shard_config: ShardConsensusConfig,
    /// Mempool knobs, cloned into each vnode's coordinator.
    pub mempool_config: MempoolConfig,
    /// Provision coordinator knobs.
    pub provision_config: ProvisionConfig,
}

/// Everything one same-shard vnode group boots from at seat time —
/// startup, runtime join, or sim harness alike.
pub struct SeatVnodeGroup<'a> {
    /// How each vnode is built.
    pub config: SeatConfig,
    /// The schedule the group's replicas start from, and the epoch the
    /// beacon folded it at: the chain's registration reply, or the running
    /// loop's held schedule for a vnode seated into it.
    pub schedule: (Arc<TopologySchedule>, Epoch),
    /// Shard every vnode in the group targets.
    pub shard: ShardId,
    /// Boot state — loaded from retained storage, synthesized from a
    /// snap-synced anchor, or default for a genesis replay.
    pub recovered: &'a RecoveredState,
    /// `(validator, signer)` per seated vnode.
    pub vnodes: Vec<(ValidatorId, Arc<dyn Signer>)>,
}

/// One validator waiting to join a shard its host already runs. The loop
/// builds it when it admits the seat, from its own store and its group's
/// stores.
pub struct VnodeSeat {
    /// How the vnode is built.
    pub config: SeatConfig,
    /// The validator taking the seat.
    pub validator: ValidatorId,
    /// Its signer.
    pub signer: Arc<dyn Signer>,
}

/// The stores every vnode of one shard's group co-owns.
///
/// Determinism guarantees same-shard vnodes admit identical sets, but
/// co-owning the stores makes the canonical view explicit and gives the
/// request/sync handlers one place to read. Per-shard scoping matters
/// for `ProvisionStore`: under cross-shard packing the co-hosted source
/// shard's `OutboundProvisionTracker` evicts on every acknowledged EC,
/// and a host-wide store would let that eviction delete entries the
/// inbound coordinator on the target shard still needs to verify
/// proposals against.
#[derive(Clone)]
pub struct GroupStores {
    pub provision_store: Arc<ProvisionStore>,
    pub tx_store: Arc<TxStore>,
    pub exec_cert_store: Arc<ExecCertStore>,
    pub finalization_store: Arc<FinalizationStore>,
    pub crossing_index: Arc<CrossingIndexSlot>,
}

impl GroupStores {
    /// Stores for a group seated from `recovered`. The bodies its own
    /// committed blocks carried go back in the store everything reads
    /// them from: a stored block keeps only their hashes, so without
    /// them a restarted host holds blocks it cannot serve and legs it
    /// cannot replay.
    fn fresh(recovered: &RecoveredState) -> Self {
        let provision_store = Arc::new(ProvisionStore::new());
        for provisions in &recovered.retained_provisions {
            provision_store.insert(Arc::clone(provisions));
        }
        Self {
            provision_store,
            tx_store: Arc::new(TxStore::new()),
            exec_cert_store: Arc::new(ExecCertStore::new()),
            finalization_store: Arc::new(FinalizationStore::new()),
            crossing_index: Arc::new(CrossingIndexSlot::default()),
        }
    }
}

/// Build one [`VnodeInit`] per vnode in a same-shard group, over one
/// fresh set of [`GroupStores`].
///
/// Each vnode is a `NodeStateMachine` booted from `recovered` over the
/// group's schedule. The stores are shared across the group and into the
/// `NodeHost`'s `SharedCaches`.
#[must_use]
pub fn seat_vnode_group(args: SeatVnodeGroup<'_>) -> Vec<VnodeInit> {
    let stores = GroupStores::fresh(args.recovered);
    seat_vnode_into_group(args, &stores)
}

/// Build one [`VnodeInit`] per vnode over `stores`, the stores of the
/// group the vnodes join.
pub fn seat_vnode_into_group(args: SeatVnodeGroup<'_>, stores: &GroupStores) -> Vec<VnodeInit> {
    let config = &args.config;
    let (schedule, epoch) = args.schedule;
    args.vnodes
        .into_iter()
        .map(|(validator, signer)| {
            let state = NodeStateMachine::new(
                validator,
                Arc::clone(&config.verifier),
                Arc::clone(&config.derivation),
                Arc::clone(&config.code),
                args.shard,
                &config.shard_config,
                args.recovered,
                Arc::clone(&schedule),
                epoch,
                config.mempool_config.clone(),
                config.provision_config,
                Arc::clone(&stores.provision_store),
                Arc::clone(&stores.tx_store),
                Arc::clone(&stores.exec_cert_store),
                Arc::clone(&stores.finalization_store),
                Arc::clone(&stores.crossing_index),
            );
            VnodeInit {
                validator,
                state,
                signer,
            }
        })
        .collect()
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

    /// Signing identity for votes and proposals. Shared with
    /// `DispatchHandles` via `Arc` so delegated handlers running on
    /// thread pools can sign without re-entering the pinned thread.
    pub(crate) signer: Arc<dyn Signer>,
}
