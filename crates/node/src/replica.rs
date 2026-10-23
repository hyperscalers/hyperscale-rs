//! What a host builds each shard's replica from, and the signers it
//! attaches to one.
//!
//! A [`ShardLoop`] runs one replica, a [`NodeStateMachine`] built with no
//! signer, and each validator identity the host holds a seat for on that
//! shard attaches to it as an [`AttachedSigner`].
//!
//! [`ShardLoop`]: crate::shard::ShardLoop

use std::sync::Arc;

use hyperscale_core::SignerGate;
use hyperscale_engine::CodeAvailability;
use hyperscale_mempool::MempoolConfig;
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::RecoveredState;
use hyperscale_types::{
    BlockHeight, Derivation, Epoch, GenesisConfigHash, NetworkDefinition, ShardId, Signer,
    TopologySchedule, Verifier,
};

use crate::NodeStateMachine;

/// What every replica a host runs is built with, whichever shard it
/// follows and whenever the host takes it up, and what the host's fold is
/// resumed with.
#[derive(Clone)]
pub struct ReplicaConfig {
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
    /// Mempool knobs.
    pub mempool_config: MempoolConfig,
    /// Provision coordinator knobs.
    pub provision_config: ProvisionConfig,
}

/// Build `shard`'s replica with no signer, booted from `recovered` over
/// `schedule`, the schedule the beacon folded at `epoch`, on a store
/// written through `persisted_base`.
pub fn build_replica(
    config: &ReplicaConfig,
    shard: ShardId,
    recovered: &RecoveredState,
    (schedule, epoch): (Arc<TopologySchedule>, Epoch),
    persisted_base: BlockHeight,
) -> NodeStateMachine {
    NodeStateMachine::new(
        Arc::clone(&config.verifier),
        Arc::clone(&config.derivation),
        Arc::clone(&config.code),
        shard,
        &config.shard_config,
        recovered,
        schedule,
        epoch,
        config.mempool_config.clone(),
        config.provision_config,
        persisted_base,
    )
}

/// A validator identity attached to a replica: the key it signs with,
/// shared by `Arc` with the off-thread handlers that sign, and the
/// single-use release gate every action it signs carries.
pub struct AttachedSigner {
    pub signer: Arc<dyn Signer>,
    pub gate: Arc<SignerGate>,
}

impl AttachedSigner {
    /// `signer` behind a fresh, open gate.
    pub fn new(signer: Arc<dyn Signer>) -> Self {
        Self {
            signer,
            gate: Arc::new(SignerGate::new()),
        }
    }
}
