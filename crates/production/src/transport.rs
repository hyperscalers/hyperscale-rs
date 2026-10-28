//! Stands a host's iroh networking up.

use std::collections::BTreeSet;
use std::sync::Arc;

use hyperscale_network::{HandlerRegistry, ValidatorKeyMap};
use hyperscale_network_iroh::{
    IrohAdapter, IrohAdapterArgs, IrohConfig, IrohNetwork, NetworkError, RequestManager,
    RequestManagerConfig, RequestPool, RequestStreams,
};
use hyperscale_node::SharedTopologySnapshot;
use hyperscale_types::{NetworkDefinition, ShardId, Signer, ValidatorId, Verifier};
use tokio::runtime::Handle as TokioHandle;
use tokio::task::block_in_place;

/// What a host's networking is built from.
pub struct NetworkBuildArgs {
    pub network_config: IrohConfig,
    /// Network identity, bound into signed bind handshake messages so a
    /// signature collected on one network can't validate on another.
    pub network: NetworkDefinition,
    /// Shards hosted by this host.
    pub local_shards: BTreeSet<ShardId>,
    /// One `(validator_id, signer)` per hosted vnode. The bind handshake
    /// attests as every entry.
    pub bind_vnodes: Vec<(ValidatorId, Arc<dyn Signer>)>,
    pub initial_validator_keys: Arc<ValidatorKeyMap>,
    /// Scheme verifier for signed gossip and bind attestations.
    pub verifier: Arc<dyn Verifier>,
    /// Topology snapshot shared with the network for shard-based peer
    /// resolution on outbound requests.
    pub topology_snapshot: SharedTopologySnapshot,
}

/// A host's networking: the adapter the runner drives and reads, and the
/// [`Network`](hyperscale_network::Network) the node sends through.
pub struct NetworkStack {
    pub adapter: Arc<IrohAdapter>,
    pub network: IrohNetwork,
}

/// Stand the host's networking up. The endpoint binds as the network key in
/// the configuration, so the identity is whatever the caller keeps.
///
/// Binding the endpoint is asynchronous and the runner is built
/// synchronously, so this blocks its thread until the endpoint is bound. It
/// must be called from within a multi-threaded tokio runtime.
pub fn build_network_stack(args: NetworkBuildArgs) -> Result<NetworkStack, NetworkError> {
    let registry = Arc::new(HandlerRegistry::new(
        args.local_shards.iter().copied().collect(),
    ));
    let simulated_outbound_latency = args.network_config.simulated_outbound_latency;
    let runtime = TokioHandle::current();

    let adapter = block_in_place(|| {
        runtime.block_on(IrohAdapter::bind(IrohAdapterArgs {
            config: args.network_config,
            network: args.network,
            vnodes: args.bind_vnodes,
            local_shards: args.local_shards.into_iter().collect(),
            registry: Arc::clone(&registry),
            validator_keys: args.initial_validator_keys,
            verifier: args.verifier,
        }))
    })?;

    let request_pool: Arc<dyn RequestPool> = Arc::new(RequestStreams::new(
        Arc::clone(&adapter),
        simulated_outbound_latency,
    ));
    let request_manager = Arc::new(RequestManager::new(
        request_pool,
        RequestManagerConfig::default(),
    ));

    let network = IrohNetwork::new(
        Arc::clone(&adapter),
        request_manager,
        runtime,
        registry,
        args.topology_snapshot,
        simulated_outbound_latency,
    );

    Ok(NetworkStack { adapter, network })
}
