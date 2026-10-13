//! The iroh backend.

use std::sync::Arc;

use hyperscale_network::HandlerRegistry;
pub use hyperscale_network_iroh::VersionInteroperabilityMode;
use hyperscale_network_iroh::{
    IrohAdapter, IrohAdapterArgs, IrohConfig, IrohNetwork, NetworkError, RequestManager,
    RequestManagerConfig, RequestPool, RequestStreams,
};
use tokio::runtime::Handle as TokioHandle;
use tokio::task::block_in_place;

use super::{NetworkBuildArgs, NetworkStack};

/// The [`Network`](hyperscale_network::Network) the node sends through.
pub type ProdNetwork = IrohNetwork;

/// The adapter the runner drives and reads.
pub type TransportAdapter = IrohAdapter;

/// The backend's configuration.
pub type TransportConfig = IrohConfig;

/// The backend's setup error.
pub type TransportError = NetworkError;

/// Stand the host's networking up. The endpoint binds as the network key in
/// the configuration, so the identity is whatever the caller keeps.
///
/// Binding the endpoint is asynchronous and the runner is built
/// synchronously, so this blocks its thread until the endpoint is bound. It
/// must be called from within a multi-threaded tokio runtime.
pub fn build_network_stack(args: NetworkBuildArgs) -> Result<NetworkStack, TransportError> {
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
