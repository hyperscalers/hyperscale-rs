//! The libp2p backend.

use std::sync::Arc;

use hyperscale_network::HandlerRegistry;
pub use hyperscale_network_libp2p::VersionInteroperabilityMode;
use hyperscale_network_libp2p::{
    Libp2pAdapter, Libp2pAdapterArgs, Libp2pConfig, Libp2pNetwork, NetworkError, RequestManager,
    RequestManagerConfig, RequestStreamPool, generate_random_keypair,
};
use tokio::runtime::Handle as TokioHandle;

use super::{NetworkBuildArgs, NetworkStack};

/// The [`Network`](hyperscale_network::Network) the node sends through.
pub type ProdNetwork = Libp2pNetwork;

/// The adapter the runner drives and reads.
pub type TransportAdapter = Libp2pAdapter;

/// The backend's configuration.
pub type TransportConfig = Libp2pConfig;

/// The backend's setup error.
pub type TransportError = NetworkError;

/// Stand the host's networking up. The transport identity is fresh on every
/// start.
///
/// Must be called from within a tokio runtime context: the adapter and
/// request manager capture `Handle::current()`.
pub fn build_network_stack(args: NetworkBuildArgs) -> Result<NetworkStack, TransportError> {
    let registry = Arc::new(HandlerRegistry::new(
        args.local_shards.iter().copied().collect(),
    ));

    // Read before the config is moved into the adapter; applied uniformly to
    // every outbound send path so test clusters pace to a simulated RTT.
    let simulated_outbound_latency = args.network_config.simulated_outbound_latency;

    let adapter = Libp2pAdapter::new(Libp2pAdapterArgs {
        config: args.network_config,
        network: args.network,
        keypair: generate_random_keypair(),
        vnodes: args.bind_vnodes,
        local_shards: args.local_shards.into_iter().collect(),
        registry: registry.clone(),
        validator_keys: args.initial_validator_keys,
        verifier: args.verifier,
    })?;

    let request_pool = Arc::new(RequestStreamPool::new(
        adapter.clone(),
        TokioHandle::current(),
        simulated_outbound_latency,
    ));
    let request_manager = Arc::new(RequestManager::new(
        request_pool,
        RequestManagerConfig::default(),
    ));

    let network = Libp2pNetwork::new(
        adapter.clone(),
        request_manager,
        TokioHandle::current(),
        registry,
        args.topology_snapshot,
        simulated_outbound_latency,
    );

    Ok(NetworkStack { adapter, network })
}
