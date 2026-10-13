//! The network backend the production runner is built on.
//!
//! One backend is compiled into a build. libp2p is the default; the `iroh`
//! cargo feature replaces it with the iroh transport. Each backend module
//! exports the same names, so the rest of the crate is written once.

use std::collections::BTreeSet;
use std::sync::Arc;

use hyperscale_network::ValidatorKeyMap;
use hyperscale_node::SharedTopologySnapshot;
use hyperscale_types::{NetworkDefinition, ShardId, Signer, ValidatorId, Verifier};

#[cfg(all(not(feature = "iroh"), not(feature = "libp2p")))]
compile_error!("hyperscale-production needs a network backend: enable `libp2p` or `iroh`");

#[cfg_attr(feature = "iroh", path = "transport/iroh.rs")]
#[cfg_attr(not(feature = "iroh"), path = "transport/libp2p.rs")]
mod backend;

pub(crate) use backend::build_network_stack;
pub use backend::{
    ProdNetwork, TransportAdapter, TransportConfig, TransportError, VersionInteroperabilityMode,
};

/// Everything a backend needs to stand a host's networking up.
pub(crate) struct NetworkBuildArgs {
    pub(crate) network_config: TransportConfig,
    /// Network identity, bound into signed bind handshake messages so a
    /// signature collected on one network can't validate on another.
    pub(crate) network: NetworkDefinition,
    /// Shards hosted by this host.
    pub(crate) local_shards: BTreeSet<ShardId>,
    /// One `(validator_id, signer)` per hosted vnode. The bind handshake
    /// attests as every entry.
    pub(crate) bind_vnodes: Vec<(ValidatorId, Arc<dyn Signer>)>,
    pub(crate) initial_validator_keys: Arc<ValidatorKeyMap>,
    /// Scheme verifier for signed gossip and bind attestations.
    pub(crate) verifier: Arc<dyn Verifier>,
    /// Topology snapshot shared with the network for shard-based peer
    /// resolution on outbound requests.
    pub(crate) topology_snapshot: SharedTopologySnapshot,
}

/// A host's networking: the adapter the runner drives and reads, and the
/// [`Network`](hyperscale_network::Network) the node sends through.
pub(crate) struct NetworkStack {
    pub(crate) adapter: Arc<TransportAdapter>,
    pub(crate) network: ProdNetwork,
}
