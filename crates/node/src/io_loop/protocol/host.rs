//! Bundle of fetch + sync protocols owned by the I/O loop.
//!
//! `ProtocolHost` holds the seven payload-specific fetch state machines plus
//! the sync protocol and its rehydration scratch state. Lifting these out of
//! `IoLoop` collapses 8 fields into one and makes "what the I/O loop is
//! orchestrating" explicit.

use super::binding::{
    ExecCertFetch, FinalizedWaveFetch, HeaderFetch, LocalProvisionFetch, ProvisionFetch,
    TransactionFetch,
};
use super::fetch::FetchConfig;
use super::sync::SyncProtocol;
use crate::config::NodeConfig;
use hyperscale_messages::response::ElidedCertifiedBlock;
use hyperscale_types::BlockHeight;
use std::collections::HashMap;

/// Sync + per-payload fetch protocols owned by the I/O loop.
pub struct ProtocolHost {
    /// Block-sync state machine.
    pub sync: SyncProtocol,

    /// Elided sync responses awaiting a top-up. Keyed by block height.
    /// Populated when rehydration misses; drained on topup response or
    /// topup failure.
    pub pending_block_topups: HashMap<BlockHeight, Box<ElidedCertifiedBlock>>,

    /// Per-block transaction fetch (intra-shard, pinned to proposer).
    pub transaction: TransactionFetch,

    /// Per-block local-provision fetch (intra-shard, pinned to proposer).
    pub local_provision: LocalProvisionFetch,

    /// Per-block finalized-wave fetch (intra-shard, rotates through committee).
    pub finalized_wave: FinalizedWaveFetch,

    /// Cross-shard provision fetch (rotates through source committee).
    pub provision: ProvisionFetch,

    /// Cross-shard execution-cert fetch (rotates through source committee).
    pub exec_cert: ExecCertFetch,

    /// Cross-shard committed-block-header fetch (rotates through source committee).
    pub header: HeaderFetch,
}

impl ProtocolHost {
    /// Build the protocol host from a node config.
    #[must_use]
    pub fn new(config: &NodeConfig) -> Self {
        Self {
            sync: SyncProtocol::new(config.sync.clone()),
            pending_block_topups: HashMap::new(),
            transaction: TransactionFetch::new("transaction", config.transaction_fetch.clone()),
            local_provision: LocalProvisionFetch::new(
                "local_provision",
                FetchConfig {
                    max_in_flight: 64,
                    max_ids_per_request: 16,
                    parallel_chunks_per_tick: 2,
                },
            ),
            finalized_wave: FinalizedWaveFetch::new(
                "finalized_wave",
                FetchConfig {
                    max_in_flight: 8,
                    max_ids_per_request: 4,
                    parallel_chunks_per_tick: 1,
                },
            ),
            provision: ProvisionFetch::new("provision", config.provision_fetch.clone()),
            exec_cert: ExecCertFetch::new("exec_cert", config.exec_cert_fetch.clone()),
            // Header fetches are scope-id (one per height); single-id chunks suffice.
            header: HeaderFetch::new(
                "header",
                FetchConfig {
                    max_in_flight: 16,
                    max_ids_per_request: 1,
                    parallel_chunks_per_tick: 4,
                },
            ),
        }
    }

    /// True if any fetch protocol has work outstanding (in-flight or
    /// queued), or if sync has heights parked behind a backoff.
    #[must_use]
    pub fn has_any_pending(&self) -> bool {
        self.transaction.has_pending()
            || self.local_provision.has_pending()
            || self.finalized_wave.has_pending()
            || self.provision.has_pending()
            || self.exec_cert.has_pending()
            || self.header.has_pending()
            || self.sync.has_deferred()
    }
}
