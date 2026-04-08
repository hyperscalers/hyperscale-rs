//! Transaction certificate fetch protocol state machine.
//!
//! Pure synchronous state machine for fetching missing `WaveCertificate`s
//! needed by pending blocks.  Sits between the `BftState`'s `FetchCertificates`
//! action and the actual `network.request()` call, rotating through available
//! peers on failure before giving up.
//!
//! Modelled on `execution_cert_fetch.rs`.
//!
//! # Usage
//!
//! ```text
//! Runner ──► TxCertFetchProtocol::handle(Input) ──► Vec<Output>
//! ```

use hyperscale_metrics as metrics;
use hyperscale_types::{Hash, ValidatorId, WaveCertificate};
use quick_cache::sync::Cache as QuickCache;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use tracing::{debug, trace, warn};

// ═══════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════

/// Configuration for the transaction certificate fetch protocol.
#[derive(Debug, Clone)]
pub struct TxCertFetchConfig {
    /// Maximum number of concurrent fetch operations.
    pub max_concurrent: usize,
    /// Maximum full rounds through all peers before giving up.
    pub max_rounds: u32,
    /// Maximum certificate hashes per single network request.
    pub max_hashes_per_request: usize,
}

impl Default for TxCertFetchConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            max_rounds: 3,
            max_hashes_per_request: 1024 * 8,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Input / Output
// ═══════════════════════════════════════════════════════════════════════

/// Inputs to the transaction certificate fetch protocol state machine.
#[derive(Debug)]
pub enum TxCertFetchInput {
    /// A new fetch request from the BFT state machine.
    Request {
        block_hash: Hash,
        proposer: ValidatorId,
        cert_hashes: Vec<Hash>,
        peers: Vec<ValidatorId>,
    },
    /// Certificates were successfully received from a peer.
    Received {
        block_hash: Hash,
        certificates: Vec<Arc<WaveCertificate>>,
    },
    /// A fetch attempt failed (network error or peer returned empty).
    Failed { block_hash: Hash },
    /// Cancel a pending fetch (block committed, stale, or superseded).
    #[allow(dead_code)]
    Cancel { block_hash: Hash },
    /// Periodic tick — spawn pending fetch operations.
    Tick,
}

/// Outputs from the transaction certificate fetch protocol state machine.
#[derive(Debug)]
#[allow(dead_code)]
pub enum TxCertFetchOutput {
    /// Request the runner to fetch certificates from a specific peer.
    Fetch {
        block_hash: Hash,
        proposer: ValidatorId,
        cert_hashes: Vec<Hash>,
        peer: ValidatorId,
    },
    /// Deliver fetched certificates to the state machine.
    Deliver {
        block_hash: Hash,
        certificates: Vec<Arc<WaveCertificate>>,
    },
}

// ═══════════════════════════════════════════════════════════════════════
// Internal state
// ═══════════════════════════════════════════════════════════════════════

/// State for a single pending certificate fetch.
#[derive(Debug)]
struct PendingTxCertFetch {
    proposer: ValidatorId,
    cert_hashes: Vec<Hash>,
    peers: Vec<ValidatorId>,
    tried: HashSet<ValidatorId>,
    in_flight: bool,
    rounds: u32,
}

// ═══════════════════════════════════════════════════════════════════════
// Protocol state machine
// ═══════════════════════════════════════════════════════════════════════

/// Transaction certificate fetch protocol state machine.
pub struct TxCertFetchProtocol {
    config: TxCertFetchConfig,
    /// Pending fetches keyed by block_hash.
    pending: BTreeMap<Hash, PendingTxCertFetch>,
}

impl TxCertFetchProtocol {
    /// Create a new transaction certificate fetch protocol state machine.
    pub fn new(config: TxCertFetchConfig) -> Self {
        Self {
            config,
            pending: BTreeMap::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: TxCertFetchInput) -> Vec<TxCertFetchOutput> {
        match input {
            TxCertFetchInput::Request {
                block_hash,
                proposer,
                cert_hashes,
                peers,
            } => self.handle_request(block_hash, proposer, cert_hashes, peers),
            TxCertFetchInput::Received {
                block_hash,
                certificates,
            } => self.handle_received(block_hash, certificates),
            TxCertFetchInput::Failed { block_hash } => self.handle_failed(block_hash),
            TxCertFetchInput::Cancel { block_hash } => self.handle_cancel(block_hash),
            TxCertFetchInput::Tick => self.spawn_pending_fetches(),
        }
    }

    /// Check whether there are any pending certificate fetches.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Returns the number of currently in-flight fetch operations.
    #[allow(dead_code)]
    pub fn in_flight_count(&self) -> usize {
        self.pending.values().filter(|s| s.in_flight).count()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Input Handlers
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_request(
        &mut self,
        block_hash: Hash,
        proposer: ValidatorId,
        cert_hashes: Vec<Hash>,
        peers: Vec<ValidatorId>,
    ) -> Vec<TxCertFetchOutput> {
        if let Some(existing) = self.pending.get_mut(&block_hash) {
            // Duplicate request: refresh cert_hashes, peers, reset rounds.
            existing.cert_hashes = cert_hashes;
            existing.peers = peers;
            existing.proposer = proposer;
            existing.rounds = 0;
            trace!(?block_hash, "Refreshed peer list for pending tx cert fetch");
            return vec![];
        }

        debug!(
            ?block_hash,
            cert_count = cert_hashes.len(),
            peer_count = peers.len(),
            "Starting tx cert fetch"
        );
        metrics::record_fetch_started("tx_cert");

        self.pending.insert(
            block_hash,
            PendingTxCertFetch {
                proposer,
                cert_hashes,
                peers,
                tried: HashSet::new(),
                in_flight: false,
                rounds: 0,
            },
        );
        vec![]
    }

    fn handle_received(
        &mut self,
        block_hash: Hash,
        certificates: Vec<Arc<WaveCertificate>>,
    ) -> Vec<TxCertFetchOutput> {
        if self.pending.remove(&block_hash).is_some() {
            debug!(
                ?block_hash,
                count = certificates.len(),
                "Tx cert fetch complete"
            );
            metrics::record_fetch_completed("tx_cert");
            vec![TxCertFetchOutput::Deliver {
                block_hash,
                certificates,
            }]
        } else {
            trace!(?block_hash, "Tx certs received for unknown fetch");
            vec![]
        }
    }

    fn handle_failed(&mut self, block_hash: Hash) -> Vec<TxCertFetchOutput> {
        if let Some(state) = self.pending.get_mut(&block_hash) {
            state.in_flight = false;
            metrics::record_fetch_failed("tx_cert");
            warn!(
                ?block_hash,
                tried = state.tried.len(),
                remaining = state.peers.len().saturating_sub(state.tried.len()),
                "Tx cert fetch failed, will try next peer"
            );
        }
        vec![]
    }

    fn handle_cancel(&mut self, block_hash: Hash) -> Vec<TxCertFetchOutput> {
        if self.pending.remove(&block_hash).is_some() {
            debug!(?block_hash, "Tx cert fetch cancelled");
        }
        vec![]
    }

    /// Spawn pending fetch operations (called on Tick).
    fn spawn_pending_fetches(&mut self) -> Vec<TxCertFetchOutput> {
        let mut outputs = Vec::new();
        let mut to_remove = Vec::new();

        // Count current in-flight to respect max_concurrent.
        let in_flight_count = self.pending.values().filter(|s| s.in_flight).count();
        let mut available_slots = self.config.max_concurrent.saturating_sub(in_flight_count);

        for (&block_hash, state) in &mut self.pending {
            if available_slots == 0 {
                break;
            }
            if state.in_flight {
                continue;
            }

            // Prefer the proposer first, then rotate through remaining peers.
            let peer = if !state.tried.contains(&state.proposer)
                && state.peers.contains(&state.proposer)
            {
                Some(state.proposer)
            } else {
                state
                    .peers
                    .iter()
                    .find(|p| !state.tried.contains(p))
                    .copied()
            };

            match peer {
                Some(peer) => {
                    state.tried.insert(peer);
                    state.in_flight = true;
                    available_slots -= 1;

                    // Truncate to max_hashes_per_request.
                    let hashes = if state.cert_hashes.len() > self.config.max_hashes_per_request {
                        state.cert_hashes[..self.config.max_hashes_per_request].to_vec()
                    } else {
                        state.cert_hashes.clone()
                    };

                    trace!(
                        ?block_hash,
                        peer = peer.0,
                        cert_count = hashes.len(),
                        "Fetching tx certs from peer"
                    );
                    outputs.push(TxCertFetchOutput::Fetch {
                        block_hash,
                        proposer: state.proposer,
                        cert_hashes: hashes,
                        peer,
                    });
                }
                None => {
                    state.rounds += 1;
                    if state.rounds >= self.config.max_rounds {
                        warn!(
                            ?block_hash,
                            rounds = state.rounds,
                            "Tx cert fetch exhausted all rounds, dropping"
                        );
                        to_remove.push(block_hash);
                    } else {
                        warn!(
                            ?block_hash,
                            round = state.rounds,
                            "Tx cert fetch starting new round"
                        );
                        state.tried.clear();
                    }
                }
            }
        }

        for key in to_remove {
            self.pending.remove(&key);
        }

        outputs
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Serving function
// ═══════════════════════════════════════════════════════════════════════

/// Serve a wave certificate fetch request using cache + storage fallback.
///
/// Called by the network request handler on the handler thread pool.
/// Keys are `wave_id.hash()` values from `BlockManifest::cert_hashes`.
pub fn serve_certificate_request<S: hyperscale_storage::ConsensusStore>(
    storage: &S,
    cert_cache: &QuickCache<Hash, Arc<WaveCertificate>>,
    req: hyperscale_messages::request::GetCertificatesRequest,
) -> hyperscale_messages::response::GetCertificatesResponse {
    let mut found = Vec::with_capacity(req.cert_hashes.len());
    let mut cache_misses = Vec::new();

    // Check cache first.
    for hash in &req.cert_hashes {
        if let Some(cert) = cert_cache.get(hash) {
            found.push(cert);
        } else {
            cache_misses.push(*hash);
        }
    }

    // Storage fallback: look up wave certificates by their identity hash.
    if !cache_misses.is_empty() {
        let from_storage = storage.get_certificates_batch(&cache_misses);
        for wc in from_storage {
            found.push(Arc::new(wc));
        }
    }

    hyperscale_messages::response::GetCertificatesResponse::new(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> TxCertFetchConfig {
        TxCertFetchConfig::default()
    }

    fn vid(id: u64) -> ValidatorId {
        ValidatorId(id)
    }

    fn hash(s: &[u8]) -> Hash {
        Hash::from_bytes(s)
    }

    #[test]
    fn test_config_defaults() {
        let config = TxCertFetchConfig::default();
        assert_eq!(config.max_concurrent, 4);
        assert_eq!(config.max_rounds, 3);
        assert_eq!(config.max_hashes_per_request, 1024 * 8);
    }

    #[test]
    fn test_request_and_tick() {
        let mut protocol = TxCertFetchProtocol::new(default_config());

        let outputs = protocol.handle(TxCertFetchInput::Request {
            block_hash: hash(b"block1"),
            proposer: vid(1),
            cert_hashes: vec![hash(b"cert1"), hash(b"cert2")],
            peers: vec![vid(1), vid(2), vid(3)],
        });
        assert!(outputs.is_empty());
        assert!(protocol.has_pending());

        // Tick should emit a Fetch with the proposer (preferred peer).
        let outputs = protocol.handle(TxCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            TxCertFetchOutput::Fetch {
                block_hash,
                proposer,
                cert_hashes,
                peer,
            } => {
                assert_eq!(*block_hash, hash(b"block1"));
                assert_eq!(*proposer, vid(1));
                assert_eq!(cert_hashes.len(), 2);
                assert_eq!(*peer, vid(1)); // proposer preferred
            }
            _ => panic!("Expected Fetch output"),
        }
    }

    #[test]
    fn test_peer_rotation_on_failure() {
        let mut protocol = TxCertFetchProtocol::new(default_config());

        protocol.handle(TxCertFetchInput::Request {
            block_hash: hash(b"block1"),
            proposer: vid(1),
            cert_hashes: vec![hash(b"cert1")],
            peers: vec![vid(1), vid(2), vid(3)],
        });

        // Tick 1: proposer vid(1).
        let outputs = protocol.handle(TxCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            TxCertFetchOutput::Fetch { peer, .. } if *peer == vid(1)
        ));

        // Fail → frees in_flight.
        protocol.handle(TxCertFetchInput::Failed {
            block_hash: hash(b"block1"),
        });

        // Tick 2: next untried peer (vid(2)).
        let outputs = protocol.handle(TxCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            TxCertFetchOutput::Fetch { peer, .. } if *peer == vid(2)
        ));

        // Fail again.
        protocol.handle(TxCertFetchInput::Failed {
            block_hash: hash(b"block1"),
        });

        // Tick 3: last peer (vid(3)).
        let outputs = protocol.handle(TxCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            TxCertFetchOutput::Fetch { peer, .. } if *peer == vid(3)
        ));
    }

    #[test]
    fn test_all_peers_exhausted_after_max_rounds() {
        let config = TxCertFetchConfig {
            max_rounds: 2,
            ..default_config()
        };
        let mut protocol = TxCertFetchProtocol::new(config);

        protocol.handle(TxCertFetchInput::Request {
            block_hash: hash(b"block1"),
            proposer: vid(1),
            cert_hashes: vec![hash(b"cert1")],
            peers: vec![vid(1), vid(2)],
        });

        // --- Round 0 ---
        protocol.handle(TxCertFetchInput::Tick);
        protocol.handle(TxCertFetchInput::Failed {
            block_hash: hash(b"block1"),
        });
        protocol.handle(TxCertFetchInput::Tick);
        protocol.handle(TxCertFetchInput::Failed {
            block_hash: hash(b"block1"),
        });
        // All peers exhausted → round 0→1, tried reset.
        let outputs = protocol.handle(TxCertFetchInput::Tick);
        assert!(outputs.is_empty());
        assert!(
            protocol.has_pending(),
            "Should still be pending after round 0"
        );

        // --- Round 1 ---
        let outputs = protocol.handle(TxCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1, "Should retry vid(1) in round 1");
        protocol.handle(TxCertFetchInput::Failed {
            block_hash: hash(b"block1"),
        });
        protocol.handle(TxCertFetchInput::Tick);
        protocol.handle(TxCertFetchInput::Failed {
            block_hash: hash(b"block1"),
        });
        // All peers exhausted → round 1→2, but max_rounds=2 → drop.
        let outputs = protocol.handle(TxCertFetchInput::Tick);
        assert!(outputs.is_empty());
        assert!(
            !protocol.has_pending(),
            "Should be dropped after max_rounds"
        );
    }

    #[test]
    fn test_successful_receive() {
        let mut protocol = TxCertFetchProtocol::new(default_config());

        protocol.handle(TxCertFetchInput::Request {
            block_hash: hash(b"block1"),
            proposer: vid(1),
            cert_hashes: vec![hash(b"cert1")],
            peers: vec![vid(1), vid(2)],
        });

        // Tick → fetch from proposer.
        protocol.handle(TxCertFetchInput::Tick);

        // Receive certificates.
        let outputs = protocol.handle(TxCertFetchInput::Received {
            block_hash: hash(b"block1"),
            certificates: vec![],
        });

        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            TxCertFetchOutput::Deliver { certificates, .. } if certificates.is_empty()
        ));
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_cancel_removes_pending() {
        let mut protocol = TxCertFetchProtocol::new(default_config());

        protocol.handle(TxCertFetchInput::Request {
            block_hash: hash(b"block1"),
            proposer: vid(1),
            cert_hashes: vec![hash(b"cert1")],
            peers: vec![vid(1)],
        });
        assert!(protocol.has_pending());

        protocol.handle(TxCertFetchInput::Cancel {
            block_hash: hash(b"block1"),
        });
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_max_concurrent_respected() {
        let config = TxCertFetchConfig {
            max_concurrent: 2,
            ..default_config()
        };
        let mut protocol = TxCertFetchProtocol::new(config);

        for i in 0..3u8 {
            protocol.handle(TxCertFetchInput::Request {
                block_hash: hash(&[i]),
                proposer: vid(1),
                cert_hashes: vec![hash(b"cert1")],
                peers: vec![vid(1)],
            });
        }

        let outputs = protocol.handle(TxCertFetchInput::Tick);
        assert_eq!(outputs.len(), 2);
    }

    #[test]
    fn test_in_flight_not_double_dispatched() {
        let mut protocol = TxCertFetchProtocol::new(default_config());

        protocol.handle(TxCertFetchInput::Request {
            block_hash: hash(b"block1"),
            proposer: vid(1),
            cert_hashes: vec![hash(b"cert1")],
            peers: vec![vid(1), vid(2)],
        });

        let outputs = protocol.handle(TxCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1);

        // Second tick while still in-flight: no new dispatch.
        let outputs = protocol.handle(TxCertFetchInput::Tick);
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_receive_for_unknown_fetch_ignored() {
        let mut protocol = TxCertFetchProtocol::new(default_config());

        let outputs = protocol.handle(TxCertFetchInput::Received {
            block_hash: hash(b"unknown"),
            certificates: vec![],
        });
        assert!(outputs.is_empty());
    }
}
