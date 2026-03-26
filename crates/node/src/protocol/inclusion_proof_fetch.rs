//! Inclusion proof fetch protocol state machine.
//!
//! Pure synchronous state machine for fetching transaction inclusion proofs
//! from source shards during livelock resolution. Sits between the livelock
//! system's `RequestTxInclusionProof` action and the actual `network.request()`
//! call, rotating through available peers on failure before giving up.
//!
//! # Usage
//!
//! ```text
//! Runner ──► InclusionProofFetchProtocol::handle(Input) ──► Vec<Output>
//! ```

use hyperscale_types::{BlockHeight, Hash, ShardGroupId, TransactionInclusionProof, ValidatorId};
use std::collections::{HashMap, HashSet};
use tracing::{debug, trace, warn};

/// Configuration for the inclusion proof fetch protocol.
#[derive(Debug, Clone)]
pub struct InclusionProofFetchConfig {
    /// Maximum number of retries per peer before rotating to the next.
    pub max_retries_per_peer: u32,
}

impl Default for InclusionProofFetchConfig {
    fn default() -> Self {
        Self {
            max_retries_per_peer: 3,
        }
    }
}

/// Inputs to the inclusion proof fetch protocol state machine.
#[derive(Debug)]
pub enum InclusionProofFetchInput {
    /// A new fetch request from the livelock system.
    Request {
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        winner_tx_hash: Hash,
        loser_tx_hash: Hash,
        peers: Vec<ValidatorId>,
        preferred_peer: ValidatorId,
    },
    /// Proof was successfully received.
    Received {
        winner_tx_hash: Hash,
        loser_tx_hash: Hash,
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        proof: TransactionInclusionProof,
    },
    /// A fetch attempt failed.
    Failed { winner_tx_hash: Hash },
    /// Cancel a pending fetch (e.g. loser tx completed before proof arrived).
    /// TODO: Wire up cancellation when loser tx completes (certificate/abort)
    /// before the inclusion proof arrives, to avoid wasted network requests.
    #[allow(dead_code)]
    Cancel { winner_tx_hash: Hash },
    /// Periodic tick — spawn pending fetch operations.
    Tick,
}

/// Outputs from the inclusion proof fetch protocol state machine.
#[derive(Debug)]
pub enum InclusionProofFetchOutput {
    /// Send a network request to a peer.
    Fetch {
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        winner_tx_hash: Hash,
        loser_tx_hash: Hash,
        peer: ValidatorId,
    },
    /// Deliver the proof to the state machine.
    Deliver {
        winner_tx_hash: Hash,
        loser_tx_hash: Hash,
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        proof: TransactionInclusionProof,
    },
}

/// State for a single pending inclusion proof fetch.
#[derive(Debug)]
struct PendingInclusionProofFetch {
    source_shard: ShardGroupId,
    source_block_height: BlockHeight,
    loser_tx_hash: Hash,
    peers: Vec<ValidatorId>,
    preferred_peer: ValidatorId,
    tried: HashSet<ValidatorId>,
    retries_on_current: u32,
    current_peer: Option<ValidatorId>,
    in_flight: bool,
}

/// Inclusion proof fetch protocol state machine.
pub struct InclusionProofFetchProtocol {
    config: InclusionProofFetchConfig,
    /// Pending fetches keyed by winner_tx_hash.
    pending: HashMap<Hash, PendingInclusionProofFetch>,
}

impl InclusionProofFetchProtocol {
    /// Create a new inclusion proof fetch protocol state machine.
    pub fn new(config: InclusionProofFetchConfig) -> Self {
        Self {
            config,
            pending: HashMap::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: InclusionProofFetchInput) -> Vec<InclusionProofFetchOutput> {
        match input {
            InclusionProofFetchInput::Request {
                source_shard,
                source_block_height,
                winner_tx_hash,
                loser_tx_hash,
                peers,
                preferred_peer,
            } => self.handle_request(
                source_shard,
                source_block_height,
                winner_tx_hash,
                loser_tx_hash,
                peers,
                preferred_peer,
            ),
            InclusionProofFetchInput::Received {
                winner_tx_hash,
                loser_tx_hash,
                source_shard,
                source_block_height,
                proof,
            } => self.handle_received(
                winner_tx_hash,
                loser_tx_hash,
                source_shard,
                source_block_height,
                proof,
            ),
            InclusionProofFetchInput::Failed { winner_tx_hash } => {
                self.handle_failed(winner_tx_hash)
            }
            InclusionProofFetchInput::Cancel { winner_tx_hash } => {
                self.handle_cancel(winner_tx_hash)
            }
            InclusionProofFetchInput::Tick => self.spawn_pending_fetches(),
        }
    }

    /// Check whether there are any pending inclusion proof fetches.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Input Handlers
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_request(
        &mut self,
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        winner_tx_hash: Hash,
        loser_tx_hash: Hash,
        peers: Vec<ValidatorId>,
        preferred_peer: ValidatorId,
    ) -> Vec<InclusionProofFetchOutput> {
        if let Some(existing) = self.pending.get_mut(&winner_tx_hash) {
            // Duplicate request: refresh peer list, reset retries for fresh cycle.
            existing.peers = peers;
            existing.preferred_peer = preferred_peer;
            existing.retries_on_current = 0;
            existing.current_peer = None;
            existing.tried.clear();
            trace!(
                winner_tx = %winner_tx_hash,
                "Refreshed peer list for pending inclusion proof fetch"
            );
            return vec![];
        }

        debug!(
            winner_tx = %winner_tx_hash,
            loser_tx = %loser_tx_hash,
            source_shard = source_shard.0,
            block_height = source_block_height.0,
            peer_count = peers.len(),
            "Starting inclusion proof fetch"
        );

        self.pending.insert(
            winner_tx_hash,
            PendingInclusionProofFetch {
                source_shard,
                source_block_height,
                loser_tx_hash,
                peers,
                preferred_peer,
                tried: HashSet::new(),
                retries_on_current: 0,
                current_peer: None,
                in_flight: false,
            },
        );
        vec![]
    }

    fn handle_received(
        &mut self,
        winner_tx_hash: Hash,
        loser_tx_hash: Hash,
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        proof: TransactionInclusionProof,
    ) -> Vec<InclusionProofFetchOutput> {
        if self.pending.remove(&winner_tx_hash).is_some() {
            debug!(
                winner_tx = %winner_tx_hash,
                "Inclusion proof fetch complete"
            );
            vec![InclusionProofFetchOutput::Deliver {
                winner_tx_hash,
                loser_tx_hash,
                source_shard,
                source_block_height,
                proof,
            }]
        } else {
            trace!(
                winner_tx = %winner_tx_hash,
                "Inclusion proof received for unknown fetch"
            );
            vec![]
        }
    }

    fn handle_cancel(&mut self, winner_tx_hash: Hash) -> Vec<InclusionProofFetchOutput> {
        if self.pending.remove(&winner_tx_hash).is_some() {
            debug!(
                winner_tx = %winner_tx_hash,
                "Inclusion proof fetch cancelled"
            );
        }
        vec![]
    }

    fn handle_failed(&mut self, winner_tx_hash: Hash) -> Vec<InclusionProofFetchOutput> {
        if let Some(state) = self.pending.get_mut(&winner_tx_hash) {
            state.in_flight = false;
            state.retries_on_current += 1;

            // If we've exhausted retries on the current peer, mark it as tried
            // and move to the next one.
            if state.retries_on_current >= self.config.max_retries_per_peer {
                if let Some(peer) = state.current_peer.take() {
                    state.tried.insert(peer);
                }
                state.retries_on_current = 0;
            }

            warn!(
                winner_tx = %winner_tx_hash,
                tried = state.tried.len(),
                retries_on_current = state.retries_on_current,
                "Inclusion proof fetch failed, will retry"
            );
        }
        vec![]
    }

    /// Spawn pending fetch operations (called on Tick).
    fn spawn_pending_fetches(&mut self) -> Vec<InclusionProofFetchOutput> {
        let mut outputs = Vec::new();
        let mut to_remove = Vec::new();

        for (&winner_tx_hash, state) in &mut self.pending {
            if state.in_flight {
                continue;
            }

            // If we have a current peer that hasn't exhausted retries, reuse it.
            if let Some(peer) = state.current_peer {
                state.in_flight = true;
                trace!(
                    winner_tx = %winner_tx_hash,
                    peer = peer.0,
                    retry = state.retries_on_current,
                    "Retrying inclusion proof fetch from same peer"
                );
                outputs.push(InclusionProofFetchOutput::Fetch {
                    source_shard: state.source_shard,
                    block_height: state.source_block_height,
                    winner_tx_hash,
                    loser_tx_hash: state.loser_tx_hash,
                    peer,
                });
                continue;
            }

            // Pick the next peer to try.
            let peer = if !state.tried.contains(&state.preferred_peer) {
                Some(state.preferred_peer)
            } else {
                state
                    .peers
                    .iter()
                    .find(|p| !state.tried.contains(p))
                    .copied()
            };

            match peer {
                Some(peer) => {
                    state.current_peer = Some(peer);
                    state.retries_on_current = 0;
                    state.in_flight = true;
                    trace!(
                        winner_tx = %winner_tx_hash,
                        peer = peer.0,
                        "Fetching inclusion proof from peer"
                    );
                    outputs.push(InclusionProofFetchOutput::Fetch {
                        source_shard: state.source_shard,
                        block_height: state.source_block_height,
                        winner_tx_hash,
                        loser_tx_hash: state.loser_tx_hash,
                        peer,
                    });
                }
                None => {
                    // All peers exhausted — give up.
                    warn!(
                        winner_tx = %winner_tx_hash,
                        tried = state.tried.len(),
                        "Inclusion proof fetch exhausted all peers, dropping"
                    );
                    to_remove.push(winner_tx_hash);
                }
            }
        }

        for key in to_remove {
            self.pending.remove(&key);
        }

        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> InclusionProofFetchConfig {
        InclusionProofFetchConfig::default()
    }

    fn shard(id: u64) -> ShardGroupId {
        ShardGroupId(id)
    }

    fn height(h: u64) -> BlockHeight {
        BlockHeight(h)
    }

    fn vid(id: u64) -> ValidatorId {
        ValidatorId(id)
    }

    fn tx_hash(val: u8) -> Hash {
        let bytes = [val; 1];
        Hash::from_bytes(&bytes)
    }

    fn dummy_proof() -> TransactionInclusionProof {
        TransactionInclusionProof {
            siblings: vec![],
            leaf_index: 0,
            leaf_hash: Hash::ZERO,
        }
    }

    #[test]
    fn test_config_defaults() {
        let config = InclusionProofFetchConfig::default();
        assert_eq!(config.max_retries_per_peer, 3);
    }

    #[test]
    fn test_request_and_tick() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());

        let outputs = protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            loser_tx_hash: tx_hash(2),
            peers: vec![vid(1), vid(2), vid(3)],
            preferred_peer: vid(1),
        });
        assert!(outputs.is_empty());
        assert!(protocol.has_pending());

        // Tick should emit a Fetch with the preferred peer.
        let outputs = protocol.handle(InclusionProofFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            InclusionProofFetchOutput::Fetch {
                source_shard,
                block_height,
                winner_tx_hash,
                peer,
                ..
            } => {
                assert_eq!(*source_shard, shard(1));
                assert_eq!(*block_height, height(10));
                assert_eq!(*winner_tx_hash, tx_hash(1));
                assert_eq!(*peer, vid(1));
            }
            _ => panic!("Expected Fetch output"),
        }
    }

    #[test]
    fn test_retry_same_peer_then_rotate() {
        let config = InclusionProofFetchConfig {
            max_retries_per_peer: 2,
        };
        let mut protocol = InclusionProofFetchProtocol::new(config);

        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            loser_tx_hash: tx_hash(2),
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        // Tick 1: preferred peer (vid(1)).
        let outputs = protocol.handle(InclusionProofFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            InclusionProofFetchOutput::Fetch { peer, .. } if *peer == vid(1)
        ));

        // Fail once — should retry same peer (retries_on_current < 2).
        protocol.handle(InclusionProofFetchInput::Failed {
            winner_tx_hash: tx_hash(1),
        });
        let outputs = protocol.handle(InclusionProofFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            InclusionProofFetchOutput::Fetch { peer, .. } if *peer == vid(1)
        ));

        // Fail again — now retries_on_current reaches 2, rotate to vid(2).
        protocol.handle(InclusionProofFetchInput::Failed {
            winner_tx_hash: tx_hash(1),
        });
        let outputs = protocol.handle(InclusionProofFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            InclusionProofFetchOutput::Fetch { peer, .. } if *peer == vid(2)
        ));
    }

    #[test]
    fn test_all_peers_exhausted() {
        let config = InclusionProofFetchConfig {
            max_retries_per_peer: 1,
        };
        let mut protocol = InclusionProofFetchProtocol::new(config);

        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            loser_tx_hash: tx_hash(2),
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        // Try vid(1), fail (exhausted after 1 retry).
        protocol.handle(InclusionProofFetchInput::Tick);
        protocol.handle(InclusionProofFetchInput::Failed {
            winner_tx_hash: tx_hash(1),
        });

        // Try vid(2), fail.
        protocol.handle(InclusionProofFetchInput::Tick);
        protocol.handle(InclusionProofFetchInput::Failed {
            winner_tx_hash: tx_hash(1),
        });

        // All peers exhausted — should be dropped.
        let outputs = protocol.handle(InclusionProofFetchInput::Tick);
        assert!(outputs.is_empty());
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_successful_receive() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());

        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            loser_tx_hash: tx_hash(2),
            peers: vec![vid(1)],
            preferred_peer: vid(1),
        });

        protocol.handle(InclusionProofFetchInput::Tick);

        let outputs = protocol.handle(InclusionProofFetchInput::Received {
            winner_tx_hash: tx_hash(1),
            loser_tx_hash: tx_hash(2),
            source_shard: shard(1),
            source_block_height: height(10),
            proof: dummy_proof(),
        });

        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            InclusionProofFetchOutput::Deliver { winner_tx_hash, .. } if *winner_tx_hash == tx_hash(1)
        ));
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_cancel_removes_pending() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());

        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            loser_tx_hash: tx_hash(2),
            peers: vec![vid(1)],
            preferred_peer: vid(1),
        });
        assert!(protocol.has_pending());

        protocol.handle(InclusionProofFetchInput::Cancel {
            winner_tx_hash: tx_hash(1),
        });
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_cancel_unknown_is_noop() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());
        let outputs = protocol.handle(InclusionProofFetchInput::Cancel {
            winner_tx_hash: tx_hash(99),
        });
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_receive_for_unknown_ignored() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());
        let outputs = protocol.handle(InclusionProofFetchInput::Received {
            winner_tx_hash: tx_hash(99),
            loser_tx_hash: tx_hash(100),
            source_shard: shard(1),
            source_block_height: height(10),
            proof: dummy_proof(),
        });
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_in_flight_not_double_dispatched() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());

        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            loser_tx_hash: tx_hash(2),
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        let outputs = protocol.handle(InclusionProofFetchInput::Tick);
        assert_eq!(outputs.len(), 1);

        // Second tick while in-flight: no new dispatch.
        let outputs = protocol.handle(InclusionProofFetchInput::Tick);
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_duplicate_request_refreshes_peers() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());

        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            loser_tx_hash: tx_hash(2),
            peers: vec![vid(1)],
            preferred_peer: vid(1),
        });

        // Submit duplicate with different peers.
        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            loser_tx_hash: tx_hash(2),
            peers: vec![vid(1), vid(2), vid(3)],
            preferred_peer: vid(2),
        });

        // Should use the new preferred peer.
        let outputs = protocol.handle(InclusionProofFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            InclusionProofFetchOutput::Fetch { peer, .. } if *peer == vid(2)
        ));
    }
}
