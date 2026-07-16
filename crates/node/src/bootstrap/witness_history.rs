//! Joiner-side beacon-witness history assembler.
//!
//! A vnode joining a shard must seed its beacon-witness accumulator
//! with the leaf-hash history at its boundary anchor: block headers
//! commit `(beacon_witness_root, beacon_witness_leaf_count)` over the
//! accumulator's full leaf-hash vector, so verifying any future
//! proposal requires every hash up to the anchor. The effects of folded
//! witnesses already live in the joiner's `BeaconState` — only the
//! hashes are needed, to extend and verify the commitment.
//!
//! Sans-io: [`WitnessHistorySync`] emits [`GetWitnessHistoryRequest`]s
//! and consumes responses; the driver owns peer selection and
//! transport.
//!
//! # Verification
//!
//! Pages carry no individual proof. The served header must hash to the
//! beacon-attested anchor `block_hash` (binding its witness root and
//! count), and the fully assembled vector must merkle to that root with
//! exactly that count. A mismatch — whichever page caused it — resets
//! the assembly to scratch; the driver rotates peers and retries, so a
//! Byzantine page costs one round, never a poisoned seed.

use hyperscale_types::network::request::GetWitnessHistoryRequest;
use hyperscale_types::network::response::GetWitnessHistoryResponse;
use hyperscale_types::{BeaconWitnessRoot, BlockHeader, Hash, ShardAnchor, compute_merkle_root};

use super::BootstrapOutcome;

#[derive(Debug, PartialEq, Eq)]
enum SyncState {
    /// Ready for [`WitnessHistorySync::next_request`] to emit a fetch.
    Idle,
    /// A request is out; responses in other states are unsolicited.
    InFlight,
    /// Assembled and verified against the anchor-bound header.
    Complete,
}

/// Witness-history assembly state for one shard bootstrap.
pub struct WitnessHistorySync {
    anchor: ShardAnchor,
    limit: u32,
    state: SyncState,
    header: Option<BlockHeader>,
    hashes: Vec<Hash>,
}

impl WitnessHistorySync {
    /// Start an assembly against `anchor`, fetching up to `limit` leaf
    /// hashes per request.
    #[must_use]
    pub fn new(anchor: ShardAnchor, limit: u32) -> Self {
        Self {
            anchor,
            limit: limit.max(1),
            state: SyncState::Idle,
            header: None,
            hashes: Vec::new(),
        }
    }

    /// The next page request, or `None` while one is in flight or the
    /// assembly is complete.
    ///
    /// `start_index` is absolute: the window base (learned from the
    /// first page's header) plus the hashes assembled so far. The
    /// opening request starts at zero — the server clamps it up to the
    /// base the joiner doesn't yet know.
    pub fn next_request(&mut self) -> Option<GetWitnessHistoryRequest> {
        if self.state != SyncState::Idle {
            return None;
        }
        self.state = SyncState::InFlight;
        let base = self
            .header
            .as_ref()
            .map_or(0, |h| h.beacon_witness_base().inner());
        Some(GetWitnessHistoryRequest {
            height: self.anchor.height,
            block_hash: self.anchor.block_hash,
            start_index: base + self.hashes.len() as u64,
            limit: self.limit,
        })
    }

    /// Re-arm after a transport-level failure (timeout, unreachable
    /// peer). Not a peer verdict — that's the transport's.
    pub fn on_failure(&mut self) {
        if self.state == SyncState::InFlight {
            self.state = SyncState::Idle;
        }
    }

    /// Verify and absorb one response.
    pub fn on_response(&mut self, response: &GetWitnessHistoryResponse) -> BootstrapOutcome {
        if self.state != SyncState::InFlight {
            return BootstrapOutcome::Rejected("unsolicited response");
        }
        self.state = SyncState::Idle;

        let Some(chunk) = &response.history else {
            return self.reject("history unavailable at peer");
        };
        if chunk.header.hash() != self.anchor.block_hash {
            return self.reject("served header does not hash to the anchor");
        }
        // The header's commitment spans its window `[base, count)`; the
        // assembly is the window's hashes only.
        let window_len = chunk
            .header
            .beacon_witness_leaf_count()
            .inner()
            .saturating_sub(chunk.header.beacon_witness_base().inner());
        let assembled = self.hashes.len() as u64 + chunk.leaf_hashes.len() as u64;
        if assembled > window_len {
            return self.reject("served hashes exceed the header's window");
        }
        if chunk.more {
            if chunk.leaf_hashes.is_empty() {
                return self.reject("empty page with continuation");
            }
            if assembled == window_len {
                return self.reject("continuation past the header's window");
            }
        } else if assembled < window_len {
            return self.reject("final page leaves the window short");
        }

        self.header = Some(chunk.header.clone());
        self.hashes.extend(chunk.leaf_hashes.iter().copied());
        if chunk.more {
            return BootstrapOutcome::Accepted;
        }

        // Final binding: the assembled window must merkle to the
        // anchor-bound header's commitment. Count equality holds by the
        // arithmetic above.
        let root = BeaconWitnessRoot::from_raw(compute_merkle_root(&self.hashes));
        if root != chunk.header.beacon_witness_root() {
            return self.reject("assembled window does not merkle to the header's root");
        }
        self.state = SyncState::Complete;
        BootstrapOutcome::Accepted
    }

    /// Whether the history is fully assembled and verified.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.state == SyncState::Complete
    }

    /// Take the verified boundary header and leaf-hash history, ready
    /// to seed a `RecoveredState`.
    ///
    /// # Panics
    ///
    /// Panics unless [`Self::is_complete`] — a partial history would
    /// seed an accumulator whose roots can never match.
    #[must_use]
    pub fn take_parts(&mut self) -> (BlockHeader, Vec<Hash>) {
        assert!(
            self.is_complete(),
            "witness history taken before assembly completed",
        );
        (
            self.header
                .take()
                .expect("complete assembly stored its header"),
            std::mem::take(&mut self.hashes),
        )
    }

    /// Drop everything assembled so far and re-arm. Pages carry no
    /// individual proof, so any failure poisons the whole assembly.
    fn reject(&mut self, reason: &'static str) -> BootstrapOutcome {
        self.hashes.clear();
        self.header = None;
        self.state = SyncState::Idle;
        BootstrapOutcome::Rejected(reason)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::{commit_block_with_witnesses, stake_deposit};
    use hyperscale_storage::{PendingChain, RecoveredState};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        BeaconWitnessLeafCount, BlockHash, BlockHeight, ShardWitnessPayload, StateRoot,
        WeightedTimestamp,
    };

    use super::*;
    use crate::bootstrap::witness_history_serve::serve_witness_history_request;

    const HEIGHT: u64 = 1;

    /// A serving replica with `leaves` committed at `HEIGHT`, plus the
    /// anchor naming its boundary.
    fn replica(leaves: &[ShardWitnessPayload]) -> (PendingChain<SimShardStorage>, ShardAnchor) {
        let storage = SimShardStorage::default();
        let block_hash = commit_block_with_witnesses(&storage, BlockHeight::new(HEIGHT), leaves);
        let anchor = ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash,
            height: BlockHeight::new(HEIGHT),
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            settled_waves_root: None,
        };
        (PendingChain::new(Arc::new(storage)), anchor)
    }

    /// Drive the assembly to completion against `peer`, asserting every
    /// page is accepted.
    fn drive(sync: &mut WitnessHistorySync, peer: &PendingChain<SimShardStorage>) {
        for _ in 0..1_000 {
            let Some(request) = sync.next_request() else {
                break;
            };
            let response = serve_witness_history_request(peer, &request);
            assert_eq!(sync.on_response(&response), BootstrapOutcome::Accepted);
        }
    }

    #[test]
    fn assembles_and_verifies_a_paginated_history() {
        let leaves: Vec<_> = (1u64..=5).map(stake_deposit).collect();
        let (peer, anchor) = replica(&leaves);

        let mut sync = WitnessHistorySync::new(anchor, 2);
        drive(&mut sync, &peer);
        assert!(sync.is_complete());
        assert!(sync.next_request().is_none());

        let (header, hashes) = sync.take_parts();
        assert_eq!(header.hash(), anchor.block_hash);
        let expected: Vec<Hash> = leaves.iter().map(ShardWitnessPayload::leaf_hash).collect();
        assert_eq!(hashes, expected);

        // The verified parts seed a snap-synced bootstrap's recovery.
        let recovered = RecoveredState::from_snap_synced_boundary(&anchor, &header, hashes, 0);
        assert_eq!(recovered.committed_height, anchor.height);
        assert_eq!(recovered.committed_hash, Some(anchor.block_hash));
        assert_eq!(recovered.jmt_root, Some(anchor.state_root));
        assert_eq!(
            recovered.committed_anchor_ts,
            Some(header.parent_qc().weighted_timestamp()),
        );
        assert!(recovered.latest_qc.is_none());
        assert_eq!(recovered.beacon_witness_leaf_hashes, expected);
    }

    #[test]
    fn zero_leaf_history_completes_empty() {
        let (peer, anchor) = replica(&[]);
        let mut sync = WitnessHistorySync::new(anchor, 16);
        drive(&mut sync, &peer);
        assert!(sync.is_complete());
        let (_, hashes) = sync.take_parts();
        assert!(hashes.is_empty());
    }

    /// An anchor whose header commits a window starting past leaf zero:
    /// the opening zero request clamps up to the base at the server, the
    /// assembly verifies against the windowed root, and the seeded
    /// recovery starts the accumulator at the base.
    #[test]
    fn windowed_anchor_assembles_the_window_only() {
        use hyperscale_storage::test_helpers::commit_block_with_witness_window;
        use hyperscale_types::BeaconWitnessLeafCount;

        let storage = SimShardStorage::default();
        let window: Vec<_> = (10u64..15).map(stake_deposit).collect();
        let block_hash = commit_block_with_witness_window(
            &storage,
            BlockHeight::new(HEIGHT),
            3,
            &window,
            &window,
            None,
        );
        let anchor = ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash,
            height: BlockHeight::new(HEIGHT),
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            settled_waves_root: None,
        };
        let peer = PendingChain::new(Arc::new(storage));

        let mut sync = WitnessHistorySync::new(anchor, 2);
        drive(&mut sync, &peer);
        assert!(sync.is_complete());

        let (header, hashes) = sync.take_parts();
        assert_eq!(header.beacon_witness_base(), BeaconWitnessLeafCount::new(3));
        let expected: Vec<Hash> = window.iter().map(ShardWitnessPayload::leaf_hash).collect();
        assert_eq!(hashes, expected);

        let recovered = RecoveredState::from_snap_synced_boundary(&anchor, &header, hashes, 0);
        assert_eq!(
            recovered.beacon_witness_start,
            BeaconWitnessLeafCount::new(3)
        );
    }

    #[test]
    fn header_not_matching_the_anchor_is_rejected() {
        let leaves: Vec<_> = (1u64..=3).map(stake_deposit).collect();
        let (peer, anchor) = replica(&leaves);

        // A peer on a different chain: same height, different block.
        let forged = ShardAnchor {
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"some_other_chain")),
            ..anchor
        };
        let mut sync = WitnessHistorySync::new(forged, 16);
        let request = sync.next_request().expect("idle assembly emits");
        // The honest peer answers unavailable for the unknown hash; a
        // Byzantine one would answer its own header, which fails the
        // anchor binding. Exercise the latter by asking the peer for
        // its real history and feeding it to the forged-anchor sync.
        let honest_request = GetWitnessHistoryRequest {
            block_hash: anchor.block_hash,
            ..request
        };
        let response = serve_witness_history_request(&peer, &honest_request);
        assert!(matches!(
            sync.on_response(&response),
            BootstrapOutcome::Rejected("served header does not hash to the anchor"),
        ));
        assert!(!sync.is_complete());
    }

    #[test]
    fn tampered_hash_fails_the_final_root_check_and_retry_heals() {
        let leaves: Vec<_> = (1u64..=4).map(stake_deposit).collect();
        let (peer, anchor) = replica(&leaves);

        let mut sync = WitnessHistorySync::new(anchor, 16);
        let request = sync.next_request().expect("idle assembly emits");
        let mut response = serve_witness_history_request(&peer, &request);
        response.history.as_mut().unwrap().leaf_hashes.0[1] = Hash::from_bytes(b"tampered");
        assert!(matches!(
            sync.on_response(&response),
            BootstrapOutcome::Rejected("assembled window does not merkle to the header's root"),
        ));

        // The rejection reset the assembly; an honest retry completes.
        drive(&mut sync, &peer);
        assert!(sync.is_complete());
    }

    #[test]
    fn short_final_page_is_rejected() {
        let leaves: Vec<_> = (1u64..=4).map(stake_deposit).collect();
        let (peer, anchor) = replica(&leaves);

        let mut sync = WitnessHistorySync::new(anchor, 16);
        let request = sync.next_request().expect("idle assembly emits");
        let mut response = serve_witness_history_request(&peer, &request);
        let chunk = response.history.as_mut().unwrap();
        chunk.leaf_hashes.0.pop();
        assert!(matches!(
            sync.on_response(&response),
            BootstrapOutcome::Rejected("final page leaves the window short"),
        ));
    }

    #[test]
    fn empty_continuation_page_is_rejected() {
        let leaves: Vec<_> = (1u64..=4).map(stake_deposit).collect();
        let (peer, anchor) = replica(&leaves);

        let mut sync = WitnessHistorySync::new(anchor, 16);
        let request = sync.next_request().expect("idle assembly emits");
        let mut response = serve_witness_history_request(&peer, &request);
        let chunk = response.history.as_mut().unwrap();
        chunk.leaf_hashes.0.clear();
        chunk.more = true;
        assert!(matches!(
            sync.on_response(&response),
            BootstrapOutcome::Rejected("empty page with continuation"),
        ));
    }

    #[test]
    fn unavailable_peer_rearms() {
        let leaves: Vec<_> = (1u64..=2).map(stake_deposit).collect();
        let (peer, anchor) = replica(&leaves);

        let mut sync = WitnessHistorySync::new(anchor, 16);
        let _ = sync.next_request().expect("idle assembly emits");
        assert!(matches!(
            sync.on_response(&GetWitnessHistoryResponse { history: None }),
            BootstrapOutcome::Rejected("history unavailable at peer"),
        ));

        drive(&mut sync, &peer);
        assert!(sync.is_complete());
    }

    #[test]
    fn unsolicited_response_is_rejected_without_reset() {
        let leaves: Vec<_> = (1u64..=2).map(stake_deposit).collect();
        let (peer, anchor) = replica(&leaves);

        let mut sync = WitnessHistorySync::new(anchor, 16);
        let request = sync.next_request().expect("idle assembly emits");
        let response = serve_witness_history_request(&peer, &request);
        assert_eq!(sync.on_response(&response), BootstrapOutcome::Accepted);
        assert!(sync.is_complete());

        // A duplicate delivery after completion must not disturb the
        // assembled state.
        assert!(matches!(
            sync.on_response(&response),
            BootstrapOutcome::Rejected("unsolicited response"),
        ));
        assert!(sync.is_complete());
    }
}
