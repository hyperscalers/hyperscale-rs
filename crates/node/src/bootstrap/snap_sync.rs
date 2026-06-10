//! Joiner-side snap-sync assembler.
//!
//! A vnode joining a shard bootstraps the shard's committed state
//! against its beacon-attested boundary anchor: the shard's key span is
//! partitioned into disjoint sub-ranges fetched from serving peers in
//! parallel, every chunk is verified against the anchor's `state_root`
//! before it is kept, and the accumulated leaves feed
//! `BoundaryStore::import_boundary_state` — whose returned root the
//! driver compares against the anchor before trusting the store.
//!
//! Sans-io: [`SnapSync`] emits [`GetStateRangeRequest`]s and consumes
//! responses; the driver owns peer selection, transport, and retry
//! pacing. A rejected or failed chunk simply re-arms its sub-range, so
//! retrying against a different peer is the driver rotating who it asks.
//!
//! # Chunk verification
//!
//! Nothing in a response is trusted bare. Three bindings tie each chunk
//! to the attested root:
//!
//! 1. the range proof proves the leaf keys into `state_root`, with the
//!    completeness check rejecting omitted in-span leaves;
//! 2. each leaf key's low half must equal `blake3(storage_key)[..16]`,
//!    binding the shipped raw key without needing the ownership map (the
//!    high, owner-routing half is positional — the proof attests it);
//! 3. each proof claim's value hash is recomputed from the shipped raw
//!    value.

use hyperscale_jmt::{Blake3Hasher, Key, MultiProof, NibblePath, RangeChunk, Tree, subspan};
use hyperscale_storage::ImportLeaf;
use hyperscale_types::network::request::GetStateRangeRequest;
use hyperscale_types::network::response::{GetStateRangeResponse, StateRangeChunk};
use hyperscale_types::state_key::{jmt_value_hash, leaf_key_binds_storage_key};
use hyperscale_types::{Hash, ShardAnchor};

type Jmt = Tree<Blake3Hasher, 1>;

/// One partitioned sub-range of the shard's key span.
#[derive(Debug)]
struct SubRange {
    /// Next un-fetched key (inclusive).
    cursor: Key,
    /// Last key of this sub-range (inclusive).
    end: Key,
    state: SubRangeState,
}

#[derive(Debug, PartialEq, Eq)]
enum SubRangeState {
    /// Ready for [`SnapSync::next_requests`] to emit a fetch.
    Idle,
    /// A request is out; responses for other states are unsolicited.
    InFlight,
    /// Exhausted through `end`.
    Done,
}

/// Outcome of feeding one response into [`SnapSync::on_response`].
#[derive(Debug, PartialEq, Eq)]
pub enum ChunkOutcome {
    /// Chunk verified and absorbed; the sub-range continues (or just
    /// finished — check [`SnapSync::is_complete`]).
    Accepted,
    /// Chunk rejected; the sub-range is re-armed for retry. The driver
    /// should penalize the peer and rotate.
    Rejected(&'static str),
}

/// Snap-sync assembly state for one shard bootstrap.
pub struct SnapSync {
    anchor: ShardAnchor,
    root_path: NibblePath,
    chunk_limit: u32,
    sub_ranges: Vec<SubRange>,
    leaves: Vec<ImportLeaf>,
}

impl SnapSync {
    /// Start an assembly against `anchor` for the shard rooted at
    /// `root_path`, partitioned into `2^split_bits` parallel sub-ranges,
    /// fetching up to `chunk_limit` leaves per request.
    #[must_use]
    pub fn new(
        anchor: ShardAnchor,
        root_path: NibblePath,
        split_bits: u8,
        chunk_limit: u32,
    ) -> Self {
        let sub_ranges = (0..1u64 << split_bits)
            .map(|index| {
                let (low, high) = subspan(&root_path, split_bits, index);
                SubRange {
                    cursor: low,
                    end: high,
                    state: SubRangeState::Idle,
                }
            })
            .collect();
        Self {
            anchor,
            root_path,
            chunk_limit: chunk_limit.max(1),
            sub_ranges,
            leaves: Vec::new(),
        }
    }

    /// Emit a request for every idle sub-range, marking each in flight.
    /// Returned pairs are `(sub_range id, request)`; the driver answers
    /// through [`Self::on_response`] / [`Self::on_failure`] with the id.
    pub fn next_requests(&mut self) -> Vec<(usize, GetStateRangeRequest)> {
        let height = self.anchor.height;
        let limit = self.chunk_limit;
        self.sub_ranges
            .iter_mut()
            .enumerate()
            .filter(|(_, sub)| sub.state == SubRangeState::Idle)
            .map(|(id, sub)| {
                sub.state = SubRangeState::InFlight;
                let request = GetStateRangeRequest {
                    height,
                    start: Hash::from_hash_bytes(&sub.cursor),
                    end: Hash::from_hash_bytes(&sub.end),
                    limit,
                };
                (id, request)
            })
            .collect()
    }

    /// Re-arm a sub-range after a transport-level failure (timeout,
    /// unreachable peer). Not a peer verdict — that's the transport's.
    ///
    /// # Panics
    ///
    /// Panics if `sub_range` is not an id this assembly emitted.
    pub fn on_failure(&mut self, sub_range: usize) {
        let sub = &mut self.sub_ranges[sub_range];
        if sub.state == SubRangeState::InFlight {
            sub.state = SubRangeState::Idle;
        }
    }

    /// Verify and absorb one response for `sub_range`.
    ///
    /// # Panics
    ///
    /// Panics if `sub_range` is not an id this assembly emitted.
    pub fn on_response(
        &mut self,
        sub_range: usize,
        response: &GetStateRangeResponse,
    ) -> ChunkOutcome {
        let sub = &mut self.sub_ranges[sub_range];
        if sub.state != SubRangeState::InFlight {
            return ChunkOutcome::Rejected("unsolicited response");
        }
        sub.state = SubRangeState::Idle;

        let Some(chunk) = &response.chunk else {
            return ChunkOutcome::Rejected("boundary unavailable at peer");
        };
        let verified = match verify_chunk(
            self.anchor.state_root.as_raw().as_bytes(),
            &self.root_path,
            &sub.cursor,
            &sub.end,
            chunk,
        ) {
            Ok(verified) => verified,
            Err(reason) => return ChunkOutcome::Rejected(reason),
        };

        if chunk.more {
            // Complete through the last leaf; resume just past it. The
            // verifier rejected `more` without leaves, so `last` exists,
            // and a leaf at the absolute key-space maximum cannot have a
            // successor — the span is exhausted.
            let last = verified
                .last()
                .expect("verified truncated chunk carries leaves")
                .leaf_key;
            match next_key(&last) {
                Some(next) => sub.cursor = next,
                None => sub.state = SubRangeState::Done,
            }
        } else {
            sub.state = SubRangeState::Done;
        }
        self.leaves.extend(verified);
        ChunkOutcome::Accepted
    }

    /// Whether every sub-range is exhausted.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.sub_ranges
            .iter()
            .all(|sub| sub.state == SubRangeState::Done)
    }

    /// The verified leaves, ready for
    /// `BoundaryStore::import_boundary_state`.
    ///
    /// # Panics
    ///
    /// Panics unless [`Self::is_complete`] — a partial import would
    /// produce a root that can never match the anchor.
    #[must_use]
    pub fn into_leaves(self) -> Vec<ImportLeaf> {
        assert!(
            self.is_complete(),
            "snap-sync leaves taken before assembly completed",
        );
        self.leaves
    }
}

/// Verify one wire chunk against the attested root over
/// `[start, end]`; returns the leaves as import-ready entries.
fn verify_chunk(
    expected_root: &[u8; 32],
    root_path: &NibblePath,
    start: &Key,
    end: &Key,
    chunk: &StateRangeChunk,
) -> Result<Vec<ImportLeaf>, &'static str> {
    let mut jmt_leaves: Vec<(Key, [u8; 32])> = Vec::with_capacity(chunk.leaves.len());
    for leaf in chunk.leaves.iter() {
        let leaf_key = *leaf.leaf_key.as_bytes();
        if !leaf_key_binds_storage_key(&leaf_key, &leaf.storage_key) {
            return Err("leaf key does not bind the shipped storage key");
        }
        jmt_leaves.push((leaf_key, jmt_value_hash(&leaf.value)));
    }

    let proof =
        MultiProof::decode(chunk.proof.as_bytes()).map_err(|_| "undecodable range proof")?;
    let range = RangeChunk {
        leaves: jmt_leaves,
        more: chunk.more,
    };
    Jmt::verify_range(&proof, *expected_root, root_path, start, end, &range)
        .map_err(|_| "range proof does not verify against the anchor")?;

    Ok(chunk
        .leaves
        .iter()
        .map(|leaf| ImportLeaf {
            leaf_key: *leaf.leaf_key.as_bytes(),
            storage_key: leaf.storage_key.to_vec(),
            value: leaf.value.to_vec(),
        })
        .collect())
}

/// The key immediately after `key`, or `None` at the key-space maximum.
fn next_key(key: &Key) -> Option<Key> {
    let mut out = *key;
    for byte in out.iter_mut().rev() {
        if *byte == u8::MAX {
            *byte = 0;
        } else {
            *byte += 1;
            return Some(out);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::{commit_block_with_updates, make_database_update};
    use hyperscale_storage::{BoundaryStore, SubstateStore};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{BlockHash, BlockHeight};

    use super::*;
    use crate::shard_io::fetch::state_range_serve::serve_state_range_request;

    const ENTRIES: u8 = 12;
    const HEIGHT: u64 = ENTRIES as u64;

    /// A serving replica: `ENTRIES` substates committed through the
    /// production path, pinned at the boundary. Identical commits yield
    /// identical replicas.
    fn replica() -> Arc<SimShardStorage> {
        let storage = SimShardStorage::default();
        for seed in 1..=ENTRIES {
            let updates =
                make_database_update(vec![seed; 50], 0, vec![seed], vec![seed, seed, seed]);
            commit_block_with_updates(&storage, BlockHeight::new(u64::from(seed)), &updates);
        }
        storage.pin_boundary(BlockHeight::new(HEIGHT)).unwrap();
        Arc::new(storage)
    }

    fn anchor_for(storage: &SimShardStorage) -> ShardAnchor {
        ShardAnchor {
            state_root: storage.state_root(),
            block_hash: BlockHash::ZERO,
            height: BlockHeight::new(HEIGHT),
        }
    }

    /// Drive the assembly to completion, serving each request from the
    /// peer `pick` selects (by sub-range id and attempt count).
    fn drive(
        sync: &mut SnapSync,
        pick: impl Fn(usize, usize) -> Arc<SimShardStorage>,
    ) -> Vec<ChunkOutcome> {
        let mut outcomes = Vec::new();
        let mut attempts = vec![0usize; sync.sub_ranges.len()];
        for _ in 0..1_000 {
            let requests = sync.next_requests();
            if requests.is_empty() {
                break;
            }
            for (id, request) in requests {
                let peer = pick(id, attempts[id]);
                attempts[id] += 1;
                let response = serve_state_range_request(&peer, &request);
                outcomes.push(sync.on_response(id, &response));
            }
        }
        outcomes
    }

    /// The Phase 2 exit criterion: a joiner reconstructs the shard's
    /// full committed state from two serving peers and reaches the
    /// attested root.
    #[test]
    fn reconstructs_state_from_two_peers() {
        let peer_a = replica();
        let peer_b = replica();
        let anchor = anchor_for(&peer_a);

        // Four sub-ranges, chunks of two: pagination and fan-out both
        // exercised; requests alternate between the two peers.
        let mut sync = SnapSync::new(anchor, NibblePath::empty(), 2, 2);
        let outcomes = drive(&mut sync, |id, attempt| {
            if (id + attempt) % 2 == 0 {
                Arc::clone(&peer_a)
            } else {
                Arc::clone(&peer_b)
            }
        });
        assert!(outcomes.iter().all(|o| *o == ChunkOutcome::Accepted));
        assert!(sync.is_complete());

        let leaves = sync.into_leaves();
        assert_eq!(leaves.len(), usize::from(ENTRIES));

        let fresh = SimShardStorage::default();
        let imported_root = fresh
            .import_boundary_state(BlockHeight::new(HEIGHT), leaves)
            .unwrap();
        assert_eq!(imported_root, anchor.state_root);
    }

    /// A peer serving a different state fails verification against the
    /// anchor; retries against an honest peer heal the assembly.
    #[test]
    fn byzantine_peer_is_rejected_and_healed_by_retry() {
        let honest = replica();
        let byzantine = {
            let storage = SimShardStorage::default();
            for seed in 1..=ENTRIES {
                // Same keys, one diverging value — a plausible forgery.
                let value = if seed == 5 {
                    vec![0xEE; 3]
                } else {
                    vec![seed, seed, seed]
                };
                let updates = make_database_update(vec![seed; 50], 0, vec![seed], value);
                commit_block_with_updates(&storage, BlockHeight::new(u64::from(seed)), &updates);
            }
            storage.pin_boundary(BlockHeight::new(HEIGHT)).unwrap();
            Arc::new(storage)
        };
        let anchor = anchor_for(&honest);

        let mut sync = SnapSync::new(anchor, NibblePath::empty(), 1, 100);
        let outcomes = drive(&mut sync, |_, attempt| {
            if attempt == 0 {
                Arc::clone(&byzantine)
            } else {
                Arc::clone(&honest)
            }
        });
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, ChunkOutcome::Rejected(_)))
        );
        assert!(sync.is_complete());

        let fresh = SimShardStorage::default();
        let imported_root = fresh
            .import_boundary_state(BlockHeight::new(HEIGHT), sync.into_leaves())
            .unwrap();
        assert_eq!(imported_root, anchor.state_root);
    }

    /// A tampered raw value breaks the recomputed value hash.
    #[test]
    fn tampered_value_is_rejected() {
        let peer = replica();
        let anchor = anchor_for(&peer);

        let mut sync = SnapSync::new(anchor, NibblePath::empty(), 0, 100);
        let (id, request) = sync.next_requests().pop().expect("one sub-range");
        let mut response = serve_state_range_request(&peer, &request);
        response.chunk.as_mut().unwrap().leaves.0[0].value.0[0] ^= 0xFF;

        assert!(matches!(
            sync.on_response(id, &response),
            ChunkOutcome::Rejected(_)
        ));
        assert!(!sync.is_complete());
    }

    /// A swapped storage key breaks the leaf-key low-half binding even
    /// though the proof itself still verifies.
    #[test]
    fn swapped_storage_key_is_rejected() {
        let peer = replica();
        let anchor = anchor_for(&peer);

        let mut sync = SnapSync::new(anchor, NibblePath::empty(), 0, 100);
        let (id, request) = sync.next_requests().pop().expect("one sub-range");
        let mut response = serve_state_range_request(&peer, &request);
        let chunk = response.chunk.as_mut().unwrap();
        let other_key = chunk.leaves.0[1].storage_key.clone();
        chunk.leaves.0[0].storage_key = other_key;

        assert!(matches!(
            sync.on_response(id, &response),
            ChunkOutcome::Rejected(_)
        ));
    }

    /// An unavailable peer re-arms the sub-range instead of wedging it.
    #[test]
    fn unavailable_peer_rearms_the_sub_range() {
        let peer = replica();
        let anchor = anchor_for(&peer);

        let mut sync = SnapSync::new(anchor, NibblePath::empty(), 0, 100);
        let (id, _) = sync.next_requests().pop().expect("one sub-range");
        let unavailable = GetStateRangeResponse { chunk: None };
        assert!(matches!(
            sync.on_response(id, &unavailable),
            ChunkOutcome::Rejected(_)
        ));

        // The retry against the live peer completes the assembly.
        let outcomes = drive(&mut sync, |_, _| Arc::clone(&peer));
        assert!(outcomes.iter().all(|o| *o == ChunkOutcome::Accepted));
        assert!(sync.is_complete());
    }
}
