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

use hyperscale_jmt::{
    Blake3Hasher, Key, MultiProof, NibblePath, RangeChunk, Tree, next_key, subspan,
};
use hyperscale_storage::ImportLeaf;
use hyperscale_types::network::request::GetStateRangeRequest;
use hyperscale_types::network::response::{GetStateRangeResponse, StateRangeChunk};
use hyperscale_types::state_key::{jmt_value_hash, leaf_key_binds_storage_key};
use hyperscale_types::{Hash, ShardAnchor};

use super::BootstrapOutcome;

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
        let span_path = root_path.clone();
        Self::spanning(anchor, root_path, &span_path, split_bits, chunk_limit)
    }

    /// Start an assembly fetching only `span_path`'s key span out of a
    /// serving tree rooted at `root_path` — a reshape observer syncs
    /// its pending child's span out of the splitting shard's attested
    /// whole-tree root this way. Every chunk still proves into
    /// `anchor.state_root` at `root_path`'s depth; only the fetched
    /// span narrows.
    ///
    /// # Panics
    ///
    /// Panics unless `span_path` sits at or under `root_path`.
    #[must_use]
    pub fn spanning(
        anchor: ShardAnchor,
        root_path: NibblePath,
        span_path: &NibblePath,
        split_bits: u8,
        chunk_limit: u32,
    ) -> Self {
        let mut span_prefix = span_path.clone();
        span_prefix.truncate(root_path.len());
        assert!(
            span_prefix == root_path,
            "span does not sit under the serving root",
        );
        let sub_ranges = (0..1u64 << split_bits)
            .map(|index| {
                let (low, high) = subspan(span_path, split_bits, index);
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
    ) -> BootstrapOutcome {
        let sub = &mut self.sub_ranges[sub_range];
        if sub.state != SubRangeState::InFlight {
            return BootstrapOutcome::Rejected("unsolicited response");
        }
        sub.state = SubRangeState::Idle;

        let Some(chunk) = &response.chunk else {
            return BootstrapOutcome::Rejected("boundary unavailable at peer");
        };
        let verified = match verify_chunk(
            self.anchor.state_root.as_raw().as_bytes(),
            &self.root_path,
            &sub.cursor,
            &sub.end,
            chunk,
        ) {
            Ok(verified) => verified,
            Err(reason) => return BootstrapOutcome::Rejected(reason),
        };

        if chunk.more {
            // Complete through the last leaf; resume just past it. The
            // verifier rejected `more` without leaves, so `last` exists.
            // A successor past the sub-range end (or none at all — the
            // absolute key-space maximum) means the span is exhausted.
            let last = verified
                .last()
                .expect("verified truncated chunk carries leaves")
                .leaf_key;
            match next_key(&last) {
                Some(next) if next <= sub.end => sub.cursor = next,
                _ => sub.state = SubRangeState::Done,
            }
        } else {
            sub.state = SubRangeState::Done;
        }
        self.leaves.extend(verified);
        BootstrapOutcome::Accepted
    }

    /// Whether every sub-range is exhausted.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.sub_ranges
            .iter()
            .all(|sub| sub.state == SubRangeState::Done)
    }

    /// Take the verified leaves, ready for
    /// `BoundaryStore::import_boundary_state`.
    ///
    /// # Panics
    ///
    /// Panics unless [`Self::is_complete`] — a partial import would
    /// produce a root that can never match the anchor.
    #[must_use]
    pub fn take_leaves(&mut self) -> Vec<ImportLeaf> {
        assert!(
            self.is_complete(),
            "snap-sync leaves taken before assembly completed",
        );
        std::mem::take(&mut self.leaves)
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_storage::BoundaryStore;
    use hyperscale_storage::test_helpers::{
        commit_block_with_updates, commit_block_with_witnesses, make_database_update,
        pin_snap_sync_replica,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::BlockHeight;

    use super::*;
    use crate::fetch::state_range_serve::serve_state_range_request;

    const ENTRIES: u8 = 12;

    /// A serving replica: `ENTRIES` substates committed through the
    /// production path, pinned at the boundary. Identical commits yield
    /// identical replicas and anchors.
    fn replica() -> (Arc<SimShardStorage>, ShardAnchor) {
        let storage = SimShardStorage::default();
        let anchor = pin_snap_sync_replica(&storage, ENTRIES, &[]);
        (Arc::new(storage), anchor)
    }

    /// Drive the assembly to completion, serving each request from the
    /// peer `pick` selects (by sub-range id and attempt count).
    fn drive(
        sync: &mut SnapSync,
        pick: impl Fn(usize, usize) -> Arc<SimShardStorage>,
    ) -> Vec<BootstrapOutcome> {
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

    /// A joiner reconstructs the shard's full committed state from two
    /// serving peers and reaches the attested root.
    #[test]
    fn reconstructs_state_from_two_peers() {
        let (peer_a, anchor) = replica();
        let (peer_b, _) = replica();

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
        assert!(outcomes.iter().all(|o| *o == BootstrapOutcome::Accepted));
        assert!(sync.is_complete());

        let leaves = sync.take_leaves();
        assert_eq!(leaves.len(), usize::from(ENTRIES));

        let fresh = SimShardStorage::default();
        let imported_root = fresh.import_boundary_state(anchor.height, leaves).unwrap();
        assert_eq!(imported_root, anchor.state_root);
    }

    /// A peer serving a different state fails verification against the
    /// anchor; retries against an honest peer heal the assembly.
    #[test]
    fn byzantine_peer_is_rejected_and_healed_by_retry() {
        let (honest, anchor) = replica();
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
            commit_block_with_witnesses(&storage, anchor.height, &[]);
            storage.pin_boundary(anchor.height).unwrap();
            Arc::new(storage)
        };

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
                .any(|o| matches!(o, BootstrapOutcome::Rejected(_)))
        );
        assert!(sync.is_complete());

        let fresh = SimShardStorage::default();
        let imported_root = fresh
            .import_boundary_state(anchor.height, sync.take_leaves())
            .unwrap();
        assert_eq!(imported_root, anchor.state_root);
    }

    /// A tampered raw value breaks the recomputed value hash.
    #[test]
    fn tampered_value_is_rejected() {
        let (peer, anchor) = replica();

        let mut sync = SnapSync::new(anchor, NibblePath::empty(), 0, 100);
        let (id, request) = sync.next_requests().pop().expect("one sub-range");
        let mut response = serve_state_range_request(&peer, &request);
        response.chunk.as_mut().unwrap().leaves.0[0].value.0[0] ^= 0xFF;

        assert!(matches!(
            sync.on_response(id, &response),
            BootstrapOutcome::Rejected(_)
        ));
        assert!(!sync.is_complete());
    }

    /// A swapped storage key breaks the leaf-key low-half binding even
    /// though the proof itself still verifies.
    #[test]
    fn swapped_storage_key_is_rejected() {
        let (peer, anchor) = replica();

        let mut sync = SnapSync::new(anchor, NibblePath::empty(), 0, 100);
        let (id, request) = sync.next_requests().pop().expect("one sub-range");
        let mut response = serve_state_range_request(&peer, &request);
        let chunk = response.chunk.as_mut().unwrap();
        let other_key = chunk.leaves.0[1].storage_key.clone();
        chunk.leaves.0[0].storage_key = other_key;

        assert!(matches!(
            sync.on_response(id, &response),
            BootstrapOutcome::Rejected(_)
        ));
    }

    /// An unavailable peer re-arms the sub-range instead of wedging it.
    #[test]
    fn unavailable_peer_rearms_the_sub_range() {
        let (peer, anchor) = replica();

        let mut sync = SnapSync::new(anchor, NibblePath::empty(), 0, 100);
        let (id, _) = sync.next_requests().pop().expect("one sub-range");
        let unavailable = GetStateRangeResponse { chunk: None };
        assert!(matches!(
            sync.on_response(id, &unavailable),
            BootstrapOutcome::Rejected(_)
        ));

        // The retry against the live peer completes the assembly.
        let outcomes = drive(&mut sync, |_, _| Arc::clone(&peer));
        assert!(outcomes.iter().all(|o| *o == BootstrapOutcome::Accepted));
        assert!(sync.is_complete());
    }
}
