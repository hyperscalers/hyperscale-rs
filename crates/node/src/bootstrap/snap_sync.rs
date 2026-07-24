//! Joiner-side snap-sync assembler.
//!
//! A vnode joining a shard bootstraps the shard's committed state
//! against its beacon-attested boundary anchor: the shard's key span is
//! partitioned into disjoint sub-ranges fetched from serving peers in
//! parallel, and every chunk is verified against the anchor's
//! `state_root` before it is kept. Verified chunks stream straight back
//! to the driver ([`StateRangeOutcome::Staged`]) with a progress
//! snapshot, to be persisted atomically via
//! `BoundaryStore::stage_import_chunk` — the assembler holds no leaf
//! buffer, so memory stays bounded by one wire chunk regardless of
//! shard size. Once every sub-range is exhausted the driver finalizes
//! the staged state and compares the resulting root against the anchor
//! before trusting the store.
//!
//! Sans-io: [`SnapSync`] emits [`GetStateRangeRequest`]s and consumes
//! responses; the driver owns peer selection, transport, retry pacing,
//! and the staging writes. A rejected or failed chunk simply re-arms
//! its sub-range, so retrying against a different peer is the driver
//! rotating who it asks.
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
use hyperscale_storage::{ImportCursor, ImportLeaf, ImportProgress};
use hyperscale_types::network::request::GetStateRangeRequest;
use hyperscale_types::network::response::{GetStateRangeResponse, StateRangeChunk};
use hyperscale_types::state_key::{jmt_value_hash, leaf_key_binds_storage_key};
use hyperscale_types::{Hash, ShardAnchor};

type Jmt = Tree<Blake3Hasher, 1>;

/// Outcome of feeding one state-range response into [`SnapSync`].
#[derive(Debug, PartialEq, Eq)]
pub enum StateRangeOutcome {
    /// Chunk verified; the driver persists it atomically via
    /// `BoundaryStore::stage_import_chunk` before pumping further
    /// responses — the progress snapshot already covers this chunk's
    /// cursor advance and byte tally.
    Staged {
        /// The chunk's verified leaves.
        leaves: Vec<ImportLeaf>,
        /// The assembly's progress after absorbing this chunk.
        progress: ImportProgress,
    },
    /// Response rejected; the sub-range re-arms and the driver should
    /// penalize the peer and rotate.
    Rejected(&'static str),
}

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
    split_bits: u8,
    chunk_limit: u32,
    sub_ranges: Vec<SubRange>,
    /// Leaf value bytes across every chunk handed to the driver for
    /// staging — the imported substate byte total once complete.
    staged_bytes: u64,
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
            split_bits,
            chunk_limit: chunk_limit.max(1),
            sub_ranges,
            staged_bytes: 0,
        }
    }

    /// Resume an assembly from the durable `progress` of an earlier one
    /// against the same `anchor`: exhausted sub-ranges stay done, the
    /// rest re-arm at their persisted cursors, and the byte tally
    /// carries over. The caller has already matched the progress record
    /// against the anchor and fetch geometry — staged chunks are
    /// meaningless against any other `state_root`.
    #[must_use]
    pub fn with_cursors(
        anchor: ShardAnchor,
        root_path: NibblePath,
        progress: &ImportProgress,
    ) -> Self {
        let sub_ranges = progress
            .cursors
            .iter()
            .map(|cursor| SubRange {
                cursor: cursor.next,
                end: cursor.end,
                state: if cursor.done {
                    SubRangeState::Done
                } else {
                    SubRangeState::Idle
                },
            })
            .collect();
        Self {
            anchor,
            root_path,
            split_bits: progress.split_bits,
            chunk_limit: progress.chunk_limit.max(1),
            sub_ranges,
            staged_bytes: progress.staged_bytes,
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

    /// Verify one response for `sub_range`, returning its leaves and a
    /// progress snapshot for the driver to persist.
    ///
    /// # Panics
    ///
    /// Panics if `sub_range` is not an id this assembly emitted.
    pub fn on_response(
        &mut self,
        sub_range: usize,
        response: &GetStateRangeResponse,
    ) -> StateRangeOutcome {
        let sub = &mut self.sub_ranges[sub_range];
        if sub.state != SubRangeState::InFlight {
            return StateRangeOutcome::Rejected("unsolicited response");
        }
        sub.state = SubRangeState::Idle;

        let Some(chunk) = &response.chunk else {
            return StateRangeOutcome::Rejected("boundary unavailable at peer");
        };
        let verified = match verify_chunk(
            self.anchor.state_root.as_raw().as_bytes(),
            &self.root_path,
            &sub.cursor,
            &sub.end,
            chunk,
        ) {
            Ok(verified) => verified,
            Err(reason) => return StateRangeOutcome::Rejected(reason),
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
        self.staged_bytes += verified.iter().map(|l| l.value.len() as u64).sum::<u64>();
        StateRangeOutcome::Staged {
            leaves: verified,
            progress: self.progress(),
        }
    }

    /// Whether every sub-range is exhausted.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.sub_ranges
            .iter()
            .all(|sub| sub.state == SubRangeState::Done)
    }

    /// Leaf value bytes across every chunk handed to the driver for
    /// staging.
    #[must_use]
    pub const fn staged_bytes(&self) -> u64 {
        self.staged_bytes
    }

    /// The assembly's durable progress record: anchor binding, fetch
    /// geometry, byte tally, and per-sub-range cursors.
    fn progress(&self) -> ImportProgress {
        ImportProgress {
            anchor_height: self.anchor.height,
            anchor_state_root: self.anchor.state_root,
            split_bits: self.split_bits,
            chunk_limit: self.chunk_limit,
            staged_bytes: self.staged_bytes,
            cursors: self
                .sub_ranges
                .iter()
                .map(|sub| ImportCursor {
                    next: sub.cursor,
                    end: sub.end,
                    done: sub.state == SubRangeState::Done,
                })
                .collect(),
        }
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

    use hyperscale_storage::test_helpers::{
        commit_block_with_updates, commit_block_with_witnesses, make_database_update,
        pin_snap_sync_replica,
    };
    use hyperscale_storage::{BoundaryStore, WitnessSeed};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::BlockHeight;

    use super::*;
    use crate::bootstrap::state_range_serve::serve_state_range_request;

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
    /// peer `pick` selects (by sub-range id and attempt count) and
    /// staging every verified chunk into `fresh`. Returns how many
    /// responses were rejected.
    fn drive(
        sync: &mut SnapSync,
        fresh: &SimShardStorage,
        pick: impl Fn(usize, usize) -> Arc<SimShardStorage>,
    ) -> usize {
        let mut rejected = 0;
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
                match sync.on_response(id, &response) {
                    StateRangeOutcome::Staged { leaves, progress } => {
                        fresh.stage_import_chunk(&progress, &leaves).unwrap();
                    }
                    StateRangeOutcome::Rejected(_) => rejected += 1,
                }
            }
        }
        rejected
    }

    /// A joiner reconstructs the shard's full committed state from two
    /// serving peers and reaches the attested root.
    #[test]
    fn reconstructs_state_from_two_peers() {
        let (peer_a, anchor) = replica();
        let (peer_b, _) = replica();

        // Four sub-ranges, chunks of two: pagination and fan-out both
        // exercised; requests alternate between the two peers.
        let fresh = SimShardStorage::default();
        let mut sync = SnapSync::new(anchor, NibblePath::empty(), 2, 2);
        let rejected = drive(&mut sync, &fresh, |id, attempt| {
            if (id + attempt) % 2 == 0 {
                Arc::clone(&peer_a)
            } else {
                Arc::clone(&peer_b)
            }
        });
        assert_eq!(rejected, 0);
        assert!(sync.is_complete());
        // Every replica entry staged: 3 value bytes per seed.
        assert_eq!(sync.staged_bytes(), u64::from(ENTRIES) * 3);

        let imported_root = fresh
            .finalize_boundary_import(anchor.height, WitnessSeed::default())
            .unwrap();
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

        let fresh = SimShardStorage::default();
        let mut sync = SnapSync::new(anchor, NibblePath::empty(), 1, 100);
        let rejected = drive(&mut sync, &fresh, |_, attempt| {
            if attempt == 0 {
                Arc::clone(&byzantine)
            } else {
                Arc::clone(&honest)
            }
        });
        assert!(rejected > 0);
        assert!(sync.is_complete());

        let imported_root = fresh
            .finalize_boundary_import(anchor.height, WitnessSeed::default())
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
            StateRangeOutcome::Rejected(_)
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
            StateRangeOutcome::Rejected(_)
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
            StateRangeOutcome::Rejected(_)
        ));

        // The retry against the live peer completes the assembly.
        let fresh = SimShardStorage::default();
        assert_eq!(drive(&mut sync, &fresh, |_, _| Arc::clone(&peer)), 0);
        assert!(sync.is_complete());
    }
}
