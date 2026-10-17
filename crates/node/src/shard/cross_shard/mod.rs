//! Per-shard cross-shard subsystem.
//!
//! Owns the per-shard state and code for everything a shard does *across*
//! shard boundaries: tracking other shards' certified headers, fetching and
//! serving cross-shard data (provisions, finalized ticks, a departed
//! shard's settled set).
//!
//! [`CrossShardState`] is the per-shard state struct `ShardIo` composes;
//! subsystem-specific FSM instances, bindings, serves, and glue live here
//! beside it.

pub mod crossing_push;
mod fetch;
mod finalization_serve;
mod local_provision_serve;
mod provision_serve;
mod remote_header;
mod remote_header_serve;
mod remote_header_sync;
mod settled_txs_serve;
mod state_proof_serve;

use std::collections::{BTreeMap, BTreeSet};

pub use fetch::{
    FinalizationBinding, FinalizationFetch, LocalProvisionBinding, LocalProvisionFetch,
    ProvisionBinding, ProvisionFetch, SettledTxsBinding, SettledTxsFetch, StateProofBinding,
    StateProofFetch, VerdictProofBinding, VerdictProofFetch,
};
pub use finalization_serve::serve_finalizations_request;
use hyperscale_execution::MAX_VERDICT_ASKS_PER_SIBLING;
use hyperscale_types::{Anchor, LocalTimestamp, SubstateKey, TerminalEvidence, ValidatorId};
pub use local_provision_serve::serve_local_provisions_request;
pub use provision_serve::serve_provision_request;
pub use remote_header::RemoteHeaderSyncInput;
use remote_header::{RemoteHeaderSync, RemoteHeaderSyncOutput};
pub use remote_header_serve::{serve_local_certified_headers, serve_remote_headers_request};
pub use settled_txs_serve::{SettledTxsCache, serve_settled_txs_request};
pub use state_proof_serve::{serve_cells_request, serve_state_proof_request};

use crate::config::NodeConfig;
use crate::fetch::FetchConfig;

/// Per-shard cross-shard subsystem state.
///
/// Composed into [`ShardIo`](crate::shard::ShardIo).
pub struct CrossShardState {
    /// Multi-shard remote-header sync: tracks other shards' certified header
    /// chains for the cross-shard data dependencies a shard provisions against.
    pub(crate) remote_header_sync: RemoteHeaderSync,

    /// Cross-shard provision fetch (rotates through source committee).
    pub(crate) provision: ProvisionFetch,
    /// Finalization fetch (rotates through committee).
    pub(crate) finalization: FinalizationFetch,
    /// Local-provision fetch (pinned to proposer).
    pub(crate) local_provision: LocalProvisionFetch,
    /// State-proof fetch against other shards' commit-proven headers
    /// (rotates through the anchor's committee).
    pub(crate) state_proof: StateProofFetch,
    /// Fetch of siblings' verdict cells, a question an id, apart from
    /// `state_proof` so asks a silent sibling never answers take none of
    /// its places.
    pub(crate) verdict_proof: VerdictProofFetch,
    /// Settled-set fetch against departed shards' terminals (rotates
    /// through the terminal committee).
    pub(crate) settled_txs: SettledTxsFetch,
    /// The pre-cut proofs each seat last named, by terminal.
    pub(crate) precut_wants: SeatWants<(Anchor, SubstateKey)>,
    /// The settled sets each seat last named.
    pub(crate) settled_wants: SeatWants<TerminalEvidence>,
}

/// What each seat last named of a fetch whose consumer re-derives its
/// whole wanted set each pass.
///
/// One fetch serves every seat on the loop, and each seat names its set
/// from its own progress, so a seat behind its siblings still wants ids
/// they have finished with. The fetch keeps every id any seat names: a
/// pass from a caught-up sibling releases nothing a slower seat still
/// asks for.
#[derive(Debug)]
pub struct SeatWants<Id> {
    by_seat: BTreeMap<ValidatorId, BTreeSet<Id>>,
}

impl<Id> Default for SeatWants<Id> {
    fn default() -> Self {
        Self {
            by_seat: BTreeMap::new(),
        }
    }
}

impl<Id: Ord + Clone> SeatWants<Id> {
    /// `seat` now names exactly `wanted` among the ids `within` selects.
    /// Returns every id there that any seat names.
    pub(crate) fn replace(
        &mut self,
        seat: ValidatorId,
        wanted: &BTreeSet<Id>,
        within: impl Fn(&Id) -> bool,
    ) -> BTreeSet<Id> {
        let named = self.by_seat.entry(seat).or_default();
        named.retain(|id| !within(id));
        named.extend(wanted.iter().cloned());
        if named.is_empty() {
            self.by_seat.remove(&seat);
        }
        self.by_seat
            .values()
            .flatten()
            .filter(|id| within(id))
            .cloned()
            .collect()
    }

    /// `seat` left the loop.
    pub(crate) fn forget(&mut self, seat: ValidatorId) {
        self.by_seat.remove(&seat);
    }
}

/// What the state-proof fetch may hold in flight.
const STATE_PROOF_FETCH: FetchConfig = FetchConfig {
    max_in_flight: 256,
    max_ids_per_request: 64,
    parallel_chunks_per_tick: 2,
};

/// How many verdict questions one request carries: each expands to
/// its three cells, and a request names no more keys than a state-proof
/// request does.
const VERDICT_QUESTIONS_PER_REQUEST: usize = STATE_PROOF_FETCH.max_ids_per_request / 3;

/// How many verdict requests may be in flight at once.
const VERDICT_REQUESTS_IN_FLIGHT: usize = 4;

/// What the fetch of siblings' verdict cells may hold in flight: four
/// requests, and as many a tick. The composer keeps at most one
/// request's questions out toward any one sibling, so four siblings that
/// never answer fill it and three leave a place; and every request with
/// a place goes out in the tick it is put, so one toward a sibling no
/// peer can be reached for, put again each tick, holds back no other
/// sibling's.
const VERDICT_PROOF_FETCH: FetchConfig = FetchConfig {
    max_in_flight: VERDICT_REQUESTS_IN_FLIGHT * VERDICT_QUESTIONS_PER_REQUEST,
    max_ids_per_request: VERDICT_QUESTIONS_PER_REQUEST,
    parallel_chunks_per_tick: VERDICT_REQUESTS_IN_FLIGHT,
};

const _: () = assert!(VERDICT_QUESTIONS_PER_REQUEST == MAX_VERDICT_ASKS_PER_SIBLING);

impl CrossShardState {
    /// Build cross-shard state for a freshly hosted shard.
    #[must_use]
    pub(crate) fn new(config: &NodeConfig) -> Self {
        Self {
            remote_header_sync: RemoteHeaderSync::new(remote_header::default_config()),
            provision: ProvisionFetch::new("provision", config.provision_fetch.clone()),
            finalization: FinalizationFetch::new(
                "finalization",
                FetchConfig {
                    max_in_flight: 8,
                    max_ids_per_request: 4,
                    parallel_chunks_per_tick: 1,
                },
            ),
            local_provision: LocalProvisionFetch::new(
                "local_provision",
                FetchConfig {
                    max_in_flight: 64,
                    max_ids_per_request: 16,
                    parallel_chunks_per_tick: 2,
                },
            ),
            state_proof: StateProofFetch::new("state_proof", STATE_PROOF_FETCH),
            verdict_proof: VerdictProofFetch::new("verdict_proof", VERDICT_PROOF_FETCH),
            settled_txs: SettledTxsFetch::new(
                "settled_txs",
                FetchConfig {
                    max_in_flight: 8,
                    max_ids_per_request: 8,
                    parallel_chunks_per_tick: 2,
                },
            ),
            precut_wants: SeatWants::default(),
            settled_wants: SeatWants::default(),
        }
    }

    /// True if any cross-shard FSM (remote-header sync or the cross-shard
    /// fetches) has pending work — keeps this shard's `FetchTick` alive so
    /// deferred work retries.
    #[must_use]
    pub(crate) fn has_pending(&self) -> bool {
        self.remote_header_sync.has_deferred()
            || self.remote_header_sync.is_syncing()
            || self.provision.has_pending()
            || self.finalization.has_pending()
            || self.local_provision.has_pending()
            || self.state_proof.has_pending()
            || self.verdict_proof.has_pending()
            || self.settled_txs.has_pending()
    }

    /// Drive the remote-header-sync FSM's periodic tick. Returns range
    /// fetches and any newly-emitted `SyncComplete` for shards that just
    /// caught up.
    pub(crate) fn remote_header_tick(
        &mut self,
        now: LocalTimestamp,
    ) -> Vec<RemoteHeaderSyncOutput> {
        self.remote_header_sync
            .handle(RemoteHeaderSyncInput::Tick { now })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fmt::Debug;
    use std::hash::Hash;
    use std::mem::take;

    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{
        Anchor, BlockHeight, ShardId, StateRoot, ValidatorId, VerdictCells, WeightedTimestamp,
    };

    use super::{
        MAX_VERDICT_ASKS_PER_SIBLING, STATE_PROOF_FETCH, SeatWants, StateProofFetch,
        VERDICT_PROOF_FETCH, VerdictProofFetch,
    };
    use crate::fetch::{Fetch, FetchInput, FetchOutput};

    const A: ValidatorId = ValidatorId::new(1);
    const B: ValidatorId = ValidatorId::new(2);

    /// `shard`'s header at `height`.
    fn header(shard: ShardId, height: u64) -> Anchor {
        Anchor {
            shard,
            height: BlockHeight::new(height),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::from_millis(height),
        }
    }

    /// `count` verdict questions put to `shard` at one header.
    fn questions(shard: ShardId, count: usize) -> Vec<(Anchor, VerdictCells)> {
        let key = |seed: usize| test_key(u8::try_from(seed).expect("a small fixture"));
        (0..count)
            .map(|question| {
                let cells = VerdictCells {
                    leaf: key(3 * question),
                    row: key(3 * question + 1),
                    marker: key(3 * question + 2),
                };
                (header(shard, 1), cells)
            })
            .collect()
    }

    /// Ask `fetch` for `ids` of `shard`, and fail every chunk it sends
    /// through `ticks` ticks, as a shard that never answers does.
    fn ask_in_vain<Id>(fetch: &mut Fetch<Id>, shard: ShardId, ids: Vec<Id>, ticks: usize)
    where
        Id: Eq + Hash + Ord + Clone + Debug,
    {
        let mut sent = fetch.handle(FetchInput::Request {
            ids,
            shard,
            preferred: None,
            class: None,
        });
        for _ in 0..ticks {
            sent.extend(fetch.handle(FetchInput::Tick));
            for FetchOutput::Send { ids, .. } in take(&mut sent) {
                sent.extend(fetch.handle(FetchInput::Failed { ids }));
            }
        }
    }

    /// Verdict asks a silent sibling never answers stay in the verdict
    /// fetch, each failed chunk asked again at once. They hold none of
    /// the state-proof fetch's places, so a record ask toward another
    /// shard goes out at once.
    #[test]
    fn verdict_asks_a_silent_sibling_never_answers_take_no_place_a_record_ask_needs() {
        let (silent, healthy) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let mut verdicts = VerdictProofFetch::new("verdict_proof", VERDICT_PROOF_FETCH);
        let mut records = StateProofFetch::new("state_proof", STATE_PROOF_FETCH);
        ask_in_vain(
            &mut verdicts,
            silent,
            questions(silent, MAX_VERDICT_ASKS_PER_SIBLING),
            16,
        );
        assert_eq!(verdicts.in_flight_count(), MAX_VERDICT_ASKS_PER_SIBLING);
        let sent = records.handle(FetchInput::Request {
            ids: vec![(header(healthy, 1), test_key(1))],
            shard: healthy,
            preferred: None,
            class: None,
        });
        assert!(
            matches!(sent.as_slice(), [FetchOutput::Send { shard, .. }] if *shard == healthy),
            "the record ask is dispatched: {sent:?}",
        );
    }

    /// Every question the composer keeps out toward a sibling that never
    /// answers stays in flight, and a question toward another sibling is
    /// still dispatched, whole, in a request of its own.
    #[test]
    fn a_verdict_ask_toward_a_healthy_sibling_dispatches_beside_a_silent_one() {
        let (silent, healthy) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let mut verdicts = VerdictProofFetch::new("verdict_proof", VERDICT_PROOF_FETCH);
        ask_in_vain(
            &mut verdicts,
            silent,
            questions(silent, MAX_VERDICT_ASKS_PER_SIBLING),
            16,
        );
        let asked = questions(healthy, 2);
        let sent = verdicts.handle(FetchInput::Request {
            ids: asked.clone(),
            shard: healthy,
            preferred: None,
            class: None,
        });
        assert!(
            matches!(
                sent.as_slice(),
                [FetchOutput::Send { shard, ids, .. }] if *shard == healthy && *ids == asked
            ),
            "the ask toward the healthy sibling is dispatched: {sent:?}",
        );
    }

    /// A request no peer of its sibling can be reached for gives its
    /// places back until the next tick, and is put again then. A question
    /// toward another sibling is dispatched in the same tick, however
    /// the two siblings sort.
    #[test]
    fn a_verdict_ask_toward_a_healthy_sibling_dispatches_beside_an_unroutable_one() {
        let (unroutable, healthy) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let mut verdicts = VerdictProofFetch::new("verdict_proof", VERDICT_PROOF_FETCH);
        let unreached = |fetch: &mut VerdictProofFetch, sent: Vec<FetchOutput<_>>| {
            let mut toward_healthy = Vec::new();
            for FetchOutput::Send { ids, shard, .. } in sent {
                if shard == healthy {
                    toward_healthy.push(ids);
                } else {
                    assert!(
                        fetch.handle(FetchInput::Unroutable { ids }).is_empty(),
                        "an unroutable chunk waits for the tick",
                    );
                }
            }
            toward_healthy
        };
        let sent = verdicts.handle(FetchInput::Request {
            ids: questions(unroutable, MAX_VERDICT_ASKS_PER_SIBLING),
            shard: unroutable,
            preferred: None,
            class: None,
        });
        assert!(unreached(&mut verdicts, sent).is_empty());
        assert_eq!(verdicts.in_flight_count(), 0);

        let asked = questions(healthy, 2);
        let sent = verdicts.handle(FetchInput::Request {
            ids: asked.clone(),
            shard: healthy,
            preferred: None,
            class: None,
        });
        let mut dispatched = unreached(&mut verdicts, sent);
        for _ in 0..4 {
            let sent = verdicts.handle(FetchInput::Tick);
            dispatched.extend(unreached(&mut verdicts, sent));
        }
        assert_eq!(
            dispatched,
            vec![asked],
            "the ask toward the healthy sibling goes out once, whole",
        );
    }

    /// One request carries as many questions as expand to no more keys
    /// than a state-proof request names.
    #[test]
    fn a_verdict_request_names_no_more_keys_than_a_state_proof_request() {
        let shard = ShardId::leaf(1, 0);
        let mut verdicts = VerdictProofFetch::new("verdict_proof", VERDICT_PROOF_FETCH);
        let sent = verdicts.handle(FetchInput::Request {
            ids: questions(shard, 40),
            shard,
            preferred: None,
            class: None,
        });
        let sizes: Vec<usize> = sent
            .iter()
            .map(|FetchOutput::Send { ids, .. }| ids.len())
            .collect();
        assert_eq!(sizes, vec![21, 19], "cut into requests of 21: {sent:?}");
        assert!(3 * sizes[0] <= STATE_PROOF_FETCH.max_ids_per_request);
    }

    /// A caught-up seat naming nothing keeps what a slower seat still
    /// names; once neither names an id, it goes.
    #[test]
    fn an_id_stays_wanted_while_any_seat_names_it() {
        let mut wants: SeatWants<u64> = SeatWants::default();
        assert_eq!(wants.replace(B, &BTreeSet::from([7]), |_| true), [7].into());
        assert_eq!(wants.replace(A, &BTreeSet::new(), |_| true), [7].into());
        assert!(wants.replace(B, &BTreeSet::new(), |_| true).is_empty());
    }

    /// A pass scoped to some ids leaves the seat's others named.
    #[test]
    fn a_scoped_pass_replaces_only_its_scope() {
        let mut wants: SeatWants<u64> = SeatWants::default();
        let _ = wants.replace(A, &BTreeSet::from([1, 12]), |_| true);
        assert!(wants.replace(A, &BTreeSet::new(), |id| *id < 10).is_empty());
        assert_eq!(
            wants.replace(B, &BTreeSet::new(), |id| *id >= 10),
            [12].into()
        );
    }

    /// A seat that leaves stops holding its ids.
    #[test]
    fn a_seat_that_leaves_names_nothing() {
        let mut wants: SeatWants<u64> = SeatWants::default();
        let _ = wants.replace(B, &BTreeSet::from([7]), |_| true);
        wants.forget(B);
        assert!(wants.replace(A, &BTreeSet::new(), |_| true).is_empty());
    }
}
