//! Inbound settled-transaction window request handling.
//!
//! Serves a terminated shard's complete settled-transaction window list to a
//! surviving counterpart resolving cross-shard transactions across a split
//! boundary. The request names the terminal block `B`; the server
//! reconstructs `S_P` off its committed chain over the window reaching
//! back to the terminating reshape's admission — the same set `B`'s
//! `settled_txs_root` commits — so the requester accepts the list
//! against the beacon-attested root. No
//! per-block QC: completeness is the merkle root, not block-by-block
//! verification.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use hyperscale_hbor::Capped;
use hyperscale_storage::{BlockForSync, PendingChain, ShardStorage};
use hyperscale_types::network::request::GetSettledTxsRequest;
use hyperscale_types::network::response::GetSettledTxsResponse;
use hyperscale_types::{
    BlockHash, BlockHeight, MAX_FINALIZED_TX_PER_BLOCK, TxHash, WeightedTimestamp,
    local_settled_tx_hashes,
};

/// How many terminals' reconstructed windows are held at once — the same
/// weight the committed-membership side keeps, for the same reason: a
/// shard terminates once per reshape, and the slack covers a node hosting
/// several shards through overlapping ones.
const CACHED_TERMINALS: usize = 4;

/// Reconstructed settled windows, keyed by the terminal they end at and
/// the floor they were taken under.
///
/// The walk behind an answer folds every block within the terminating
/// shard's whole scheduled window — several epochs — and the chain's own
/// single-slot memo only ever extends, so a request below its coverage
/// re-walks the span in full and leaves the memo alone. Descending heights
/// therefore miss every time. The set a block hash ends is fixed by the
/// chain that hash commits, so one reconstruction answers every query
/// about it.
///
/// A window this store cannot answer is held too, as `None`. A walk that
/// ran below what the store holds stays short, since a store's chain
/// floor only rises; and a window past the wire cap stays past it. Left
/// out, either would let a peer buy the multi-epoch walk again with
/// every repeat of a well-formed request.
///
/// The floor is part of the key because it is read off the serving node's
/// live topology projection: a narrower projection serves a narrower
/// window, and the two are different answers.
#[derive(Default)]
pub struct SettledTxsCache {
    /// Most recently reconstructed first, truncated at
    /// [`CACHED_TERMINALS`]. A queue rather than a map because the
    /// capacity is smaller than a hash.
    entries: Mutex<VecDeque<CachedWindow>>,
}

/// A terminal's settled window as it goes on the wire.
type SettledWindow = Capped<Vec<TxHash>, MAX_FINALIZED_TX_PER_BLOCK>;

/// What reconstructing a held terminal's window came to.
enum Reconstructed {
    /// The window, whole.
    Window(SettledWindow),
    /// A window this store cannot answer for: it runs below the blocks
    /// held here, or past the wire cap.
    Unanswerable,
}

/// One terminal's reconstructed window: the block it ends at, the floor it
/// was taken under, and the transactions it settled, or `None` where this
/// store cannot answer for them.
type CachedWindow = (
    BlockHeight,
    BlockHash,
    Option<WeightedTimestamp>,
    Option<Arc<SettledWindow>>,
);

impl SettledTxsCache {
    /// The window for `terminal` under `floor`, reconstructed by `walk` on
    /// a miss.
    ///
    /// A `walk` answering `None` found no terminal by that name here, and
    /// nothing is cached: the key is the asker's, and a slot per unheld
    /// name would let any peer evict the windows that are held.
    fn get_or_insert(
        &self,
        height: BlockHeight,
        hash: BlockHash,
        floor: Option<WeightedTimestamp>,
        walk: impl FnOnce() -> Option<Reconstructed>,
    ) -> Option<Arc<SettledWindow>> {
        if let Ok(entries) = self.entries.lock()
            && let Some((_, _, _, window)) = entries
                .iter()
                .find(|(h, b, f, _)| *h == height && *b == hash && *f == floor)
        {
            return window.clone();
        }
        let window = match walk()? {
            Reconstructed::Window(window) => Some(Arc::new(window)),
            Reconstructed::Unanswerable => None,
        };
        if let Ok(mut entries) = self.entries.lock() {
            entries.push_front((height, hash, floor, window.clone()));
            entries.truncate(CACHED_TERMINALS);
        }
        window
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().map_or(0, |entries| entries.len())
    }
}

/// Serve an inbound settled-transaction window request from the local chain.
///
/// The served set is the **cross-shard** transactions the terminated shard settled
/// in the window — the only ones a counterpart's fence can query (see
/// [`local_settled_tx_hashes`]) — so it stays proportional to cross-shard
/// traffic, not total throughput.
///
/// `window_floor` is the shard's settled-window floor read off the serving
/// node's topology projection — the same value the terminal's proposer
/// floored the attested root at, so the recomputed list matches it. A
/// projection that no longer carries the floor serves a narrower window;
/// the requester's root check catches the mismatch and rotates peers.
///
/// Returns `not_found` when the terminal block isn't held, the stored
/// block's hash doesn't match the requested terminal, or that block
/// carries no terminal settled root — the requester rotates peers. Returns
/// `not_found` too when the window runs below the blocks held here, or
/// exceeds the wire cap (logged loudly; within-cap for any realistic
/// cross-shard load).
#[must_use]
pub fn serve_settled_txs_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    cache: &SettledTxsCache,
    window_floor: Option<WeightedTimestamp>,
    req: &GetSettledTxsRequest,
) -> GetSettledTxsResponse {
    cache
        .get_or_insert(
            req.terminal_height,
            req.terminal_block_hash,
            window_floor,
            || reconstruct(pending_chain, window_floor, req),
        )
        .map_or_else(GetSettledTxsResponse::not_found, |window| {
            GetSettledTxsResponse::found(SettledWindow::clone(&window))
        })
}

/// The window `req` names, reconstructed off this store, or `None` where
/// no terminal by that name is held here.
fn reconstruct<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    window_floor: Option<WeightedTimestamp>,
    req: &GetSettledTxsRequest,
) -> Option<Reconstructed> {
    // The name is checked on the header before the block is loaded, so a
    // request naming a block this store does not hold costs a header read.
    let header = pending_chain
        .certified_header(req.terminal_height)
        .or_else(|| pending_chain.certified_uncommitted_header(req.terminal_height))?;
    if header.header().hash() != req.terminal_block_hash {
        return None;
    }
    // The answer is checked against the named block's own
    // `settled_txs_root`, so a block carrying no terminal settled root is one
    // whose window no requester can accept — and the walk behind it
    // reaches back epochs. Answering at every height this node holds
    // would hand any peer a multi-epoch fold per request, on a shard that
    // is not terminating at all.
    header.header().settled_txs_root()?;
    let BlockForSync { block, .. } = pending_chain.block_for_sync(req.terminal_height)?;
    if block.hash() != req.terminal_block_hash {
        return None;
    }
    // Genesis carries no certificates and never terminates a split.
    let parent_height = block.height().prev()?;

    let shard = block.header().shard_id();
    let own = local_settled_tx_hashes(block.certificates().iter(), shard);
    let (set, coverage) = pending_chain.settled_txs_in_window(
        shard,
        block.header().parent_block_hash(),
        parent_height,
        block.header().parent_qc().weighted_timestamp(),
        window_floor,
        own,
    );
    if coverage.short_at().is_some() {
        // The window runs below what this store answers for. Serving the
        // prefix would tell the requester a settled transaction settled
        // nowhere, which is worse than not answering.
        tracing::warn!(
            shard = ?shard,
            terminal_height = req.terminal_height.inner(),
            "settled-transaction window runs below the blocks held here; serving not_found"
        );
        return Some(Reconstructed::Unanswerable);
    }

    // A window exceeding the wire cap serves `not_found` rather than
    // shipping a response the receiver would reject at decode. The set is
    // the cross-shard settled transactions only — one entry each, across a
    // window spanning the retention horizon — so the headroom is that many
    // cross-shard transactions per horizon, not per block. Log it loudly
    // rather than letting the requester read the overflow `not_found` as a
    // plain "block not held" and rotate peers forever.
    let window = set.len();
    let Ok(txs) = SettledWindow::new(set.into_iter().collect()) else {
        tracing::warn!(
            shard = ?shard,
            terminal_height = req.terminal_height.inner(),
            window,
            cap = MAX_FINALIZED_TX_PER_BLOCK,
            "settled-transaction window exceeds the wire cap; serving not_found — \
             cross-shard load outran the one-shot transfer"
        );
        return Some(Reconstructed::Unanswerable);
    };
    Some(Reconstructed::Window(txs))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::{commit_settled_at, make_test_certified};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash,
        BlockHeader, BlockHeaderParts, BlockHeight, CertificateRoot, ConsensusReceipt,
        ExecutionCertificate, ExecutionOutcome, Finalization, GlobalReceiptHash, Hash,
        ProposerTimestamp, QuorumCertificate, RETENTION_HORIZON, Role, Round, SectionRoots,
        SettledTxsRoot, ShardId, SignerBitfield, StateWrites, StoredReceipt, TickHalf, TickId,
        TxHash, TxOutcome, Verifiable, Verified, WeightedTimestamp, WitnessSources,
        compute_global_receipt_root, settled_txs_root_from_hashes,
    };

    use super::*;

    const SHARD: ShardId = ShardId::ROOT;

    /// The transaction the tick at `height` settles — distinct per tick,
    /// so a window over several ticks has one entry each.
    fn settled_tx(height: u64) -> TxHash {
        TxHash::from(Hash::from_bytes(&height.to_le_bytes()))
    }

    fn finalization(height: u64) -> Arc<Verifiable<Finalization>> {
        // A leg that ran: the settled set names only what reaches beyond
        // this shard, so a single-shard fixture would be filtered out
        // before the merkle root.
        let tick = TickId::new(SHARD, BlockHeight::new(height));
        let certificate = |tick: TickId| {
            let outcomes = [TxOutcome::new(
                settled_tx(height),
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )
            .as_role(Role::Leg)];
            Arc::new(ExecutionCertificate::new(
                tick,
                WeightedTimestamp::from_millis(1),
                compute_global_receipt_root(&outcomes),
                Capped::from_array(outcomes),
                AggregateSignature::new([0u8; 96]),
                SignerBitfield::new(4),
            ))
        };
        Arc::new(Verifiable::from(Finalization::new(
            tick,
            TickHalf::Determined,
            Some(certificate(tick)),
            Capped::from_array([StoredReceipt::new(
                settled_tx(height),
                Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    writes: StateWrites::default(),
                    beacon_witness_events: Capped::empty(),
                    events: Capped::empty(),
                }),
            )]),
        )))
    }

    fn commit_block(
        storage: &SimShardStorage,
        height: u64,
        parent: BlockHash,
        pred_wt: u64,
        certs: &[Arc<Verifiable<Finalization>>],
    ) -> BlockHash {
        let parent_qc = QuorumCertificate::new(
            parent,
            SHARD,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::new([0u8; 96]),
            WeightedTimestamp::from_millis(pred_wt),
        );
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: SHARD,
            height: BlockHeight::new(height),
            parent_block_hash: parent,
            parent_qc: parent_qc.into(),
            timestamp: ProposerTimestamp::from_millis(1_000 * height),
            body_root: SectionRoots {
                certificates: *Verified::<CertificateRoot>::compute(certs).as_ref(),
                ..SectionRoots::EMPTY
            }
            .root(),
            provision_tx_roots: Capped::default(),
            // Every block of a terminating window carries the root; a
            // block without it is not one this handler answers for.
            terminal_settled_txs: Some(SettledTxsRoot::ZERO),
            ..Default::default()
        });
        let block = Block::Live {
            header,
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(
                Capped::new(certs.to_vec()).expect("a list written out in a test"),
            ),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let hash = block.hash();
        commit_settled_at(
            storage,
            &make_test_certified(block),
            &[],
            &[],
            &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        );
        hash
    }

    /// The served window list recomputes to the terminal block's
    /// `settled_txs_root` — every block's settled transaction over the window.
    #[test]
    fn serves_the_full_settled_window() {
        let storage = SimShardStorage::default();
        let mut parent = BlockHash::ZERO;
        for h in 1..=3 {
            parent = commit_block(&storage, h, parent, 1_000 * h, &[finalization(h)]);
        }
        let terminal = parent;
        let pending_chain = PendingChain::new(Arc::new(storage), BlockHeight::GENESIS);

        let req = GetSettledTxsRequest::new(BlockHeight::new(3), terminal);
        let response =
            serve_settled_txs_request(&pending_chain, &SettledTxsCache::default(), None, &req);
        let served = response.txs.expect("terminal block is held");

        let expected: BTreeSet<TxHash> = (1..=3).map(settled_tx).collect();
        assert_eq!(served.iter().copied().collect::<BTreeSet<_>>(), expected);
        // The fence accepts iff the recomputed root equals the attested one.
        assert_eq!(
            settled_txs_root_from_hashes(served.iter()),
            settled_txs_root_from_hashes(expected.iter()),
        );
    }

    /// A schedule-supplied floor reaches settlements older than the
    /// anchor-relative horizon: a transaction settled early in the terminating
    /// shard's scheduled window — below `terminal − RETENTION_HORIZON` —
    /// is served only when the floor covers it.
    #[test]
    fn window_floor_serves_early_settlements() {
        let rh_ms = RETENTION_HORIZON.as_secs() * 1000;
        let storage = SimShardStorage::default();
        let mut parent = commit_block(&storage, 1, BlockHash::ZERO, 1_000, &[finalization(1)]);
        parent = commit_block(&storage, 2, parent, rh_ms + 10_000, &[finalization(2)]);
        let terminal = commit_block(&storage, 3, parent, rh_ms + 11_000, &[finalization(3)]);
        let pending_chain = PendingChain::new(Arc::new(storage), BlockHeight::GENESIS);
        let req = GetSettledTxsRequest::new(BlockHeight::new(3), terminal);

        // Anchor-only floor: the early settlement falls outside the window.
        let narrow =
            serve_settled_txs_request(&pending_chain, &SettledTxsCache::default(), None, &req)
                .txs
                .expect("terminal block is held");
        assert_eq!(narrow.len(), 2);

        // The floor reaches back past the early settlement.
        let wide = serve_settled_txs_request(
            &pending_chain,
            &SettledTxsCache::default(),
            Some(WeightedTimestamp::from_millis(500)),
            &req,
        )
        .txs
        .expect("terminal block is held");
        assert_eq!(wide.len(), 3);
    }

    /// A hash mismatch against the stored block serves `not_found`.
    #[test]
    fn wrong_terminal_hash_serves_not_found() {
        let storage = SimShardStorage::default();
        let _ = commit_block(&storage, 1, BlockHash::ZERO, 1_000, &[finalization(1)]);
        let pending_chain = PendingChain::new(Arc::new(storage), BlockHeight::GENESIS);
        let req = GetSettledTxsRequest::new(
            BlockHeight::new(1),
            BlockHash::from_raw(Hash::from_bytes(b"other-chain")),
        );
        assert!(
            serve_settled_txs_request(&pending_chain, &SettledTxsCache::default(), None, &req)
                .txs
                .is_none()
        );
    }

    /// A block carrying no terminal settled root is one no requester could
    /// accept an answer against, and the walk behind that answer reaches
    /// back epochs. Serving at any height a node holds hands any peer a
    /// multi-epoch fold per request, on a shard that is not terminating.
    #[test]
    fn a_block_with_no_terminal_settled_txs_serves_not_found() {
        let storage = SimShardStorage::default();
        let parent_qc = QuorumCertificate::new(
            BlockHash::ZERO,
            SHARD,
            BlockHeight::new(0),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::new([0u8; 96]),
            WeightedTimestamp::from_millis(1_000),
        );
        let certs = [finalization(1)];
        let block = Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                shard_id: SHARD,
                height: BlockHeight::new(1),
                parent_block_hash: BlockHash::ZERO,
                parent_qc: parent_qc.into(),
                timestamp: ProposerTimestamp::from_millis(1_000),
                body_root: SectionRoots {
                    certificates: *Verified::<CertificateRoot>::compute(&certs).as_ref(),
                    ..SectionRoots::EMPTY
                }
                .root(),
                provision_tx_roots: Capped::default(),
                ..Default::default()
            }),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(
                Capped::new(certs.to_vec()).expect("a list written out in a test"),
            ),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let hash = block.hash();
        commit_settled_at(
            &storage,
            &make_test_certified(block),
            &[],
            &[],
            &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        );
        let pending_chain = PendingChain::new(Arc::new(storage), BlockHeight::GENESIS);

        let req = GetSettledTxsRequest::new(BlockHeight::new(1), hash);
        assert!(
            serve_settled_txs_request(&pending_chain, &SettledTxsCache::default(), None, &req)
                .txs
                .is_none(),
            "the block is held and its hash matches; what it lacks is the root"
        );
    }

    /// One reconstruction answers every later request about the terminal.
    ///
    /// The chain's own memo only ever extends, so a request below its
    /// coverage re-walks the terminating window in full — and nothing
    /// rate-limits a well-formed request.
    #[test]
    fn a_terminals_window_is_reconstructed_once() {
        let storage = SimShardStorage::default();
        let mut parent = BlockHash::ZERO;
        for h in 1..=3 {
            parent = commit_block(&storage, h, parent, 1_000 * h, &[finalization(h)]);
        }
        let pending_chain = PendingChain::new(Arc::new(storage), BlockHeight::GENESIS);
        let cache = SettledTxsCache::default();
        let req = GetSettledTxsRequest::new(BlockHeight::new(3), parent);

        let first = serve_settled_txs_request(&pending_chain, &cache, None, &req)
            .txs
            .expect("terminal block is held");
        assert_eq!(cache.len(), 1);
        let second = serve_settled_txs_request(&pending_chain, &cache, None, &req)
            .txs
            .expect("served from the cache");
        assert_eq!(first, second);
        assert_eq!(cache.len(), 1, "the second request adds no entry");

        // A different floor is a different window, so it is a different
        // answer and gets its own slot.
        let _ = serve_settled_txs_request(
            &pending_chain,
            &cache,
            Some(WeightedTimestamp::from_millis(500)),
            &req,
        );
        assert_eq!(cache.len(), 2);
    }

    /// A window running below the blocks held here is held as one this
    /// store cannot answer, so a repeat does not walk it again; a name
    /// this store does not hold takes no slot.
    #[test]
    fn a_window_this_store_cannot_answer_is_held_and_an_unheld_name_is_not() {
        let storage = SimShardStorage::default();
        // The first block's parent is one this store never held, so the
        // walk from the terminal runs off the bottom of the chain.
        let lost = BlockHash::from_raw(Hash::from_bytes(b"a parent nobody kept"));
        let mut parent = commit_block(&storage, 2, lost, 2_000, &[finalization(2)]);
        parent = commit_block(&storage, 3, parent, 3_000, &[finalization(3)]);
        let pending_chain = PendingChain::new(Arc::new(storage), BlockHeight::GENESIS);
        let cache = SettledTxsCache::default();
        let req = GetSettledTxsRequest::new(BlockHeight::new(3), parent);

        for _ in 0..2 {
            assert!(
                serve_settled_txs_request(&pending_chain, &cache, None, &req)
                    .txs
                    .is_none()
            );
            assert_eq!(cache.len(), 1, "the short window is held once");
        }

        let unheld = GetSettledTxsRequest::new(BlockHeight::new(3), BlockHash::ZERO);
        assert!(
            serve_settled_txs_request(&pending_chain, &cache, None, &unheld)
                .txs
                .is_none()
        );
        assert_eq!(cache.len(), 1, "a name not held here takes no slot");
    }

    /// An unheld height serves `not_found`.
    #[test]
    fn unheld_height_serves_not_found() {
        let storage = Arc::new(SimShardStorage::default());
        let pending_chain = PendingChain::new(storage, BlockHeight::GENESIS);
        let req = GetSettledTxsRequest::new(BlockHeight::new(7), BlockHash::ZERO);
        assert!(
            serve_settled_txs_request(&pending_chain, &SettledTxsCache::default(), None, &req)
                .txs
                .is_none()
        );
    }
}
