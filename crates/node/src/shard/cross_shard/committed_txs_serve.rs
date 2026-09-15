//! Inbound committed-transaction membership handling.
//!
//! Answers a reshape successor asking whether this shard, before it
//! terminated, committed a transaction whose validity window opened
//! before the successor's origin. The successor refuses all such
//! transactions by default; an `Absent` answer here is what lets it admit
//! one, so absence is proven against the terminal's `committed_txs_root`
//! and inclusion is not — see [`CommittedTxVerdict`].
//!
//! The set is reconstructed off the committed chain over the same window
//! the terminal's proposer rooted, so the proofs verify against the
//! attested root without this server being trusted for any of it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{BlockForSync, PendingChain, ShardStorage};
use hyperscale_types::network::request::GetCommittedTxsRequest;
use hyperscale_types::network::response::{CommittedTxVerdict, GetCommittedTxsResponse};
use hyperscale_types::{BlockHash, BlockHeight, TxHash, prove_committed_tx_absent};

/// How many terminals' reconstructed sets are held at once.
///
/// A shard terminates once per reshape and a successor only asks within a
/// validity range of the cut, so one entry answers the live case. The rest
/// is slack for a node hosting several vnodes through overlapping
/// reshapes.
const CACHED_TERMINALS: usize = 4;

/// Reconstructed committed sets, keyed by the terminal they end at.
///
/// The walk this memoizes folds every transaction in every block within a
/// retention horizon of the terminal — the cost is throughput times the
/// horizon, and it lands on every request. The set it produces is
/// immutable: the terminal is committed, and no later block extends the
/// chain it ends.
///
/// A miss under concurrency walks twice rather than blocking, which is the
/// trade this weight of cache exists to make. Two walks over the same
/// committed ancestry produce the same set, so the loser's work is
/// redundant rather than wrong.
#[derive(Default)]
pub struct CommittedTxsCache {
    /// Most recently reconstructed first, truncated at
    /// [`CACHED_TERMINALS`]. A queue rather than a map because the
    /// capacity is smaller than a hash.
    entries: Mutex<VecDeque<CachedTerminal>>,
}

/// One terminal's reconstructed set: the block it ends at, and the
/// members that block's window rooted.
type CachedTerminal = (BlockHeight, BlockHash, Arc<Vec<TxHash>>);

impl CommittedTxsCache {
    /// The set for `terminal`, reconstructed by `walk` on a miss.
    ///
    /// A `walk` answering `None` reached below what this store holds, so
    /// the set it could build is a prefix. Nothing is cached then: a
    /// truncated set left here would answer every later request for this
    /// terminal, and the absence proofs taken over it would name
    /// transactions the chain did commit.
    fn get_or_insert(
        &self,
        height: BlockHeight,
        hash: BlockHash,
        walk: impl FnOnce() -> Option<Vec<TxHash>>,
    ) -> Option<Arc<Vec<TxHash>>> {
        if let Ok(entries) = self.entries.lock()
            && let Some((_, _, members)) =
                entries.iter().find(|(h, b, _)| *h == height && *b == hash)
        {
            return Some(Arc::clone(members));
        }
        let members = Arc::new(walk()?);
        if let Ok(mut entries) = self.entries.lock() {
            entries.push_front((height, hash, Arc::clone(&members)));
            entries.truncate(CACHED_TERMINALS);
        }
        Some(members)
    }
}

/// Serve an inbound committed-transaction query from the local chain.
///
/// Returns `not_found` when the terminal block isn't held or the stored
/// block's hash doesn't match the requested terminal — the requester
/// rotates peers. The hash is checked before the walk, so an unheld
/// terminal costs a lookup rather than a reconstruction.
#[must_use]
pub fn serve_committed_txs_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    cache: &CommittedTxsCache,
    req: &GetCommittedTxsRequest,
) -> GetCommittedTxsResponse {
    let Some(BlockForSync { block, .. }) = pending_chain.block_for_sync(req.terminal_height) else {
        record_fetch_response_sent("committed_txs", 0);
        return GetCommittedTxsResponse::not_found();
    };
    if block.hash() != req.terminal_block_hash {
        record_fetch_response_sent("committed_txs", 0);
        return GetCommittedTxsResponse::not_found();
    }
    let Some(parent_height) = block.height().prev() else {
        // Genesis carries no transactions and never terminates a chain.
        record_fetch_response_sent("committed_txs", 0);
        return GetCommittedTxsResponse::not_found();
    };

    let members = cache.get_or_insert(req.terminal_height, req.terminal_block_hash, || {
        let own: Vec<TxHash> = block.transactions().iter().map(|tx| tx.hash()).collect();
        // Sorted and deduplicated by the walk's `BTreeSet`, which is what
        // the absence proofs' leaf indices are relative to.
        let (set, coverage) = pending_chain.committed_txs_in_window(
            block.header().parent_block_hash(),
            parent_height,
            block.header().parent_qc().weighted_timestamp(),
            own,
        );
        coverage
            .short_at()
            .is_none()
            .then(|| set.into_iter().collect())
    });
    let Some(members) = members else {
        // The window runs below what this store answers for. An absence
        // proof over the prefix would say a committed transaction was
        // never committed, so this node is not one that can answer.
        tracing::warn!(
            terminal_height = req.terminal_height.inner(),
            "committed-transaction window runs below the blocks held here; serving not_found"
        );
        record_fetch_response_sent("committed_txs", 0);
        return GetCommittedTxsResponse::not_found();
    };

    let verdicts = req
        .tx_hashes
        .iter()
        .map(|tx_hash| {
            prove_committed_tx_absent(&members, tx_hash)
                .map_or(CommittedTxVerdict::Committed, CommittedTxVerdict::Absent)
        })
        .collect();
    record_fetch_response_sent("committed_txs", 1);
    GetCommittedTxsResponse::found(verdicts)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::{commit_settled_at, make_test_certified};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash,
        BlockHeader, BlockHeaderParts, BlockHeight, ChainOrigin, Hash, ProposerTimestamp,
        QuorumCertificate, RETENTION_HORIZON, Round, ShardId, SignerBitfield, Transaction,
        Verifiable, WeightedTimestamp, WitnessSources, committed_txs_root_from_hashes,
    };

    use super::*;

    const SHARD: ShardId = ShardId::ROOT;

    fn tx_hash(seed: u8) -> TxHash {
        test_transaction(seed).hash()
    }

    /// Commit a block at `height` carrying `test_transaction(seed)` for
    /// each seed, with `pred_wt` as its parent-QC weighted timestamp —
    /// the clock the window floor reads.
    fn commit_block(
        storage: &SimShardStorage,
        height: u64,
        parent: BlockHash,
        pred_wt: u64,
        seeds: &[u8],
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
            provision_tx_roots: std::collections::BTreeMap::new(),
            ..Default::default()
        });
        let txs: Vec<Arc<Verifiable<Transaction>>> = seeds
            .iter()
            .map(|&seed| Arc::new(Verifiable::from(test_transaction(seed))))
            .collect();
        let block = Block::Live {
            header,
            transactions: Arc::new(txs),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
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

    /// A three-block chain committing seeds 1..=6, and its terminal hash.
    fn chain() -> (PendingChain<SimShardStorage>, BlockHash) {
        let storage = SimShardStorage::default();
        let mut parent = BlockHash::ZERO;
        for (h, seeds) in [(1u64, &[1u8, 2][..]), (2, &[3, 4]), (3, &[5, 6])] {
            parent = commit_block(&storage, h, parent, 1_000 * h, seeds);
        }
        (
            PendingChain::new(Arc::new(storage), ChainOrigin::ROOT),
            parent,
        )
    }

    /// A transaction the chain committed answers `Committed`; one it never
    /// saw answers `Absent` with a proof that verifies against the root
    /// the terminal's proposer would have attested.
    #[test]
    fn answers_membership_against_the_attested_root() {
        let (pending_chain, terminal) = chain();
        let absent = tx_hash(99);
        let req = GetCommittedTxsRequest::new(
            BlockHeight::new(3),
            terminal,
            vec![tx_hash(1), tx_hash(5), absent],
        );
        let verdicts =
            serve_committed_txs_request(&pending_chain, &CommittedTxsCache::default(), &req)
                .verdicts
                .expect("terminal block is held");
        assert_eq!(verdicts.len(), 3);

        assert_eq!(
            verdicts[0],
            CommittedTxVerdict::Committed,
            "seed 1 committed"
        );
        assert_eq!(
            verdicts[1],
            CommittedTxVerdict::Committed,
            "seed 5 committed"
        );

        // The root the terminal's proposer attests over this window.
        let root = committed_txs_root_from_hashes(
            [1u8, 2, 3, 4, 5, 6]
                .iter()
                .map(|&s| tx_hash(s))
                .collect::<Vec<_>>()
                .iter(),
        );
        let CommittedTxVerdict::Absent(proof) = &verdicts[2] else {
            panic!("an uncommitted transaction must answer Absent");
        };
        assert!(proof.proves_absent(&absent, root));
    }

    /// Every transaction the chain committed is refused an absence proof
    /// — the property the successor's safety rests on, checked across the
    /// whole window rather than one sample.
    #[test]
    fn no_committed_transaction_is_shown_absent() {
        let (pending_chain, terminal) = chain();
        let committed: Vec<TxHash> = (1..=6u8).map(tx_hash).collect();
        let req = GetCommittedTxsRequest::new(BlockHeight::new(3), terminal, committed.clone());
        let verdicts =
            serve_committed_txs_request(&pending_chain, &CommittedTxsCache::default(), &req)
                .verdicts
                .expect("terminal block is held");
        for (verdict, tx) in verdicts.iter().zip(&committed) {
            assert_eq!(
                verdict,
                &CommittedTxVerdict::Committed,
                "{tx:?} was committed and must not be shown absent"
            );
        }
    }

    /// The window floors at `RETENTION_HORIZON` behind the terminal's
    /// anchor: a transaction committed below the floor is outside the set
    /// the terminal roots, so it answers `Absent` against that root — and
    /// its proof verifies, because the root excludes it too.
    #[test]
    fn a_transaction_below_the_floor_is_outside_the_window() {
        let rh_ms = RETENTION_HORIZON.as_secs() * 1000;
        let storage = SimShardStorage::default();
        let mut parent = commit_block(&storage, 1, BlockHash::ZERO, 1_000, &[10]);
        parent = commit_block(&storage, 2, parent, rh_ms + 10_000, &[11]);
        let terminal = commit_block(&storage, 3, parent, rh_ms + 11_000, &[12]);
        let pending_chain = PendingChain::new(Arc::new(storage), ChainOrigin::ROOT);

        let below_floor = tx_hash(10);
        let req = GetCommittedTxsRequest::new(BlockHeight::new(3), terminal, vec![below_floor]);
        let verdicts =
            serve_committed_txs_request(&pending_chain, &CommittedTxsCache::default(), &req)
                .verdicts
                .expect("terminal block is held");

        let root = committed_txs_root_from_hashes([tx_hash(11), tx_hash(12)].iter());
        let CommittedTxVerdict::Absent(proof) = &verdicts[0] else {
            panic!("a below-floor transaction is outside the rooted window");
        };
        assert!(proof.proves_absent(&below_floor, root));
    }

    /// An empty query is answered, not refused — the caller asked nothing
    /// and gets nothing back, rather than reading a `not_found` and
    /// rotating peers over it.
    #[test]
    fn an_empty_query_answers_empty() {
        let (pending_chain, terminal) = chain();
        let req = GetCommittedTxsRequest::new(BlockHeight::new(3), terminal, Vec::new());
        assert_eq!(
            serve_committed_txs_request(&pending_chain, &CommittedTxsCache::default(), &req)
                .verdicts,
            Some(Vec::new())
        );
    }

    /// A hash mismatch against the stored block serves `not_found`.
    #[test]
    fn wrong_terminal_hash_serves_not_found() {
        let (pending_chain, _) = chain();
        let req = GetCommittedTxsRequest::new(
            BlockHeight::new(3),
            BlockHash::from_raw(Hash::from_bytes(b"other-chain")),
            vec![tx_hash(1)],
        );
        assert!(
            serve_committed_txs_request(&pending_chain, &CommittedTxsCache::default(), &req)
                .verdicts
                .is_none()
        );
    }

    /// One reconstruction answers every later query about the same
    /// terminal. Checked by mutating the store out from under the cache:
    /// a fourth block lands after the first answer, and the cached set
    /// still reflects the chain as it stood at the terminal — which a
    /// re-walk would not.
    #[test]
    fn the_set_is_reconstructed_once_per_terminal() {
        let storage = SimShardStorage::default();
        let mut parent = BlockHash::ZERO;
        for (h, seeds) in [(1u64, &[1u8, 2][..]), (2, &[3, 4]), (3, &[5, 6])] {
            parent = commit_block(&storage, h, parent, 1_000 * h, seeds);
        }
        let storage = Arc::new(storage);
        let pending_chain = PendingChain::new(Arc::clone(&storage), ChainOrigin::ROOT);
        let cache = CommittedTxsCache::default();

        let ask = |probe: TxHash| {
            let req = GetCommittedTxsRequest::new(BlockHeight::new(3), parent, vec![probe]);
            serve_committed_txs_request(&pending_chain, &cache, &req)
                .verdicts
                .expect("terminal block is held")
                .remove(0)
        };
        assert_eq!(ask(tx_hash(1)), CommittedTxVerdict::Committed);

        // A block the terminal does not extend. Nothing in it belongs to
        // the set the terminal rooted, and the memo is what guarantees a
        // later answer says so.
        commit_block(&storage, 4, parent, 4_000, &[7]);
        let CommittedTxVerdict::Absent(proof) = ask(tx_hash(7)) else {
            panic!("a transaction committed past the terminal is outside its set");
        };
        let root = committed_txs_root_from_hashes(
            [1u8, 2, 3, 4, 5, 6]
                .iter()
                .map(|&s| tx_hash(s))
                .collect::<Vec<_>>()
                .iter(),
        );
        assert!(proof.proves_absent(&tx_hash(7), root));
    }

    /// The memo is keyed by the terminal, so a query naming a different
    /// one is not answered from another's set.
    #[test]
    fn a_second_terminal_does_not_read_the_first_ones_set() {
        let (pending_chain, terminal) = chain();
        let cache = CommittedTxsCache::default();

        let first = GetCommittedTxsRequest::new(BlockHeight::new(3), terminal, vec![tx_hash(1)]);
        assert_eq!(
            serve_committed_txs_request(&pending_chain, &cache, &first).verdicts,
            Some(vec![CommittedTxVerdict::Committed]),
        );

        // Same height, different terminal: the cache must miss and the
        // hash check must refuse, rather than the entry answering for it.
        let forged = GetCommittedTxsRequest::new(
            BlockHeight::new(3),
            BlockHash::from_raw(Hash::from_bytes(b"other-chain")),
            vec![tx_hash(1)],
        );
        assert!(
            serve_committed_txs_request(&pending_chain, &cache, &forged)
                .verdicts
                .is_none()
        );
    }

    /// An unheld height serves `not_found`.
    #[test]
    fn unheld_height_serves_not_found() {
        let pending_chain =
            PendingChain::new(Arc::new(SimShardStorage::default()), ChainOrigin::ROOT);
        let req =
            GetCommittedTxsRequest::new(BlockHeight::new(7), BlockHash::ZERO, vec![tx_hash(1)]);
        assert!(
            serve_committed_txs_request(&pending_chain, &CommittedTxsCache::default(), &req)
                .verdicts
                .is_none()
        );
    }
}
