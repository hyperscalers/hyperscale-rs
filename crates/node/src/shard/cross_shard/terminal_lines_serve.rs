//! Inbound terminal-lines request handling.
//!
//! Serves a terminated shard's terminal tick manifest, with the header
//! and section roots that bind it, to a surviving sibling reading which
//! transactions this shard had accepted when its chain ended. The
//! request names the terminal block; the answer is that block's own
//! content and nothing behind it, so any holder of the block answers
//! whole and the requester holds the answer to the terminal's hash.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{BlockForSync, PendingChain, ShardStorage};
use hyperscale_types::network::request::GetTerminalLinesRequest;
use hyperscale_types::network::response::GetTerminalLinesResponse;
use hyperscale_types::{BlockHash, BlockHeight, TerminalLines};

/// How many terminals' lines are held at once: a shard terminates once
/// per reshape, and the slack covers a node hosting several vnodes
/// through overlapping ones.
const CACHED_TERMINALS: usize = 4;

/// The lines of the terminals most recently asked about.
///
/// Taking a block's lines loads and decodes it, hashes it, and
/// recomputes the root of every section of its body; a committed block's
/// are fixed, so one taking answers every later request about it
/// without reading the block again.
#[derive(Default)]
pub struct TerminalLinesCache {
    /// Newest first, truncated at [`CACHED_TERMINALS`], no terminal
    /// twice. A queue rather than a map because the capacity is smaller
    /// than a hash.
    entries: Mutex<VecDeque<(BlockHeight, BlockHash, Arc<TerminalLines>)>>,
}

impl TerminalLinesCache {
    /// The lines held for the terminal at `height` hashing to `hash`.
    fn get(&self, height: BlockHeight, hash: BlockHash) -> Option<Arc<TerminalLines>> {
        let entries = self.entries.lock().ok()?;
        entries
            .iter()
            .find(|(at, terminal, _)| *at == height && *terminal == hash)
            .map(|(_, _, held)| Arc::clone(held))
    }

    /// Hold `taken` as the lines of the terminal at `height` hashing to
    /// `hash`, and return what is held for it: the lines already there
    /// where another request took them first.
    fn insert(
        &self,
        height: BlockHeight,
        hash: BlockHash,
        taken: TerminalLines,
    ) -> Arc<TerminalLines> {
        let Ok(mut entries) = self.entries.lock() else {
            return Arc::new(taken);
        };
        if let Some((_, _, held)) = entries
            .iter()
            .find(|(at, terminal, _)| *at == height && *terminal == hash)
        {
            return Arc::clone(held);
        }
        let taken = Arc::new(taken);
        entries.push_front((height, hash, Arc::clone(&taken)));
        entries.truncate(CACHED_TERMINALS);
        taken
    }
}

/// Serve an inbound terminal-lines request from the local chain.
///
/// Answers `not_found` when the block isn't held, the stored block's
/// hash doesn't match the requested terminal, or that block carries no
/// terminal settled root — the requester rotates peers. The last keeps
/// the handler to blocks of a terminating window: a requester's evidence
/// only ever names one, and answering at every height this node holds
/// would hand any peer a hash of every section of a block per request,
/// on a shard that is not terminating at all.
///
/// A terminal whose lines `cache` holds is answered from it, reading no
/// block. The answer owns its lines, so each one copies them once.
#[must_use]
pub fn serve_terminal_lines_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    cache: &TerminalLinesCache,
    req: &GetTerminalLinesRequest,
) -> GetTerminalLinesResponse {
    let (height, hash) = (req.terminal_height, req.terminal_block_hash);
    let Some(lines) = cache
        .get(height, hash)
        .or_else(|| take_lines(pending_chain, cache, height, hash))
    else {
        record_fetch_response_sent("terminal_lines", 0);
        return GetTerminalLinesResponse::not_found();
    };
    record_fetch_response_sent("terminal_lines", 1);
    GetTerminalLinesResponse::found(TerminalLines::clone(&lines))
}

/// Take the lines of the block the chain holds at `height` into `cache`,
/// where that block hashes to `hash` and is one of a terminating window.
fn take_lines<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    cache: &TerminalLinesCache,
    height: BlockHeight,
    hash: BlockHash,
) -> Option<Arc<TerminalLines>> {
    let BlockForSync { block, .. } = pending_chain.block_for_sync(height)?;
    if block.hash() != hash || block.header().settled_txs_root().is_none() {
        return None;
    }
    Some(cache.insert(height, hash, TerminalLines::of(&block)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_hbor::Capped;
    use hyperscale_storage::PendingChain;
    use hyperscale_storage::test_helpers::{commit_settled_at, make_test_certified};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash, BlockHeader,
        BlockHeaderParts, BlockHeight, ChainOrigin, Hash, ShardId, TickLine, WitnessSources,
    };

    use super::*;
    use crate::shard::cross_shard::terminal_fixture::{commit_block, end_line};

    /// Three blocks of a terminating window, the last carrying `lines`:
    /// the store and that last block.
    fn chain_ending_in(lines: &[TickLine]) -> (SimShardStorage, Block) {
        let storage = SimShardStorage::default();
        let first = commit_block(&storage, 1, BlockHash::ZERO, &[]);
        let second = commit_block(&storage, 2, first.hash(), &[]);
        let terminal = commit_block(&storage, 3, second.hash(), lines);
        (storage, terminal)
    }

    fn served(
        pending_chain: &PendingChain<SimShardStorage>,
        height: BlockHeight,
        hash: BlockHash,
    ) -> GetTerminalLinesResponse {
        serve_terminal_lines_request(
            pending_chain,
            &TerminalLinesCache::default(),
            &GetTerminalLinesRequest::new(height, hash),
        )
    }

    /// A held terminal answers with its header, the roots of its
    /// sections and its manifest whole, in block order.
    #[test]
    fn a_held_terminal_serves_its_lines() {
        let lines = [end_line(1), end_line(2)];
        let (storage, terminal) = chain_ending_in(&lines);
        let pending_chain = PendingChain::new(Arc::new(storage), ChainOrigin::ROOT);

        let response = served(&pending_chain, terminal.height(), terminal.hash());

        let found = response.lines.expect("the terminal is held");
        assert_eq!(found, TerminalLines::of(&terminal));
        assert_eq!(found.manifest.as_slice(), lines.as_slice());
    }

    /// The lines need the terminal block and nothing behind it: a store
    /// holding no block below the terminal's own window still answers.
    #[test]
    fn the_lines_are_served_with_nothing_held_behind_the_terminal() {
        let storage = SimShardStorage::default();
        let terminal = commit_block(&storage, 7, BlockHash::ZERO, &[end_line(1)]);
        let pending_chain = PendingChain::new(Arc::new(storage), ChainOrigin::ROOT);

        let response = served(&pending_chain, terminal.height(), terminal.hash());

        assert_eq!(response.lines, Some(TerminalLines::of(&terminal)));
    }

    /// A height this node does not hold answers empty.
    #[test]
    fn a_terminal_not_held_answers_empty() {
        let (storage, terminal) = chain_ending_in(&[end_line(1)]);
        let pending_chain = PendingChain::new(Arc::new(storage), ChainOrigin::ROOT);
        assert_eq!(
            served(&pending_chain, BlockHeight::new(9), terminal.hash()),
            GetTerminalLinesResponse::not_found(),
        );
    }

    /// A block held at the height under another hash is not the terminal
    /// asked about.
    #[test]
    fn a_hash_mismatch_answers_empty() {
        let (storage, terminal) = chain_ending_in(&[end_line(1)]);
        let pending_chain = PendingChain::new(Arc::new(storage), ChainOrigin::ROOT);
        let other = BlockHash::from_raw(Hash::from_bytes(b"other-chain"));
        assert_eq!(
            served(&pending_chain, terminal.height(), other),
            GetTerminalLinesResponse::not_found(),
        );
    }

    /// A block carrying no terminal settled root is no block of a
    /// terminating window, and its lines are not served though it is
    /// held and its hash matches.
    #[test]
    fn a_block_outside_a_terminating_window_answers_empty() {
        let storage = SimShardStorage::default();
        let block = Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                shard_id: ShardId::ROOT,
                height: BlockHeight::new(1),
                ..Default::default()
            }),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
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
        let pending_chain = PendingChain::new(Arc::new(storage), ChainOrigin::ROOT);

        assert_eq!(
            served(&pending_chain, BlockHeight::new(1), hash),
            GetTerminalLinesResponse::not_found(),
        );
    }

    /// One taking of a terminal's lines answers every later request
    /// about it without reading the block: a chain holding no block at
    /// all answers a cached terminal as the chain it was taken from
    /// did, and an uncached one not at all.
    #[test]
    fn a_cached_terminal_is_served_without_reading_its_block() {
        let (storage, terminal) = chain_ending_in(&[end_line(1)]);
        let pending_chain = PendingChain::new(Arc::new(storage), ChainOrigin::ROOT);
        let blockless = PendingChain::new(Arc::new(SimShardStorage::default()), ChainOrigin::ROOT);
        let cache = TerminalLinesCache::default();
        let req = GetTerminalLinesRequest::new(terminal.height(), terminal.hash());
        assert_eq!(
            serve_terminal_lines_request(&blockless, &cache, &req),
            GetTerminalLinesResponse::not_found(),
        );

        let first = serve_terminal_lines_request(&pending_chain, &cache, &req);
        let second = serve_terminal_lines_request(&blockless, &cache, &req);

        assert_eq!(first.lines, Some(TerminalLines::of(&terminal)));
        assert_eq!(first, second);
    }

    /// A cached terminal answers only the request that names it: its
    /// hash at another height is no block this node holds.
    #[test]
    fn a_cached_terminal_answers_only_at_its_own_height() {
        let (storage, terminal) = chain_ending_in(&[end_line(1)]);
        let pending_chain = PendingChain::new(Arc::new(storage), ChainOrigin::ROOT);
        let cache = TerminalLinesCache::default();
        let named = GetTerminalLinesRequest::new(terminal.height(), terminal.hash());
        let _ = serve_terminal_lines_request(&pending_chain, &cache, &named);

        let elsewhere = GetTerminalLinesRequest::new(BlockHeight::new(2), terminal.hash());
        assert_eq!(
            serve_terminal_lines_request(&pending_chain, &cache, &elsewhere),
            GetTerminalLinesResponse::not_found(),
        );
    }

    /// Two requests that both miss and both take the lines leave one
    /// entry, and the second is handed the lines the first put there.
    #[test]
    fn a_terminal_taken_twice_is_held_once() {
        let (_, terminal) = chain_ending_in(&[end_line(1)]);
        let cache = TerminalLinesCache::default();
        let (height, hash) = (terminal.height(), terminal.hash());

        let first = cache.insert(height, hash, TerminalLines::of(&terminal));
        let second = cache.insert(height, hash, TerminalLines::of(&terminal));

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(cache.entries.lock().unwrap().len(), 1);
    }
}
