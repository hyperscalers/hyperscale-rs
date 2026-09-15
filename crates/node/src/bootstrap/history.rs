//! Committed-chain backfill below a snap-synced boundary anchor.
//!
//! Snap-sync imports state, and state alone: the store it leaves behind
//! answers for the boundary it verified against and for nothing beneath
//! it. That is enough to follow the chain forward, and not enough to
//! fold the windows a terminating shard's boundary header carries — the
//! settled one reaches back to the epoch its reshape was admitted, which
//! is epochs below any boundary a joiner would import at. A member that
//! cannot fold them declines every block of the terminating epoch, so
//! past `f` such members the shard cannot terminate at all.
//!
//! So the joiner walks its own history down. Nothing here is trusted
//! bare: the anchor is beacon-attested, the block at the anchor's height
//! must hash to the anchor's `block_hash`, and each block below must be
//! the one its child names as its parent. That hash line is what settles
//! which block stands at a height — a QC signature could not add to it —
//! and it descends from an attested point, so a serving peer has no room
//! to substitute a fork.
//!
//! Sans-io, like the assemblers beside it: this emits block fetches and
//! hands back verified blocks; the driver owns transport, peer rotation
//! and the writes.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::network::request::GetBlockRequest;
use hyperscale_types::network::response::GetBlockResponse;
use hyperscale_types::{
    BlockHash, BlockHeight, CertifiedBlock, RETENTION_HORIZON, ShardAnchor, WeightedTimestamp,
};

/// How many heights the walk keeps in flight at once.
///
/// The hash line is checked downward, so a block cannot be verified
/// before its child — but it can be *fetched* before it, and the window
/// is what keeps a walk spanning thousands of blocks from costing a
/// round trip each. Sized to the state fan-out beside it, which the same
/// drivers already pace against.
const WINDOW: u64 = 16;

/// The weighted-time floor a joiner's history has to reach for the
/// attested folds to complete, given the window floor its schedule
/// records for the shard.
///
/// Two reaches, and the lower of them wins. `RETENTION_HORIZON` below
/// the anchor is what the committed fold asks for and what a reshape
/// admitted *after* this bootstrap can ask of the settled one: such a
/// reshape's floor is the start of its own admitting epoch backed off by
/// the horizon, and the anchor cannot sit above that epoch's start. A
/// reshape already admitted names its floor outright, and it is deeper.
#[must_use]
pub fn history_floor(
    anchor_wt: WeightedTimestamp,
    settled_window_floor: Option<WeightedTimestamp>,
) -> WeightedTimestamp {
    let horizon = WeightedTimestamp::from_millis(
        anchor_wt
            .as_millis()
            .saturating_sub(RETENTION_HORIZON.as_secs() * 1000),
    );
    settled_window_floor.map_or(horizon, |floor| floor.min(horizon))
}

/// What feeding one block response into the walk produced.
#[derive(Debug, PartialEq, Eq)]
pub enum HistoryOutcome {
    /// Absorbed, with nothing verified yet — the blocks above this one
    /// have not all arrived.
    Accepted,
    /// The hash line reached these blocks, highest height first. The
    /// driver records them before pumping further responses.
    Verified(Vec<CertifiedBlock>),
    /// Response rejected; the height re-arms and the driver should
    /// rotate peers.
    Rejected(&'static str),
}

/// The walk down from a boundary anchor.
#[derive(Debug)]
pub(crate) struct HistoryBackfill {
    /// The highest height not yet on the hash line.
    next: BlockHeight,
    /// The hash the block at [`Self::next`] must have.
    expected: BlockHash,
    /// Weighted-time floor: the walk ends on the first block whose own
    /// parent-QC anchor falls below it, that block included. The folds
    /// read the block they stop below, so it has to be here.
    floor: WeightedTimestamp,
    /// Arrived and not yet on the hash line.
    held: BTreeMap<BlockHeight, CertifiedBlock>,
    /// Heights the driver has a request out for.
    asked: BTreeSet<BlockHeight>,
    done: bool,
}

impl HistoryBackfill {
    /// Walk down from `anchor` until the chain's own timestamps fall
    /// below `floor`.
    ///
    /// Starts at the anchor's own height rather than below it: the
    /// boundary import seats that block's header and no manifest, so the
    /// first row a fold asks for is already one the store cannot answer.
    #[must_use]
    pub(crate) const fn new(anchor: &ShardAnchor, floor: WeightedTimestamp) -> Self {
        Self {
            next: anchor.height,
            expected: anchor.block_hash,
            floor,
            held: BTreeMap::new(),
            asked: BTreeSet::new(),
            done: false,
        }
    }

    /// Whether the walk has reached the floor or the bottom of the chain.
    #[must_use]
    pub(crate) const fn is_complete(&self) -> bool {
        self.done
    }

    /// Every height the walk wants in flight and has no request out for.
    pub(crate) fn next_requests(&mut self) -> Vec<GetBlockRequest> {
        if self.done {
            return Vec::new();
        }
        let mut requests = Vec::new();
        let mut height = self.next;
        for _ in 0..WINDOW {
            if !self.held.contains_key(&height) && self.asked.insert(height) {
                // No inventory: a store this fresh can rehydrate nothing,
                // so every body has to ride inline.
                requests.push(GetBlockRequest::new(height, height));
            }
            let Some(prev) = height.prev() else { break };
            height = prev;
        }
        requests
    }

    /// Re-arm `height` after a transport failure or an empty answer, so
    /// the next pass asks another peer.
    pub(crate) fn on_failure(&mut self, height: BlockHeight) {
        self.asked.remove(&height);
    }

    /// Absorb one block response for `height`.
    ///
    /// Rehydrated against nothing: the walk advertises no inventory, so
    /// a peer that elides a body has answered something this store could
    /// never reassemble and the height re-arms against another.
    pub(crate) fn on_response(
        &mut self,
        height: BlockHeight,
        response: &GetBlockResponse,
    ) -> HistoryOutcome {
        let Some(elided) = response.certified.as_ref() else {
            self.on_failure(height);
            return HistoryOutcome::Accepted;
        };
        let Ok(certified) = elided.try_rehydrate(|_| None, |_| None, |_| None) else {
            self.on_failure(height);
            return HistoryOutcome::Rejected(
                "block answered with bodies this store cannot resolve",
            );
        };
        self.absorb(height, certified)
    }

    /// Absorb the block a fetch for `height` returned.
    fn absorb(&mut self, height: BlockHeight, certified: CertifiedBlock) -> HistoryOutcome {
        self.asked.remove(&height);
        if self.done {
            return HistoryOutcome::Accepted;
        }
        if certified.height() != height {
            return HistoryOutcome::Rejected("block answered for a height it does not carry");
        }
        if height > self.next {
            return HistoryOutcome::Accepted;
        }
        self.held.insert(height, certified);
        self.extend()
    }

    /// Take every held block the hash line now reaches.
    fn extend(&mut self) -> HistoryOutcome {
        let mut verified = Vec::new();
        while let Some(certified) = self.held.remove(&self.next) {
            if certified.hash() != self.expected {
                // A peer answering with a fork, or with the right height
                // off the wrong chain. Re-arm and rotate; the line below
                // is untouched, so nothing already verified is at risk.
                self.asked.remove(&self.next);
                return HistoryOutcome::Rejected("block is not the one its child names as parent");
            }
            let header = certified.block().header();
            // Two ends, and either is the bottom. The floor is the one
            // the folds test, and it reads the block it stops below, so
            // that block is recorded before the walk stops. The other is
            // the chain's own beginning: a structural genesis parent QC
            // means there is no parent block anywhere, which is where a
            // split child's line ends rather than at height zero.
            let bottom = header.parent_qc().weighted_timestamp() < self.floor
                || header.parent_qc().is_genesis();
            let parent = header.parent_block_hash();
            let prev = self.next.prev();
            verified.push(certified);
            if bottom {
                self.done = true;
                break;
            }
            let Some(prev) = prev else {
                self.done = true;
                break;
            };
            self.next = prev;
            self.expected = parent;
        }
        if self.done {
            self.held.clear();
            self.asked.clear();
        }
        if verified.is_empty() {
            HistoryOutcome::Accepted
        } else {
            HistoryOutcome::Verified(verified)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_types::{
        AggregateSignature, BeaconWitnessLeafCount, Block, BlockHeader, BlockHeaderParts,
        ChainOrigin, ElidedCertifiedBlock, Inventory, ProposerTimestamp, QuorumCertificate, Round,
        ShardId, SignerBitfield, StateRoot, ValidatorId, Verifiable, Verified, WitnessSources,
    };

    use super::*;

    const SHARD: ShardId = ShardId::ROOT;

    /// A QC over `block_hash` with a signer set, so it is not the
    /// structural genesis the walk stops at.
    fn real_qc(block_hash: BlockHash, wt_ms: u64) -> Verified<QuorumCertificate> {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        Verified::new_unchecked_for_test(QuorumCertificate::new(
            block_hash,
            SHARD,
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            Round::new(1),
            signers,
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(wt_ms),
        ))
    }

    /// A chain of `len` blocks rising to height `len`, each naming the
    /// one below it, whose parent-QC anchors run `1000` apart. The
    /// lowest block's parent QC is genesis-shaped, so it is the bottom.
    fn chain_from(len: u64, proposer: u64) -> Vec<CertifiedBlock> {
        let mut blocks: Vec<CertifiedBlock> = Vec::new();
        for height in 1..=len {
            let parent_hash = blocks.last().map_or(BlockHash::ZERO, CertifiedBlock::hash);
            let parent_qc = if height == 1 {
                QuorumCertificate::genesis(SHARD, ChainOrigin::ROOT).into()
            } else {
                parent_qc_of(parent_hash, height * 1000)
            };
            let header = BlockHeader::new(BlockHeaderParts {
                shard_id: SHARD,
                height: BlockHeight::new(height),
                parent_block_hash: parent_hash,
                parent_qc,
                proposer: ValidatorId::new(proposer),
                timestamp: ProposerTimestamp::from_millis(height * 1000),
                ..Default::default()
            });
            let block = Block::Live {
                header,
                transactions: Arc::new(Vec::new()),
                certificates: Arc::new(Vec::new()),
                provisions: Arc::new(Vec::new()),
                abandonment_records: Arc::new(Vec::new()),
                state_claims: Arc::new(Vec::new()),
                witness_sources: Arc::new(WitnessSources::empty()),
            };
            let qc = real_qc(block.hash(), height * 1000);
            blocks.push(CertifiedBlock::new_unchecked(block, qc));
        }
        blocks
    }

    /// The canonical chain under test.
    fn chain(len: u64) -> Vec<CertifiedBlock> {
        chain_from(len, 0)
    }

    fn parent_qc_of(parent_hash: BlockHash, wt_ms: u64) -> Verifiable<QuorumCertificate> {
        real_qc(parent_hash, wt_ms).into()
    }

    fn anchor_over(top: &CertifiedBlock) -> ShardAnchor {
        ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: top.hash(),
            height: top.height(),
            weighted_timestamp: top.block().header().parent_qc().weighted_timestamp(),
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_roots: None,
            handoff_complete: None,
        }
    }

    fn answer(chain: &[CertifiedBlock], height: BlockHeight) -> GetBlockResponse {
        chain
            .iter()
            .find(|c| c.height() == height)
            .map_or_else(GetBlockResponse::not_found, |c| {
                GetBlockResponse::found(ElidedCertifiedBlock::elide(
                    c.block(),
                    c.qc().clone(),
                    &Inventory::empty(),
                ))
            })
    }

    /// Drive `walk` against `serve`, answering every height it asks for,
    /// and return the heights it recorded in the order it recorded them.
    fn run(
        walk: &mut HistoryBackfill,
        serve: impl Fn(BlockHeight) -> GetBlockResponse,
    ) -> Vec<u64> {
        let mut recorded = Vec::new();
        for _ in 0..100 {
            if walk.is_complete() {
                return recorded;
            }
            for request in walk.next_requests() {
                let response = serve(request.height);
                if let HistoryOutcome::Verified(blocks) =
                    walk.on_response(request.height, &response)
                {
                    recorded.extend(blocks.iter().map(|c| c.height().inner()));
                }
            }
        }
        panic!("the walk did not finish");
    }

    /// The walk stops on the first block whose own anchor falls below
    /// the floor, that block included — the fold reads the block it
    /// stops below, so leaving it out would leave the hole one height
    /// lower. Block `h` anchors at `h * 1000`, so a floor of 8000 keeps
    /// height 8 and ends on height 7.
    #[test]
    fn the_walk_records_the_block_it_stops_below() {
        let chain = chain(10);
        let top = chain.last().expect("a chain of ten");
        let mut walk =
            HistoryBackfill::new(&anchor_over(top), WeightedTimestamp::from_millis(8_000));
        let recorded = run(&mut walk, |h| answer(&chain, h));
        assert_eq!(recorded, vec![10, 9, 8, 7]);
    }

    /// Nothing below the chain's own beginning: the walk ends on the
    /// block whose parent QC is the structural genesis rather than
    /// asking for a height no server can answer for.
    #[test]
    fn the_walk_ends_at_the_bottom_of_the_chain() {
        let chain = chain(4);
        let top = chain.last().expect("a chain of four");
        let mut walk = HistoryBackfill::new(&anchor_over(top), WeightedTimestamp::ZERO);
        let recorded = run(&mut walk, |h| answer(&chain, h));
        assert_eq!(recorded, vec![4, 3, 2, 1]);
    }

    /// A block off another chain is refused however well-formed it is:
    /// what settles a height is the hash line down from the attested
    /// anchor, and nothing below the refusal is touched.
    #[test]
    fn a_block_its_child_does_not_name_is_refused() {
        let chain = chain(6);
        // A chain of the same shape under a different proposer, so it
        // shares no hash with the one the anchor names.
        let fork = chain_from(6, 1);
        let top = chain.last().expect("a chain of six");
        let mut walk = HistoryBackfill::new(&anchor_over(top), WeightedTimestamp::ZERO);

        // The top block is on the line; the one below it is answered
        // from a chain that shares no hashes.
        assert!(matches!(
            walk.on_response(BlockHeight::new(6), &answer(&chain, BlockHeight::new(6))),
            HistoryOutcome::Verified(_)
        ));
        assert_eq!(
            walk.on_response(BlockHeight::new(5), &answer(&fork, BlockHeight::new(5))),
            HistoryOutcome::Rejected("block is not the one its child names as parent"),
        );
        // The height re-arms, and the honest answer takes it.
        let recorded = run(&mut walk, |h| answer(&chain, h));
        assert_eq!(recorded, vec![5, 4, 3, 2, 1]);
    }

    /// A height nobody can answer for re-arms rather than ending the
    /// walk: the peer may simply not hold it.
    #[test]
    fn an_unanswered_height_rearms() {
        let chain = chain(3);
        let top = chain.last().expect("a chain of three");
        let mut walk = HistoryBackfill::new(&anchor_over(top), WeightedTimestamp::ZERO);
        assert_eq!(
            walk.on_response(BlockHeight::new(3), &GetBlockResponse::not_found()),
            HistoryOutcome::Accepted,
        );
        assert!(!walk.is_complete());
        let recorded = run(&mut walk, |h| answer(&chain, h));
        assert_eq!(recorded, vec![3, 2, 1]);
    }

    /// The floor is the deeper of the two reaches, and a shard with no
    /// window floor recorded still reaches the retention horizon.
    #[test]
    fn the_floor_takes_the_deeper_of_the_two_reaches() {
        let anchor = WeightedTimestamp::from_millis(1_000_000);
        let horizon = 1_000_000 - RETENTION_HORIZON.as_secs() * 1000;
        assert_eq!(history_floor(anchor, None).as_millis(), horizon);
        assert_eq!(
            history_floor(anchor, Some(WeightedTimestamp::from_millis(10_000))).as_millis(),
            10_000,
        );
        assert_eq!(
            history_floor(anchor, Some(WeightedTimestamp::from_millis(999_999))).as_millis(),
            horizon,
        );
    }

    /// A shard whose chain is younger than the horizon floors at zero
    /// rather than wrapping.
    #[test]
    fn a_young_chain_floors_at_zero() {
        assert_eq!(
            history_floor(WeightedTimestamp::from_millis(500), None).as_millis(),
            0,
        );
    }
}
