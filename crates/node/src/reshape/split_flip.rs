//! The split-child genesis flip's anchor fallback.
//!
//! A member of a split child that did not recognise its parent's terminal
//! crossing on its own follow derives the child's genesis from the
//! terminated parent chain instead: the terminal block `B` and the
//! canonical weighted timestamp the beacon recorded for it.
//!
//! The clock is read from the child's beacon anchor, which the fold took
//! from `B`'s committed successor's `parent_qc` — the canonical certifying
//! QC carried in the chain. The QC the local store serves *alongside* `B`
//! is not that one: a terminal can be re-certified at a higher round during
//! the parent's coast, so the served certified block carries the freshest
//! QC over `B`, whose weighted timestamp differs from the canonical
//! `parent_qc`'s. A weighted timestamp may therefore only ever be taken
//! from a `parent_qc`; the served QC confirms only that `B` is certified.

use hyperscale_types::{
    Block, BlockHeader, ChainOrigin, QuorumCertificate, ShardId, WeightedTimestamp,
};

/// Derive a split child's genesis block and chain origin from the parent
/// chain's certified terminal block.
///
/// The fallback path a duty takes when it could not recognise the crossing
/// on its own follow — a late-discovered duty, or one whose walk lost the
/// race. `terminal_header` is `B`, the block below the child's genesis
/// height, and `terminal_qc` a QC certifying it.
///
/// The derivation itself is [`Block::split_child_genesis_from_terminal`],
/// shared with the beacon fold and the cut-over flip, so all three install
/// the same block. `canonical_wt` is the clock the caller read from the
/// beacon's child anchor — the value the fold took from `B`'s committed
/// successor's `parent_qc`. `terminal_qc` only confirms `B` is certified;
/// its own weighted timestamp may be a higher-round re-certification past
/// the crossing and is never used.
///
/// Verifying the result against the anchor is the caller's: it holds one
/// on this path, and the derivation is shared with paths that do not.
///
/// # Errors
///
/// Fails when the quorum certificate does not certify the terminal header,
/// or when the terminal carries no `split_child_roots` pair composing to
/// its own committed state root.
pub(crate) fn split_genesis_from_terminal(
    child: ShardId,
    terminal_header: &BlockHeader,
    terminal_qc: &QuorumCertificate,
    canonical_wt: WeightedTimestamp,
) -> Result<(Block, ChainOrigin), String> {
    if terminal_qc.block_hash() != terminal_header.hash() {
        return Err("the quorum certificate does not certify the terminal block".to_string());
    }
    Block::split_child_genesis_from_terminal(child, terminal_header, canonical_wt)
        .ok_or_else(|| "the terminal carries no composing split child roots".to_string())
}

#[cfg(test)]
mod tests {

    use hyperscale_types::{
        AggregateSignature, BlockHash, BlockHeaderParts, BlockHeight, Hash, QuorumCertificate,
        Round, ShardId, SignerBitfield, SplitChildRoots, StateRoot, ValidatorId, WeightedTimestamp,
    };

    use super::*;

    fn header_at(
        shard: ShardId,
        height: BlockHeight,
        parent_qc: QuorumCertificate,
        state_root: StateRoot,
        pair: Option<SplitChildRoots>,
    ) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: parent_qc.into(),
            proposer: ValidatorId::new(2),
            round: Round::new(7),
            state_root,
            split_child_roots: pair,
            ..Default::default()
        })
    }

    fn certifying_qc(terminal: &BlockHeader, wt: u64) -> QuorumCertificate {
        QuorumCertificate::new(
            terminal.hash(),
            terminal.shard_id(),
            terminal.height(),
            terminal.parent_block_hash(),
            Round::new(9),
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(wt),
        )
    }

    /// A terminal carrying a composing child-root pair derives the child's
    /// genesis, clocked by the canonical timestamp the caller supplies —
    /// never by the served QC, which carries a higher-round
    /// re-certification stamp from past the crossing.
    #[test]
    fn derivation_uses_the_canonical_clock_not_the_served_qc() {
        let parent = ShardId::leaf(1, 0);
        let (left, _) = parent.children();
        let pair = SplitChildRoots {
            left: StateRoot::from_raw(Hash::from_bytes(b"left subtree")),
            right: StateRoot::from_raw(Hash::from_bytes(b"right subtree")),
        };
        let terminal = header_at(
            parent,
            BlockHeight::new(9),
            QuorumCertificate::genesis(parent, ChainOrigin::ROOT),
            pair.composed_root(),
            Some(pair),
        );
        let canonical_wt = WeightedTimestamp::from_millis(2_500);

        let stale_qc = certifying_qc(&terminal, 9_999);
        let (genesis, origin) =
            split_genesis_from_terminal(left, &terminal, &stale_qc, canonical_wt).expect("derives");
        assert_eq!(
            genesis.hash(),
            Block::split_child_genesis(left, pair.left, &terminal, canonical_wt).hash(),
        );
        assert_eq!(origin.genesis_height, BlockHeight::new(10));
        assert_eq!(origin.anchor_wt, canonical_wt);
    }

    /// A terminal whose child-root pair does not compose to its own
    /// committed state root derives nothing — a parent cannot name a
    /// subtree its terminal does not hold.
    #[test]
    fn a_non_composing_pair_derives_nothing() {
        let parent = ShardId::leaf(1, 0);
        let (left, _) = parent.children();
        let pair = SplitChildRoots {
            left: StateRoot::from_raw(Hash::from_bytes(b"left subtree")),
            right: StateRoot::from_raw(Hash::from_bytes(b"right subtree")),
        };
        let terminal = header_at(
            parent,
            BlockHeight::new(9),
            QuorumCertificate::genesis(parent, ChainOrigin::ROOT),
            StateRoot::from_raw(Hash::from_bytes(b"a different root")),
            Some(pair),
        );
        let qc = certifying_qc(&terminal, 2_500);
        assert!(
            split_genesis_from_terminal(
                left,
                &terminal,
                &qc,
                WeightedTimestamp::from_millis(2_500)
            )
            .is_err()
        );
    }
}
