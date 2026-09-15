//! The merged-parent genesis flip's deterministic core.
//!
//! A keeper reforms the parent from its two children's terminated
//! chains: each child's terminal block `B` — the crossing that ends its
//! chain — and its certifying quorum certificate. Every input to the
//! genesis is in those two blocks and the schedule both halves already
//! read, so a keeper derives it at the cut rather than an epoch later
//! when the beacon composes the same value.

use hyperscale_types::{
    Block, BlockHeader, ChainOrigin, PredecessorTerminal, QuorumCertificate, ShardId, TerminalRef,
    WeightedTimestamp,
};

/// Derive a merged parent's genesis block and chain origin from its two
/// children's certified terminal blocks.
///
/// `left`/`right` are the terminal blocks of `parent`'s `path‖0` and
/// `path‖1` children in canonical order — the order
/// [`BlockHeader::merge_parent_genesis`] composes — each with a QC
/// certifying it. The merged root is the internal node over the two
/// terminal subtree roots, the inverse of the composition a split
/// verifies; each side is attested by its own chain, so the pair cannot
/// name a subtree neither terminal committed. The first block continues
/// both height lines at `max(h_p0, h_p1) + 1`.
///
/// `cut_wt` is the instant the children terminate at — the end of their
/// scheduled terminal window, which the beacon fold composes from the
/// same schedule. The terminal QCs confirm the terminals are certified
/// but their own weighted timestamps are never the clock: the fold binds
/// whichever QC `canonical_boundary_qcs` ranked highest across the
/// committed proposal set, so no keeper could reproduce that choice.
///
/// Both children are predecessors of the reformed parent, so the third
/// element carries both: a transaction proven absent from one child's
/// committed set says nothing about what the other committed, and the
/// successor may only admit one absent from both.
///
/// All or nothing, for that same reason. A terminal carrying no
/// commitment takes the pair with it rather than leaving the other
/// standing alone — a successor holding one of the two chains it
/// succeeds would read a single absence proof as the whole answer and
/// admit what the other child committed. Empty is the strict refusal it
/// already runs under.
///
/// # Errors
///
/// Fails when a quorum certificate does not certify its terminal block.
pub(crate) fn merge_genesis_from_terminals(
    parent: ShardId,
    left: (&BlockHeader, &QuorumCertificate),
    right: (&BlockHeader, &QuorumCertificate),
    cut_wt: WeightedTimestamp,
) -> Result<(Block, ChainOrigin, Vec<PredecessorTerminal>), String> {
    let (left_terminal, left_qc) = left;
    let (right_terminal, right_qc) = right;
    if left_qc.block_hash() != left_terminal.hash() {
        return Err("the left quorum certificate does not certify the left terminal".to_string());
    }
    if right_qc.block_hash() != right_terminal.hash() {
        return Err("the right quorum certificate does not certify the right terminal".to_string());
    }
    // The one shared derivation, so a keeper reforming the parent installs
    // exactly the block the beacon fold composes from the same terminals.
    let (genesis, origin) = Block::merge_parent_genesis_from_terminals(
        parent,
        TerminalRef {
            state_root: left_terminal.state_root(),
            block_hash: left_terminal.hash(),
            height: left_terminal.height(),
        },
        TerminalRef {
            state_root: right_terminal.state_root(),
            block_hash: right_terminal.hash(),
            height: right_terminal.height(),
        },
        cut_wt,
    );
    let predecessors: Vec<PredecessorTerminal> = [left_terminal, right_terminal]
        .into_iter()
        .map(BlockHeader::as_predecessor_terminal)
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    Ok((genesis, origin, predecessors))
}

#[cfg(test)]
mod tests {

    use hyperscale_types::{
        AggregateSignature, BlockHash, BlockHeaderParts, BlockHeight, ChainOrigin,
        CommittedTxsRoot, Hash, QuorumCertificate, Round, SettledTxsRoot, ShardId, SignerBitfield,
        SplitChildRoots, StateRoot, TerminalRoots, ValidatorId, WeightedTimestamp,
    };

    use super::*;

    fn terminal_header(shard: ShardId, height: u64, state_root: StateRoot) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height: BlockHeight::new(height),
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(shard, ChainOrigin::ROOT).into(),
            proposer: ValidatorId::new(2),
            round: Round::new(7),
            state_root,
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

    /// The derivation reproduces exactly the genesis the beacon fold
    /// composes: same inputs, same hash, height `max + 1`, clock at the
    /// cut. The served QCs carry higher-round re-certification timestamps
    /// the derivation must ignore.
    #[test]
    fn derivation_reproduces_the_fold_composition() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let left_root = StateRoot::from_raw(Hash::from_bytes(b"left subtree"));
        let right_root = StateRoot::from_raw(Hash::from_bytes(b"right subtree"));
        let composed = SplitChildRoots {
            left: left_root,
            right: right_root,
        }
        .composed_root();

        // Children terminate at heights 8 and 9, at a cut of 2000ms.
        let left_terminal = terminal_header(left, 8, left_root);
        let right_terminal = terminal_header(right, 9, right_root);
        let left_qc = certifying_qc(&left_terminal, 2_400);
        let right_qc = certifying_qc(&right_terminal, 2_600);
        let cut_wt = WeightedTimestamp::from_millis(2_000);

        // The fold's composition over the same inputs.
        let expected = Block::merge_parent_genesis(
            parent,
            composed,
            (left_terminal.hash(), left_terminal.height()),
            (right_terminal.hash(), right_terminal.height()),
            cut_wt,
        );

        let (genesis, origin, predecessors) = merge_genesis_from_terminals(
            parent,
            (&left_terminal, &left_qc),
            (&right_terminal, &right_qc),
            cut_wt,
        )
        .expect("derives");
        assert_eq!(genesis.hash(), expected.hash());
        assert_eq!(genesis.header().state_root(), composed);
        assert_eq!(origin.genesis_height, BlockHeight::new(10));
        assert_eq!(origin.anchor_wt, cut_wt);
        // Neither terminal carries a committed-transaction commitment
        // here, so the merged parent succeeds them with nothing to ask
        // against and keeps its strict rule.
        assert!(predecessors.is_empty());
    }

    /// A merged parent succeeds *both* children, so both terminals become
    /// predecessors. One absence proof settles nothing on its own: the
    /// transaction has to be absent from each child's committed set.
    #[test]
    fn both_children_become_predecessors() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let left_terminal = child_terminal(left, 8, b"left committed", true);
        let right_terminal = child_terminal(right, 9, b"right committed", true);

        let predecessors = merge_predecessors(parent, &left_terminal, &right_terminal);

        assert_eq!(predecessors.len(), 2, "both children are predecessors");
        assert_eq!(predecessors[0].shard, left);
        assert_eq!(predecessors[0].block_hash, left_terminal.hash());
        assert_eq!(predecessors[1].shard, right);
        assert_eq!(predecessors[1].block_hash, right_terminal.hash());
        assert_ne!(
            predecessors[0].committed_txs_root, predecessors[1].committed_txs_root,
            "each child commits its own set"
        );
    }

    /// And both or neither. A terminal carrying no commitment takes the
    /// pair with it: a merged parent holding one of the two chains it
    /// succeeds would read that child's absence proof as the whole answer
    /// and admit a transaction the other child committed — the replay the
    /// rule exists to refuse. Empty keeps the strict refusal instead.
    #[test]
    fn one_child_without_a_commitment_takes_the_pair() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();

        // Either side missing is the same answer, so both polarities run.
        for (left_carries, right_carries) in [(true, false), (false, true)] {
            let left_terminal = child_terminal(left, 8, b"left committed", left_carries);
            let right_terminal = child_terminal(right, 9, b"right committed", right_carries);
            assert!(
                merge_predecessors(parent, &left_terminal, &right_terminal).is_empty(),
                "one child's commitment is not the merged parent's answer",
            );
        }
    }

    /// A terminating child's header at `height`, carrying its own
    /// committed-transaction commitment when `carries_roots`.
    fn child_terminal(shard: ShardId, height: u64, tag: &[u8], carries_roots: bool) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height: BlockHeight::new(height),
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(shard, ChainOrigin::ROOT).into(),
            proposer: ValidatorId::new(2),
            round: Round::new(7),
            state_root: StateRoot::from_raw(Hash::from_bytes(tag)),
            terminal_roots: carries_roots.then(|| TerminalRoots {
                settled_txs: SettledTxsRoot::ZERO,
                committed_txs: CommittedTxsRoot::from_raw(Hash::from_bytes(tag)),
            }),
            ..Default::default()
        })
    }

    /// The predecessors a merge of these two terminals hands its parent.
    fn merge_predecessors(
        parent: ShardId,
        left_terminal: &BlockHeader,
        right_terminal: &BlockHeader,
    ) -> Vec<PredecessorTerminal> {
        let left_qc = certifying_qc(left_terminal, 2_400);
        let right_qc = certifying_qc(right_terminal, 2_600);
        let (_, _, predecessors) = merge_genesis_from_terminals(
            parent,
            (left_terminal, &left_qc),
            (right_terminal, &right_qc),
            WeightedTimestamp::from_millis(2_000),
        )
        .expect("derives");
        predecessors
    }

    /// The merged root is composed from the terminals themselves, so a
    /// terminal naming a different subtree yields a different genesis
    /// rather than silently adopting the beacon's.
    #[test]
    fn a_different_terminal_root_changes_the_genesis() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let cut_wt = WeightedTimestamp::from_millis(2_000);
        let right_terminal = terminal_header(right, 9, StateRoot::from_raw(Hash::from_bytes(b"r")));
        let right_qc = certifying_qc(&right_terminal, 2_600);

        let derive = |root: &[u8]| {
            let left_terminal =
                terminal_header(left, 8, StateRoot::from_raw(Hash::from_bytes(root)));
            let left_qc = certifying_qc(&left_terminal, 2_400);
            merge_genesis_from_terminals(
                parent,
                (&left_terminal, &left_qc),
                (&right_terminal, &right_qc),
                cut_wt,
            )
            .expect("derives")
            .0
            .hash()
        };

        assert_ne!(derive(b"honest"), derive(b"forged"));
    }

    /// A quorum certificate that doesn't certify its terminal block is
    /// rejected before any composition.
    #[test]
    fn uncertified_terminal_is_rejected() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let left_terminal = terminal_header(left, 8, StateRoot::ZERO);
        let right_terminal = terminal_header(right, 9, StateRoot::ZERO);
        let good = certifying_qc(&left_terminal, 2_400);
        // A QC certifying the wrong block.
        let bad = certifying_qc(&right_terminal, 2_600);
        assert!(
            merge_genesis_from_terminals(
                parent,
                (&left_terminal, &bad),
                (&right_terminal, &good),
                WeightedTimestamp::ZERO,
            )
            .is_err()
        );
    }
}
