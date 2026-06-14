//! The merged-parent genesis flip's deterministic core.
//!
//! A keeper reforms the parent from its two children's terminated
//! chains: each child's terminal block `B` (the crossing the beacon
//! anchors) and its certifying quorum certificate. The merged store the
//! keeper built holds both subtrees, so its root is `r_p`; the beacon
//! composed the same root and seeded the parent anchor with
//! [`BlockHeader::merge_parent_genesis`]'s hash over the terminal pair.
//! The derived genesis must reconstruct that anchor byte-for-byte, or
//! the local chains and the beacon disagree and the flip fails closed.

use hyperscale_types::{
    Block, BlockHeader, ChainOrigin, EpochWindows, QuorumCertificate, ShardAnchor, ShardId,
};

/// Derive a merged parent's genesis block and chain origin from its two
/// children's certified terminal blocks, verified against the beacon's
/// composed parent anchor.
///
/// `left`/`right` are the terminal blocks of `parent`'s `path‖0` and
/// `path‖1` children in canonical order — the order
/// [`BlockHeader::merge_parent_genesis`] composes — each with the QC
/// certifying it. Both children cross the same cut (the start of the
/// epoch their terminal blocks fall in); the merged chain's clock
/// anchors there and its first block continues both height lines at
/// `max(h_p0, h_p1) + 1`. `anchor.state_root` is the beacon-composed
/// `r_p` the keeper's merged store must already hold.
///
/// # Errors
///
/// Fails when a quorum certificate does not certify its terminal block,
/// when the schedule carries no epoch boundaries, or when the derived
/// genesis does not reconstruct the beacon-composed anchor.
pub fn merge_genesis_from_terminals(
    parent: ShardId,
    left: (&BlockHeader, &QuorumCertificate),
    right: (&BlockHeader, &QuorumCertificate),
    epoch_duration_ms: u64,
    anchor: &ShardAnchor,
) -> Result<(Block, ChainOrigin), String> {
    let (left_terminal, left_qc) = left;
    let (right_terminal, right_qc) = right;
    if left_qc.block_hash() != left_terminal.hash() {
        return Err("the left quorum certificate does not certify the left terminal".to_string());
    }
    if right_qc.block_hash() != right_terminal.hash() {
        return Err("the right quorum certificate does not certify the right terminal".to_string());
    }
    if epoch_duration_ms == 0 {
        return Err("a merge needs epoch boundaries to anchor the cut".to_string());
    }
    // The merged chain's clock anchors at the cut the beacon composes in
    // `compose_merge_parent`: the start of the epoch after the children's
    // final one. Both terminals coasted across that boundary, so either
    // QC's weighted timestamp floors to it; any divergence from the
    // beacon's composed cut fails closed at the genesis-hash check below.
    let windows = EpochWindows::new(epoch_duration_ms);
    let cut_wt = windows
        .window_of(windows.epoch_for(left_qc.weighted_timestamp()))
        .start;
    let genesis = Block::merge_parent_genesis(
        parent,
        anchor.state_root,
        (left_terminal.hash(), left_terminal.height()),
        (right_terminal.hash(), right_terminal.height()),
        cut_wt,
    );
    if genesis.hash() != anchor.block_hash {
        return Err(format!(
            "derived merge genesis {:?} does not reconstruct the beacon anchor {:?}",
            genesis.hash(),
            anchor.block_hash,
        ));
    }
    let origin = ChainOrigin {
        genesis_height: genesis.height(),
        anchor_wt: cut_wt,
    };
    Ok((genesis, origin))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeight, CertificateRoot,
        ChainOrigin, Hash, InFlightCount, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot,
        QuorumCertificate, Round, ShardId, SignerBitfield, SplitChildRoots, StateRoot,
        TransactionRoot, ValidatorId, WeightedTimestamp, zero_bls_signature,
    };

    use super::*;

    fn terminal_header(shard: ShardId, height: u64, state_root: StateRoot) -> BlockHeader {
        BlockHeader::new(
            shard,
            BlockHeight::new(height),
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(shard, ChainOrigin::ROOT),
            ValidatorId::new(2),
            ProposerTimestamp::ZERO,
            Round::new(7),
            false,
            state_root,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        )
    }

    fn certifying_qc(terminal: &BlockHeader, wt: u64) -> QuorumCertificate {
        QuorumCertificate::new(
            terminal.hash(),
            terminal.shard_id(),
            terminal.height(),
            terminal.parent_block_hash(),
            Round::new(9),
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(wt),
        )
    }

    /// The derivation reproduces exactly the genesis the beacon fold
    /// composed: same inputs, same hash, height `max + 1`, clock at the
    /// cut. A wrong anchor fails closed.
    #[test]
    fn derivation_reconstructs_the_beacon_anchor() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let left_root = StateRoot::from_raw(Hash::from_bytes(b"left subtree"));
        let right_root = StateRoot::from_raw(Hash::from_bytes(b"right subtree"));
        let composed = SplitChildRoots {
            left: left_root,
            right: right_root,
        }
        .composed_root();

        // Children terminate at heights 8 and 9, crossing the cut at
        // 2000ms (epoch duration 1000); their canonical timestamps land
        // past it in the next epoch.
        let left_terminal = terminal_header(left, 8, left_root);
        let right_terminal = terminal_header(right, 9, right_root);
        let left_qc = certifying_qc(&left_terminal, 2_400);
        let right_qc = certifying_qc(&right_terminal, 2_600);

        // The fold's composition over the same inputs.
        let expected = Block::merge_parent_genesis(
            parent,
            composed,
            (left_terminal.hash(), left_terminal.height()),
            (right_terminal.hash(), right_terminal.height()),
            WeightedTimestamp::from_millis(2_000),
        );
        let anchor = ShardAnchor {
            state_root: composed,
            block_hash: expected.hash(),
            height: BlockHeight::new(10),
            settled_waves_root: None,
        };

        let (genesis, origin) = merge_genesis_from_terminals(
            parent,
            (&left_terminal, &left_qc),
            (&right_terminal, &right_qc),
            1_000,
            &anchor,
        )
        .expect("derives");
        assert_eq!(genesis.hash(), anchor.block_hash);
        assert_eq!(origin.genesis_height, BlockHeight::new(10));
        assert_eq!(origin.anchor_wt, WeightedTimestamp::from_millis(2_000));

        let wrong = ShardAnchor {
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"forged")),
            ..anchor
        };
        assert!(
            merge_genesis_from_terminals(
                parent,
                (&left_terminal, &left_qc),
                (&right_terminal, &right_qc),
                1_000,
                &wrong,
            )
            .is_err()
        );
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
        let anchor = ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: BlockHeight::new(10),
            settled_waves_root: None,
        };
        assert!(
            merge_genesis_from_terminals(
                parent,
                (&left_terminal, &bad),
                (&right_terminal, &good),
                1_000,
                &anchor,
            )
            .is_err()
        );
    }
}
