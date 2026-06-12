//! The split-child genesis flip's deterministic core.
//!
//! A pre-staffed member of a split child derives the child's genesis
//! from the terminated parent chain it holds: the terminal block `B`
//! (the crossing the beacon anchors) and the coast block above it,
//! whose `parent_qc` is `B`'s canonical QC. The derived genesis must
//! reconstruct the beacon's child anchor byte-for-byte — the fold
//! seeded the anchor with [`BlockHeader::split_child_genesis`]'s hash
//! over the same inputs — so a mismatch means the local parent chain
//! and the beacon disagree, and the flip fails closed.

use hyperscale_types::{Block, BlockHeader, ChainOrigin, ShardAnchor, ShardId};

/// Derive a split child's genesis block and chain origin from the
/// parent chain's terminal pair, verified against the beacon's child
/// anchor.
///
/// `terminal_header` is `B` (the block at `anchor.height - 1` on the
/// parent chain) and `coast_header` its committed child (at
/// `anchor.height`), whose `parent_qc` carries `B`'s canonical weighted
/// timestamp — the child clock's start anchor.
///
/// # Errors
///
/// Fails when the coast header does not certify the terminal header, or
/// when the derived genesis does not reconstruct the beacon-anchored
/// genesis hash and adopted state root.
pub fn split_genesis_from_terminal(
    child: ShardId,
    terminal_header: &BlockHeader,
    coast_header: &BlockHeader,
    anchor: &ShardAnchor,
) -> Result<(Block, ChainOrigin), String> {
    if coast_header.parent_qc().block_hash() != terminal_header.hash() {
        return Err("coast header does not certify the terminal block".to_string());
    }
    let canonical_wt = coast_header.parent_qc().weighted_timestamp();
    let origin = ChainOrigin {
        genesis_height: terminal_header.height().next(),
        anchor_wt: canonical_wt,
    };
    let genesis =
        Block::split_child_genesis(child, anchor.state_root, terminal_header, canonical_wt);
    if genesis.hash() != anchor.block_hash {
        return Err(format!(
            "derived split genesis {:?} does not reconstruct the beacon anchor {:?}",
            genesis.hash(),
            anchor.block_hash,
        ));
    }
    Ok((genesis, origin))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeight, CertificateRoot, Hash,
        InFlightCount, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot, QuorumCertificate,
        Round, ShardId, SignerBitfield, StateRoot, TransactionRoot, ValidatorId, WeightedTimestamp,
        zero_bls_signature,
    };

    use super::*;

    fn header_at(shard: ShardId, height: BlockHeight, parent_qc: QuorumCertificate) -> BlockHeader {
        BlockHeader::new(
            shard,
            height,
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc,
            ValidatorId::new(2),
            ProposerTimestamp::ZERO,
            Round::new(7),
            false,
            StateRoot::from_raw(Hash::from_bytes(b"terminal state")),
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
        )
    }

    fn coast_over(terminal: &BlockHeader, wt: u64) -> BlockHeader {
        let qc = QuorumCertificate::new(
            terminal.hash(),
            terminal.shard_id(),
            terminal.height(),
            terminal.parent_block_hash(),
            Round::new(9),
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(wt),
        );
        header_at(terminal.shard_id(), terminal.height().next(), qc)
    }

    /// The derivation reproduces exactly the genesis the beacon fold
    /// seeded: same inputs, same hash; a wrong anchor fails closed.
    #[test]
    fn derivation_reconstructs_the_beacon_anchor() {
        let parent = ShardId::leaf(1, 0);
        let (left, _) = parent.children();
        let terminal = header_at(
            parent,
            BlockHeight::new(9),
            QuorumCertificate::genesis(parent, ChainOrigin::ROOT),
        );
        let coast = coast_over(&terminal, 2_500);
        let child_root = StateRoot::from_raw(Hash::from_bytes(b"left subtree"));

        // The fold's seeding convention over the same inputs.
        let expected = Block::split_child_genesis(
            left,
            child_root,
            &terminal,
            WeightedTimestamp::from_millis(2_500),
        );
        let anchor = ShardAnchor {
            state_root: child_root,
            block_hash: expected.hash(),
            height: BlockHeight::new(10),
        };

        let (genesis, origin) =
            split_genesis_from_terminal(left, &terminal, &coast, &anchor).expect("derives");
        assert_eq!(genesis.hash(), anchor.block_hash);
        assert_eq!(origin.genesis_height, BlockHeight::new(10));
        assert_eq!(origin.anchor_wt, WeightedTimestamp::from_millis(2_500));

        let wrong = ShardAnchor {
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"forged")),
            ..anchor
        };
        assert!(split_genesis_from_terminal(left, &terminal, &coast, &wrong).is_err());
    }
}
