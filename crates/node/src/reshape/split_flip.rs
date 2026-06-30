//! The split-child genesis flip's deterministic core.
//!
//! A pre-staffed member of a split child derives the child's genesis
//! from the terminated parent chain: the terminal block `B` (the
//! crossing the beacon anchors) and the canonical weighted timestamp the
//! beacon recorded for it. The derived genesis must reconstruct the
//! beacon's child anchor byte-for-byte — the fold seeded the anchor with
//! [`BlockHeader::split_child_genesis`]'s hash over the same inputs — so
//! a mismatch means the local parent chain and the beacon disagree, and
//! the flip fails closed.
//!
//! The clock anchor is read from the beacon's [`ShardAnchor::weighted_timestamp`],
//! which the fold derived from `B`'s committed child's `parent_qc` — the
//! canonical certifying QC carried in the chain. The QC the local store
//! serves *alongside* `B` is not that one: a terminal block can be
//! re-certified at a higher round during the parent's coast, so the served
//! certified block carries the freshest QC over `B`, whose weighted
//! timestamp differs from the canonical `parent_qc`'s. A weighted timestamp
//! must therefore only ever be taken from a `parent_qc`; the served QC is
//! used only to confirm `B` is certified at all.

use hyperscale_types::{Block, BlockHeader, ChainOrigin, QuorumCertificate, ShardAnchor, ShardId};

/// Derive a split child's genesis block and chain origin from the
/// parent chain's certified terminal block, verified against the
/// beacon's child anchor.
///
/// `terminal_header` is `B` (the block at `anchor.height - 1` on the
/// parent chain) and `terminal_qc` a QC certifying it. The child clock's
/// start anchor is *not* read from `terminal_qc` — it is
/// [`anchor.weighted_timestamp`](ShardAnchor::weighted_timestamp), the
/// canonical value the beacon fold took from `B`'s committed child's
/// `parent_qc`. `terminal_qc` only confirms `B` is certified; its own
/// weighted timestamp may be a higher-round re-certification past the
/// crossing and is never used.
///
/// # Errors
///
/// Fails when the quorum certificate does not certify the terminal
/// header, or when the derived genesis does not reconstruct the
/// beacon-anchored genesis hash and adopted state root.
pub fn split_genesis_from_terminal(
    child: ShardId,
    terminal_header: &BlockHeader,
    terminal_qc: &QuorumCertificate,
    anchor: &ShardAnchor,
) -> Result<(Block, ChainOrigin), String> {
    if terminal_qc.block_hash() != terminal_header.hash() {
        return Err("the quorum certificate does not certify the terminal block".to_string());
    }
    let canonical_wt = anchor.weighted_timestamp;
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
    /// seeded: same inputs, same hash; a wrong anchor fails closed. The
    /// clock anchor is the beacon's `anchor.weighted_timestamp`, not the
    /// served QC's — a QC re-certified at a higher round past the crossing
    /// carries a divergent timestamp the derivation must ignore.
    #[test]
    fn derivation_reconstructs_the_beacon_anchor() {
        let parent = ShardId::leaf(1, 0);
        let (left, _) = parent.children();
        let terminal = header_at(
            parent,
            BlockHeight::new(9),
            QuorumCertificate::genesis(parent, ChainOrigin::ROOT),
        );
        let canonical_wt = WeightedTimestamp::from_millis(2_500);
        let child_root = StateRoot::from_raw(Hash::from_bytes(b"left subtree"));

        // The fold seeds the anchor with the canonical (parent-QC) timestamp.
        let expected = Block::split_child_genesis(left, child_root, &terminal, canonical_wt);
        let anchor = ShardAnchor {
            state_root: child_root,
            block_hash: expected.hash(),
            height: BlockHeight::new(10),
            weighted_timestamp: canonical_wt,
            settled_waves_root: None,
        };

        // The served QC carries a *higher-round* re-certification timestamp;
        // the derivation must use the anchor's, not this one.
        let stale_qc = certifying_qc(&terminal, 9_999);
        let (genesis, origin) =
            split_genesis_from_terminal(left, &terminal, &stale_qc, &anchor).expect("derives");
        assert_eq!(genesis.hash(), anchor.block_hash);
        assert_eq!(origin.genesis_height, BlockHeight::new(10));
        assert_eq!(origin.anchor_wt, canonical_wt);

        let wrong = ShardAnchor {
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"forged")),
            ..anchor
        };
        assert!(split_genesis_from_terminal(left, &terminal, &stale_qc, &wrong).is_err());
    }
}
