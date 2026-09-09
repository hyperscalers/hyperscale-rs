//! Hash-level block contents (`BlockManifest`) and denormalized storage form
//! (`BlockMetadata`).

use hyperscale_hbor::Hbor;

use crate::{
    AbandonmentRecord, BeaconWitnessLeafCount, Block, BlockHash, BlockHeader, BlockHeight,
    FinalizationHash, MAX_FINALIZED_TX_PER_BLOCK, MAX_PROVISION_TARGET_SHARDS,
    MAX_PROVISIONS_PER_BLOCK, MAX_STATE_CLAIMS_PER_BLOCK, MAX_TXS_PER_BLOCK, ProvisionHash,
    QuorumCertificate, StateClaim, TxHash, Verifiable, WitnessSources,
};

/// Hash-level description of a block's contents (transactions and certificates).
///
/// This is the common denominator shared by `BlockHeaderNotification`, `BlockMetadata`,
/// and `ProtocolEvent::BlockHeaderReceived`. Extracting it into a standalone type
/// eliminates copy-paste across those sites.
///
/// Per-collection caps mirror [`Block`]'s caps one-to-one — a manifest is a
/// hash-only projection of a `Block` and inherits its natural ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct BlockManifest {
    #[hbor(max = MAX_TXS_PER_BLOCK)]
    tx_hashes: Vec<TxHash>,
    #[hbor(max = MAX_FINALIZED_TX_PER_BLOCK)]
    cert_ids: Vec<FinalizationHash>,
    #[hbor(max = MAX_PROVISIONS_PER_BLOCK)]
    provision_hashes: Vec<ProvisionHash>,
    /// What departed shards left unresolved of this chain's business,
    /// mirrored verbatim rather than by hash: a verdict is composed on
    /// the records themselves however long after the terminal they came
    /// from, and there is no later source to fetch them from.
    #[hbor(max = MAX_PROVISION_TARGET_SHARDS)]
    abandonment_records: Vec<AbandonmentRecord>,
    /// The block's state claims, mirrored verbatim: they are small, and
    /// a voter checks each against a proof of its own rather than
    /// against anything it could fetch back from a later source.
    #[hbor(max = MAX_STATE_CLAIMS_PER_BLOCK)]
    state_claims: Vec<StateClaim>,
    /// The block's beacon-witness inputs, mirrored verbatim — the
    /// sync/reload path replays leaf derivation from the manifest under
    /// QC trust. See [`WitnessSources`].
    witness_sources: WitnessSources,
}

impl Default for BlockManifest {
    /// An empty manifest with the reveal sentinel
    /// ([`WitnessSources::empty`]). Hand-written rather than derived so
    /// the sentinel stays an explicit choice.
    fn default() -> Self {
        Self {
            tx_hashes: Vec::new(),
            cert_ids: Vec::new(),
            provision_hashes: Vec::new(),
            abandonment_records: Vec::new(),
            state_claims: Vec::new(),
            witness_sources: WitnessSources::empty(),
        }
    }
}

impl BlockManifest {
    /// Build a manifest from its parts. Per-field caps are enforced at
    /// encode and decode, not here.
    #[must_use]
    pub const fn new(
        tx_hashes: Vec<TxHash>,
        cert_ids: Vec<FinalizationHash>,
        provision_hashes: Vec<ProvisionHash>,
        abandonment_records: Vec<AbandonmentRecord>,
        state_claims: Vec<StateClaim>,
        witness_sources: WitnessSources,
    ) -> Self {
        Self {
            tx_hashes,
            cert_ids,
            provision_hashes,
            abandonment_records,
            state_claims,
            witness_sources,
        }
    }

    /// Transaction hashes in block order.
    #[must_use]
    pub const fn tx_hashes(&self) -> &Vec<TxHash> {
        &self.tx_hashes
    }

    /// Finalization identities in block order — each the leaf its
    /// block's `certificate_root` commits, which is what a validator
    /// matches against what it finalized locally and what it fetches a
    /// missing body by. Identity is content rather than tick, so a tick
    /// settling in more than one part names each part separately.
    #[must_use]
    pub const fn cert_ids(&self) -> &Vec<FinalizationHash> {
        &self.cert_ids
    }

    /// Hashes of provisions included in this block.
    /// Used for provision data availability — validators fetch missing batches by hash.
    #[must_use]
    pub const fn provision_hashes(&self) -> &Vec<ProvisionHash> {
        &self.provision_hashes
    }

    /// What departed shards left unresolved of this chain's business.
    #[must_use]
    pub const fn abandonment_records(&self) -> &Vec<AbandonmentRecord> {
        &self.abandonment_records
    }

    /// The block's state claims.
    #[must_use]
    pub const fn state_claims(&self) -> &Vec<StateClaim> {
        &self.state_claims
    }

    /// The block's beacon-witness inputs.
    #[must_use]
    pub const fn witness_sources(&self) -> &WitnessSources {
        &self.witness_sources
    }

    /// Get total transaction count.
    #[must_use]
    pub const fn transaction_count(&self) -> usize {
        self.tx_hashes.len()
    }

    /// Build a manifest from a full block (extracting hashes).
    ///
    /// `Block::Sealed` carries no provisions, so the resulting manifest's
    /// `provision_hashes` is empty for sealed blocks. The caller is
    /// responsible for only invoking this on `Live` blocks (or accepting
    /// the empty result) when provision-hash fidelity matters — e.g. the
    /// commit-bookkeeping path that populates `CommitDedupIndex`.
    /// `witness_sources` is carried on the block itself, so it
    /// round-trips faithfully here — the commit-time beacon-witness leaf
    /// derivation reads it and must match every node.
    #[must_use]
    pub fn from_block(block: &Block) -> Self {
        // The source `Block` collections are capped at the same limits by
        // `Block`'s own decode validator, so the manifest cannot outgrow
        // the caps its fields declare.
        let tx_hashes: Vec<_> = block.transactions().iter().map(|tx| tx.hash()).collect();
        let cert_ids: Vec<_> = block
            .certificates()
            .iter()
            .map(|c| c.receipt_hash())
            .collect();
        let provision_hashes = block.provision_hashes();
        Self::new(
            tx_hashes,
            cert_ids,
            provision_hashes,
            block.abandonment_records().to_vec(),
            block.state_claims().to_vec(),
            block.witness_sources().as_ref().clone(),
        )
    }
}

/// Denormalized block metadata for efficient storage.
///
/// Unlike `Block`, this stores only hashes for transactions and certificates,
/// which are stored separately in their own column families. This eliminates
/// duplication and enables direct lookups.
///
/// # Storage Layout
///
/// - `"blocks"` CF: `BlockMetadata` (this struct) keyed by height
/// - `"transactions"` CF: `Transaction` keyed by `tx_hash`
/// - `"certificates"` CF: `Finalization` attestations keyed by `tick_id` hash
///
/// To reconstruct a full `Block`, fetch the metadata, then batch-fetch
/// transactions and certificates using the stored hashes.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct BlockMetadata {
    header: BlockHeader,
    manifest: BlockManifest,
    qc: Verifiable<QuorumCertificate>,
    beacon_witness_leaf_count_at_block_end: BeaconWitnessLeafCount,
}

impl BlockMetadata {
    /// Create metadata from a full block and QC. The
    /// `beacon_witness_leaf_count_at_block_end` field is left at
    /// `ZERO`; callers that know the leaf count (the per-block commit
    /// path) should use [`Self::from_block_with_witness_count`].
    #[must_use]
    pub fn from_block(block: &Block, qc: impl Into<Verifiable<QuorumCertificate>>) -> Self {
        Self::from_block_with_witness_count(block, qc, BeaconWitnessLeafCount::ZERO)
    }

    /// Create metadata stamped with `beacon_witness_leaf_count_at_block_end`.
    /// Storage backends call this so the fetch responder can map
    /// `committed_block_hash` to a `(first_leaf, last_leaf)` range without
    /// re-walking history.
    #[must_use]
    pub fn from_block_with_witness_count(
        block: &Block,
        qc: impl Into<Verifiable<QuorumCertificate>>,
        beacon_witness_leaf_count_at_block_end: BeaconWitnessLeafCount,
    ) -> Self {
        Self {
            header: block.header().clone(),
            manifest: BlockManifest::from_block(block),
            qc: qc.into(),
            beacon_witness_leaf_count_at_block_end,
        }
    }

    /// Block header (contains height, parent hash, proposer, etc.)
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Block contents (transaction hashes, certificates, deferrals, etc.)
    #[must_use]
    pub const fn manifest(&self) -> &BlockManifest {
        &self.manifest
    }

    /// Quorum certificate that commits this block.
    #[must_use]
    pub fn qc(&self) -> &QuorumCertificate {
        self.qc.as_unverified()
    }

    /// Total leaves in the shard's beacon-witness accumulator after
    /// this block. See the field doc.
    #[must_use]
    pub const fn beacon_witness_leaf_count_at_block_end(&self) -> BeaconWitnessLeafCount {
        self.beacon_witness_leaf_count_at_block_end
    }

    /// Consume the metadata and return its parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        BlockHeader,
        BlockManifest,
        Verifiable<QuorumCertificate>,
        BeaconWitnessLeafCount,
    ) {
        (
            self.header,
            self.manifest,
            self.qc,
            self.beacon_witness_leaf_count_at_block_end,
        )
    }

    /// Get block height.
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.header.height()
    }

    /// Compute hash of this block (hashes the header).
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// Get total transaction count.
    #[must_use]
    pub const fn transaction_count(&self) -> usize {
        self.manifest.transaction_count()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use super::*;

    /// Hand-roll a `BlockManifest` whose `tx_hashes` length prefix exceeds
    /// the cap. The bound check fires before any per-element allocation.
    #[test]
    fn decode_rejects_oversized_tx_hashes_count() {
        let mut buf = Vec::new();
        varint::write(&mut buf, MAX_TXS_PER_BLOCK + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, (MAX_TXS_PER_BLOCK + 1) * 32));
        let err = hbor_from_slice::<BlockManifest>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_TXS_PER_BLOCK && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_cert_ids_count() {
        // Empty tx_hashes.
        let mut buf = hbor_to_vec(&Vec::<TxHash>::new()).unwrap();
        // Oversized cert_ids.
        varint::write(&mut buf, MAX_FINALIZED_TX_PER_BLOCK + 1).unwrap();
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_FINALIZED_TX_PER_BLOCK + 1) * 32,
        ));
        let err = hbor_from_slice::<BlockManifest>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_FINALIZED_TX_PER_BLOCK
                    && actual == MAX_FINALIZED_TX_PER_BLOCK + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_provision_hashes_count() {
        let mut buf = hbor_to_vec(&Vec::<TxHash>::new()).unwrap();
        buf.extend_from_slice(&hbor_to_vec(&Vec::<FinalizationHash>::new()).unwrap());
        // Oversized provision_hashes.
        varint::write(&mut buf, MAX_PROVISIONS_PER_BLOCK + 1).unwrap();
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_PROVISIONS_PER_BLOCK + 1) * 32,
        ));
        let err = hbor_from_slice::<BlockManifest>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_PROVISIONS_PER_BLOCK
                    && actual == MAX_PROVISIONS_PER_BLOCK + 1
        ));
    }
}
