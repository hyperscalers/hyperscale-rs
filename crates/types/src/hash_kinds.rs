//! Domain-specific [`Hash`](crate::Hash) newtypes for compile-time safety.
//!
//! Each newtype is a `#[repr(transparent)]` wrapper with `#[sbor(transparent)]`
//! encoding, so swapping a field's type from `Hash` to a newtype is source-level
//! only — wire format and on-disk bytes are unchanged.
//!
//! See [`TypedHash`](crate::TypedHash) for the shared interface and the
//! `hash_newtype!` macro in [`crate::hash`] for the declaration pattern.

use crate::hash::hash_newtype;

// ── Block layer ──────────────────────────────────────────────────────────────

hash_newtype!(
    /// Hash identifying a committed or proposed block.
    ///
    /// Appears as `block_hash`, `parent_block_hash`, `qc_block_hash`,
    /// `committed_hash`, `unblocked_hash` throughout the codebase.
    pub BlockHash,
    "BlockHash"
);

hash_newtype!(
    /// Hash identifying a transaction.
    ///
    /// Appears as `tx_hash` / `transaction_hash`.
    pub TxHash,
    "TxHash"
);

// ── Per-block merkle roots ───────────────────────────────────────────────────

hash_newtype!(
    /// Merkle root over the transactions in a block.
    pub TransactionRoot,
    "TransactionRoot"
);

hash_newtype!(
    /// Merkle root over the execution certificates attached to a block.
    pub CertificateRoot,
    "CertificateRoot"
);

hash_newtype!(
    /// Merkle root over the cross-shard provisions attached to a block.
    pub ProvisionsRoot,
    "ProvisionsRoot"
);

hash_newtype!(
    /// Identity hash of a [`Provision`](crate::Provision) batch.
    ///
    /// Computed from the content fields (source shard, block height, proof,
    /// transactions) at construction / deserialization. Used as the fetch
    /// key, cache key, and manifest leaf for cross-shard provision batches.
    pub ProvisionHash,
    "ProvisionHash"
);

hash_newtype!(
    /// Per-target-shard merkle root over the tx hashes destined for that
    /// target in a block's cross-shard provision batches.
    ///
    /// Populated in [`BlockHeader::provision_tx_roots`](crate::BlockHeader)
    /// and verified by target shards against their received `ProvisionBatch`
    /// to detect a proposer omitting transactions.
    pub ProvisionTxRoot,
    "ProvisionTxRoot"
);

hash_newtype!(
    /// Merkle root over this shard's local receipts for a block.
    pub LocalReceiptRoot,
    "LocalReceiptRoot"
);

hash_newtype!(
    /// Merkle root over the global (cross-shard) receipts for a block.
    pub GlobalReceiptRoot,
    "GlobalReceiptRoot"
);

hash_newtype!(
    /// Per-transaction global receipt hash (identity of a [`GlobalReceipt`](crate::GlobalReceipt)).
    ///
    /// Computed from `(outcome, event_root, writes_root)` — this is what
    /// validators sign over in execution votes and what remote shards compare
    /// against for cross-shard agreement.
    pub GlobalReceiptHash,
    "GlobalReceiptHash"
);

hash_newtype!(
    /// Merkle root over application events emitted in a block.
    pub EventRoot,
    "EventRoot"
);

hash_newtype!(
    /// Merkle root over state writes committed in a block.
    pub WritesRoot,
    "WritesRoot"
);

// ── State (JMT) ──────────────────────────────────────────────────────────────

hash_newtype!(
    /// Jellyfish Merkle Tree root identifying a specific state version.
    ///
    /// Appears as `state_root`, `parent_state_root`, `committed_state_root`,
    /// and the generic `root_hash` / `current_root_hash` / `base_root` used by
    /// the JMT and `CommitStore` APIs.
    pub StateRoot,
    "StateRoot"
);

// ── Certificates & waves ─────────────────────────────────────────────────────

hash_newtype!(
    /// Canonical content hash of an [`ExecutionCertificate`](crate::ExecutionCertificate).
    ///
    /// Excludes the BLS signature and signer bitfield — this is the safety
    /// property that lets multiple aggregators produce the same canonical hash
    /// for equivalent certificates.
    pub ExecutionCertificateHash,
    "ExecutionCertificateHash"
);

hash_newtype!(
    /// Content identity of a [`WaveCertificate`](crate::WaveCertificate).
    ///
    /// Computed from the ordered `(shard_group_id, canonical_hash)` pairs of
    /// its execution certificates — identifies the set of ECs a wave
    /// committed to.
    pub WaveReceiptHash,
    "WaveReceiptHash"
);

hash_newtype!(
    /// Identity hash of a [`WaveId`](crate::WaveId).
    ///
    /// Computed from the SBOR-encoded `(shard_group_id, block_height, remote_shards)`
    /// tuple — uniquely identifies a wave without requiring knowledge of its
    /// execution certificates. Used as the key for wave-cert storage,
    /// `BlockManifest::cert_hashes`, fetch requests, and the `tx_to_wave` index.
    pub WaveIdHash,
    "WaveIdHash"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;
    use sbor::prelude::*;

    #[test]
    fn sbor_encoding_is_identical_to_inner_hash() {
        let raw = Hash::from_bytes(b"wire-format");
        let wrapped = BlockHash::from_raw(raw);

        let raw_bytes = basic_encode(&raw).unwrap();
        let wrapped_bytes = basic_encode(&wrapped).unwrap();

        assert_eq!(
            raw_bytes, wrapped_bytes,
            "#[sbor(transparent)] must make newtype encoding byte-identical to Hash"
        );

        let decoded: BlockHash = basic_decode(&raw_bytes).unwrap();
        assert_eq!(decoded, wrapped);
    }

    #[test]
    fn debug_output_uses_kind_label() {
        let h = StateRoot::from_raw(Hash::from_bytes(b"state"));
        let rendered = format!("{h:?}");
        assert!(
            rendered.starts_with("StateRoot("),
            "Debug output should start with kind label, got: {rendered}"
        );
    }

    #[test]
    fn round_trip_preserves_bytes() {
        let raw = Hash::from_bytes(b"round-trip");
        assert_eq!(ExecutionCertificateHash::from_raw(raw).into_raw(), raw);
        assert_eq!(*TxHash::from_raw(raw).as_raw(), raw);
        assert_eq!(Hash::from(TransactionRoot::from_raw(raw)), raw);
    }
}
