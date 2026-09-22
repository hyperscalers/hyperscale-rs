//! Domain-specific [`Hash`](crate::Hash) newtypes for compile-time safety.
//!
//! Each newtype is a `#[repr(transparent)]` wrapper with `#[hbor(transparent)]`
//! encoding, so swapping a field's type from `Hash` to a newtype is source-level
//! only — wire format and on-disk bytes are unchanged.
//!
//! See [`TypedHash`](crate::TypedHash) for the shared interface and the
//! `hash_newtype!` macro in [`crate::primitives::hash`] for the declaration pattern.

use crate::primitives::hash::{Hash, TypedHash, hash_newtype};

// ── Block layer ──────────────────────────────────────────────────────────────

hash_newtype!(
    /// Hash identifying a committed or proposed block.
    ///
    /// Appears as `block_hash`, `parent_block_hash`, `qc_block_hash`,
    /// `committed_hash`, `unblocked_hash` throughout the codebase.
    pub BlockHash,
    "BlockHash"
);

// A transaction's identity is VM vocabulary — the hash of its envelope's
// canonical bytes, and the kernel's canonical ordering key — so the type
// lives there; it joins the typed-hash family through the impls below.
pub use hyperscale_vm_types::TxHash;

impl From<Hash> for TxHash {
    fn from(raw: Hash) -> Self {
        Self(raw.as_hash32())
    }
}

impl From<TxHash> for Hash {
    fn from(tx: TxHash) -> Self {
        tx.0.into()
    }
}

impl TypedHash for TxHash {
    const KIND: &'static str = "TxHash";

    fn from_raw(raw: Hash) -> Self {
        Self(raw.as_hash32())
    }

    fn into_raw(self) -> Hash {
        self.0.into()
    }

    fn as_raw(&self) -> Hash {
        self.0.into()
    }
}

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
    /// Identity hash of a [`Provisions`](crate::Provisions) batch.
    ///
    /// Computed from the content fields (source shard, block height, proof,
    /// transactions) at construction / deserialization. Used as the fetch
    /// key, cache key, and manifest leaf for cross-shard provisions.
    pub ProvisionHash,
    "ProvisionHash"
);

hash_newtype!(
    /// Per-target-shard merkle root over the tx hashes destined for that
    /// target in a block's cross-shard provisions.
    ///
    /// Populated in [`BlockHeader::provision_tx_roots`](crate::BlockHeader)
    /// and verified by target shards against their received `Provisions`
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
    /// and the generic `root_hash` / `current_root_hash` / `base_root` used
    /// by the JMT and chain-storage APIs.
    pub StateRoot,
    "StateRoot"
);

// ── Certificates & ticks ─────────────────────────────────────────────────────

hash_newtype!(
    /// Content identity of a [`Finalization`](crate::Finalization).
    ///
    /// Computed from the ordered `(shard_id, tick_id)` pairs of
    /// its execution certificates — identifies the set of ECs a tick
    /// committed to.
    pub FinalizationHash,
    "FinalizationHash"
);

hash_newtype!(
    /// Merkle root over the tick-ids a shard settled within its retention
    /// window up to a terminal block.
    ///
    /// Carried in [`BlockHeader::settled_txs_root`](crate::BlockHeader) on
    /// a terminating shard's boundary header and folded into
    /// [`ShardBoundary`](crate::ShardBoundary), so a surviving counterpart
    /// resolves split-straddling ticks against the terminated shard's
    /// beacon-attested settled set.
    pub SettledTxsRoot,
    "SettledTxsRoot"
);

hash_newtype!(
    /// Merkle root over the [`AbandonmentRecord`](crate::AbandonmentRecord)
    /// records a block carries.
    ///
    /// Carried in
    /// [`BlockHeader::abandonment_root`](crate::BlockHeader), so what
    /// a departed shard left unresolved of this chain's business is
    /// committed content rather than a reading that expires with the
    /// terminal it came from.
    pub AbandonmentRoot,
    "AbandonmentRoot"
);

hash_newtype!(
    /// Merkle root over the [`StateClaim`](crate::StateClaim)
    /// bundles a block carries.
    ///
    /// Carried in
    /// [`BlockHeader::state_claims_root`](crate::BlockHeader), so a
    /// proof of a counterpart's cell is committed content every replica
    /// folds at the same height rather than a reading one validator
    /// fetched.
    pub StateClaimsRoot,
    "StateClaimsRoot"
);

hash_newtype!(
    /// Merkle root over the transactions a shard committed within its
    /// retention window up to a terminal block.
    ///
    /// Carried in [`BlockHeader::committed_txs_root`](crate::BlockHeader)
    /// on a terminating shard's boundary header, beside
    /// [`SettledTxsRoot`]. A successor reads it off the terminal it
    /// commit-proved to tell a replay of something the predecessor
    /// committed from a first inclusion the predecessor never made.
    ///
    /// Leaves are sorted by transaction hash, which is what makes absence
    /// provable from a bracketing pair rather than the whole set.
    pub CommittedTxsRoot,
    "CommittedTxsRoot"
);

// ── Beacon chain ─────────────────────────────────────────────────────────────

hash_newtype!(
    /// Hash identifying a finalized beacon block.
    ///
    /// Chains beacon blocks: each header carries the previous block's
    /// `BeaconBlockHash` as `prev_block_hash`. Genesis predecessor is
    /// `BeaconBlockHash::ZERO`.
    pub BeaconBlockHash,
    "BeaconBlockHash"
);

hash_newtype!(
    /// HBOR-canonical hash of a [`BeaconGenesisConfig`](crate::BeaconGenesisConfig).
    ///
    /// Carried directly by [`BeaconCert::Genesis`](crate::BeaconCert)
    /// so the genesis block's authenticator binds the chain to a
    /// specific operator configuration. Two operators with different
    /// TOMLs produce different `GenesisConfigHash`es and reject each
    /// other's genesis blocks at the constructor's pairing check.
    pub GenesisConfigHash,
    "GenesisConfigHash"
);

hash_newtype!(
    /// Root of a shard's monotonic beacon-witness accumulator at a
    /// given committed block.
    ///
    /// Carried in `BlockHeader::beacon_witness_root` and therefore
    /// QC-attested. Beacon validators recompute this root from a fetched
    /// chunk's payloads plus its range proof, so a run only counts toward
    /// the committed block it was fetched against.
    pub BeaconWitnessRoot,
    "BeaconWitnessRoot"
);

hash_newtype!(
    /// Running hash chain over a shard's randomness reveals within one
    /// anchor epoch.
    ///
    /// Carried in `BlockHeader::reveal_chain` and therefore QC-attested.
    /// Resets to `ZERO`-seeded at every anchor-epoch change, so the chain a
    /// boundary block carries is exactly the closed chain of the epoch that
    /// block ends — the value the beacon folds into `state.randomness`.
    pub RevealChain,
    "RevealChain"
);

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::Hash;

    #[test]
    fn hbor_encoding_is_identical_to_inner_hash() {
        let raw = Hash::from_bytes(b"wire-format");
        let wrapped = BlockHash::from_raw(raw);

        let raw_bytes = hbor_to_vec(&raw).unwrap();
        let wrapped_bytes = hbor_to_vec(&wrapped).unwrap();

        assert_eq!(
            raw_bytes, wrapped_bytes,
            "#[hbor(transparent)] must make newtype encoding byte-identical to Hash"
        );

        let decoded: BlockHash = hbor_from_slice(&raw_bytes).unwrap();
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
        assert_eq!(Hash::from(TxHash::from(raw)), raw);
        assert_eq!(Hash::from(TransactionRoot::from_raw(raw)), raw);
    }
}
