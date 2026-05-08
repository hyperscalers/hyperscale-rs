//! `RoutableTransaction` — wraps a Radix `UserTransaction` with shard-routing metadata.

use std::fmt::{self, Debug, Formatter};
use std::sync::OnceLock;

use blake3::Hasher;
use radix_common::data::manifest::{manifest_decode, manifest_encode};
use radix_transactions::model::{UserTransaction, ValidatedUserTransaction};
use radix_transactions::validation::TransactionValidator;
use sbor::prelude::*;

use crate::{
    BoundedBytes, BoundedVec, Hash, MAX_DECLARED_NODES_PER_TX, MAX_TX_BYTES_LEN, NodeId,
    TimestampRange, TxHash, shard_for_node,
};

/// A transaction with routing information.
///
/// Wraps a Radix `UserTransaction` with routing metadata for sharding.
///
/// `serialized_bytes` is the canonical wire form. The `transaction` view
/// (a deserialized `UserTransaction`) is kept around because basic-SBOR
/// can't reach into manifest-SBOR's custom value kinds — the bytes are
/// the SBOR-universe bridge. Other cached fields (`hash`, `validated`,
/// `cached_sbor`) are skipped on the wire and lazily populated from
/// `serialized_bytes`.
#[derive(BasicSbor)]
pub struct RoutableTransaction {
    /// Manifest-encoded `UserTransaction` bytes — the canonical wire form.
    serialized_bytes: BoundedBytes<MAX_TX_BYTES_LEN>,

    /// `NodeIds` that this transaction reads from.
    pub declared_reads: BoundedVec<NodeId, MAX_DECLARED_NODES_PER_TX>,

    /// `NodeIds` that this transaction writes to.
    pub declared_writes: BoundedVec<NodeId, MAX_DECLARED_NODES_PER_TX>,

    /// Half-open `WeightedTimestamp` range during which this tx may be
    /// included in a block. Anchored on the parent QC's `weighted_timestamp`
    /// at every check site. Signer-chosen, chain-enforced.
    pub validity_range: TimestampRange,

    /// Deserialized `UserTransaction`, populated by `transaction()` on
    /// first access via `manifest_decode(&serialized_bytes)`. `::new`
    /// pre-populates from the input. Not on the wire.
    #[sbor(skip)]
    transaction: OnceLock<UserTransaction>,

    /// Content hash, populated on first call to `hash()` via
    /// `blake3(&serialized_bytes)`. `::new` pre-populates. Not on the
    /// wire — recomputed at each end so a peer can't ship `(hash=X,
    /// tx_bytes=Y)` and have us key the bogus body by X.
    #[sbor(skip)]
    hash: OnceLock<Hash>,

    /// Cached signature-validated transaction. Populated lazily by
    /// `get_or_validate(validator)`. `Option` carries validation
    /// success/failure (the latter shouldn't happen for RPC-validated
    /// txs).
    #[sbor(skip)]
    validated: OnceLock<Option<ValidatedUserTransaction>>,

    /// Pre-encoded SBOR bytes of the full `RoutableTransaction`,
    /// populated lazily by `cached_sbor_bytes()`. Lets the commit thread
    /// hand bytes to `cf_put_raw` without re-encoding.
    #[sbor(skip)]
    cached_sbor: OnceLock<Vec<u8>>,
}

// Manual PartialEq/Eq - compare by hash for efficiency
impl PartialEq for RoutableTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for RoutableTransaction {}

// Manual Clone - OnceLock doesn't implement Clone. Eagerly-populated
// caches (`transaction`, `hash`) are copied if present so the clone
// doesn't pay first-access cost twice.
impl Clone for RoutableTransaction {
    fn clone(&self) -> Self {
        let transaction = OnceLock::new();
        if let Some(t) = self.transaction.get() {
            let _ = transaction.set(t.clone());
        }
        let hash = OnceLock::new();
        if let Some(h) = self.hash.get() {
            let _ = hash.set(*h);
        }
        let cached_sbor = OnceLock::new();
        if let Some(b) = self.cached_sbor.get() {
            let _ = cached_sbor.set(b.clone());
        }
        Self {
            serialized_bytes: self.serialized_bytes.clone(),
            declared_reads: self.declared_reads.clone(),
            declared_writes: self.declared_writes.clone(),
            validity_range: self.validity_range,
            transaction,
            hash,
            validated: OnceLock::new(),
            cached_sbor,
        }
    }
}

// Manual Debug — skip the validated and cached_sbor fields.
impl Debug for RoutableTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutableTransaction")
            .field("hash", &self.hash())
            .field("declared_reads", &self.declared_reads)
            .field("declared_writes", &self.declared_writes)
            .field("validity_range", &self.validity_range)
            .finish_non_exhaustive()
    }
}

impl RoutableTransaction {
    /// Create a new routable transaction from a `UserTransaction`.
    ///
    /// `validity_range` must be supplied explicitly — there is no chain-side
    /// default. The signer chooses the bounds; the chain enforces them.
    ///
    /// # Panics
    ///
    /// Panics if the `UserTransaction` cannot be SBOR-encoded — that
    /// indicates a programmer error since `UserTransaction` is a closed
    /// SBOR type and its encoding is infallible in practice.
    #[must_use]
    pub fn new(
        transaction: UserTransaction,
        declared_reads: Vec<NodeId>,
        declared_writes: Vec<NodeId>,
        validity_range: TimestampRange,
    ) -> Self {
        let payload = manifest_encode(&transaction).expect("transaction should be encodable");
        let mut hasher = Hasher::new();
        hasher.update(&payload);
        let hash = Hash::from_hash_bytes(hasher.finalize().as_bytes());

        let tx_lock = OnceLock::new();
        let _ = tx_lock.set(transaction);
        let hash_lock = OnceLock::new();
        let _ = hash_lock.set(hash);

        Self {
            serialized_bytes: payload.into(),
            declared_reads: declared_reads.into(),
            declared_writes: declared_writes.into(),
            validity_range,
            transaction: tx_lock,
            hash: hash_lock,
            validated: OnceLock::new(),
            cached_sbor: OnceLock::new(),
        }
    }

    /// Get the transaction hash (content-addressed).
    ///
    /// Computes `blake3(serialized_bytes)` on first call and caches the
    /// result. `::new` pre-populates the cache.
    pub fn hash(&self) -> TxHash {
        TxHash::from_raw(*self.hash.get_or_init(|| {
            let mut hasher = Hasher::new();
            hasher.update(&self.serialized_bytes);
            Hash::from_hash_bytes(hasher.finalize().as_bytes())
        }))
    }

    /// Get a reference to the underlying Radix transaction.
    ///
    /// Decodes `serialized_bytes` via `manifest_decode` on first call.
    /// `::new` pre-populates the cache.
    ///
    /// # Panics
    ///
    /// Panics if `serialized_bytes` doesn't decode under `manifest_decode`.
    /// Wire-decoded transactions are validated by callers (admission /
    /// pre-vote) before this is invoked.
    pub fn transaction(&self) -> &UserTransaction {
        self.transaction.get_or_init(|| {
            manifest_decode(&self.serialized_bytes)
                .expect("RoutableTransaction.serialized_bytes failed manifest_decode")
        })
    }

    /// Consume self and return the underlying transaction, decoding from
    /// the cached bytes if no decoded form is available.
    ///
    /// # Panics
    ///
    /// Same conditions as [`Self::transaction`].
    pub fn into_transaction(self) -> UserTransaction {
        // Force population, then take.
        let _ = self.transaction();
        self.transaction.into_inner().expect(
            "transaction OnceLock populated by self.transaction() invocation immediately above",
        )
    }

    /// Get or create a validated transaction.
    ///
    /// The first call validates the transaction and caches the result.
    /// Subsequent calls return the cached value, avoiding re-validation.
    ///
    /// Returns None if validation fails (should not happen for transactions
    /// that passed RPC validation).
    pub fn get_or_validate(
        &self,
        validator: &TransactionValidator,
    ) -> Option<&ValidatedUserTransaction> {
        self.validated
            .get_or_init(|| {
                self.transaction()
                    .clone()
                    .prepare_and_validate(validator)
                    .ok()
            })
            .as_ref()
    }

    /// Check if this transaction has already been validated and cached.
    pub fn is_validated(&self) -> bool {
        self.validated.get().is_some()
    }

    /// Get the cached serialized transaction bytes.
    ///
    /// These are the manifest-encoded bytes of the underlying
    /// `UserTransaction`. Use this for:
    /// - Computing transaction merkle roots (avoids re-serialization)
    /// - Network encoding (bytes are ready to use)
    pub fn serialized_bytes(&self) -> &[u8] {
        &self.serialized_bytes
    }

    /// Get the transaction as manifest-encoded bytes.
    ///
    /// Returns a clone of the cached serialized bytes. For read-only access,
    /// prefer `serialized_bytes()`.
    pub fn transaction_bytes(&self) -> Vec<u8> {
        self.serialized_bytes.0.clone()
    }

    /// Pre-serialized SBOR bytes of the full `RoutableTransaction`.
    /// Computed on first call and cached.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding fails — that's a programmer error since
    /// every field is `BasicSbor` and the type itself is closed.
    pub fn cached_sbor_bytes(&self) -> &[u8] {
        self.cached_sbor.get_or_init(|| {
            basic_encode(self).expect("RoutableTransaction SBOR encode is infallible")
        })
    }

    /// Check if this transaction is cross-shard for the given number of shards.
    pub fn is_cross_shard(&self, num_shards: u64) -> bool {
        if self.declared_writes.is_empty() {
            return false;
        }

        let first_shard = shard_for_node(&self.declared_writes[0], num_shards);
        self.declared_writes
            .iter()
            .skip(1)
            .any(|node| shard_for_node(node, num_shards) != first_shard)
    }

    /// All `NodeIds` this transaction declares access to.
    pub fn all_declared_nodes(&self) -> impl Iterator<Item = &NodeId> {
        self.declared_reads
            .iter()
            .chain(self.declared_writes.iter())
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, Categorize as _, DecodeError,
        Encoder as _, NoCustomValueKind, ValueKind, VecEncoder, basic_decode, basic_encode,
    };

    use super::*;
    use crate::test_utils::{test_node, test_transaction_with_nodes};

    #[test]
    fn roundtrip_preserves_content_hash() {
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);
        let original_hash = tx.hash();
        let bytes = basic_encode(&tx).unwrap();
        let decoded: RoutableTransaction = basic_decode(&bytes).unwrap();
        assert_eq!(decoded.hash(), original_hash);
        assert_eq!(decoded.serialized_bytes(), tx.serialized_bytes());
    }

    #[test]
    fn decoded_hash_is_blake3_of_tx_bytes_not_wire_value() {
        // The hash isn't on the wire; decode pulls only `serialized_bytes`
        // and the lazy `hash()` call computes blake3 over those bytes.
        let tx = test_transaction_with_nodes(&[7, 8, 9], vec![test_node(3)], vec![test_node(4)]);
        let bytes = basic_encode(&tx).unwrap();
        let decoded: RoutableTransaction = basic_decode(&bytes).unwrap();
        let mut hasher = Hasher::new();
        hasher.update(decoded.serialized_bytes());
        let expected = TxHash::from_raw(Hash::from_hash_bytes(hasher.finalize().as_bytes()));
        assert_eq!(decoded.hash(), expected);
    }

    #[test]
    fn decode_rejects_oversized_tx_bytes() {
        // Hand-roll a 4-field payload whose `tx_bytes` length prefix
        // exceeds MAX_TX_BYTES_LEN. The `BoundedBytes` decoder must
        // error before allocating the full Vec.
        let mut buf = Vec::with_capacity(32);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(4).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ValueKind::U8).unwrap();
            enc.write_size(MAX_TX_BYTES_LEN + 1).unwrap();
        }
        let err = basic_decode::<RoutableTransaction>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_TX_BYTES_LEN && actual == MAX_TX_BYTES_LEN + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_declared_reads() {
        // Hand-roll a 4-field payload: a real (decodable) tx_bytes
        // followed by a declared_reads array whose length exceeds the
        // cap. The `BoundedVec` decoder fires before consuming any
        // element bytes.
        let real = test_transaction_with_nodes(&[1], vec![test_node(1)], vec![test_node(1)]);
        let mut buf = Vec::with_capacity(real.serialized_bytes().len() + 16);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(4).unwrap();
            enc.encode(&real.serialized_bytes().to_vec()).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(NodeId::value_kind()).unwrap();
            enc.write_size(MAX_DECLARED_NODES_PER_TX + 1).unwrap();
        }
        let err = basic_decode::<RoutableTransaction>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_DECLARED_NODES_PER_TX && actual == MAX_DECLARED_NODES_PER_TX + 1
        ));
    }

    #[test]
    fn decode_rejects_old_5_field_shape() {
        // Hand-roll the prior wire layout (with a leading hash field) to
        // confirm a peer can't keep shipping the spoofable shape.
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);
        let mut buf = Vec::with_capacity(256);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(5).unwrap();
            // Forged hash (peer-chosen, would diverge from real tx hash).
            let bogus_hash = [0xAAu8; 32];
            enc.encode(&bogus_hash).unwrap();
            enc.encode(&tx.serialized_bytes().to_vec()).unwrap();
            enc.encode(&tx.declared_reads).unwrap();
            enc.encode(&tx.declared_writes).unwrap();
            enc.encode(&tx.validity_range).unwrap();
        }
        let err = basic_decode::<RoutableTransaction>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: 4,
                actual: 5
            }
        ));
    }
}
