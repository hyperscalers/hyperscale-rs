//! `RoutableTransaction` — wraps a Radix `UserTransaction` with shard-routing metadata.

use std::fmt::{self, Debug, Formatter};
use std::sync::OnceLock;

use blake3::Hasher;
use radix_common::data::manifest::{manifest_decode, manifest_encode};
use radix_transactions::model::{UserTransaction, ValidatedUserTransaction};
use radix_transactions::validation::TransactionValidator;
use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::sbor_codec::decode_bounded_bytes;
use crate::{
    Hash, MAX_DECLARED_NODES_PER_TX, MAX_TX_BYTES_LEN, NodeId, TimestampRange, TxHash,
    shard_for_node,
};

/// A transaction with routing information.
///
/// Wraps a Radix `UserTransaction` with routing metadata for sharding.
pub struct RoutableTransaction {
    /// The underlying Radix transaction.
    transaction: UserTransaction,

    /// `NodeIds` that this transaction reads from.
    pub declared_reads: Vec<NodeId>,

    /// `NodeIds` that this transaction writes to.
    pub declared_writes: Vec<NodeId>,

    /// Half-open `WeightedTimestamp` range during which this tx may be
    /// included in a block. Anchored on the parent QC's `weighted_timestamp`
    /// at every check site. Signer-chosen, chain-enforced.
    pub validity_range: TimestampRange,

    /// Cached hash (computed on first access).
    hash: Hash,

    /// Cached serialized transaction bytes.
    ///
    /// These are the SBOR-encoded bytes of the `UserTransaction`, captured during
    /// construction or deserialization. This avoids redundant re-serialization when:
    /// - Computing transaction merkle roots for block headers
    /// - Re-encoding for network transmission
    ///
    /// The hash is computed from these bytes.
    serialized_bytes: Vec<u8>,

    /// Cached validated transaction (computed on first validation).
    /// This avoids re-validating signatures during execution.
    /// Not serialized - reconstructed on demand.
    /// Option because validation can theoretically fail (though shouldn't for RPC-validated txs).
    validated: OnceLock<Option<ValidatedUserTransaction>>,

    /// Cached full SBOR encoding of this `RoutableTransaction`.
    /// Set eagerly at construction/decode time so the commit thread
    /// never re-encodes — the bytes are ready for `cf_put_raw`.
    cached_sbor: Option<Vec<u8>>,
}

// Manual PartialEq/Eq - compare by hash for efficiency
impl PartialEq for RoutableTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for RoutableTransaction {}

// Manual Clone - OnceLock doesn't implement Clone, and we don't want to clone the cached value
impl Clone for RoutableTransaction {
    fn clone(&self) -> Self {
        Self {
            transaction: self.transaction.clone(),
            declared_reads: self.declared_reads.clone(),
            declared_writes: self.declared_writes.clone(),
            validity_range: self.validity_range,
            hash: self.hash,
            serialized_bytes: self.serialized_bytes.clone(),
            validated: OnceLock::new(),
            cached_sbor: self.cached_sbor.clone(),
        }
    }
}

// Manual Debug - skip the validated field
impl Debug for RoutableTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutableTransaction")
            .field("hash", &self.hash)
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
        // Serialize the transaction payload - we keep these bytes for:
        // 1. Computing the hash (below)
        // 2. Efficient re-encoding for network/merkle (via serialized_bytes())
        let payload = manifest_encode(&transaction).expect("transaction should be encodable");

        // Hash the transaction payload directly
        let mut hasher = Hasher::new();
        hasher.update(&payload);
        let hash = Hash::from_hash_bytes(hasher.finalize().as_bytes());

        let mut tx = Self {
            transaction,
            declared_reads,
            declared_writes,
            validity_range,
            hash,
            serialized_bytes: payload,
            validated: OnceLock::new(),
            cached_sbor: None,
        };
        tx.populate_cached_sbor();
        tx
    }

    /// Get the transaction hash (content-addressed).
    pub const fn hash(&self) -> TxHash {
        TxHash::from_raw(self.hash)
    }

    /// Get a reference to the underlying Radix transaction.
    pub const fn transaction(&self) -> &UserTransaction {
        &self.transaction
    }

    /// Consume self and return the underlying transaction.
    pub fn into_transaction(self) -> UserTransaction {
        self.transaction
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
                self.transaction
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
    /// These are the SBOR-encoded bytes of the underlying `UserTransaction`,
    /// captured during construction or deserialization. Use this for:
    /// - Computing transaction merkle roots (avoids re-serialization)
    /// - Network encoding (bytes are ready to use)
    pub fn serialized_bytes(&self) -> &[u8] {
        &self.serialized_bytes
    }

    /// Get the transaction as SBOR-encoded bytes.
    ///
    /// This returns a clone of the cached serialized bytes. For read-only access,
    /// prefer `serialized_bytes()` which returns a reference.
    pub fn transaction_bytes(&self) -> Vec<u8> {
        self.serialized_bytes.clone()
    }

    /// Pre-serialized SBOR bytes of the full `RoutableTransaction`.
    pub fn cached_sbor_bytes(&self) -> Option<&[u8]> {
        self.cached_sbor.as_deref()
    }

    fn populate_cached_sbor(&mut self) {
        self.cached_sbor = Some(basic_encode(self).expect("RoutableTransaction SBOR encode"));
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

// ============================================================================
// Manual SBOR implementation since UserTransaction uses ManifestSbor
// ============================================================================

fn decode_bounded_node_ids<D: Decoder<NoCustomValueKind>>(
    decoder: &mut D,
    max_len: usize,
) -> Result<Vec<NodeId>, DecodeError> {
    decoder.read_and_check_value_kind(ValueKind::Array)?;
    let element_kind = decoder.read_and_check_value_kind(NodeId::value_kind())?;
    let len = decoder.read_size()?;
    if len > max_len {
        return Err(DecodeError::UnexpectedSize {
            expected: max_len,
            actual: len,
        });
    }
    // Cap the with_capacity hint so a peer-claimed huge `len` can't
    // pre-allocate before the decode loop short-circuits on missing data.
    let mut out = Vec::with_capacity(len.min(1024));
    for _ in 0..len {
        out.push(decoder.decode_deeper_body_with_value_kind(element_kind)?);
    }
    Ok(out)
}

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for RoutableTransaction {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        // Hash is content-derived (blake3 over `serialized_bytes`); the
        // decoder recomputes it. Sending the hash on the wire would let a
        // peer ship `(hash=X, tx_bytes=Y)` and have us key the bogus body
        // by X, diverging from any later re-hash from `tx_bytes`.
        encoder.write_size(4)?;
        encoder.encode(&self.serialized_bytes)?;
        encoder.encode(&self.declared_reads)?;
        encoder.encode(&self.declared_writes)?;
        encoder.encode(&self.validity_range)?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for RoutableTransaction {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 4 {
            return Err(DecodeError::UnexpectedSize {
                expected: 4,
                actual: length,
            });
        }

        let tx_bytes = decode_bounded_bytes(decoder, MAX_TX_BYTES_LEN)?;
        let transaction: UserTransaction =
            manifest_decode(&tx_bytes).map_err(|_| DecodeError::InvalidCustomValue)?;
        let declared_reads = decode_bounded_node_ids(decoder, MAX_DECLARED_NODES_PER_TX)?;
        let declared_writes = decode_bounded_node_ids(decoder, MAX_DECLARED_NODES_PER_TX)?;
        let validity_range: TimestampRange = decoder.decode()?;

        // Recompute the hash from `tx_bytes` — it's content-derived and
        // must not be trusted from the wire (see Encode::encode_body).
        let mut hasher = Hasher::new();
        hasher.update(&tx_bytes);
        let hash = Hash::from_hash_bytes(hasher.finalize().as_bytes());

        let mut tx = Self {
            hash,
            transaction,
            declared_reads,
            declared_writes,
            validity_range,
            serialized_bytes: tx_bytes,
            validated: OnceLock::new(),
            cached_sbor: None,
        };
        tx.populate_cached_sbor();
        Ok(tx)
    }
}

impl Categorize<NoCustomValueKind> for RoutableTransaction {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for RoutableTransaction {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("RoutableTransaction", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, VecEncoder, basic_decode,
        basic_encode,
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
        // Hand-roll a 4-field payload where field 0 (tx_bytes) is the real
        // tx, and confirm the decoded hash matches blake3(tx_bytes) — i.e.
        // there is no wire field a peer could populate to spoof the hash.
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
        // exceeds MAX_TX_BYTES_LEN. The decoder must error before the
        // SBOR fast path attempts a Vec::with_capacity(huge_len).
        let mut buf = Vec::with_capacity(32);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(4).unwrap();
            // tx_bytes prefix: Array<U8> with claimed_len = MAX + 1.
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
        // cap. The cap fires before the loop attempts to consume any
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
