//! `RoutableTransaction` — wraps a Radix `UserTransaction` with shard-routing metadata.

use crate::{Hash, NodeId, TimestampRange, TxHash};
use radix_common::data::manifest::{manifest_decode, manifest_encode};
use radix_transactions::model::{UserTransaction, ValidatedUserTransaction};
use radix_transactions::validation::TransactionValidator;
use sbor::prelude::*;
use std::sync::OnceLock;

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
impl std::fmt::Debug for RoutableTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        let mut hasher = blake3::Hasher::new();
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
    pub fn hash(&self) -> TxHash {
        TxHash::from_raw(self.hash)
    }

    /// Get a reference to the underlying Radix transaction.
    pub fn transaction(&self) -> &UserTransaction {
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
        self.cached_sbor = Some(sbor::basic_encode(self).expect("RoutableTransaction SBOR encode"));
    }

    /// Check if this transaction is cross-shard for the given number of shards.
    pub fn is_cross_shard(&self, num_shards: u64) -> bool {
        if self.declared_writes.is_empty() {
            return false;
        }

        let first_shard = crate::shard_for_node(&self.declared_writes[0], num_shards);
        self.declared_writes
            .iter()
            .skip(1)
            .any(|node| crate::shard_for_node(node, num_shards) != first_shard)
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

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for RoutableTransaction
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(5)?; // 5 fields

        // Encode hash as [u8; 32]
        let hash_bytes: [u8; 32] = *self.hash.as_bytes();
        encoder.encode(&hash_bytes)?;

        // Encode transaction as bytes (using cached serialized_bytes)
        encoder.encode(&self.serialized_bytes)?;

        // Encode declared_reads
        encoder.encode(&self.declared_reads)?;

        // Encode declared_writes
        encoder.encode(&self.declared_writes)?;

        // Encode validity_range
        encoder.encode(&self.validity_range)?;

        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for RoutableTransaction
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 5 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 5,
                actual: length,
            });
        }

        // Decode hash (stored as [u8; 32])
        let hash_bytes: [u8; 32] = decoder.decode()?;
        let hash = Hash::from_hash_bytes(&hash_bytes);

        // Decode transaction bytes and convert to UserTransaction
        let tx_bytes: Vec<u8> = decoder.decode()?;
        let transaction: UserTransaction =
            manifest_decode(&tx_bytes).map_err(|_| sbor::DecodeError::InvalidCustomValue)?;

        // Decode declared_reads
        let declared_reads: Vec<NodeId> = decoder.decode()?;

        // Decode declared_writes
        let declared_writes: Vec<NodeId> = decoder.decode()?;

        // Decode validity_range
        let validity_range: TimestampRange = decoder.decode()?;

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

impl sbor::Categorize<sbor::NoCustomValueKind> for RoutableTransaction {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for RoutableTransaction {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("RoutableTransaction", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}
