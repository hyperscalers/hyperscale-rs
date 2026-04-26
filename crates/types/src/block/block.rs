//! [`Block`] enum (Live/Sealed) plus its manual SBOR encoding.

use crate::{
    BlockHash, BlockHeader, BlockHeight, FinalizedWave, Provisions, RoutableTransaction,
    ShardGroupId, StateRoot, TxHash, ValidatorId, decode_finalized_wave_vec,
    encode_finalized_wave_vec,
};
use sbor::prelude::*;
use std::sync::Arc;

/// Complete block with header and transaction data.
///
/// Transactions are stored in a single flat list, sorted by hash for deterministic ordering.
///
/// Blocks have two variants reflecting their temporal lifecycle:
/// - **`Live`**: within the cross-shard execution window. Carries the
///   provisions needed to execute cross-shard waves locally.
/// - **`Sealed`**: past the execution window (at least `WAVE_TIMEOUT` of
///   wall-clock behind the local committed tip). Waves are finalized from
///   certs + receipts alone, so provisions are no longer needed and are
///   dropped from memory. The on-disk / storage shape is always `Sealed`.
///
/// The header's `provision_root` commits to the original provision set, so
/// `Sealed` is self-consistent — a `Live` block matches its `Sealed` form
/// modulo the provision payload.
#[derive(Debug, Clone)]
pub enum Block {
    /// Block within its cross-shard execution window — carries provisions.
    Live {
        /// Block header (contains all merkle roots).
        header: BlockHeader,
        /// Transactions in this block, sorted by hash.
        transactions: Vec<Arc<RoutableTransaction>>,
        /// Wave certificates finalized in this block.
        certificates: Vec<Arc<FinalizedWave>>,
        /// Provisions needed to execute cross-shard waves locally.
        provisions: Vec<Arc<Provisions>>,
    },
    /// Block past its execution window — provisions dropped.
    Sealed {
        /// Block header (contains all merkle roots).
        header: BlockHeader,
        /// Transactions in this block, sorted by hash.
        transactions: Vec<Arc<RoutableTransaction>>,
        /// Wave certificates finalized in this block.
        certificates: Vec<Arc<FinalizedWave>>,
    },
}

// Manual PartialEq - compare transaction/certificate content, not Arc pointers.
// Provisions are excluded from equality: the header's `provision_root` already
// commits to them, and a Live and Sealed form of the same block should compare
// equal for content purposes.
impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        fn tx_lists_equal(a: &[Arc<RoutableTransaction>], b: &[Arc<RoutableTransaction>]) -> bool {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.hash() == y.hash())
        }
        fn cert_lists_equal(a: &[Arc<FinalizedWave>], b: &[Arc<FinalizedWave>]) -> bool {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(x, y)| x.as_ref() == y.as_ref())
        }

        self.header() == other.header()
            && tx_lists_equal(self.transactions(), other.transactions())
            && cert_lists_equal(self.certificates(), other.certificates())
    }
}

impl Eq for Block {}

// ============================================================================
// Manual SBOR implementation (since Arc doesn't derive BasicSbor)
// We serialize/deserialize the inner types directly.
// ============================================================================

/// Helper to encode a Vec<Arc<RoutableTransaction>> as an SBOR array.
fn encode_tx_vec<E: sbor::Encoder<sbor::NoCustomValueKind>>(
    encoder: &mut E,
    txs: &[Arc<RoutableTransaction>],
) -> Result<(), sbor::EncodeError> {
    encoder.write_value_kind(sbor::ValueKind::Array)?;
    encoder.write_value_kind(sbor::ValueKind::Tuple)?;
    encoder.write_size(txs.len())?;
    for tx in txs {
        encoder.encode_deeper_body(tx.as_ref())?;
    }
    Ok(())
}

/// Helper to encode a Vec<Arc<Provision>> as an SBOR array. Mirrors the
/// transaction / finalized-wave helpers.
fn encode_provision_vec<E: sbor::Encoder<sbor::NoCustomValueKind>>(
    encoder: &mut E,
    provisions: &[Arc<Provisions>],
) -> Result<(), sbor::EncodeError> {
    encoder.write_value_kind(sbor::ValueKind::Array)?;
    encoder.write_value_kind(sbor::ValueKind::Tuple)?;
    encoder.write_size(provisions.len())?;
    for p in provisions {
        encoder.encode_deeper_body(p.as_ref())?;
    }
    Ok(())
}

// Variant tag bytes for SBOR encoding. Explicit rather than relying on
// derive so future additions don't renumber existing variants silently.
const BLOCK_VARIANT_LIVE: u8 = 0;
const BLOCK_VARIANT_SEALED: u8 = 1;

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E> for Block {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Enum)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        match self {
            Self::Live {
                header,
                transactions,
                certificates,
                provisions,
            } => {
                encoder.write_discriminator(BLOCK_VARIANT_LIVE)?;
                encoder.write_size(4)?;
                encoder.encode(header)?;
                encode_tx_vec(encoder, transactions)?;
                encode_finalized_wave_vec(encoder, certificates)?;
                encode_provision_vec(encoder, provisions)?;
            }
            Self::Sealed {
                header,
                transactions,
                certificates,
            } => {
                encoder.write_discriminator(BLOCK_VARIANT_SEALED)?;
                encoder.write_size(3)?;
                encoder.encode(header)?;
                encode_tx_vec(encoder, transactions)?;
                encode_finalized_wave_vec(encoder, certificates)?;
            }
        }
        Ok(())
    }
}

/// Maximum items in a single collection during SBOR decoding.
///
/// Prevents allocation bombs where a crafted SBOR payload claims millions of
/// items, causing multi-GB `Vec::with_capacity()` pre-allocations. This limit
/// is generous enough for any legitimate block content while blocking malicious
/// payloads. Applied to transaction arrays, certificate arrays, and commitment
/// proof maps.
const MAX_SBOR_COLLECTION_SIZE: usize = 10_000;

/// Helper to decode a Vec<Arc<RoutableTransaction>> from an SBOR array.
fn decode_tx_vec<D: sbor::Decoder<sbor::NoCustomValueKind>>(
    decoder: &mut D,
) -> Result<Vec<Arc<RoutableTransaction>>, sbor::DecodeError> {
    decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
    decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
    let count = decoder.read_size()?;
    if count > MAX_SBOR_COLLECTION_SIZE {
        return Err(sbor::DecodeError::UnexpectedSize {
            expected: MAX_SBOR_COLLECTION_SIZE,
            actual: count,
        });
    }
    let mut txs = Vec::with_capacity(count);
    for _ in 0..count {
        let tx: RoutableTransaction =
            decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
        txs.push(Arc::new(tx));
    }
    Ok(txs)
}

/// Helper to decode a Vec<Arc<Provision>> from an SBOR array.
fn decode_provision_vec<D: sbor::Decoder<sbor::NoCustomValueKind>>(
    decoder: &mut D,
) -> Result<Vec<Arc<Provisions>>, sbor::DecodeError> {
    decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
    decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
    let count = decoder.read_size()?;
    if count > MAX_SBOR_COLLECTION_SIZE {
        return Err(sbor::DecodeError::UnexpectedSize {
            expected: MAX_SBOR_COLLECTION_SIZE,
            actual: count,
        });
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let p: Provisions = decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
        out.push(Arc::new(p));
    }
    Ok(out)
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D> for Block {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Enum)?;
        let discriminator = decoder.read_discriminator()?;
        let length = decoder.read_size()?;

        match discriminator {
            BLOCK_VARIANT_LIVE => {
                if length != 4 {
                    return Err(sbor::DecodeError::UnexpectedSize {
                        expected: 4,
                        actual: length,
                    });
                }
                let header: BlockHeader = decoder.decode()?;
                let transactions = decode_tx_vec(decoder)?;
                let certificates = decode_finalized_wave_vec(decoder, MAX_SBOR_COLLECTION_SIZE)?;
                let provisions = decode_provision_vec(decoder)?;
                Ok(Self::Live {
                    header,
                    transactions,
                    certificates,
                    provisions,
                })
            }
            BLOCK_VARIANT_SEALED => {
                if length != 3 {
                    return Err(sbor::DecodeError::UnexpectedSize {
                        expected: 3,
                        actual: length,
                    });
                }
                let header: BlockHeader = decoder.decode()?;
                let transactions = decode_tx_vec(decoder)?;
                let certificates = decode_finalized_wave_vec(decoder, MAX_SBOR_COLLECTION_SIZE)?;
                Ok(Self::Sealed {
                    header,
                    transactions,
                    certificates,
                })
            }
            other => Err(sbor::DecodeError::UnknownDiscriminator(other)),
        }
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for Block {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Enum
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for Block {
    const TYPE_ID: sbor::RustTypeId = sbor::RustTypeId::novel_with_code("Block", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

impl Block {
    /// Create an empty genesis block with the given proposer and JMT state.
    ///
    /// Genesis is born `Live` with no provisions — the temporality machinery
    /// activates only once there are cross-shard waves in flight.
    #[must_use]
    pub fn genesis(
        shard_group_id: ShardGroupId,
        proposer: ValidatorId,
        state_root: StateRoot,
    ) -> Self {
        Self::Live {
            header: BlockHeader::genesis(shard_group_id, proposer, state_root),
            transactions: vec![],
            certificates: vec![],
            provisions: vec![],
        }
    }

    /// Block header — present in both variants.
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        match self {
            Self::Live { header, .. } | Self::Sealed { header, .. } => header,
        }
    }

    /// Transactions in the block — present in both variants.
    #[must_use]
    pub fn transactions(&self) -> &[Arc<RoutableTransaction>] {
        match self {
            Self::Live { transactions, .. } | Self::Sealed { transactions, .. } => transactions,
        }
    }

    /// Finalized waves (certificates) in the block — present in both variants.
    #[must_use]
    pub fn certificates(&self) -> &[Arc<FinalizedWave>] {
        match self {
            Self::Live { certificates, .. } | Self::Sealed { certificates, .. } => certificates,
        }
    }

    /// Provisions. Non-empty only for `Live`; `Sealed` blocks have
    /// dropped their provisions because the cross-shard execution window
    /// they served has passed. Use `is_live()` when the variant itself
    /// matters — this accessor flattens both cases to a slice.
    #[must_use]
    pub fn provisions(&self) -> &[Arc<Provisions>] {
        match self {
            Self::Live { provisions, .. } => provisions,
            Self::Sealed { .. } => &[],
        }
    }

    /// True if this block is still in its `Live` variant.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Live { .. })
    }

    /// Convert to `Sealed` by dropping provisions. Identity on an already-
    /// sealed block. This is the canonical persisted shape; sync-serving
    /// glue re-attaches provisions (via `into_live`) when the requester
    /// needs them.
    #[must_use]
    pub fn into_sealed(self) -> Self {
        match self {
            Self::Live {
                header,
                transactions,
                certificates,
                ..
            } => Self::Sealed {
                header,
                transactions,
                certificates,
            },
            sealed @ Self::Sealed { .. } => sealed,
        }
    }

    /// Attach provisions, promoting `Sealed` → `Live`. Used by sync-serving
    /// to upgrade a persisted block when the requester is still inside the
    /// cross-shard execution window.
    ///
    /// # Panics
    ///
    /// Panics if invoked on a `Live` block — that would silently discard
    /// the existing provision set.
    #[must_use]
    pub fn into_live(self, provisions: Vec<Arc<Provisions>>) -> Self {
        match self {
            Self::Sealed {
                header,
                transactions,
                certificates,
            } => Self::Live {
                header,
                transactions,
                certificates,
                provisions,
            },
            Self::Live { .. } => {
                panic!("into_live called on an already-Live block")
            }
        }
    }

    /// Compute hash of this block (hashes the header).
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        self.header().hash()
    }

    /// Get block height.
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.header().height
    }

    /// Get total number of transactions.
    #[must_use]
    pub fn transaction_count(&self) -> usize {
        self.transactions().len()
    }

    /// Check if this block contains a specific transaction by hash.
    #[must_use]
    pub fn contains_transaction(&self, tx_hash: &TxHash) -> bool {
        self.transactions().iter().any(|tx| tx.hash() == *tx_hash)
    }

    /// Get all transaction hashes.
    #[must_use]
    pub fn transaction_hashes(&self) -> Vec<TxHash> {
        self.transactions().iter().map(|tx| tx.hash()).collect()
    }

    /// Check if this is the genesis block.
    #[must_use]
    pub const fn is_genesis(&self) -> bool {
        self.header().is_genesis()
    }

    /// Get number of wave certificates in this block.
    #[must_use]
    pub fn certificate_count(&self) -> usize {
        self.certificates().len()
    }
}
