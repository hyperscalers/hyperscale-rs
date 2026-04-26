//! Bloom filter typed by the item kind, for sync-inventory negotiation.
//!
//! The filter exists so a sync requester can tell the responder which
//! transactions / certificates / provisions it already has locally, letting
//! the responder elide those bodies from the response. All items inserted
//! are already 32-byte cryptographic hashes ([`TypedHash`]), so no hashing
//! is performed here — probes are derived directly from the item bytes via
//! Kirsch-Mitzenmacher double-hashing (same FPR as independent hashes; see
//! Kirsch & Mitzenmacher, "Less Hashing, Same Performance", 2006).
//!
//! The phantom [`T`] tags the filter with the item kind so
//! `BloomFilter<TxHash>` can't be confused with `BloomFilter<WaveIdHash>`
//! at a call site. The wire format is identical regardless of `T`.
//!
//! Sizing: callers construct via [`BloomFilter::with_capacity`] supplying
//! an item count and an FPR. The bit count is rounded up to a multiple of
//! 64 and capped at [`MAX_BITS`]; requests above the cap yield `None` so
//! the caller can fall back to sending no filter at all.
//!
//! Example:
//!
//! ```ignore
//! let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(10_000, 0.01).unwrap();
//! for h in mempool_hashes { bf.insert(&h); }
//! // ...send on the wire...
//! assert!(bf.contains(&h_known));
//! ```

use std::marker::PhantomData;

use crate::TypedHash;

/// Default target false-positive rate (1%).
pub const DEFAULT_FPR: f64 = 0.01;

/// Hard cap on filter size. At 1M bits (128 KiB) and 1% FPR the filter can
/// hold ~100k items; past that, sync skips the inventory and sends the full
/// response rather than growing the request indefinitely.
pub const MAX_BITS: usize = 1 << 20;

/// Hard cap on the number of hash probes per item. `k = 7` suffices for any
/// capacity we'd actually use (k grows as `(m/n) * ln 2`, plateauing around
/// 7 for a 1% target FPR).
pub const MAX_K: u8 = 32;

/// Typed bloom filter over items that are themselves cryptographic hashes.
///
/// Wire shape is `(Vec<u64>, u8)`. The phantom `T` is compile-time-only and
/// is not encoded.
pub struct BloomFilter<T> {
    bits: Vec<u64>,
    k: u8,
    _phantom: PhantomData<fn() -> T>,
}

impl<T> BloomFilter<T> {
    /// Construct an empty filter sized for `n` items at the requested FPR.
    /// Returns `None` if the required bit count exceeds [`MAX_BITS`].
    ///
    /// `n == 0` yields a minimal one-word filter that never matches.
    #[must_use]
    pub fn with_capacity(n: usize, fpr: f64) -> Option<Self> {
        let (m_bits, k) = size_for(n, fpr)?;
        let words = m_bits.div_ceil(64);
        Some(Self {
            bits: vec![0u64; words],
            k,
            _phantom: PhantomData,
        })
    }

    /// Construct an empty filter that never matches. Wire-cheapest form;
    /// callers use this when they have nothing to declare as "already have."
    #[must_use]
    pub fn empty() -> Self {
        Self {
            bits: vec![0u64; 1],
            k: 1,
            _phantom: PhantomData,
        }
    }

    /// Number of bits in the backing array. Always a multiple of 64.
    #[must_use]
    pub const fn bit_len(&self) -> usize {
        self.bits.len() * 64
    }

    /// Number of hash probes per item.
    #[must_use]
    pub const fn k(&self) -> u8 {
        self.k
    }

    /// Whether the filter has any bits set. A freshly-constructed
    /// [`BloomFilter::empty`] or [`BloomFilter::with_capacity`] filter
    /// returns `true`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }
}

impl<T: TypedHash> BloomFilter<T> {
    /// Insert an item. Items are already cryptographic hashes; probes come
    /// straight from the item bytes with no rehashing.
    pub fn insert(&mut self, item: &T) {
        let (h1, h2) = split_hash(item);
        let m = self.bit_len() as u64;
        for i in 0..u64::from(self.k) {
            let bit = probe(h1, h2, i, m);
            let word = (bit / 64) as usize;
            let off = bit % 64;
            self.bits[word] |= 1u64 << off;
        }
    }

    /// Test membership. False negatives never occur on items that were
    /// actually inserted into *this* instance; false positives occur at the
    /// configured FPR when populated to capacity.
    pub fn contains(&self, item: &T) -> bool {
        let (h1, h2) = split_hash(item);
        let m = self.bit_len() as u64;
        for i in 0..u64::from(self.k) {
            let bit = probe(h1, h2, i, m);
            let word = (bit / 64) as usize;
            let off = bit % 64;
            if (self.bits[word] >> off) & 1 == 0 {
                return false;
            }
        }
        true
    }
}

/// Compute `(m_bits_rounded_to_64, k)` for the requested `(n, fpr)`, or
/// `None` if the computed size exceeds [`MAX_BITS`].
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)] // bloom-filter sizing math: inputs bounded by MAX_BITS / MAX_K, results clamped before truncation
fn size_for(n: usize, fpr: f64) -> Option<(usize, u8)> {
    if n == 0 {
        return Some((64, 1));
    }
    let fpr = fpr.clamp(1e-9, 0.5);
    let ln2 = std::f64::consts::LN_2;
    let m_raw = -(n as f64) * fpr.ln() / (ln2 * ln2);
    let m_words = (m_raw.ceil() as usize).div_ceil(64).max(1);
    let m_bits = m_words * 64;
    if m_bits > MAX_BITS {
        return None;
    }
    let k_raw = (m_bits as f64 / n as f64) * ln2;
    let k = (k_raw.ceil() as u32).clamp(1, u32::from(MAX_K)) as u8;
    Some((m_bits, k))
}

/// Split a 32-byte typed hash into two `u64` halves. The low 16 bytes are
/// used; the upper 16 are unused but available for future variants.
/// Bit 0 of `h2` is forced set so `i * h2` steps through every residue
/// class of `m` (avoids short probe cycles when `m` is a power of two).
fn split_hash<T: TypedHash>(item: &T) -> (u64, u64) {
    let bytes = item.as_raw().as_bytes();
    let h1 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let h2 = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) | 1;
    (h1, h2)
}

#[inline]
const fn probe(h1: u64, h2: u64, i: u64, m: u64) -> u64 {
    h1.wrapping_add(i.wrapping_mul(h2)) % m
}

// ── Trait impls ──────────────────────────────────────────────────────────────

impl<T> Clone for BloomFilter<T> {
    fn clone(&self) -> Self {
        Self {
            bits: self.bits.clone(),
            k: self.k,
            _phantom: PhantomData,
        }
    }
}

impl<T> PartialEq for BloomFilter<T> {
    fn eq(&self, other: &Self) -> bool {
        self.k == other.k && self.bits == other.bits
    }
}

impl<T> Eq for BloomFilter<T> {}

impl<T> std::fmt::Debug for BloomFilter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BloomFilter")
            .field("bits", &format_args!("<{} bits>", self.bit_len()))
            .field("k", &self.k)
            .finish()
    }
}

// ── SBOR: encode as `(Vec<u64>, u8)`; phantom is not serialized. ─────────────

impl<T, E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for BloomFilter<T>
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(&self.bits)?;
        encoder.encode(&self.k)?;
        Ok(())
    }
}

impl<T, D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for BloomFilter<T>
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }
        let bits: Vec<u64> = decoder.decode()?;
        let k: u8 = decoder.decode()?;
        Ok(Self {
            bits,
            k,
            _phantom: PhantomData,
        })
    }
}

impl<T> sbor::Categorize<sbor::NoCustomValueKind> for BloomFilter<T> {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl<T> sbor::Describe<sbor::NoCustomTypeKind> for BloomFilter<T> {
    const TYPE_ID: sbor::RustTypeId = sbor::RustTypeId::novel_with_code("BloomFilter", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash, TxHash, WaveIdHash};
    use sbor::{basic_decode, basic_encode};

    fn tx(n: u64) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(&n.to_le_bytes()))
    }

    #[test]
    fn empty_filter_matches_nothing() {
        let bf: BloomFilter<TxHash> = BloomFilter::empty();
        for i in 0..1000 {
            assert!(!bf.contains(&tx(i)));
        }
        assert!(bf.is_empty());
    }

    #[test]
    fn insert_contains_roundtrip() {
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(1_000, 0.01).unwrap();
        for i in 0..1_000 {
            bf.insert(&tx(i));
        }
        for i in 0..1_000 {
            assert!(bf.contains(&tx(i)), "inserted item {i} not found");
        }
    }

    #[test]
    fn fpr_at_capacity_is_near_target() {
        let n = 5_000;
        let target_fpr = 0.01;
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(n, target_fpr).unwrap();
        for i in 0..n as u64 {
            bf.insert(&tx(i));
        }
        let probe_count = 20_000u64;
        let mut false_positives = 0u64;
        for i in (n as u64)..(n as u64 + probe_count) {
            if bf.contains(&tx(i)) {
                false_positives += 1;
            }
        }
        // headline ratio for human-readable test output; precision loss is fine.
        #[allow(clippy::cast_precision_loss)]
        let observed = false_positives as f64 / probe_count as f64;
        assert!(
            observed < target_fpr * 3.0,
            "observed FPR {observed} >> target {target_fpr} (fp={false_positives}/{probe_count})"
        );
    }

    #[test]
    fn sizing_caps_at_max_bits() {
        assert!(BloomFilter::<TxHash>::with_capacity(200_000, 0.01).is_none());
    }

    #[test]
    fn zero_capacity_yields_minimal_filter() {
        let bf: BloomFilter<TxHash> = BloomFilter::with_capacity(0, 0.01).unwrap();
        assert_eq!(bf.bit_len(), 64);
        assert!(!bf.contains(&tx(1)));
    }

    #[test]
    fn sbor_roundtrip_preserves_bits() {
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(100, 0.01).unwrap();
        for i in 0..50 {
            bf.insert(&tx(i));
        }
        let bytes = basic_encode(&bf).unwrap();
        let decoded: BloomFilter<TxHash> = basic_decode(&bytes).unwrap();
        assert_eq!(bf, decoded);
        for i in 0..50 {
            assert!(decoded.contains(&tx(i)));
        }
    }

    #[test]
    fn phantom_tag_is_compile_time_only() {
        // Same wire bytes regardless of tag; the tag is a source-level label.
        let bf_tx: BloomFilter<TxHash> = BloomFilter::empty();
        let bytes_tx = basic_encode(&bf_tx).unwrap();
        let bf_wave: BloomFilter<WaveIdHash> = BloomFilter::empty();
        let bytes_wave = basic_encode(&bf_wave).unwrap();
        assert_eq!(bytes_tx, bytes_wave);
    }
}
