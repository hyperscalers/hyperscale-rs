//! Bloom filter typed by the item kind, for sync-inventory negotiation.
//!
//! The filter exists so a sync requester can tell the responder which
//! transactions / certificates / provisions it already has locally, letting
//! the responder elide those bodies from the response. Each item produces a
//! 16-byte seed via the [`BloomKey`] trait — for [`TypedHash`] items the
//! seed is the first 16 bytes of the hash (free); a structured id would
//! derive one from its identity hash. Probes use Kirsch-Mitzenmacher
//! double-hashing (same FPR as independent hashes; see Kirsch &
//! Mitzenmacher, "Less Hashing, Same Performance", 2006).
//!
//! The phantom [`T`] tags the filter with the item kind so
//! `BloomFilter<TxHash>` can't be confused with
//! `BloomFilter<ProvisionHash>` at a call site. The wire format is
//! identical regardless of `T`.
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

use std::f64::consts::LN_2;
use std::fmt;
use std::marker::PhantomData;

use hyperscale_hbor::error::{DecodeError as HborDecodeError, EncodeError as HborEncodeError};
use hyperscale_hbor::{
    Decoder as HborDecoder, Encoder as HborEncoder, HborDecode, HborEncode, HborWidth, Sink,
};

use crate::TypedHash;

/// Seed source for [`BloomFilter`] entries. Produces the 16-byte seed that
/// double-hashing splits into the two `u64`s used to derive bit probes.
///
/// For [`TypedHash`] items the seed is the first 16 bytes of the underlying
/// 32-byte hash — free, since the bytes are already a cryptographic hash.
/// A structured identifier would implement this by hashing its own
/// encoding down to a seed.
pub trait BloomKey {
    /// Return the 16-byte seed used to derive the filter's bit probes.
    fn bloom_seed(&self) -> [u8; 16];
}

impl<T: TypedHash> BloomKey for T {
    fn bloom_seed(&self) -> [u8; 16] {
        let raw = self.as_raw();
        let mut out = [0u8; 16];
        out.copy_from_slice(&raw.as_bytes()[0..16]);
        out
    }
}

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
    pub(crate) const fn bit_len(&self) -> usize {
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

impl<T: BloomKey> BloomFilter<T> {
    /// Insert an item. The item's [`BloomKey::bloom_seed`] supplies the
    /// 16-byte material the probes are derived from.
    pub fn insert(&mut self, item: &T) {
        let (h1, h2) = split_seed(&item.bloom_seed());
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
        let (h1, h2) = split_seed(&item.bloom_seed());
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
    let m_raw = -(n as f64) * fpr.ln() / (LN_2 * LN_2);
    let m_words = (m_raw.ceil() as usize).div_ceil(64).max(1);
    let m_bits = m_words * 64;
    if m_bits > MAX_BITS {
        return None;
    }
    let k_raw = (m_bits as f64 / n as f64) * LN_2;
    let k = (k_raw.ceil() as u32).clamp(1, u32::from(MAX_K)) as u8;
    Some((m_bits, k))
}

/// Split a 16-byte seed into two `u64` halves used by double-hashing.
/// Bit 0 of `h2` is forced set so `i * h2` steps through every residue
/// class of `m` (avoids short probe cycles when `m` is a power of two).
fn split_seed(seed: &[u8; 16]) -> (u64, u64) {
    let h1 = u64::from_le_bytes(seed[0..8].try_into().unwrap());
    let h2 = u64::from_le_bytes(seed[8..16].try_into().unwrap()) | 1;
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

impl<T> fmt::Debug for BloomFilter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BloomFilter")
            .field("bits", &format_args!("<{} bits>", self.bit_len()))
            .field("k", &self.k)
            .finish()
    }
}

// ── Wire codec: encode as `(Vec<u64>, u8)`; phantom is not serialized. ─────────────

// Manual codec — the decode-side sanity bounds don't fit a derive, and
// every one is reachable from a single peer over `block.request`:
// bits.len() == 0 lets `probe(...) % m` divide by zero in contains/insert;
// bits.len() > MAX_BITS/64 lets a peer push a ~128 KiB filter past our own
// outbound cap; k == 0 makes contains() vacuously true (peer claims to have
// everything); k > MAX_K lets a peer multiply per-item probe work.

impl<T> HborWidth for BloomFilter<T> {
    const MIN_ENCODED_LEN: usize = 1 + 1;
}

impl<T> HborEncode for BloomFilter<T> {
    fn encode<S: Sink>(&self, encoder: &mut HborEncoder<S>) -> Result<(), HborEncodeError> {
        encoder.nested(&self.bits)?;
        encoder.nested(&self.k)
    }
}

impl<T> HborDecode for BloomFilter<T> {
    fn decode(decoder: &mut HborDecoder<'_>) -> Result<Self, HborDecodeError> {
        let bits: Vec<u64> = decoder.nested()?;
        let k: u8 = decoder.nested()?;
        if bits.is_empty() || bits.len() > MAX_BITS / 64 {
            return Err(HborDecodeError::FailedValidation(
                "filter bits empty or past the size cap",
            ));
        }
        if k == 0 || k > MAX_K {
            return Err(HborDecodeError::FailedValidation(
                "probe count zero or past the cap",
            ));
        }
        Ok(Self {
            bits,
            k,
            _phantom: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        DecodeError, Hbor, from_slice as hbor_from_slice, to_vec as hbor_to_vec,
    };

    use super::*;
    use crate::{Hash, ProvisionHash, TxHash};

    fn tx(n: u64) -> TxHash {
        TxHash::from(Hash::from_bytes(&n.to_le_bytes()))
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
    fn hbor_roundtrip_preserves_bits() {
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(100, 0.01).unwrap();
        for i in 0..50 {
            bf.insert(&tx(i));
        }
        let bytes = hbor_to_vec(&bf).unwrap();
        let decoded: BloomFilter<TxHash> = hbor_from_slice(&bytes).unwrap();
        assert_eq!(bf, decoded);
        for i in 0..50 {
            assert!(decoded.contains(&tx(i)));
        }
    }

    #[test]
    fn phantom_tag_is_compile_time_only() {
        // Same wire bytes regardless of tag; the tag is a source-level label.
        let bf_tx: BloomFilter<TxHash> = BloomFilter::empty();
        let bytes_tx = hbor_to_vec(&bf_tx).unwrap();
        let bf_prov: BloomFilter<ProvisionHash> = BloomFilter::empty();
        let bytes_prov = hbor_to_vec(&bf_prov).unwrap();
        assert_eq!(bytes_tx, bytes_prov);
    }

    /// Mirror of the `BloomFilter` wire layout, used to forge payloads
    /// that the production decoder must reject. The derive emits the
    /// same `(Vec<u64>, u8)` tuple shape as the manual codec.
    #[derive(Hbor)]
    struct ManualBloom {
        bits: Vec<u64>,
        k: u8,
    }

    #[test]
    fn decode_rejects_empty_bits() {
        // The exact divide-by-zero attack: bits.len() == 0 makes
        // `probe(...) % m` divide by zero in contains/insert.
        let attacker = ManualBloom {
            bits: Vec::new(),
            k: 1,
        };
        let bytes = hbor_to_vec(&attacker).unwrap();
        assert!(matches!(
            hbor_from_slice::<BloomFilter<TxHash>>(&bytes),
            Err(DecodeError::FailedValidation(_)),
        ));
    }

    #[test]
    fn decode_rejects_oversized_bits() {
        // Above-cap bits would let a peer push a >128 KiB filter past
        // our own outbound MAX_BITS gate.
        let attacker = ManualBloom {
            bits: vec![0u64; (MAX_BITS / 64) + 1],
            k: 1,
        };
        let bytes = hbor_to_vec(&attacker).unwrap();
        assert!(matches!(
            hbor_from_slice::<BloomFilter<TxHash>>(&bytes),
            Err(DecodeError::FailedValidation(_)),
        ));
    }

    #[test]
    fn decode_rejects_zero_k() {
        // k == 0 makes contains() vacuously true for every probe,
        // letting a peer claim to already have every item.
        let attacker = ManualBloom {
            bits: vec![0u64; 1],
            k: 0,
        };
        let bytes = hbor_to_vec(&attacker).unwrap();
        assert!(matches!(
            hbor_from_slice::<BloomFilter<TxHash>>(&bytes),
            Err(DecodeError::FailedValidation(_)),
        ));
    }

    #[test]
    fn decode_rejects_oversized_k() {
        // k > MAX_K multiplies per-item probe work without bound.
        let attacker = ManualBloom {
            bits: vec![0u64; 1],
            k: MAX_K + 1,
        };
        let bytes = hbor_to_vec(&attacker).unwrap();
        assert!(matches!(
            hbor_from_slice::<BloomFilter<TxHash>>(&bytes),
            Err(DecodeError::FailedValidation(_)),
        ));
    }
}
