//! ECDSA over secp256k1 for the transaction path.
//!
//! Keys are SEC1 compressed points; signatures are compact `r || s` with
//! no recovery byte, because an envelope carries the key that verifies it
//! and nothing has to recover one.
//!
//! # Signatures are strictly low-`s`
//!
//! ECDSA admits two valid signatures per `(key, message)`: `s` and
//! `n - s`. Both would verify, and both would ride the wire — which for
//! this envelope means two encodings of one signed content, and so two
//! distinct `TxHash` values naming the same transaction. Verification
//! therefore refuses high-`s` outright rather than normalising it, and
//! signing emits the low form.
//!
//! Signing takes a prehashed message and is RFC 6979 deterministic, so a
//! fixture signed twice is the same bytes twice.

use std::pin::Pin;

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use zeroize::Zeroize;

/// A secp256k1 public key: the SEC1 compressed point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Secp256k1PublicKey(pub [u8; Self::LENGTH]);

impl Secp256k1PublicKey {
    /// Byte length of a compressed public key.
    pub(crate) const LENGTH: usize = 33;
}

/// A secp256k1 signature: compact `r || s`, low-`s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Secp256k1Signature(pub [u8; Self::LENGTH]);

impl Secp256k1Signature {
    /// Byte length of a compact signature.
    pub(crate) const LENGTH: usize = 64;
}

/// A secp256k1 signing key.
///
/// Boxed, pinned, and cleared on drop on the same terms as the ed25519
/// key: the secret has one address for its whole life, and dropping the
/// inner key is what clears it.
pub struct Secp256k1PrivateKey(Pin<Box<Option<SigningKey>>>);

impl Secp256k1PrivateKey {
    /// Byte length of a private scalar.
    pub const LENGTH: usize = 32;

    fn signing_key(&self) -> &SigningKey {
        (*self.0)
            .as_ref()
            .expect("the signing key is only cleared on drop")
    }

    /// The public key this key signs under.
    #[must_use]
    pub fn public_key(&self) -> Secp256k1PublicKey {
        let encoded = self.signing_key().verifying_key().to_sec1_point(true);
        let mut bytes = [0u8; Secp256k1PublicKey::LENGTH];
        bytes.copy_from_slice(encoded.as_bytes());
        Secp256k1PublicKey(bytes)
    }

    /// Sign a 32-byte prehashed message.
    ///
    /// # Panics
    ///
    /// If the curve's own signing fails, which it does only for a key
    /// this type cannot hold.
    #[must_use]
    pub(crate) fn sign_prehash(&self, prehash: &[u8; 32]) -> Secp256k1Signature {
        let signature: EcdsaSignature = self
            .signing_key()
            .sign_prehash(prehash)
            .expect("a 32-byte prehash is the curve's own digest width");
        Secp256k1Signature(signature.normalize_s().to_bytes().into())
    }

    /// Build a key from its 32 scalar bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` if `slice` is not exactly [`Self::LENGTH`] bytes,
    /// or is not a scalar in `[1, n)` — unlike ed25519, where every 32
    /// bytes are a key, secp256k1 has both ends to refuse.
    #[allow(clippy::result_unit_err)] // one failure mode; nothing to name
    pub fn from_bytes(slice: &[u8]) -> Result<Self, ()> {
        let key = SigningKey::from_slice(slice).map_err(|_| ())?;
        Ok(Self(Box::pin(Some(key))))
    }

    /// The key's scalar bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signing_key().to_bytes().to_vec()
    }
}

impl Zeroize for Secp256k1PrivateKey {
    fn zeroize(&mut self) {
        *self.0 = None;
    }
}

impl Drop for Secp256k1PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Whether `signature` is `public_key`'s signature over the 32-byte
/// `prehash`.
///
/// A malformed key, a point off the curve, an uncompressed encoding, and
/// a high-`s` signature are all refusals rather than panics, so
/// peer-supplied bytes reach this directly.
#[must_use]
pub fn verify_secp256k1(
    prehash: &[u8; 32],
    public_key: &Secp256k1PublicKey,
    signature: &Secp256k1Signature,
) -> bool {
    let Ok(signature) = EcdsaSignature::from_slice(&signature.0) else {
        return false;
    };
    if signature.normalize_s() != signature {
        return false;
    }
    VerifyingKey::from_sec1_bytes(&public_key.0)
        .is_ok_and(|key| key.verify_prehash(prehash, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;

    use super::{
        EcdsaSignature, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature,
        verify_secp256k1,
    };

    fn key(seed: u8) -> Secp256k1PrivateKey {
        Secp256k1PrivateKey::from_bytes(&[seed; 32]).expect("a scalar in range")
    }

    #[test]
    fn a_signature_verifies_under_its_own_key_and_message() {
        let k = key(7);
        let sig = k.sign_prehash(&[1u8; 32]);
        assert!(verify_secp256k1(&[1u8; 32], &k.public_key(), &sig));
        assert!(!verify_secp256k1(&[2u8; 32], &k.public_key(), &sig));
        assert!(!verify_secp256k1(&[1u8; 32], &key(8).public_key(), &sig));
    }

    #[test]
    fn signing_is_deterministic_in_its_key_and_message() {
        assert_eq!(
            key(42).sign_prehash(&[9u8; 32]),
            key(42).sign_prehash(&[9u8; 32])
        );
        assert_ne!(key(42).public_key(), key(43).public_key());
    }

    #[test]
    fn from_bytes_refuses_what_is_not_a_scalar() {
        assert!(Secp256k1PrivateKey::from_bytes(&[1u8; 32]).is_ok());
        assert!(Secp256k1PrivateKey::from_bytes(&[0u8; 32]).is_err());
        assert!(Secp256k1PrivateKey::from_bytes(&[0u8; 31]).is_err());
        assert!(Secp256k1PrivateKey::from_bytes(&[]).is_err());
    }

    /// The high-`s` twin of a valid signature verifies under the curve
    /// but not here: two encodings of one signed content would be two
    /// transaction identities for one transaction.
    #[test]
    fn the_high_s_twin_of_a_valid_signature_refuses() {
        let k = key(5);
        let sig = k.sign_prehash(&[3u8; 32]);
        let parsed = EcdsaSignature::from_slice(&sig.0).expect("we just made it");
        let flipped = Secp256k1Signature(
            EcdsaSignature::from_scalars(*parsed.r(), -*parsed.s())
                .expect("negating s stays on the curve")
                .to_bytes()
                .into(),
        );

        assert!(verify_secp256k1(&[3u8; 32], &k.public_key(), &sig));
        assert_ne!(flipped, sig);
        assert!(!verify_secp256k1(&[3u8; 32], &k.public_key(), &flipped));
    }

    /// A key that is not a compressed point on the curve is a refusal,
    /// never a panic — the bytes arrive from a peer.
    #[test]
    fn malformed_material_refuses() {
        let k = key(1);
        let sig = k.sign_prehash(&[4u8; 32]);
        assert!(!verify_secp256k1(
            &[4u8; 32],
            &Secp256k1PublicKey([0u8; 33]),
            &sig
        ));
        assert!(!verify_secp256k1(
            &[4u8; 32],
            &k.public_key(),
            &Secp256k1Signature([0xFF; 64])
        ));
    }

    /// The public key rides the wire compressed; an uncompressed encoding
    /// is 65 bytes and has nowhere to sit.
    #[test]
    fn public_keys_are_compressed() {
        let signing = SigningKey::from_slice(&[6u8; 32]).expect("a scalar in range");
        let compressed = signing.verifying_key().to_sec1_point(true);
        assert_eq!(compressed.as_bytes().len(), Secp256k1PublicKey::LENGTH);
        assert_eq!(key(6).public_key().0, compressed.as_bytes());
    }
}
