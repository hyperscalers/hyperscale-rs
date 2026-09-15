//! Ed25519 over the transaction path.
//!
//! Plain RFC 8032 Ed25519 (SHA-512, no pre-hash) over the whole signed
//! message. Verification is `verify_strict`: it rejects small-order
//! public keys and non-canonical encodings, so a signature is valid
//! under exactly one key and cannot be made to verify under a cofactor
//! variant.
//!
//! The signing key is pinned and zeroed on drop, so moving the value
//! cannot leave a copy of the secret behind.

use std::pin::Pin;

use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroize;

/// An Ed25519 public key: the compressed Edwards point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ed25519PublicKey(pub [u8; Self::LENGTH]);

impl Ed25519PublicKey {
    /// Byte length of a public key.
    pub(crate) const LENGTH: usize = 32;
}

/// An Ed25519 signature: `R || s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519Signature(pub [u8; Self::LENGTH]);

impl Ed25519Signature {
    /// Byte length of a signature.
    pub(crate) const LENGTH: usize = 64;
}

/// An Ed25519 signing key.
///
/// Boxed and pinned so the secret has one fixed address for its whole
/// life, and zeroed on drop. The inner `Option` is what makes zeroing
/// possible: `SigningKey` holds a verifying key that is not itself
/// zeroizable, so the secret is cleared by dropping the whole key rather
/// than by scrubbing it in place.
pub struct Ed25519PrivateKey(Pin<Box<Option<SigningKey>>>);

impl Ed25519PrivateKey {
    /// Byte length of a private key seed.
    pub(crate) const LENGTH: usize = 32;

    fn signing_key(&self) -> &SigningKey {
        (*self.0)
            .as_ref()
            .expect("the signing key is only cleared on drop")
    }

    /// The public key this key signs under.
    #[must_use]
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.signing_key().verifying_key().to_bytes())
    }

    /// Sign `msg`.
    #[must_use]
    pub(crate) fn sign(&self, msg: impl AsRef<[u8]>) -> Ed25519Signature {
        Ed25519Signature(self.signing_key().sign(msg.as_ref()).to_bytes())
    }

    /// The key's seed bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signing_key().to_bytes().to_vec()
    }

    /// Build a key from its 32 seed bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` if `slice` is not exactly [`Self::LENGTH`] bytes.
    /// Every 32-byte string is a valid seed, so length is the only failure.
    #[allow(clippy::result_unit_err)] // one failure mode; nothing to name
    pub fn from_bytes(slice: &[u8]) -> Result<Self, ()> {
        let seed: [u8; Self::LENGTH] = slice.try_into().map_err(|_| ())?;
        Ok(Self(Box::pin(Some(SigningKey::from_bytes(&seed)))))
    }
}

impl Zeroize for Ed25519PrivateKey {
    fn zeroize(&mut self) {
        *self.0 = None;
    }
}

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Whether `signature` is `public_key`'s signature over `message`.
///
/// Strict verification: a malformed key or signature is a refusal, never
/// a panic, so peer-supplied bytes reach this directly.
#[must_use]
pub fn verify_ed25519(
    message: impl AsRef<[u8]>,
    public_key: &Ed25519PublicKey,
    signature: &Ed25519Signature,
) -> bool {
    let sig = DalekSignature::from_bytes(&signature.0);
    VerifyingKey::from_bytes(&public_key.0)
        .is_ok_and(|key| key.verify_strict(message.as_ref(), &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> Ed25519PrivateKey {
        Ed25519PrivateKey::from_bytes(&[seed; 32]).expect("32 bytes")
    }

    #[test]
    fn a_signature_verifies_under_its_own_key_and_message() {
        let k = key(7);
        let sig = k.sign(b"message");
        assert!(verify_ed25519(b"message", &k.public_key(), &sig));
        assert!(!verify_ed25519(b"other", &k.public_key(), &sig));
        assert!(!verify_ed25519(b"message", &key(8).public_key(), &sig));
    }

    #[test]
    fn keys_are_deterministic_in_their_seed() {
        assert_eq!(key(42).public_key(), key(42).public_key());
        assert_eq!(key(42).sign(b"m"), key(42).sign(b"m"));
        assert_ne!(key(42).public_key(), key(43).public_key());
    }

    #[test]
    fn from_bytes_takes_exactly_the_seed_length() {
        assert!(Ed25519PrivateKey::from_bytes(&[0u8; 32]).is_ok());
        assert!(Ed25519PrivateKey::from_bytes(&[0u8; 31]).is_err());
        assert!(Ed25519PrivateKey::from_bytes(&[0u8; 33]).is_err());
        assert!(Ed25519PrivateKey::from_bytes(&[]).is_err());
    }

    /// Peer-supplied bytes reach verification directly, so a malformed
    /// key or signature must refuse rather than panic.
    #[test]
    fn malformed_inputs_refuse() {
        let k = key(1);
        let sig = k.sign(b"m");
        // An all-zero key is not a valid compressed point.
        assert!(!verify_ed25519(b"m", &Ed25519PublicKey([0u8; 32]), &sig));
        assert!(!verify_ed25519(
            b"m",
            &k.public_key(),
            &Ed25519Signature([0xFF; 64])
        ));
    }
}
