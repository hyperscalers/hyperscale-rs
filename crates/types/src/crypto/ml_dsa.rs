//! ML-DSA-65 over the transaction path.
//!
//! Pure ML-DSA as FIPS 204 defines it, under the empty context string and
//! never the pre-hash variant: what this path presents is already a
//! digest, and a scheme that hashed it again would leave two preimages
//! behind one signature.
//!
//! Signing is the standard's deterministic variant, so a key and a
//! message name exactly one signature. That is a property of this signer
//! rather than of the scheme — a hedged signature verifies here too, and
//! must, because refusing one would make validity depend on how a wallet
//! chose its randomness.
//!
//! Unlike the curve schemes there are no fixed-size newtypes for the
//! material. A key and a signature are kilobytes, and wrapping them in
//! `Copy` arrays would put multi-kilobyte moves behind ordinary-looking
//! assignments for no gain: the widths are the registry's to enforce and
//! the encodings are FIPS 204's to validate. The functions here take
//! slices and check the widths themselves, so peer-supplied bytes reach
//! them directly.
//!
//! The signing key is pinned and zeroed on drop, so moving the value
//! cannot leave a copy of the secret behind.

use std::pin::Pin;

use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Seed, Signature, SigningKey, VerifyingKey,
};
use zeroize::Zeroize;

/// An ML-DSA-65 signing key.
///
/// Boxed and pinned so the secret has one fixed address for its whole
/// life, and zeroed on drop by dropping the key rather than scrubbing it
/// in place, on the same terms as the curve keys beside it.
pub struct MlDsa65PrivateKey(Pin<Box<Option<SigningKey<MlDsa65>>>>);

impl MlDsa65PrivateKey {
    /// Byte length of a private key seed.
    ///
    /// The seed is the whole secret: FIPS 204 derives the expanded
    /// signing key from it, and every parameter set seeds from the same
    /// 32 bytes.
    pub(crate) const LENGTH: usize = 32;

    fn signing_key(&self) -> &SigningKey<MlDsa65> {
        (*self.0)
            .as_ref()
            .expect("the signing key is only cleared on drop")
    }

    /// The public key this key signs under, in `pkEncode` form.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.signing_key().verifying_key().encode().to_vec()
    }

    /// Sign `msg`, yielding a signature in `sigEncode` form.
    #[must_use]
    pub(crate) fn sign(&self, msg: impl AsRef<[u8]>) -> Vec<u8> {
        let signature: Signature<MlDsa65> = self.signing_key().sign(msg.as_ref());
        signature.encode().to_vec()
    }

    /// The key's seed bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signing_key().to_seed().to_vec()
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
        let key = SigningKey::<MlDsa65>::from_seed(&Seed::from(seed));
        Ok(Self(Box::pin(Some(key))))
    }
}

impl Zeroize for MlDsa65PrivateKey {
    fn zeroize(&mut self) {
        *self.0 = None;
    }
}

impl Drop for MlDsa65PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Whether `signature` is `public_key`'s ML-DSA-65 signature over
/// `message`.
///
/// Material of the wrong width, a signature whose encoding FIPS 204 does
/// not admit, and a well-formed signature over another message are all
/// the same refusal. A public key of the right width always decodes —
/// `pkDecode` is total — so a key that stands for no honest keypair
/// refuses at the verification equation rather than at the encoding.
#[must_use]
pub fn verify_ml_dsa_65(message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (
        EncodedVerifyingKey::<MlDsa65>::try_from(public_key),
        EncodedSignature::<MlDsa65>::try_from(signature),
    ) else {
        return false;
    };
    let Some(sig) = Signature::<MlDsa65>::decode(&sig) else {
        return false;
    };
    VerifyingKey::<MlDsa65>::decode(&key).verify_with_context(message, &[], &sig)
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::{SchemeId, SchemeSpec};

    use super::*;

    fn key(seed: u8) -> MlDsa65PrivateKey {
        MlDsa65PrivateKey::from_bytes(&[seed; 32]).expect("32 bytes")
    }

    fn spec() -> SchemeSpec {
        SchemeId::ML_DSA_65.spec().expect("ml-dsa-65 is registered")
    }

    #[test]
    fn a_signature_verifies_under_its_own_key_and_message() {
        let k = key(7);
        let sig = k.sign(b"message");
        assert!(verify_ml_dsa_65(b"message", &k.public_key(), &sig));
        assert!(!verify_ml_dsa_65(b"other", &k.public_key(), &sig));
        assert!(!verify_ml_dsa_65(b"message", &key(8).public_key(), &sig));
    }

    /// The deterministic variant: a key and a message name one signature,
    /// so a signer cannot mint distinct envelopes over one intent by
    /// re-signing it.
    #[test]
    fn keys_and_signatures_are_deterministic_in_their_seed() {
        assert_eq!(key(42).public_key(), key(42).public_key());
        assert_eq!(key(42).sign(b"m"), key(42).sign(b"m"));
        assert_ne!(key(42).public_key(), key(43).public_key());
    }

    #[test]
    fn from_bytes_takes_exactly_the_seed_length() {
        assert!(MlDsa65PrivateKey::from_bytes(&[0u8; 32]).is_ok());
        assert!(MlDsa65PrivateKey::from_bytes(&[0u8; 31]).is_err());
        assert!(MlDsa65PrivateKey::from_bytes(&[0u8; 33]).is_err());
        assert!(MlDsa65PrivateKey::from_bytes(&[]).is_err());
    }

    /// Peer-supplied bytes reach verification directly, so malformed
    /// material must refuse rather than panic.
    #[test]
    fn malformed_inputs_refuse() {
        let k = key(1);
        let sig = k.sign(b"m");
        let pk = k.public_key();
        // A key of the right width standing for no honest keypair, and a
        // signature of the right width in no encoding FIPS 204 admits.
        assert!(!verify_ml_dsa_65(b"m", &vec![0u8; spec().key_len], &sig));
        assert!(!verify_ml_dsa_65(b"m", &pk, &vec![0xFF; spec().sig_len]));
        assert!(!verify_ml_dsa_65(b"m", &pk[..pk.len() - 1], &sig));
        assert!(!verify_ml_dsa_65(b"m", &pk, &sig[..sig.len() - 1]));
        assert!(!verify_ml_dsa_65(b"m", &[], &[]));
    }

    /// The registry sizes the scheme for the wire and prices it, and it
    /// cannot see the implementation that produces the material. This is
    /// what keeps the two from drifting apart: a parameter set swapped
    /// under the entry, or an encoding the crate changes, fails here
    /// rather than at a peer that decoded the envelope differently.
    #[test]
    fn the_registered_widths_are_the_widths_this_scheme_produces() {
        let k = key(3);
        assert!(spec().admits(&k.public_key(), &k.sign(b"m")));
    }
}
