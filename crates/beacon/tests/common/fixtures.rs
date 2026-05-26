//! Deterministic fixtures — committees keyed off a seed, plus PC
//! signing-context builders.

use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Epoch, PcContext, SpcView, ValidatorId,
    bls_keypair_from_seed, pc_context, spc_context,
};

/// A small in-test validator committee — deterministic keys derived
/// from a `(test_seed, validator_id)` pair so each test gets a stable
/// set of keypairs without persistent fixture files.
pub struct Committee {
    /// Per-validator BLS secret keys, indexed positionally.
    pub keys: Vec<Bls12381G1PrivateKey>,
    /// Per-validator `(ValidatorId, public_key)` pairs, indexed
    /// positionally and in the same order as `keys`. Suitable for
    /// passing straight into the PC verifier API.
    pub members: Vec<(ValidatorId, Bls12381G1PublicKey)>,
}

impl Committee {
    /// Construct an `n`-member committee whose validator ids are
    /// `0..n` and whose BLS keys are deterministic functions of
    /// `(seed, validator_id)`.
    #[must_use]
    pub fn new(n: usize, seed: u64) -> Self {
        let mut keys = Vec::with_capacity(n);
        let mut members = Vec::with_capacity(n);
        for i in 0..n {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
            let sk = bls_keypair_from_seed(&bytes);
            let id = ValidatorId::new(i as u64);
            let pk = sk.public_key();
            keys.push(sk);
            members.push((id, pk));
        }
        Self { keys, members }
    }

    /// Number of members.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.members.len()
    }

    /// Secret key for the validator at position `i`.
    ///
    /// # Panics
    ///
    /// Panics if `i >= self.len()`.
    #[must_use]
    pub fn sk(&self, i: usize) -> &Bls12381G1PrivateKey {
        &self.keys[i]
    }

    /// Validator id at position `i`.
    ///
    /// # Panics
    ///
    /// Panics if `i >= self.len()`.
    #[must_use]
    pub fn id(&self, i: usize) -> ValidatorId {
        self.members[i].0
    }
}

/// Build a PC signing context for `(epoch, view)`. Matches the runtime
/// path: SPC binds the epoch, PC binds the view on top.
#[must_use]
pub fn pc_ctx(epoch: u64, view: u32) -> PcContext {
    let spc = spc_context(Epoch::new(epoch));
    pc_context(&spc, SpcView::new(view))
}
