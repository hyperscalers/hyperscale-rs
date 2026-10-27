//! Intents one account signs and another composes and pays for.
//!
//! A declaration is signed over its own hash, which covers no fee terms:
//! whoever composes it into a transaction sets those and pays. The
//! declaration's attestation answers its own account's gates wherever it
//! is composed, and its nullifier spends it once.

use hyperscale_effects_bridge::ProtocolHasher;
use hyperscale_effects_bridge::genesis::{OWNER_BADGE_ID, pool_owner_badge};
use hyperscale_effects_bridge::vm_statics::principal_for;
use hyperscale_hbor::{DecodeError, EncodeError, from_slice_with_depth, to_vec};
use hyperscale_types::{
    AccountSigner, ComponentAddr, ProtocolVerifier, SchemeVerifier, Transaction,
};
use hyperscale_vm_effects::{Intent, IntentHeader, SignedIntent, TREE_WIRE_DEPTH};
use hyperscale_vm_manifest_builder::{IntentBuilder, IntentError, TypedBuilder, TypedError};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::PrincipalAddr;

use crate::{Client, Terms, principal_of};

impl Client {
    /// The declaration acting as `owner`, whose account holds `pool`'s
    /// owner badge, that presents the badge around `call`: any operator
    /// action on the pool, under `header`.
    ///
    /// The same inputs build the same declaration, so a composer can
    /// rebuild it to see exactly what it is asked to pay for.
    ///
    /// # Errors
    ///
    /// [`IntentError`] if the owner's account, the pool or `call` does not
    /// resolve in this client's world.
    pub fn operator_declaration(
        &self,
        owner: PrincipalAddr,
        pool: ComponentAddr,
        header: IntentHeader,
        call: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>,
    ) -> Result<Intent, IntentError> {
        let chain = self.records();
        let mut decl = IntentBuilder::new(&chain, &ProtocolHasher, owner, header);
        let badge =
            account::present_instance(&mut decl, owner, pool_owner_badge(pool), OWNER_BADGE_ID)?;
        decl.presenting(badge, call)?;
        decl.into_decl()
    }

    /// `signed` composed under a root of `payer`'s own that calls nothing,
    /// in a transaction `payer` signs and pays for under `terms`.
    ///
    /// # Errors
    ///
    /// [`IntentError`] if `signed` declares sockets or gives, which a root
    /// that calls nothing cannot fill or take, or is not well formed.
    pub fn sponsor<S: AccountSigner>(
        &self,
        signed: SignedIntent,
        payer: &S,
        root: IntentHeader,
        terms: Terms,
    ) -> Result<Transaction, IntentError> {
        let chain = self.records();
        let mut builder = IntentBuilder::new(&chain, &ProtocolHasher, principal_of(payer), root);
        let interface = builder.adopt(signed)?;
        interface.sockets.none()?;
        interface.gives.none()?;
        let tree = builder.build()?;
        Ok(Transaction::new(self.sign_tree(&tree, &[payer], terms)))
    }
}

/// `intent` attested by `key`, the one principal it declares.
///
/// # Panics
///
/// If `intent` already carries every attestation it may, which a fresh
/// declaration never does.
#[must_use]
pub fn sign_intent<S: AccountSigner + ?Sized>(intent: Intent, key: &S) -> SignedIntent {
    let mut signed = SignedIntent::unsigned(intent);
    signed
        .attest(key, &ProtocolHasher)
        .expect("a fresh declaration has room for its attestation");
    signed
}

/// `signed`'s bytes on the wire.
///
/// # Errors
///
/// [`EncodeError`] if it outgrows the wire caps, which no declaration
/// this client builds does.
pub fn encode_intent(signed: &SignedIntent) -> Result<Vec<u8>, EncodeError> {
    to_vec(signed)
}

/// The signed intent `bytes` carry, read at the depth a transaction's
/// tree is read at.
///
/// # Errors
///
/// [`DecodeError`] if `bytes` are not one.
pub fn decode_intent(bytes: &[u8]) -> Result<SignedIntent, DecodeError> {
    from_slice_with_depth(bytes, TREE_WIRE_DEPTH)
}

/// Whether `signed` declares `principal` alone as its attester and carries
/// exactly its valid attestation, over the intent's hash.
#[must_use]
pub fn attested_only_by(signed: &SignedIntent, principal: PrincipalAddr) -> bool {
    let [attestation] = signed.signatures.as_slice() else {
        return false;
    };
    if signed.intent.attested_by.as_slice() != [principal] {
        return false;
    }
    let Some(derived) = principal_for(attestation.scheme, &attestation.public_key) else {
        return false;
    };
    derived == principal
        && ProtocolVerifier.verify(
            attestation.scheme,
            &attestation.public_key,
            &attestation.signature,
            &signed.intent.hash(&ProtocolHasher).0.0,
        )
}

#[cfg(test)]
mod tests {

    use hyperscale_types::test_utils::test_principal;
    use hyperscale_types::{NetworkId, StakePoolSeat, ed25519_keypair_from_seed};

    use super::*;
    use crate::{Ceilings, Staking, pool_address};

    const NETWORK: NetworkId = NetworkId(242);

    fn seat() -> StakePoolSeat {
        StakePoolSeat {
            number: 0,
            operator: test_principal(7),
            founding: Vec::new(),
        }
    }

    fn header(discriminator: u64) -> IntentHeader {
        IntentHeader {
            network: NETWORK,
            validity_start_ms: 0,
            validity_end_ms: 900_000,
            discriminator,
        }
    }

    /// The unjail of `validator` in `pool` as `owner` declares it.
    fn unjail(
        client: &Client,
        owner: PrincipalAddr,
        pool: ComponentAddr,
        validator: u64,
    ) -> Intent {
        client
            .operator_declaration(owner, pool, header(1), |b| {
                Staking::at(pool).unjail(b, validator)
            })
            .unwrap()
    }

    const fn terms() -> Terms {
        Terms {
            max_fee: 1_000,
            ceilings: Ceilings::Guessed,
            priority_bp: 0,
            message: Vec::new(),
        }
    }

    /// An owner's signed unjail crosses the wire whole, reads as its
    /// owner's alone, and a payer composes it into a transaction of its own.
    #[test]
    fn a_signed_unjail_travels_and_another_account_pays_for_it() {
        let client = Client::with_pools(&[seat()], NETWORK);
        let pool = pool_address(&seat());
        let owner_key = ed25519_keypair_from_seed(&[3; 32]);
        let owner = principal_of(&owner_key);
        let intent = unjail(&client, owner, pool, 1000);
        assert_eq!(
            unjail(&client, owner, pool, 1000),
            intent,
            "the same inputs build the same declaration"
        );
        let signed = sign_intent(intent, &owner_key);
        let back = decode_intent(&encode_intent(&signed).unwrap()).unwrap();
        assert_eq!(back, signed);
        assert!(attested_only_by(&back, owner));
        assert!(!attested_only_by(&back, test_principal(9)));

        let payer = ed25519_keypair_from_seed(&[4; 32]);
        let tx = client.sponsor(back, &payer, header(0), terms()).unwrap();
        assert_eq!(tx.body().terms.fee_payer, principal_of(&payer));
    }

    /// An attestation over another declaration does not stand for this one.
    #[test]
    fn an_attestation_moved_onto_another_declaration_is_not_its_owners() {
        let client = Client::with_pools(&[seat()], NETWORK);
        let pool = pool_address(&seat());
        let owner_key = ed25519_keypair_from_seed(&[3; 32]);
        let owner = principal_of(&owner_key);
        let declare = |validator| unjail(&client, owner, pool, validator);
        let mut moved = sign_intent(declare(1000), &owner_key);
        moved.intent = declare(1001);
        assert!(!attested_only_by(&moved, owner));
        assert!(!attested_only_by(
            &SignedIntent::unsigned(declare(1000)),
            owner
        ));
    }
}
