//! Joining: an account founds its own stake pool and seats a validator in
//! it, and a sponsor funds and pays for what the account signed.
//!
//! The first join brings the pool up: the pool's bring-up takes the
//! founding stake and registers the validator in the one node that makes
//! the pool actual, so the account signs a single declaration and the
//! sponsor fills its funds socket. Every later join presents the owner
//! badge the account already holds, and seats only where the pool's
//! stake already covers it.

use std::slice;

use hyperscale_effects_bridge::genesis::founded_pool;
use hyperscale_effects_bridge::{PROTOCOL_RESOURCE, ProtocolHasher};
use hyperscale_types::{
    AccountSigner, ConsensusPublicKey, ConsensusSignature, Transaction, ValidatorId,
};
use hyperscale_vm_effects::{Composed, Intent, IntentHeader, SignedIntent};
use hyperscale_vm_manifest_builder::{IntentBuilder, IntentError};
use hyperscale_vm_stdlib::{account, instantiate, staking};
use hyperscale_vm_types::PrincipalAddr;

use crate::{Client, Terms, principal_of};

impl Client {
    /// The declaration acting as `founder` that founds `founder`'s pool
    /// holding what its one funds socket is filled with, with `validator`
    /// registered under the consensus key it will be known by and the
    /// proof it holds that key, under `header`. The pool's owner badge
    /// lands in `founder`'s account.
    ///
    /// The same inputs build the same declaration, so a sponsor can
    /// rebuild it to see exactly what it is asked to pay for.
    ///
    /// # Errors
    ///
    /// [`IntentError`] if the founder's account does not resolve in this
    /// client's world.
    pub fn found_declaration(
        &self,
        founder: PrincipalAddr,
        header: IntentHeader,
        validator: ValidatorId,
        key: &ConsensusPublicKey,
        proof: &ConsensusSignature,
    ) -> Result<Intent, IntentError> {
        let chain = self.records();
        let pool = founded_pool(founder);
        let composed = Composed::new(&chain, slice::from_ref(&pool), &ProtocolHasher);
        let mut decl = IntentBuilder::new(&composed, &ProtocolHasher, founder, header);
        let funds = decl.declare(*PROTOCOL_RESOURCE, []);
        instantiate(
            &mut decl,
            pool.address(&ProtocolHasher),
            (funds, validator.inner(), *key.as_bytes(), *proof.as_bytes()),
        )?;
        decl.into_decl()
    }

    /// The declaration acting as `owner`, which holds its pool's owner
    /// badge, that registers `validator` in that pool under `header`.
    ///
    /// # Errors
    ///
    /// As [`found_declaration`](Self::found_declaration).
    pub fn join_declaration(
        &self,
        owner: PrincipalAddr,
        header: IntentHeader,
        validator: ValidatorId,
        key: &ConsensusPublicKey,
        proof: &ConsensusSignature,
    ) -> Result<Intent, IntentError> {
        let address = founded_pool(owner).address(&ProtocolHasher);
        self.operator_declaration(owner, address, header, |b| {
            staking::Staking::at(address).register_validator(
                b,
                validator.inner(),
                *key.as_bytes(),
                *proof.as_bytes(),
            )
        })
    }

    /// `signed`, `founder`'s [`found_declaration`](Self::found_declaration),
    /// composed under a root of `payer`'s own that withdraws `amount` of
    /// the protocol resource into its funds socket, presenting the pool's
    /// record, in a transaction `payer` signs and pays for under `terms`.
    ///
    /// # Errors
    ///
    /// [`IntentError`] if `signed` declares other than one funds socket
    /// and no gives, or does not compose.
    pub fn found_and_join<S: AccountSigner>(
        &self,
        signed: SignedIntent,
        founder: PrincipalAddr,
        payer: &S,
        root: IntentHeader,
        terms: Terms,
        amount: u128,
    ) -> Result<Transaction, IntentError> {
        let chain = self.records();
        let pool = founded_pool(founder);
        let composed = Composed::new(&chain, slice::from_ref(&pool), &ProtocolHasher);
        let sponsor = principal_of(payer);
        let mut builder = IntentBuilder::new(&composed, &ProtocolHasher, sponsor, root);
        let interface = builder.adopt(signed)?;
        let funds_socket = interface.sockets.one()?;
        interface.gives.none()?;
        let funds = account::withdraw(&mut builder, sponsor, *PROTOCOL_RESOURCE, amount)?;
        builder.bind(funds_socket, funds)?;
        let tree = builder.build_presenting(vec![pool], Vec::new())?;
        Ok(Transaction::new(self.sign_tree(&tree, &[payer], terms)))
    }

    /// `signed`, `founder`'s [`join_declaration`](Self::join_declaration),
    /// in a transaction `payer` signs and pays for under `terms`.
    ///
    /// # Errors
    ///
    /// [`IntentError`] if `signed` declares sockets or gives, or does not
    /// compose.
    pub fn join<S: AccountSigner>(
        &self,
        signed: SignedIntent,
        founder: PrincipalAddr,
        payer: &S,
        root: IntentHeader,
        terms: Terms,
    ) -> Result<Transaction, IntentError> {
        let chain = self.records();
        let pool = founded_pool(founder);
        let composed = Composed::new(&chain, slice::from_ref(&pool), &ProtocolHasher);
        let mut builder = IntentBuilder::new(&composed, &ProtocolHasher, principal_of(payer), root);
        let interface = builder.adopt(signed)?;
        interface.sockets.none()?;
        interface.gives.none()?;
        let tree = builder.build()?;
        Ok(Transaction::new(self.sign_tree(&tree, &[payer], terms)))
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_principal;
    use hyperscale_types::{NetworkId, ed25519_keypair_from_seed};
    use hyperscale_vm_effects::Socket;

    use super::*;
    use crate::{Ceilings, sign_intent};

    const NETWORK: NetworkId = NetworkId(242);
    const VALIDATOR: ValidatorId = ValidatorId::new(3);

    fn header(discriminator: u64) -> IntentHeader {
        IntentHeader {
            network: NETWORK,
            validity_start_ms: 0,
            validity_end_ms: 900_000,
            discriminator,
        }
    }

    fn key() -> ConsensusPublicKey {
        ConsensusPublicKey::new([1; 48])
    }

    fn proof() -> ConsensusSignature {
        ConsensusSignature::new([2; 96])
    }

    const fn terms() -> Terms {
        Terms {
            max_fee: 1_000,
            ceilings: Ceilings::Guessed,
            priority_bp: 0,
            message: Vec::new(),
        }
    }

    /// The same inputs build the same declaration, which is what lets a
    /// sponsor rebuild the one it is handed and pay only for that.
    #[test]
    fn a_founding_and_a_join_rebuild_alike() {
        let client = Client::with_pools(&[], NETWORK);
        let founder = test_principal(9);
        let found = || {
            client
                .found_declaration(founder, header(1), VALIDATOR, &key(), &proof())
                .unwrap()
        };
        assert_eq!(found(), found());
        let join = || {
            client
                .join_declaration(founder, header(2), VALIDATOR, &key(), &proof())
                .unwrap()
        };
        assert_eq!(join(), join());
        assert_ne!(found(), join());
    }

    /// A founding asks for one thing: the protocol resource it comes up
    /// holding, in its one socket.
    #[test]
    fn a_founding_declares_one_funds_socket_of_the_protocol_resource() {
        let client = Client::with_pools(&[], NETWORK);
        let founding = client
            .found_declaration(test_principal(9), header(1), VALIDATOR, &key(), &proof())
            .unwrap();
        assert!(matches!(
            founding.sockets.as_slice(),
            [Socket::Value { resource, .. }] if *resource == *PROTOCOL_RESOURCE
        ));
        assert!(founding.gives.is_empty());
    }

    /// A sponsor composes a founding into a transaction it pays for, and
    /// a join the same way; each composes alike from the same inputs, so
    /// whoever rebuilds one holds the same transaction.
    #[test]
    fn a_sponsor_composes_a_founding_and_a_join_alike() {
        let client = Client::with_pools(&[], NETWORK);
        let founder_key = ed25519_keypair_from_seed(&[4; 32]);
        let founder = principal_of(&founder_key);
        let sponsor = ed25519_keypair_from_seed(&[5; 32]);
        let signed = |intent| sign_intent(intent, &founder_key);
        let composed_founding = || {
            let founding = client
                .found_declaration(founder, header(1), VALIDATOR, &key(), &proof())
                .unwrap();
            client
                .found_and_join(signed(founding), founder, &sponsor, header(10), terms(), 1)
                .unwrap()
        };
        assert_eq!(composed_founding(), composed_founding());
        let joined = || {
            let join = client
                .join_declaration(founder, header(2), VALIDATOR, &key(), &proof())
                .unwrap();
            client
                .join(signed(join), founder, &sponsor, header(11), terms())
                .unwrap()
        };
        assert_eq!(joined(), joined());
    }
}
