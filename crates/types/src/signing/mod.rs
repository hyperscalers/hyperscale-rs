//! Signing messages for every signature the consensus protocol gathers.
//!
//! Each signable artifact pairs with a message struct deriving
//! `#[hbor(signing_domain = "...", signing_context = NetworkId)]`: the
//! bytes a signature covers are
//! [`HborSignedWith::signing_bytes`](hyperscale_hbor::HborSignedWith) —
//! the framed domain, the network the session is for, then the canonical
//! encoding of the fields. Domain separation prevents cross-protocol
//! replay; the context prevents cross-network replay; injectivity of the
//! canonical encoding makes every field binding, with no per-message
//! framing argument.

use hyperscale_hbor::HborSignedWith;
/// The network a signing session is for — the context every consensus
/// preimage mixes in ahead of its fields, so a signature produced for
/// one network can never verify against another. One type with the
/// envelope's signed network field, so the session vocabulary and the
/// transaction's own claim cannot drift apart.
pub use hyperscale_vm_types::NetworkId;

use crate::NetworkDefinition;

impl From<&NetworkDefinition> for NetworkId {
    fn from(network: &NetworkDefinition) -> Self {
        Self(network.id)
    }
}

/// The bytes a signature over `message` covers, in `network`'s sessions.
///
/// Every signing message is a small closed struct, so encoding cannot
/// hit a length or depth cap; the panic is unreachable.
///
/// # Panics
///
/// Panics if encoding the message fails, which the message shapes rule
/// out.
#[must_use]
pub fn signed_bytes<M: HborSignedWith<Context = NetworkId>>(
    message: &M,
    network: &NetworkDefinition,
) -> Vec<u8> {
    message
        .signing_bytes(&NetworkId::from(network))
        .expect("signing messages are small closed structs")
}

mod beacon_pc;
mod beacon_ratify;
mod beacon_reveal;
mod execution;
mod provisions;
mod shard;
mod shard_reveal;
mod validator_address;
mod validator_bind;
mod validator_possession_proof;

pub use beacon_pc::{
    PcRound, PcScope, PcVoteMessage, SpcEmptyViewMessage, SpcRelayKind, SpcRelayMessage,
};
pub use beacon_ratify::RatifyVoteMessage;
pub use beacon_reveal::{
    BeaconRevealMessage, beacon_reveal_sign, beacon_reveal_verify, vrf_output_from_proof,
};
pub use execution::{ExecutionCertificatesSenderMessage, ExecutionVoteMessage};
pub use provisions::ProvisionsSenderMessage;
pub use shard::{BlockProposalMessage, BlockVoteMessage, CertifiedBlockHeaderSenderMessage};
pub use shard_reveal::{ShardRevealMessage, shard_reveal_sign, shard_reveal_verify};
pub use validator_address::ValidatorAddressMessage;
pub use validator_bind::{VALIDATOR_BIND_NONCE_LEN, ValidatorBindMessage};
pub use validator_possession_proof::{
    ValidatorPossessionProofMessage, validator_possession_proof_sign,
    validator_possession_proof_verify,
};

#[cfg(test)]
mod tests {
    use hyperscale_hbor::HborSigned as _;

    use super::*;
    use crate::{
        BlockHash, BlockHeight, Hash, ReadySignal, Round, ShardId, Timeout, TransactionEnvelope,
    };

    /// The context is covered: the same message signed for two networks
    /// commits to two byte strings, which is what makes a cross-network
    /// replay fail. One message type stands in for all — the context
    /// enters every preimage the same way.
    #[test]
    fn context_enters_the_preimage() {
        let message = BlockVoteMessage {
            shard_group: ShardId::ROOT,
            height: BlockHeight::new(10),
            round: Round::INITIAL,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"block")),
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
        };
        assert_ne!(
            signed_bytes(&message, &NetworkDefinition::mainnet()),
            signed_bytes(&message, &NetworkDefinition::testnet())
        );
    }

    /// Every signing domain in the crate, pairwise distinct. The domain is
    /// framed into the preimage, so distinct domains give disjoint preimage
    /// spaces — this one check is what stops a signature gathered for one
    /// message type from verifying as any other, for every pair at once.
    #[test]
    fn signing_domains_are_pairwise_distinct() {
        let domains: &[(&str, &[u8])] = &[
            ("PcVoteMessage", PcVoteMessage::SIGNING_DOMAIN),
            ("SpcEmptyViewMessage", SpcEmptyViewMessage::SIGNING_DOMAIN),
            ("SpcRelayMessage", SpcRelayMessage::SIGNING_DOMAIN),
            ("RatifyVoteMessage", RatifyVoteMessage::SIGNING_DOMAIN),
            ("BeaconRevealMessage", BeaconRevealMessage::SIGNING_DOMAIN),
            ("ExecutionVoteMessage", ExecutionVoteMessage::SIGNING_DOMAIN),
            (
                "ExecutionCertificatesSenderMessage",
                ExecutionCertificatesSenderMessage::SIGNING_DOMAIN,
            ),
            (
                "ProvisionsSenderMessage",
                ProvisionsSenderMessage::SIGNING_DOMAIN,
            ),
            ("ReadySignal", ReadySignal::SIGNING_DOMAIN),
            ("BlockVoteMessage", BlockVoteMessage::SIGNING_DOMAIN),
            ("BlockProposalMessage", BlockProposalMessage::SIGNING_DOMAIN),
            ("Timeout", Timeout::SIGNING_DOMAIN),
            (
                "CertifiedBlockHeaderSenderMessage",
                CertifiedBlockHeaderSenderMessage::SIGNING_DOMAIN,
            ),
            ("ShardRevealMessage", ShardRevealMessage::SIGNING_DOMAIN),
            (
                "ValidatorAddressMessage",
                ValidatorAddressMessage::SIGNING_DOMAIN,
            ),
            ("ValidatorBindMessage", ValidatorBindMessage::SIGNING_DOMAIN),
            (
                "ValidatorPossessionProofMessage",
                ValidatorPossessionProofMessage::SIGNING_DOMAIN,
            ),
            ("TransactionEnvelope", TransactionEnvelope::SIGNING_DOMAIN),
        ];
        for (i, (name_a, domain_a)) in domains.iter().enumerate() {
            for (name_b, domain_b) in &domains[i + 1..] {
                assert_ne!(
                    domain_a, domain_b,
                    "{name_a} and {name_b} share a signing domain"
                );
            }
        }
    }
}
