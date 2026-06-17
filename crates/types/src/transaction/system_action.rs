//! Beacon actions carried in a transaction's plaintext message.
//!
//! A *system transaction* is an ordinary [`RoutableTransaction`](crate::RoutableTransaction)
//! whose manifest is a native-only no-op (a `lock_fee` that pays the fee and
//! does nothing else) and whose plaintext message carries the
//! [`BeaconWitnessEvent`] it wants the beacon to observe. The message is part
//! of the signed transaction bytes, so the carried action is signature- and
//! hash-covered and identical on every validator.
//!
//! Receipt projection reads the action with [`system_action`], lifts it into
//! the executing shard's `beacon_witness_events`, and the beacon folds it like
//! any committee-attested witness.
//!
//! This message carrier is a stop-gap until the Radix Engine system components
//! are aligned: once native staking and governance blueprints emit these events
//! directly, the beacon reads them from real receipts and this channel goes
//! away. Until then the action is asserted by the transaction and attested by
//! the emitting committee — not enforced by the manifest's effect, which is a
//! fee-paying no-op.

use radix_transactions::model::{MessageContentsV1, MessageV1, MessageV2, UserTransaction};
use sbor::prelude::*;

use crate::BeaconWitnessEvent;

/// Domain prefix marking a plaintext message as a beacon system action.
///
/// An ordinary user message that doesn't begin with this tag is never read as
/// an action, so user text and system actions can't be confused.
pub const SYSTEM_ACTION_TAG: &[u8] = b"hyperscale-system-action-v1";

/// Encode `event` for carriage in a transaction's plaintext message: the
/// domain tag followed by the SBOR encoding of the event.
///
/// # Panics
///
/// Panics if SBOR encoding fails. [`BeaconWitnessEvent`] derives `BasicSbor`
/// over closed scalar fields, so encoding is infallible in practice.
#[must_use]
pub fn encode_system_action(event: &BeaconWitnessEvent) -> Vec<u8> {
    let encoded = basic_encode(event).expect("BeaconWitnessEvent SBOR encode is infallible");
    let mut out = Vec::with_capacity(SYSTEM_ACTION_TAG.len() + encoded.len());
    out.extend_from_slice(SYSTEM_ACTION_TAG);
    out.extend_from_slice(&encoded);
    out
}

/// Decode a beacon action from raw message bytes, or `None` if the bytes don't
/// carry the system-action tag or the tagged remainder doesn't decode to a
/// [`BeaconWitnessEvent`].
#[must_use]
pub fn decode_system_action(bytes: &[u8]) -> Option<BeaconWitnessEvent> {
    let payload = bytes.strip_prefix(SYSTEM_ACTION_TAG)?;
    basic_decode(payload).ok()
}

/// The byte-typed plaintext message a transaction carries, if any.
///
/// Returns `None` for an absent, encrypted, or string-typed message — only the
/// `Bytes` form carries a system action.
#[must_use]
pub fn plaintext_message_bytes(tx: &UserTransaction) -> Option<&[u8]> {
    let contents = match tx {
        UserTransaction::V1(notarized) => match &notarized.signed_intent.intent.message {
            MessageV1::Plaintext(plaintext) => &plaintext.message,
            MessageV1::None | MessageV1::Encrypted(_) => return None,
        },
        UserTransaction::V2(notarized) => {
            match &notarized
                .signed_transaction_intent
                .transaction_intent
                .root_intent_core
                .message
            {
                MessageV2::Plaintext(plaintext) => &plaintext.message,
                MessageV2::None | MessageV2::Encrypted(_) => return None,
            }
        }
    };
    match contents {
        MessageContentsV1::Bytes(bytes) => Some(bytes),
        MessageContentsV1::String(_) => None,
    }
}

/// The beacon action `tx` asserts, if it is a system transaction: the
/// [`BeaconWitnessEvent`] decoded from a tagged byte-typed plaintext message.
#[must_use]
pub fn system_action(tx: &UserTransaction) -> Option<BeaconWitnessEvent> {
    decode_system_action(plaintext_message_bytes(tx)?)
}

#[cfg(test)]
mod tests {
    use radix_common::crypto::Ed25519PrivateKey;
    use radix_common::math::Decimal;
    use radix_common::network::NetworkDefinition;
    use radix_common::types::ComponentAddress;
    use radix_transactions::builder::ManifestBuilder;
    use radix_transactions::model::PlaintextMessageV1;
    use radix_transactions::prelude::TransactionManifestV1;

    use super::*;
    use crate::{NotarizeOptions, Stake, StakePoolId, sign_and_notarize_with_options};

    fn sample_event() -> BeaconWitnessEvent {
        BeaconWitnessEvent::StakeDeposit {
            pool_id: StakePoolId::new(7),
            amount: Stake::from_whole_tokens(1_000),
        }
    }

    /// A `lock_fee` no-op manifest paid from `key`'s account.
    fn lock_fee_manifest(key: &Ed25519PrivateKey) -> TransactionManifestV1 {
        let payer = ComponentAddress::preallocated_account_from_public_key(&key.public_key());
        ManifestBuilder::new()
            .lock_fee(payer, Decimal::from(10))
            .build()
    }

    #[test]
    fn encode_decode_round_trip() {
        let event = sample_event();
        let bytes = encode_system_action(&event);
        assert_eq!(decode_system_action(&bytes), Some(event));
    }

    #[test]
    fn untagged_bytes_decode_to_none() {
        // A bare SBOR encoding without the tag is not a system action.
        let raw = basic_encode(&sample_event()).unwrap();
        assert_eq!(decode_system_action(&raw), None);
    }

    #[test]
    fn tag_with_garbage_payload_decodes_to_none() {
        let mut bytes = SYSTEM_ACTION_TAG.to_vec();
        bytes.extend_from_slice(b"not an event");
        assert_eq!(decode_system_action(&bytes), None);
    }

    #[test]
    fn reads_action_from_a_notarized_transaction() {
        let event = sample_event();
        let message = MessageV1::Plaintext(PlaintextMessageV1 {
            mime_type: "application/octet-stream".to_string(),
            message: MessageContentsV1::Bytes(encode_system_action(&event)),
        });
        let key = Ed25519PrivateKey::from_u64(1).unwrap();
        let notarized = sign_and_notarize_with_options(
            lock_fee_manifest(&key),
            &NetworkDefinition::simulator(),
            1,
            NotarizeOptions {
                message,
                ..Default::default()
            },
            &key,
        )
        .unwrap();
        let tx = UserTransaction::V1(notarized);
        assert_eq!(system_action(&tx), Some(event));
    }

    #[test]
    fn plaintext_string_message_carries_no_action() {
        let message = MessageV1::Plaintext(PlaintextMessageV1::text("hello"));
        let key = Ed25519PrivateKey::from_u64(2).unwrap();
        let notarized = sign_and_notarize_with_options(
            lock_fee_manifest(&key),
            &NetworkDefinition::simulator(),
            1,
            NotarizeOptions {
                message,
                ..Default::default()
            },
            &key,
        )
        .unwrap();
        let tx = UserTransaction::V1(notarized);
        assert_eq!(system_action(&tx), None);
    }
}
