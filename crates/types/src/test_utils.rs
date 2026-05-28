//! Test utilities.

use radix_common::constants::PACKAGE_PACKAGE;
use radix_common::crypto::{Ed25519PrivateKey, IsHash, PublicKey as RadixPublicKey};
use radix_common::prelude::Epoch;
use radix_common::types::BlueprintId;
use radix_engine_interface::types::{Emitter, EventTypeIdentifier};
use radix_transactions::model::{
    BlobsV1, HasSignedTransactionIntentHash, InstructionsV1, IntentSignaturesV1, IntentV1,
    MessageV1, NotarizedTransactionV1, NotarySignatureV1, SignatureV1, SignedIntentV1,
    TransactionHeaderV1, TransactionPayload, UserTransaction,
};
use radix_transactions::prelude::PreparationSettings;

use crate::{NetworkDefinition, NodeId, RoutableTransaction, TimestampRange, WeightedTimestamp};

/// Create a test `NodeId` from a seed byte.
#[must_use]
pub const fn test_node(seed: u8) -> NodeId {
    NodeId([seed; 30])
}

/// Create a deterministic [`EventTypeIdentifier`] for tests.
///
/// Uses the well-known `PACKAGE_PACKAGE` address so the underlying
/// `PackageAddress` constructor accepts the bytes; the seed varies the
/// blueprint and event names so different seeds produce different identifiers
/// (and therefore different event hashes).
#[must_use]
pub fn test_event_type_identifier(seed: u8) -> EventTypeIdentifier {
    EventTypeIdentifier(
        Emitter::Function(BlueprintId::new(
            &PACKAGE_PACKAGE,
            format!("TestBlueprint{seed}"),
        )),
        format!("TestEvent{seed}"),
    )
}

/// Fixed Ed25519 keypair used as the notary for every fixture-built
/// transaction. Deterministic across runs so test fixtures produce
/// repeatable tx hashes.
fn test_notary_key() -> Ed25519PrivateKey {
    // 32 bytes of 0x42, fixed and unprivileged.
    Ed25519PrivateKey::from_bytes(&[0x42u8; 32]).expect("static 32-byte seed is valid")
}

/// Create a minimal test `NotarizedTransactionV1` from seed bytes.
///
/// The resulting transaction has a properly-computed notary signature
/// against the intent hash (using a fixed test keypair) and no intent
/// signatures, so Radix's `prepare_and_validate` accepts it. The
/// transaction won't execute successfully — its manifest is empty —
/// but admission-time validation passes, which is what test fixtures
/// downstream of the validation pool need.
///
/// # Panics
///
/// Panics if intent or signed-intent preparation fails. Both are
/// deterministic over the fixture's constant header / empty
/// instructions, so a panic here indicates a Radix-side breaking
/// change to preparation rather than a runtime condition.
#[must_use]
pub fn test_notarized_transaction_v1(seed_bytes: &[u8]) -> NotarizedTransactionV1 {
    let notary = test_notary_key();
    let header = TransactionHeaderV1 {
        network_id: NetworkDefinition::simulator().id,
        start_epoch_inclusive: Epoch::of(0),
        end_epoch_exclusive: Epoch::of(100),
        nonce: {
            let mut nonce_bytes = [0u8; 4];
            for (i, &b) in seed_bytes.iter().take(4).enumerate() {
                nonce_bytes[i] = b;
            }
            u32::from_le_bytes(nonce_bytes)
        },
        notary_public_key: RadixPublicKey::Ed25519(notary.public_key()),
        notary_is_signatory: true,
        tip_percentage: 0,
    };

    let intent = IntentV1 {
        header,
        instructions: InstructionsV1(vec![]),
        blobs: BlobsV1 { blobs: vec![] },
        message: MessageV1::None,
    };

    let signed_intent = SignedIntentV1 {
        intent,
        intent_signatures: IntentSignaturesV1 { signatures: vec![] },
    };

    let prepared_signed = signed_intent
        .prepare(&PreparationSettings::latest())
        .expect("test signed intent always prepares");
    let signed_intent_hash = *prepared_signed
        .signed_transaction_intent_hash()
        .as_hash()
        .as_bytes();

    let notary_signature = SignatureV1::Ed25519(notary.sign(signed_intent_hash));

    NotarizedTransactionV1 {
        signed_intent,
        notary_signature: NotarySignatureV1(notary_signature),
    }
}

/// Create a test transaction with specific read/write nodes.
#[must_use]
pub fn test_transaction_with_nodes(
    seed_bytes: &[u8],
    read_nodes: Vec<NodeId>,
    write_nodes: Vec<NodeId>,
) -> RoutableTransaction {
    let tx = test_notarized_transaction_v1(seed_bytes);
    RoutableTransaction::new(
        UserTransaction::V1(tx),
        read_nodes,
        write_nodes,
        test_validity_range(),
    )
}

/// Validity range used for test transactions.
///
/// A wide window centred on `WeightedTimestamp::ZERO` so test fixtures
/// don't need to thread a real anchor through every helper. Tests that
/// exercise expiry should build their own range.
#[must_use]
pub fn test_validity_range() -> TimestampRange {
    use std::time::Duration;
    TimestampRange::new(
        WeightedTimestamp::ZERO,
        WeightedTimestamp::ZERO.plus(Duration::from_mins(1)),
    )
}

/// Create a simple test transaction.
#[must_use]
pub fn test_transaction(seed: u8) -> RoutableTransaction {
    test_transaction_with_nodes(
        &[seed, seed + 1, seed + 2],
        vec![test_node(seed)],
        vec![test_node(seed + 10)],
    )
}
