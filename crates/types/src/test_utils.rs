//! Test utilities.

use crate::{NodeId, RoutableTransaction, TimestampRange, WeightedTimestamp};
use radix_common::crypto::{Ed25519PublicKey, Ed25519Signature, PublicKey as RadixPublicKey};
use radix_common::prelude::Epoch;
use radix_transactions::model::{
    BlobsV1, InstructionsV1, IntentSignaturesV1, IntentV1, MessageV1, NotarizedTransactionV1,
    NotarySignatureV1, SignatureV1, SignedIntentV1, TransactionHeaderV1, UserTransaction,
};

/// Create a test `NodeId` from a seed byte.
#[must_use]
pub fn test_node(seed: u8) -> NodeId {
    NodeId([seed; 30])
}

/// Create a minimal test `NotarizedTransactionV1` from seed bytes.
///
/// This creates a valid but minimal transaction structure for testing.
/// The transaction won't execute successfully but is structurally valid.
#[must_use]
pub fn test_notarized_transaction_v1(seed_bytes: &[u8]) -> NotarizedTransactionV1 {
    // Create minimal header with unique nonce from seed
    let header = TransactionHeaderV1 {
        network_id: 0xf2, // Simulator network
        start_epoch_inclusive: Epoch::of(0),
        end_epoch_exclusive: Epoch::of(100),
        nonce: {
            let mut nonce_bytes = [0u8; 4];
            for (i, &b) in seed_bytes.iter().take(4).enumerate() {
                nonce_bytes[i] = b;
            }
            u32::from_le_bytes(nonce_bytes)
        },
        notary_public_key: RadixPublicKey::Ed25519(Ed25519PublicKey([0u8; 32])),
        notary_is_signatory: false,
        tip_percentage: 0,
    };

    // Create a minimal intent
    let intent = IntentV1 {
        header,
        instructions: InstructionsV1(vec![]),
        blobs: BlobsV1 { blobs: vec![] },
        message: MessageV1::None,
    };

    // Create signed intent with no signatures
    let signed_intent = SignedIntentV1 {
        intent,
        intent_signatures: IntentSignaturesV1 { signatures: vec![] },
    };

    // Create notarized transaction with a zero signature
    NotarizedTransactionV1 {
        signed_intent,
        notary_signature: NotarySignatureV1(SignatureV1::Ed25519(Ed25519Signature([0u8; 64]))),
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

/// Validity range used for test transactions: a wide window centred on
/// `WeightedTimestamp::ZERO` so test fixtures don't need to thread a
/// real anchor through every helper. Tests that exercise expiry should
/// build their own range.
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
