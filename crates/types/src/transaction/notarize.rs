//! Helpers for signing and notarizing a Radix `TransactionManifestV1`.

use crate::TransactionError;
use radix_common::crypto::IsHash;
use radix_common::network::NetworkDefinition;
use radix_common::prelude::Epoch;
use radix_transactions::model::{
    HasSignedTransactionIntentHash, HasTransactionIntentHash, IntentSignatureV1,
    IntentSignaturesV1, IntentV1, NotarizedTransactionV1, NotarySignatureV1, SignatureV1,
    SignatureWithPublicKeyV1, SignedIntentV1, TransactionHeaderV1, TransactionPayload,
};
use radix_transactions::prelude::{PreparationSettings, TransactionManifestV1};

/// Sign and notarize a transaction manifest.
///
/// This takes a pre-built manifest and signs it with the provided keypair,
/// producing a fully notarized transaction ready for conversion to `RoutableTransaction`.
///
/// # Arguments
///
/// * `manifest` - The transaction manifest built using `ManifestBuilder`
/// * `network` - The network definition
/// * `nonce` - Transaction nonce for replay protection
/// * `signer` - The Ed25519 private key to sign with (acts as both signer and notary)
///
/// Note: Only Ed25519 keys are supported for Radix transactions (not BLS).
///
/// # Errors
///
/// Forwards any error from [`sign_and_notarize_with_options`] (manifest
/// build / hashing / signing).
pub fn sign_and_notarize(
    manifest: TransactionManifestV1,
    network: &NetworkDefinition,
    nonce: u32,
    signer: &crate::Ed25519PrivateKey,
) -> Result<NotarizedTransactionV1, TransactionError> {
    sign_and_notarize_with_options(
        manifest,
        network,
        nonce,
        0,              // tip_percentage
        Epoch::of(0),   // start_epoch
        Epoch::of(100), // end_epoch (Radix has ~100 epoch max range)
        signer,
    )
}

/// Sign and notarize a transaction manifest with full options.
///
/// This provides full control over transaction header parameters.
///
/// Note: Only Ed25519 keys are supported for Radix transactions (not BLS).
///
/// # Errors
///
/// Returns [`TransactionError`] if intent construction or hashing fails
/// (these only fire on programmer error today: malformed manifests).
pub fn sign_and_notarize_with_options(
    manifest: TransactionManifestV1,
    network: &NetworkDefinition,
    nonce: u32,
    tip_percentage: u16,
    start_epoch: Epoch,
    end_epoch: Epoch,
    signer: &crate::Ed25519PrivateKey,
) -> Result<NotarizedTransactionV1, TransactionError> {
    let (instructions, blobs) = manifest.for_intent();
    let notary_public_key = radix_common::crypto::PublicKey::Ed25519(signer.public_key());

    let intent = IntentV1 {
        header: TransactionHeaderV1 {
            network_id: network.id,
            start_epoch_inclusive: start_epoch,
            end_epoch_exclusive: end_epoch,
            nonce,
            notary_public_key,
            notary_is_signatory: true,
            tip_percentage,
        },
        instructions,
        blobs,
        message: radix_transactions::prelude::MessageV1::None,
    };

    // Prepare and sign the intent
    let prepared_intent = intent
        .prepare(&PreparationSettings::latest())
        .map_err(|e| TransactionError::EncodeFailed(format!("{e:?}")))?;

    let intent_hash = *prepared_intent
        .transaction_intent_hash()
        .as_hash()
        .as_bytes();
    let intent_sig = signer.sign(intent_hash);
    let intent_signature = SignatureWithPublicKeyV1::Ed25519 {
        public_key: signer.public_key(),
        signature: intent_sig,
    };

    let signed_intent = SignedIntentV1 {
        intent,
        intent_signatures: IntentSignaturesV1 {
            signatures: vec![IntentSignatureV1(intent_signature)],
        },
    };

    // Prepare and notarize the signed intent
    let prepared_signed = signed_intent
        .prepare(&PreparationSettings::latest())
        .map_err(|e| TransactionError::EncodeFailed(format!("{e:?}")))?;

    let signed_intent_hash = *prepared_signed
        .signed_transaction_intent_hash()
        .as_hash()
        .as_bytes();
    let notary_sig = signer.sign(signed_intent_hash);
    let notary_signature = SignatureV1::Ed25519(notary_sig);

    Ok(NotarizedTransactionV1 {
        signed_intent,
        notary_signature: NotarySignatureV1(notary_signature),
    })
}
