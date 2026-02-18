//! Pure provision verification and aggregation functions shared between runners.
//!
//! These functions contain the core BLS signature verification and aggregation
//! algorithms for cross-shard state provisions, separated from dispatch and
//! result delivery concerns.

use hyperscale_types::{
    batch_verify_bls_same_message, verify_bls12381_v1, zero_bls_signature, BlockHeight,
    Bls12381G1PublicKey, Bls12381G2Signature, CommitmentProof, Hash, ShardGroupId, SignerBitfield,
    StateEntry, StateProvision, Topology,
};

/// Result of provision verification and aggregation.
pub struct ProvisionVerificationResult {
    pub verified_provisions: Vec<StateProvision>,
    pub commitment_proof: Option<CommitmentProof>,
}

/// Verify provision signatures and aggregate into a `CommitmentProof`.
///
/// All provisions for the same `(tx, source_shard)` pair sign the same message,
/// enabling an optimized verification path: a single pairing check via BLS
/// same-message batch verification. Falls back to individual verification on
/// failure (Byzantine behavior).
///
/// Algorithm:
/// 1. Extract signatures and signing message from provisions
/// 2. `batch_verify_bls_same_message()` — single pairing check
/// 3. Fast path (all valid): build SignerBitfield via topology, aggregate sigs, build proof
/// 4. Slow path (batch fails): verify individually, collect valid, build proof from subset
#[allow(clippy::too_many_arguments)]
pub fn verify_and_aggregate_provisions(
    tx_hash: Hash,
    source_shard: ShardGroupId,
    block_height: BlockHeight,
    block_timestamp: u64,
    entries: Vec<StateEntry>,
    provisions: Vec<StateProvision>,
    public_keys: &[Bls12381G1PublicKey],
    committee_size: usize,
    topology: &dyn Topology,
) -> ProvisionVerificationResult {
    let signatures: Vec<Bls12381G2Signature> = provisions.iter().map(|p| p.signature).collect();

    let message = provisions
        .first()
        .map(|p| p.signing_message())
        .unwrap_or_default();

    let all_valid = batch_verify_bls_same_message(&message, &signatures, public_keys);

    let (verified_provisions, commitment_proof) = if all_valid {
        // Fast path: all signatures valid, build proof directly
        let mut signers = SignerBitfield::new(committee_size);
        for provision in &provisions {
            if let Some(idx) =
                topology.committee_index_for_shard(source_shard, provision.validator_id)
            {
                signers.set(idx);
            }
        }

        let aggregated_signature = Bls12381G2Signature::aggregate(&signatures, true)
            .unwrap_or_else(|_| zero_bls_signature());

        let proof = CommitmentProof::new(
            tx_hash,
            source_shard,
            signers,
            aggregated_signature,
            block_height,
            block_timestamp,
            entries,
        );

        (provisions, Some(proof))
    } else {
        // Slow path: aggregate verification failed, find valid signatures individually
        tracing::warn!(
            tx_hash = %tx_hash,
            source_shard = source_shard.0,
            provision_count = provisions.len(),
            "Aggregate provision verification failed, falling back to individual"
        );

        let mut verified = Vec::new();
        let mut valid_sigs = Vec::new();
        let mut signer_indices = Vec::new();

        for (provision, pk) in provisions.iter().zip(public_keys.iter()) {
            if verify_bls12381_v1(&message, pk, &provision.signature) {
                verified.push(provision.clone());
                valid_sigs.push(provision.signature);
                if let Some(idx) =
                    topology.committee_index_for_shard(source_shard, provision.validator_id)
                {
                    signer_indices.push(idx);
                }
            } else {
                tracing::warn!(
                    tx_hash = %tx_hash,
                    validator = provision.validator_id.0,
                    "Invalid provision signature"
                );
            }
        }

        let proof = if !valid_sigs.is_empty() {
            let mut signers = SignerBitfield::new(committee_size);
            for idx in &signer_indices {
                signers.set(*idx);
            }

            let aggregated_signature = Bls12381G2Signature::aggregate(&valid_sigs, true)
                .unwrap_or_else(|_| zero_bls_signature());

            Some(CommitmentProof::new(
                tx_hash,
                source_shard,
                signers,
                aggregated_signature,
                block_height,
                block_timestamp,
                entries,
            ))
        } else {
            None
        };

        (verified, proof)
    };

    ProvisionVerificationResult {
        verified_provisions,
        commitment_proof,
    }
}
