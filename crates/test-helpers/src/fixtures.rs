//! Signed fixture builders for test data.
//!
//! These functions create properly-signed test fixtures that exercise
//! real cryptographic verification paths.

use crate::TestCommittee;
use hyperscale_types::{
    block_vote_message, verify_bls12381_v1, BlockHeight, BlockVote, Bls12381G1PublicKey,
    Bls12381G2Signature, Hash, QuorumCertificate, ShardExecutionProof, ShardGroupId,
    SignerBitfield,
};

/// Create a properly-signed block vote.
///
/// The vote is signed with the keypair at `voter_idx` in the committee.
///
/// # Example
///
/// ```rust
/// use hyperscale_test_helpers::{TestCommittee, fixtures};
/// use hyperscale_types::{Hash, BlockHeight, ShardGroupId, verify_bls12381_v1};
///
/// let committee = TestCommittee::new(4, 42);
/// let vote = fixtures::make_signed_block_vote(
///     &committee,
///     0,
///     Hash::from_bytes(b"block"),
///     BlockHeight(1),
///     0,
///     ShardGroupId(0),
/// );
///
/// // Verify the signature is valid
/// let msg = vote.signing_message();
/// assert!(verify_bls12381_v1(&msg, committee.public_key(0), &vote.signature));
/// ```
pub fn make_signed_block_vote(
    committee: &TestCommittee,
    voter_idx: usize,
    block_hash: Hash,
    height: BlockHeight,
    round: u64,
    shard: ShardGroupId,
) -> BlockVote {
    BlockVote::new(
        block_hash,
        shard,
        height,
        round,
        committee.validator_id(voter_idx),
        committee.keypair(voter_idx),
        1000 + voter_idx as u64 * 100, // Deterministic timestamps
    )
}

/// Create a quorum certificate from signed votes.
///
/// Aggregates BLS signatures from the specified voter indices.
/// The resulting QC has a valid aggregated signature that can be verified.
///
/// # Example
///
/// ```rust
/// use hyperscale_test_helpers::{TestCommittee, fixtures};
/// use hyperscale_types::{Hash, BlockHeight, ShardGroupId, Bls12381G1PublicKey, batch_verify_bls_same_message};
///
/// let committee = TestCommittee::new(4, 42);
/// let qc = fixtures::make_signed_qc(
///     &committee,
///     &[0, 1, 2], // 3 voters
///     Hash::from_bytes(b"block"),
///     BlockHeight(1),
///     0,
///     Hash::from_bytes(b"parent"),
///     ShardGroupId(0),
/// );
///
/// // Verify the aggregated signature
/// let msg = qc.signing_message();
/// let signer_keys: Vec<_> = [0, 1, 2].iter()
///     .map(|&i| *committee.public_key(i))
///     .collect();
/// let agg_pk = Bls12381G1PublicKey::aggregate(&signer_keys, true).unwrap();
/// assert!(hyperscale_types::verify_bls12381_v1(&msg, &agg_pk, &qc.aggregated_signature));
/// ```
pub fn make_signed_qc(
    committee: &TestCommittee,
    voter_indices: &[usize],
    block_hash: Hash,
    height: BlockHeight,
    round: u64,
    parent_hash: Hash,
    shard: ShardGroupId,
) -> QuorumCertificate {
    let message = block_vote_message(shard, height.0, round, &block_hash);

    // Collect individual signatures
    let signatures: Vec<Bls12381G2Signature> = voter_indices
        .iter()
        .map(|&idx| committee.keypair(idx).sign_v1(&message))
        .collect();

    // Aggregate signatures
    let aggregated_signature =
        Bls12381G2Signature::aggregate(&signatures, true).expect("BLS aggregation should succeed");

    // Build signer bitfield
    let mut signers = SignerBitfield::new(committee.size());
    for &idx in voter_indices {
        signers.set(idx);
    }

    // Calculate weighted timestamp
    let weighted_timestamp_ms = voter_indices
        .iter()
        .map(|&idx| 1000 + idx as u64 * 100)
        .sum::<u64>()
        / voter_indices.len() as u64;

    QuorumCertificate {
        block_hash,
        shard_group_id: shard,
        height,
        parent_block_hash: parent_hash,
        round,
        signers,
        aggregated_signature,
        weighted_timestamp_ms,
    }
}

/// Create a shard execution proof for testing.
///
/// Simple proof with no BLS signatures (execution certificates handle signatures).
pub fn make_shard_execution_proof(receipt_hash: Hash, success: bool) -> ShardExecutionProof {
    ShardExecutionProof {
        receipt_hash,
        success,
        write_nodes: vec![],
    }
}

/// Verify a block vote signature.
///
/// Convenience function for tests.
pub fn verify_block_vote(vote: &BlockVote, public_key: &Bls12381G1PublicKey) -> bool {
    let message = vote.signing_message();
    verify_bls12381_v1(&message, public_key, &vote.signature)
}

/// Verify a QC's aggregated signature.
///
/// Aggregates the public keys of signers and verifies against the aggregated signature.
pub fn verify_qc(qc: &QuorumCertificate, committee: &TestCommittee) -> bool {
    let message = qc.signing_message();

    // Collect signer public keys
    let signer_keys: Vec<Bls12381G1PublicKey> = qc
        .signers
        .set_indices()
        .map(|idx| *committee.public_key(idx))
        .collect();

    if signer_keys.is_empty() {
        return false;
    }

    // Aggregate and verify
    match Bls12381G1PublicKey::aggregate(&signer_keys, true) {
        Ok(agg_pk) => verify_bls12381_v1(&message, &agg_pk, &qc.aggregated_signature),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_block_vote() {
        let committee = TestCommittee::new(4, 42);
        let block_hash = Hash::from_bytes(b"test_block");
        let shard = ShardGroupId(0);

        let vote = make_signed_block_vote(&committee, 0, block_hash, BlockHeight(1), 0, shard);

        // Should verify with correct key
        assert!(verify_block_vote(&vote, committee.public_key(0)));

        // Should not verify with wrong key
        assert!(!verify_block_vote(&vote, committee.public_key(1)));
    }

    #[test]
    fn test_signed_qc() {
        let committee = TestCommittee::new(4, 42);
        let block_hash = Hash::from_bytes(b"test_block");
        let parent_hash = Hash::from_bytes(b"parent");
        let shard = ShardGroupId(0);

        let qc = make_signed_qc(
            &committee,
            &[0, 1, 2],
            block_hash,
            BlockHeight(1),
            0,
            parent_hash,
            shard,
        );

        assert!(verify_qc(&qc, &committee));
        assert_eq!(qc.signer_count(), 3);
    }

    #[test]
    fn test_shard_execution_proof() {
        let receipt_hash = Hash::from_bytes(b"commitment");

        let proof = make_shard_execution_proof(receipt_hash, true);

        assert!(proof.success);
        assert_eq!(proof.receipt_hash, receipt_hash);
    }
}
