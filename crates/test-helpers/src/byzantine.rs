//! Byzantine/negative test helpers for crypto verification.
//!
//! These functions create invalid signatures and malformed fixtures
//! for testing that verification correctly rejects bad inputs.

use crate::TestCommittee;
use hyperscale_types::{
    batch_verify_bls_same_message, block_vote_message, exec_vote_message, BlockHeight, BlockVote,
    Bls12381G1PublicKey, Bls12381G2Signature, Hash, QuorumCertificate, ShardGroupId,
    SignerBitfield, StateVoteBlock, VotePower,
};

/// Create a block vote with an invalid signature (signed with wrong key).
///
/// The vote claims to be from `claimed_voter_idx` but is signed by `actual_signer_idx`.
/// This simulates a Byzantine validator trying to forge another validator's vote.
pub fn make_wrong_key_block_vote(
    committee: &TestCommittee,
    claimed_voter_idx: usize,
    actual_signer_idx: usize,
    block_hash: Hash,
    height: BlockHeight,
    round: u64,
    shard: ShardGroupId,
) -> BlockVote {
    let message = block_vote_message(shard, height.0, round, &block_hash);
    // Sign with wrong key
    let signature = committee.keypair(actual_signer_idx).sign_v1(&message);

    BlockVote {
        block_hash,
        height,
        round,
        voter: committee.validator_id(claimed_voter_idx), // Claims to be this voter
        signature,                                        // But signed by different key
        timestamp: 1000,
    }
}

/// Create a block vote signed for a different message (wrong block hash).
///
/// The signature is valid for a different block, simulating a replay attack
/// or message manipulation.
pub fn make_wrong_message_block_vote(
    committee: &TestCommittee,
    voter_idx: usize,
    claimed_block_hash: Hash,
    actual_signed_hash: Hash,
    height: BlockHeight,
    round: u64,
    shard: ShardGroupId,
) -> BlockVote {
    // Sign for different block
    let message = block_vote_message(shard, height.0, round, &actual_signed_hash);
    let signature = committee.keypair(voter_idx).sign_v1(&message);

    BlockVote {
        block_hash: claimed_block_hash, // Claims this block
        height,
        round,
        voter: committee.validator_id(voter_idx),
        signature, // But signed for different block
        timestamp: 1000,
    }
}

/// Create a QC where one signature is invalid (signed with wrong key).
///
/// Returns the QC and the index of the bad voter.
/// This tests the batch verification fallback path.
#[allow(clippy::too_many_arguments)]
pub fn make_partially_invalid_qc(
    committee: &TestCommittee,
    valid_voter_indices: &[usize],
    bad_voter_idx: usize,
    wrong_signer_idx: usize,
    block_hash: Hash,
    height: BlockHeight,
    round: u64,
    parent_hash: Hash,
    shard: ShardGroupId,
) -> (QuorumCertificate, usize) {
    let message = block_vote_message(shard, height.0, round, &block_hash);

    let mut all_indices: Vec<usize> = valid_voter_indices.to_vec();
    all_indices.push(bad_voter_idx);
    all_indices.sort();

    // Collect signatures - one is signed with wrong key
    let signatures: Vec<Bls12381G2Signature> = all_indices
        .iter()
        .map(|&idx| {
            if idx == bad_voter_idx {
                // Sign with wrong key
                committee.keypair(wrong_signer_idx).sign_v1(&message)
            } else {
                committee.keypair(idx).sign_v1(&message)
            }
        })
        .collect();

    // Aggregate all signatures (including the bad one)
    let aggregated_signature =
        Bls12381G2Signature::aggregate(&signatures, true).expect("BLS aggregation should succeed");

    // Build signer bitfield
    let mut signers = SignerBitfield::new(committee.size());
    for &idx in &all_indices {
        signers.set(idx);
    }

    let voting_power = VotePower(all_indices.len() as u64);

    let qc = QuorumCertificate {
        block_hash,
        height,
        parent_block_hash: parent_hash,
        round,
        signers,
        aggregated_signature,
        voting_power,
        weighted_timestamp_ms: 1000,
    };

    (qc, bad_voter_idx)
}

/// Create a state vote with an invalid signature.
pub fn make_wrong_key_state_vote(
    committee: &TestCommittee,
    claimed_voter_idx: usize,
    actual_signer_idx: usize,
    tx_hash: Hash,
    state_root: Hash,
    shard: ShardGroupId,
    success: bool,
) -> StateVoteBlock {
    let message = exec_vote_message(&tx_hash, &state_root, shard, success);
    let signature = committee.keypair(actual_signer_idx).sign_v1(&message);

    StateVoteBlock {
        transaction_hash: tx_hash,
        shard_group_id: shard,
        state_root,
        success,
        state_writes: vec![],
        validator: committee.validator_id(claimed_voter_idx),
        signature,
    }
}

/// Create a state vote signed for a different state root.
pub fn make_wrong_state_root_vote(
    committee: &TestCommittee,
    voter_idx: usize,
    tx_hash: Hash,
    claimed_state_root: Hash,
    actual_signed_root: Hash,
    shard: ShardGroupId,
    success: bool,
) -> StateVoteBlock {
    let message = exec_vote_message(&tx_hash, &actual_signed_root, shard, success);
    let signature = committee.keypair(voter_idx).sign_v1(&message);

    StateVoteBlock {
        transaction_hash: tx_hash,
        shard_group_id: shard,
        state_root: claimed_state_root,
        success,
        state_writes: vec![],
        validator: committee.validator_id(voter_idx),
        signature,
    }
}

/// Create a completely random/garbage signature.
///
/// This tests that verification handles malformed signatures gracefully.
pub fn make_garbage_signature() -> Bls12381G2Signature {
    // Create a signature with zero bytes (not a valid BLS signature point)
    Bls12381G2Signature([0u8; 96])
}

/// Create a vote with a garbage signature.
pub fn make_garbage_signature_vote(
    committee: &TestCommittee,
    voter_idx: usize,
    block_hash: Hash,
    height: BlockHeight,
    round: u64,
) -> BlockVote {
    BlockVote {
        block_hash,
        height,
        round,
        voter: committee.validator_id(voter_idx),
        signature: make_garbage_signature(),
        timestamp: 1000,
    }
}

/// Verify that batch verification correctly identifies bad signatures.
///
/// Returns true if batch verification rejects the set (as expected).
pub fn batch_verification_rejects(
    message: &[u8],
    signatures: &[Bls12381G2Signature],
    pubkeys: &[Bls12381G1PublicKey],
) -> bool {
    !batch_verify_bls_same_message(message, signatures, pubkeys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{make_signed_block_vote, verify_block_vote, verify_state_vote};

    #[test]
    fn test_wrong_key_vote_rejected() {
        let committee = TestCommittee::new(4, 42);
        let block_hash = Hash::from_bytes(b"block");
        let shard = ShardGroupId(0);

        // Vote claims to be from validator 0 but signed by validator 1
        let bad_vote = make_wrong_key_block_vote(
            &committee,
            0, // claimed
            1, // actual signer
            block_hash,
            BlockHeight(1),
            0,
            shard,
        );

        // Should NOT verify with claimed voter's key
        assert!(!verify_block_vote(
            &bad_vote,
            committee.public_key(0),
            shard
        ));

        // Would verify with actual signer's key (but voter ID wouldn't match)
        assert!(verify_block_vote(&bad_vote, committee.public_key(1), shard));
    }

    #[test]
    fn test_wrong_message_vote_rejected() {
        let committee = TestCommittee::new(4, 42);
        let shard = ShardGroupId(0);

        let claimed_hash = Hash::from_bytes(b"claimed_block");
        let actual_hash = Hash::from_bytes(b"actual_block");

        let bad_vote = make_wrong_message_block_vote(
            &committee,
            0,
            claimed_hash,
            actual_hash,
            BlockHeight(1),
            0,
            shard,
        );

        // Should NOT verify (message mismatch)
        assert!(!verify_block_vote(
            &bad_vote,
            committee.public_key(0),
            shard
        ));
    }

    #[test]
    fn test_wrong_key_state_vote_rejected() {
        let committee = TestCommittee::new(4, 42);
        let tx_hash = Hash::from_bytes(b"tx");
        let state_root = Hash::from_bytes(b"state");
        let shard = ShardGroupId(0);

        let bad_vote = make_wrong_key_state_vote(
            &committee, 0, // claimed
            1, // actual signer
            tx_hash, state_root, shard, true,
        );

        // Should NOT verify with claimed voter's key
        assert!(!verify_state_vote(&bad_vote, committee.public_key(0)));
    }

    #[test]
    fn test_garbage_signature_rejected() {
        let committee = TestCommittee::new(4, 42);
        let block_hash = Hash::from_bytes(b"block");
        let shard = ShardGroupId(0);

        let bad_vote = make_garbage_signature_vote(&committee, 0, block_hash, BlockHeight(1), 0);

        // Should NOT verify
        assert!(!verify_block_vote(
            &bad_vote,
            committee.public_key(0),
            shard
        ));
    }

    #[test]
    fn test_valid_vote_still_works() {
        // Sanity check that valid votes still verify
        let committee = TestCommittee::new(4, 42);
        let block_hash = Hash::from_bytes(b"block");
        let shard = ShardGroupId(0);

        let valid_vote =
            make_signed_block_vote(&committee, 0, block_hash, BlockHeight(1), 0, shard);

        assert!(verify_block_vote(
            &valid_vote,
            committee.public_key(0),
            shard
        ));
    }
}
