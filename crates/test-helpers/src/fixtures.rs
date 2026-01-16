//! Signed fixture builders for test data.
//!
//! These functions create properly-signed test fixtures that exercise
//! real cryptographic verification paths.

use std::sync::Arc;

use crate::TestCommittee;
use hyperscale_types::{
    block_vote_message, exec_vote_message, state_provision_message, verify_bls12381_v1,
    BlockHeight, BlockVote, Bls12381G1PublicKey, Bls12381G2Signature, Hash, QuorumCertificate,
    ShardGroupId, SignerBitfield, StateCertificate, StateEntry, StateProvision, StateVoteBlock,
    VotePower,
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
/// let msg = hyperscale_types::block_vote_message(ShardGroupId(0), 1, 0, &vote.block_hash);
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
    let message = block_vote_message(shard, height.0, round, &block_hash);
    let signature = committee.keypair(voter_idx).sign_v1(&message);

    BlockVote {
        block_hash,
        height,
        round,
        voter: committee.validator_id(voter_idx),
        signature,
        timestamp: 1000 + voter_idx as u64 * 100, // Deterministic timestamps
    }
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
/// let msg = hyperscale_types::block_vote_message(ShardGroupId(0), 1, 0, &qc.block_hash);
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

    // Calculate voting power (1 per voter for simplicity)
    let voting_power = VotePower(voter_indices.len() as u64);

    // Calculate weighted timestamp
    let weighted_timestamp_ms = voter_indices
        .iter()
        .map(|&idx| 1000 + idx as u64 * 100)
        .sum::<u64>()
        / voter_indices.len() as u64;

    QuorumCertificate {
        block_hash,
        height,
        parent_block_hash: parent_hash,
        round,
        signers,
        aggregated_signature,
        voting_power,
        weighted_timestamp_ms,
    }
}

/// Create a properly-signed state vote.
///
/// The vote is signed with the keypair at `voter_idx` in the committee.
pub fn make_signed_state_vote(
    committee: &TestCommittee,
    voter_idx: usize,
    tx_hash: Hash,
    state_root: Hash,
    shard: ShardGroupId,
    success: bool,
) -> StateVoteBlock {
    let message = exec_vote_message(&tx_hash, &state_root, shard, success);
    let signature = committee.keypair(voter_idx).sign_v1(&message);

    StateVoteBlock {
        transaction_hash: tx_hash,
        shard_group_id: shard,
        state_root,
        success,
        state_writes: vec![],
        validator: committee.validator_id(voter_idx),
        signature,
    }
}

/// Create a state certificate from signed votes.
///
/// Aggregates BLS signatures from the specified voter indices.
pub fn make_signed_state_certificate(
    committee: &TestCommittee,
    voter_indices: &[usize],
    tx_hash: Hash,
    merkle_root: Hash,
    shard: ShardGroupId,
    success: bool,
) -> StateCertificate {
    let message = exec_vote_message(&tx_hash, &merkle_root, shard, success);

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

    StateCertificate {
        transaction_hash: tx_hash,
        shard_group_id: shard,
        read_nodes: vec![],
        state_writes: vec![],
        outputs_merkle_root: merkle_root,
        success,
        aggregated_signature,
        signers,
        voting_power: voter_indices.len() as u64,
    }
}

/// Create a properly-signed state provision.
///
/// The provision is signed with the keypair at `validator_idx` in the committee.
#[allow(clippy::too_many_arguments)]
pub fn make_signed_provision(
    committee: &TestCommittee,
    validator_idx: usize,
    tx_hash: Hash,
    target_shard: ShardGroupId,
    source_shard: ShardGroupId,
    block_height: BlockHeight,
    block_timestamp: u64,
    entries: Vec<StateEntry>,
) -> StateProvision {
    // Compute entry hashes for signing
    let entry_hashes: Vec<Hash> = entries.iter().map(|e| e.hash()).collect();

    let message = state_provision_message(
        &tx_hash,
        target_shard,
        source_shard,
        block_height,
        block_timestamp,
        &entry_hashes,
    );
    let signature = committee.keypair(validator_idx).sign_v1(&message);

    StateProvision {
        transaction_hash: tx_hash,
        target_shard,
        source_shard,
        block_height,
        block_timestamp,
        entries: Arc::new(entries),
        validator_id: committee.validator_id(validator_idx),
        signature,
    }
}

/// Verify a block vote signature.
///
/// Convenience function for tests.
pub fn verify_block_vote(
    vote: &BlockVote,
    public_key: &Bls12381G1PublicKey,
    shard: ShardGroupId,
) -> bool {
    let message = block_vote_message(shard, vote.height.0, vote.round, &vote.block_hash);
    verify_bls12381_v1(&message, public_key, &vote.signature)
}

/// Verify a QC's aggregated signature.
///
/// Aggregates the public keys of signers and verifies against the aggregated signature.
pub fn verify_qc(qc: &QuorumCertificate, committee: &TestCommittee, shard: ShardGroupId) -> bool {
    let message = block_vote_message(shard, qc.height.0, qc.round, &qc.block_hash);

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

/// Verify a state vote signature.
pub fn verify_state_vote(vote: &StateVoteBlock, public_key: &Bls12381G1PublicKey) -> bool {
    let message = vote.signing_message();
    verify_bls12381_v1(&message, public_key, &vote.signature)
}

/// Verify a state certificate's aggregated signature.
pub fn verify_state_certificate(cert: &StateCertificate, committee: &TestCommittee) -> bool {
    let message = cert.signing_message();

    // Collect signer public keys
    let signer_keys: Vec<Bls12381G1PublicKey> = cert
        .signers
        .set_indices()
        .map(|idx| *committee.public_key(idx))
        .collect();

    if signer_keys.is_empty() {
        return false;
    }

    // Aggregate and verify
    match Bls12381G1PublicKey::aggregate(&signer_keys, true) {
        Ok(agg_pk) => verify_bls12381_v1(&message, &agg_pk, &cert.aggregated_signature),
        Err(_) => false,
    }
}

/// Verify a state provision signature.
pub fn verify_provision(provision: &StateProvision, public_key: &Bls12381G1PublicKey) -> bool {
    let message = provision.signing_message();
    verify_bls12381_v1(&message, public_key, &provision.signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::NodeId;

    #[test]
    fn test_signed_block_vote() {
        let committee = TestCommittee::new(4, 42);
        let block_hash = Hash::from_bytes(b"test_block");
        let shard = ShardGroupId(0);

        let vote = make_signed_block_vote(&committee, 0, block_hash, BlockHeight(1), 0, shard);

        // Should verify with correct key
        assert!(verify_block_vote(&vote, committee.public_key(0), shard));

        // Should not verify with wrong key
        assert!(!verify_block_vote(&vote, committee.public_key(1), shard));
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

        assert!(verify_qc(&qc, &committee, shard));
        assert_eq!(qc.signer_count(), 3);
        assert_eq!(qc.voting_power.0, 3);
    }

    #[test]
    fn test_signed_state_vote() {
        let committee = TestCommittee::new(4, 42);
        let tx_hash = Hash::from_bytes(b"tx");
        let state_root = Hash::from_bytes(b"state");
        let shard = ShardGroupId(0);

        let vote = make_signed_state_vote(&committee, 0, tx_hash, state_root, shard, true);

        // Should verify with correct key
        assert!(verify_state_vote(&vote, committee.public_key(0)));

        // Should not verify with wrong key
        assert!(!verify_state_vote(&vote, committee.public_key(1)));
    }

    #[test]
    fn test_signed_state_certificate() {
        let committee = TestCommittee::new(4, 42);
        let tx_hash = Hash::from_bytes(b"tx");
        let merkle_root = Hash::from_bytes(b"merkle");
        let shard = ShardGroupId(0);

        let cert = make_signed_state_certificate(
            &committee,
            &[0, 1, 2],
            tx_hash,
            merkle_root,
            shard,
            true,
        );

        assert!(verify_state_certificate(&cert, &committee));
        assert_eq!(cert.signer_count(), 3);
    }

    #[test]
    fn test_signed_provision() {
        let committee = TestCommittee::new(4, 42);
        let tx_hash = Hash::from_bytes(b"tx");
        let entries = vec![StateEntry::test_entry(
            NodeId([1u8; 30]),
            1,
            vec![1, 2, 3],
            Some(vec![4, 5, 6]),
        )];

        let provision = make_signed_provision(
            &committee,
            0,
            tx_hash,
            ShardGroupId(1),
            ShardGroupId(0),
            BlockHeight(10),
            1000, // block_timestamp
            entries,
        );

        // Should verify with correct key
        assert!(verify_provision(&provision, committee.public_key(0)));

        // Should not verify with wrong key
        assert!(!verify_provision(&provision, committee.public_key(1)));
    }
}
