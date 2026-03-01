//! Crash recovery tests.
//!
//! Tests that verify the system correctly handles crash recovery scenarios,
//! particularly around vote persistence and chain metadata recovery.

use hyperscale_bft::RecoveredState;
use hyperscale_types::Hash;
use std::collections::HashMap;

/// Test that recovered votes prevent equivocation after restart.
#[test]
fn test_recovered_votes_prevent_equivocation() {
    use hyperscale_bft::{BftConfig, BftState};
    use hyperscale_types::{
        generate_bls_keypair, zero_bls_signature, BlockHeader, BlockHeight, Bls12381G1PrivateKey,
        QuorumCertificate, ShardGroupId, SignerBitfield, StaticTopology, ValidatorId,
        ValidatorInfo, ValidatorSet, VotePower,
    };
    use std::sync::Arc;
    use std::time::Duration;

    // Create keys for 4 validators
    let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();

    let validators: Vec<ValidatorInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| ValidatorInfo {
            validator_id: ValidatorId(i as u64),
            public_key: k.public_key(),
            voting_power: 1,
        })
        .collect();
    let validator_set = ValidatorSet::new(validators);
    let topology = Arc::new(StaticTopology::new(ValidatorId(1), 1, validator_set));

    // Simulate: We previously voted for block_a at height 5
    let block_a_hash = Hash::from_bytes(b"block_a_at_height_5_aaaaaaa");
    let mut recovered_votes = HashMap::new();
    recovered_votes.insert(5u64, (block_a_hash, 0u64)); // height 5, round 0

    let recovered = RecoveredState {
        voted_heights: recovered_votes,
        committed_height: 3, // Committed up to height 3
        committed_hash: Some(Hash::from_bytes(b"committed_at_3_aaaaaaaaaaaa")),
        latest_qc: None,
        jmt_state: None, // Fresh start for simulation test
    };

    let mut state = BftState::new(
        1,
        {
            let key_bytes = keys[1].to_bytes();
            Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
        },
        topology,
        BftConfig::default(),
        recovered,
    );
    state.set_time(Duration::from_secs(100));

    // Now try to vote for a DIFFERENT block at the same height (5)
    // This should be rejected because we already voted for block_a at height 5
    let _block_b_hash = Hash::from_bytes(b"block_b_at_height_5_bbbbbbb");

    // Create a block header for block_b at height 5
    let mut signers = SignerBitfield::new(4);
    signers.set(0);
    signers.set(1);
    signers.set(2);

    let parent_hash = Hash::from_bytes(b"parent_at_4_aaaaaaaaaaaaaaa");
    let parent_qc = QuorumCertificate {
        block_hash: parent_hash,
        shard_group_id: ShardGroupId(0),
        height: BlockHeight(4),
        parent_block_hash: Hash::from_bytes(b"grandparent_3_aaaaaaaaaaa"),
        round: 0,
        signers: signers.clone(),
        aggregated_signature: zero_bls_signature(),
        voting_power: VotePower(3),
        weighted_timestamp_ms: 99000,
    };

    let header_b = BlockHeader {
        height: BlockHeight(5),
        parent_hash,
        parent_qc,
        proposer: ValidatorId(0),
        timestamp: 100000,
        round: 0,
        is_fallback: false,
        state_root: Hash::ZERO,
        state_version: 0,
        transaction_root: Hash::ZERO,
    };

    // Compute block hash before moving header
    let header_b_hash = header_b.hash();

    // Process this block - it should NOT result in a vote because we already voted at height 5
    let actions = state.on_block_header(
        header_b,
        vec![], // retry_hashes
        vec![], // priority_hashes
        vec![], // tx_hashes
        vec![], // cert_hashes
        vec![], // deferred
        vec![], // aborted
        HashMap::new(),
        &HashMap::new(),
        &HashMap::new(),
    );

    // Check that no vote was broadcast
    let voted = actions
        .iter()
        .any(|a| matches!(a, hyperscale_core::Action::BroadcastBlockVote { .. }));

    // We might get a VerifyQcSignature action first, so let's simulate that verification
    // and then check if vote is created
    let verify_action = actions
        .iter()
        .find(|a| matches!(a, hyperscale_core::Action::VerifyQcSignature { .. }));

    if verify_action.is_some() {
        // Simulate QC verification success - but with the correct block hash
        let vote_actions = state.on_qc_signature_verified(header_b_hash, true);

        // Should NOT vote because we already voted at this height for a DIFFERENT block
        let voted_after_verify = vote_actions
            .iter()
            .any(|a| matches!(a, hyperscale_core::Action::BroadcastBlockVote { .. }));

        assert!(
            !voted_after_verify,
            "Should NOT vote for different block at same height after recovery"
        );
    } else {
        // If no QC verification needed (genesis case), check directly
        assert!(
            !voted,
            "Should NOT vote for different block at same height after recovery"
        );
    }
}

/// Test that stale votes (below committed height) are pruned during recovery.
#[test]
fn test_stale_votes_pruned_on_recovery() {
    use hyperscale_bft::{BftConfig, BftState};
    use hyperscale_types::{
        generate_bls_keypair, Bls12381G1PrivateKey, StaticTopology, ValidatorId, ValidatorInfo,
        ValidatorSet,
    };
    use std::sync::Arc;

    let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();

    let validators: Vec<ValidatorInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| ValidatorInfo {
            validator_id: ValidatorId(i as u64),
            public_key: k.public_key(),
            voting_power: 1,
        })
        .collect();
    let validator_set = ValidatorSet::new(validators);
    let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));

    // Simulate votes at heights 1, 2, 3, 5, 7
    let mut recovered_votes = HashMap::new();
    recovered_votes.insert(1, (Hash::from_bytes(b"block_1_aaaaaaaaaaaaaaaaaaaa"), 0));
    recovered_votes.insert(2, (Hash::from_bytes(b"block_2_aaaaaaaaaaaaaaaaaaaa"), 0));
    recovered_votes.insert(3, (Hash::from_bytes(b"block_3_aaaaaaaaaaaaaaaaaaaa"), 0));
    recovered_votes.insert(5, (Hash::from_bytes(b"block_5_aaaaaaaaaaaaaaaaaaaa"), 0));
    recovered_votes.insert(7, (Hash::from_bytes(b"block_7_aaaaaaaaaaaaaaaaaaaa"), 0));

    let recovered = RecoveredState {
        voted_heights: recovered_votes,
        committed_height: 4, // Committed up to height 4
        committed_hash: Some(Hash::from_bytes(b"committed_at_4_aaaaaaaaaaaa")),
        latest_qc: None,
        jmt_state: None, // Fresh start for simulation test
    };

    let state = BftState::new(
        0,
        {
            let key_bytes = keys[0].to_bytes();
            Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
        },
        topology,
        BftConfig::default(),
        recovered,
    );

    // Votes at heights 1, 2, 3 should be pruned (at or below committed_height 4)
    // Votes at heights 5, 7 should remain
    assert!(
        !state.voted_heights().contains_key(&1),
        "Vote at height 1 should be pruned"
    );
    assert!(
        !state.voted_heights().contains_key(&2),
        "Vote at height 2 should be pruned"
    );
    assert!(
        !state.voted_heights().contains_key(&3),
        "Vote at height 3 should be pruned"
    );
    assert!(
        !state.voted_heights().contains_key(&4),
        "Vote at height 4 should be pruned (equal to committed)"
    );
    assert!(
        state.voted_heights().contains_key(&5),
        "Vote at height 5 should remain"
    );
    assert!(
        state.voted_heights().contains_key(&7),
        "Vote at height 7 should remain"
    );
}

/// Test that chain metadata is correctly restored from RecoveredState.
#[test]
fn test_chain_metadata_recovery() {
    use hyperscale_bft::{BftConfig, BftState};
    use hyperscale_types::{
        generate_bls_keypair, zero_bls_signature, BlockHeight, Bls12381G1PrivateKey,
        QuorumCertificate, ShardGroupId, SignerBitfield, StaticTopology, ValidatorId,
        ValidatorInfo, ValidatorSet, VotePower,
    };
    use std::sync::Arc;

    let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();

    let validators: Vec<ValidatorInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| ValidatorInfo {
            validator_id: ValidatorId(i as u64),
            public_key: k.public_key(),
            voting_power: 1,
        })
        .collect();
    let validator_set = ValidatorSet::new(validators);
    let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));

    let committed_hash = Hash::from_bytes(b"committed_block_hash_aaaaaa");
    let mut signers = SignerBitfield::new(4);
    signers.set(0);
    signers.set(1);
    signers.set(2);

    let latest_qc = QuorumCertificate {
        block_hash: committed_hash,
        shard_group_id: ShardGroupId(0),
        height: BlockHeight(10),
        parent_block_hash: Hash::from_bytes(b"parent_block_hash_aaaaaaaa"),
        round: 0,
        signers,
        aggregated_signature: zero_bls_signature(),
        voting_power: VotePower(3),
        weighted_timestamp_ms: 12345,
    };

    let recovered = RecoveredState {
        voted_heights: HashMap::new(),
        committed_height: 10,
        committed_hash: Some(committed_hash),
        latest_qc: Some(latest_qc.clone()),
        jmt_state: None, // Fresh start for simulation test
    };

    let state = BftState::new(
        0,
        {
            let key_bytes = keys[0].to_bytes();
            Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
        },
        topology,
        BftConfig::default(),
        recovered,
    );

    // Verify chain state was restored
    assert_eq!(state.committed_height(), 10);
    assert_eq!(state.committed_hash(), committed_hash);
    assert!(state.latest_qc().is_some());
    assert_eq!(state.latest_qc().unwrap().height, BlockHeight(10));
}

/// Test fresh start with default RecoveredState.
#[test]
fn test_fresh_start_with_default_recovered_state() {
    use hyperscale_bft::{BftConfig, BftState};
    use hyperscale_types::{
        generate_bls_keypair, Bls12381G1PrivateKey, StaticTopology, ValidatorId, ValidatorInfo,
        ValidatorSet,
    };
    use std::sync::Arc;

    let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();

    let validators: Vec<ValidatorInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| ValidatorInfo {
            validator_id: ValidatorId(i as u64),
            public_key: k.public_key(),
            voting_power: 1,
        })
        .collect();
    let validator_set = ValidatorSet::new(validators);
    let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));

    // Fresh start - no recovered state
    let state = BftState::new(
        0,
        {
            let key_bytes = keys[0].to_bytes();
            Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
        },
        topology,
        BftConfig::default(),
        RecoveredState::default(),
    );

    assert_eq!(state.committed_height(), 0);
    assert!(state.latest_qc().is_none());
    assert!(state.voted_heights().is_empty());
}
