//! Domain-separated signing for cryptographic operations.
//!
//! This module provides type-safe domain separation tags for all signed messages
//! in the consensus protocol. Domain separation prevents cross-protocol attacks
//! where a signature from one context could be replayed in another.
//!
//! # Domain Tags
//!
//! Each signable message type has a unique domain tag prefix:
//!
//! | Tag | Purpose |
//! |-----|---------|
//! | `BLOCK_VOTE` | BFT block votes |
//! | `EXEC_VOTE` | Execution votes |
//! | `COMMITTED_BLOCK_HEADER` | Committed block header gossip |
//! | `BLOCK_HEADER` | Block header proposal gossip |
//! | `VALIDATOR_BIND` | Validator-bind PeerId authentication |
//!
//! # Usage
//!
//! Types that need signing should implement the `Signable` trait or use the
//! `signing_message()` method pattern. The signing message is constructed
//! by prepending the domain tag to the serialized content.

use crate::{BlockHeight, Hash, ShardGroupId, StateProvision, WaveId};

/// Domain tag for BFT block votes.
///
/// Format: `BLOCK_VOTE` || shard_group_id || height || round || block_hash
pub const DOMAIN_BLOCK_VOTE: &[u8] = b"BLOCK_VOTE";

/// Domain tag for committed block header gossip.
///
/// Format: `COMMITTED_BLOCK_HEADER` || shard_group_id || height || block_hash
///
/// Signed by the sender (proposer) when broadcasting committed block headers
/// globally. Verified by IoLoop before admitting to the state machine.
pub const DOMAIN_COMMITTED_BLOCK_HEADER: &[u8] = b"COMMITTED_BLOCK_HEADER";

/// Build the signing message for a block vote.
///
/// This is used for:
/// - Individual block vote signatures
/// - QC aggregated signature verification
/// - View change highest_qc verification
pub fn block_vote_message(
    shard_group: ShardGroupId,
    height: u64,
    round: u64,
    block_hash: &Hash,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(80);
    message.extend_from_slice(DOMAIN_BLOCK_VOTE);
    message.extend_from_slice(&shard_group.0.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(&round.to_le_bytes());
    message.extend_from_slice(block_hash.as_bytes());
    message
}

/// Build the signing message for a committed block header gossip.
///
/// This is used for verifying the sender's signature on globally broadcast
/// committed block headers before admitting them to the state machine.
pub fn committed_block_header_message(
    shard_group_id: ShardGroupId,
    height: u64,
    block_hash: &Hash,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(DOMAIN_COMMITTED_BLOCK_HEADER);
    message.extend_from_slice(&shard_group_id.0.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(block_hash.as_bytes());
    message
}

/// Domain tag for block header proposal gossip.
///
/// Format: `BLOCK_HEADER` || shard_group_id || height || round || block_hash
///
/// Signed by the proposer when broadcasting block header proposals.
/// Verified by receivers before admitting the proposal into BFT.
/// Distinct from `DOMAIN_BLOCK_VOTE` to prevent cross-protocol replay.
pub const DOMAIN_BLOCK_HEADER: &[u8] = b"BLOCK_HEADER";

/// Build the signing message for a block header proposal.
///
/// This is used for:
/// - Proposer signature on BlockHeaderNotification (authenticated proposals)
/// - Verification before admitting proposals to the BFT state machine
pub fn block_header_message(
    shard_group: ShardGroupId,
    height: u64,
    round: u64,
    block_hash: &Hash,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(80);
    message.extend_from_slice(DOMAIN_BLOCK_HEADER);
    message.extend_from_slice(&shard_group.0.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(&round.to_le_bytes());
    message.extend_from_slice(block_hash.as_bytes());
    message
}

/// Domain tag for state provision batch gossip.
///
/// Format: `STATE_PROVISION_BATCH` || source_shard || target_shard || block_height || H(tx_hashes)
///
/// Signed by the sender when broadcasting cross-shard state provisions.
/// Verified by receivers to reject unauthenticated provision spam before
/// doing expensive merkle proof verification.
pub const DOMAIN_STATE_PROVISION_BATCH: &[u8] = b"STATE_PROVISION_BATCH";

/// Build the signing message for a state provision batch gossip.
///
/// The message covers source shard, target shard, block height, and a
/// digest of the transaction hashes in the batch. This is cheap to
/// reconstruct at verification (no re-serialization needed) while binding
/// the signature to the specific batch contents.
pub fn state_provision_batch_message(
    source_shard: ShardGroupId,
    target_shard: ShardGroupId,
    block_height: BlockHeight,
    provisions: &[StateProvision],
) -> Vec<u8> {
    // Hash the concatenated transaction hashes to produce a batch digest.
    let mut hasher = blake3::Hasher::new();
    for p in provisions {
        hasher.update(p.transaction_hash.as_bytes());
    }
    let tx_digest = hasher.finalize();

    let mut message = Vec::with_capacity(96);
    message.extend_from_slice(DOMAIN_STATE_PROVISION_BATCH);
    message.extend_from_slice(&source_shard.0.to_le_bytes());
    message.extend_from_slice(&target_shard.0.to_le_bytes());
    message.extend_from_slice(&block_height.0.to_le_bytes());
    message.extend_from_slice(tx_digest.as_bytes());
    message
}

/// Domain tag for validator-bind protocol.
///
/// Format: `VALIDATOR_BIND` || peer_id_bytes
///
/// Signed by a validator's BLS key to cryptographically bind their
/// consensus identity (ValidatorId) to their ephemeral libp2p PeerId.
/// Verified by peers using the BLS public key from the topology.
pub const DOMAIN_VALIDATOR_BIND: &[u8] = b"VALIDATOR_BIND";

/// Build the signing message for the validator-bind protocol.
///
/// The message binds a validator's BLS identity to their ephemeral libp2p PeerId.
/// The Noise handshake proves PeerId ownership; this signature proves the BLS key
/// holder authorised that PeerId.
pub fn validator_bind_message(peer_id_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN_VALIDATOR_BIND.len() + peer_id_bytes.len());
    message.extend_from_slice(DOMAIN_VALIDATOR_BIND);
    message.extend_from_slice(peer_id_bytes);
    message
}

/// Domain tag for execution votes.
///
/// Format: `EXEC_VOTE` || block_hash || block_height || wave_id_len || wave_id_shards... || shard_group || global_receipt_root || tx_count
///
/// Used for both individual `ExecutionVote` signatures and
/// `ExecutionCertificate` aggregated signature verification.
pub const DOMAIN_EXEC_VOTE: &[u8] = b"EXEC_VOTE";

/// Domain tag for execution vote batch gossip.
///
/// Format: `EXEC_VOTE_BATCH` || shard_group_id || H(global_receipt_roots)
pub const DOMAIN_EXEC_VOTE_BATCH: &[u8] = b"EXEC_VOTE_BATCH";

/// Domain tag for execution certificate batch gossip.
///
/// Format: `EXEC_CERT_BATCH` || shard_group_id || H(global_receipt_roots)
pub const DOMAIN_EXEC_CERT_BATCH: &[u8] = b"EXEC_CERT_BATCH";

/// Build the signing message for an execution vote.
///
/// This is used for:
/// - Individual `ExecutionVote` signatures
/// - `ExecutionCertificate` aggregated signature verification
///
/// The wave_id is serialized as length-prefixed sorted shard IDs, making
/// the message deterministic regardless of construction order.
pub fn exec_vote_message(
    vote_anchor_ts_ms: crate::WeightedTimestamp,
    wave_id: &WaveId,
    shard_group: ShardGroupId,
    global_receipt_root: &Hash,
    tx_count: u32,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(128);
    message.extend_from_slice(DOMAIN_EXEC_VOTE);
    message.extend_from_slice(&vote_anchor_ts_ms.as_millis().to_le_bytes());
    // WaveId is self-contained (shard + block_height + remote_shards),
    // so no separate block_hash needed in the signing message.
    message.extend_from_slice(&wave_id.shard_group_id.0.to_le_bytes());
    message.extend_from_slice(&wave_id.block_height.to_le_bytes());
    message.extend_from_slice(&(wave_id.remote_shards.len() as u32).to_le_bytes());
    for shard in &wave_id.remote_shards {
        message.extend_from_slice(&shard.0.to_le_bytes());
    }
    message.extend_from_slice(&shard_group.0.to_le_bytes());
    message.extend_from_slice(global_receipt_root.as_bytes());
    message.extend_from_slice(&tx_count.to_le_bytes());
    message
}

/// Build the signing message for an execution vote batch gossip.
pub fn exec_vote_batch_message(
    shard_group: ShardGroupId,
    votes: &[crate::ExecutionVote],
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    for v in votes {
        hasher.update(v.global_receipt_root.as_bytes());
    }
    let digest = hasher.finalize();

    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(DOMAIN_EXEC_VOTE_BATCH);
    message.extend_from_slice(&shard_group.0.to_le_bytes());
    message.extend_from_slice(digest.as_bytes());
    message
}

/// Build the signing message for an execution certificate batch gossip.
pub fn exec_cert_batch_message(
    shard_group: ShardGroupId,
    certificates: &[crate::ExecutionCertificate],
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    for c in certificates {
        hasher.update(c.global_receipt_root.as_bytes());
    }
    let digest = hasher.finalize();

    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(DOMAIN_EXEC_CERT_BATCH);
    message.extend_from_slice(&shard_group.0.to_le_bytes());
    message.extend_from_slice(digest.as_bytes());
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_vote_message_deterministic() {
        let shard = ShardGroupId(1);
        let block = Hash::from_bytes(b"test_block");

        let msg1 = block_vote_message(shard, 10, 0, &block);
        let msg2 = block_vote_message(shard, 10, 0, &block);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_BLOCK_VOTE));
    }

    #[test]
    fn test_committed_block_header_message_deterministic() {
        let shard = ShardGroupId(1);
        let block = Hash::from_bytes(b"test_block");

        let msg1 = committed_block_header_message(shard, 10, &block);
        let msg2 = committed_block_header_message(shard, 10, &block);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_COMMITTED_BLOCK_HEADER));
    }

    #[test]
    fn test_block_header_message_deterministic() {
        let shard = ShardGroupId(1);
        let block = Hash::from_bytes(b"test_block");

        let msg1 = block_header_message(shard, 10, 0, &block);
        let msg2 = block_header_message(shard, 10, 0, &block);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_BLOCK_HEADER));
    }

    #[test]
    fn test_block_header_differs_from_block_vote() {
        let shard = ShardGroupId(1);
        let block = Hash::from_bytes(b"test_block");

        let header_msg = block_header_message(shard, 10, 0, &block);
        let vote_msg = block_vote_message(shard, 10, 0, &block);

        // Must differ due to different domain tags (prevents cross-protocol replay)
        assert_ne!(header_msg, vote_msg);
    }

    #[test]
    fn test_state_provision_batch_message_deterministic() {
        use crate::StateProvision;
        use std::sync::Arc;

        let provisions = vec![StateProvision {
            transaction_hash: Hash::from_bytes(b"tx1"),
            target_shard: ShardGroupId(2),
            source_shard: ShardGroupId(1),
            block_height: BlockHeight(10),
            entries: Arc::new(vec![]),
        }];

        let msg1 = state_provision_batch_message(
            ShardGroupId(1),
            ShardGroupId(2),
            BlockHeight(10),
            &provisions,
        );
        let msg2 = state_provision_batch_message(
            ShardGroupId(1),
            ShardGroupId(2),
            BlockHeight(10),
            &provisions,
        );

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_STATE_PROVISION_BATCH));
    }

    #[test]
    fn test_validator_bind_message_deterministic() {
        let peer_id = b"12D3KooWDummyPeerId000000000000000";

        let msg1 = validator_bind_message(peer_id);
        let msg2 = validator_bind_message(peer_id);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_VALIDATOR_BIND));
    }

    #[test]
    fn test_validator_bind_differs_from_other_domains() {
        let bytes = b"some_bytes_here_for_testing_1234";

        let bind_msg = validator_bind_message(bytes);
        let block_msg = block_vote_message(ShardGroupId(0), 0, 0, &Hash::from_bytes(bytes));

        assert_ne!(bind_msg, block_msg);
    }
}
