//! Domain-separated signing for execution votes and certificate gossip.

use blake3::Hasher;

use crate::{
    ExecutionCertificate, ExecutionVote, GlobalReceiptRoot, NetworkDefinition, ShardGroupId,
    WaveId, WeightedTimestamp,
};

/// Domain tag for execution votes.
///
/// Format: `EXEC_VOTE` || `network.id` || `vote_anchor_ts` || `wave_id_shard`
/// || `wave_id_height` || `wave_id_remote_shards_len` ||
/// `wave_id_remote_shards`... || `shard_group` || `global_receipt_root` ||
/// `tx_count`
///
/// Used for both individual `ExecutionVote` signatures and
/// `ExecutionCertificate` aggregated signature verification.
pub const DOMAIN_EXEC_VOTE: &[u8] = b"EXEC_VOTE";

/// Domain tag for execution vote batch gossip.
///
/// Format: `EXEC_VOTE_BATCH` || `network.id` || `shard_group_id` ||
/// `H(global_receipt_roots)`
pub const DOMAIN_EXEC_VOTE_BATCH: &[u8] = b"EXEC_VOTE_BATCH";

/// Domain tag for execution certificate batch gossip.
///
/// Format: `EXEC_CERT_BATCH` || `network.id` || `shard_group_id` ||
/// `H(global_receipt_roots)`
pub const DOMAIN_EXEC_CERT_BATCH: &[u8] = b"EXEC_CERT_BATCH";

/// Build the signing message for an execution vote.
///
/// This is used for:
/// - Individual `ExecutionVote` signatures
/// - `ExecutionCertificate` aggregated signature verification
///
/// The `wave_id` is serialized as length-prefixed sorted shard IDs, making
/// the message deterministic regardless of construction order.
#[must_use]
pub fn exec_vote_message(
    network: &NetworkDefinition,
    vote_anchor_ts: WeightedTimestamp,
    wave_id: &WaveId,
    shard_group: ShardGroupId,
    global_receipt_root: &GlobalReceiptRoot,
    tx_count: u32,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(129);
    message.extend_from_slice(DOMAIN_EXEC_VOTE);
    message.push(network.id);
    message.extend_from_slice(&vote_anchor_ts.as_millis().to_le_bytes());
    // WaveId is self-contained (shard + block_height + remote_shards),
    // so no separate block_hash needed in the signing message.
    message.extend_from_slice(&wave_id.shard_group_id().to_le_bytes());
    message.extend_from_slice(&wave_id.block_height().to_le_bytes());
    message.extend_from_slice(
        &u32::try_from(wave_id.remote_shards().len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for shard in wave_id.remote_shards().iter() {
        message.extend_from_slice(&shard.to_le_bytes());
    }
    message.extend_from_slice(&shard_group.to_le_bytes());
    message.extend_from_slice(global_receipt_root.as_raw().as_bytes());
    message.extend_from_slice(&tx_count.to_le_bytes());
    message
}

/// Build the signing message for an execution vote batch gossip.
#[must_use]
pub fn exec_vote_batch_message<'a, I>(
    network: &NetworkDefinition,
    shard_group: ShardGroupId,
    votes: I,
) -> Vec<u8>
where
    I: IntoIterator<Item = &'a ExecutionVote>,
{
    let mut hasher = Hasher::new();
    for v in votes {
        hasher.update(v.global_receipt_root().as_raw().as_bytes());
    }
    let digest = hasher.finalize();

    let mut message = Vec::with_capacity(65);
    message.extend_from_slice(DOMAIN_EXEC_VOTE_BATCH);
    message.push(network.id);
    message.extend_from_slice(&shard_group.to_le_bytes());
    message.extend_from_slice(digest.as_bytes());
    message
}

/// Build the signing message for an execution certificate batch gossip.
#[must_use]
pub fn exec_cert_batch_message(
    network: &NetworkDefinition,
    shard_group: ShardGroupId,
    certificates: &[ExecutionCertificate],
) -> Vec<u8> {
    let mut hasher = Hasher::new();
    for c in certificates {
        hasher.update(c.global_receipt_root().as_raw().as_bytes());
    }
    let digest = hasher.finalize();

    let mut message = Vec::with_capacity(65);
    message.extend_from_slice(DOMAIN_EXEC_CERT_BATCH);
    message.push(network.id);
    message.extend_from_slice(&shard_group.to_le_bytes());
    message.extend_from_slice(digest.as_bytes());
    message
}
