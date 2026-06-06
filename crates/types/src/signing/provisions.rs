//! Domain-separated signing for cross-shard state provisions.

use blake3::Hasher;

use crate::{NetworkDefinition, Provisions};

/// Domain tag for state provisions gossip.
///
/// Format: `STATE_PROVISION_BATCH` || `network.id` || `source_shard` ||
/// `target_shard` || `block_height` || `H(tx_hashes)`
///
/// Signed by the sender when broadcasting cross-shard state provisions.
/// Verified by receivers to reject unauthenticated provision spam before
/// doing expensive merkle proof verification.
pub const DOMAIN_STATE_PROVISION_BATCH: &[u8] = b"STATE_PROVISION_BATCH";

/// Build the signing message for a state provisions gossip.
///
/// The message covers source shard, target shard, block height, and a
/// digest of the transaction hashes in the bundle. Cheap to reconstruct at
/// verification while binding the signature to the specific bundle contents.
#[must_use]
pub fn state_provisions_message(network: &NetworkDefinition, provisions: &Provisions) -> Vec<u8> {
    let mut hasher = Hasher::new();
    for tx in provisions.transactions().iter() {
        hasher.update(tx.tx_hash.as_bytes());
    }
    let tx_digest = hasher.finalize();

    let mut message = Vec::with_capacity(97);
    message.extend_from_slice(DOMAIN_STATE_PROVISION_BATCH);
    message.push(network.id);
    message.extend_from_slice(&provisions.source_shard().to_le_bytes());
    message.extend_from_slice(&provisions.target_shard().to_le_bytes());
    message.extend_from_slice(&provisions.block_height().to_le_bytes());
    message.extend_from_slice(tx_digest.as_bytes());
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockHeight, Hash, MerkleInclusionProof, ProvisionEntry, ShardGroupId, TxHash};

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn test_state_provisions_message_deterministic() {
        let provisions = Provisions::new(
            ShardGroupId::leaf(1, 0),
            ShardGroupId::leaf(1, 1),
            BlockHeight::new(10),
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from_raw(Hash::from_bytes(b"tx1")),
                vec![],
                vec![],
                vec![],
            )],
        );

        let msg1 = state_provisions_message(&net(), &provisions);
        let msg2 = state_provisions_message(&net(), &provisions);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_STATE_PROVISION_BATCH));
    }
}
