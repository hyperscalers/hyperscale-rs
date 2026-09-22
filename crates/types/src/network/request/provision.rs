//! Provision fetch request.

use hyperscale_hbor::{Capped, Hbor};

use crate::network::response::GetProvisionResponse;
use crate::{
    BlockHeight, MAX_PROOFS_PER_QUERY, MessageClass, NetworkMessage, Request, ShardId, SubstateKey,
};

/// What a provisions request asks for, and so what anchor its answer
/// stands at.
///
/// Two questions on one channel, because both are answered by building a
/// bundle and both ride into a block the same way — what differs is only
/// what fixes the reading.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub enum Anchored {
    /// Everything a source block promised this target, at that block's
    /// own height.
    ///
    /// The push's fallback: a remote block's `ticks` named this shard
    /// and no provisions arrived, so the bundle is rebuilt from the
    /// block that owed it. The height fixes the reading, and the
    /// producing header's `provision_tx_roots` says what a complete
    /// answer is.
    Block(BlockHeight),
    /// The cells named, at an anchor of the source's that the asker has
    /// already commit-proven.
    ///
    /// The pull. **Nothing is pinned to a height that can expire**,
    /// which is the property this exists for — but the height is the
    /// *asker's* newest proven anchor rather than the block that issued
    /// the crossing, so it moves forward as the asker proves more and
    /// never ages out from under it.
    ///
    /// It cannot be the source's own tip, however fresh that would be. A
    /// bundle is verified against a header, and only a commit-proven one
    /// will do: a bare quorum certificate does not establish that the
    /// source canonicalized the block, and an f+1..2f corrupt committee
    /// can certify a sibling that never commits. An asker cannot hold a
    /// commit proof for a tip that only just happened, because such a
    /// proof needs a round-contiguous pair above it.
    ///
    /// A record read here is safe to be slightly behind. The pull serves
    /// the **owed** path, and an owed record is never credited back —
    /// `escrow_settle` refuses a reclaim of one — so its only disposal is
    /// retirement against the asker's own claim, and that claim is what
    /// stops a second delivery. There is no credit to race.
    ///
    /// No promise says what a complete answer is here, and none is
    /// needed: the asker named the keys, so it already knows.
    Records {
        /// The source height to read at, which the asker holds a commit
        /// proof for.
        at: BlockHeight,
        /// The record cells wanted.
        keys: Capped<Vec<SubstateKey>, MAX_PROOFS_PER_QUERY>,
    },
}

/// Request to fetch provisions from a source shard.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetProvisionsRequest {
    /// What is being asked for, and the anchor that fixes the answer.
    pub asks: Anchored,
    /// The shard requesting provisions (so the source knows which
    /// state entries to include in the response).
    pub target_shard: ShardId,
}

impl GetProvisionsRequest {
    /// Rebuild what the block at `height` owed `target_shard`.
    #[must_use]
    pub const fn at_block(height: BlockHeight, target_shard: ShardId) -> Self {
        Self {
            asks: Anchored::Block(height),
            target_shard,
        }
    }

    /// Read `keys` at `at`, a source height the asker has commit-proven.
    #[must_use]
    pub const fn for_records(
        at: BlockHeight,
        keys: Capped<Vec<SubstateKey>, MAX_PROOFS_PER_QUERY>,
        target_shard: ShardId,
    ) -> Self {
        Self {
            asks: Anchored::Records { at, keys },
            target_shard,
        }
    }
}

impl NetworkMessage for GetProvisionsRequest {
    fn message_type_id() -> &'static str {
        "provision.request"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl Request for GetProvisionsRequest {
    type Response = GetProvisionResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.provisions.is_none()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{Address, AddressClass, LocalKey};

    fn key(tag: u8) -> SubstateKey {
        SubstateKey {
            owner: Address::new([tag; 31], AddressClass::Component),
            local: LocalKey([tag; 16]),
        }
    }

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetProvisionsRequest::at_block(BlockHeight::new(42), ShardId::ROOT);
        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetProvisionsRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn a_pull_names_its_keys_and_a_proven_anchor() {
        let request = GetProvisionsRequest::for_records(
            BlockHeight::new(7),
            Capped::from_array([key(1), key(2)]),
            ShardId::ROOT,
        );
        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetProvisionsRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
        let Anchored::Records { at, keys } = decoded.asks else {
            panic!("a pull names records");
        };
        assert_eq!(at, BlockHeight::new(7));
        assert_eq!(keys.len(), 2);
    }
}
