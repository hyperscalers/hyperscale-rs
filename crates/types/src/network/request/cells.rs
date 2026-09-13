//! Request for the cells a declaration names, proven at a committed
//! height.
//!
//! What a preview needs of a shard it does not serve. A declaration
//! reaches point cells by key and collection entries by interval, and a
//! preview has to run against both — so this asks for both at once and
//! is answered with one multiproof over everything it returned.
//!
//! Distinct from [`GetStateProofRequest`](super::GetStateProofRequest),
//! which proves named keys and nothing else, and from
//! [`GetStateRangeRequest`](super::GetStateRangeRequest), which hands a
//! joining vnode a raw leaf byte interval at a pinned epoch boundary.
//! This one is in the declaration's own terms — an owner, a collection
//! and an order interval — at whatever committed height the server has.
//!
//! The requester checks the answer against the state root of a header it
//! already commit-proved, so any node of the shard may serve and none is
//! trusted. See
//! [`GetCellsResponse`](crate::network::response::GetCellsResponse) for
//! what a served answer does and does not attest.

use hyperscale_hbor::Hbor;

use crate::network::response::GetCellsResponse;
use crate::{
    Address, BlockHeight, CollectionId, MAX_PROOFS_PER_QUERY, MessageClass, NetworkMessage,
    Request, SubstateKey,
};

/// The most intervals one request may name.
///
/// The same bound the keys carry, for the same reason: a request is
/// answered by walking the tree once per leaf it reaches, and a
/// declaration wide enough to need more than this was refused before a
/// preview of it ran.
pub const MAX_RANGES_PER_QUERY: usize = MAX_PROOFS_PER_QUERY;

/// One collection interval a declaration reaches, in the terms the
/// declaration states it in.
///
/// `cap` is the declaration's own, and it is signed — the transaction
/// paid for `(cap + 1) × width` read bytes before this was asked — so
/// the server needs no bound of its own beyond the frame.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct CellRange {
    /// The collection's owner, which fixes the shard that answers.
    pub owner: Address,
    /// The collection under that owner.
    pub collection: CollectionId,
    /// The first order in the interval, inclusive.
    pub lo: u128,
    /// The last order in the interval, inclusive.
    pub hi: u128,
    /// The most entries the declaration may read out of it.
    pub cap: u32,
}

/// The point cells and intervals to answer, and the committed height to
/// answer them at.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetCellsRequest {
    /// The committed height whose state root the proof reconstructs.
    pub height: BlockHeight,
    /// Point cells to answer, present or absent.
    #[hbor(max = MAX_PROOFS_PER_QUERY)]
    pub keys: Vec<SubstateKey>,
    /// Collection intervals to answer.
    #[hbor(max = MAX_RANGES_PER_QUERY)]
    pub ranges: Vec<CellRange>,
}

impl GetCellsRequest {
    /// A request for `keys` and `ranges` at `height`.
    #[must_use]
    pub const fn new(height: BlockHeight, keys: Vec<SubstateKey>, ranges: Vec<CellRange>) -> Self {
        Self {
            height,
            keys,
            ranges,
        }
    }
}

impl NetworkMessage for GetCellsRequest {
    fn message_type_id() -> &'static str {
        "cells.request"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl Request for GetCellsRequest {
    type Response = GetCellsResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.proof.is_none()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::test_utils::{test_key, test_prefix};

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetCellsRequest::new(
            BlockHeight::new(42),
            vec![test_key(7)],
            vec![CellRange {
                owner: test_prefix(3),
                collection: CollectionId([0xEE; 16]),
                lo: 0,
                hi: u128::MAX,
                cap: 64,
            }],
        );
        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetCellsRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
