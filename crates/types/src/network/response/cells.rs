//! Response to a cells request: the values the declaration reaches and
//! one multiproof over every leaf they came from.
//!
//! # What a served answer attests, and what it does not
//!
//! Every value here is proven present under the height's state root, and
//! every point key the request named but the answer omits is proven
//! absent. A server cannot invent a cell or a value.
//!
//! It can omit an entry from an interval. A collection's order space is
//! not the tree's — an entry leaf commits under a digest of its owner,
//! collection and order — so no non-inclusion proof over the tree says
//! anything about what lies between two orders, and completeness of an
//! interval is not provable this way at all. A preview built on this is
//! optimistic in exactly the sense it already claimed to be: it can be
//! answered with a narrower collection than the chain would execute
//! against, the same way it can lose a race or miss a crossing. What it
//! cannot be answered with is a value nobody wrote.

use hyperscale_hbor::Hbor;
use hyperscale_jmt::MAX_PROOF_CLAIMS;

use crate::network::request::MAX_RANGES_PER_QUERY;
use crate::{
    CertifiedBlockHeader, MAX_CELLS_PER_QUERY, MAX_PROOFS_PER_QUERY, MerkleInclusionProof,
    MessageClass, NetworkMessage, SubstateKey,
};

/// The most entries one interval's answer may carry.
///
/// One interval may legitimately be the whole of what a request spends,
/// so the per-answer bound is the request's own — which is the claim cap
/// a multiproof decodes under, that being what binds
/// [`MAX_CELLS_PER_QUERY`]. What keeps a peer from sending this many
/// under every one of its answers is the frame.
const MAX_ENTRIES_PER_ANSWER: usize = MAX_PROOF_CLAIMS;

/// The per-answer bound is not below the whole request's, or an answer
/// a server may build is one the asker refuses to decode.
const _: () = assert!(MAX_CELLS_PER_QUERY <= MAX_ENTRIES_PER_ANSWER as u64);

/// The entries one requested interval holds at the height, ascending by
/// order.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct RangeAnswer {
    /// The entries found, `(order, value)`, ascending and no more than
    /// the interval's declared cap.
    #[hbor(max = MAX_ENTRIES_PER_ANSWER)]
    pub entries: Vec<(u128, Vec<u8>)>,
}

/// The values, and the proof they stand on, or nothing when the height
/// is not served here.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetCellsResponse {
    /// The point cells that were present, in the request's own order of
    /// keys; a key the tree does not hold is absent from this and proven
    /// so by `proof`.
    #[hbor(max = MAX_PROOFS_PER_QUERY)]
    pub cells: Vec<(SubstateKey, Vec<u8>)>,
    /// One answer per requested interval, positionally.
    #[hbor(max = MAX_RANGES_PER_QUERY)]
    pub ranges: Vec<RangeAnswer>,
    /// A multiproof over every leaf above — the point keys asked, present
    /// or absent, and the entry leaves the intervals returned — against
    /// `anchor`'s state root. `None` when this peer cannot answer at all.
    pub proof: Option<MerkleInclusionProof>,
    /// The certified header the answer stands under: the anchor this
    /// server chose, and the only thing that makes the proof checkable.
    ///
    /// The asker holds no view of this shard's chain, so it cannot name
    /// a height and cannot look one up. What it *does* hold, for every
    /// shard, is the committee — so it verifies this header's quorum
    /// certificate against that committee and then the proof against
    /// this header's root. A server that forges either is answering for
    /// a chain its own committee never signed.
    pub anchor: Option<Box<CertifiedBlockHeader>>,
}

impl GetCellsResponse {
    /// A served answer.
    #[must_use]
    pub fn found(
        cells: Vec<(SubstateKey, Vec<u8>)>,
        ranges: Vec<RangeAnswer>,
        proof: MerkleInclusionProof,
        anchor: CertifiedBlockHeader,
    ) -> Self {
        Self {
            cells,
            ranges,
            proof: Some(proof),
            anchor: Some(Box::new(anchor)),
        }
    }

    /// The height is not served here.
    #[must_use]
    pub const fn not_found() -> Self {
        Self {
            cells: Vec::new(),
            ranges: Vec::new(),
            proof: None,
            anchor: None,
        }
    }
}

impl NetworkMessage for GetCellsResponse {
    fn message_type_id() -> &'static str {
        "cells.response"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::test_utils::test_key;
    use crate::{BlockHeader, BlockHeaderParts, ChainOrigin, QuorumCertificate, ShardId};

    #[test]
    fn test_hbor_roundtrip() {
        for response in [
            GetCellsResponse::not_found(),
            GetCellsResponse::found(
                vec![(test_key(7), vec![1, 2, 3])],
                vec![RangeAnswer {
                    entries: vec![(0, vec![4, 5]), (9, vec![6])],
                }],
                MerkleInclusionProof::new(vec![1, 2, 3]),
                CertifiedBlockHeader::new(
                    BlockHeader::new(BlockHeaderParts::default()),
                    QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::default()),
                ),
            ),
        ] {
            let encoded = hbor_to_vec(&response).unwrap();
            let decoded: GetCellsResponse = hbor_from_slice(&encoded).unwrap();
            assert_eq!(response, decoded);
        }
    }
}
