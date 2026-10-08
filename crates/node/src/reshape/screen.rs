//! Peer verdicts on reshape fetch answers.
//!
//! A reshape duty judges an answer on the driver's loop, after the
//! transport's response callback has already returned, so what it refuses
//! there never reaches the peer health tracker. What the request alone
//! decides — the height asked for, the block named, a certificate pinned to
//! its header, a header batch that chains — is judged here instead, inside
//! the callback, and scored as the scoped fetches score a refusal: a scope
//! the peer does not hold yet is an honest answer, one that does not
//! answer the request is the peer's fault.
//!
//! Both drivers screen through these, so the simulation exercises the same
//! verdicts the production transport acts on. The duty still judges every
//! answer it is handed; a screen that passes an answer promises nothing
//! about its commit, which only the duty's two-chain can show.

use hyperscale_metrics::record_fetch_response_refused;
use hyperscale_network::ResponseVerdict;
use hyperscale_types::network::request::{GetBlockRequest, GetRemoteHeadersRequest};
use hyperscale_types::network::response::{GetBlockResponse, GetRemoteHeadersResponse};
use hyperscale_types::{BlockHeader, QuorumCertificate};
use tracing::warn;

use crate::fetch::{Refusal, scored};

/// The peer verdict on a reshape duty's block answer.
#[must_use]
pub fn block_verdict(request: &GetBlockRequest, response: &GetBlockResponse) -> ResponseVerdict {
    verdict("reshape_block", screen_block(request, response))
}

/// The peer verdict on a reshape walk's certified-header answer.
#[must_use]
pub fn headers_verdict(
    request: &GetRemoteHeadersRequest,
    response: &GetRemoteHeadersResponse,
) -> ResponseVerdict {
    verdict("reshape_headers", screen_headers(request, response))
}

fn verdict(name: &'static str, screened: Result<(), Refusal>) -> ResponseVerdict {
    match screened {
        Ok(()) => ResponseVerdict::Accept,
        Err(refusal) => {
            if let Refusal::Unusable(reason) = refusal {
                warn!(
                    binding = name,
                    reason, "Scoring a reshape fetch answer: unusable"
                );
                record_fetch_response_refused(name, reason);
            }
            scored(refusal)
        }
    }
}

fn screen_block(request: &GetBlockRequest, response: &GetBlockResponse) -> Result<(), Refusal> {
    let Some(certified) = response.block() else {
        return Err(Refusal::NotHeld);
    };
    let header = certified.header();
    if header.height() != request.height {
        return Err(Refusal::Unusable("block height off the requested height"));
    }
    // A server holding a different block at a named height answers
    // `not_found`, so a named request answered by another block is wrong.
    if request.hash.is_some_and(|named| header.hash() != named) {
        return Err(Refusal::Unusable("block other than the one requested"));
    }
    pinned(header, certified.qc())
}

fn screen_headers(
    request: &GetRemoteHeadersRequest,
    response: &GetRemoteHeadersResponse,
) -> Result<(), Refusal> {
    if response.headers.is_empty() {
        return Err(Refusal::NotHeld);
    }
    if response.headers.len() as u64 > request.count.inner() {
        return Err(Refusal::Unusable("more headers than requested"));
    }
    let mut expected = request.from_height;
    let mut parent = None;
    for certified in response.headers.iter() {
        let header = certified.header();
        if header.shard_id() != request.source_shard {
            return Err(Refusal::Unusable("header of another shard"));
        }
        if header.height() != expected {
            return Err(Refusal::Unusable("header height off the requested run"));
        }
        if parent.is_some_and(|hash| header.parent_block_hash() != hash) {
            return Err(Refusal::Unusable("headers that do not chain"));
        }
        pinned(header, certified.qc())?;
        parent = Some(header.hash());
        expected = expected.next();
    }
    Ok(())
}

/// Whether `qc` certifies `header` at all. Its signatures are the duty's to
/// verify, against the committee of the QC's window.
fn pinned(header: &BlockHeader, qc: &QuorumCertificate) -> Result<(), Refusal> {
    let certified = (header.hash(), header.height(), header.shard_id());
    if (qc.block_hash(), qc.height(), qc.shard_id()) != certified {
        return Err(Refusal::Unusable("certificate over another block"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Capped;
    use hyperscale_storage::test_helpers::make_test_block;
    use hyperscale_types::network::request::{BlockIntent, MAX_REMOTE_HEADERS_PER_REQUEST};
    use hyperscale_types::test_utils::{TestCommittee, signed_child_block};
    use hyperscale_types::{
        Block, BlockHeight, CertifiedBlockHeader, ElidedCertifiedBlock, Inventory, Round, ShardId,
        WeightedTimestamp,
    };

    use super::*;

    fn qc_over(committee: &TestCommittee, block: &Block) -> QuorumCertificate {
        committee.sign_qc(
            block.header(),
            &committee.quorum_indices(),
            WeightedTimestamp::from_millis(900),
        )
    }

    fn found(block: &Block, qc: QuorumCertificate) -> GetBlockResponse {
        GetBlockResponse::found(ElidedCertifiedBlock::elide(block, qc, &Inventory::empty()))
    }

    /// Three blocks of one chain above height 1.
    fn chain(committee: &TestCommittee) -> [Block; 3] {
        let base = make_test_block(BlockHeight::new(1));
        let b2 = signed_child_block(
            committee,
            &base,
            Round::new(2),
            WeightedTimestamp::from_millis(100),
        );
        let b3 = signed_child_block(
            committee,
            &b2,
            Round::new(3),
            WeightedTimestamp::from_millis(200),
        );
        [base, b2, b3]
    }

    /// An answer that holds nothing yet is honest and costs the peer
    /// nothing; one that answers some other question is scored.
    #[test]
    fn a_block_answer_off_its_request_is_rejected() {
        let committee = TestCommittee::new(4, 3);
        let [_, b2, b3] = chain(&committee);
        let at_two = GetBlockRequest::new(BlockHeight::new(2), BlockIntent::Execute);

        assert_eq!(
            block_verdict(&at_two, &GetBlockResponse::not_found()),
            ResponseVerdict::Accept,
        );
        assert_eq!(
            block_verdict(&at_two, &found(&b2, qc_over(&committee, &b2))),
            ResponseVerdict::Accept,
        );
        assert_eq!(
            block_verdict(&at_two, &found(&b3, qc_over(&committee, &b3))),
            ResponseVerdict::Reject,
            "a block at another height",
        );
        assert_eq!(
            block_verdict(&at_two, &found(&b2, qc_over(&committee, &b3))),
            ResponseVerdict::Reject,
            "a certificate over another block",
        );
        let named = at_two.naming(b3.hash());
        assert_eq!(
            block_verdict(&named, &found(&b2, qc_over(&committee, &b2))),
            ResponseVerdict::Reject,
            "a block other than the one named",
        );
    }

    fn batch(committee: &TestCommittee, blocks: &[&Block]) -> GetRemoteHeadersResponse {
        GetRemoteHeadersResponse::of(
            Capped::new(
                blocks
                    .iter()
                    .map(|block| {
                        CertifiedBlockHeader::new(block.header().clone(), qc_over(committee, block))
                    })
                    .collect(),
            )
            .expect("within one request"),
        )
    }

    #[test]
    fn a_header_batch_off_its_request_is_rejected() {
        let committee = TestCommittee::new(4, 3);
        let [base, b2, b3] = chain(&committee);
        let from_two = GetRemoteHeadersRequest {
            source_shard: ShardId::ROOT,
            from_height: BlockHeight::new(2),
            count: MAX_REMOTE_HEADERS_PER_REQUEST,
        };

        assert_eq!(
            headers_verdict(&from_two, &batch(&committee, &[])),
            ResponseVerdict::Accept,
        );
        assert_eq!(
            headers_verdict(&from_two, &batch(&committee, &[&b2, &b3])),
            ResponseVerdict::Accept,
        );
        assert_eq!(
            headers_verdict(&from_two, &batch(&committee, &[&b3])),
            ResponseVerdict::Reject,
            "a run starting off the requested height",
        );
        let fork = signed_child_block(
            &committee,
            &base,
            Round::new(4),
            WeightedTimestamp::from_millis(300),
        );
        let off_chain = signed_child_block(
            &committee,
            &fork,
            Round::new(5),
            WeightedTimestamp::from_millis(400),
        );
        assert_eq!(
            headers_verdict(&from_two, &batch(&committee, &[&b2, &off_chain])),
            ResponseVerdict::Reject,
            "a run that does not chain",
        );
        let mispaired = GetRemoteHeadersResponse::of(
            Capped::new(vec![CertifiedBlockHeader::new(
                b2.header().clone(),
                qc_over(&committee, &b3),
            )])
            .expect("one header"),
        );
        assert_eq!(
            headers_verdict(&from_two, &mispaired),
            ResponseVerdict::Reject,
            "a certificate over another block",
        );
    }
}
