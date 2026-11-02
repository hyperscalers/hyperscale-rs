//! Inbound local-provision fetch request handling.

use std::collections::HashSet;

use hyperscale_provisions::ProvisionStore;
use hyperscale_types::network::encoded_len;
use hyperscale_types::network::request::GetLocalProvisionsRequest;
use hyperscale_types::network::response::{GetLocalProvisionsResponse, LocalProvisionEntry};
use hyperscale_types::{BlockHeight, CertifiedBlockHeader, MAX_FETCH_RESPONSE_BYTES, ShardId};

use crate::serve::Answer;

/// Serve an inbound local-provision fetch request.
///
/// Bundles the matching source header with the first returned part of
/// each source block, so the requester can verify and admit without
/// first racing the remote-header pipeline; the block's later parts
/// ride without it. `source_header` reads the same buffer the
/// coordinator writes through, so a present part implies its header was
/// admitted at some point; `None` means it has since been retired and
/// the requester falls back to the buffered path.
///
/// The answer stops where its parts and headers would pass a fetch
/// response's budget. A part left out is asked again.
#[must_use]
pub fn serve_local_provisions_request(
    provision_store: &ProvisionStore,
    source_header: impl Fn((ShardId, BlockHeight)) -> Option<CertifiedBlockHeader>,
    req: &GetLocalProvisionsRequest,
) -> GetLocalProvisionsResponse {
    let mut entries = Answer::of(req.batch_hashes.len()).within(MAX_FETCH_RESPONSE_BYTES);
    let mut headed: HashSet<(ShardId, BlockHeight)> = HashSet::new();
    for h in &req.batch_hashes {
        let Some(provision) = provision_store.get(*h) else {
            continue;
        };
        let block = (provision.source_shard(), provision.block_height());
        let entry = LocalProvisionEntry {
            source_header: if headed.contains(&block) {
                None
            } else {
                source_header(block)
            },
            provision,
        };
        let size = encoded_len(&entry);
        if entries.offer(entry, size).is_break() {
            break;
        }
        headed.insert(block);
    }
    GetLocalProvisionsResponse::new(entries.finish())
}

#[cfg(test)]
mod tests {
    use crossbeam::channel::unbounded;
    use hyperscale_core::{FetchIds, ProtocolEvent};
    use hyperscale_hbor::Capped;
    use hyperscale_network::ResponseVerdict;
    use hyperscale_types::{
        AggregateSignature, BlockHash, BlockHeader, BlockHeaderParts, ChainOrigin, Epoch, Hash,
        LeafPath, MAX_MERKLE_PROOF_LEN, MerkleInclusionProof, Provision, ProvisionHash,
        ProvisionParts, QuorumCertificate, Round, SignerBitfield, TxHash, WeightedTimestamp,
    };

    use super::*;
    use crate::event::{HostEvent, ShardScopedInput};
    use crate::fetch::{ShardReply, settle_solicited};
    use crate::shard::cross_shard::LocalProvisionBinding;

    const SOURCE: ShardId = ShardId::leaf(1, 1);
    const LOCAL: ShardId = ShardId::leaf(1, 0);

    /// A part of the source block at `height`, its proof `proof_len`
    /// bytes long.
    fn part(height: u64, index: u32, proof_len: usize) -> Provision {
        Provision::new(ProvisionParts {
            source_shard: SOURCE,
            target_shard: LOCAL,
            block_height: BlockHeight::new(height),
            source_block_ts: WeightedTimestamp::ZERO,
            tx_hash: TxHash::from(Hash::from_bytes(&[u8::try_from(index).unwrap()])),
            entries: Capped::empty(),
            proof: MerkleInclusionProof::new(vec![0x5A; proof_len]),
            leaf: LeafPath {
                count: 2,
                index,
                siblings: Capped::empty(),
            },
        })
    }

    fn header(height: BlockHeight) -> CertifiedBlockHeader {
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: SOURCE,
            height,
            parent_qc: QuorumCertificate::genesis(
                SOURCE,
                ChainOrigin::root(WeightedTimestamp::ZERO),
            )
            .into(),
            ..Default::default()
        });
        let qc = QuorumCertificate::new(
            header.hash(),
            SOURCE,
            height,
            BlockHash::ZERO,
            Round::INITIAL,
            Epoch::GENESIS,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        CertifiedBlockHeader::new(header, qc)
    }

    fn serve(parts: &[Provision]) -> GetLocalProvisionsResponse {
        let store = ProvisionStore::new();
        for part in parts {
            store.insert(part.clone());
        }
        let hashes = parts.iter().map(Provision::hash).collect();
        serve_local_provisions_request(
            &store,
            |(_, height)| Some(header(height)),
            &GetLocalProvisionsRequest::new(Capped::new(hashes).unwrap()),
        )
    }

    /// A chunk naming two parts at the proof cap is answered with the
    /// first alone, under the fetch response budget, and the second is
    /// released to be asked again without blame on the peer.
    #[test]
    fn a_chunk_of_two_maximal_parts_answers_one_and_asks_the_other_again() {
        let parts = [
            part(7, 0, MAX_MERKLE_PROOF_LEN),
            part(7, 1, MAX_MERKLE_PROOF_LEN),
        ];
        let response = serve(&parts);
        assert_eq!(
            response
                .entries
                .iter()
                .map(|entry| entry.provision.hash())
                .collect::<Vec<_>>(),
            vec![parts[0].hash()],
        );
        assert!(encoded_len(&response) <= MAX_FETCH_RESPONSE_BYTES);

        let (sender, events) = unbounded();
        let verdict = settle_solicited::<LocalProvisionBinding, _>(
            parts.iter().map(Provision::hash).collect(),
            Ok(response),
            &ShardReply {
                shard: LOCAL,
                sender,
            },
        );
        assert_eq!(verdict, ResponseVerdict::Accept);
        let asked_again: Vec<ProvisionHash> = events
            .try_iter()
            .filter_map(|event| match event {
                HostEvent::Shard(
                    _,
                    ShardScopedInput::FetchFailed(FetchIds::LocalProvisions(ids)),
                ) => Some(ids),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(asked_again, vec![parts[1].hash()]);
    }

    /// A source block's header rides its first part alone; a part of
    /// another block brings its own.
    #[test]
    fn one_header_rides_each_source_block() {
        let parts = [part(7, 0, 64), part(7, 1, 64), part(8, 0, 64)];
        let headed: Vec<Option<BlockHeight>> = serve(&parts)
            .entries
            .iter()
            .map(|entry| entry.source_header.as_ref().map(|h| h.header().height()))
            .collect();
        assert_eq!(
            headed,
            vec![Some(BlockHeight::new(7)), None, Some(BlockHeight::new(8))]
        );
        let (sender, events) = unbounded();
        settle_solicited::<LocalProvisionBinding, _>(
            parts.iter().map(Provision::hash).collect(),
            Ok(serve(&parts)),
            &ShardReply {
                shard: LOCAL,
                sender,
            },
        );
        let delivered = events
            .try_iter()
            .filter(|event| {
                matches!(
                    event,
                    HostEvent::Shard(_, ShardScopedInput::Protocol(event))
                        if matches!(**event, ProtocolEvent::UnverifiedRemoteHeaderReceived { .. })
                )
            })
            .count();
        assert_eq!(delivered, 2, "one header per source block reaches the loop");
    }
}
