//! Proposal fetch: a block proposal a committee member's vote named and
//! this replica never received.
//!
//! A proposal header goes out once, to the committee, and nothing else
//! carries it until a quorum certifies it, so a member it missed cannot
//! vote on it. The shard coordinator asks for it by hash when a committee
//! member's vote names a block it does not hold. A peer answers from the
//! proposals its replica admitted, held here as their proposer signed them,
//! and the answer enters through the same signature check and header
//! admission as a gossiped one.

use std::collections::BTreeMap;
use std::sync::Mutex;

use hyperscale_core::{FetchIds, ProtocolEvent};
use hyperscale_dispatch::Dispatch;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_network::{Network, Verdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::notification::BlockHeaderNotification;
use hyperscale_types::network::request::GetProposalRequest;
use hyperscale_types::network::response::GetProposalResponse;
use hyperscale_types::{BlockHash, BlockHeight};

use crate::event::ShardScopedInput;
use crate::fetch::{
    Fetch, FetchBinding, FetchedBy, Route, Settles, ShardReply, SolicitedAnswer, dispatch_solicited,
};
use crate::shard::verify::verify_signed_by_proposer;
use crate::shard::{ShardIo, ShardLoop};

/// Proposals held for serving at once. The coordinator admits proposals
/// only within its own window above the committed tip, and commits prune
/// everything at or below the persisted height, so the cap only bounds
/// what a burst of view changes holds between commits.
const MAX_HELD_PROPOSALS: usize = 256;

/// Proposal fetch keyed by block hash.
pub type ProposalFetch = Fetch<BlockHash>;

/// The proposals this shard's replica admitted, as their proposer signed
/// them, by block hash.
#[derive(Default)]
pub struct ProposalStore {
    held: Mutex<BTreeMap<BlockHash, (BlockHeight, BlockHeaderNotification)>>,
}

impl ProposalStore {
    /// Hold `proposal`, dropping the lowest held height past the cap.
    pub(crate) fn admit(&self, proposal: BlockHeaderNotification) {
        let mut held = self.held.lock().expect("proposal store lock");
        held.insert(proposal.header.hash(), (proposal.header.height(), proposal));
        while held.len() > MAX_HELD_PROPOSALS {
            let Some(lowest) = held
                .iter()
                .min_by_key(|(hash, (height, _))| (*height, **hash))
                .map(|(hash, _)| *hash)
            else {
                break;
            };
            held.remove(&lowest);
        }
        drop(held);
    }

    /// Drop every proposal at or below `height`, which has persisted.
    pub(crate) fn prune(&self, height: BlockHeight) {
        self.held
            .lock()
            .expect("proposal store lock")
            .retain(|_, (held, _)| *held > height);
    }

    /// Serve an inbound fetch: the proposal if held, otherwise empty.
    pub(crate) fn serve(&self, req: &GetProposalRequest) -> GetProposalResponse {
        let proposal = self
            .held
            .lock()
            .expect("proposal store lock")
            .get(&req.block_hash)
            .map(|(_, proposal)| proposal.clone());
        let response = GetProposalResponse::new(proposal);
        record_fetch_response_sent("proposal", usize::from(response.proposal.is_some()));
        response
    }
}

/// Marker type for the proposal fetch.
pub struct ProposalBinding;

impl FetchBinding for ProposalBinding {
    type Id = BlockHash;

    const NAME: &'static str = "proposal";

    const PER_ID: bool = true;

    type Ids = FetchIds;

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::Proposals(ids)
    }
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for ProposalBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.consensus.proposal
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        route: Route,
        network: &N,
        reply: &ShardReply,
    ) {
        dispatch_solicited::<Self, N, _>(ids, route, network, reply);
    }
}

/// One request per proposal. The answer is checked against the hash
/// asked for here, so a proposal for another block is unsolicited; its
/// proposer's signature is checked on the shard loop, as a gossiped
/// header's is at intake.
impl SolicitedAnswer for ProposalBinding {
    type Request = GetProposalRequest;
    type Item = BlockHeaderNotification;
    type Input = ShardScopedInput;

    const SETTLES: Settles = Settles::OnAnswer;

    fn request(ids: &[BlockHash]) -> GetProposalRequest {
        debug_assert_eq!(ids.len(), 1, "PER_ID hands over one id at a time");
        GetProposalRequest::new(ids[0])
    }

    fn items(response: GetProposalResponse) -> Vec<BlockHeaderNotification> {
        response.proposal.into_iter().collect()
    }

    fn answers_for(
        proposal: &BlockHeaderNotification,
    ) -> impl IntoIterator<Item = BlockHash> + use<> {
        [proposal.header.hash()]
    }

    fn deliver(kept: Vec<BlockHeaderNotification>) -> Vec<ShardScopedInput> {
        kept.into_iter()
            .map(|proposal| ShardScopedInput::ProposalFetched {
                proposal: Box::new(proposal),
            })
            .collect()
    }
}

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// A proposal whose proposer signature has been checked: feed its
    /// header to the replica, and hold it for serving once it admitted it.
    pub(in crate::shard) fn handle_proposal_received(&mut self, proposal: BlockHeaderNotification) {
        let block_hash = proposal.header.hash();
        let (header, manifest, signature) = proposal.into_parts();
        self.handle_protocol_passthrough(ProtocolEvent::BlockHeaderReceived {
            header: std::sync::Arc::clone(&header),
            manifest: manifest.clone(),
        });
        if self.replica.shard_coordinator().holds_proposal(block_hash) {
            self.io
                .consensus
                .proposals
                .admit(BlockHeaderNotification::new(header, manifest, signature));
        }
    }

    /// A fetched proposal: checked against its proposer's signature, as a
    /// gossiped one is at intake, before anything reads it.
    pub(in crate::shard) fn handle_proposal_fetched(&mut self, proposal: BlockHeaderNotification) {
        let topology = self.process.topology_snapshot.load();
        if verify_signed_by_proposer(
            self.process.verifier.as_ref(),
            &topology,
            &proposal,
            "block_header",
            "fetched block header",
        ) != Verdict::Accept
        {
            return;
        }
        self.handle_proposal_received(proposal);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::time::Duration;

    use crossbeam::channel::unbounded;
    use hyperscale_network::ResponseVerdict;
    use hyperscale_network_memory::{HostLayout, LinkStreams, NetworkConfig, SimulatedNetwork};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        BlockHeader, BlockHeaderParts, BlockManifest, ChainOrigin, ConsensusSignature, Hash,
        QuorumCertificate, ShardId, ValidatorId, WeightedTimestamp,
    };

    use super::*;
    use crate::event::HostEvent;
    use crate::fetch::{FetchConfig, FetchInput, FetchOutput, settle_solicited};

    fn proposal_at(height: u64, tag: &[u8]) -> BlockHeaderNotification {
        let header = BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(height),
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(tag)),
            parent_qc: QuorumCertificate::genesis(
                ShardId::ROOT,
                ChainOrigin::root(WeightedTimestamp::ZERO),
            )
            .into(),
            ..Default::default()
        });
        let manifest = BlockManifest::default();
        BlockHeaderNotification::new(header, manifest, ConsensusSignature::ZERO)
    }

    /// A held proposal is served by its hash, signature and all, and
    /// anything else is answered empty; a persisted height takes the
    /// proposals at or below it out of service.
    #[test]
    fn a_held_proposal_is_served_until_its_height_persists() {
        let store = ProposalStore::default();
        let held = proposal_at(7, b"seven");
        let hash = held.header.hash();
        store.admit(held.clone());

        assert_eq!(
            store.serve(&GetProposalRequest::new(hash)).proposal,
            Some(held)
        );
        let unknown = BlockHash::from_raw(Hash::from_bytes(b"unknown"));
        assert_eq!(
            store.serve(&GetProposalRequest::new(unknown)).proposal,
            None
        );

        store.prune(BlockHeight::new(6));
        assert!(
            store
                .serve(&GetProposalRequest::new(hash))
                .proposal
                .is_some()
        );
        store.prune(BlockHeight::new(7));
        assert_eq!(store.serve(&GetProposalRequest::new(hash)).proposal, None);
    }

    /// Past the cap the lowest height goes first, so the proposals still
    /// being voted on stay servable.
    #[test]
    fn the_store_drops_its_lowest_height_past_the_cap() {
        let store = ProposalStore::default();
        let lowest = proposal_at(1, b"lowest");
        store.admit(lowest.clone());
        for height in 2..=u64::try_from(MAX_HELD_PROPOSALS).expect("fits") + 1 {
            store.admit(proposal_at(height, b"filler"));
        }
        assert_eq!(
            store
                .serve(&GetProposalRequest::new(lowest.header.hash()))
                .proposal,
            None
        );
    }

    /// This host's replica answering with a proposal other than the one
    /// asked for does not hold the fetch: the retry is asked past it, and
    /// the peer that holds the proposal answers it before any tick.
    #[test]
    fn a_refused_local_answer_is_asked_again_of_a_peer() {
        const SHARD: ShardId = ShardId::leaf(1, 0);
        let mut network = SimulatedNetwork::new(
            NetworkConfig::default(),
            HostLayout {
                hosted: vec![BTreeSet::from([SHARD]); 2],
                validator_to_host: HashMap::from([
                    (ValidatorId::new(0), 0),
                    (ValidatorId::new(1), 1),
                ]),
            },
            7,
        );
        let mut streams = LinkStreams::new(7);
        let wanted = proposal_at(7, b"wanted");
        let stale = proposal_at(7, b"stale");
        let here = network.create_adapter(0);
        here.register_request_handler(SHARD, move |_: GetProposalRequest| {
            GetProposalResponse::new(Some(stale.clone()))
        });
        let held = wanted.clone();
        network
            .create_adapter(1)
            .register_request_handler(SHARD, move |_: GetProposalRequest| {
                GetProposalResponse::new(Some(held.clone()))
            });

        let mut fetch = ProposalFetch::new("proposal", FetchConfig::default());
        let (sender, events) = unbounded();
        let mut outputs = fetch.handle(FetchInput::Request {
            ids: vec![wanted.header.hash()],
            shard: SHARD,
            preferred: None,
            class: None,
        });
        let mut fetched = None;
        while !outputs.is_empty() {
            for FetchOutput::Send { ids, route } in std::mem::take(&mut outputs) {
                <ProposalBinding as FetchedBy<ShardIo<SimShardStorage>>>::dispatch_chunk(
                    ids,
                    route,
                    &here,
                    &ShardReply {
                        shard: SHARD,
                        sender: sender.clone(),
                    },
                );
            }
            network.accept_requests(
                0,
                Duration::ZERO,
                here.drain_pending_requests(),
                &mut streams,
            );
            network.flush_requests(Duration::from_secs(60), &mut streams);
            for event in events.try_iter() {
                match event {
                    HostEvent::Shard(
                        _,
                        ShardScopedInput::FetchFailed(FetchIds::Proposals(ids)),
                    ) => {
                        outputs.extend(fetch.handle(FetchInput::Failed { ids }));
                    }
                    HostEvent::Shard(_, ShardScopedInput::ProposalFetched { proposal }) => {
                        fetched = Some(*proposal);
                    }
                    _ => {}
                }
            }
        }
        assert_eq!(fetched, Some(wanted), "the peer's answer lands");
    }

    /// A proposal's answer settles its fetch as it lands: the boundary is
    /// the whole check. One the peer does not hold is asked again at no
    /// cost to it.
    #[test]
    fn a_fetched_proposal_retires_its_fetch_as_it_lands() {
        let wanted = proposal_at(7, b"wanted");
        let hash = wanted.header.hash();
        let settle = |response| {
            let (sender, events) = unbounded();
            let verdict = settle_solicited::<ProposalBinding, _>(
                vec![hash],
                Ok(response),
                &ShardReply {
                    shard: ShardId::ROOT,
                    sender,
                },
            );
            let inputs: Vec<ShardScopedInput> = events
                .try_iter()
                .filter_map(|event| match event {
                    HostEvent::Shard(_, input) => Some(input),
                    HostEvent::Beacon(_) => None,
                })
                .collect();
            (verdict, inputs)
        };

        let (verdict, inputs) = settle(GetProposalResponse::new(Some(wanted)));
        assert_eq!(verdict, ResponseVerdict::Accept);
        assert!(matches!(
            inputs.as_slice(),
            [
                ShardScopedInput::FetchFulfilled(FetchIds::Proposals(_)),
                ShardScopedInput::ProposalFetched { .. },
            ]
        ));

        let (verdict, inputs) = settle(GetProposalResponse::new(None));
        assert_eq!(verdict, ResponseVerdict::Accept);
        assert!(matches!(
            inputs.as_slice(),
            [ShardScopedInput::FetchFailed(FetchIds::Proposals(_))]
        ));
    }
}
