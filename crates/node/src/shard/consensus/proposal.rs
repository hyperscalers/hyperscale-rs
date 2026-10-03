//! Proposal fetch: a block proposal a committee member's vote named and
//! this replica never received.
//!
//! A proposal header goes out once, to the committee, and nothing else
//! carries it until a quorum certifies it, so a member it missed cannot
//! vote on it. The shard coordinator asks for it by hash when a committee
//! member's vote names a block it does not hold. A peer answers from the
//! proposals its vnodes admitted, held here as their proposer signed them,
//! and the answer enters through the same signature check and header
//! admission as a gossiped one.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crossbeam::channel::Sender;
use hyperscale_core::{FetchIds, ProtocolEvent};
use hyperscale_dispatch::Dispatch;
use hyperscale_metrics::{record_fetch_response_refused, record_fetch_response_sent};
use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::notification::BlockHeaderNotification;
use hyperscale_types::network::request::GetProposalRequest;
use hyperscale_types::network::response::GetProposalResponse;
use hyperscale_types::{BlockHash, BlockHeight, MessageClass, ShardId, ValidatorId};
use tracing::warn;

use crate::fetch::{Fetch, FetchBinding, defers_to_the_tick};
use crate::shard::verify::verify_signed_by_proposer;
use crate::shard::{HostEvent, ShardIo, ShardLoop, ShardScopedInput, push_shard_input};

/// Proposals held for serving at once. The coordinator admits proposals
/// only within its own window above the committed tip, and commits prune
/// everything at or below the persisted height, so the cap only bounds
/// what a burst of view changes holds between commits.
const MAX_HELD_PROPOSALS: usize = 256;

/// Proposal fetch keyed by block hash.
pub type ProposalFetch = Fetch<BlockHash>;

/// The proposals this shard's vnodes admitted, as their proposer signed
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

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::Proposals(ids)
    }

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.consensus.proposal
    }

    /// One request per proposal. The answer is checked against the hash
    /// asked for here; its proposer's signature is checked on the shard
    /// loop, as a gossiped header's is at intake.
    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<HostEvent>,
    ) {
        for block_hash in ids {
            let es = sender.clone();
            network.request(
                shard,
                preferred,
                GetProposalRequest::new(block_hash),
                class,
                Box::new(move |result: Result<GetProposalResponse, RequestError>| {
                    let requested = FetchIds::Proposals(vec![block_hash]);
                    let response = match result {
                        Ok(response) => response,
                        Err(error) => {
                            let input = if defers_to_the_tick(&error) {
                                ShardScopedInput::FetchUnroutable(requested)
                            } else {
                                ShardScopedInput::FetchFailed(requested)
                            };
                            push_shard_input(&es, local_shard, input);
                            return ResponseVerdict::Accept;
                        }
                    };
                    let Some(proposal) = response.proposal else {
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::FetchFailed(requested),
                        );
                        return ResponseVerdict::Accept;
                    };
                    if proposal.header.hash() != block_hash {
                        warn!(
                            ?block_hash,
                            "Dropping fetched proposal: not the block asked for"
                        );
                        record_fetch_response_refused(Self::NAME, "proposal_mismatch");
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::FetchFailed(requested),
                        );
                        return ResponseVerdict::Reject;
                    }
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::FetchFulfilled(requested),
                    );
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::ProposalFetched {
                            proposal: Box::new(proposal),
                        },
                    );
                    ResponseVerdict::Accept
                }),
            );
        }
    }
}

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// A proposal whose proposer signature has been checked: feed its
    /// header to every vnode, and hold it for serving once one of them
    /// admitted it.
    pub(in crate::shard) fn handle_proposal_received(&mut self, proposal: BlockHeaderNotification) {
        let block_hash = proposal.header.hash();
        let (header, manifest, signature) = proposal.into_parts();
        self.handle_protocol_passthrough(ProtocolEvent::BlockHeaderReceived {
            header: std::sync::Arc::clone(&header),
            manifest: manifest.clone(),
        });
        if self
            .vnodes
            .iter()
            .any(|vnode| vnode.state.shard_coordinator().holds_proposal(block_hash))
        {
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
        if !verify_signed_by_proposer(
            self.process.verifier.as_ref(),
            &topology,
            &proposal,
            "block_header",
            "fetched block header",
        ) {
            return;
        }
        self.handle_proposal_received(proposal);
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Capped;
    use hyperscale_types::{
        BlockHeader, BlockHeaderParts, BlockManifest, ChainOrigin, ConsensusSignature, Hash,
        QuorumCertificate, WitnessSources,
    };

    use super::*;

    fn proposal_at(height: u64, tag: &[u8]) -> BlockHeaderNotification {
        let header = BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(height),
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(tag)),
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            ..Default::default()
        });
        let manifest = BlockManifest::new(
            Capped::from_array([]),
            Capped::from_array([]),
            Capped::from_array([]),
            Capped::from_array([]),
            Capped::from_array([]),
            Capped::from_array([]),
            WitnessSources::empty(),
        );
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
}
