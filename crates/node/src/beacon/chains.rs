//! The shard chains registered with the beacon loop: what each chain's
//! loop reports, and the commit-proof asks routed to them.

use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_beacon::coordinator::{LocalChainAnchors, retention_floor};
use hyperscale_beacon::{BeaconParticipant, ChainRegistration};
use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{BlockHeight, ShardId};

use super::BeaconLoop;
use super::records::{InstanceRecordBinding, PackageArtifactBinding};
use crate::event::{BeaconInput, BeaconOwner, HostEvent, Registration};

impl<S, N, D> BeaconLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Track a chain a loop is about to run from its recovered committed
    /// `height` and the anchors its tip carries, and send the chain's
    /// beacon events to `sender` from now on.
    ///
    /// A chain anchored below the oldest window the fold retains widens
    /// the schedule from beacon storage first, so the replica built from
    /// the returned schedule resolves its tip's committee.
    pub(crate) fn register(
        &mut self,
        shard: ShardId,
        anchors: LocalChainAnchors,
        height: BlockHeight,
        sender: Sender<HostEvent>,
    ) -> Registration {
        let anchor_epoch = self
            .fold
            .state()
            .chain_config
            .epoch_windows()
            .epoch_for(anchors.committee);
        if self
            .fold
            .schedule()
            .retained_epochs()
            .is_some_and(|(oldest, _)| anchor_epoch < oldest)
        {
            let floor = retention_floor(self.fold.state(), Some(anchors.committee), self.now);
            let history = self.process.beacon_storage.states_since(floor);
            self.fold.widen(&history);
        }
        let token = self.fold.register_chain(shard, anchors, height);
        self.shard_senders.insert(token, (shard, sender));
        Registration {
            token,
            schedule: Arc::clone(self.fold.shared_schedule()),
            epoch: self.fold.state().current_epoch,
            chain_config: self.fold.state().chain_config,
        }
    }

    /// Stop tracking the chain `token` names. The commit-proof asks its
    /// loop held go to another registered loop, and what it asked for on
    /// its own behalf is wanted by it no longer.
    pub(crate) fn deregister(&mut self, token: ChainRegistration) {
        self.fold.deregister_chain(token);
        self.shard_senders.remove(&token);
        self.forget::<InstanceRecordBinding>(BeaconOwner::Chain(token));
        self.forget::<PackageArtifactBinding>(BeaconOwner::Chain(token));
        let held: Vec<(ShardId, BlockHeight)> = self
            .proof_routes
            .iter()
            .filter(|(_, route)| **route == token)
            .map(|(ask, _)| *ask)
            .collect();
        for ask in held {
            self.proof_routes.remove(&ask);
            self.route_proof_ask(ask);
        }
    }

    /// What a chain's loop reported: the fold records it, and every
    /// participant re-evaluates the proposals it was waiting on. A report
    /// under a registration the loop no longer holds is a closed loop's
    /// late word, and changes nothing.
    pub(super) fn on_shard_input(&mut self, chain: ChainRegistration, input: BeaconInput) {
        if !self.shard_senders.contains_key(&chain) {
            return;
        }
        match input {
            BeaconInput::LocalCommit { header } => {
                self.pending_admitted.push(Arc::clone(&header));
                let actions = self.fold.on_local_block_committed(chain, &header);
                self.run_fold_actions(actions);
                self.release_awaited_proposals();
            }
            BeaconInput::CertifiedHeader { header } => {
                self.pending_admitted.push(Arc::clone(&header));
                self.fold.on_certified_local_header(chain, &header);
                self.release_awaited_proposals();
            }
            BeaconInput::SourceHeader { header } => {
                self.pending_admitted.push(Arc::clone(&header));
                let actions = self.fold.on_source_header(&header);
                self.run_fold_actions(actions);
                self.release_awaited_proposals();
            }
            BeaconInput::CommitProven { header } => {
                self.proof_routes
                    .remove(&(header.shard_id(), header.height()));
                if self
                    .fold
                    .admit_proven_for(&header, self.participants.values().map(|p| &p.duty))
                {
                    self.release_awaited_proposals();
                }
            }
            BeaconInput::ForkProof(proof) => {
                for participant in self.participants.values_mut() {
                    participant
                        .duty
                        .observe_fork_proof(&self.fold, (*proof).clone());
                }
            }
            BeaconInput::VoteEquivocation { evidence } => {
                self.observe_vote_equivocation(evidence);
            }
            BeaconInput::RecordsWanted {
                instances,
                packages,
            } => self.want_records(BeaconOwner::Chain(chain), instances, packages),
            BeaconInput::RecordsAbandoned {
                instances,
                packages,
            } => self.abandon_records(BeaconOwner::Chain(chain), instances, packages),
        }
    }

    fn release_awaited_proposals(&mut self) {
        for validator in self.validator_list() {
            self.drive(validator, BeaconParticipant::on_source_header);
        }
    }

    /// Hand a commit-proof ask for `source`'s block at `height` to the
    /// lowest registered chain still live on another shard. A loop never
    /// answers for its own shard; with no other, the ask goes nowhere and
    /// `source`'s own certified headers release what waits on it.
    pub(super) fn route_proof_ask(&mut self, (source, height): (ShardId, BlockHeight)) {
        let Some((&token, (shard, sender))) =
            self.shard_senders.iter().find(|(token, (shard, _))| {
                *shard != source
                    && self
                        .fold
                        .chain(**token)
                        .is_some_and(|chain| !chain.terminal_committed)
            })
        else {
            return;
        };
        let _ = sender.send(HostEvent::protocol(
            *shard,
            ProtocolEvent::CommitProofNeeded {
                source_shard: source,
                block_height: height,
            },
        ));
        self.proof_routes.insert((source, height), token);
    }
}
