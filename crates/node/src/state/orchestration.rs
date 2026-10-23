//! Cross-coordinator orchestration: the flows that feed **both** the shard
//! half and the beacon from one event.
//!
//! These stay on [`NodeStateMachine`] rather than [`ShardParticipation`] because
//! they report to the beacon — the local shard's committed certified headers,
//! which advance its committee anchor, and the remote headers it admits and
//! proves. They push a [`BeaconInput`] for each, which the replica's loop
//! sends to the host's beacon loop once the event has run.
//!
//! [`ShardParticipation`]: super::participation::ShardParticipation

use std::sync::Arc;

use hyperscale_core::Action;
use hyperscale_types::{
    Anchor, CertifiedBlock, CertifiedBlockHeader, Verified, WeightedTimestamp,
    derive_block_transactions,
};

use super::NodeStateMachine;
use crate::event::BeaconInput;

impl NodeStateMachine {
    /// Block committed: fold it into execution and notify every
    /// subsystem the live commit stream feeds.
    ///
    /// Transactions are derived first, and the block's snapshot is marked
    /// a usable parent before anything can emit a child verification.
    /// The fork fence clears before any coordinator reads it. The mempool
    /// marks the block committed before it hears the fold's resolutions,
    /// and engagement evidence lands before the proposal latch, which
    /// [`settle_tip`](super::participation::ShardParticipation::settle_tip)
    /// runs last.
    ///
    /// The restart's replay folds through the same execution entry and
    /// the same two hand-offs, and feeds none of the hooks between: each
    /// of them reads the tip it is handed rather than the run behind it,
    /// so it heals from the head on the next live commit.
    pub(super) fn on_block_committed(
        &mut self,
        certified: &Verified<CertifiedBlock>,
        committee_anchor: WeightedTimestamp,
        inputs: &mut Vec<BeaconInput>,
    ) -> Vec<Action> {
        let s = &mut self.shard;
        let mut actions = Vec::new();
        let block_hash = certified.block().hash();
        derive_block_transactions(certified.block(), s.derivation.as_ref());

        s.shard_coordinator
            .on_block_committed_verification(block_hash);

        // The node's one fork fence clears here, before any coordinator
        // reads it for this commit, once the attested recovery for a
        // fenced shard completes; a later re-fork can then re-engage.
        let head = self.schedule.head();
        let cleared = s
            .fork_fence
            .clear_completed(|shard| head.latest_completed_recovery(shard));

        actions.extend(s.mempool_coordinator.on_block_committed(head, certified));
        // Committed engagements are engagement evidence: promote any
        // parked cross-shard transaction whose payer bundle just
        // committed. Covers the case where another proposer paired the
        // bundle before this node's provisions pipeline verified it, and
        // reads the list the engagement tier folds, so a block that
        // arrives sealed promotes what a live one does.
        let trie = head.shard_trie().clone();
        let engagements = certified.block().engagements();
        // Ascending, so each source's entries are one run.
        for run in engagements.chunk_by(|a, b| a.source == b.source) {
            s.mempool_coordinator.on_engagement_evidence(
                &trie,
                run[0].source,
                run.iter().map(|engagement| engagement.tx_hash),
            );
        }

        actions.extend(s.remote_headers_coordinator.on_block_committed(
            &self.schedule,
            certified,
            &cleared,
        ));

        actions.extend(
            s.provisions_coordinator
                .on_block_committed(&self.schedule, certified),
        );

        // Both take the block's own anchor and not a deadline clock's
        // running maximum ([`WeightedTimestamp::advanced_by_commit`]).
        // The eviction below has to be the same on every validator, and
        // the beacon's is a retention floor over topology windows: a
        // maximum there evicts a window the chain can still legitimately
        // be asked to verify against, on whichever node happens to have
        // seen the most history.
        s.outbound_provisions
            .on_block_committed(certified.block().header().parent_qc().weighted_timestamp());

        inputs.push(BeaconInput::LocalCommit {
            header: Arc::new(certified.certified_header()),
        });

        let effects =
            s.execution_coordinator
                .commit_block(&self.schedule, certified, committee_anchor);
        s.shard_coordinator
            .retire_carried(s.execution_coordinator.committed_height());
        actions.extend(s.apply_commit_effects(effects));
        actions.extend(s.settle_tip(&self.schedule));

        actions
    }

    /// Fan a verified remote header to provisions, then report it to the
    /// beacon. Shard consensus already received the header in
    /// `RemoteHeaderQcVerified` (early insertion for deferral proof validation).
    ///
    /// Admission arms expectations only — the header's exports (provisions,
    /// execution certificates) become consumable on `RemoteHeaderCommitted`,
    /// once its commit proof is held.
    pub(super) fn on_remote_header_admitted(
        &mut self,
        certified_header: Arc<Verified<CertifiedBlockHeader>>,
        inputs: &mut Vec<BeaconInput>,
    ) -> Vec<Action> {
        let actions = self
            .shard
            .provisions_coordinator
            .on_verified_remote_header(&certified_header);
        inputs.push(BeaconInput::SourceHeader {
            header: certified_header,
        });
        actions
    }

    /// Fan a commit-proven remote header to the cross-shard consumers: the
    /// shard coordinator records the proven anchor; the provisions
    /// coordinator opens the header for provision verification and drains
    /// bundles parked on it; the execution coordinator marks the source
    /// block proven and drains execution certificates deferred on the
    /// proof. The beacon takes a boundary block it asked for from the
    /// pushed input, after all of them.
    pub(super) fn on_remote_header_committed(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
        inputs: &mut Vec<BeaconInput>,
    ) -> Vec<Action> {
        inputs.push(BeaconInput::CommitProven {
            header: Arc::clone(certified_header),
        });
        let topology_schedule = &self.schedule;
        let s = &mut self.shard;

        // The anchor lands first and in one place: the vote fence holds a
        // block's state proofs to what this validator has commit-proven,
        // and the certificate gate and the probe anchor read the same
        // mirror, so nothing downstream may run before it is in. A chain
        // that refuses it has dissolved, and nothing downstream of it
        // will act again.
        if !s
            .shard_coordinator
            .record_proven_anchor(topology_schedule, Anchor::of(certified_header))
        {
            return Vec::new();
        }
        let mut actions = s
            .provisions_coordinator
            .on_committed_remote_header(topology_schedule, certified_header);
        actions.extend(
            s.execution_coordinator
                .on_committed_remote_header(topology_schedule, Anchor::of(certified_header)),
        );
        // What the anchor releases is offered to the next proposal.
        s.shard_coordinator.queue_ready_proposal();
        actions
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_core::{ProtocolEvent, StateMachine};
    use hyperscale_hbor::Capped;
    use hyperscale_storage::RecoveredState;
    use hyperscale_types::test_utils::{TestCommittee, certify, make_live_block};
    use hyperscale_types::{
        AggregateSignature, BeaconBlock, BeaconCert, BeaconProposal, BeaconState, Block, BlockHash,
        BlockHeight, CertifiedBeaconBlock, ChainOrigin, Epoch, LocalTimestamp, NetworkDefinition,
        PcQc2, PcQc3, PcSignerLengths, PcVector, PcXpProof, RatifyCert, RatifyRound, Round,
        ShardId, SignerBitfield, SpcCert, SpcView, StateRoot, TopologySchedule, ValidatorId,
        Verifiable, beacon_reveal_sign,
    };

    use super::*;
    use crate::state::test_support::TestNode;

    /// The states a merge of the root's two children leaves: window 1
    /// runs both children, and window 1000 runs the root alone, live past
    /// genesis, so a child's terminal window is 1 and its successor is
    /// live. The child's terminal record is already gone, as its handoff
    /// evidence window closing collects it.
    fn merged(genesis: BeaconState) -> Vec<BeaconState> {
        let mut before = genesis.clone();
        before.current_epoch = Epoch::new(1);
        let committee = before.shard_committees[&ShardId::ROOT].clone();
        let (left, right) = ShardId::ROOT.children();
        before.shard_committees = [(left, committee.clone()), (right, committee)].into();
        before.next_shard_committees = before.shard_committees.clone();
        before.shard_consensus_members = before.ready_consensus_members(&before.shard_committees);
        let mut after = genesis;
        after.current_epoch = Epoch::new(1000);
        after
            .boundaries
            .get_mut(&ShardId::ROOT)
            .expect("genesis seats the root's boundary")
            .last_live_epoch = Epoch::new(1000);
        after.advanced.insert(ShardId::ROOT);
        vec![before, after]
    }

    fn epoch_ms(node: &TestNode) -> u64 {
        node.fold.state().chain_config.epoch_duration_ms
    }

    fn in_window(node: &TestNode, epoch: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(epoch * epoch_ms(node) + 1)
    }

    /// [`merged`], with the left child's terminal record still held: its
    /// handoff completes at the first epoch whose evidence window outlives
    /// the next adoption's start and closes before the one after.
    fn merged_with_terminal_record(genesis: BeaconState) -> Vec<BeaconState> {
        let (child, _) = ShardId::ROOT.children();
        let windows = genesis.chain_config.epoch_windows();
        let next_adoption = windows.window_of(Epoch::new(1001)).start;
        let handoff_complete = (1..1000)
            .map(Epoch::new)
            .find(|&done| windows.handoff_evidence_expiry(done) >= next_adoption)
            .expect("an evidence window spans the next adoption");
        let mut record = genesis.boundaries[&ShardId::ROOT].clone();
        record.terminal_epoch = Some(Epoch::new(1));
        record.handoff_complete = Some(handoff_complete);
        let mut history = merged(genesis);
        history
            .last_mut()
            .expect("merged yields its states")
            .boundaries
            .insert(child, record);
        history
    }

    /// A replica of the root's left child recovered at height 5, its tip
    /// anchored in window `anchor_epoch`, over `history`.
    fn child_replica_over(
        anchor_epoch: u64,
        history: fn(BeaconState) -> Vec<BeaconState>,
    ) -> TestNode {
        let (child, _) = ShardId::ROOT.children();
        let ed = epoch_ms(&TestNode::new());
        let anchor = WeightedTimestamp::from_millis(anchor_epoch * ed + 1);
        let recovered = RecoveredState {
            committed_height: BlockHeight::new(5),
            committed_block_anchor_wt: Some(anchor),
            committed_committee_anchor_wt: Some(anchor),
            ..RecoveredState::default()
        };
        TestNode::builder()
            .local_shard(child)
            .recovered(recovered)
            .beacon_history(history)
            .build()
    }

    fn child_replica(anchor_epoch: u64) -> TestNode {
        child_replica_over(anchor_epoch, merged)
    }

    /// The node's beacon adopts the skip block for the epoch after its
    /// tip.
    fn adopt_skip(node: &mut TestNode) {
        let tip = node.fold.latest_block().block_hash();
        let epoch = node.fold.state().current_epoch.next();
        let block = BeaconBlock::skip(epoch, tip);
        let cert = RatifyCert::new(
            tip,
            epoch,
            RatifyRound::INITIAL,
            block.block_hash(),
            SignerBitfield::new(4),
            AggregateSignature::new([0; 96]),
        );
        let block = Arc::new(Verified::new_unchecked_for_test(
            CertifiedBeaconBlock::new_unchecked(block, BeaconCert::Skip(cert)),
        ));
        let now = LocalTimestamp::from_millis((epoch.inner() + 1) * epoch_ms(node));
        node.adopt(now, block);
        assert_eq!(node.fold.state().current_epoch, epoch);
    }

    /// The node's beacon adopts a normal block for the epoch after its
    /// tip, carrying one bare proposal from the first committee member,
    /// so the epoch runs the boundary fold and its terminal-record GC.
    fn adopt_normal(node: &mut TestNode) {
        let tip = node.fold.latest_block().block_hash();
        let epoch = node.fold.state().current_epoch.next();
        let network = NetworkDefinition::simulator();
        let committee = TestCommittee::new(4, 7);
        let reveal = beacon_reveal_sign(committee.signer(0).as_ref(), &network, epoch)
            .expect("the test key signs its reveal");
        let proposal = BeaconProposal::new(
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            reveal,
        );
        let block = BeaconBlock::new(
            epoch,
            tip,
            Capped::from_array([(committee.validator_id(0), proposal)]),
        );
        let qc2 = PcQc2::new(
            PcVector::empty(),
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            PcXpProof::Full,
        );
        let qc3 = PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            SignerBitfield::new(4),
            PcSignerLengths::Uniform(0),
            AggregateSignature::ZERO,
        );
        let spc = SpcCert::Direct {
            prev_view: SpcView::new(0),
            value: PcVector::empty(),
            proof: Verifiable::from(qc3),
        };
        let ratify = RatifyCert::new(
            tip,
            epoch,
            RatifyRound::INITIAL,
            block.block_hash(),
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
        );
        let block = Arc::new(Verified::new_unchecked_for_test(
            CertifiedBeaconBlock::new_unchecked(
                block,
                BeaconCert::Normal {
                    spc: Box::new(spc),
                    ratify,
                },
            ),
        ));
        let now = LocalTimestamp::from_millis((epoch.inner() + 1) * epoch_ms(node));
        node.adopt(now, block);
        assert_eq!(node.fold.state().current_epoch, epoch);
    }

    fn holds_window(node: &TestNode, epoch: u64) -> bool {
        node.node
            .schedule
            .at(WeightedTimestamp::from_millis(epoch * epoch_ms(node)))
            .is_some()
    }

    /// A chain whose last commit lands past its terminal before the
    /// beacon has folded the window that shows it: nothing reads the
    /// commit as terminal until that fold, and no further commit comes.
    /// The adoption that folds it latches the chain and releases the
    /// windows it held.
    #[test]
    fn a_chain_whose_last_commit_precedes_its_terminal_fold_releases_the_floor_at_that_adoption() {
        let (child, _) = ShardId::ROOT.children();
        let mut node = child_replica(1);
        let past_lookahead = in_window(&node, 1002);
        let block = make_live_block(
            child,
            BlockHeight::new(6),
            past_lookahead.as_millis(),
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        let certified = Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(certify(
            block,
            past_lookahead.as_millis(),
        )));
        let now = LocalTimestamp::from_millis(1001 * epoch_ms(&node));
        let _ = node.handle(
            now,
            ProtocolEvent::BlockCommitted {
                certified,
                committee_anchor: in_window(&node, 1),
            },
        );
        assert!(
            !node.node.schedule.past_terminal(child, past_lookahead),
            "the window past the cut is not folded yet",
        );

        adopt_skip(&mut node);
        assert!(
            !holds_window(&node, 1),
            "the adoption that folds the terminal window releases the floor",
        );
    }

    /// A cleanup tick hands the pending pool back for the last time only
    /// once the held schedule shows the replica dissolved. The adoption
    /// that folds the terminal installs that schedule, so the tick before
    /// it and the tick after it read differently.
    #[test]
    fn a_shard_event_reads_the_schedule_the_last_adoption_left() {
        let mut node = child_replica_over(1002, merged_with_terminal_record);
        let cleanup = |node: &mut TestNode| {
            let now = node.fold.now();
            let _ = node.handle(now, ProtocolEvent::CleanupTimer);
            node.node.shard.pending_pool_handed_back
        };
        assert!(!cleanup(&mut node), "no schedule shows the terminal yet");

        adopt_skip(&mut node);
        assert!(
            cleanup(&mut node),
            "the adoption's schedule shows it dissolved"
        );
    }

    /// A replica that an adoption shows dissolved, with no commit after
    /// it, stays dissolved once the windows that showed it are evicted.
    #[test]
    fn a_replica_an_adoption_dissolves_stays_dissolved_after_its_windows_are_evicted() {
        let (child, _) = ShardId::ROOT.children();
        let mut node = child_replica_over(1002, merged_with_terminal_record);
        let anchor = in_window(&node, 1002);
        assert!(!node.node.shard_coordinator().quiescent(&node.node.schedule));

        adopt_skip(&mut node);
        assert!(node.node.schedule.past_terminal(child, anchor));

        adopt_normal(&mut node);
        adopt_normal(&mut node);
        assert!(!holds_window(&node, 1), "the terminal window is evicted");
        assert!(!node.node.schedule.past_terminal(child, anchor));
        assert!(node.node.shard_coordinator().quiescent(&node.node.schedule));
        assert!(node.node.shard_coordinator().dissolved(&node.node.schedule));
    }

    /// A replica seated at a genesis anchored past its terminal reads
    /// itself dissolved with no commit to latch the reading, and the next
    /// adoption evicts the windows that showed it, since the beacon holds
    /// the chain past them. The schedule the replica gives up at that
    /// adoption is the last one that can latch it.
    #[test]
    fn a_genesis_replica_stays_dissolved_once_the_next_adoption_evicts_its_windows() {
        let (child, _) = ShardId::ROOT.children();
        let mut node = child_replica(1002);
        let anchor = in_window(&node, 1000);
        let genesis = Block::genesis(
            child,
            ValidatorId::new(0),
            StateRoot::ZERO,
            ChainOrigin {
                genesis_height: BlockHeight::new(5),
                anchor_wt: anchor,
            },
        );
        let now = node.fold.now();
        let _ = node.node.initialize_genesis(now, &genesis);
        assert!(node.node.shard_coordinator().dissolved(&node.node.schedule));

        adopt_skip(&mut node);
        assert!(!holds_window(&node, 1), "the terminal window is evicted");
        assert!(!node.node.schedule.past_terminal(child, anchor));
        assert!(node.node.shard_coordinator().dissolved(&node.node.schedule));
    }

    /// A retained replica that read itself dissolved stays dissolved once
    /// the beacon collects its terminal record and the windows that
    /// showed it are evicted, so the schedule can no longer say so.
    #[test]
    fn a_retained_terminated_replica_stays_dissolved_after_its_windows_are_evicted() {
        let (child, _) = ShardId::ROOT.children();
        let mut node = child_replica_over(1000, merged_with_terminal_record);
        let anchor = in_window(&node, 1000);
        let schedule = &node.node.schedule;
        assert!(schedule.past_terminal(child, anchor));
        assert!(node.node.shard_coordinator().dissolved(schedule));
        let held_record = |node: &TestNode| node.fold.state().boundaries.contains_key(&child);

        adopt_normal(&mut node);
        assert!(held_record(&node), "the evidence window is still open");
        assert!(
            holds_window(&node, 1),
            "the terminal record pins its window"
        );

        adopt_normal(&mut node);
        assert!(!held_record(&node), "the terminal record is collected");
        assert!(!holds_window(&node, 1), "the terminal window is evicted");
        let schedule = &node.node.schedule;
        assert!(
            !schedule.past_terminal(child, anchor),
            "the schedule no longer reads the chain past its terminal",
        );
        assert!(node.node.shard_coordinator().quiescent(schedule));
        assert!(node.node.shard_coordinator().dissolved(schedule));
    }

    /// A proposer whose committee lookup stalls on a not-yet-committed epoch
    /// has no retry signal other than the beacon adopting that epoch, so
    /// `BeaconBlockPersisted` must latch a proposal retry for the
    /// post-dispatch hook to turn into `try_propose`. Without it the
    /// view-change timer fires first, the height moves to a later round, and
    /// the round-contiguous commit rule never sees consecutive rounds while
    /// the beacon trails. End-to-end on a leader, the event must surface a
    /// `BuildProposal` action.
    #[test]
    fn beacon_block_persisted_drives_proposal_through_post_dispatch_hook() {
        // Rounds increase per block, so height 1 is round 1:
        // proposer_for(r=1) = committee[1 % 4] = ValidatorId::new(1).
        let mut test = TestNode::builder().local_idx(1).build();
        assert!(
            test.node
                .topology_snapshot()
                .proposer_for(test.node.shard_id(), Round::new(1))
                == test.committee.validator_id(1),
            "local must be the height-1 proposer for this test",
        );

        let schedule = Arc::new(test.fold.schedule().clone());
        let actions = test.node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::BeaconBlockPersisted {
                epoch: Epoch::GENESIS,
                schedule,
            },
        );

        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BuildProposal { .. })),
            "expected BuildProposal after BeaconBlockPersisted on a leader; got {actions:?}",
        );
    }

    /// A replica restored past its terminal from a store that commits
    /// nothing more latches its dissolution against its first schedule,
    /// at construction: a schedule that has since evicted the windows
    /// that showed it reads nothing, and the replica still reads itself
    /// dissolved.
    #[test]
    fn a_departed_shard_restored_after_a_restart_stays_dissolved_once_its_windows_are_evicted() {
        let (child, _) = ShardId::ROOT.children();
        let node = child_replica_over(1000, merged_with_terminal_record);
        let anchor = in_window(&node, 1000);
        let evicted = TopologySchedule::new(
            epoch_ms(&node),
            Epoch::new(1001),
            Arc::clone(node.node.schedule.head()),
        );
        assert!(
            !evicted.past_terminal(child, anchor),
            "a schedule without the terminal's windows reads nothing",
        );
        assert!(node.node.shard_coordinator().quiescent(&evicted));
        assert!(node.node.shard_coordinator().dissolved(&evicted));
    }

    /// `node`'s committee on the root shard with validator 1 placed but
    /// not yet ready: outside the consensus subset.
    fn one_not_ready(test: &TestNode) -> TopologySchedule {
        use std::collections::{BTreeSet, HashMap};

        use hyperscale_types::{TopologySnapshot, ValidatorInfo, ValidatorSet};

        let members: Vec<ValidatorId> = (0..test.committee.size())
            .map(|i| test.committee.validator_id(i))
            .collect();
        let validators = ValidatorSet::new(
            (0..test.committee.size())
                .map(|i| ValidatorInfo {
                    validator_id: test.committee.validator_id(i),
                    public_key: *test.committee.public_key(i),
                })
                .collect(),
        );
        let ready: Vec<ValidatorId> = members
            .iter()
            .copied()
            .filter(|member| *member != ValidatorId::new(1))
            .collect();
        let snapshot = TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &validators,
            HashMap::from([(ShardId::ROOT, members)]),
            HashMap::from([(ShardId::ROOT, ready)]),
            BTreeMap::new(),
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        );
        TopologySchedule::single(Arc::new(snapshot))
    }

    fn ready_signallers(actions: &[Action]) -> Vec<ValidatorId> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::SignAndBroadcastReadySignal { signer, .. } => Some(*signer),
                _ => None,
            })
            .collect()
    }

    /// An attach whose schedule a later epoch folded installs it, and the
    /// signer it places but has not readied signals at that epoch's beacon
    /// block, not at the attach.
    #[test]
    fn an_attach_carrying_a_newer_schedule_signals_at_that_epochs_beacon_block() {
        let mut test = TestNode::builder().build();
        let held = test.node.schedule_epoch();
        let newer = Arc::new(one_not_ready(&test));
        let epoch = Epoch::new(held.inner() + 1);

        let attached = test.node.attach_signer(
            LocalTimestamp::ZERO,
            ValidatorId::new(1),
            None,
            Round::INITIAL,
            Arc::clone(&newer),
            epoch,
        );
        assert!(Arc::ptr_eq(test.node.schedule(), &newer));
        assert_eq!(test.node.schedule_epoch(), epoch);
        assert!(ready_signallers(&attached).is_empty(), "{attached:?}");

        let persisted = test.node.handle(
            LocalTimestamp::ZERO,
            ProtocolEvent::BeaconBlockPersisted {
                epoch,
                schedule: newer,
            },
        );
        assert_eq!(
            ready_signallers(&persisted),
            vec![ValidatorId::new(1)],
            "{persisted:?}"
        );
    }

    /// An attach carrying a schedule at the epoch the replica already
    /// holds leaves the held one, whose windows its registration widened.
    #[test]
    fn an_attach_at_an_equal_epoch_keeps_the_widened_windows() {
        let mut test = TestNode::builder().build();
        let held = Arc::clone(test.node.schedule());
        let epoch = test.node.schedule_epoch();
        let narrow = Arc::new(TopologySchedule::single(Arc::clone(held.head())));

        let _ = test.node.attach_signer(
            LocalTimestamp::ZERO,
            ValidatorId::new(1),
            None,
            Round::INITIAL,
            narrow,
            epoch,
        );
        assert!(Arc::ptr_eq(test.node.schedule(), &held));
        assert_eq!(test.node.schedule_epoch(), epoch);
    }

    /// The root committee on one-second windows a halt recovery replaces,
    /// and the one it seats: `test`'s four members govern every window of
    /// the first schedule; the second is the fold that seated the recovery
    /// at epoch 100, with validator 7 in place of member 3 from its bridge
    /// at 101.
    fn before_and_after_a_seated_halt_recovery(
        test: &TestNode,
    ) -> (TopologySchedule, TopologySchedule) {
        use std::collections::{BTreeSet, HashMap};

        use hyperscale_crypto_bls::BlsSigner;
        use hyperscale_types::{
            RecoveryCause, ShardRecovery, Signer, TopologySnapshot, ValidatorInfo, ValidatorSet,
        };

        let fresh_member = ValidatorInfo {
            validator_id: ValidatorId::new(7),
            public_key: BlsSigner::generate().public_key(),
        };
        let validators = ValidatorSet::new(
            (0..test.committee.size())
                .map(|i| ValidatorInfo {
                    validator_id: test.committee.validator_id(i),
                    public_key: *test.committee.public_key(i),
                })
                .chain(std::iter::once(fresh_member))
                .collect(),
        );
        let committee = |members: Vec<ValidatorId>| {
            TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &validators,
                HashMap::from([(ShardId::ROOT, members.clone())]),
                HashMap::from([(ShardId::ROOT, members)]),
                BTreeMap::new(),
                HashMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
            )
        };
        let members: Vec<ValidatorId> = (0..test.committee.size())
            .map(|i| test.committee.validator_id(i))
            .collect();
        let halted = Arc::new(committee(members.clone()));
        let mut fresh_members = members;
        fresh_members[3] = ValidatorId::new(7);
        let fresh = Arc::new(
            committee(fresh_members).with_pending_recoveries(
                std::iter::once((
                    ShardId::ROOT,
                    ShardRecovery {
                        cause: RecoveryCause::Halt,
                        rotated_at: Epoch::new(100),
                        retained: vec![test.committee.validator_id(3)],
                        attested_frontier: BlockHeight::GENESIS,
                    },
                ))
                .collect(),
            ),
        );
        let mut before = TopologySchedule::new(1_000, Epoch::new(0), Arc::clone(&halted));
        let mut after = TopologySchedule::new(1_000, Epoch::new(0), Arc::clone(&halted));
        for epoch in 1..=110 {
            before.insert(Epoch::new(epoch), Arc::clone(&halted));
            let seated = if epoch < 101 { &halted } else { &fresh };
            after.insert(Epoch::new(epoch), Arc::clone(seated));
        }
        before.set_head(halted);
        after.set_head(fresh);
        (before, after)
    }

    /// An unsigned replica holding, under the halted schedule of
    /// [`before_and_after_a_seated_halt_recovery`], the halted committee's
    /// uncertified block at its view with every check passed; the schedule
    /// that seats the recovery, the epoch it folds at, and the block.
    fn holding_a_halted_pending_block() -> (TestNode, Arc<TopologySchedule>, Epoch, BlockHash) {
        use hyperscale_types::{
            BlockHeader, BlockHeaderParts, BlockManifest, CheckOutcome, ProposerTimestamp,
            QuorumCertificate, ShardLoad, StandingAnswers, VerificationKind,
        };

        let mut test = TestNode::new();
        let (halted, seated) = before_and_after_a_seated_halt_recovery(&test);
        let held = test.node.schedule_epoch();
        let at = LocalTimestamp::from_millis(2_000);
        let _ = test.node.handle(
            at,
            ProtocolEvent::BeaconBlockPersisted {
                epoch: Epoch::new(held.inner() + 1),
                schedule: Arc::new(halted.clone()),
            },
        );
        test.node.detach_signer(test.committee.validator_id(0));
        let genesis = Block::genesis(
            ShardId::ROOT,
            test.committee.validator_id(0),
            StateRoot::ZERO,
            ChainOrigin::ROOT,
        );
        let _ = test.node.initialize_genesis(at, &genesis);
        test.node
            .seed_standing_answers(BlockHeight::GENESIS, StandingAnswers::default());

        let round = Round::new(1);
        let header = BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(1),
            parent_block_hash: genesis.hash(),
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            proposer: halted.head().proposer_for(ShardId::ROOT, round),
            timestamp: ProposerTimestamp::from_millis(1_000),
            round,
            load: ShardLoad {
                blocks: 1,
                ..ShardLoad::ZERO
            },
            ..Default::default()
        });
        let block_hash = header.hash();
        let coordinator = &mut test.node.shard.shard_coordinator;
        let _ = coordinator.on_block_header(
            &halted,
            &header,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );
        for kind in [
            VerificationKind::BodyRoot,
            VerificationKind::BeaconWitnessRoot,
            VerificationKind::StateRoot,
        ] {
            let _ = coordinator.on_block_check_completed(
                &halted,
                block_hash,
                kind,
                CheckOutcome::checked(),
            );
        }
        assert!(coordinator.holds_proposal(block_hash), "the block is held");
        (
            test,
            Arc::new(seated),
            Epoch::new(held.inner() + 2),
            block_hash,
        )
    }

    fn votes_for(actions: &[Action], block_hash: BlockHash) -> bool {
        actions.iter().any(|action| {
            matches!(
                action,
                Action::SignAndBroadcastBlockVote { block_hash: voted, .. } if *voted == block_hash
            )
        })
    }

    /// The `BeaconBlockPersisted` that seats a halt recovery drops the
    /// replica's uncertified block judged under the halted committee, so
    /// a fresh signer attached after it does not vote the block.
    #[test]
    fn the_beacon_block_seating_a_recovery_drops_a_halted_pending_block_before_an_attach() {
        let (mut test, seated, epoch, block_hash) = holding_a_halted_pending_block();
        let now = LocalTimestamp::from_millis(101_500);
        let _ = test.node.handle(
            now,
            ProtocolEvent::BeaconBlockPersisted {
                epoch,
                schedule: Arc::clone(&seated),
            },
        );
        assert!(!test.node.shard_coordinator().holds_proposal(block_hash));

        let attached = test.node.attach_signer(
            now,
            ValidatorId::new(7),
            None,
            Round::INITIAL,
            seated,
            epoch,
        );
        assert!(!votes_for(&attached, block_hash), "{attached:?}");
    }

    /// A batch for the halted committee's block, in flight when the
    /// seating drops the block with its vote set, forms no QC when it
    /// returns at quorum: its signer bitfield indexes a committee that no
    /// longer governs the block.
    #[test]
    fn a_batch_in_flight_across_the_seating_drop_forms_no_qc() {
        use hyperscale_types::{
            BlockVote, ConsensusSignature, ProposerTimestamp, QuorumCertificate, Verified,
            WeightedTimestamp,
        };

        let (mut test, seated, epoch, block_hash) = holding_a_halted_pending_block();
        let at = LocalTimestamp::from_millis(2_000);
        let height = BlockHeight::new(1);
        let round = Round::new(1);
        let mut batch = Vec::new();
        for member in 0..3 {
            let vote = BlockVote::from_parts(
                block_hash,
                ShardId::ROOT,
                height,
                round,
                test.committee.validator_id(member),
                ConsensusSignature::ZERO,
                ProposerTimestamp::from_millis(1_000),
            );
            batch.extend(test.handle(at, ProtocolEvent::UnverifiedBlockVoteReceived { vote }));
        }
        let binding = batch
            .iter()
            .find_map(|action| match action {
                Action::VerifyAndBuildQuorumCertificate { binding, .. } => Some(*binding),
                _ => None,
            })
            .unwrap_or_else(|| panic!("the halted committee reaches a batch: {batch:?}"));

        let now = LocalTimestamp::from_millis(101_500);
        let _ = test.node.handle(
            now,
            ProtocolEvent::BeaconBlockPersisted {
                epoch,
                schedule: seated,
            },
        );
        assert!(!test.node.shard_coordinator().holds_proposal(block_hash));

        let qc = QuorumCertificate::new(
            block_hash,
            ShardId::ROOT,
            height,
            BlockHash::ZERO,
            round,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        let actions = test.node.handle(
            now,
            ProtocolEvent::QuorumCertificateResult {
                block_hash,
                qc: Some(Verified::new_unchecked_for_test(qc)),
                verified_votes: Vec::new(),
                binding,
            },
        );
        assert!(
            !actions.iter().any(|action| matches!(
                action,
                Action::Continuation(ProtocolEvent::QuorumCertificateFormed { .. })
            )),
            "{actions:?}"
        );
    }

    /// An attach carrying the schedule that seats a halt recovery drops
    /// the halted committee's uncertified block before the fresh signer
    /// re-drives its votes.
    #[test]
    fn an_attach_carrying_the_seating_schedule_drops_a_halted_pending_block_first() {
        let (mut test, seated, epoch, block_hash) = holding_a_halted_pending_block();
        let now = LocalTimestamp::from_millis(101_500);
        let attached = test.node.attach_signer(
            now,
            ValidatorId::new(7),
            None,
            Round::INITIAL,
            seated,
            epoch,
        );
        assert!(!votes_for(&attached, block_hash), "{attached:?}");
        assert!(!test.node.shard_coordinator().holds_proposal(block_hash));
    }
}
