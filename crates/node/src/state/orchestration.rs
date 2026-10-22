//! Cross-coordinator orchestration: the flows that drive **both** the shard
//! half and the beacon coordinator from one event.
//!
//! These stay on [`NodeStateMachine`] rather than [`ShardParticipation`] because
//! they mutate `beacon_coordinator` — feeding it the local shard's committed
//! certified headers and advancing its committee anchor. Each destructures both
//! halves explicitly: the shard fields through `self.shard` and the beacon
//! coordinator through `self.beacon_coordinator`, disjoint field borrows the
//! borrow checker keeps separate.
//!
//! [`ShardParticipation`]: super::participation::ShardParticipation

use std::sync::Arc;

use hyperscale_core::Action;
use hyperscale_types::{
    Anchor, CertifiedBlock, CertifiedBlockHeader, Verified, WeightedTimestamp,
    derive_block_transactions,
};

use super::NodeStateMachine;

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
    ) -> Vec<Action> {
        let Some(s) = self.shard.as_mut() else {
            return Vec::new();
        };
        let mut actions = Vec::new();
        let block_hash = certified.block().hash();
        derive_block_transactions(certified.block(), s.derivation.as_ref());

        s.shard_coordinator
            .on_block_committed_verification(block_hash);

        // The node's one fork fence clears here, before any coordinator
        // reads it for this commit, once the attested recovery for a
        // fenced shard completes; a later re-fork can then re-engage.
        let head = self.beacon_coordinator.topology_schedule().head();
        let cleared = s
            .fork_fence
            .clear_completed(|shard| head.latest_completed_recovery(shard));

        actions.extend(s.mempool_coordinator.on_block_committed(
            self.beacon_coordinator.current_topology_snapshot(),
            certified,
        ));
        // Committed engagements are engagement evidence: promote any
        // parked cross-shard transaction whose payer bundle just
        // committed. Covers the case where another proposer paired the
        // bundle before this node's provisions pipeline verified it, and
        // reads the list the engagement tier folds, so a block that
        // arrives sealed promotes what a live one does.
        let trie = self
            .beacon_coordinator
            .current_topology_snapshot()
            .shard_trie()
            .clone();
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
            self.beacon_coordinator.topology_schedule(),
            certified,
            &cleared,
        ));

        actions.extend(
            s.provisions_coordinator
                .on_block_committed(self.beacon_coordinator.topology_schedule(), certified),
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

        let certified_header = Arc::new(certified.certified_header());
        actions.extend(
            self.beacon_coordinator
                .on_local_block_committed(&certified_header),
        );

        let effects = s.execution_coordinator.commit_block(
            self.beacon_coordinator.topology_schedule(),
            certified,
            committee_anchor,
        );
        s.shard_coordinator
            .retire_carried(s.execution_coordinator.committed_height());
        actions.extend(s.apply_commit_effects(effects));
        actions.extend(s.settle_tip(self.beacon_coordinator.topology_schedule()));

        actions
    }

    /// Fan a verified remote header to provisions, then feed it to the
    /// beacon coordinator. Shard consensus already received the header in
    /// `RemoteHeaderQcVerified` (early insertion for deferral proof validation).
    ///
    /// Admission arms expectations only — the header's exports (provisions,
    /// execution certificates) become consumable on `RemoteHeaderCommitted`,
    /// once its commit proof is held.
    pub(super) fn on_remote_header_admitted(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        let Some(s) = self.shard.as_mut() else {
            return Vec::new();
        };

        let mut actions = s
            .provisions_coordinator
            .on_verified_remote_header(certified_header);
        actions.extend(
            self.beacon_coordinator
                .on_verified_source_header(certified_header),
        );
        actions
    }

    /// Fan a commit-proven remote header to the cross-shard consumers: the
    /// beacon coordinator takes a boundary block it asked for; the
    /// provisions coordinator opens the header for provision verification
    /// and drains bundles parked on it; the execution coordinator marks the
    /// source block proven and drains execution certificates deferred on the
    /// proof.
    pub(super) fn on_remote_header_committed(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        let mut actions = self
            .beacon_coordinator
            .on_commit_proven_source_header(certified_header);
        let topology_schedule = self.beacon_coordinator.topology_schedule();
        let Some(s) = self.shard.as_mut() else {
            return actions;
        };

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
            return actions;
        }
        actions.extend(
            s.provisions_coordinator
                .on_committed_remote_header(topology_schedule, certified_header),
        );
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
        AggregateSignature, BeaconBlock, BeaconCert, BeaconProposal, BeaconState, BlockHeight,
        CertifiedBeaconBlock, Epoch, LocalTimestamp, NetworkDefinition, PcQc2, PcQc3,
        PcSignerLengths, PcVector, PcXpProof, RatifyCert, RatifyRound, ShardId, SignerBitfield,
        SpcCert, SpcView, ValidatorId, Verifiable, beacon_reveal_sign,
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

    fn epoch_ms(node: &NodeStateMachine) -> u64 {
        node.beacon_coordinator()
            .current_state()
            .chain_config
            .epoch_duration_ms
    }

    fn in_window(node: &NodeStateMachine, epoch: u64) -> WeightedTimestamp {
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
    ) -> NodeStateMachine {
        let (child, _) = ShardId::ROOT.children();
        let ed = TestNode::new()
            .node
            .beacon_coordinator()
            .current_state()
            .chain_config
            .epoch_duration_ms;
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
            .node
    }

    fn child_replica(anchor_epoch: u64) -> NodeStateMachine {
        child_replica_over(anchor_epoch, merged)
    }

    /// The node's beacon adopts the skip block for the epoch after its tip.
    fn adopt_skip(node: &mut NodeStateMachine) {
        let tip = node.beacon_coordinator().latest_block().block_hash();
        let epoch = node.beacon_coordinator().current_epoch().next();
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
        let _ = node.handle(
            now,
            ProtocolEvent::BeaconBlockVerified { result: Ok(block) },
        );
        assert_eq!(node.beacon_coordinator().current_epoch(), epoch);
    }

    /// The node's beacon adopts a normal block for the epoch after its
    /// tip, carrying one bare proposal from the first committee member,
    /// so the epoch runs the boundary fold and its terminal-record GC.
    fn adopt_normal(node: &mut NodeStateMachine) {
        let tip = node.beacon_coordinator().latest_block().block_hash();
        let epoch = node.beacon_coordinator().current_epoch().next();
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
        let _ = node.handle(
            now,
            ProtocolEvent::BeaconBlockVerified { result: Ok(block) },
        );
        assert_eq!(node.beacon_coordinator().current_epoch(), epoch);
    }

    fn holds_window(node: &NodeStateMachine, epoch: u64) -> bool {
        node.beacon_coordinator()
            .topology_schedule()
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
            !node
                .beacon_coordinator()
                .topology_schedule()
                .past_terminal(child, past_lookahead),
            "the window past the cut is not folded yet",
        );

        adopt_skip(&mut node);
        assert!(
            !holds_window(&node, 1),
            "the adoption that folds the terminal window releases the floor",
        );
    }

    /// A retained replica that read itself dissolved stays dissolved once
    /// the beacon collects its terminal record and the windows that
    /// showed it are evicted, so the schedule can no longer say so.
    #[test]
    fn a_retained_terminated_replica_stays_dissolved_after_its_windows_are_evicted() {
        let (child, _) = ShardId::ROOT.children();
        let mut node = child_replica_over(1000, merged_with_terminal_record);
        let anchor = in_window(&node, 1000);
        let schedule = node.beacon_coordinator().topology_schedule();
        assert!(schedule.past_terminal(child, anchor));
        assert!(node.shard_coordinator().dissolved(schedule));
        let held_record = |node: &NodeStateMachine| {
            node.beacon_coordinator()
                .current_state()
                .boundaries
                .contains_key(&child)
        };

        adopt_normal(&mut node);
        assert!(held_record(&node), "the evidence window is still open");
        assert!(
            holds_window(&node, 1),
            "the terminal record pins its window"
        );

        adopt_normal(&mut node);
        assert!(!held_record(&node), "the terminal record is collected");
        assert!(!holds_window(&node, 1), "the terminal window is evicted");
        let schedule = node.beacon_coordinator().topology_schedule();
        assert!(
            !schedule.past_terminal(child, anchor),
            "the schedule no longer reads the chain past its terminal",
        );
        assert!(node.shard_coordinator().quiescent(schedule));
        assert!(node.shard_coordinator().dissolved(schedule));
    }
}
