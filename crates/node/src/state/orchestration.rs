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
        let cleared = s.fork_fence.clear_completed(
            self.beacon_coordinator
                .topology_schedule()
                .head()
                .completed_recoveries(),
        );

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

        self.beacon_coordinator
            .on_local_block_committed(certified.block().header().parent_qc().weighted_timestamp());

        let certified_header = Arc::new(certified.certified_header());
        actions.extend(
            self.beacon_coordinator
                .on_verified_source_header(&certified_header),
        );

        let effects = s.execution_coordinator.commit_block(
            self.beacon_coordinator.topology_schedule(),
            certified,
            committee_anchor,
        );
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
    /// provisions coordinator opens the header for provision verification
    /// and drains bundles parked on it; the execution coordinator marks the
    /// source block proven and drains execution certificates deferred on the
    /// proof.
    pub(super) fn on_remote_header_committed(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        let topology_schedule = self.beacon_coordinator.topology_schedule();
        let Some(s) = self.shard.as_mut() else {
            return Vec::new();
        };

        // The anchor lands first and in one place: the vote fence holds a
        // block's state proofs to what this validator has commit-proven,
        // and the certificate gate and the probe anchor read the same
        // mirror, so nothing downstream may run before it is in.
        s.shard_coordinator
            .record_proven_anchor(Anchor::of(certified_header));
        let mut actions = s
            .provisions_coordinator
            .on_committed_remote_header(topology_schedule, certified_header);
        actions.extend(
            s.execution_coordinator
                .on_committed_remote_header(topology_schedule, Anchor::of(certified_header)),
        );
        actions
    }
}
