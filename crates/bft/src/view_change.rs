//! View change component for liveness.
//!
//! Handles timeout detection and coordinated round increments when progress stalls.
//!
//! # HotStuff-2 QC Forwarding
//!
//! With the 2-chain commit rule, view change votes include the validator's `highest_qc`.
//! This ensures the new proposer learns about the highest certified block and can build
//! on it, preserving safety. The `highest_qc` is attached as **unsigned data** to allow
//! BLS signature aggregation.

use hyperscale_types::{
    BlockHeight, Hash, KeyPair, PublicKey, QuorumCertificate, ShardGroupId, Signature,
    SignerBitfield, Topology, ValidatorId, ViewChangeCertificate, VotePower,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use hyperscale_core::{Action, Event, OutboundMessage, TimerId};
use hyperscale_messages::{ViewChangeVote, ViewChangeVoteGossip};

use crate::state::BftState;

/// Marker for view change vote pending signature verification.
/// The vote itself is returned in the verification callback event.
#[derive(Debug, Clone, Copy)]
struct PendingVoteVerification;

/// Marker for view change vote pending highest_qc verification.
/// The vote itself is returned in the verification callback event.
#[derive(Debug, Clone, Copy)]
struct PendingHighestQcVerification;

/// View change state for a deterministic BFT node.
///
/// Unlike the async version that uses DashMap and AtomicU64, this version
/// uses plain HashMap and u64 since it's single-threaded.
pub struct ViewChangeState {
    /// Shard group identifier for replay protection.
    shard_group: Hash,

    /// Signing key for votes.
    signing_key: KeyPair,

    /// Network topology (single source of truth for committee/shard info).
    topology: Arc<dyn Topology>,

    /// View change timeout duration.
    timeout: Duration,

    /// Time of last progress (block commit).
    last_progress_time: Duration,

    /// Current round number.
    current_round: u64,

    /// Current height being tracked.
    current_height: u64,

    /// Whether we've broadcast a vote for the current timeout.
    timeout_vote_broadcast: bool,

    /// Collects view change votes: (height, new_round) -> map of voter -> (signature, highest_qc).
    vote_collector: HashMap<(u64, u64), BTreeMap<ValidatorId, (Signature, QuorumCertificate)>>,

    /// Highest QC we've seen (HotStuff-2 QC forwarding).
    highest_qc: QuorumCertificate,

    /// Highest QC seen from view change votes: (height, new_round) -> highest QC.
    highest_qc_collector: HashMap<(u64, u64), QuorumCertificate>,

    /// Votes pending vote signature verification.
    /// Key: (height, new_round, voter)
    pending_vote_verifications: HashMap<(u64, u64, ValidatorId), PendingVoteVerification>,

    /// Votes pending highest_qc verification (vote signature already verified).
    /// Key: (height, new_round, voter)
    pending_qc_verifications: HashMap<(u64, u64, ValidatorId), PendingHighestQcVerification>,

    /// Current simulation time.
    now: Duration,
}

impl ViewChangeState {
    /// Create a new view change state.
    pub fn new(
        shard_group: Hash,
        signing_key: KeyPair,
        topology: Arc<dyn Topology>,
        timeout: Duration,
    ) -> Self {
        Self {
            shard_group,
            signing_key,
            topology,
            timeout,
            last_progress_time: Duration::ZERO,
            current_round: 0,
            current_height: 0,
            timeout_vote_broadcast: false,
            vote_collector: HashMap::new(),
            highest_qc: QuorumCertificate::genesis(),
            highest_qc_collector: HashMap::new(),
            pending_vote_verifications: HashMap::new(),
            pending_qc_verifications: HashMap::new(),
            now: Duration::ZERO,
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Topology Accessors
    // ═══════════════════════════════════════════════════════════════════════════

    /// Get the local validator ID.
    fn validator_id(&self) -> ValidatorId {
        self.topology.local_validator_id()
    }

    /// Get the local shard.
    fn local_shard(&self) -> ShardGroupId {
        self.topology.local_shard()
    }

    /// Get the local committee.
    fn committee(&self) -> &[ValidatorId] {
        self.topology.local_committee()
    }

    /// Get the total voting power.
    fn total_voting_power(&self) -> u64 {
        self.topology.local_voting_power()
    }

    /// Get voting power for a validator.
    fn voting_power(&self, validator_id: ValidatorId) -> u64 {
        self.topology.voting_power(validator_id).unwrap_or(0)
    }

    /// Get public key for a validator.
    fn public_key(&self, validator_id: ValidatorId) -> Option<PublicKey> {
        self.topology.public_key(validator_id)
    }

    /// Check if we have quorum.
    #[allow(dead_code)]
    fn has_quorum(&self, voting_power: u64) -> bool {
        self.topology.local_has_quorum(voting_power)
    }

    /// Get committee index for a validator.
    fn committee_index(&self, validator_id: ValidatorId) -> Option<usize> {
        self.topology.local_committee_index(validator_id)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Public API
    // ═══════════════════════════════════════════════════════════════════════════

    /// Set the current time.
    pub fn set_time(&mut self, now: Duration) {
        self.now = now;
    }

    /// Get the current round.
    pub fn current_round(&self) -> u64 {
        self.current_round
    }

    /// Get the current height.
    pub fn current_height(&self) -> u64 {
        self.current_height
    }

    /// Get the highest QC.
    pub fn highest_qc(&self) -> &QuorumCertificate {
        &self.highest_qc
    }

    /// Update the highest QC we've seen.
    pub fn update_highest_qc(&mut self, qc: QuorumCertificate) {
        if qc.height > self.highest_qc.height {
            debug!(
                old_height = self.highest_qc.height.0,
                new_height = qc.height.0,
                "Updated highest QC for view change"
            );
            self.highest_qc = qc;
        }
    }

    /// Check if a view change should occur.
    ///
    /// Returns true if timeout has elapsed since last progress at the current height.
    pub fn should_change_view(&self) -> bool {
        // Don't trigger view change at genesis height
        if self.current_height == 0 {
            return false;
        }

        // Check if timeout elapsed
        let elapsed = self.now.saturating_sub(self.last_progress_time);
        elapsed > self.timeout
    }

    /// Reset timeout due to progress (block committed).
    pub fn reset_timeout(&mut self, height: u64) {
        let old_height = self.current_height;

        // Update height
        self.current_height = height;

        // If height increased, reset round to 0
        if height > old_height {
            self.current_round = 0;
            debug!(height = height, "Progress made, reset to round 0");
        }

        // Update last progress time
        self.last_progress_time = self.now;

        // Reset view change state
        self.timeout_vote_broadcast = false;
        self.cleanup_old_votes(height);
    }

    /// Handle view change timer event.
    ///
    /// Returns actions to take (broadcast vote, set timer).
    pub fn on_view_change_timer(&mut self) -> Vec<Action> {
        let mut actions = vec![];

        // Always reschedule the timer
        actions.push(Action::SetTimer {
            id: TimerId::ViewChange,
            duration: self.timeout,
        });

        // Check if we should trigger view change
        if !self.should_change_view() {
            info!(
                current_height = self.current_height,
                now = ?self.now,
                last_progress_time = ?self.last_progress_time,
                timeout = ?self.timeout,
                "View change timer fired but should_change_view = false"
            );
            return actions;
        }

        info!(
            current_height = self.current_height,
            current_round = self.current_round,
            "View change timer fired, triggering view change"
        );

        // Create and broadcast view change vote
        if let Some(vote) = self.create_view_change_vote() {
            debug!(
                height = vote.height.0,
                current_round = vote.current_round,
                new_view = vote.new_view,
                "Broadcasting view change vote"
            );

            let gossip = ViewChangeVoteGossip { vote: vote.clone() };

            actions.push(Action::BroadcastToShard {
                shard: self.local_shard(),
                message: OutboundMessage::ViewChangeVote(gossip),
            });

            // Process our own vote directly (no verification needed - we just created it)
            // Skip the signature verification since we signed it ourselves
            actions.extend(self.finalize_vote(vote));
        }

        actions
    }

    /// Create a view change vote for broadcasting.
    ///
    /// Returns None if already broadcast for current timeout.
    pub fn create_view_change_vote(&mut self) -> Option<ViewChangeVote> {
        // Only create vote once per timeout period
        if self.timeout_vote_broadcast {
            return None;
        }
        self.timeout_vote_broadcast = true;

        let height = BlockHeight(self.current_height);
        let current_round = self.current_round;
        let new_round = current_round + 1;

        // Sign the vote: (shard_group, height, new_round)
        let message = Self::view_change_message(&self.shard_group, height, new_round);
        let signature = self.signing_key.sign(&message);

        Some(ViewChangeVote::new(
            height,
            current_round,
            new_round,
            self.validator_id(),
            self.highest_qc.clone(),
            signature,
        ))
    }

    /// Create the message bytes to sign for a view change vote.
    pub fn view_change_message(shard_group: &Hash, height: BlockHeight, new_round: u64) -> Vec<u8> {
        let mut message = Vec::with_capacity(60);
        message.extend_from_slice(b"view_change:");
        message.extend_from_slice(shard_group.as_bytes());
        message.extend_from_slice(&height.0.to_le_bytes());
        message.extend_from_slice(&new_round.to_le_bytes());
        message
    }

    /// Get the shard group hash (needed for signing message construction).
    pub fn shard_group(&self) -> &Hash {
        &self.shard_group
    }

    /// Handle a view change vote from another validator.
    ///
    /// Performs initial validation and delegates signature verification to the runner.
    /// Returns actions to verify the vote signature.
    pub fn on_view_change_vote(&mut self, vote: ViewChangeVote) -> Vec<Action> {
        let (height, new_round) = vote.vote_key();
        let vote_key = (height.0, new_round, vote.voter);

        // Ignore votes for old heights
        if height.0 < self.current_height {
            debug!(
                vote_height = height.0,
                current_height = self.current_height,
                "Ignoring view change vote for old height"
            );
            return vec![];
        }

        // Ignore votes for rounds we've already passed
        if height.0 == self.current_height && new_round <= self.current_round {
            debug!(
                new_round = new_round,
                current_round = self.current_round,
                "Ignoring view change vote for old/current round"
            );
            return vec![];
        }

        // Check if already pending verification
        if self.pending_vote_verifications.contains_key(&vote_key)
            || self.pending_qc_verifications.contains_key(&vote_key)
        {
            debug!(voter = ?vote.voter, "Vote already pending verification");
            return vec![];
        }

        // Check for duplicate (already accepted vote)
        let voters = self.vote_collector.get(&(height.0, new_round));
        if voters.is_some_and(|v| v.contains_key(&vote.voter)) {
            debug!(voter = ?vote.voter, "Ignoring duplicate view change vote");
            return vec![];
        }

        // Verify the voter is in the committee
        if self.committee_index(vote.voter).is_none() {
            warn!(voter = ?vote.voter, "View change vote from unknown validator");
            return vec![];
        }

        let public_key = match self.public_key(vote.voter) {
            Some(pk) => pk,
            None => {
                warn!(voter = ?vote.voter, "No public key for voter");
                return vec![];
            }
        };

        // Store pending verification marker
        self.pending_vote_verifications
            .insert(vote_key, PendingVoteVerification);

        // Delegate vote signature verification to runner
        let signing_message = Self::view_change_message(&self.shard_group, height, new_round);
        vec![Action::VerifyViewChangeVoteSignature {
            vote,
            public_key,
            signing_message,
        }]
    }

    /// Handle vote signature verification result.
    ///
    /// If valid, proceeds to verify the highest_qc (if non-genesis).
    /// Returns actions to verify the QC signature, or finalizes the vote if genesis QC.
    pub fn on_vote_signature_verified(&mut self, vote: ViewChangeVote, valid: bool) -> Vec<Action> {
        let (height, new_round) = vote.vote_key();
        let vote_key = (height.0, new_round, vote.voter);

        // Remove from pending
        if self.pending_vote_verifications.remove(&vote_key).is_none() {
            warn!(voter = ?vote.voter, "Vote signature verified but not pending");
            return vec![];
        }

        if !valid {
            warn!(voter = ?vote.voter, "View change vote has invalid signature");
            return vec![];
        }

        // Check the attached highest_qc has quorum (structural check)
        let total_power = self.total_voting_power();
        if !vote.highest_qc.is_genesis() && !vote.highest_qc.has_quorum(total_power) {
            warn!(voter = ?vote.voter, "View change vote contains QC without quorum");
            return vec![];
        }

        // If highest_qc is genesis, skip QC verification and finalize directly
        if vote.highest_qc.is_genesis() {
            return self.finalize_vote(vote);
        }

        // Get public keys for QC signers
        let signer_keys: Vec<PublicKey> = vote
            .highest_qc
            .signers
            .set_indices()
            .filter_map(|idx| {
                self.topology
                    .local_validator_at_index(idx)
                    .and_then(|v| self.public_key(v))
            })
            .collect();

        if signer_keys.is_empty() {
            warn!(voter = ?vote.voter, "No valid signer keys for highest_qc");
            return vec![];
        }

        // Store pending QC verification marker
        self.pending_qc_verifications
            .insert(vote_key, PendingHighestQcVerification);

        // Construct signing message for the highest_qc with domain separation
        let signing_message = BftState::block_vote_message(
            &self.shard_group,
            vote.highest_qc.height.0,
            vote.highest_qc.round,
            &vote.highest_qc.block_hash,
        );

        // Delegate QC signature verification to runner
        vec![Action::VerifyViewChangeHighestQc {
            vote,
            public_keys: signer_keys,
            signing_message,
        }]
    }

    /// Handle highest_qc signature verification result.
    ///
    /// If valid, finalizes the vote and checks for quorum.
    pub fn on_highest_qc_verified(&mut self, vote: ViewChangeVote, valid: bool) -> Vec<Action> {
        let (height, new_round) = vote.vote_key();
        let vote_key = (height.0, new_round, vote.voter);

        // Remove from pending
        if self.pending_qc_verifications.remove(&vote_key).is_none() {
            warn!(voter = ?vote.voter, "Highest QC verified but not pending");
            return vec![];
        }

        if !valid {
            warn!(voter = ?vote.voter, "View change vote has invalid highest_qc signature");
            return vec![];
        }

        self.finalize_vote(vote)
    }

    /// Finalize a view change vote after all verifications pass.
    ///
    /// Adds the vote to the collector and checks for quorum.
    fn finalize_vote(&mut self, vote: ViewChangeVote) -> Vec<Action> {
        let (height, new_round) = vote.vote_key();
        let vote_key = (height.0, new_round);

        // Track the highest QC seen for this (height, new_round)
        self.highest_qc_collector
            .entry(vote_key)
            .and_modify(|existing| {
                if vote.highest_qc.height > existing.height {
                    *existing = vote.highest_qc.clone();
                }
            })
            .or_insert(vote.highest_qc.clone());

        // Add vote to collector
        let voters = self.vote_collector.entry(vote_key).or_default();

        // Double-check for duplicate (shouldn't happen, but be safe)
        if voters.contains_key(&vote.voter) {
            debug!(voter = ?vote.voter, "Ignoring duplicate view change vote in finalize");
            return vec![];
        }

        // Add new vote
        voters.insert(
            vote.voter,
            (vote.signature.clone(), vote.highest_qc.clone()),
        );

        // Calculate voting power
        let voter_ids: Vec<ValidatorId> = voters.keys().copied().collect();
        let vote_power = self.calculate_voting_power(&voter_ids);
        let total_power = self.total_voting_power();

        debug!(
            height = height.0,
            new_round = new_round,
            vote_power = vote_power,
            total_power = total_power,
            "View change vote added"
        );

        // Check for quorum
        if VotePower::has_quorum(vote_power, total_power) {
            debug!(
                height = height.0,
                new_round = new_round,
                "View change quorum reached"
            );

            // Emit internal event to trigger view change completion
            return vec![Action::EnqueueInternal {
                event: Event::ViewChangeCompleted {
                    height: height.0,
                    new_round,
                },
            }];
        }

        vec![]
    }

    /// Legacy method for backward compatibility with tests.
    /// Performs synchronous verification (NOT for production use).
    #[cfg(test)]
    pub fn add_view_change_vote(&mut self, vote: ViewChangeVote) -> Option<(u64, u64)> {
        let (height, new_round) = vote.vote_key();

        // Perform all the checks that on_view_change_vote does
        if height.0 < self.current_height {
            return None;
        }
        if height.0 == self.current_height && new_round <= self.current_round {
            return None;
        }
        self.committee_index(vote.voter)?;
        let public_key = self.public_key(vote.voter)?;

        // Synchronous signature verification (test only)
        let message = Self::view_change_message(&self.shard_group, height, new_round);
        if !public_key.verify(&message, &vote.signature) {
            return None;
        }

        // Check QC quorum
        let total_power = self.total_voting_power();
        if !vote.highest_qc.is_genesis() && !vote.highest_qc.has_quorum(total_power) {
            return None;
        }

        // Finalize vote and check for quorum
        let actions = self.finalize_vote(vote);

        // Check if quorum was reached (ViewChangeCompleted emitted)
        for action in actions {
            if let Action::EnqueueInternal {
                event: Event::ViewChangeCompleted { height, new_round },
            } = action
            {
                return Some((height, new_round));
            }
        }

        None
    }

    /// Calculate total voting power for a set of voters.
    fn calculate_voting_power(&self, voters: &[ValidatorId]) -> u64 {
        voters.iter().map(|&v| self.voting_power(v)).sum()
    }

    /// Apply a view change after quorum reached.
    ///
    /// This is called when `add_view_change_vote` returns `Some((height, new_round))`,
    /// indicating quorum was reached. The caller must invoke this to actually apply
    /// the view change and get the resulting actions.
    pub fn apply_view_change(&mut self, height: u64, new_round: u64) -> Vec<Action> {
        // Verify this is a valid transition
        if height != self.current_height {
            warn!(
                height = height,
                current_height = self.current_height,
                "Cannot apply view change for different height"
            );
            return vec![];
        }

        if new_round <= self.current_round {
            debug!(
                new_round = new_round,
                current_round = self.current_round,
                "View change already applied"
            );
            return vec![];
        }

        // Update to new round
        self.current_round = new_round;
        self.last_progress_time = self.now;
        self.timeout_vote_broadcast = false;

        info!(
            height = height,
            new_round = new_round,
            "Applied coordinated view change"
        );

        // Clean up old votes
        self.cleanup_old_votes(height);

        // Build and broadcast certificate
        let mut actions = vec![];
        if let Some(cert) = self.build_certificate(BlockHeight(height), new_round) {
            let gossip = hyperscale_messages::ViewChangeCertificateGossip { certificate: cert };
            actions.push(Action::BroadcastToShard {
                shard: self.local_shard(),
                message: OutboundMessage::ViewChangeCertificate(gossip),
            });
        }

        // Emit internal event for BFT state to react to
        actions.push(Action::EnqueueInternal {
            event: Event::ViewChangeCompleted { height, new_round },
        });

        actions
    }

    /// Build a ViewChangeCertificate from collected votes.
    pub fn build_certificate(
        &self,
        height: BlockHeight,
        new_round: u64,
    ) -> Option<ViewChangeCertificate> {
        let vote_key = (height.0, new_round);
        let voters = self.vote_collector.get(&vote_key)?;

        // Check quorum
        let vote_power: u64 = voters.keys().map(|&v| self.voting_power(v)).sum();
        let total_power = self.total_voting_power();

        if !VotePower::has_quorum(vote_power, total_power) {
            return None;
        }

        // Aggregate signatures
        let signatures: Vec<Signature> = voters.values().map(|(sig, _)| sig.clone()).collect();
        let aggregated_signature = match Signature::aggregate_bls(&signatures) {
            Ok(sig) => sig,
            Err(e) => {
                warn!(error = ?e, "Failed to aggregate view change signatures");
                return None;
            }
        };

        // Build signer bitfield
        let committee_size = self.committee().len();
        let mut signers = SignerBitfield::new(committee_size);
        for voter_id in voters.keys() {
            if let Some(idx) = self.committee_index(*voter_id) {
                signers.set(idx);
            }
        }

        // Get the highest QC collected
        let highest_qc = self
            .highest_qc_collector
            .get(&vote_key)
            .cloned()
            .unwrap_or_else(QuorumCertificate::genesis);
        let highest_qc_block_hash = highest_qc.block_hash;

        Some(ViewChangeCertificate {
            height,
            new_view: new_round,
            highest_qc,
            highest_qc_block_hash,
            aggregated_signature,
            signers,
            voting_power: VotePower(vote_power),
        })
    }

    /// Handle a received view change certificate.
    pub fn on_view_change_certificate(&mut self, cert: &ViewChangeCertificate) -> Vec<Action> {
        // Verify certificate is for current height
        if cert.height.0 != self.current_height {
            debug!(
                cert_height = cert.height.0,
                current_height = self.current_height,
                "Ignoring view change certificate for different height"
            );
            return vec![];
        }

        // Verify certificate is for future round
        if cert.new_round() <= self.current_round {
            debug!(
                cert_round = cert.new_round(),
                current_round = self.current_round,
                "Ignoring view change certificate for old/current round"
            );
            return vec![];
        }

        // Verify quorum
        let total_power = self.total_voting_power();
        if !cert.has_quorum(total_power) {
            warn!(
                voting_power = cert.voting_power.0,
                "View change certificate does not have quorum"
            );
            return vec![];
        }

        // Verify aggregated signature
        if let Err(e) = self.verify_certificate_signature(cert) {
            warn!(error = ?e, "View change certificate has invalid signature");
            return vec![];
        }

        // Verify embedded highest_qc
        if !cert.highest_qc.is_genesis() && !cert.highest_qc.has_quorum(total_power) {
            warn!("View change certificate contains QC without quorum");
            return vec![];
        }

        // Apply the view change
        self.current_round = cert.new_round();
        self.last_progress_time = self.now;
        self.timeout_vote_broadcast = false;

        info!(
            height = cert.height.0,
            new_round = cert.new_round(),
            "Applied view change from certificate"
        );

        self.cleanup_old_votes(cert.height.0);

        vec![Action::EnqueueInternal {
            event: Event::ViewChangeCompleted {
                height: cert.height.0,
                new_round: cert.new_round(),
            },
        }]
    }

    /// Verify a ViewChangeCertificate's aggregated BLS signature.
    fn verify_certificate_signature(&self, cert: &ViewChangeCertificate) -> Result<(), String> {
        // Get signer public keys from the bitfield
        let signer_keys: Vec<PublicKey> = cert
            .signers
            .set_indices()
            .filter_map(|idx| {
                self.topology
                    .local_validator_at_index(idx)
                    .and_then(|v| self.public_key(v))
            })
            .collect();

        if signer_keys.is_empty() {
            return Err("No signers in view change certificate".to_string());
        }

        if signer_keys.len() != cert.signers.count() {
            return Err(format!(
                "Could not find public keys for all signers: expected {}, found {}",
                cert.signers.count(),
                signer_keys.len()
            ));
        }

        // Aggregate public keys
        let aggregated_pubkey = PublicKey::aggregate_bls(&signer_keys)
            .map_err(|e| format!("Failed to aggregate signer keys: {}", e))?;

        // Construct the message that was signed
        let message = Self::view_change_message(&self.shard_group, cert.height, cert.new_round());

        // Verify the aggregated signature
        if !aggregated_pubkey.verify(&message, &cert.aggregated_signature) {
            return Err("View change certificate signature verification failed".to_string());
        }

        Ok(())
    }

    /// Clean up view change votes for old heights/rounds.
    fn cleanup_old_votes(&mut self, current_height: u64) {
        self.vote_collector
            .retain(|(height, _round), _voters| *height >= current_height);
        self.highest_qc_collector
            .retain(|(height, _round), _qc| *height >= current_height);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{KeyPair, StaticTopology, ValidatorInfo, ValidatorSet};
    use tracing_test::traced_test;

    fn make_test_state() -> (ViewChangeState, Vec<KeyPair>) {
        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();

        // Create validator set with ValidatorInfo
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);

        // Create topology
        let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));

        let shard_group = Hash::from_bytes(b"test_shard");

        let state = ViewChangeState::new(
            shard_group,
            keys[0].clone(),
            topology,
            Duration::from_secs(5),
        );

        (state, keys)
    }

    #[traced_test]
    #[test]
    fn test_no_view_change_at_genesis() {
        let (state, _) = make_test_state();
        assert!(!state.should_change_view());
    }

    #[traced_test]
    #[test]
    fn test_view_change_after_timeout() {
        let (mut state, _) = make_test_state();

        // Set height and last progress
        state.current_height = 1;
        state.last_progress_time = Duration::ZERO;

        // Advance time past timeout
        state.now = Duration::from_secs(6);

        assert!(state.should_change_view());
    }

    #[traced_test]
    #[test]
    fn test_create_view_change_vote() {
        let (mut state, _) = make_test_state();
        state.current_height = 1;
        state.now = Duration::from_secs(1);

        // First vote should succeed
        let vote = state.create_view_change_vote();
        assert!(vote.is_some());
        let vote = vote.unwrap();
        assert_eq!(vote.height.0, 1);
        assert_eq!(vote.current_round, 0);
        assert_eq!(vote.new_view, 1);

        // Second vote should fail (already broadcast)
        let vote2 = state.create_view_change_vote();
        assert!(vote2.is_none());
    }

    #[traced_test]
    #[test]
    fn test_add_view_change_votes_quorum() {
        let (mut state, keys) = make_test_state();
        state.current_height = 1;

        let shard_group = Hash::from_bytes(b"test_shard");

        // Create votes from validators 1, 2, 3
        // Note: Using range loop intentionally because i is used both for indexing keys
        // and for constructing ValidatorId (which must match the key index).
        #[allow(clippy::needless_range_loop)]
        for i in 1..=3 {
            let message = ViewChangeState::view_change_message(&shard_group, BlockHeight(1), 1);
            let signature = keys[i].sign(&message);
            let vote = ViewChangeVote::new(
                BlockHeight(1),
                0,
                1,
                ValidatorId(i as u64),
                QuorumCertificate::genesis(),
                signature,
            );

            let result = state.add_view_change_vote(vote);
            if i < 3 {
                assert!(result.is_none(), "Should not have quorum yet at vote {}", i);
            } else {
                assert_eq!(result, Some((1, 1)), "Should have quorum at vote 3");
            }
        }
    }

    #[traced_test]
    #[test]
    fn test_reset_timeout() {
        let (mut state, _) = make_test_state();
        state.current_height = 1;
        state.current_round = 2;
        state.now = Duration::from_secs(10);

        // Reset at same height - round should not reset
        state.reset_timeout(1);
        assert_eq!(state.current_round, 2);

        // Reset at new height - round should reset
        state.reset_timeout(2);
        assert_eq!(state.current_round, 0);
        assert_eq!(state.current_height, 2);
    }
}
