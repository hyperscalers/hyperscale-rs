//! Process-level serve cache for beacon proposals.
//!
//! Backs the inbound `GetBeaconProposalRequest` responder so peers can
//! recover proposals they missed on gossip. Fed at the two admission
//! boundaries — the wire `BeaconProposalNotification` handler and the
//! `BuildAndBroadcastBeaconProposal` action handler's locally signed
//! proposal — so serving never reads any vnode's coordinator pool.
//! Entries are VRF-verified before admission; an unauthenticated peer
//! can't occupy a validator's serve slot with junk.

use std::sync::{Arc, Mutex};

use hyperscale_beacon::proposal_pool::BeaconProposalPool;
use hyperscale_types::network::request::beacon::GetBeaconProposalRequest;
use hyperscale_types::network::response::beacon::GetBeaconProposalResponse;
use hyperscale_types::{
    BeaconProposal, BeaconProposalVerifyContext, ConsensusPublicKey, Epoch, NetworkDefinition,
    ValidatorId, Verifiable, Verified, Verifier, Verify,
};

use super::proposal_serve::serve_beacon_proposal_request;

/// Per-epoch cache of beacon proposals for inbound fetch serving.
///
/// Tracks the newest epoch any feed has seen; older entries drop on
/// advance, mirroring each coordinator pool's one-in-flight-epoch
/// scope. Writers race across the network worker (wire admissions) and
/// the consensus pool (the local proposer's own), so feeds serialize
/// through a mutex; reads stay lock-free on the pool's concurrent map.
pub struct BeaconProposalCache {
    /// Domain bytes the VRF reveal verifies under — the same beacon
    /// network definition the coordinators sign with.
    network: NetworkDefinition,
    /// Serializes epoch advance + admit so concurrent feeds can't
    /// interleave `reset` and leave the pool tracking a stale epoch.
    feed: Mutex<()>,
    pool: BeaconProposalPool,
}

impl BeaconProposalCache {
    pub(crate) fn new(network: NetworkDefinition) -> Self {
        Self {
            network,
            feed: Mutex::new(()),
            pool: BeaconProposalPool::new(Epoch::GENESIS),
        }
    }

    /// Admit a verified proposal, advancing the cache to `epoch` when
    /// newer. First write per `(epoch, validator)` wins, mirroring the
    /// coordinator pools' discipline.
    pub(crate) fn admit(
        &self,
        from: ValidatorId,
        epoch: Epoch,
        proposal: Arc<Verified<BeaconProposal>>,
    ) {
        let _feed = self.feed.lock().expect("beacon proposal cache feed lock");
        if epoch > self.pool.epoch() {
            self.pool.reset(epoch);
        }
        let _ = self.pool.admit(from, epoch, proposal);
    }

    /// Admit a wire proposal: reuse a surviving `Verified` marker
    /// (local dispatch), otherwise VRF-verify under `sender_pk` and
    /// drop on failure.
    pub(crate) fn admit_wire(
        &self,
        verifier: &dyn Verifier,
        from: ValidatorId,
        epoch: Epoch,
        proposal: &Verifiable<BeaconProposal>,
        sender_pk: ConsensusPublicKey,
    ) {
        let admitted = if let Some(verified) = proposal.verified() {
            verified.clone()
        } else {
            let ctx = BeaconProposalVerifyContext {
                verifier,
                network: &self.network,
                epoch,
                sender_pk,
            };
            match proposal.as_unverified().verify(&ctx) {
                Ok(fresh) => fresh,
                Err(_) => return,
            }
        };
        self.admit(from, epoch, Arc::new(admitted));
    }

    /// Serve an inbound fetch from the cache.
    pub(crate) fn serve(&self, req: &GetBeaconProposalRequest) -> GetBeaconProposalResponse {
        serve_beacon_proposal_request(&self.pool, req)
    }
}
