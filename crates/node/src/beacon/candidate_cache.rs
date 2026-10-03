//! Process-level serve cache for ratify candidates.
//!
//! Backs the inbound `GetBeaconCandidateRequest` responder so a pool
//! member that missed a candidate on gossip can fetch it from one that
//! prevoted it. Fed at the two places a vnode comes to hold a candidate
//! — assembling it and verifying a peer's — so serving never reads any
//! vnode's coordinator.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_types::network::request::beacon::GetBeaconCandidateRequest;
use hyperscale_types::network::response::beacon::GetBeaconCandidateResponse;
use hyperscale_types::{BeaconBlockHash, CandidateBeaconBlock, Epoch, Verifiable, Verified};

/// Candidates held per epoch. One committee certifies one candidate;
/// two exist only when the committee equivocates, and the cap keeps
/// the cache bounded whatever it does.
const MAX_CANDIDATES_PER_EPOCH: usize = 4;

/// The newest epoch's candidates any vnode on this host assembled or
/// verified, by block hash. Older epochs drop on advance: a candidate
/// is only ever fetched while its epoch is pending.
pub struct BeaconCandidateCache {
    inner: Mutex<CachedEpoch>,
}

struct CachedEpoch {
    epoch: Epoch,
    candidates: BTreeMap<BeaconBlockHash, Arc<Verified<CandidateBeaconBlock>>>,
}

impl BeaconCandidateCache {
    pub(crate) const fn new() -> Self {
        Self {
            inner: Mutex::new(CachedEpoch {
                epoch: Epoch::GENESIS,
                candidates: BTreeMap::new(),
            }),
        }
    }

    /// Hold `candidate`, advancing the cache to its epoch when newer.
    /// A candidate for an older epoch, or past the per-epoch cap, is
    /// not held.
    pub(crate) fn admit(&self, candidate: Arc<Verified<CandidateBeaconBlock>>) {
        let mut cached = self.inner.lock().expect("beacon candidate cache lock");
        let epoch = candidate.epoch();
        if epoch > cached.epoch {
            cached.epoch = epoch;
            cached.candidates.clear();
        }
        if epoch < cached.epoch || cached.candidates.len() >= MAX_CANDIDATES_PER_EPOCH {
            return;
        }
        cached
            .candidates
            .entry(candidate.block_hash())
            .or_insert(candidate);
    }

    /// Serve an inbound fetch from the cache.
    pub(crate) fn serve(&self, req: &GetBeaconCandidateRequest) -> GetBeaconCandidateResponse {
        let candidate = {
            let cached = self.inner.lock().expect("beacon candidate cache lock");
            (cached.epoch == req.epoch)
                .then(|| cached.candidates.get(&req.block_hash).cloned())
                .flatten()
        };
        let response = GetBeaconCandidateResponse::new(
            candidate.map(|held| Arc::new(Verifiable::from((*held).clone()))),
        );
        record_fetch_response_sent(
            "beacon_candidate",
            usize::from(response.candidate.is_some()),
        );
        response
    }
}

impl Default for BeaconCandidateCache {
    fn default() -> Self {
        Self::new()
    }
}
