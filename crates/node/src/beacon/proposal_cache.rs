//! Process-level serve cache for beacon proposals.
//!
//! Backs the inbound `GetBeaconProposalRequest` responder so peers can
//! recover proposals they missed on gossip. Fed at the two admission
//! boundaries — the wire `BeaconProposalNotification` handler and the
//! `BuildAndBroadcastBeaconProposal` action handler's locally signed
//! proposal — so serving never reads any vnode's coordinator pool.
//! Entries are verified against their author before admission; an
//! unauthenticated peer can't occupy a validator's serve slot with junk.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::BeaconChainReader;
use hyperscale_types::network::request::beacon::GetBeaconProposalRequest;
use hyperscale_types::network::response::beacon::GetBeaconProposalResponse;
use hyperscale_types::{
    BeaconProposal, BeaconProposalVerifyContext, ConsensusPublicKey, Epoch, NetworkDefinition,
    ValidatorId, Verifiable, Verified, Verifier, Verify,
};

/// Epochs held past this host's committed beacon tip: the in-flight
/// epoch, and the one after it for a proposer whose commit landed before
/// this host's did.
const EPOCHS_AHEAD: u64 = 2;

type Proposals = BTreeMap<ValidatorId, Arc<Verified<BeaconProposal>>>;

/// Per-epoch cache of beacon proposals for inbound fetch serving.
///
/// Holds only the epochs a proposal can be pending in, as this host's
/// own committed beacon chain places them. Any validator can sign a
/// reveal for any epoch, so a window drawn from what arrives would let
/// one far-future proposal push the cache past the epoch its peers are
/// fetching.
pub struct BeaconProposalCache {
    /// Domain bytes proposals verify under — the same beacon network
    /// definition the coordinators sign with.
    network: NetworkDefinition,
    beacon: Arc<dyn BeaconChainReader>,
    window: Mutex<BTreeMap<Epoch, Proposals>>,
}

impl BeaconProposalCache {
    pub(crate) fn new(network: NetworkDefinition, beacon: Arc<dyn BeaconChainReader>) -> Self {
        Self {
            network,
            beacon,
            window: Mutex::new(BTreeMap::new()),
        }
    }

    /// Admit a verified proposal when `epoch` sits in the window above
    /// this host's committed tip, dropping epochs the tip has passed.
    /// First write per `(epoch, validator)` wins, mirroring the
    /// coordinator pools' discipline.
    pub(crate) fn admit(
        &self,
        from: ValidatorId,
        epoch: Epoch,
        proposal: Arc<Verified<BeaconProposal>>,
    ) {
        let Some(in_flight) = self.beacon.latest_committed_epoch().map(Epoch::next) else {
            return;
        };
        let mut window = self.window.lock().expect("beacon proposal cache lock");
        *window = window.split_off(&in_flight);
        if epoch < in_flight || epoch.inner() >= in_flight.inner() + EPOCHS_AHEAD {
            return;
        }
        window
            .entry(epoch)
            .or_default()
            .entry(from)
            .or_insert(proposal);
    }

    /// Admit a wire proposal: reuse a surviving `Verified` marker
    /// (local dispatch), otherwise verify under `sender_pk` and drop on
    /// failure.
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
        let held = self
            .window
            .lock()
            .expect("beacon proposal cache lock")
            .get(&req.epoch)
            .and_then(|proposals| proposals.get(&req.validator).cloned());
        let response = GetBeaconProposalResponse::new(
            held.map(|verified| Arc::new(Verifiable::from((*verified).clone()))),
        );
        record_fetch_response_sent("beacon_proposal", usize::from(response.proposal.is_some()));
        response
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use hyperscale_types::{BeaconBlockHash, BeaconState, CertifiedBeaconBlock, VrfProof};

    use super::*;

    /// A beacon chain whose committed tip is set by the test.
    struct Tip(AtomicU64);

    impl BeaconChainReader for Tip {
        fn get_beacon_block_by_epoch(
            &self,
            _epoch: Epoch,
        ) -> Option<Arc<Verified<CertifiedBeaconBlock>>> {
            None
        }

        fn get_beacon_block_by_hash(
            &self,
            _hash: BeaconBlockHash,
        ) -> Option<Arc<Verified<CertifiedBeaconBlock>>> {
            None
        }

        fn get_state_by_epoch(&self, _epoch: Epoch) -> Option<Arc<BeaconState>> {
            None
        }

        fn latest_committed_epoch(&self) -> Option<Epoch> {
            Some(Epoch::new(self.0.load(Ordering::Relaxed)))
        }

        fn latest_committed(
            &self,
        ) -> Option<(Arc<Verified<CertifiedBeaconBlock>>, Arc<BeaconState>)> {
            None
        }
    }

    fn cache_at(tip: u64) -> (BeaconProposalCache, Arc<Tip>) {
        let chain = Arc::new(Tip(AtomicU64::new(tip)));
        let cache = BeaconProposalCache::new(
            NetworkDefinition::simulator(),
            Arc::clone(&chain) as Arc<dyn BeaconChainReader>,
        );
        (cache, chain)
    }

    fn proposal() -> Arc<Verified<BeaconProposal>> {
        Arc::new(Verified::new_unchecked_for_test(BeaconProposal::vrf_only(
            VrfProof::new([0xAB; 96]),
        )))
    }

    fn served(cache: &BeaconProposalCache, epoch: u64, validator: u64) -> bool {
        cache
            .serve(&GetBeaconProposalRequest::new(
                Epoch::new(epoch),
                ValidatorId::new(validator),
            ))
            .proposal
            .is_some()
    }

    /// A proposal signed for an epoch far past the tip is not held, and
    /// the in-flight epoch's proposals stay served.
    #[test]
    fn a_far_future_proposal_does_not_displace_the_in_flight_epoch() {
        let (cache, _) = cache_at(9);
        cache.admit(ValidatorId::new(1), Epoch::new(10), proposal());
        cache.admit(ValidatorId::new(2), Epoch::new(1_000_000), proposal());

        assert!(served(&cache, 10, 1));
        assert!(!served(&cache, 1_000_000, 2));
    }

    /// The epoch after the in-flight one is held beside it, for a
    /// proposer whose commit landed first.
    #[test]
    fn the_next_epoch_is_held_beside_the_in_flight_one() {
        let (cache, _) = cache_at(9);
        cache.admit(ValidatorId::new(1), Epoch::new(10), proposal());
        cache.admit(ValidatorId::new(1), Epoch::new(11), proposal());
        cache.admit(ValidatorId::new(1), Epoch::new(12), proposal());

        assert!(served(&cache, 10, 1));
        assert!(served(&cache, 11, 1));
        assert!(!served(&cache, 12, 1));
    }

    /// Epochs the tip has committed past drop on the next admission,
    /// and nothing below the in-flight epoch is taken.
    #[test]
    fn a_committed_epoch_drops_as_the_tip_passes_it() {
        let (cache, chain) = cache_at(9);
        cache.admit(ValidatorId::new(1), Epoch::new(10), proposal());

        chain.0.store(10, Ordering::Relaxed);
        cache.admit(ValidatorId::new(1), Epoch::new(10), proposal());
        cache.admit(ValidatorId::new(1), Epoch::new(11), proposal());

        assert!(!served(&cache, 10, 1));
        assert!(served(&cache, 11, 1));
    }
}
