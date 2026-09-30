//! Signing message for a beacon proposal's body.
//!
//! The VRF reveal a proposal carries is a function of `(key, network,
//! epoch)` alone, so anyone holding it can pair it with other
//! observations. The body signature binds the proposer to the exact
//! witnesses and evidence it submitted; the reveal stays out of the
//! signed body's influence so the proposer cannot grind its randomness
//! contribution by varying what it reports.

use hyperscale_hbor::Hbor;

use crate::signing::NetworkId;
use crate::{Epoch, Hash};

/// What a beacon proposal's body signature covers: the epoch and the
/// digest of the proposal body, under the network.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-beacon-proposal-v1", signing_context = NetworkId)]
pub struct BeaconProposalMessage {
    /// The epoch the proposal targets.
    pub(crate) epoch: Epoch,
    /// Blake3 digest of the proposal body's canonical encoding.
    pub(crate) body: Hash,
}
