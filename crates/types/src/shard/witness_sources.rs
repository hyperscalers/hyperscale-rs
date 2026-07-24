//! [`WitnessSources`] — the proposer-supplied inputs to a block's
//! beacon-witness leaf derivation.

use std::sync::Arc;

use sbor::prelude::*;

use crate::{BoundedVec, MAX_READY_SIGNALS_PER_BLOCK, ReadySignal, ReshapeTrigger, VrfProof};

/// Shared handle to a block's [`WitnessSources`] — wrapped in `Arc` so
/// verification actions can hold their own owner without deep-cloning,
/// same rationale as `SharedTransactions`.
pub type SharedWitnessSources = Arc<WitnessSources>;

/// Proposer-supplied inputs to a block's beacon-witness leaf derivation.
///
/// Every leaf the derivation cannot reproduce from the block's other
/// content rides here: receipt-sourced leaves derive from the carried
/// certificates and missed-proposal leaves from the header's round gap,
/// but these three are the proposer's own — drained from its gossip
/// pool, asserted from its load predicate, or signed with its key.
/// (Double-vote evidence rides the global gossip lane to the beacon
/// instead — a network-carried channel needs no chain carriage.)
///
/// All three share one contract: the header's `beacon_witness_root`
/// commits them, voters re-verify them as a block-validity condition
/// (so the QC transitively attests them), and they ride the block body
/// so commit-time leaf derivation is byte-identical on every node
/// however the block arrived — proposed, synced, or reloaded. They are
/// retained through sealing (unlike provisions) because the
/// beacon-witness fold consuming them can run well after the block
/// seals.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct WitnessSources {
    /// Validator-emitted ready signals the proposer drained from its
    /// pool — one readiness leaf each.
    ready_signals: BoundedVec<ReadySignal, MAX_READY_SIGNALS_PER_BLOCK>,
    /// The proposer's reshape assertion, if any — validated against the
    /// locally recomputed load predicate.
    reshape_trigger: Option<ReshapeTrigger>,
    /// The proposer's per-block randomness reveal — the VRF proof over
    /// `(network, shard, height)` whose digest is leaf 0 of the block's
    /// witness contribution. Re-verified against the proposer's key;
    /// genesis blocks carry [`VrfProof::ZERO`].
    randomness_reveal: VrfProof,
}

impl WitnessSources {
    /// Build from the proposer's drained parts.
    ///
    /// # Panics
    ///
    /// Panics if a list exceeds its per-block cap.
    #[must_use]
    pub fn new(
        ready_signals: Vec<ReadySignal>,
        reshape_trigger: Option<ReshapeTrigger>,
        randomness_reveal: VrfProof,
    ) -> Self {
        Self {
            ready_signals: ready_signals.into(),
            reshape_trigger,
            randomness_reveal,
        }
    }

    /// The sources of a content-free block, with the reveal at its
    /// [`VrfProof::ZERO`] sentinel — the shape genesis blocks carry.
    /// Deliberately not a `Default` impl: the sentinel stays an
    /// explicit choice so `VrfProof` is never blanket-defaultable to an
    /// invalid proof.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            ready_signals: BoundedVec::new(),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        }
    }

    /// Validator-emitted ready signals the proposer included. The leaf
    /// derivation projects one readiness leaf per signal.
    #[must_use]
    pub const fn ready_signals(&self) -> &BoundedVec<ReadySignal, MAX_READY_SIGNALS_PER_BLOCK> {
        &self.ready_signals
    }

    /// The proposer's reshape assertion, if any.
    #[must_use]
    pub const fn reshape_trigger(&self) -> Option<ReshapeTrigger> {
        self.reshape_trigger
    }

    /// The proposer's randomness reveal.
    #[must_use]
    pub const fn randomness_reveal(&self) -> &VrfProof {
        &self.randomness_reveal
    }
}
