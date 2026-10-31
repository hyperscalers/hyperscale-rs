//! Provision work a shard loop delegates: state provision verification
//! and outbound provision and crossing reading broadcast. Run by
//! `hyperscale_provisions::action_handlers`.

use std::collections::{BTreeMap, HashMap};

use hyperscale_dispatch::DispatchPool;
use hyperscale_types::{
    Anchor, BlockHash, BlockHeight, Provisions, ShardId, SubstateKey, ValidatorId,
    WeightedTimestamp,
};

use super::{Delegated, ProvisionsRequest};

/// Provision work, run on the throughput dispatch pool.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum ProvisionAction {
    /// Prove the crossing records the committed block at `anchor` wrote
    /// and push each to the committee of every shard that reads it.
    ///
    /// Emitted by the proposer of the block after `anchor`'s, whose
    /// certified header is what proves the anchor to a consumer, so the
    /// push lands beside its proof. Delegated to the execution pool,
    /// where each target's keys are read at the block's own view, proved
    /// at its root, built into held claims and sent as
    /// `CrossingReadingsNotification`s.
    PushCrossingReadings {
        /// The block whose records are pushed.
        block_hash: BlockHash,
        /// That block's anchor: the claims' anchor and the proof's root.
        anchor: Anchor,
        /// The record keys to push, by the shard reading each.
        targets: BTreeMap<ShardId, Vec<SubstateKey>>,
        /// Each target's committee.
        shard_recipients: HashMap<ShardId, Vec<ValidatorId>>,
        /// The signer preferred to sign the envelopes: the proposer of the
        /// block after `anchor`'s.
        signer: ValidatorId,
    },

    /// Fetch state entries and broadcast provisions for all cross-shard txs in a block.
    ///
    /// Only the block proposer emits this (once per block). Delegated to the
    /// execution pool where it fetches entries, generates merkle proofs, builds
    /// per-shard provision batches, groups by target shard, and returns batches via
    /// `ProtocolEvent::OutboundProvisionBroadcast` for network broadcast.
    FetchAndBroadcastProvisions {
        /// The committed block whose state is being attested to. Anchors
        /// state reads via `PendingChain::view_at`. Merkle proofs are
        /// generated against this block's state root.
        block_hash: BlockHash,
        /// One entry per cross-shard tx that needs provisioning.
        requests: Vec<ProvisionsRequest>,
        /// Shard producing the provisions (this validator's shard).
        source_shard: ShardId,
        /// Source-shard block height the provisions are anchored to.
        block_height: BlockHeight,
        /// The source block's parent-QC weighted timestamp, carried on
        /// the bundle wire form and checked against the commit-proven
        /// header at verification.
        source_block_ts: WeightedTimestamp,
        /// Per-shard recipients for provision broadcasts (excluding self).
        shard_recipients: HashMap<ShardId, Vec<ValidatorId>>,
        /// The signer preferred to sign the envelopes: the block's proposer.
        signer: ValidatorId,
    },

    /// Verify provisions' merkle inclusion proofs.
    ///
    /// The QC was already verified by `RemoteHeaderCoordinator` when the header
    /// was promoted to verified, so this only checks merkle proofs against the
    /// certified header's state root.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::StateProvisionsVerified` when complete.
    VerifyProvisions {
        /// The provisions to verify (all from the same source block).
        provisions: Provisions,
        /// The source anchor whose `state_root` the proof is checked
        /// against — off the producing header for a pushed bundle, off
        /// this node's own mirror of what it has commit-proven for a
        /// pulled one.
        anchor: Anchor,
    },
}

impl Delegated for ProvisionAction {
    const POOL: DispatchPool = DispatchPool::Throughput;

    fn type_name(&self) -> &'static str {
        self.into()
    }

    fn signer(&self) -> Option<ValidatorId> {
        match self {
            Self::PushCrossingReadings { signer, .. }
            | Self::FetchAndBroadcastProvisions { signer, .. } => Some(*signer),
            Self::VerifyProvisions { .. } => None,
        }
    }

    fn envelope_only(&self) -> bool {
        matches!(
            self,
            Self::PushCrossingReadings { .. } | Self::FetchAndBroadcastProvisions { .. }
        )
    }
}
