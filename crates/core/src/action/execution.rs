//! Execution work a shard loop delegates: tick and execution certificate
//! aggregation, transaction execution, and execution vote and
//! certificate sign-and-broadcast. Run by
//! `hyperscale_execution::action_handlers`.

use std::collections::BTreeSet;

use hyperscale_dispatch::DispatchPool;
use hyperscale_engine::TickEnvironment;
use hyperscale_storage::{FeeTerms, TickResolution};
use hyperscale_types::{
    BlockHash, BlockHeight, ConsensusPublicKey, ExecutionCertificate, ExecutionVote, Finalization,
    GlobalReceiptRoot, ShardId, TickId, TxHash, TxOutcome, ValidatorId, Verifiable, Verified,
    WeightedTimestamp,
};

use super::{CrossShardExecutionRequest, Delegated};

/// Execution work, run on the throughput dispatch pool.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum ExecutionAction {
    /// Sign and send an execution vote to `recipients` for aggregation.
    ///
    /// Emitted by the state machine when a tick completes (all txs
    /// executed), addressed to the tick leader alone, and on every retry,
    /// addressed to the whole attesting committee. The `io_loop` signs the
    /// vote (it owns the signing key) and sends it; whichever recipient
    /// holds 2f+1 votes aggregates them into an EC.
    SignAndSendExecutionVote {
        /// Block whose tick is being voted on.
        block_hash: BlockHash,
        /// Consensus timestamp at which this vote is being cast.
        vote_anchor_ts: WeightedTimestamp,
        /// Tick identifier whose execution is being attested to.
        tick_id: TickId,
        /// Global receipt root over the tick's per-tx outcomes.
        global_receipt_root: GlobalReceiptRoot,
        /// Per-tx outcomes in tick order. Carried on the vote so the
        /// leader can extract them directly when building the EC.
        tx_outcomes: Vec<TxOutcome>,
        /// Who tallies the vote, beyond the signers of the emitting
        /// replica: the vote goes to them over the network.
        recipients: Vec<ValidatorId>,
        /// Whether a signer of the emitting replica tallies the vote too:
        /// the vote is fed back to the replica rather than sent.
        local_recipient: bool,
        /// The attached signer attesting the tick.
        signer: ValidatorId,
    },

    /// Broadcast an execution certificate to local peers or remote shards.
    ///
    /// The tick leader broadcasts to both local committee peers (who need the
    /// EC since they don't aggregate) and remote participating shard committees.
    BroadcastExecutionCertificate {
        /// Target shard receiving the EC.
        shard: ShardId,
        /// Aggregated execution certificate.
        certificate: Verified<ExecutionCertificate>,
        /// Target shard peers (excluding self) for the broadcast.
        recipients: Vec<ValidatorId>,
        /// The signer preferred to sign the envelope. The certificate is
        /// self-authenticating, so any attached committee signer may.
        signer: ValidatorId,
    },

    /// Aggregate execution votes into an `ExecutionCertificate` (quorum reached).
    ///
    /// Performs signature aggregation on execution votes.
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionCertificateAggregated` when complete.
    AggregateExecutionCertificate {
        /// Tick identifier. The producing shard is `tick_id.shard_id`.
        tick_id: TickId,
        /// Global receipt root (merkle root over per-tx outcome leaves).
        global_receipt_root: GlobalReceiptRoot,
        /// Verified votes to aggregate (with quorum). The first vote's
        /// `tx_outcomes` is used for the EC payload (all quorum votes have
        /// identical outcomes).
        votes: Vec<Verified<ExecutionVote>>,
        /// Ordered committee for the shard (for `SignerBitfield` index mapping).
        committee: Vec<ValidatorId>,
    },

    /// Batch verify execution votes (deferred verification).
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionVotesVerifiedAndAggregated` when complete.
    VerifyAndAggregateExecutionVotes {
        /// Tick identifier.
        tick_id: TickId,
        /// Block hash for correlation.
        block_hash: BlockHash,
        /// Votes to verify with their public keys.
        votes: Vec<(ExecutionVote, ConsensusPublicKey)>,
    },

    /// Verify an execution certificate's aggregated signature.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionCertificateSignatureVerified` when complete.
    VerifyExecutionCertificateSignature {
        /// The execution certificate to verify. A
        /// `Verifiable::Verified` wrapper short-circuits
        /// verification.
        certificate: Verifiable<ExecutionCertificate>,
        /// Public keys of the signers (in committee order).
        public_keys: Vec<ConsensusPublicKey>,
    },

    /// Verify a fetched [`Finalization`]'s certificate in one async
    /// dispatch.
    ///
    /// Used by `ExecutionCoordinator::admit_finalization` to keep the
    /// state-machine call off the signature verification critical path.
    /// Returns `ProtocolEvent::FinalizationVerified` when complete.
    VerifyFinalization {
        /// The finalization whose certificate needs signature
        /// verification before admission. A `Verifiable::Verified`
        /// wrapper short-circuits verification.
        finalization: Verifiable<Finalization>,
        /// The committee of its certificate, in committee order; `None`
        /// for a legs half, which carries none.
        public_keys: Option<Vec<ConsensusPublicKey>>,
    },

    /// Build the legs half of `tick` accepting `names` from the yes
    /// receipts the stated rows stage in the committed state at `tip`.
    ///
    /// Any replica holding the chain builds it, whether or not it ran the
    /// tick. A name whose row no longer stands stated there is left out.
    /// Returns `ProtocolEvent::LegsHalfBuilt` when complete.
    BuildLegsHalf {
        /// The tick whose stated members accept.
        tick: TickId,
        /// The members whose rows accept at `tip`.
        names: BTreeSet<TxHash>,
        /// The committed block the names were read at.
        tip: BlockHash,
        /// Its height.
        tip_height: BlockHeight,
    },

    /// Execute one tick's whole batch: the committing block's
    /// local-only tick beside every cross-shard tick whose provisions
    /// completed at that commit, as one executor batch.
    ///
    /// Delegated to the engine thread pool in production, instant in
    /// simulation. Ticks dispatch serially — the coordinator holds the
    /// next tick until this one's `ProtocolEvent::ExecutionBatchCompleted`
    /// returns, because the tick's output is the next tick's baseline.
    /// The handler reads through `TickChain::view_at` at the previous
    /// tick, never through the settlement overlay.
    ExecuteTransactions {
        /// Tick identifier: the committing block's height.
        tick: BlockHeight,
        /// Every fate the coordinator held for the tick when it dispatched
        /// it, which the chain applies as it appends the output: a tick
        /// run after its fate committed leaves what the base already
        /// carries, and no read may find its entry before that is said.
        fates: Vec<TickResolution>,
        /// The committing block's parent-QC weighted timestamp.
        tick_ts: WeightedTimestamp,
        /// What the block fixed about the environment: the seeds a
        /// sealed draw may settle on and the epoch grid a clock resolves
        /// against. Resolved by the coordinator off the block's anchored
        /// committee, not the `ArcSwap` head, so every replica executes
        /// the tick over one window however far each has folded the
        /// beacon.
        env: TickEnvironment,
        /// Tick-attributed members of the batch. Results fan back to each
        /// tick by `tick_id`.
        /// The members, each with its provisions and environment.
        requests: Vec<CrossShardExecutionRequest>,
        /// The fee terms of every transaction the committing block
        /// carries, members of the batch or not: the holds that block's
        /// commit includes, which stand on their vaults for this tick
        /// and are in no base it reads.
        included: Vec<FeeTerms>,
    },
}

impl Delegated for ExecutionAction {
    const POOL: DispatchPool = DispatchPool::Throughput;

    fn type_name(&self) -> &'static str {
        self.into()
    }

    fn signer(&self) -> Option<ValidatorId> {
        match self {
            Self::SignAndSendExecutionVote { signer, .. }
            | Self::BroadcastExecutionCertificate { signer, .. } => Some(*signer),
            Self::AggregateExecutionCertificate { .. }
            | Self::VerifyAndAggregateExecutionVotes { .. }
            | Self::VerifyExecutionCertificateSignature { .. }
            | Self::VerifyFinalization { .. }
            | Self::BuildLegsHalf { .. }
            | Self::ExecuteTransactions { .. } => None,
        }
    }

    fn envelope_only(&self) -> bool {
        matches!(self, Self::BroadcastExecutionCertificate { .. })
    }
}
