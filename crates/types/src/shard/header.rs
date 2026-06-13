//! Block header containing consensus metadata.
//!
//! [`BlockHeader`] is the raw wire form. Its verified form is
//! `Verified<BlockHeader>`; predicate at [`impl Verify<()>`](Verify::verify)
//! below.

use std::collections::{BTreeMap, BTreeSet};

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeight, BoundedBTreeMap, BoundedVec,
    CertificateRoot, ChainOrigin, Hash, InFlightCount, LocalReceiptRoot,
    MAX_REMOTE_SHARDS_PER_WAVE, MAX_TXS_PER_BLOCK, ProposerTimestamp, ProvisionTxRoot,
    ProvisionsRoot, QuorumCertificate, Round, ShardId, SplitChildRoots, StateRoot, TransactionRoot,
    ValidatorId, Verifiable, Verified, Verify, WaveId, WeightedTimestamp,
};

/// Block header containing consensus metadata.
///
/// The header is what validators vote on. It contains:
/// - Chain position (height, parent hash)
/// - Proposer identity
/// - Proof of parent commitment (parent QC)
/// - State commitment (JMT root after applying committed certificates)
/// - Transaction commitment (merkle root of all transactions in the block)
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockHeader {
    shard_id: ShardId,
    height: BlockHeight,
    parent_block_hash: BlockHash,
    parent_qc: Verifiable<QuorumCertificate>,
    proposer: ValidatorId,
    timestamp: ProposerTimestamp,
    round: Round,
    is_fallback: bool,
    state_root: StateRoot,
    transaction_root: TransactionRoot,
    certificate_root: CertificateRoot,
    local_receipt_root: LocalReceiptRoot,
    provision_root: ProvisionsRoot,
    waves: BoundedVec<WaveId, MAX_TXS_PER_BLOCK>,
    provision_tx_roots: BoundedBTreeMap<ShardId, ProvisionTxRoot, MAX_REMOTE_SHARDS_PER_WAVE>,
    in_flight: InFlightCount,
    beacon_witness_root: BeaconWitnessRoot,
    beacon_witness_leaf_count: BeaconWitnessLeafCount,
    /// The beacon-witness window base of the window this block belongs
    /// to — the folded watermark frozen at promotion, resolved from the
    /// same schedule entry as the block's committee
    /// (`epoch_for(parent_qc.wt)`). Verification rejects a header whose
    /// claim differs from the schedule-resolved value, so every
    /// downstream consumer (fold proofs, witness serving, snap-sync
    /// joiners) reads the base off the header instead of reconstructing
    /// historical beacon state.
    beacon_witness_base: BeaconWitnessLeafCount,
    /// The two child hashes of the JMT root node behind `state_root`,
    /// carried on every header of a split-pending shard's final epoch
    /// (`None` everywhere else). Produced by the same replay that fills
    /// `state_root` and verified beside it — see
    /// [`SplitChildRoots`]. The beacon seeds the post-split children's
    /// anchors from the terminal header's pair; it cannot decompose
    /// `state_root` itself.
    split_child_roots: Option<SplitChildRoots>,
}

impl BlockHeader {
    /// Build a `BlockHeader` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `waves.len() > MAX_TXS_PER_BLOCK` or
    /// `provision_tx_roots.len() > MAX_REMOTE_SHARDS_PER_WAVE`.
    #[allow(clippy::too_many_arguments)] // mirrors the 20 stored fields
    #[must_use]
    pub fn new(
        shard_id: ShardId,
        height: BlockHeight,
        parent_block_hash: BlockHash,
        parent_qc: impl Into<Verifiable<QuorumCertificate>>,
        proposer: ValidatorId,
        timestamp: ProposerTimestamp,
        round: Round,
        is_fallback: bool,
        state_root: StateRoot,
        transaction_root: TransactionRoot,
        certificate_root: CertificateRoot,
        local_receipt_root: LocalReceiptRoot,
        provision_root: ProvisionsRoot,
        waves: Vec<WaveId>,
        provision_tx_roots: BTreeMap<ShardId, ProvisionTxRoot>,
        in_flight: InFlightCount,
        beacon_witness_root: BeaconWitnessRoot,
        beacon_witness_leaf_count: BeaconWitnessLeafCount,
        beacon_witness_base: BeaconWitnessLeafCount,
        split_child_roots: Option<SplitChildRoots>,
    ) -> Self {
        Self {
            shard_id,
            height,
            parent_block_hash,
            parent_qc: parent_qc.into(),
            proposer,
            timestamp,
            round,
            is_fallback,
            state_root,
            transaction_root,
            certificate_root,
            local_receipt_root,
            provision_root,
            waves: waves.into(),
            provision_tx_roots: provision_tx_roots.into(),
            in_flight,
            beacon_witness_root,
            beacon_witness_leaf_count,
            beacon_witness_base,
            split_child_roots,
        }
    }

    /// Create a genesis block header with the given proposer and JMT
    /// state. The [`ChainOrigin`] supplies the genesis height and the
    /// chain's start-time anchor (see [`QuorumCertificate::genesis`]):
    /// [`ChainOrigin::ROOT`] for chains born at network genesis; a child
    /// chain created by a shard split continues the parent's height line
    /// and clock.
    #[must_use]
    pub fn genesis(
        shard_id: ShardId,
        proposer: ValidatorId,
        state_root: StateRoot,
        origin: ChainOrigin,
    ) -> Self {
        Self {
            shard_id,
            height: origin.genesis_height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(&[0u8; 32])),
            // Genesis QC carries no signature and is valid by definition;
            // `Verified::<QuorumCertificate>::genesis` is the only path to a
            // verified genesis value (the predicate's signer check would
            // reject the zero-signers genesis bitfield).
            parent_qc: Verified::<QuorumCertificate>::genesis(shard_id, origin).into(),
            proposer,
            timestamp: ProposerTimestamp::ZERO,
            round: Round::INITIAL,
            is_fallback: false,
            state_root,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: BoundedVec::new(),
            provision_tx_roots: BoundedBTreeMap::new(),
            in_flight: InFlightCount::ZERO,
            beacon_witness_root: BeaconWitnessRoot::ZERO,
            beacon_witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            beacon_witness_base: BeaconWitnessLeafCount::ZERO,
            split_child_roots: None,
        }
    }

    /// The deterministic genesis header of a split child adopting
    /// `state_root` — its subtree of the parent's terminal root.
    ///
    /// Pure over `(child, state_root, parent terminal header, parent
    /// canonical weighted timestamp)`, so the beacon fold and every child
    /// committee member construct the byte-identical genesis: the beacon
    /// seeds the child's anchor with this header's hash, and the flip
    /// installs the same block. Provenance rides `parent_block_hash` (the
    /// parent's terminal block hash; the parent shard itself is the
    /// child's structural trie parent). The chain origin continues the
    /// parent's lines: genesis at terminal height + 1, clock anchored at
    /// the parent's final committed canonical weighted timestamp. The
    /// proposer is inherited from the terminal block — a deterministic
    /// choice that needs no committee context.
    #[must_use]
    pub fn split_child_genesis(
        child: ShardId,
        state_root: StateRoot,
        parent_terminal: &Self,
        parent_canonical_wt: WeightedTimestamp,
    ) -> Self {
        let origin = ChainOrigin {
            genesis_height: parent_terminal.height().next(),
            anchor_wt: parent_canonical_wt,
        };
        Self {
            shard_id: child,
            height: origin.genesis_height,
            parent_block_hash: parent_terminal.hash(),
            parent_qc: Verified::<QuorumCertificate>::genesis(child, origin).into(),
            proposer: parent_terminal.proposer(),
            timestamp: ProposerTimestamp::ZERO,
            round: Round::INITIAL,
            is_fallback: false,
            state_root,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: BoundedVec::new(),
            provision_tx_roots: BoundedBTreeMap::new(),
            in_flight: InFlightCount::ZERO,
            beacon_witness_root: BeaconWitnessRoot::ZERO,
            beacon_witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            beacon_witness_base: BeaconWitnessLeafCount::ZERO,
            split_child_roots: None,
        }
    }

    /// The deterministic genesis header of a merged parent adopting
    /// `state_root` — the internal node `hash_internal(r_p0, r_p1)` over
    /// its two children's terminal subtree roots.
    ///
    /// Pure over `(parent, state_root, both terminal block hashes and
    /// heights, the cut weighted timestamp)`, so the beacon fold composes
    /// the same anchor every keeper installs. The merged chain continues
    /// both children's height lines at `max(h_p0, h_p1) + 1`, its clock
    /// anchored at the cut (the boundary the children terminated at, which
    /// places the merged chain's first block in the epoch after their
    /// final one). Provenance rides `parent_block_hash` — the taller
    /// child's terminal block, the structural predecessor of `max + 1`,
    /// ties breaking to the left child. The proposer is a genesis sentinel
    /// (`0`): a structural genesis is never proposed, so the field carries
    /// no committee meaning and both sides set it identically.
    ///
    /// Each terminal is its child's `(block hash, height)` — exactly what
    /// the beacon tracks in [`ShardBoundary`](crate::ShardBoundary) and
    /// what a keeper reads off the child's terminal block.
    #[must_use]
    pub fn merge_parent_genesis(
        parent: ShardId,
        state_root: StateRoot,
        left_terminal: (BlockHash, BlockHeight),
        right_terminal: (BlockHash, BlockHeight),
        cut_wt: WeightedTimestamp,
    ) -> Self {
        let (left_terminal_hash, left_terminal_height) = left_terminal;
        let (right_terminal_hash, right_terminal_height) = right_terminal;
        let genesis_height = left_terminal_height.max(right_terminal_height).next();
        let parent_block_hash = if right_terminal_height > left_terminal_height {
            right_terminal_hash
        } else {
            left_terminal_hash
        };
        let origin = ChainOrigin {
            genesis_height,
            anchor_wt: cut_wt,
        };
        Self {
            shard_id: parent,
            height: genesis_height,
            parent_block_hash,
            parent_qc: Verified::<QuorumCertificate>::genesis(parent, origin).into(),
            proposer: ValidatorId::new(0),
            timestamp: ProposerTimestamp::ZERO,
            round: Round::INITIAL,
            is_fallback: false,
            state_root,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: BoundedVec::new(),
            provision_tx_roots: BoundedBTreeMap::new(),
            in_flight: InFlightCount::ZERO,
            beacon_witness_root: BeaconWitnessRoot::ZERO,
            beacon_witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            beacon_witness_base: BeaconWitnessLeafCount::ZERO,
            split_child_roots: None,
        }
    }

    /// Shard group this block belongs to.
    ///
    /// Makes headers self-describing for cross-shard verification. A remote shard
    /// needs to know which shard's committee to verify the QC against.
    #[must_use]
    pub const fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// Block height in the chain. The genesis height is a per-chain
    /// property: 0 for chains born at network genesis, parent terminal
    /// height + 1 for a split child.
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.height
    }

    /// Hash of parent block.
    #[must_use]
    pub const fn parent_block_hash(&self) -> BlockHash {
        self.parent_block_hash
    }

    /// Quorum certificate proving parent block was committed.
    #[must_use]
    pub fn parent_qc(&self) -> &QuorumCertificate {
        self.parent_qc.as_unverified()
    }

    /// Borrow the parent QC's [`Verifiable`] wrapper, exposing the
    /// verification marker. Used by typestate consumers that branch on
    /// whether the parent QC has already been verified.
    #[must_use]
    pub const fn parent_qc_verifiable(&self) -> &Verifiable<QuorumCertificate> {
        &self.parent_qc
    }

    /// Validator that proposed this block.
    #[must_use]
    pub const fn proposer(&self) -> ValidatorId {
        self.proposer
    }

    /// Proposer's local wall-clock when this block was proposed.
    ///
    /// **Not** BFT-authenticated. Used only for shard consensus liveness bounds (rejecting
    /// rushed/stale proposals against the local validator's clock) and local
    /// latency metrics. Never anchor a deterministic timeout on this — use
    /// `qc.weighted_timestamp` / `ts_ms` fields derived from it instead.
    #[must_use]
    pub const fn timestamp(&self) -> ProposerTimestamp {
        self.timestamp
    }

    /// View/round number for view change protocol.
    #[must_use]
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Whether this block was created as a fallback when leader timed out.
    #[must_use]
    pub const fn is_fallback(&self) -> bool {
        self.is_fallback
    }

    /// JMT state root hash after applying all certificates in this block.
    #[must_use]
    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    /// Merkle root of all transactions in this block.
    ///
    /// Each transaction's hash is a leaf in a padded binary merkle tree.
    /// For empty blocks (fallback, sync), this is `TransactionRoot::ZERO`.
    #[must_use]
    pub const fn transaction_root(&self) -> TransactionRoot {
        self.transaction_root
    }

    /// Merkle root of all certificate receipt hashes in this block.
    ///
    /// Each certificate's `receipt_hash` (hash of outcome + `event_root`) is a leaf
    /// in a binary merkle tree. This enables light-client proof of "did transaction
    /// X succeed/fail in block N?" without replaying the block.
    ///
    /// For empty blocks (genesis, fallback, no certificates), this is `CertificateRoot::ZERO`.
    #[must_use]
    pub const fn certificate_root(&self) -> CertificateRoot {
        self.certificate_root
    }

    /// Merkle root of per-tx consensus-receipt hashes
    /// ([`ConsensusReceipt::local_receipt_hash`](crate::ConsensusReceipt::local_receipt_hash))
    /// for all transactions covered by this block's wave certificates.
    ///
    /// Commits to the specific per-tx state deltas (shard-filtered `DatabaseUpdates`)
    /// that were applied to produce `state_root`. Enables per-tx delta attribution
    /// and receipt integrity verification by sync nodes.
    ///
    /// For empty blocks (genesis, fallback, no certificates), this is `LocalReceiptRoot::ZERO`.
    #[must_use]
    pub const fn local_receipt_root(&self) -> LocalReceiptRoot {
        self.local_receipt_root
    }

    /// Merkle root of provisions included in this block.
    ///
    /// Commits to which remote-shard provisions are available at this height.
    /// Validators who voted for the shard consensus proposal have this data locally.
    /// `ProvisionsRoot::ZERO` when no provisions are included (single-shard or empty block).
    #[must_use]
    pub const fn provision_root(&self) -> ProvisionsRoot {
        self.provision_root
    }

    /// Cross-shard execution waves in this block.
    ///
    /// Each `WaveId` is the set of remote shards that a group of transactions
    /// depends on for provisions. Transactions with identical remote shard sets
    /// share a wave. Wave-zero (single-shard txs) is excluded.
    ///
    /// QC-attested (covered by the block hash), so a byzantine proposer
    /// cannot forge it without the block being rejected by honest validators —
    /// `validate_waves` recomputes this from `transactions` and compares.
    ///
    /// Used by remote shards to know which execution certificates to expect.
    /// Provisions completeness is handled separately via
    /// [`BlockHeader::provision_tx_roots`]. Empty for genesis, fallback, and
    /// sync blocks.
    #[must_use]
    pub const fn waves(&self) -> &BoundedVec<WaveId, MAX_TXS_PER_BLOCK> {
        &self.waves
    }

    /// Per-target-shard merkle commitment over the tx hashes a target shard
    /// should receive provisions for from this block.
    ///
    /// Key = target shard; value = `compute_merkle_root` over the
    /// ordered tx hashes destined for that target (block order, already
    /// hash-ascending). Lets the target verify a received `Provisions`
    /// contains the full set it was meant to receive — catches silently
    /// dropped txs on the broadcast path.
    #[must_use]
    pub const fn provision_tx_roots(
        &self,
    ) -> &BoundedBTreeMap<ShardId, ProvisionTxRoot, MAX_REMOTE_SHARDS_PER_WAVE> {
        &self.provision_tx_roots
    }

    /// Approximate number of in-flight transactions on this shard at proposal time.
    ///
    /// "In-flight" = committed + executed transactions in the proposer's mempool,
    /// i.e. transactions actively holding state locks. Gossiped cross-shard via
    /// `CertifiedBlockHeaderGossip` so RPC nodes can reject transactions targeting
    /// congested remote shards.
    ///
    /// shard-verified within tolerance (validators may differ slightly due to
    /// execution timing). Zero for genesis; fallback and sync blocks carry
    /// the parent's in-flight count forward unchanged (no txs admitted, none
    /// finalized).
    #[must_use]
    pub const fn in_flight(&self) -> InFlightCount {
        self.in_flight
    }

    /// Root of this shard's monotonic beacon-witness accumulator at
    /// this block.
    ///
    /// QC-attested (part of the signed header). Beacon validators
    /// verify a fetched [`ShardWitness`](crate::ShardWitness) against
    /// this root via the Merkle path in its
    /// [`ShardWitnessProof`](crate::ShardWitnessProof).
    ///
    /// `BeaconWitnessRoot::ZERO` for blocks that produced no witnesses.
    #[must_use]
    pub const fn beacon_witness_root(&self) -> BeaconWitnessRoot {
        self.beacon_witness_root
    }

    /// Total leaves in this shard's beacon-witness accumulator as of
    /// this block.
    ///
    /// Paired with [`Self::beacon_witness_root`] so a verifier holding
    /// only the header can check any inclusion proof anchored at this
    /// block without consulting a side channel for the tree size. `0`
    /// for blocks that produced no witnesses.
    #[must_use]
    pub const fn beacon_witness_leaf_count(&self) -> BeaconWitnessLeafCount {
        self.beacon_witness_leaf_count
    }

    /// The beacon-witness window base of the window this block belongs
    /// to — the folded watermark frozen at promotion. Verification
    /// rejects a claim that differs from the schedule-resolved value,
    /// so a holder of a verified header reads the window straight off
    /// it: the accumulator commitment spans leaves
    /// `[beacon_witness_base, beacon_witness_leaf_count)`.
    #[must_use]
    pub const fn beacon_witness_base(&self) -> BeaconWitnessLeafCount {
        self.beacon_witness_base
    }

    /// The two child hashes of the JMT root node behind `state_root` —
    /// present on every header of a split-pending shard's final epoch,
    /// `None` everywhere else. Verified beside the state root.
    #[must_use]
    pub const fn split_child_roots(&self) -> Option<SplitChildRoots> {
        self.split_child_roots
    }

    /// Decompose into the raw fields, in struct-declaration order.
    #[allow(clippy::type_complexity)] // mirrors the 20 stored fields
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ShardId,
        BlockHeight,
        BlockHash,
        Verifiable<QuorumCertificate>,
        ValidatorId,
        ProposerTimestamp,
        Round,
        bool,
        StateRoot,
        TransactionRoot,
        CertificateRoot,
        LocalReceiptRoot,
        ProvisionsRoot,
        BoundedVec<WaveId, MAX_TXS_PER_BLOCK>,
        BoundedBTreeMap<ShardId, ProvisionTxRoot, MAX_REMOTE_SHARDS_PER_WAVE>,
        InFlightCount,
        BeaconWitnessRoot,
        BeaconWitnessLeafCount,
        BeaconWitnessLeafCount,
        Option<SplitChildRoots>,
    ) {
        (
            self.shard_id,
            self.height,
            self.parent_block_hash,
            self.parent_qc,
            self.proposer,
            self.timestamp,
            self.round,
            self.is_fallback,
            self.state_root,
            self.transaction_root,
            self.certificate_root,
            self.local_receipt_root,
            self.provision_root,
            self.waves,
            self.provision_tx_roots,
            self.in_flight,
            self.beacon_witness_root,
            self.beacon_witness_leaf_count,
            self.beacon_witness_base,
            self.split_child_roots,
        )
    }

    /// Derive provision targets from waves (union of all shards across all waves).
    ///
    /// Returns the sorted set of all remote shards that need provisions from this block.
    #[must_use]
    pub fn provision_targets(&self) -> Vec<ShardId> {
        let mut set = BTreeSet::new();
        for wave in self.waves.iter() {
            set.extend(wave.remote_shards().iter().copied());
        }
        set.into_iter().collect()
    }

    /// Compute hash of this block header.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding fails — `BlockHeader` is a closed SBOR
    /// type and encoding is infallible in practice.
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        let bytes = basic_encode(self).expect("BlockHeader serialization should never fail");
        BlockHash::from_raw(Hash::from_bytes(&bytes))
    }

    /// Check if this is the genesis block header.
    ///
    /// Structural, not height-based: the genesis header is the only
    /// header whose parent QC is a genesis QC at the header's own height.
    /// Every later block sits above its parent QC — the first real block
    /// carries the chain's genesis QC one height below itself. A chain's
    /// genesis height is a per-chain property (a split child's genesis
    /// continues the parent's height line), so `height == 0` cannot
    /// identify genesis.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        let parent_qc = self.parent_qc();
        parent_qc.is_genesis() && self.height == parent_qc.height()
    }

    /// Get the expected proposer for this height (round-robin).
    #[must_use]
    pub const fn expected_proposer(&self, num_validators: u64) -> ValidatorId {
        ValidatorId::new((self.height.inner() + self.round.inner()) % num_validators)
    }
}

/// Failure modes of [`BlockHeader`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BlockHeaderVerifyError {
    /// The header's `parent_qc` is still in [`Verifiable::Unverified`]
    /// at the point verification is requested. Callers must verify the
    /// QC (via [`<QuorumCertificate as Verify>`](Verify) or by upgrading
    /// the wrapper) before attempting to verify the header.
    #[error("parent QC has not been verified")]
    ParentQcUnverified,
}

/// Returned when an external `Verified<QuorumCertificate>` supplied to
/// [`Verified::<BlockHeader>::with_verified_parent_qc`] doesn't byte-match
/// the header's claimed `parent_qc`.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("supplied verified parent_qc does not match the header's claimed parent_qc")]
pub struct BlockHeaderParentQcMismatch;

/// Construction asserts: the header's `parent_qc` carries a
/// [`Verifiable::Verified`] marker — i.e. the parent QC has been
/// verified against its committee context. The header's `hash()` is
/// derived from its content by definition, so there is no separately
/// claimed hash to check.
///
/// Construction goes through one of three gates:
///
/// - [`<BlockHeader as Verify>::verify`](Verify::verify) — checks that
///   the embedded `parent_qc` is in [`Verifiable::Verified`].
/// - [`Verified::<BlockHeader>::with_verified_parent_qc`] — accepts an
///   external `Verified<QuorumCertificate>` witness and rebinds the
///   header's `parent_qc` field after a byte-equality check. Used at
///   composite-assembly sites where the verified QC sits in a separate
///   cache rather than inside the wire-decoded header.
/// - [`Verified::<BlockHeader>::new_unchecked`] — re-wraps a header
///   whose predicate already held via an out-of-band trust source
///   (e.g. storage-recovery). Every call site carries a `// SAFETY:`
///   comment naming the trust source.
impl Verify<()> for BlockHeader {
    type Error = BlockHeaderVerifyError;

    fn verify(&self, _ctx: ()) -> Result<Verified<Self>, Self::Error> {
        if self.parent_qc.verified().is_none() {
            return Err(BlockHeaderVerifyError::ParentQcUnverified);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<BlockHeader> {
    /// Borrow the verified parent QC. Total by the
    /// [`Verified<BlockHeader>`] predicate, which requires
    /// `parent_qc` to sit in [`Verifiable::Verified`].
    ///
    /// # Panics
    ///
    /// Panics if a caller produced a `Verified<BlockHeader>` whose
    /// `parent_qc` is `Unverified` — only reachable through a misuse of
    /// [`Verified::new_unchecked`]. The audit list at the
    /// `new_unchecked` call sites is the right place to investigate.
    #[must_use]
    pub fn parent_qc_verified(&self) -> &Verified<QuorumCertificate> {
        self.parent_qc_verifiable()
            .verified()
            .expect("Verified<BlockHeader> predicate guarantees parent_qc is Verified")
    }

    /// Promote a wire-decoded `BlockHeader` to its verified form by
    /// pairing it with an externally-verified `parent_qc` witness.
    ///
    /// Wire-decoded headers always carry `parent_qc` in
    /// [`Verifiable::Unverified`] even after the QC has been verified
    /// elsewhere (e.g. in a coordinator's verified-QC cache), because
    /// the marker can't be upgraded in place on a shared `Arc<Block>`.
    /// This constructor closes that gap: it byte-equality-checks the
    /// supplied verified QC against the header's claimed `parent_qc`,
    /// rebinds the field to [`Verifiable::Verified`], and produces the
    /// typed verified header.
    ///
    /// Construction asserts:
    /// 1. The supplied `parent_qc` passes its own verification predicate
    ///    (witnessed by its `Verified<QuorumCertificate>` type).
    /// 2. The supplied `parent_qc` equals the header's claimed
    ///    `parent_qc` (byte-equality).
    ///
    /// # Errors
    ///
    /// Returns [`BlockHeaderParentQcMismatch`] when the supplied verified
    /// QC differs from the header's claimed `parent_qc`.
    pub fn with_verified_parent_qc(
        header: BlockHeader,
        parent_qc: Verified<QuorumCertificate>,
    ) -> Result<Self, BlockHeaderParentQcMismatch> {
        if header.parent_qc.as_unverified() != parent_qc.as_ref() {
            return Err(BlockHeaderParentQcMismatch);
        }
        let header = BlockHeader {
            parent_qc: parent_qc.into(),
            ..header
        };
        Ok(Self::new_unchecked(header))
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder as _,
        NoCustomValueKind, ValueKind, VecEncoder, basic_decode,
    };

    use super::*;

    fn sample_header() -> BlockHeader {
        BlockHeader::genesis(
            ShardId::ROOT,
            ValidatorId::new(0),
            StateRoot::ZERO,
            ChainOrigin::ROOT,
        )
    }

    /// A split child's genesis is a pure function of the parent's
    /// terminal block: byte-identical across the beacon fold and every
    /// flipping member, structurally genesis, continuing the parent's
    /// height line and clock with the terminal hash as provenance.
    #[test]
    fn split_child_genesis_is_deterministic_and_structural() {
        let parent_terminal = sample_header();
        let child = ShardId::leaf(1, 0);
        let root = StateRoot::from_raw(Hash::from_bytes(b"child subtree"));
        let wt = WeightedTimestamp::from_millis(42_000);

        let a = BlockHeader::split_child_genesis(child, root, &parent_terminal, wt);
        let b = BlockHeader::split_child_genesis(child, root, &parent_terminal, wt);
        assert_eq!(a.hash(), b.hash());

        assert!(a.is_genesis());
        assert_eq!(a.height(), parent_terminal.height().next());
        assert_eq!(a.parent_qc().height(), a.height());
        assert_eq!(a.parent_qc().weighted_timestamp(), wt);
        assert_eq!(a.parent_block_hash(), parent_terminal.hash());
        assert_eq!(a.state_root(), root);
        assert_eq!(a.split_child_roots(), None);
    }

    /// A merged parent's genesis is a pure function of its two children's
    /// terminals: byte-identical across the beacon fold and every keeper,
    /// structurally genesis, continuing both height lines at `max + 1`
    /// with the clock at the cut and the taller terminal as provenance.
    #[test]
    fn merge_parent_genesis_is_deterministic_and_structural() {
        let parent = ShardId::ROOT;
        let root = StateRoot::from_raw(Hash::from_bytes(b"merged subtree"));
        let cut = WeightedTimestamp::from_millis(50_000);
        let left = (
            BlockHash::from_raw(Hash::from_bytes(b"left terminal")),
            BlockHeight::new(40),
        );
        let right = (
            BlockHash::from_raw(Hash::from_bytes(b"right terminal")),
            BlockHeight::new(42),
        );

        let a = BlockHeader::merge_parent_genesis(parent, root, left, right, cut);
        let b = BlockHeader::merge_parent_genesis(parent, root, left, right, cut);
        assert_eq!(a.hash(), b.hash());

        assert!(a.is_genesis());
        // Continues both height lines at max + 1.
        assert_eq!(a.height(), BlockHeight::new(43));
        assert_eq!(a.parent_qc().height(), a.height());
        assert_eq!(a.parent_qc().weighted_timestamp(), cut);
        // The taller terminal (right, h42) is the structural predecessor.
        assert_eq!(a.parent_block_hash(), right.0);
        assert_eq!(a.state_root(), root);
        assert_eq!(a.split_child_roots(), None);

        // A height tie breaks to the left child.
        let tied_right = (
            BlockHash::from_raw(Hash::from_bytes(b"tied right")),
            BlockHeight::new(40),
        );
        let tied = BlockHeader::merge_parent_genesis(parent, root, left, tied_right, cut);
        assert_eq!(tied.parent_block_hash(), left.0);
        assert_eq!(tied.height(), BlockHeight::new(41));
    }

    /// `split_child_roots` is hash-affecting header content: a populated
    /// pair survives the wire round-trip and produces a different block
    /// hash than the same header without it.
    #[test]
    fn split_child_roots_round_trip_and_hash() {
        let bare = sample_header();
        let pair = SplitChildRoots {
            left: StateRoot::from_raw(Hash::from_bytes(b"left")),
            right: StateRoot::from_raw(Hash::from_bytes(b"right")),
        };
        let (
            shard_id,
            height,
            parent_block_hash,
            parent_qc,
            proposer,
            timestamp,
            round,
            is_fallback,
            state_root,
            transaction_root,
            certificate_root,
            local_receipt_root,
            provision_root,
            waves,
            provision_tx_roots,
            in_flight,
            beacon_witness_root,
            beacon_witness_leaf_count,
            beacon_witness_base,
            _,
        ) = bare.clone().into_parts();
        let carrying = BlockHeader::new(
            shard_id,
            height,
            parent_block_hash,
            parent_qc,
            proposer,
            timestamp,
            round,
            is_fallback,
            state_root,
            transaction_root,
            certificate_root,
            local_receipt_root,
            provision_root,
            waves.iter().cloned().collect(),
            provision_tx_roots.iter().map(|(k, v)| (*k, *v)).collect(),
            in_flight,
            beacon_witness_root,
            beacon_witness_leaf_count,
            beacon_witness_base,
            Some(pair),
        );

        let decoded: BlockHeader = basic_decode(&basic_encode(&carrying).unwrap()).unwrap();
        assert_eq!(decoded.split_child_roots(), Some(pair));
        assert_ne!(carrying.hash(), bare.hash());
    }

    /// Hand-roll a `BlockHeader` whose `waves` length prefix exceeds the cap.
    /// The `BoundedVec` decoder fires before any per-element work happens.
    #[test]
    fn decode_rejects_oversized_waves_count() {
        let h = sample_header();
        let mut buf = Vec::with_capacity(256);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            // BlockHeader has 20 fields.
            enc.write_size(20).unwrap();
            enc.encode(&h.shard_id).unwrap();
            enc.encode(&h.height).unwrap();
            enc.encode(&h.parent_block_hash).unwrap();
            enc.encode(&h.parent_qc).unwrap();
            enc.encode(&h.proposer).unwrap();
            enc.encode(&h.timestamp).unwrap();
            enc.encode(&h.round).unwrap();
            enc.encode(&h.is_fallback).unwrap();
            enc.encode(&h.state_root).unwrap();
            enc.encode(&h.transaction_root).unwrap();
            enc.encode(&h.certificate_root).unwrap();
            enc.encode(&h.local_receipt_root).unwrap();
            enc.encode(&h.provision_root).unwrap();
            // Oversized waves array.
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(WaveId::value_kind()).unwrap();
            enc.write_size(MAX_TXS_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<BlockHeader>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_TXS_PER_BLOCK && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }

    /// Hand-roll a `BlockHeader` whose `provision_tx_roots` map size exceeds
    /// the cap. The `BoundedBTreeMap` decoder fires before any per-entry
    /// work happens.
    #[test]
    fn decode_rejects_oversized_provision_tx_roots_count() {
        let h = sample_header();
        let mut buf = Vec::with_capacity(256);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(20).unwrap();
            enc.encode(&h.shard_id).unwrap();
            enc.encode(&h.height).unwrap();
            enc.encode(&h.parent_block_hash).unwrap();
            enc.encode(&h.parent_qc).unwrap();
            enc.encode(&h.proposer).unwrap();
            enc.encode(&h.timestamp).unwrap();
            enc.encode(&h.round).unwrap();
            enc.encode(&h.is_fallback).unwrap();
            enc.encode(&h.state_root).unwrap();
            enc.encode(&h.transaction_root).unwrap();
            enc.encode(&h.certificate_root).unwrap();
            enc.encode(&h.local_receipt_root).unwrap();
            enc.encode(&h.provision_root).unwrap();
            // Empty waves.
            enc.encode(&Vec::<WaveId>::new()).unwrap();
            // Oversized provision_tx_roots map.
            enc.write_value_kind(ValueKind::Map).unwrap();
            enc.write_value_kind(ShardId::value_kind()).unwrap();
            enc.write_value_kind(ProvisionTxRoot::value_kind()).unwrap();
            enc.write_size(MAX_REMOTE_SHARDS_PER_WAVE + 1).unwrap();
        }
        let err = basic_decode::<BlockHeader>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_REMOTE_SHARDS_PER_WAVE
                    && actual == MAX_REMOTE_SHARDS_PER_WAVE + 1
        ));
    }

    /// Genesis headers verify (`parent_qc` arrives pre-marked verified),
    /// and the resulting `Verified<BlockHeader>` projects out the
    /// verified parent QC through the type-level borrow.
    #[test]
    fn verified_header_projects_parent_qc() {
        let header = sample_header();
        let verified = header.verify(()).expect("genesis header verifies");
        let pqc = verified.parent_qc_verified();
        assert!(pqc.is_genesis());
    }

    /// A header with an unverified `parent_qc` fails `verify`, so the
    /// projector is unreachable without resorting to `new_unchecked`.
    #[test]
    fn verify_rejects_unverified_parent_qc() {
        let mut header = sample_header();
        header.parent_qc = header.parent_qc.as_unverified().clone().into();
        let err = header
            .verify(())
            .expect_err("unverified parent_qc rejected");
        assert_eq!(err, BlockHeaderVerifyError::ParentQcUnverified);
    }

    /// `with_verified_parent_qc` upgrades a wire-decoded header by pairing
    /// it with an externally-verified QC witness that byte-matches the
    /// claimed `parent_qc`.
    #[test]
    fn with_verified_parent_qc_upgrades_matching_header() {
        let mut header = sample_header();
        header.parent_qc = header.parent_qc.as_unverified().clone().into();
        let verified_qc =
            Verified::<QuorumCertificate>::genesis(header.shard_id(), ChainOrigin::ROOT);
        let verified = Verified::<BlockHeader>::with_verified_parent_qc(header, verified_qc)
            .expect("matching parent_qc accepted");
        assert!(verified.parent_qc_verified().is_genesis());
    }

    /// `with_verified_parent_qc` rejects a witness QC that differs from
    /// the header's claimed `parent_qc`.
    #[test]
    fn with_verified_parent_qc_rejects_mismatched_witness() {
        let header = sample_header();
        let other_shard = ShardId::from_heap_index(header.shard_id().inner() + 1);
        let mismatched = Verified::<QuorumCertificate>::genesis(other_shard, ChainOrigin::ROOT);
        let err = Verified::<BlockHeader>::with_verified_parent_qc(header, mismatched)
            .expect_err("mismatched parent_qc rejected");
        assert_eq!(err, BlockHeaderParentQcMismatch);
    }
}
