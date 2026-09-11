//! Block header containing consensus metadata.
//!
//! [`BlockHeader`] is the raw wire form. Its verified form is
//! `Verified<BlockHeader>`; predicate at [`impl Verify<()>`](Verify::verify)
//! below.

use std::collections::BTreeMap;

use hyperscale_hbor::{Hbor, to_vec as hbor_to_vec};
use thiserror::Error;

use crate::{
    AbandonmentRoot, BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeight,
    CertificateRoot, ChainOrigin, CommittedTxsRoot, Hash, LocalReceiptRoot,
    MAX_PROVISION_TARGET_SHARDS, PredecessorTerminal, ProposerTimestamp, ProvisionTxRoot,
    ProvisionsRoot, QuorumCertificate, RevealChain, Round, SettledTxsRoot, ShardId, ShardLoad,
    SplitChildRoots, StateClaimsRoot, StateRoot, SweepFrontier, TerminalRoots, TransactionRoot,
    TxsInFlight, ValidatorId, Verifiable, Verified, Verify, WeightedTimestamp,
};

/// The running values a block extending the committed tip is checked
/// against, all read off the tip's own header.
///
/// Held as one value because they resolve as one: a replica that has the
/// tip's header supplies all four, and one that does not supplies none.
/// Carried separately they admit a state nothing can produce — a parent
/// resolvable for its reveal chain and unresolvable for its drain total —
/// and a checker reading the absent one refuses a block it could have
/// checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedTip {
    /// Work the tip leaves in flight, which the next block advances.
    pub txs_in_flight: TxsInFlight,
    /// Highest tick whose determined half has settled at or below the tip.
    pub settled_tick_frontier: BlockHeight,
    /// How far the tip's sweep reached, which the next block advances.
    pub sweep_frontier: SweepFrontier,
    /// Reveal chain the next block extends, or reseeds past in a later epoch.
    pub reveal_chain: RevealChain,
    /// Attested load through the tip: running gas total and the byte level.
    pub load: ShardLoad,
}

impl CommittedTip {
    /// A chain's genesis tip, whose header carries zero of everything —
    /// known rather than guessed, which is why a fresh start resolves here
    /// instead of refusing to check its first block.
    pub const GENESIS: Self = Self {
        txs_in_flight: TxsInFlight::ZERO,
        settled_tick_frontier: BlockHeight::GENESIS,
        sweep_frontier: SweepFrontier::ZERO,
        reveal_chain: RevealChain::ZERO,
        load: ShardLoad::ZERO,
    };
}

/// Block header containing consensus metadata.
///
/// The header is what validators vote on. It contains:
/// - Chain position (height, parent hash)
/// - Proposer identity
/// - Proof of parent commitment (parent QC)
/// - State commitment (JMT root after applying committed certificates)
/// - Transaction commitment (merkle root of all transactions in the block)
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
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
    #[hbor(max = MAX_PROVISION_TARGET_SHARDS)]
    provision_tx_roots: BTreeMap<ShardId, ProvisionTxRoot>,
    /// Commits the block's [`AbandonmentRecord`](crate::AbandonmentRecord)
    /// records — what departed shards left unresolved of this chain's
    /// business, written down while the evidence for it could still be
    /// read.
    abandonment_root: AbandonmentRoot,
    state_claims_root: StateClaimsRoot,
    txs_in_flight: TxsInFlight,
    /// The highest tick whose determined half has settled at or below
    /// this block: the parent's, raised to the last determined half this
    /// block carries. Folded like `txs_in_flight` and read off the block
    /// the same way — the certificates name their tick and their half, so
    /// a validator checks the claim with no history behind it.
    ///
    /// It is what makes settlement order a validity rule rather than a
    /// proposer convention. A receipt states an absolute computed from
    /// its tick's baseline and settlement is last writer per cell, so an
    /// earlier tick's determined half landing after a later one's reverts
    /// a write later ticks have already read — and every replica would
    /// agree on the wrong state, leaving nothing to detect afterwards.
    settled_tick_frontier: BlockHeight,
    /// How far this block's sweep reached: the position in expiry order
    /// that its removals stop at.
    ///
    /// The block's removals are exactly the sweepable cells in
    /// `(parent.sweep_frontier, this]`, so the pair — the parent's and
    /// this one's — states the whole set without listing it, and a
    /// validator checks completeness by walking the same interval. Read
    /// off the block the way `settled_tick_frontier` is: a monotone
    /// claim with no history behind it.
    ///
    /// Advancing is obliged rather than permitted. A removal earns no
    /// fee and costs a proposer block space, so a rule that let one
    /// decline is a rule honest proposers converge on declining, and the
    /// bound would then hold only because the reference client happened
    /// to sweep.
    sweep_frontier: SweepFrontier,
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
    /// Running hash chain over this shard's randomness reveals within the
    /// block's anchor epoch (`epoch_for(parent_qc.wt)`), reseeded whenever
    /// that epoch differs from the parent's. A block whose child anchors
    /// past the epoch cut is the last of its epoch, so the chain a boundary
    /// block carries is the closed value the beacon folds into
    /// `state.randomness` — one 32-byte commitment per epoch rather than a
    /// leaf per block.
    reveal_chain: RevealChain,
    /// The two child hashes of the JMT root node behind `state_root`,
    /// carried on every header of a split-pending shard's final epoch
    /// (`None` everywhere else). Produced by the same replay that fills
    /// `state_root` and verified beside it — see
    /// [`SplitChildRoots`]. The beacon seeds the post-split children's
    /// anchors from the terminal header's pair; it cannot decompose
    /// `state_root` itself.
    split_child_roots: Option<SplitChildRoots>,
    /// The commitments a terminating shard leaves for the chains that
    /// outlive it, carried on the boundary header of its final epoch and
    /// `None` everywhere else. The beacon folds them into
    /// [`ShardBoundary`](crate::ShardBoundary). One field because both are
    /// computed over the same committed window and carried by the same
    /// headers — see [`TerminalRoots`] for what each answers and for whom.
    terminal_roots: Option<TerminalRoots>,
    /// The shard's attested load through this block — attested work as a
    /// running total, and the byte total behind the parent state. The
    /// beacon reads it off the boundary header it already sources and
    /// reweights the per-epoch emission by it; verification recomputes
    /// both scalars and rejects a header whose claim diverges, so a
    /// committed load carries the committee's quorum behind it. See
    /// [`ShardLoad`].
    load: ShardLoad,
}

/// Every field of a [`BlockHeader`], named.
///
/// The header commits two dozen things and grows with the protocol, so
/// its constructor takes them by name: a fixture states the handful its
/// case turns on and takes [`Default`] for the rest, and a new
/// commitment costs the sites that set it rather than every site that
/// builds a header.
///
/// The defaults are the empty chain's values — the same ones
/// [`BlockHeader::genesis`] uses — so a partially-specified header is a
/// header about nothing rather than a header with plausible-looking
/// content it never meant to claim.
#[derive(Debug, Clone)]
#[allow(missing_docs)] // one field per header commitment; documented on `BlockHeader` itself
pub struct BlockHeaderParts {
    pub shard_id: ShardId,
    pub height: BlockHeight,
    pub parent_block_hash: BlockHash,
    pub parent_qc: Verifiable<QuorumCertificate>,
    pub proposer: ValidatorId,
    pub timestamp: ProposerTimestamp,
    pub round: Round,
    pub is_fallback: bool,
    pub state_root: StateRoot,
    pub transaction_root: TransactionRoot,
    pub certificate_root: CertificateRoot,
    pub local_receipt_root: LocalReceiptRoot,
    pub provision_root: ProvisionsRoot,
    pub provision_tx_roots: BTreeMap<ShardId, ProvisionTxRoot>,
    pub abandonment_root: AbandonmentRoot,
    pub state_claims_root: StateClaimsRoot,
    pub txs_in_flight: TxsInFlight,
    pub settled_tick_frontier: BlockHeight,
    pub sweep_frontier: SweepFrontier,
    pub beacon_witness_root: BeaconWitnessRoot,
    pub beacon_witness_leaf_count: BeaconWitnessLeafCount,
    pub beacon_witness_base: BeaconWitnessLeafCount,
    pub reveal_chain: RevealChain,
    pub split_child_roots: Option<SplitChildRoots>,
    pub terminal_roots: Option<TerminalRoots>,
    pub load: ShardLoad,
}

impl Default for BlockHeaderParts {
    fn default() -> Self {
        Self {
            shard_id: ShardId::ROOT,
            height: BlockHeight::GENESIS,
            parent_block_hash: BlockHash::from_raw(Hash::ZERO),
            parent_qc: Verified::<QuorumCertificate>::genesis(ShardId::ROOT, ChainOrigin::ROOT)
                .into(),
            proposer: ValidatorId::new(0),
            timestamp: ProposerTimestamp::ZERO,
            round: Round::INITIAL,
            is_fallback: false,
            state_root: StateRoot::ZERO,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            provision_tx_roots: BTreeMap::new(),
            abandonment_root: AbandonmentRoot::ZERO,
            state_claims_root: StateClaimsRoot::ZERO,
            txs_in_flight: TxsInFlight::ZERO,
            settled_tick_frontier: BlockHeight::GENESIS,
            sweep_frontier: SweepFrontier::ZERO,
            beacon_witness_root: BeaconWitnessRoot::ZERO,
            beacon_witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            beacon_witness_base: BeaconWitnessLeafCount::ZERO,
            reveal_chain: RevealChain::ZERO,
            split_child_roots: None,
            terminal_roots: None,
            load: ShardLoad::ZERO,
        }
    }
}

impl BlockHeader {
    /// Build a `BlockHeader` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `provision_tx_roots.len() > MAX_PROVISION_TARGET_SHARDS`.
    #[allow(clippy::too_many_arguments)] // mirrors the stored fields one to one
    #[must_use]
    pub fn new(parts: BlockHeaderParts) -> Self {
        let BlockHeaderParts {
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
            provision_tx_roots,
            abandonment_root,
            state_claims_root,
            txs_in_flight,
            settled_tick_frontier,
            sweep_frontier,
            beacon_witness_root,
            beacon_witness_leaf_count,
            beacon_witness_base,
            reveal_chain,
            split_child_roots,
            terminal_roots,
            load,
        } = parts;
        Self {
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
            provision_tx_roots,
            abandonment_root,
            state_claims_root,
            txs_in_flight,
            settled_tick_frontier,
            sweep_frontier,
            beacon_witness_root,
            beacon_witness_leaf_count,
            beacon_witness_base,
            reveal_chain,
            split_child_roots,
            terminal_roots,
            load,
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
        // Genesis QC carries no signature and is valid by definition;
        // `Verified::<QuorumCertificate>::genesis` is the only path to a
        // verified genesis value (the predicate's signer check would
        // reject the zero-signers genesis bitfield).
        Self::empty(
            shard_id,
            BlockHash::from_raw(Hash::from_bytes(&[0u8; 32])),
            proposer,
            state_root,
            origin,
        )
    }

    /// A genesis header of any provenance: no content, every root at
    /// zero, and the five terms that differ between one chain's birth
    /// and another's.
    ///
    /// The empty half comes from [`BlockHeaderParts::default`], which is
    /// the one place a header's zero is written down — so a root added to
    /// the header is a field every genesis gets without a line here, and
    /// three constructors cannot drift into three different empties.
    fn empty(
        shard_id: ShardId,
        parent_block_hash: BlockHash,
        proposer: ValidatorId,
        state_root: StateRoot,
        origin: ChainOrigin,
    ) -> Self {
        Self::new(BlockHeaderParts {
            shard_id,
            height: origin.genesis_height,
            parent_block_hash,
            parent_qc: Verified::<QuorumCertificate>::genesis(shard_id, origin).into(),
            proposer,
            state_root,
            ..BlockHeaderParts::default()
        })
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
        Self::empty(
            child,
            parent_terminal.hash(),
            parent_terminal.proposer(),
            state_root,
            origin,
        )
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
        Self::empty(
            parent,
            parent_block_hash,
            ValidatorId::new(0),
            state_root,
            origin,
        )
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
    /// for all transactions covered by this block's finalizations.
    ///
    /// Commits to the specific per-tx state deltas (shard-filtered writes)
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

    /// Per-target-shard merkle commitment over the tx hashes a target shard
    /// should receive provisions for from this block.
    ///
    /// Key = target shard; value = `compute_merkle_root` over the
    /// ordered tx hashes destined for that target (block order, already
    /// hash-ascending). Lets the target verify a received `Provisions`
    /// contains the full set it was meant to receive — catches silently
    /// dropped txs on the broadcast path.
    #[must_use]
    pub const fn provision_tx_roots(&self) -> &BTreeMap<ShardId, ProvisionTxRoot> {
        &self.provision_tx_roots
    }

    /// Commitment to the block's abandonment records.
    #[must_use]
    pub const fn abandonment_root(&self) -> AbandonmentRoot {
        self.abandonment_root
    }

    /// Merkle root over the state claims the block carries — what its
    /// proposer read of counterparts' cells, which every replica folds
    /// at commit.
    #[must_use]
    pub const fn state_claims_root(&self) -> StateClaimsRoot {
        self.state_claims_root
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
    pub const fn txs_in_flight(&self) -> TxsInFlight {
        self.txs_in_flight
    }

    /// The highest tick whose determined half has settled at or below
    /// this block. A block may carry determined halves only in strictly
    /// ascending tick order above its parent's frontier, and this is
    /// where that order ends up.
    #[must_use]
    pub const fn settled_tick_frontier(&self) -> BlockHeight {
        self.settled_tick_frontier
    }

    /// How far this block's sweep reached. Its removals are exactly the
    /// sweepable cells above its parent's frontier and at or below this.
    #[must_use]
    pub const fn sweep_frontier(&self) -> SweepFrontier {
        self.sweep_frontier
    }

    /// Root of this shard's monotonic beacon-witness accumulator at
    /// this block.
    ///
    /// QC-attested (part of the signed header). Beacon validators
    /// recompute it from a fetched chunk's payloads plus its range
    /// proof.
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

    /// The reveal chain this block commits.
    ///
    /// On a boundary block this is the closed chain of the epoch the block
    /// ends, which is what the beacon folds; on any other block it is a
    /// partial run that no consumer reads.
    #[must_use]
    pub const fn reveal_chain(&self) -> RevealChain {
        self.reveal_chain
    }

    /// The two child hashes of the JMT root node behind `state_root` —
    /// present on every header of a split-pending shard's final epoch,
    /// `None` everywhere else. Verified beside the state root.
    #[must_use]
    pub const fn split_child_roots(&self) -> Option<SplitChildRoots> {
        self.split_child_roots
    }

    /// The commitments this header leaves for the chains that outlive its
    /// shard — present on a terminating shard's boundary header, `None`
    /// everywhere else.
    #[must_use]
    pub const fn terminal_roots(&self) -> Option<TerminalRoots> {
        self.terminal_roots
    }

    /// Merkle root over the tick-ids this shard settled within its
    /// retention window, for a reader that wants only that half.
    #[must_use]
    pub fn settled_txs_root(&self) -> Option<SettledTxsRoot> {
        self.terminal_roots.map(|roots| roots.settled_txs)
    }

    /// Merkle root over every transaction this shard committed within its
    /// retention window, for a reader that wants only that half.
    #[must_use]
    pub fn committed_txs_root(&self) -> Option<CommittedTxsRoot> {
        self.terminal_roots.map(|roots| roots.committed_txs)
    }

    /// This header as the terminal a successor succeeds.
    ///
    /// `None` on any header carrying no terminal roots, which is every
    /// header but a terminating boundary's. A successor handed nothing
    /// here keeps refusing everything from before its origin, which is
    /// the rule it would relax rather than a fallback.
    #[must_use]
    pub fn as_predecessor_terminal(&self) -> Option<PredecessorTerminal> {
        Some(PredecessorTerminal {
            shard: self.shard_id(),
            height: self.height(),
            block_hash: self.hash(),
            committed_txs_root: self.terminal_roots?.committed_txs,
        })
    }

    /// The shard's attested load through this block: attested work as a
    /// running total over the chain's history, and the byte total behind
    /// the parent state. Both recomputed at verification.
    #[must_use]
    pub const fn load(&self) -> ShardLoad {
        self.load
    }

    /// The running values a block extending this one is checked against.
    #[must_use]
    pub const fn committed_tip(&self) -> CommittedTip {
        CommittedTip {
            txs_in_flight: self.txs_in_flight,
            settled_tick_frontier: self.settled_tick_frontier,
            sweep_frontier: self.sweep_frontier,
            reveal_chain: self.reveal_chain,
            load: self.load,
        }
    }

    /// Decompose into the parts [`Self::new`] builds one from.
    ///
    /// The inverse of the constructor rather than a positional tuple, so
    /// a caller that rebuilds a header with one field changed names that
    /// field and inherits the rest — and a header gaining a field does
    /// not rewrite every such caller.
    #[must_use]
    pub fn into_parts(self) -> BlockHeaderParts {
        BlockHeaderParts {
            shard_id: self.shard_id,
            height: self.height,
            parent_block_hash: self.parent_block_hash,
            parent_qc: self.parent_qc,
            proposer: self.proposer,
            timestamp: self.timestamp,
            round: self.round,
            is_fallback: self.is_fallback,
            state_root: self.state_root,
            transaction_root: self.transaction_root,
            certificate_root: self.certificate_root,
            local_receipt_root: self.local_receipt_root,
            provision_root: self.provision_root,
            provision_tx_roots: self.provision_tx_roots,
            abandonment_root: self.abandonment_root,
            state_claims_root: self.state_claims_root,
            txs_in_flight: self.txs_in_flight,
            settled_tick_frontier: self.settled_tick_frontier,
            sweep_frontier: self.sweep_frontier,
            beacon_witness_root: self.beacon_witness_root,
            beacon_witness_leaf_count: self.beacon_witness_leaf_count,
            beacon_witness_base: self.beacon_witness_base,
            reveal_chain: self.reveal_chain,
            split_child_roots: self.split_child_roots,
            terminal_roots: self.terminal_roots,
            load: self.load,
        }
    }

    /// Compute hash of this block header.
    ///
    /// # Panics
    ///
    /// Panics if HBOR encoding fails — `BlockHeader` is a closed wire
    /// type and encoding is infallible in practice.
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        let bytes = hbor_to_vec(self).expect("BlockHeader serialization should never fail");
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
    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };
    use hyperscale_vm_types::SweepBucket;

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

    /// Every structural genesis starts its sweep at the bottom, whatever
    /// its predecessors had reached.
    ///
    /// A frontier is only safe carried down. A merge adopting the higher
    /// of its two predecessors' cursors would put every cell the other
    /// one held between them below the successor's cursor — unswept and
    /// unreachable, a leak nothing else catches, because INV-SWEEP-7
    /// governs creation and this is inheritance. Starting at zero costs
    /// a catch-up over an interval the walk finds empty and no more.
    #[test]
    fn a_structural_genesis_starts_its_sweep_at_the_bottom() {
        let swept = BlockHeader::new(BlockHeaderParts {
            sweep_frontier: SweepFrontier::start_of(SweepBucket(9)),
            ..sample_header().into_parts()
        });
        assert_ne!(swept.sweep_frontier(), SweepFrontier::ZERO);

        let child = BlockHeader::split_child_genesis(
            ShardId::leaf(1, 0),
            StateRoot::from_raw(Hash::from_bytes(b"child subtree")),
            &swept,
            WeightedTimestamp::from_millis(42_000),
        );
        assert_eq!(child.sweep_frontier(), SweepFrontier::ZERO);

        let merged = BlockHeader::merge_parent_genesis(
            ShardId::ROOT,
            StateRoot::from_raw(Hash::from_bytes(b"merged subtree")),
            (swept.hash(), BlockHeight::new(40)),
            (swept.hash(), BlockHeight::new(42)),
            WeightedTimestamp::from_millis(50_000),
        );
        assert_eq!(merged.sweep_frontier(), SweepFrontier::ZERO);

        // And the chain's own genesis, which has no predecessor at all.
        assert_eq!(sample_header().sweep_frontier(), SweepFrontier::ZERO);
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
        let bare_parts = bare.clone().into_parts();
        let carrying = BlockHeader::new(BlockHeaderParts {
            split_child_roots: Some(pair),
            ..bare_parts
        });

        let decoded: BlockHeader = hbor_from_slice(&hbor_to_vec(&carrying).unwrap()).unwrap();
        assert_eq!(decoded.split_child_roots(), Some(pair));
        assert_ne!(carrying.hash(), bare.hash());
    }

    /// A terminating header describes itself as a predecessor terminal;
    /// an ordinary one has nothing to offer a successor and says so,
    /// which is what keeps the successor on its strict rule rather than
    /// handing it a root it could not have committed to.
    #[test]
    fn only_a_terminating_header_is_a_predecessor_terminal() {
        let bare = BlockHeader::new(BlockHeaderParts::default());
        assert!(bare.as_predecessor_terminal().is_none());

        let roots = sample_terminal_roots();
        let terminal = BlockHeader::new(BlockHeaderParts {
            shard_id: ShardId::leaf(1, 0),
            height: BlockHeight::new(41),
            terminal_roots: Some(roots),
            ..Default::default()
        });
        let predecessor = terminal
            .as_predecessor_terminal()
            .expect("a terminating header carries the commitment");
        assert_eq!(predecessor.shard, ShardId::leaf(1, 0));
        assert_eq!(predecessor.height, BlockHeight::new(41));
        assert_eq!(predecessor.block_hash, terminal.hash());
        assert_eq!(predecessor.committed_txs_root, roots.committed_txs);
    }

    fn sample_terminal_roots() -> TerminalRoots {
        TerminalRoots {
            settled_txs: SettledTxsRoot::from_raw(Hash::from_bytes(b"settled window")),
            committed_txs: CommittedTxsRoot::from_raw(Hash::from_bytes(b"committed window")),
        }
    }

    /// `terminal_roots` is hash-affecting header content: the pair
    /// survives the wire round-trip, changes the block hash, and each half
    /// moves it independently — they share a field but not a position, so
    /// neither can stand in for the other.
    #[test]
    fn terminal_roots_round_trip_and_hash() {
        let bare = BlockHeader::new(BlockHeaderParts::default());
        let roots = sample_terminal_roots();

        let carrying = BlockHeader::new(BlockHeaderParts {
            terminal_roots: Some(roots),
            ..Default::default()
        });
        let decoded: BlockHeader = hbor_from_slice(&hbor_to_vec(&carrying).unwrap()).unwrap();
        assert_eq!(decoded.terminal_roots(), Some(roots));
        assert_eq!(decoded.settled_txs_root(), Some(roots.settled_txs));
        assert_eq!(decoded.committed_txs_root(), Some(roots.committed_txs));
        assert_ne!(carrying.hash(), bare.hash());

        for altered in [
            TerminalRoots {
                settled_txs: SettledTxsRoot::from_raw(Hash::from_bytes(b"other settled")),
                ..roots
            },
            TerminalRoots {
                committed_txs: CommittedTxsRoot::from_raw(Hash::from_bytes(b"other committed")),
                ..roots
            },
        ] {
            let other = BlockHeader::new(BlockHeaderParts {
                terminal_roots: Some(altered),
                ..Default::default()
            });
            assert_ne!(
                carrying.hash(),
                other.hash(),
                "each half occupies its own header position"
            );
        }
    }

    /// Forge a `BlockHeader` whose `provision_tx_roots` length claims one
    /// past the cap, padded so the claim is input-satisfiable — the
    /// protocol cap, not the wire-level length bound, is what must fire,
    /// before any per-element work happens.
    #[test]
    fn decode_rejects_oversized_provision_tx_roots_count() {
        let h = sample_header();
        let mut buf = Vec::new();
        for part in [
            hbor_to_vec(&h.shard_id).unwrap(),
            hbor_to_vec(&h.height).unwrap(),
            hbor_to_vec(&h.parent_block_hash).unwrap(),
            hbor_to_vec(&h.parent_qc).unwrap(),
            hbor_to_vec(&h.proposer).unwrap(),
            hbor_to_vec(&h.timestamp).unwrap(),
            hbor_to_vec(&h.round).unwrap(),
            hbor_to_vec(&h.is_fallback).unwrap(),
            hbor_to_vec(&h.state_root).unwrap(),
            hbor_to_vec(&h.transaction_root).unwrap(),
            hbor_to_vec(&h.certificate_root).unwrap(),
            hbor_to_vec(&h.local_receipt_root).unwrap(),
            hbor_to_vec(&h.provision_root).unwrap(),
        ] {
            buf.extend_from_slice(&part);
        }
        // Oversized provision_tx_roots claim, padded to satisfiability.
        varint::write(&mut buf, MAX_PROVISION_TARGET_SHARDS + 1).unwrap();
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_PROVISION_TARGET_SHARDS + 1) * 64,
        ));
        let err = hbor_from_slice::<BlockHeader>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_PROVISION_TARGET_SHARDS
                    && actual == MAX_PROVISION_TARGET_SHARDS + 1
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
