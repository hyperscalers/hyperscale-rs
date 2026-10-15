//! Shared test helpers for storage crate tests.
//!
//! Provides reusable builder functions for [`StateWrites`],
//! `Finalization`, `Block`, and `QuorumCertificate` so that
//! storage-memory and storage-rocksdb tests can share a single source of truth.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice::from_ref;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_hbor::{Bytes, Capped, from_slice, to_vec};
use hyperscale_jmt::{KEY_BYTES, NibblePath, TreeReader};
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::test_utils::{
    STUB_PACKAGE_MARKER, finalization_of, install_stub_protocol_statics, make_finalization,
    make_finalization_leaving, make_finalization_settling, make_leg_finalization, proven_claim,
    rebound, stating, stub_stated_terms, stub_sweepable_cell, test_key, test_transaction,
};
use hyperscale_types::{
    AbandonmentRecord, AbortCharge, Address, AddressClass, AggregateSignature, Anchor, BeaconBlock,
    BeaconBlockHash, BeaconCert, BeaconChainConfig, BeaconState, BeaconVote, BeaconWitnessCommit,
    BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash, BlockHeader, BlockHeaderParts,
    BlockHeight, CLAIM_WINDOW, CertifiedBeaconBlock, CertifiedBlock, ChainOrigin, CollectionId,
    CommittedAt, ConsensusReceipt, Deadline, Decision, DiscardCause, EntryKey, EntryLeaf, Epoch,
    EpochWindows, Event, Evidence, ExecutionCertificate, ExecutionOutcome, Finalization,
    FrontierInputs, GlobalReceiptHash, GlobalReceiptRoot, Hash, Heard, Hears, Inclusion, Joins,
    LocalKey, MAX_SWEEP_PER_BLOCK, MerkleInclusionProof, Movement, PcQc2, PcQc3, PcSignerLengths,
    PcValueElement, PcVector, PcXpProof, PreparedCommit, PriceTable, ProposerTimestamp,
    ProtocolHasher, ProvisionEntry, ProvisionHash, Provisions, QuorumCertificate,
    RETENTION_HORIZON, Randomness, RatifyCert, RatifyRound, ReadFence, ReadFrontier, ReadMark,
    Reading, Round, SWEEP_BUCKET_MS, SafeVoteRegisters, Said, SettledWrites, Settlement,
    ShardAnchor, ShardId, ShardTrie, ShardWitnessPayload, SiblingView, SignerBitfield, Source,
    SpcCert, SpcView, SplitChildRoots, Stake, StakePoolId, StateClaim, StateRoot, StateWrites,
    Stated, StatedTerms, StoredReceipt, SubstateKey, SubstateLeaf, SweepBucket, SweepFrontier,
    SyncHint, TickHalf, TickId, TickLine, Transaction, TransactionDecision, TxHash, TxOutcome,
    TxsInFlight, UnsettledTx, ValidatorId, Value, Verifiable, Verified, VotePosition,
    WeightedTimestamp, WitnessSources, compute_global_receipt_root, compute_merkle_root, decide,
    encode_amount, entry_leaf_key, read_amount, shard_prefix_path, value_of, verdict_leaf,
};
use hyperscale_vm_effects::{
    Answered, CrossingId, CrossingLeaf, FeeHold, Hash32, IntentHash, Terms,
};
use hyperscale_vm_types::{ResourceAddr, TxHash as VmTxHash};

use crate::shard::chain_floor::{FloorInputs, chain_floor};
use crate::shard::members::{AnchorReadings, SettledHalf, VerdictLeaf, verdict_hash};
use crate::shard::sweep::{sweep_for_block, sweep_through};
use crate::shard::unresolved::{replay_window, unresolved_replay_floor};
use crate::tree::Jmt;
use crate::tree::proofs::generate_proof;
use crate::{
    Anchored, BeaconVoteRegisterStore, BlockSweep, BoundaryRetention, BoundaryStore, ChainEntry,
    ChainWrites, FeeHoldReading, FeeTerms, FetchedInstanceStore, GenesisCommit, ImportCursor,
    ImportProgress, JmtSnapshot, MemberIndex, MemberInputs, MemberRow, PackageArtifactStore,
    ParentAnchor, PendingChain, RecoveredState, RowState, SafeVoteRegisterStore, ShardChainReader,
    ShardChainWriter, SubstateStore, SubstateView, Substates, SweepIndex, TickChain, TickOutput,
    TickResolution, VerdictChange, VersionedStore, WitnessSeed, colliding_committed_cell,
    committed_here, committed_tx_cell_key, committed_tx_cells, entry_leaf_value,
    filter_state_writes_to_prefix, held_total, holds_state, key_under_prefix, member_row_leaf,
    reserved_total, verdict_changes,
};

/// The state a parent left, where the parent is certified but not yet
/// persisted: the store's own tip, overlaid with what the blocks between
/// have settled, answering for the height they reach.
///
/// This is what a [`SubstateView`](crate::SubstateView) is in production,
/// spelled small enough for a backend's own tests. It exists because
/// `ParentAnchor::state` must answer for the parent's height and a store
/// snapshot answers for the last block it wrote — the two differ exactly
/// while a proposer is building on blocks its own disk has not caught up
/// with, which is the case worth having a fixture for.
pub struct PendingBaseline<Snap> {
    base: Snap,
    settled: BTreeMap<SubstateKey, Option<Vec<u8>>>,
    anchor: BlockHeight,
}

impl<Snap: Substates> PendingBaseline<Snap> {
    /// `base` overlaid with `pending`'s settled leaves, anchored at
    /// `height`.
    #[must_use]
    pub fn new(base: Snap, pending: &[Arc<JmtSnapshot>], height: BlockHeight) -> Self {
        let mut settled = BTreeMap::new();
        for snapshot in pending {
            for key in snapshot.settled.leaf_keys() {
                let mut value = None;
                snapshot.settled.lay_leaf(*key, &mut value);
                settled.insert(*key, value);
            }
        }
        Self {
            base,
            settled,
            anchor: height,
        }
    }
}

impl<Snap: Substates> Anchored for PendingBaseline<Snap> {
    fn anchor(&self) -> BlockHeight {
        self.anchor
    }
}

impl<Snap: Substates> Substates for PendingBaseline<Snap> {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.settled
            .get(&key)
            .map_or_else(|| self.base.cell(key), Clone::clone)
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        self.base.entries_in_range(owner, collection, lo, hi, limit)
    }
}

/// A completed [`ImportProgress`] covering the whole key span as one
/// exhausted sub-range — the record a one-shot staged import carries.
#[must_use]
pub fn completed_import_progress(height: BlockHeight, staged_bytes: u64) -> ImportProgress {
    ImportProgress {
        anchor_height: height,
        anchor_state_root: StateRoot::ZERO,
        split_bits: 0,
        chunk_limit: 0,
        staged_bytes,
        cursors: vec![ImportCursor {
            next: [0u8; KEY_BYTES],
            end: [0xFF; KEY_BYTES],
            done: true,
        }],
    }
}

/// Stage `leaves` as one chunk and finalize — the one-shot import shape
/// for tests where streaming granularity is irrelevant.
///
/// # Errors
///
/// Propagates the staging or finalize failure.
pub fn import_boundary_state<S: BoundaryStore>(
    storage: &S,
    height: BlockHeight,
    leaves: &[SubstateLeaf],
    witnesses: WitnessSeed,
) -> Result<StateRoot, String> {
    let staged_bytes = leaves.iter().map(|l| l.value.len() as u64).sum();
    storage.stage_import_chunk(&completed_import_progress(height, staged_bytes), leaves)?;
    storage.finalize_boundary_import(height, witnesses)
}

/// A receipt's writes holding one cell: owner `[owner_seed; 16]`, local
/// zero-padded from `local_seed`.
#[must_use]
pub fn make_state_writes(owner_seed: u8, local_seed: u8, value: Vec<u8>) -> StateWrites {
    let mut writes = StateWrites::default();
    writes
        .cells
        .insert(state_key(owner_seed, local_seed), Some(value));
    writes
}

/// The same cell as a value a store can commit directly, for the tests
/// that skip the receipt path.
#[must_use]
pub fn make_settled_writes(owner_seed: u8, local_seed: u8, value: Vec<u8>) -> SettledWrites {
    SettledWrites::from_absolutes(BTreeMap::from([(
        state_key(owner_seed, local_seed),
        Some(value),
    )]))
}

/// A settled set carrying only ordered-collection entries of one
/// collection, for the tests that exercise the entry pipeline.
#[must_use]
pub fn make_settled_entries(owner_seed: u8, entries: &[(u128, Option<Vec<u8>>)]) -> SettledWrites {
    SettledWrites::from_parts(
        BTreeMap::new(),
        entries
            .iter()
            .map(|(order, change)| (entry_key(owner_seed, *order), change.clone()))
            .collect(),
    )
}

/// The entry key for `order` in the test collection under owner
/// `[owner_seed; 31]` — the identity [`make_settled_entries`] writes
/// under.
#[must_use]
pub const fn entry_key(owner_seed: u8, order: u128) -> EntryKey {
    EntryKey {
        owner: Address::new([owner_seed; 31], AddressClass::Component),
        collection: CollectionId([0xEE; 16]),
        order,
    }
}

/// The substate key for owner `[owner_seed; 16]`, local zero-padded from
/// `local_seed` — the key [`make_state_writes`] writes under.
#[must_use]
pub const fn state_key(owner_seed: u8, local_seed: u8) -> SubstateKey {
    let mut local = [0u8; 16];
    local[0] = local_seed;
    SubstateKey {
        owner: Address::new([owner_seed; 31], AddressClass::Component),
        local: LocalKey(local),
    }
}

/// A placeholder local execution certificate for the tick at `height`.
///
/// No signers, no outcomes, so it refuses and charges nothing. It is
/// what a stored finalization needs to decode again: one certificate
/// whose `tick_id` is the tick's own.
#[must_use]
pub fn placeholder_local_ec(shard: ShardId, height: BlockHeight) -> Arc<ExecutionCertificate> {
    Arc::new(ExecutionCertificate::new(
        TickId::new(shard, height),
        WeightedTimestamp::from_millis(0),
        GlobalReceiptRoot::ZERO,
        Capped::empty(),
        AggregateSignature::new([0u8; 96]),
        SignerBitfield::empty(),
    ))
}

/// Build a test attestation at the given height, carrying a placeholder
/// local certificate so it decodes.
#[must_use]
pub fn make_test_finalization(height: BlockHeight, shard: ShardId) -> Finalization {
    Finalization::new(
        TickId::new(shard, height),
        TickHalf::Determined,
        &Capped::from_array([placeholder_local_ec(shard, height)]),
        Capped::from_array([]),
    )
}

/// Build a minimal `Block` at the given height.
#[must_use]
pub fn make_test_block(height: BlockHeight) -> Block {
    make_test_block_with_anchor_wt(height, 0)
}

/// Build a single-validator test block at `height` stamped `timestamp_ms`.
///
/// [`make_test_qc`] carries the header's timestamp onto the QC, so this
/// is how a fixture chain sets the pace its retention floor moves at: a
/// chain a retention horizon wide per block leaves every prior version
/// behind, one a fraction of a horizon apart keeps a known number.
#[must_use]
pub(crate) fn make_test_block_at(height: BlockHeight, timestamp_ms: u64) -> Block {
    let mut block = make_test_block_with_anchor_wt(height, 0);
    if let Block::Live { header, .. } = &mut block {
        *header = BlockHeader::new(BlockHeaderParts {
            height,
            parent_block_hash: header.parent_block_hash(),
            parent_qc: header.parent_qc().clone().into(),
            timestamp: ProposerTimestamp::from_millis(timestamp_ms),
            ..Default::default()
        });
    }
    block
}

/// Build a single-validator test block at `height` whose `parent_qc` carries
/// `anchor_wt_ms` as its weighted timestamp — the canonical clock anchor a
/// block exposes for window and floor tests.
#[must_use]
pub fn make_test_block_with_anchor_wt(height: BlockHeight, anchor_wt_ms: u64) -> Block {
    // Use the full u64 bytes for the parent hash so heights > 255 don't alias.
    let mut parent_bytes = [0u8; 32];
    parent_bytes[..8].copy_from_slice(&height.to_le_bytes());
    let parent_qc = QuorumCertificate::genesis(
        ShardId::ROOT,
        ChainOrigin {
            anchor_wt: WeightedTimestamp::from_millis(anchor_wt_ms),
            ..ChainOrigin::ROOT
        },
    );
    Block::Live {
        header: BlockHeader::new(BlockHeaderParts {
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(&parent_bytes)),
            parent_qc: parent_qc.into(),
            timestamp: ProposerTimestamp::from_millis(height.inner() * 1000),
            ..Default::default()
        }),
        transactions: Arc::new(Capped::empty()),
        certificates: Arc::new(Capped::empty()),
        provisions: Arc::new(Capped::empty()),
        abandonment_records: Arc::new(Capped::empty()),
        state_claims: Arc::new(Capped::empty()),
        tick_manifest: Arc::new(Capped::empty()),
        terms: Arc::new(Capped::empty()),
        witness_sources: Arc::new(WitnessSources::empty()),
    }
}

/// Build a verified `QuorumCertificate` that references the given block.
///
/// The signature is the zero placeholder — these fixtures don't drive real
/// verification, they exercise storage and pipeline shapes. The `Verified`
/// wrapper is `new_unchecked` because the test cluster predates a real
/// signing path; consumers downstream of storage and the commit pipeline
/// require the verified marker.
#[must_use]
pub fn make_test_qc(block: &Block) -> Verified<QuorumCertificate> {
    // SAFETY: synthetic test fixture, no real signature.
    Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
        block.hash(),
        ShardId::ROOT,
        block.height(),
        block.header().parent_block_hash(),
        Round::INITIAL,
        SignerBitfield::new(4),
        AggregateSignature::ZERO,
        WeightedTimestamp::from_millis(block.header().timestamp().as_millis()),
    ))
}

/// Build a `Verified<CertifiedBlock>` for use with [`commit_settled_at`]
/// and the commit-pipeline test fixtures.
///
/// # Panics
///
/// Panics if internal `CertifiedBlock` construction fails — only happens
/// when callers feed a `qc` whose `block_hash` doesn't match `block`, which
/// the helper precludes by construction.
#[must_use]
pub fn make_test_certified(block: Block) -> Arc<Verified<CertifiedBlock>> {
    let qc = make_test_qc(&block);
    let certified = CertifiedBlock::new_unchecked(block, qc);
    // SAFETY: synthetic test fixture; storage round-trip tests don't
    // exercise the `Verified<CertifiedBlock>` predicate.
    Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(
        certified,
    ))
}

/// Build a placeholder [`SpcCert::Direct`] for test fixtures.
///
/// The embedded `PcQc3` is structurally well-formed but doesn't
/// verify; the cert is intended for storage round-trip tests, not
/// consensus verification.
#[must_use]
fn placeholder_cert() -> SpcCert {
    let qc2 = PcQc2::new(
        PcVector::empty(),
        SignerBitfield::new(4),
        AggregateSignature::new([0x11; 96]),
        PcXpProof::Full,
    );
    let proof = PcQc3::new(
        PcVector::empty(),
        qc2,
        None,
        None,
        SignerBitfield::new(4),
        PcSignerLengths::Uniform(0),
        AggregateSignature::new([0x33; 96]),
    );
    SpcCert::Direct {
        prev_view: SpcView::new(1),
        value: PcVector::empty(),
        proof: proof.into(),
    }
}

/// Build a certified beacon block at `epoch` with tag-derived
/// `prev_block_hash`.
///
/// The cert is a structurally-valid but cryptographically-unverified
/// placeholder. Suitable for storage round-trip tests, not for
/// consensus verification.
#[must_use]
pub fn make_test_beacon_block(epoch: u64, tag: &[u8]) -> Arc<Verified<CertifiedBeaconBlock>> {
    let block = BeaconBlock::new(
        Epoch::new(epoch),
        BeaconBlockHash::from_raw(Hash::from_bytes(tag)),
        Capped::empty(),
    );
    let ratify = RatifyCert::new(
        block.prev_block_hash(),
        block.epoch(),
        RatifyRound::INITIAL,
        block.block_hash(),
        SignerBitfield::new(4),
        AggregateSignature::new([0x22; 96]),
    );
    Arc::new(Verified::new_unchecked_for_test(
        CertifiedBeaconBlock::new_unchecked(
            block,
            BeaconCert::Normal {
                spc: Box::new(placeholder_cert()),
                ratify,
            },
        ),
    ))
}

/// Build a minimal `BeaconState` at `epoch` whose `randomness` is
/// derived from `tag`. All collection fields are empty.
///
/// Sufficient to drive storage round-trip tests — every field is
/// stable across HBOR encoding and two calls with identical inputs
/// produce equal states. Not a valid state under beacon-state
/// verification.
#[must_use]
pub fn make_test_beacon_state(epoch: u64, tag: &[u8]) -> Arc<BeaconState> {
    let mut randomness = [0u8; 32];
    let copy_len = tag.len().min(32);
    randomness[..copy_len].copy_from_slice(&tag[..copy_len]);
    let mut state = BeaconState::empty(BeaconChainConfig::default());
    state.current_epoch = Epoch::new(epoch);
    state.randomness = Randomness::new(randomness);
    Arc::new(state)
}

/// Build a `(block, state)` pair for storage round-trip tests.
///
/// Under the cert-as-authenticator model the block's `state_root` is
/// no longer carried on-chain (it's derived by re-running `apply_epoch`),
/// so this helper just produces a structurally well-formed block paired
/// with an arbitrary state.
#[must_use]
pub fn make_test_block_and_state(
    epoch: u64,
    tag: &[u8],
) -> (Arc<Verified<CertifiedBeaconBlock>>, Arc<BeaconState>) {
    let state = make_test_beacon_state(epoch, tag);
    let block = make_test_beacon_block(epoch, tag);
    (block, state)
}

/// Build a deterministic `StoredReceipt` from `seed` — succeeded, with a
/// single event so equality checks across seeds distinguish entries.
#[must_use]
pub fn make_test_receipt(seed: u8) -> StoredReceipt {
    let tx_hash = TxHash::from(Hash::from_bytes(&[seed; 32]));
    let consensus = ConsensusReceipt::Succeeded {
        receipt_hash: GlobalReceiptHash::ZERO,
        writes: StateWrites::default(),
        beacon_witness_events: Capped::empty(),
        events: Capped::from_array([Event {
            emitter: Address::new([seed; 31], AddressClass::Component),
            event_type: u32::from(seed),
            payload: Bytes::from_array([seed, seed + 1]),
        }]),
    };
    StoredReceipt::new(tx_hash, Arc::new(consensus))
}

// ═══════════════════════════════════════════════════════════════════════
// Execution Certificate helpers
// ═══════════════════════════════════════════════════════════════════════

/// Build a test `ExecutionCertificate` at the given block height with a
/// deterministic outcome derived from `seed`.
///
/// `seed` also disambiguates the `TickId` (via `remote_shards`), so two ECs
/// at the same `block_height` with different seeds have distinct identities
/// — matching the protocol invariant that one tick produces one EC.
///
/// # Panics
///
/// If a list written out here is past the cap its type states.
#[must_use]
pub fn make_test_execution_certificate(
    seed: u8,
    block_height: BlockHeight,
) -> ExecutionCertificate {
    let outcomes = vec![TxOutcome::new(
        TxHash::from(Hash::from_bytes(&[seed + 100; 32])),
        ExecutionOutcome::Succeeded {
            receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed + 150; 32])),
        },
    )];
    let global_receipt_root = compute_global_receipt_root(&outcomes);
    ExecutionCertificate::new(
        TickId::new(ShardId::ROOT, block_height),
        WeightedTimestamp::from_millis(block_height.inner() + 1),
        global_receipt_root,
        Capped::new(outcomes).expect("a list written out in a test"),
        AggregateSignature::new([0u8; 96]),
        SignerBitfield::new(4),
    )
}

/// Build a test block that carries ECs inside its finalizations.
///
/// The tick's `tick_id` is taken from the first EC's `tick_id` so
/// the local-EC decode invariant is satisfied without injecting a placeholder.
fn make_test_block_with_ecs(height: BlockHeight, ecs: Vec<Arc<ExecutionCertificate>>) -> Block {
    let block = make_test_block(height);
    if ecs.is_empty() {
        return block;
    }
    let certificate = Finalization::new(
        *ecs[0].tick_id(),
        TickHalf::Determined,
        &Capped::new(ecs).expect("a list written out in a test"),
        Capped::empty(),
    );
    push_certificate(block, Arc::new(certificate.into()))
}

/// Append a finalization to `block`'s certificate list, preserving
/// the block variant.
///
/// # Panics
///
/// If `fw` is past the certificate cap the block's field states.
#[must_use]
pub fn push_certificate(block: Block, fw: Arc<Verifiable<Finalization>>) -> Block {
    match block {
        Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            tick_manifest,
            terms,
            witness_sources,
        } => {
            let mut certificates = (*certificates).clone();
            certificates.push(fw).expect("a list written out in a test");
            Block::Live {
                header,
                transactions,
                certificates: Arc::new(certificates),
                provisions,
                abandonment_records,
                state_claims,
                tick_manifest,
                terms,
                witness_sources,
            }
        }
        Block::Sealed {
            header,
            transactions,
            certificates,
            provision_hashes,
            engagements,
            abandonment_records,
            state_claims,
            tick_manifest,
            terms,
            witness_sources,
        } => {
            let mut certificates = (*certificates).clone();
            certificates.push(fw).expect("a list written out in a test");
            Block::Sealed {
                header,
                transactions,
                certificates: Arc::new(certificates),
                provision_hashes,
                engagements,
                abandonment_records,
                state_claims,
                tick_manifest,
                terms,
                witness_sources,
            }
        }
    }
}

/// Put `record` on `block`, preserving the block variant.
fn with_abandonment(block: Block, record: AbandonmentRecord) -> Block {
    match block {
        Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            state_claims,
            tick_manifest,
            terms,
            witness_sources,
            ..
        } => Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            abandonment_records: Arc::new(Capped::from_array([record])),
            state_claims,
            tick_manifest,
            terms,
            witness_sources,
        },
        Block::Sealed {
            header,
            transactions,
            certificates,
            provision_hashes,
            engagements,
            state_claims,
            tick_manifest,
            terms,
            witness_sources,
            ..
        } => Block::Sealed {
            header,
            transactions,
            certificates,
            provision_hashes,
            engagements,
            abandonment_records: Arc::new(Capped::from_array([record])),
            state_claims,
            tick_manifest,
            terms,
            witness_sources,
        },
    }
}

/// The store a shared test commits through: the one commit path, and
/// the tip it lands on.
pub trait TestStore: ShardChainWriter + SubstateStore + Clone {}

impl<S: ShardChainWriter + SubstateStore + Clone> TestStore for S {}

/// Commit `certified` at its own height through the one commit path a
/// store has.
///
/// Anchored at the store's tip: prepared, then applied as a flushed
/// commit. `creations` and `removals` are the block's, on
/// [`ShardChainWriter::prepare_block_commit`]'s terms, and `witness` is
/// its beacon-witness commit. Returns the committed state root.
pub fn commit_settled_at<S: TestStore>(
    storage: &S,
    certified: &Arc<Verified<CertifiedBlock>>,
    creations: &[(SubstateKey, Vec<u8>)],
    removals: &[SubstateKey],
    witness: &BeaconWitnessCommit,
) -> StateRoot {
    commit_folding(
        storage,
        certified,
        creations,
        removals,
        witness,
        &MemberInputs::still(ShardId::ROOT),
    )
}

/// Commit `certified` as [`commit_settled_at`] does, folding into tick
/// membership what the block itself writes there: a `Pending` row for
/// each transaction it states terms for, and the removal of each row one of its
/// finalizations settles.
fn commit_with_members<S: TestStore>(
    storage: &S,
    certified: &Arc<Verified<CertifiedBlock>>,
) -> StateRoot {
    commit_folding(
        storage,
        certified,
        &[],
        &[],
        &empty_witness(),
        &MemberInputs::of(
            certified.block(),
            FrontierInputs::still(ShardId::ROOT).windows,
        ),
    )
}

fn commit_folding<S: TestStore>(
    storage: &S,
    certified: &Arc<Verified<CertifiedBlock>>,
    creations: &[(SubstateKey, Vec<u8>)],
    removals: &[SubstateKey],
    witness: &BeaconWitnessCommit,
    members: &MemberInputs,
) -> StateRoot {
    let storage = Arc::new(storage.clone());
    let block = certified.block();
    let (_, _, commit) = storage.prepare_block_commit(
        ParentAnchor {
            state_root: storage.state_root(),
            height: storage.jmt_height(),
            state: &storage.snapshot(),
            pending: &[],
            base_reads: None,
        },
        &block.certificates()[..],
        ChainWrites {
            creations,
            removals,
            sweep_frontier: certified.block().header().sweep_frontier(),
            frontier: &FrontierInputs::still(ShardId::ROOT),
            state_claims: block.state_claims(),
            members,
        },
        block.height(),
    );
    commit(SyncHint::FlushNow, certified, witness)
}

/// Commit empty blocks at every height from 1 up to, not including,
/// `target`, so a block at `target` extends a contiguous chain.
fn commit_empty_blocks_below(storage: &impl TestStore, target: BlockHeight) {
    let witness = empty_witness();
    for h in 1..target.inner() {
        let certified = make_test_certified(make_test_block(BlockHeight::new(h)));
        commit_settled_at(storage, &certified, &[], &[], &witness);
    }
}

/// A finalization at `height` whose one receipt carries `writes`, with
/// the placeholder certificate a stored finalization needs to decode.
fn settling(height: BlockHeight, writes: StateWrites) -> Arc<Verifiable<Finalization>> {
    let receipt = StoredReceipt {
        tx_hash: TxHash::ZERO,
        consensus: Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes,
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        }),
    };
    Arc::new(
        Finalization::new(
            TickId::new(ShardId::ROOT, height),
            TickHalf::Determined,
            &Capped::from_array([placeholder_local_ec(ShardId::ROOT, height)]),
            Capped::from_array([receipt]),
        )
        .into(),
    )
}

/// Commit `writes` at `height` through the one commit path.
///
/// The writes ride a single-receipt finalization inside a test block,
/// so substates, state history, and the JMT all land exactly as a live
/// commit writes them. Returns the resulting state root.
pub fn commit_block_with_updates(
    storage: &impl TestStore,
    height: BlockHeight,
    writes: &StateWrites,
) -> StateRoot {
    let block = push_certificate(make_test_block(height), settling(height, writes.clone()));
    commit_settled_at(
        storage,
        &make_test_certified(block),
        &[],
        &[],
        &empty_witness(),
    )
}

/// Commit `writes` as the one receipt of a block at the store's next
/// height, stamped `at`.
///
/// The stamp is the clock the retention floor moves on, so a chain a
/// horizon apart per commit retires every version behind it and one a
/// fraction apart keeps a known number. Empty writes commit an empty
/// block, which still advances the version. Returns the committed state
/// root.
pub fn commit_writes_at(
    storage: &impl TestStore,
    writes: &SettledWrites,
    at: WeightedTimestamp,
) -> StateRoot {
    let height = storage.jmt_height().next();
    let mut block = make_test_block_at(height, at.as_millis());
    if !writes.is_empty() {
        block = push_certificate(block, settling(height, writes.clone().into()));
    }
    commit_settled_at(
        storage,
        &make_test_certified(block),
        &[],
        &[],
        &empty_witness(),
    )
}

/// [`commit_writes_at`] on the zero clock, for a test that does not care
/// where the floor stands.
pub fn commit_writes(storage: &impl TestStore, writes: &SettledWrites) -> StateRoot {
    commit_writes_at(storage, writes, WeightedTimestamp::ZERO)
}

/// The union of already-settled fixtures — values, so nothing to fold.
#[must_use]
pub(crate) fn union_of(parts: &[SettledWrites]) -> SettledWrites {
    SettledWrites::from_absolutes(
        parts
            .iter()
            .flat_map(SettledWrites::cells)
            .map(|(key, change)| (*key, change.clone()))
            .collect(),
    )
}

/// Writes holding a single removal of the cell [`make_state_writes`]
/// writes.
#[must_use]
pub(crate) fn make_state_delete(owner_seed: u8, local_seed: u8) -> SettledWrites {
    SettledWrites::from_absolutes(BTreeMap::from([(state_key(owner_seed, local_seed), None)]))
}

/// The clock at height `h` of a chain pacing `blocks` of itself into one
/// retention horizon, so a tip at `h` leaves the floor at `h - blocks`.
#[must_use]
pub fn paced(height: u64, blocks: u64) -> WeightedTimestamp {
    let step = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX) / blocks;
    WeightedTimestamp::from_millis(height * step)
}

/// A block at `height` whose one tick settles `receipts` and which
/// carries no transactions — what a follow applies when only receipts
/// move state.
///
/// # Panics
///
/// If a list written out here is past the cap its type states.
#[must_use]
pub fn block_settling(height: BlockHeight, receipts: Vec<StoredReceipt>) -> Block {
    let finalized = Arc::new(
        Finalization::new(
            TickId::new(ShardId::ROOT, height),
            TickHalf::Determined,
            &Capped::from_array([]),
            Capped::new(receipts).expect("a list written out in a test"),
        )
        .into(),
    );
    push_certificate(make_test_block(height), finalized)
}

const fn empty_witness() -> BeaconWitnessCommit {
    BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO)
}

/// Commit a block at `height` whose header commits the beacon-witness
/// accumulator state after appending `leaves`.
///
/// The header carries the leaves' merkle root and cumulative count, and
/// the leaves fold into the same atomic write. Returns the committed
/// block hash.
pub fn commit_block_with_witnesses(
    storage: &impl TestStore,
    height: BlockHeight,
    leaves: &[ShardWitnessPayload],
) -> BlockHash {
    let leaf_hashes: Vec<Hash> = leaves.iter().map(ShardWitnessPayload::leaf_hash).collect();
    let root = BeaconWitnessRoot::from_raw(compute_merkle_root(&leaf_hashes));
    let count = BeaconWitnessLeafCount::new(leaves.len() as u64);
    let mut parent_bytes = [0u8; 32];
    parent_bytes[..8].copy_from_slice(&height.to_le_bytes());
    let block = Block::Live {
        header: BlockHeader::new(BlockHeaderParts {
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(&parent_bytes)),
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(height.inner() * 1000),
            beacon_witness_root: root,
            beacon_witness_leaf_count: count,
            ..Default::default()
        }),
        transactions: Arc::new(Capped::empty()),
        certificates: Arc::new(Capped::empty()),
        provisions: Arc::new(Capped::empty()),
        abandonment_records: Arc::new(Capped::empty()),
        state_claims: Arc::new(Capped::empty()),
        tick_manifest: Arc::new(Capped::empty()),
        terms: Arc::new(Capped::empty()),
        witness_sources: Arc::new(WitnessSources::empty()),
    };
    let block_hash = block.hash();
    let witness = BeaconWitnessCommit {
        starting_leaf_index: BeaconWitnessLeafCount::ZERO,
        leaves: leaves.to_vec(),
        leaf_count_at_block_end: count,
        prune_persisted_below: None,
    };
    commit_settled_at(storage, &make_test_certified(block), &[], &[], &witness);
    block_hash
}

/// Commit a block at `height` whose header commits the witness window
/// `[base, base + window.len())`.
///
/// The header carries the root over `window`, the cumulative count, and
/// `base` as its window base. The commit appends `appended` (the
/// window's tail at `base + window.len() - appended.len()`) and carries
/// `prune_persisted_below` so backend retention behaviour is
/// observable. Returns the committed block hash.
///
/// # Panics
///
/// Panics if `appended` is longer than `window` — the appended tail
/// must lie inside the committed window.
pub fn commit_block_with_witness_window(
    storage: &impl TestStore,
    height: BlockHeight,
    base: u64,
    window: &[ShardWitnessPayload],
    appended: &[ShardWitnessPayload],
    prune_persisted_below: Option<BeaconWitnessLeafCount>,
) -> BlockHash {
    assert!(appended.len() <= window.len());
    let leaf_hashes: Vec<Hash> = window.iter().map(ShardWitnessPayload::leaf_hash).collect();
    let root = BeaconWitnessRoot::from_raw(compute_merkle_root(&leaf_hashes));
    let count = BeaconWitnessLeafCount::new(base + window.len() as u64);
    let mut parent_bytes = [0u8; 32];
    parent_bytes[..8].copy_from_slice(&height.to_le_bytes());
    let block = Block::Live {
        header: BlockHeader::new(BlockHeaderParts {
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(&parent_bytes)),
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(height.inner() * 1000),
            beacon_witness_root: root,
            beacon_witness_leaf_count: count,
            beacon_witness_base: BeaconWitnessLeafCount::new(base),
            ..Default::default()
        }),
        transactions: Arc::new(Capped::empty()),
        certificates: Arc::new(Capped::empty()),
        provisions: Arc::new(Capped::empty()),
        abandonment_records: Arc::new(Capped::empty()),
        state_claims: Arc::new(Capped::empty()),
        tick_manifest: Arc::new(Capped::empty()),
        terms: Arc::new(Capped::empty()),
        witness_sources: Arc::new(WitnessSources::empty()),
    };
    let block_hash = block.hash();
    let witness = BeaconWitnessCommit {
        starting_leaf_index: BeaconWitnessLeafCount::new(count.inner() - appended.len() as u64),
        leaves: appended.to_vec(),
        leaf_count_at_block_end: count,
        prune_persisted_below,
    };
    commit_settled_at(storage, &make_test_certified(block), &[], &[], &witness);
    block_hash
}

/// A `ShardWitnessPayload::StakeDeposit` fixture.
#[must_use]
pub const fn stake_deposit(amount: u64) -> ShardWitnessPayload {
    ShardWitnessPayload::StakeDeposit {
        pool_id: StakePoolId::new(1),
        amount: Stake::from_whole_tokens(amount),
    }
}

/// The owner prefix seeded at `seed`, with the leading bit alternating.
///
/// A leaf key's leading bit is the first bit a depth-1 shard prefix
/// routes on, and a leaf key is its owner and local halves by identity —
/// so alternating the owner's top bit is what makes a seeded population
/// straddle the root split rather than piling into one child.
#[must_use]
pub const fn seeded_owner(seed: u8) -> u8 {
    if seed.is_multiple_of(2) {
        seed
    } else {
        seed | 0x80
    }
}

/// Seed `entries` single-substate block commits at heights
/// `1..=entries`, each writing one distinct owner keyed by
/// [`seeded_owner`] of its seed byte.
pub fn seed_substate_commits(storage: &impl TestStore, entries: u8) {
    for seed in 1..=entries {
        let writes = make_state_writes(seeded_owner(seed), seed, vec![seed, seed, seed]);
        commit_block_with_updates(storage, BlockHeight::new(u64::from(seed)), &writes);
    }
}

/// A snap-sync serving replica.
///
/// Seeds `entries` substate commits, then a boundary block at
/// `entries + 1` whose header carries the witness commitment over
/// `leaves`, pinned for serving. Returns the anchor a joiner verifies
/// against.
///
/// # Panics
///
/// Panics if pinning fails (this is a test helper).
pub fn pin_snap_sync_replica(
    storage: &(impl TestStore + BoundaryStore),
    entries: u8,
    leaves: &[ShardWitnessPayload],
) -> ShardAnchor {
    seed_substate_commits(storage, entries);
    let anchor_height = BlockHeight::new(u64::from(entries) + 1);
    let block_hash = commit_block_with_witnesses(storage, anchor_height, leaves);
    storage.pin_boundary(anchor_height).unwrap();
    ShardAnchor {
        state_root: storage.state_root(),
        block_hash,
        height: anchor_height,
        weighted_timestamp: WeightedTimestamp::from_millis(anchor_height.inner()),
        witness_base: BeaconWitnessLeafCount::ZERO,
        terminal_settled_txs: None,
        handoff_complete: None,
        terminal_epoch: None,
    }
}

/// Shared range-read test for `get_beacon_witness_payload_range`.
///
/// The range read must agree with the full prefix read on interior
/// pages, clamp nothing (callers bound `end`), and return empty for
/// degenerate or out-of-range spans.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_witness_payload_range_reads(storage: &(impl ShardChainReader + TestStore)) {
    let leaves: Vec<ShardWitnessPayload> = (1u64..=5).map(stake_deposit).collect();
    commit_block_with_witnesses(storage, BlockHeight::new(1), &leaves);

    let all = storage.get_beacon_witness_payloads(BeaconWitnessLeafCount::new(5));
    assert_eq!(all.len(), 5);
    assert_eq!(storage.get_beacon_witness_payload_range(0, 5), all);
    assert_eq!(storage.get_beacon_witness_payload_range(1, 3), all[1..3]);
    assert_eq!(storage.get_beacon_witness_payload_range(4, 9), all[4..]);
    assert!(storage.get_beacon_witness_payload_range(3, 3).is_empty());
    assert!(storage.get_beacon_witness_payload_range(7, 9).is_empty());
}

/// Shared EC roundtrip test: commit a block carrying a finalization, then
/// read its certificate back by the transaction it attests.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_ec_storage_roundtrip(storage: &(impl ShardChainReader + TestStore)) {
    let ec = make_test_execution_certificate(1, BlockHeight::new(10));
    let tick_id = *ec.tick_id();
    let tx = attested_by(&ec);

    // Absent until the finalization commits.
    assert!(storage.get_execution_certificates_for_txs(&[tx]).is_empty());

    commit_empty_blocks_below(storage, BlockHeight::new(10));
    let block = make_test_block_with_ecs(BlockHeight::new(10), vec![Arc::new(ec)]);
    let certified = make_test_certified(block);
    commit_settled_at(storage, &certified, &[], &[], &empty_witness());

    let served = storage.get_execution_certificates_for_txs(&[tx]);
    assert_eq!(
        served.len(),
        1,
        "the certificate is served by the transaction it attests"
    );
    assert_eq!(served[0].tick_id(), &tick_id);
    assert_eq!(served[0].block_height(), BlockHeight::new(10));
}

/// The one transaction a [`make_test_execution_certificate`] attests.
fn attested_by(ec: &ExecutionCertificate) -> TxHash {
    ec.tx_outcomes()
        .iter()
        .next()
        .expect("a test certificate attests one outcome")
        .tx_hash()
}

/// Shared EC batch test: commit finalizations at two heights, then ask by
/// transaction: every transaction certified here is answered by its own
/// certificate, and one never certified here is skipped.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_ec_storage_batch(storage: &(impl ShardChainReader + TestStore)) {
    let ec1 = make_test_execution_certificate(1, BlockHeight::new(10));
    let ec2 = make_test_execution_certificate(2, BlockHeight::new(20));
    let never = attested_by(&make_test_execution_certificate(3, BlockHeight::new(30)));

    commit_empty_blocks_below(storage, BlockHeight::new(10));
    let block10 = make_test_block_with_ecs(BlockHeight::new(10), vec![Arc::new(ec1.clone())]);
    commit_settled_at(
        storage,
        &make_test_certified(block10),
        &[],
        &[],
        &empty_witness(),
    );

    for h in 11..20 {
        let certified = make_test_certified(make_test_block(BlockHeight::new(h)));
        commit_settled_at(storage, &certified, &[], &[], &empty_witness());
    }
    let block20 = make_test_block_with_ecs(BlockHeight::new(20), vec![Arc::new(ec2.clone())]);
    commit_settled_at(
        storage,
        &make_test_certified(block20),
        &[],
        &[],
        &empty_witness(),
    );

    let served: BTreeSet<TickId> = storage
        .get_execution_certificates_for_txs(&[attested_by(&ec1), attested_by(&ec2), never])
        .iter()
        .map(|cert| *cert.tick_id())
        .collect();
    assert_eq!(served, BTreeSet::from([*ec1.tick_id(), *ec2.tick_id()]));

    let partial = storage.get_execution_certificates_for_txs(&[attested_by(&ec2), never]);
    assert_eq!(partial.len(), 1);
    assert_eq!(partial[0].tick_id(), ec2.tick_id());
}

/// Shared test: a finalization whose tick names another shard is stored
/// with the block and indexed for no transaction.
///
/// The by-transaction read answers what this shard attested, and a
/// counterpart's certificate answers a question nobody asks this shard.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_foreign_ticks_finalization_is_stored_and_not_indexed(
    storage: &(impl ShardChainReader + TestStore),
) {
    let tx = TxHash::from(Hash::from_bytes(&[9u8; 32]));
    let outcomes = vec![TxOutcome::new(
        tx,
        ExecutionOutcome::Succeeded {
            receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[98u8; 32])),
        },
    )];
    let foreign = ExecutionCertificate::new(
        TickId::new(ShardId::leaf(1, 1), BlockHeight::new(3)),
        WeightedTimestamp::from_millis(4),
        compute_global_receipt_root(&outcomes),
        Capped::new(outcomes).expect("a list written out in a test"),
        AggregateSignature::new([0u8; 96]),
        SignerBitfield::new(4),
    );
    let finalization: Verifiable<Finalization> = Finalization::new(
        *foreign.tick_id(),
        TickHalf::Legs,
        &Capped::from_array([Arc::new(foreign)]),
        Capped::from_array([]),
    )
    .into();
    let id = finalization.receipt_hash();

    let block = push_certificate(make_test_block(BlockHeight::new(1)), Arc::new(finalization));
    commit_settled_at(
        storage,
        &make_test_certified(block),
        &[],
        &[],
        &empty_witness(),
    );

    assert_eq!(
        storage.get_certificates_batch(&[id]).len(),
        1,
        "the finalization is stored with its block",
    );
    assert!(
        storage.get_execution_certificates_for_txs(&[tx]).is_empty(),
        "and answers for no transaction here",
    );
}

/// One substate commit for `seed`: the cell [`make_settled_writes`]
/// seeds, at the store's next height.
pub fn commit_one(storage: &impl TestStore, seed: u8) {
    commit_writes(
        storage,
        &make_settled_writes(seed, seed, vec![seed, seed, seed]),
    );
}

/// Shared boundary retention test: pin one height past the rule's
/// count and check a trim stops serving only the oldest pin.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_boundary_retention_evicts_oldest<S: BoundaryStore + TestStore>(storage: &S) {
    let retention = BoundaryRetention {
        newest: 3,
        attested: None,
    };
    let last = u64::try_from(retention.newest).expect("small count") + 1;
    for height in 1..=last {
        commit_one(storage, u8::try_from(height).expect("small loop bound"));
        storage.pin_boundary(BlockHeight::new(height)).unwrap();
        storage.trim_boundaries(retention);
    }
    assert!(storage.open_boundary(BlockHeight::new(1)).is_none());
    assert!(storage.open_boundary(BlockHeight::new(2)).is_some());
    assert!(storage.open_boundary(BlockHeight::new(last)).is_some());
}

/// Shared boundary retention test: the attested anchor outlives any
/// number of newer pins, while the count still governs the rest; once
/// the attestation moves on, the next trim evicts the old anchor.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_boundary_retention_keeps_the_attested_anchor<S: BoundaryStore + TestStore>(
    storage: &S,
) {
    let anchor = BlockHeight::new(1);
    let held = BoundaryRetention {
        newest: 2,
        attested: Some(anchor),
    };
    for height in 1..=6u64 {
        commit_one(storage, u8::try_from(height).expect("small loop bound"));
        storage.pin_boundary(BlockHeight::new(height)).unwrap();
        storage.trim_boundaries(held);
    }
    assert!(storage.open_boundary(anchor).is_some());
    for evicted in 2..=4u64 {
        assert!(storage.open_boundary(BlockHeight::new(evicted)).is_none());
    }
    assert!(storage.open_boundary(BlockHeight::new(5)).is_some());
    assert!(storage.open_boundary(BlockHeight::new(6)).is_some());

    storage.trim_boundaries(BoundaryRetention {
        attested: Some(BlockHeight::new(6)),
        ..held
    });
    assert!(storage.open_boundary(anchor).is_none());
    assert!(storage.open_boundary(BlockHeight::new(5)).is_some());
    assert!(storage.open_boundary(BlockHeight::new(6)).is_some());
}

/// Shared boundary gating test: a committed but never-pinned height is
/// not served.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_boundary_unpinned_height_not_served<S: BoundaryStore + TestStore>(storage: &S) {
    commit_one(storage, 1);
    assert!(storage.open_boundary(BlockHeight::new(1)).is_none());
}

/// The entry pipeline both backends serve identically.
///
/// Two commits over one collection — create, overwrite, remove, add — with
/// range scans, the cap, the self-describing leaf, and the historical scan at
/// the first version asserted between them. Backend-specific tails (GC,
/// retention) stay with their backend.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_entries_commit_serve_and_history<S: VersionedStore + TestStore>(storage: &S) {
    let commit = |writes: &SettledWrites| {
        commit_writes(storage, writes);
    };
    commit(&make_settled_entries(
        7,
        &[
            (5, Some(vec![5])),
            (10, Some(vec![10])),
            (20, Some(vec![20])),
        ],
    ));
    let root_v1 = storage.state_root();
    assert_ne!(root_v1, StateRoot::ZERO, "entries move the root");

    let key = entry_key(7, 5);
    assert_eq!(
        storage.entries_in_range(key.owner, key.collection, 0, u128::MAX, 10),
        vec![(5, vec![5]), (10, vec![10]), (20, vec![20])],
    );
    // Bounds and the cap hold.
    assert_eq!(
        storage.entries_in_range(key.owner, key.collection, 6, 20, 1),
        vec![(10, vec![10])],
    );
    // The leaf form is readable by its derived key and self-describes.
    let leaf = storage
        .cell(entry_leaf_key(&ProtocolHasher, key))
        .expect("the entry commits a leaf");
    let decoded = from_slice::<EntryLeaf>(&leaf).unwrap();
    assert_eq!((decoded.order, decoded.value), (5, vec![5]));

    // Version 2: overwrite one, remove one, add one.
    commit(&make_settled_entries(
        7,
        &[(10, Some(vec![99])), (20, None), (30, Some(vec![30]))],
    ));
    assert_ne!(storage.state_root(), root_v1);
    assert_eq!(
        storage.entries_in_range(key.owner, key.collection, 0, u128::MAX, 10),
        vec![(5, vec![5]), (10, vec![99]), (30, vec![30])],
    );

    // The historical scan at version 1 answers the old interval, and
    // stops at the limit: the cap is on visible entries, so the removed
    // one and the one added later are neither counted nor returned.
    assert_eq!(
        storage.snapshot_at(BlockHeight::new(1)).entries_in_range(
            key.owner,
            key.collection,
            0,
            u128::MAX,
            10
        ),
        vec![(5, vec![5]), (10, vec![10]), (20, vec![20])],
    );
    assert_eq!(
        storage.snapshot_at(BlockHeight::new(1)).entries_in_range(
            key.owner,
            key.collection,
            6,
            u128::MAX,
            1
        ),
        vec![(10, vec![10])],
    );
    assert_eq!(
        storage.snapshot_at(BlockHeight::new(2)).entries_in_range(
            key.owner,
            key.collection,
            6,
            u128::MAX,
            1
        ),
        vec![(10, vec![99])],
        "the cap counts what is visible at the version, not what the interval holds"
    );

    // A wide interval of another owner rewritten whole: the historical
    // scan returns the limit's worth of the old values and no more, off
    // the tip as at it.
    let wide_key = entry_key(8, 100);
    let wide: Vec<(u128, Option<Vec<u8>>)> = (100..140u128)
        .map(|order| (order, Some(vec![u8::try_from(order).expect("small")])))
        .collect();
    commit(&make_settled_entries(8, &wide));
    let rewritten: Vec<(u128, Option<Vec<u8>>)> = (100..140u128)
        .map(|order| (order, (order % 3 != 0).then(|| vec![0xAA])))
        .collect();
    commit(&make_settled_entries(8, &rewritten));
    assert_eq!(
        storage.snapshot_at(BlockHeight::new(3)).entries_in_range(
            wide_key.owner,
            wide_key.collection,
            100,
            139,
            3
        ),
        vec![(100, vec![100]), (101, vec![101]), (102, vec![102])],
    );
    assert_eq!(
        storage.entries_in_range(wide_key.owner, wide_key.collection, 100, 139, 3),
        vec![(100, vec![0xAA]), (101, vec![0xAA]), (103, vec![0xAA])],
        "at the tip the removed orders are skipped under the same cap"
    );
    // And another collection's interval stays empty.
    assert!(
        storage
            .entries_in_range(state_key(9, 0).owner, key.collection, 0, u128::MAX, 10)
            .is_empty()
    );
}

/// Shared sweep-index conformance: the index tracks what the leaves say,
/// and the walk that reads it visits cells in sweep order.
///
/// Runs against [`StubVmStatics`](hyperscale_types::test_utils::StubVmStatics)'s
/// sweepable family, so a backend's index is tested without a VM: what
/// the backend owes is that it indexes whatever the judgement calls
/// sweepable, which is a property of the backend and not of the family.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_sweep_index_tracks_the_leaves<S>(storage: &S)
where
    S: TestStore + SweepIndex,
{
    install_stub_protocol_statics();
    let commit = |writes: &SettledWrites| {
        commit_writes(storage, writes);
    };
    let bucket_ms = SWEEP_BUCKET_MS;
    // Three cells across two buckets under two owners, so the walk has
    // to order by bucket before owner — the property a leaf-key walk
    // does not have.
    let cells: Vec<(SubstateKey, u64)> = [
        (0xF0u8, 3 * bucket_ms, 0x11u8),
        (0x10, 3 * bucket_ms + 5, 0x22),
        (0x10, 5 * bucket_ms, 0x33),
    ]
    .into_iter()
    .map(|(owner, expiry, body)| {
        let (local, value) = stub_sweepable_cell(expiry, body);
        let key = SubstateKey {
            owner: Address::new([owner; 31], AddressClass::Component),
            local,
        };
        commit(&SettledWrites::from_absolutes(BTreeMap::from([(
            key,
            Some(value),
        )])));
        (key, expiry)
    })
    .collect();
    // And one ordinary cell, which the index must not see.
    commit(&make_settled_writes(0x10, 7, vec![9, 9, 9]));

    // Sweep order is bucket, then owner, then local — so the late
    // bucket goes last even though its owner sorts first, which is the
    // property a walk over leaf keys would not have.
    let (low_owner, high_owner, late) = (cells[1], cells[0], cells[2]);
    let expected = vec![low_owner, high_owner, late];

    let all = SweepBucket(u32::MAX);
    assert_eq!(
        storage.sweep_candidates(SweepFrontier::ZERO, all, 10),
        expected,
        "bucket orders before owner, and the plain cell is not swept"
    );

    // The ceiling excludes the clock's own bucket and everything above.
    let clock = WeightedTimestamp::from_millis(4 * bucket_ms);
    assert_eq!(
        storage.sweep_candidates(
            SweepFrontier::ZERO,
            SweepFrontier::ceiling_at(clock).bucket(),
            10
        ),
        vec![low_owner, high_owner],
    );

    // The cap stops the walk, and resuming from where it stopped picks
    // up exactly the rest — no gap, no repeat.
    let first = storage.sweep_candidates(SweepFrontier::ZERO, all, 2);
    assert_eq!(first, vec![low_owner, high_owner]);
    let resumed = SweepFrontier::of_leaf(first[1].0);
    assert_eq!(storage.sweep_candidates(resumed, all, 10), vec![late]);

    // Removing a cell takes it out of the index, and the row it emptied
    // with it — the walk then stops one short.
    commit(&SettledWrites::from_absolutes(BTreeMap::from([(
        late.0, None,
    )])));
    assert_eq!(
        storage.sweep_candidates(SweepFrontier::ZERO, all, 10),
        vec![low_owner, high_owner]
    );
}

/// Shared sweep conformance: a block prepared while its parent is still
/// unpersisted counts into the same row as its parent.
///
/// Two blocks moving one `(bucket, owner)` row is the ordinary case —
/// one signer's nullifiers, one venue's claims, the committed cells of
/// one window — and the parent of a block being prepared holds no commit
/// QC yet, so it is unpersisted exactly when this happens. A backend
/// folding the row from what it has persisted counts the second move
/// alone; the row then drains while its leaves remain, and the walk
/// stops finding them.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_sweep_index_counts_a_pending_ancestors_move<S>(storage: &S)
where
    S: TestStore + SweepIndex,
{
    install_stub_protocol_statics();
    let handle = Arc::new(storage.clone());
    let owner = Address::new([0x40; 31], AddressClass::Component);
    let expiry = 3 * SWEEP_BUCKET_MS;
    let cell = |body: u8| {
        let (local, value) = stub_sweepable_cell(expiry, body);
        (SubstateKey { owner, local }, value)
    };
    let (first, first_value) = cell(0x11);
    let (second, second_value) = cell(0x22);

    let one = BlockHeight::new(1);
    let writes = SettledWrites::from_absolutes(BTreeMap::from([(first, Some(first_value))]));
    let block_one = push_certificate(make_test_block(one), settling(one, writes.into()));
    let (root_one, snapshot_one, commit_one) = handle.prepare_block_commit(
        ParentAnchor {
            state_root: handle.state_root(),
            height: handle.jmt_height(),
            state: &handle.snapshot(),
            pending: &[],
            base_reads: None,
        },
        &block_one.certificates()[..],
        ChainWrites {
            creations: &[],
            removals: &[],
            sweep_frontier: SweepFrontier::ZERO,
            frontier: &FrontierInputs::still(ShardId::ROOT),
            state_claims: &[],
            members: &MemberInputs::still(ShardId::ROOT),
        },
        one,
    );

    // Prepared over height 1 before height 1 has been applied, which is
    // what makes the row's prior unreadable from the store.
    let two = BlockHeight::new(2);
    let writes = SettledWrites::from_absolutes(BTreeMap::from([(second, Some(second_value))]));
    let block_two = push_certificate(make_test_block(two), settling(two, writes.into()));
    let pending = from_ref(&snapshot_one);
    let (_, _, commit_two) = handle.prepare_block_commit(
        ParentAnchor {
            state_root: root_one,
            height: one,
            state: &PendingBaseline::new(handle.snapshot(), pending, one),
            pending,
            base_reads: None,
        },
        &block_two.certificates()[..],
        ChainWrites {
            creations: &[],
            removals: &[],
            sweep_frontier: SweepFrontier::ZERO,
            frontier: &FrontierInputs::still(ShardId::ROOT),
            state_claims: &[],
            members: &MemberInputs::still(ShardId::ROOT),
        },
        two,
    );

    let witness = empty_witness();
    commit_one(
        SyncHint::FlushNow,
        &make_test_certified(block_one),
        &witness,
    );
    commit_two(
        SyncHint::FlushNow,
        &make_test_certified(block_two),
        &witness,
    );

    let all = SweepBucket(u32::MAX);
    let mut both = vec![(first, expiry), (second, expiry)];
    both.sort_by_key(|(key, _)| *key);
    assert_eq!(
        storage.sweep_candidates(SweepFrontier::ZERO, all, 10),
        both,
        "both cells sit in the row the two blocks moved"
    );

    // Removing one leaves the other reachable. A row that counted one
    // move would be emptied here and take the survivor's leaf with it.
    commit_writes(
        storage,
        &SettledWrites::from_absolutes(BTreeMap::from([(first, None)])),
    );
    assert_eq!(
        storage.sweep_candidates(SweepFrontier::ZERO, all, 10),
        vec![(second, expiry)],
        "the row outlived the removal, so its surviving leaf is still swept"
    );
}

/// Shared block-sweep conformance: where a block's frontier lands, and
/// that resuming from it loses nothing.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_sweep_stops_at_the_ceiling_or_the_cap<S>(storage: &S)
where
    S: TestStore + SweepIndex,
{
    install_stub_protocol_statics();
    let commit = |writes: &SettledWrites| {
        commit_writes(storage, writes);
    };
    // Two cells a bucket apart, both long past a clock well above them.
    let cells: Vec<(SubstateKey, u64)> = [(3u64, 0x11u8), (5, 0x22)]
        .into_iter()
        .map(|(bucket, body)| {
            let expiry = bucket * SWEEP_BUCKET_MS;
            let (local, value) = stub_sweepable_cell(expiry, body);
            let key = SubstateKey {
                owner: Address::new([0x40; 31], AddressClass::Component),
                local,
            };
            commit(&SettledWrites::from_absolutes(BTreeMap::from([(
                key,
                Some(value),
            )])));
            (key, expiry)
        })
        .collect();
    let clock = WeightedTimestamp::from_millis(20 * SWEEP_BUCKET_MS);

    // Under the cap, the frontier takes the ceiling: nothing sweepable
    // is left below the clock's own bucket, so the next block starts
    // from there rather than from the last cell.
    let (removals, frontier) =
        sweep_for_block(storage, BlockSweep::From(SweepFrontier::ZERO), clock);
    assert_eq!(removals, vec![cells[0].0, cells[1].0]);
    assert_eq!(frontier, SweepFrontier::ceiling_at(clock));
    // The interval between the two frontiers names the same cells, which
    // is how a replica committing the block on its certificate comes by
    // them.
    assert_eq!(
        sweep_through(storage, SweepFrontier::ZERO, frontier),
        removals
    );

    // A block whose ceiling has not moved past its parent's frontier
    // removes nothing and repeats the frontier it inherited. That is
    // every block at sub-second times against a minute-wide bucket, so
    // the frontier's rule is monotone rather than strictly advancing.
    let (again, stood_still) = sweep_for_block(storage, BlockSweep::From(frontier), clock);
    assert!(again.is_empty());
    assert_eq!(stood_still, frontier);

    // A clock inside the first cell's own bucket reaches neither, since
    // the ceiling excludes that bucket entirely.
    let early = WeightedTimestamp::from_millis(3 * SWEEP_BUCKET_MS + 1);
    let (none, early_frontier) =
        sweep_for_block(storage, BlockSweep::From(SweepFrontier::ZERO), early);
    assert!(none.is_empty());
    assert_eq!(early_frontier, SweepFrontier::ceiling_at(early));

    // And resuming from that frontier still reaches both, so a block
    // that swept nothing has not skipped anything.
    let (resumed, _) = sweep_for_block(storage, BlockSweep::From(early_frontier), clock);
    assert_eq!(resumed, vec![cells[0].0, cells[1].0]);

    // A coasting block holds: with both cells past their expiry it removes
    // neither and keeps the frontier it inherited, so the root it carries
    // is its parent's.
    let (held, held_frontier) = sweep_for_block(storage, BlockSweep::Held(early_frontier), clock);
    assert!(held.is_empty());
    assert_eq!(held_frontier, early_frontier);
    // And the interval its header names beside its parent's is empty, so
    // it commits on its certificate as it was built.
    assert!(sweep_through(storage, early_frontier, held_frontier).is_empty());
}

/// A sweep index that counts the candidates it hands back: what a caller
/// reading through it was made to hold.
pub(crate) struct CountedSweep<'a, S: ?Sized> {
    store: &'a S,
    read: Cell<usize>,
}

impl<'a, S: ?Sized> CountedSweep<'a, S> {
    /// A count of nothing over `store`.
    pub const fn over(store: &'a S) -> Self {
        Self {
            store,
            read: Cell::new(0),
        }
    }

    /// The candidates handed back so far.
    pub const fn read(&self) -> usize {
        self.read.get()
    }
}

impl<S: SweepIndex + ?Sized> SweepIndex for CountedSweep<'_, S> {
    fn sweep_candidates(
        &self,
        after: SweepFrontier,
        below: SweepBucket,
        limit: usize,
    ) -> Vec<(SubstateKey, u64)> {
        let found = self.store.sweep_candidates(after, below, limit);
        self.read.set(self.read.get() + found.len());
        found
    }
}

/// Walk the block anchored at `clock` over `store` from `parent`, read
/// the interval its two frontiers name back, and return what the block
/// removed and the frontier it landed on.
///
/// # Panics
///
/// Panics if the interval names other cells than the walk removed, or
/// reading it back was handed a candidate the block did not remove.
pub(crate) fn replayed_sweep_reads_what_the_block_removed(
    store: &(impl SweepIndex + ?Sized),
    parent: SweepFrontier,
    clock: WeightedTimestamp,
) -> (Vec<SubstateKey>, SweepFrontier) {
    let (removed, frontier) = sweep_for_block(store, BlockSweep::From(parent), clock);
    let replay = CountedSweep::over(store);
    assert_eq!(sweep_through(&replay, parent, frontier), removed);
    assert_eq!(
        replay.read(),
        removed.len(),
        "reading a block's interval back holds the cells it removed and no others",
    );
    (removed, frontier)
}

/// Shared replay conformance: the interval a certified block's header
/// names is read back at the cost of the block's own walk, whichever of
/// its two stops the walk made.
///
/// Three blocks over one store, none of whose removals are applied, so
/// each later block also reads past cells standing at or below its
/// parent's frontier. The first crosses a bucket boundary with a full
/// bucket standing in the clock's own, which its walk never opens. The
/// second is stopped by the cap partway through that bucket. The third
/// takes the remainder and lands on its ceiling, with cells standing in
/// the bucket above.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_replayed_sweep_reads_what_its_block_removed<S>(storage: &S)
where
    S: TestStore + SweepIndex,
{
    const PER_OWNER: u8 = 162;
    install_stub_protocol_statics();
    let cell = |owner: u8, bucket: u64, body: u8| {
        let (local, value) = stub_sweepable_cell(bucket * SWEEP_BUCKET_MS, body);
        let key = SubstateKey {
            owner: Address::new([owner; 31], AddressClass::Component),
            local,
        };
        (key, Some(value))
    };
    let early: BTreeMap<_, _> = (0..3).map(|body| cell(7, 1, body)).collect();
    let late: BTreeMap<_, _> = (0..3).map(|body| cell(7, 3, body)).collect();
    commit_writes(storage, &SettledWrites::from_absolutes(early));
    commit_writes(storage, &SettledWrites::from_absolutes(late));
    for owner in 0..=u8::MAX {
        let pile = (0..PER_OWNER).map(|body| cell(owner, 2, body)).collect();
        commit_writes(storage, &SettledWrites::from_absolutes(pile));
    }
    let pile = (usize::from(u8::MAX) + 1) * usize::from(PER_OWNER);
    assert!(pile > MAX_SWEEP_PER_BLOCK && pile < 2 * MAX_SWEEP_PER_BLOCK);

    let in_bucket = |bucket: u64| WeightedTimestamp::from_millis(bucket * SWEEP_BUCKET_MS + 5);
    let (crossed, boundary) =
        replayed_sweep_reads_what_the_block_removed(storage, SweepFrontier::ZERO, in_bucket(2));
    assert_eq!(crossed.len(), 3);
    assert_eq!(boundary, SweepFrontier::start_of(SweepBucket(2)));

    let (capped, partway) =
        replayed_sweep_reads_what_the_block_removed(storage, boundary, in_bucket(3));
    assert_eq!(capped.len(), MAX_SWEEP_PER_BLOCK);
    assert_eq!(partway.bucket(), SweepBucket(2));
    assert!(partway > boundary);

    let (rest, ceiling) =
        replayed_sweep_reads_what_the_block_removed(storage, partway, in_bucket(3));
    assert_eq!(rest.len(), pile - MAX_SWEEP_PER_BLOCK);
    assert_eq!(ceiling, SweepFrontier::start_of(SweepBucket(3)));
}

/// Shared emptiness gate: which of a store's two vintages the import
/// path reads, and which it does not.
///
/// `replicated` takes the engine bootstrap a joiner replicates before its
/// span imports — substates without a trie — and must still import.
/// `born` takes a genesis build, which fills the trie at `GENESIS` while
/// leaving the chain with nothing to resume, and must be refused. That
/// pair is the reason the gate reads [`holds_state`](crate::holds_state)
/// over the trie rather than a committed height: the second store answers
/// `GENESIS` to the chain and holds a root all the same, which is the
/// vintage a reshape seat boots on.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_import_gate_reads_the_trie<S>(replicated: &S, born: &S)
where
    S: BoundaryStore + SubstateStore + ShardChainReader + GenesisCommit,
{
    let writes = make_settled_writes(3, 3, vec![3, 3, 3]);

    replicated.replicate_genesis_substates(&writes);
    assert!(
        !holds_state(replicated.jmt_height(), replicated.state_root()),
        "replicated substates are not authenticated state"
    );
    import_boundary_state(
        replicated,
        BlockHeight::new(6),
        &[SubstateLeaf {
            key: state_key(3, 3),
            value: Bytes::from_array([3, 3, 3]),
        }],
        WitnessSeed::default(),
    )
    .expect("a replicated bootstrap still imports");

    let root = born.install_genesis(&writes, &writes);
    assert_ne!(root, StateRoot::ZERO);
    assert_eq!(born.jmt_height(), BlockHeight::GENESIS);
    assert_eq!(born.committed_height(), BlockHeight::GENESIS);
    assert!(
        holds_state(born.jmt_height(), born.state_root()),
        "a root at GENESIS is state an import would overwrite"
    );
    assert!(
        import_boundary_state(born, BlockHeight::new(6), &[], WitnessSeed::default()).is_err(),
        "the gate must not read the committed height"
    );
}

/// The crossing `producer` issues to `consumer`, both owners seeded as
/// [`state_key`] seeds them: a seed under `0x80` sits in the left half.
const fn fixture_crossing(producer: u8, consumer: u8) -> CrossingId {
    CrossingId {
        producer: state_key(producer, 0).owner,
        consumer: state_key(consumer, 0).owner,
        intent: IntentHash(Hash32([producer; 32])),
        local: 0,
        output: 0,
    }
}

/// A record leaf of the crossing `producer` issues, at its derived key.
///
/// # Panics
///
/// Never: a crossing cell is narrower than a leaf's cap.
#[must_use]
pub fn crossing_record_leaf(producer: u8) -> SubstateLeaf {
    let id = fixture_crossing(producer, producer ^ 0x80);
    SubstateLeaf {
        key: id.record_key(&ProtocolHasher),
        value: Bytes::new(
            id.cell(
                VmTxHash(Hash32([0xC0; 32])),
                ResourceAddr::new([0xE0; 31]),
                500,
                1_000,
                Terms::Owed,
            )
            .to_bytes(),
        )
        .expect("a crossing cell fits a leaf"),
    }
}

/// The crossing index equals the leaves.
///
/// After a commit that writes a record and an answer, one that deletes
/// each, and an import of the store's leaves into `fresh`, the rows
/// under each half are exactly the keys among those written that
/// `CrossingLeaf::read` classifies.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_crossing_index_equals_the_leaves<S>(storage: &S, fresh: &S)
where
    S: BoundaryStore + TestStore,
{
    install_stub_protocol_statics();
    let mut written: BTreeSet<SubstateKey> = BTreeSet::new();
    let halves = [
        shard_prefix_path(ShardId::leaf(1, 0)),
        shard_prefix_path(ShardId::leaf(1, 1)),
    ];
    let holds = |store: &S, written: &BTreeSet<SubstateKey>| {
        for half in &halves {
            let leaves: Vec<SubstateKey> = written
                .iter()
                .filter(|key| key_under_prefix(&key.to_bytes(), half))
                .filter(|key| {
                    store.cell(**key).is_some_and(|value| {
                        CrossingLeaf::read(&ProtocolHasher, **key, &value).is_some()
                    })
                })
                .copied()
                .collect();
            assert_eq!(store.crossing_rows(half), leaves, "rows under {half:?}");
        }
    };
    let commit = |written: &mut BTreeSet<SubstateKey>,
                  cells: Vec<(SubstateKey, Option<Vec<u8>>)>| {
        written.extend(cells.iter().map(|(key, _)| *key));
        commit_writes(
            storage,
            &SettledWrites::from_absolutes(cells.into_iter().collect()),
        );
    };

    holds(storage, &BTreeSet::new());
    let ordinary = state_key(1, 1);
    let (left, right) = (crossing_record_leaf(2), crossing_record_leaf(0x82));
    let answered = fixture_crossing(0x84, 3);
    let answer = answered.answer_key(&ProtocolHasher, Answered::Taken);
    let answer_value = answered
        .answer(VmTxHash(Hash32([0xC1; 32])), Answered::Taken, 1_000)
        .to_bytes();
    commit(
        &mut written,
        vec![
            (ordinary, Some(vec![9, 9, 9])),
            (left.key, Some(left.value.to_vec())),
            (right.key, Some(right.value.to_vec())),
            (answer, Some(answer_value)),
        ],
    );
    holds(storage, &written);
    assert_eq!(
        storage.crossing_rows(&NibblePath::empty()).len(),
        3,
        "a record under each half and an answer, and no ordinary cell",
    );

    commit(&mut written, vec![(left.key, None), (answer, None)]);
    holds(storage, &written);
    assert_eq!(
        storage.crossing_rows(&NibblePath::empty()),
        vec![right.key],
        "a record and an answer removed leave their rows",
    );

    commit(&mut written, vec![(left.key, Some(left.value.to_vec()))]);
    storage.pin_boundary(BlockHeight::new(3)).unwrap();
    let boundary = storage.open_boundary(BlockHeight::new(3)).expect("pinned");
    let root_key = boundary.get_root_key(3).expect("root resolves");
    let chunk = Jmt::collect_range(
        &boundary,
        &root_key,
        &[0u8; KEY_BYTES],
        &[0xFF; KEY_BYTES],
        1_000,
    )
    .unwrap();
    let leaves: Vec<SubstateLeaf> = chunk
        .leaves
        .iter()
        .map(|(leaf_key, _)| {
            let key =
                SubstateKey::from_bytes(*leaf_key).expect("a stored leaf key names an address");
            SubstateLeaf {
                key,
                value: Bytes::new(boundary.cell(key).expect("resolves"))
                    .expect("a list written out in a test"),
            }
        })
        .collect();
    import_boundary_state(fresh, BlockHeight::new(3), &leaves, WitnessSeed::default()).unwrap();
    holds(fresh, &written);
    assert_eq!(
        fresh.crossing_rows(&NibblePath::empty()),
        storage.crossing_rows(&NibblePath::empty()),
        "an imported store indexes what the committing one does",
    );
}

/// The crossing journal names every row a commit moves.
///
/// A reader with no cursor, or one from another store, reads the rows
/// whole. A cursor reads the rows put or removed above it, up to the
/// height it reads at and under the prefix it reads, each once, and no
/// ordinary cell. An import starts the importing store's line over.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_crossing_changes_name_every_moved_row<S>(storage: &S, fresh: &S)
where
    S: BoundaryStore + TestStore,
{
    install_stub_protocol_statics();
    let all = NibblePath::empty();
    let (whole, start) = storage.crossing_changes(&all, None, storage.jmt_height());
    assert_eq!(whole, None, "no cursor reads the rows whole");

    let ordinary = state_key(1, 1);
    let (left, right) = (crossing_record_leaf(2), crossing_record_leaf(0x82));
    let answered = fixture_crossing(0x84, 3);
    let answer = answered.answer_key(&ProtocolHasher, Answered::Taken);
    let answer_value = answered
        .answer(VmTxHash(Hash32([0xC1; 32])), Answered::Taken, 1_000)
        .to_bytes();
    commit_writes(
        storage,
        &SettledWrites::from_absolutes(
            [
                (ordinary, Some(vec![9, 9, 9])),
                (left.key, Some(left.value.to_vec())),
                (right.key, Some(right.value.to_vec())),
                (answer, Some(answer_value)),
            ]
            .into_iter()
            .collect(),
        ),
    );
    let written = storage.jmt_height();
    let (before, held) = storage.crossing_changes(
        &all,
        Some(start),
        written.prev().expect("a commit stands above genesis"),
    );
    assert_eq!(
        before,
        Some(Vec::new()),
        "a write above the height read at is not named"
    );
    let mut moved = vec![left.key, right.key, answer];
    moved.sort_unstable();
    let (changed, cursor) = storage.crossing_changes(&all, Some(held), written);
    assert_eq!(
        changed,
        Some(moved),
        "every row the commit put, and no ordinary cell"
    );
    assert_eq!(
        storage.crossing_changes(&all, Some(cursor), written).0,
        Some(Vec::new()),
        "and nothing twice",
    );

    commit_writes(
        storage,
        &SettledWrites::from_absolutes([(left.key, None), (answer, None)].into_iter().collect()),
    );
    let removed = storage.jmt_height();
    let half = shard_prefix_path(ShardId::leaf(1, 0));
    let mut under: Vec<SubstateKey> = [left.key, answer]
        .into_iter()
        .filter(|key| key_under_prefix(&key.to_bytes(), &half))
        .collect();
    under.sort_unstable();
    assert_eq!(
        storage.crossing_changes(&half, Some(cursor), removed).0,
        Some(under),
        "the rows removed under the prefix read",
    );

    let (_, imported) = fresh.crossing_changes(&all, None, fresh.jmt_height());
    let leaves = boundary_leaves(storage, removed);
    import_boundary_state(fresh, removed, &leaves, WitnessSeed::default()).unwrap();
    assert_eq!(
        fresh.crossing_changes(&all, Some(imported), removed).0,
        None,
        "an import starts the line over",
    );
    assert_eq!(
        fresh.crossing_changes(&all, Some(cursor), removed).0,
        None,
        "and another store's cursor reads whole",
    );
}

/// Every leaf `serving` holds at `height`, pinned there, as a snap-sync
/// import receives them.
fn boundary_leaves<S: BoundaryStore>(serving: &S, height: BlockHeight) -> Vec<SubstateLeaf> {
    serving.pin_boundary(height).unwrap();
    let boundary = serving.open_boundary(height).expect("pinned");
    let root_key = boundary
        .get_root_key(height.inner())
        .expect("root resolves");
    let chunk = Jmt::collect_range(
        &boundary,
        &root_key,
        &[0u8; KEY_BYTES],
        &[0xFF; KEY_BYTES],
        1_000,
    )
    .unwrap();
    chunk
        .leaves
        .iter()
        .map(|(leaf_key, _)| {
            let key =
                SubstateKey::from_bytes(*leaf_key).expect("a stored leaf key names an address");
            let value = boundary.cell(key).expect("resolves");
            SubstateLeaf {
                key,
                value: Bytes::new(value).expect("a list written out in a test"),
            }
        })
        .collect()
}

/// Shared serve → import round trip: leaves enumerated and resolved
/// from `serving`'s pinned boundary rebuild an identical store in
/// `fresh`, with the raw substates readable and a second import
/// rejected.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_boundary_import_roundtrip<S>(serving: &S, fresh: &S)
where
    S: BoundaryStore + TestStore,
{
    for seed in 1..=5u8 {
        commit_one(serving, seed);
    }
    // The sixth commit is two ordered-collection entries, so the round
    // trip covers entry leaves and the index rebuild beside the cells.
    commit_writes(
        serving,
        &make_settled_entries(7, &[(5, Some(vec![5])), (10, Some(vec![10]))]),
    );
    let source_root = serving.state_root();
    let leaves = boundary_leaves(serving, BlockHeight::new(6));
    assert_eq!(leaves.len(), 7);
    let probe = leaves
        .iter()
        .find(|l| l.value == [3, 3, 3])
        .map(|l| l.key)
        .expect("seed-3 leaf present");

    let imported_root =
        import_boundary_state(fresh, BlockHeight::new(6), &leaves, WitnessSeed::default()).unwrap();
    assert_eq!(imported_root, source_root);
    assert_eq!(fresh.state_root(), source_root);

    // Imported raw substates read back at the imported state.
    fresh.pin_boundary(BlockHeight::new(6)).unwrap();
    let fresh_boundary = fresh.open_boundary(BlockHeight::new(6)).expect("pinned");
    assert_eq!(fresh_boundary.cell(probe), Some(vec![3, 3, 3]),);

    // The ordered index re-derived from the imported leaves answers the
    // same interval the serving store does.
    let entry = entry_key(7, 5);
    assert_eq!(
        fresh.entries_in_range(entry.owner, entry.collection, 0, u128::MAX, 10),
        serving.entries_in_range(entry.owner, entry.collection, 0, u128::MAX, 10),
    );
    assert_eq!(
        fresh.entries_in_range(entry.owner, entry.collection, 0, u128::MAX, 10),
        vec![(5, vec![5]), (10, vec![10])],
    );

    // A second import is rejected — the store is no longer empty.
    assert!(
        import_boundary_state(fresh, BlockHeight::new(6), &[], WitnessSeed::default()).is_err()
    );
}

/// A complete EC over `tx_hashes`, every transaction succeeding — the
/// producing shard's copy, and the only one [`ExecutionCertificate::project_to`]
/// can narrow.
fn execution_certificate_over(
    block_height: BlockHeight,
    tx_hashes: &[TxHash],
) -> ExecutionCertificate {
    let outcomes: Vec<TxOutcome> = tx_hashes
        .iter()
        .enumerate()
        .map(|(position, tx_hash)| {
            let seed = u8::try_from(position).expect("small fixture") + 150;
            TxOutcome::new(
                *tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed; 32])),
                },
            )
        })
        .collect();
    ExecutionCertificate::new(
        TickId::new(ShardId::ROOT, block_height),
        WeightedTimestamp::from_millis(block_height.inner() + 1),
        compute_global_receipt_root(&outcomes),
        Capped::new(outcomes).expect("a list written out in a test"),
        AggregateSignature::new([0u8; 96]),
        SignerBitfield::new(4),
    )
}

/// Shared coverage test for a tick's copies: every finalization of the
/// tick that carries a transaction answers for it, and no served
/// certificate covers none of the asked transactions.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_every_copy_of_a_tick_answers_for_what_it_carries(
    storage: &(impl ShardChainReader + TestStore),
) {
    let txs: Vec<TxHash> = (1u8..=3)
        .map(|seed| TxHash::from(Hash::from_bytes(&[seed; 32])))
        .collect();
    let complete = execution_certificate_over(BlockHeight::new(1), &txs);
    let leg = |tx: TxHash| {
        complete
            .project_to(&HashSet::from([tx]))
            .expect("the copy carries it")
    };

    // One leg arrives, and answers for the transaction it carries.
    commit_empty_blocks_below(storage, BlockHeight::new(1));
    let first = make_test_block_with_ecs(BlockHeight::new(1), vec![Arc::new(leg(txs[0]))]);
    commit_settled_at(
        storage,
        &make_test_certified(first),
        &[],
        &[],
        &empty_witness(),
    );
    let served = storage.get_execution_certificates_for_txs(&[txs[0]]);
    assert_eq!(served.len(), 1, "the transaction its copy carries");
    assert!(served[0].covers(&txs[0]));

    // A disjoint leg is a second answer, not a narrower one: the two
    // halves of one tick each carry what the other does not, and nobody
    // else holds a shard's own tick. Each answers for its own
    // transaction and neither for the other's.
    let second = make_test_block_with_ecs(BlockHeight::new(2), vec![Arc::new(leg(txs[1]))]);
    commit_settled_at(
        storage,
        &make_test_certified(second),
        &[],
        &[],
        &empty_witness(),
    );
    for tx in &txs[..2] {
        let served = storage.get_execution_certificates_for_txs(from_ref(tx));
        assert_eq!(served.len(), 1, "one copy carries it");
        assert!(served[0].covers(tx), "and that copy answers for it");
    }

    // The same finalization committed again is the same finalization,
    // and adds nothing.
    let repeat = make_test_block_with_ecs(BlockHeight::new(3), vec![Arc::new(leg(txs[0]))]);
    commit_settled_at(
        storage,
        &make_test_certified(repeat),
        &[],
        &[],
        &empty_witness(),
    );
    assert_eq!(
        storage.get_execution_certificates_for_txs(&[txs[0]]).len(),
        1
    );

    // A finalization carrying the whole tick answers for every
    // transaction of it, beside the halves that still answer for theirs;
    // nothing served covers none of what was asked.
    let fourth = make_test_block_with_ecs(BlockHeight::new(4), vec![Arc::new(complete.clone())]);
    commit_settled_at(
        storage,
        &make_test_certified(fourth),
        &[],
        &[],
        &empty_witness(),
    );
    let served = storage.get_execution_certificates_for_txs(&txs);
    for tx in &txs {
        assert!(
            served.iter().any(|cert| cert.covers(tx)),
            "every transaction of the tick is answered",
        );
    }
    assert!(
        served
            .iter()
            .all(|cert| txs.iter().any(|tx| cert.covers(tx))),
        "and nothing served covers none of the asked transactions",
    );
    let only_whole = storage.get_execution_certificates_for_txs(from_ref(&txs[2]));
    assert_eq!(
        only_whole.len(),
        1,
        "a transaction only the whole tick carries"
    );
    assert!(
        only_whole[0].is_complete(),
        "is answered by the complete copy",
    );
    assert!(
        storage
            .get_execution_certificates_for_txs(from_ref(&txs[1]))
            .iter()
            .all(|cert| cert.covers(&txs[1])),
        "and the half that never carried it does not answer for it",
    );
}

/// Shared index test: the by-transaction certificate lookup answers with
/// this shard's own certificate.
///
/// A settled cross-shard transaction lands under both sides' certificates
/// in one finalization, and the lookup serves the question a
/// counterpart's fallback fetch asks this shard. The remote copy sorts
/// after the local one in the write walk, so an unfiltered single-slot
/// index would leave it the winner and serve the requester its own
/// certificate back.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_tx_index_answers_with_the_local_shards_certificate(
    storage: &(impl ShardChainReader + TestStore),
) {
    let tx = TxHash::from(Hash::from_bytes(&[7u8; 32]));
    let local = execution_certificate_over(BlockHeight::new(1), from_ref(&tx));
    let remote_outcomes = vec![TxOutcome::new(
        tx,
        ExecutionOutcome::Succeeded {
            receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[99u8; 32])),
        },
    )];
    let remote = ExecutionCertificate::new(
        TickId::new(ShardId::leaf(1, 1), BlockHeight::new(4)),
        WeightedTimestamp::from_millis(5),
        compute_global_receipt_root(&remote_outcomes),
        Capped::new(remote_outcomes).expect("a list written out in a test"),
        AggregateSignature::new([0u8; 96]),
        SignerBitfield::new(4),
    );

    commit_empty_blocks_below(storage, BlockHeight::new(1));
    let certificate = Finalization::new(
        *local.tick_id(),
        TickHalf::Legs,
        &Capped::from_array([Arc::new(local.clone()), Arc::new(remote)]),
        Capped::from_array([]),
    );
    let block = push_certificate(
        make_test_block(BlockHeight::new(1)),
        Arc::new(certificate.into()),
    );
    commit_settled_at(
        storage,
        &make_test_certified(block),
        &[],
        &[],
        &empty_witness(),
    );

    let served = storage.get_execution_certificates_for_txs(from_ref(&tx));
    assert_eq!(served.len(), 1, "one certificate answers for the tx");
    assert_eq!(
        served[0].tick_id(),
        local.tick_id(),
        "and it is this shard's own, not the counterpart copy riding beside it",
    );
}

/// Shared test: the transaction index answers with every certificate of
/// this shard's naming the transaction, not the newest.
///
/// A shard can certify one transaction in the tick that ran it and again
/// in an abandonment that settles what the run left. A counterpart asks
/// by naming the transaction and cannot say which it wants, so a single
/// slot would hand it whichever committed last, and asking again would
/// get the same answer for as long as it asks.
///
/// Both certificates land in one block here, which is the case a
/// per-certificate write would also lose: it would read the stored set
/// before either landed and drop the first.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_the_tx_index_answers_with_every_certificate_of_this_shards(
    storage: &(impl ShardChainReader + TestStore),
) {
    let tx = TxHash::from(Hash::from_bytes(&[8u8; 32]));
    let verdict = execution_certificate_over(BlockHeight::new(1), from_ref(&tx));
    let settling = execution_certificate_over(BlockHeight::new(2), from_ref(&tx));

    commit_empty_blocks_below(storage, BlockHeight::new(1));
    let block = push_certificate(
        push_certificate(
            make_test_block(BlockHeight::new(1)),
            Arc::new(
                Finalization::new(
                    *verdict.tick_id(),
                    TickHalf::Legs,
                    &Capped::from_array([Arc::new(verdict.clone())]),
                    Capped::from_array([]),
                )
                .into(),
            ),
        ),
        Arc::new(
            Finalization::new(
                *settling.tick_id(),
                TickHalf::Determined,
                &Capped::from_array([Arc::new(settling.clone())]),
                Capped::from_array([]),
            )
            .into(),
        ),
    );
    commit_settled_at(
        storage,
        &make_test_certified(block),
        &[],
        &[],
        &empty_witness(),
    );

    let served: BTreeSet<TickId> = storage
        .get_execution_certificates_for_txs(from_ref(&tx))
        .iter()
        .map(|cert| *cert.tick_id())
        .collect();
    assert_eq!(
        served,
        BTreeSet::from([*verdict.tick_id(), *settling.tick_id()]),
        "both of this shard's certificates for the transaction answer for it",
    );
}

/// Attach a provisions bundle for `tx_hash` to a live block, preserving
/// everything else.
#[must_use]
pub fn with_provisions(block: Block, source: ShardId, tx_hash: TxHash) -> Block {
    let bundle = Provisions::new(
        source,
        ShardId::ROOT,
        BlockHeight::new(1),
        WeightedTimestamp::ZERO,
        MerkleInclusionProof::dummy(),
        Capped::from_array([ProvisionEntry::new(tx_hash, Capped::empty())]),
    );
    match block {
        Block::Live {
            header,
            transactions,
            certificates,
            abandonment_records,
            state_claims,
            witness_sources,
            ..
        } => Block::Live {
            header,
            transactions,
            certificates,
            provisions: Arc::new(Capped::from_array([Arc::new(Verifiable::from(bundle))])),
            abandonment_records,
            state_claims,
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources,
        },
        sealed @ Block::Sealed { .. } => sealed,
    }
}

/// Attach `txs` to a live block, preserving everything else.
fn with_transactions(block: Block, txs: Vec<Arc<Verifiable<Transaction>>>) -> Block {
    match block {
        Block::Live {
            header,
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            witness_sources,
            ..
        } => Block::Live {
            header,
            transactions: Arc::new(Capped::new(txs).expect("a list written out in a test")),
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources,
        },
        sealed @ Block::Sealed { .. } => sealed,
    }
}

/// Attach `claims` to a live block, preserving everything else.
///
/// # Panics
///
/// If `claims` is past the cap a block carries.
#[must_use]
pub fn with_state_claims(block: Block, claims: Vec<StateClaim>) -> Block {
    match block {
        Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            abandonment_records,
            witness_sources,
            ..
        } => Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            abandonment_records,
            state_claims: Arc::new(Capped::new(claims).expect("a list written out in a test")),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources,
        },
        sealed @ Block::Sealed { .. } => sealed,
    }
}

/// The grid the frontier fixtures read marks on: wide enough that every
/// anchor they name falls in epoch zero and no entry ages out.
const FRONTIER_WINDOW_MS: u64 = 1_000_000;

/// A block at `height` carrying one claim of `producer` at its height
/// `read_at`, reading absent the record of a crossing it names, which
/// is what makes the claim raise, and the frontier inputs the block's
/// shard reads off it.
fn block_reading(height: u64, producer: ShardId, read_at: u64) -> (Block, FrontierInputs) {
    let id = CrossingId {
        producer: test_key(0xD0).owner,
        consumer: test_key(0xD1).owner,
        intent: IntentHash(Hash32([0xD0; 32])),
        local: 0,
        output: 0,
    };
    let asked = id.record_key(&ProtocolHasher);
    let block = with_state_claims(
        make_test_block(BlockHeight::new(height)),
        vec![proven_claim(producer, read_at, &[], &[asked]).naming([(asked, id)])],
    );
    let inputs = FrontierInputs::of_block(&block, EpochWindows::new(FRONTIER_WINDOW_MS));
    (block, inputs)
}

/// The table one reading of `producer` at `read_at` leaves, on the
/// fixtures' grid.
fn frontier_of(producer: ShardId, read_at: u64) -> ReadFrontier {
    ReadFrontier::from_entries([(
        producer,
        ReadMark {
            epoch: Epoch::new(0),
            height: BlockHeight::new(read_at),
        },
    )])
}

/// Commit `block` at the store's tip through the one commit path, with
/// `frontier` as what its claims do to the read frontier and its own
/// certificates as what it settles. Returns the root the commit
/// prepared beside the one it flushed.
fn commit_raising<S: TestStore>(
    storage: &S,
    block: Block,
    frontier: &FrontierInputs,
) -> (StateRoot, StateRoot) {
    let (prepared, commit) = prepare_raising(storage, &block, frontier);
    let committed = commit(
        SyncHint::FlushNow,
        &make_test_certified(block),
        &empty_witness(),
    );
    (prepared, committed)
}

/// [`commit_raising`]'s preparation alone: the root it prepares and the
/// commit it would apply.
fn prepare_raising<S: TestStore>(
    storage: &S,
    block: &Block,
    frontier: &FrontierInputs,
) -> (StateRoot, PreparedCommit) {
    let storage = Arc::new(storage.clone());
    let claims: Vec<StateClaim> = block.state_claims().to_vec();
    let (prepared, _, commit) = storage.prepare_block_commit(
        ParentAnchor {
            state_root: storage.state_root(),
            height: storage.jmt_height(),
            state: &storage.snapshot(),
            pending: &[],
            base_reads: None,
        },
        &block.certificates()[..],
        ChainWrites {
            creations: &[],
            removals: &[],
            sweep_frontier: SweepFrontier::ZERO,
            frontier,
            state_claims: &claims,
            members: &MemberInputs::still(ShardId::ROOT),
        },
        block.height(),
    );
    (prepared, commit)
}

/// Shared: the read frontier is state, written by the one commit path.
///
/// A block carrying a claim raises its producer's entry under the root
/// it prepares and commits; the same reading again moves nothing; the
/// store answers for the table through `read_frontier`, and a store
/// resumed from the same state answers the same, so a restart seeds the
/// coordinator's copy from what the chain wrote. Both children read the
/// table too: the left one where it stands, the right one from its copy.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_the_read_frontier_is_read_off_the_state<S>(
    storage: &S,
    recovered: impl Fn(ShardId) -> RecoveredState,
) where
    S: BoundaryStore + TestStore,
{
    let local = ShardId::ROOT;
    let producer = ShardId::leaf(2, 3);
    let table = |shard: ShardId| {
        let held = storage.read_frontier(shard);
        assert_eq!(
            recovered(shard).read_frontier,
            held,
            "a resumed store holds the table a running one does",
        );
        held
    };
    assert!(table(local).is_empty(), "a fresh store has read nothing");

    let (block, inputs) = block_reading(1, producer, 7);
    let parent_root = storage.state_root();
    let (prepared, committed) = commit_raising(storage, block, &inputs);
    assert_ne!(prepared, parent_root, "a raise moves the root");
    assert_eq!(committed, prepared, "the commit lands the root it prepared");
    let expected = frontier_of(producer, 7);
    assert_eq!(table(local), expected, "the store answers for the raise");
    let (left, right) = local.children();
    assert_eq!(table(left), expected, "the left child inherits the table");
    assert_eq!(table(right), expected, "and the right child reads its copy");

    let (again, inputs) = block_reading(2, producer, 7);
    let (prepared, committed) = commit_raising(storage, again, &inputs);
    assert_eq!(
        prepared, committed,
        "a block raising nothing prepares its parent's root"
    );
    assert_eq!(committed, storage.state_root());
    assert_eq!(table(local), expected, "and leaves the table as it was");

    let (higher, inputs) = block_reading(3, producer, 9);
    let before = storage.state_root();
    let (_, committed) = commit_raising(storage, higher, &inputs);
    assert_ne!(committed, before, "a higher reading moves the root again");
    assert_eq!(table(local), frontier_of(producer, 9));
}

/// A crossing whose producer sits on the left half of the root's
/// keyspace and whose consumer sits on the right, so its record and its
/// answers land on different children of a root split.
const fn straddling_crossing(seed: u8) -> CrossingId {
    CrossingId {
        producer: Address::new([seed & 0x7F; 31], AddressClass::Component),
        consumer: Address::new([seed | 0x80; 31], AddressClass::Component),
        intent: IntentHash(Hash32([seed; 32])),
        local: 0,
        output: 0,
    }
}

/// Two crossings the settling fixtures read: one whose record stands
/// and whose consumer's `Taken` a claim reads present, and one whose
/// `Taken` stands and whose record a claim reads absent at a boundary,
/// with its producing member's row gone there.
struct Settling {
    retired: CrossingId,
    answered: CrossingId,
}

impl Settling {
    const fn new() -> Self {
        Self {
            retired: straddling_crossing(0x21),
            answered: straddling_crossing(0x22),
        }
    }

    /// The record of the crossing being retired.
    fn record(&self) -> SubstateKey {
        self.retired.record_key(&ProtocolHasher)
    }

    /// The `Taken` of the crossing whose record is gone.
    fn taken(&self) -> SubstateKey {
        self.answered.answer_key(&ProtocolHasher, Answered::Taken)
    }

    /// The two cells as state holds them before the settling block.
    fn standing(&self) -> BTreeMap<SubstateKey, Option<Vec<u8>>> {
        BTreeMap::from([
            (
                self.record(),
                Some(
                    self.retired
                        .cell(
                            VmTxHash(Hash32([0xC0; 32])),
                            ResourceAddr::new([0xE0; 31]),
                            500,
                            1_000,
                            Terms::Owed,
                        )
                        .to_bytes(),
                ),
            ),
            (
                self.taken(),
                Some(
                    self.answered
                        .answer(VmTxHash(Hash32([0xC1; 32])), Answered::Taken, 1_000)
                        .to_bytes(),
                ),
            ),
        ])
    }

    /// The anchor of the settling blocks: a retention horizon and more
    /// past the boundary the answered crossing's record is read at.
    const BLOCK_ANCHOR_MS: u64 = 500_000;

    /// A block at `height` carrying the claims that settle both, each
    /// naming its crossing: the retired crossing's `Taken` read present
    /// at an anchor fresh to the block, and the answered crossing's
    /// record read absent at a boundary of it, beside the row of the
    /// transaction that answered, read absent there past its validity
    /// end.
    fn block(&self, height: u64) -> (Block, FrontierInputs) {
        let counterpart = ShardId::leaf(2, 3);
        let taken = self.retired.answer_key(&ProtocolHasher, Answered::Taken);
        let record = self.answered.record_key(&ProtocolHasher);
        let took = self
            .retired
            .answer(VmTxHash(Hash32([0xC0; 32])), Answered::Taken, 1_000)
            .to_bytes();
        let at = |height: u64, ts_ms: u64| Anchor {
            shard: counterpart,
            height: BlockHeight::new(height),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::from_millis(ts_ms),
        };
        let boundary = StateClaim::new(
            at(7, 7_000),
            [
                (record, Inclusion::Absent),
                (
                    member_row_leaf(counterpart, VmTxHash(Hash32([0xC1; 32]))),
                    Inclusion::Absent,
                ),
            ],
            MerkleInclusionProof::dummy(),
        )
        .naming([(record, self.answered)]);
        let fresh = StateClaim::new(
            at(90, Self::BLOCK_ANCHOR_MS - 1_000),
            [(taken, Inclusion::Present(jmt_value_hash(&took)))],
            MerkleInclusionProof::dummy(),
        )
        .naming([(taken, self.retired)]);
        let anchor = WeightedTimestamp::from_millis(Self::BLOCK_ANCHOR_MS);
        assert!(boundary.at_boundary(anchor) && !fresh.at_boundary(anchor));
        let block = with_state_claims(
            make_test_block_with_anchor_wt(BlockHeight::new(height), Self::BLOCK_ANCHOR_MS),
            vec![boundary, fresh],
        );
        let inputs = FrontierInputs::of_block(&block, EpochWindows::new(FRONTIER_WINDOW_MS));
        (block, inputs)
    }
}

/// Shared: a block's claims settle crossings in its commit fold.
///
/// A record whose consumer's `Taken` a claim reads present is removed,
/// and an answer whose record a claim reads absent at a boundary, its
/// producing member exited, is removed, under the root the one commit
/// path prepares and commits; the same block again, with nothing left
/// to remove, prepares its parent's root.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_settling_claim_folds_its_removals<S: TestStore>(storage: &S) {
    let settling = Settling::new();
    commit_writes(storage, &SettledWrites::from_absolutes(settling.standing()));
    assert!(storage.cell(settling.record()).is_some());
    assert!(storage.cell(settling.taken()).is_some());

    let (block, inputs) = settling.block(2);
    let parent_root = storage.state_root();
    let (prepared, committed) = commit_raising(storage, block, &inputs);
    assert_ne!(prepared, parent_root, "a settlement moves the root");
    assert_eq!(committed, prepared);
    assert!(
        storage.cell(settling.record()).is_none(),
        "the Taken read present retires the record",
    );
    assert!(
        storage.cell(settling.taken()).is_none(),
        "and the record read absent at a boundary deletes the answer",
    );

    let (again, inputs) = settling.block(3);
    let before = storage.state_root();
    let (prepared, committed) = commit_raising(storage, again, &inputs);
    assert_eq!(
        prepared, before,
        "nothing left to remove prepares the parent's root"
    );
    assert_eq!(committed, before);
}

/// Shared: a split follower on each half folds the settlements of the
/// parent's block that land on its half, and the halves recompose the
/// parent's root.
///
/// The record sits on the left half and the answer on the right, so
/// one block settles crossings whose ends are in different children:
/// each follower removes the key it holds, reads the other absent and
/// writes nothing for it.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_followed_halves_fold_the_settlements<S>(parent: &S, left: &S, right: &S)
where
    S: BoundaryStore + TestStore,
{
    let settling = Settling::new();
    let mut writes = StateWrites::default();
    for (key, value) in settling.standing() {
        writes.cells.insert(key, value);
    }
    let receipt = StoredReceipt::new(
        TxHash::from(Hash::from_bytes(b"standing")),
        Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes,
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        }),
    );
    let standing = block_settling(BlockHeight::new(1), vec![receipt]);
    commit_writes(parent, &SettledWrites::from_absolutes(settling.standing()));
    let still = FrontierInputs::still(ShardId::ROOT);
    left.follow_block_writes(&standing, &[], &still).unwrap();
    right.follow_block_writes(&standing, &[], &still).unwrap();
    assert!(
        left.cell(settling.record()).is_some(),
        "the record is on the left"
    );
    assert!(
        right.cell(settling.taken()).is_some(),
        "the answer on the right"
    );
    let under = |store: &S, key: SubstateKey| {
        store
            .crossing_rows(&NibblePath::empty())
            .into_iter()
            .filter(|row| *row == key)
            .count()
    };
    assert_eq!(
        (
            under(left, settling.record()),
            under(right, settling.taken())
        ),
        (1, 1),
        "a followed block indexes what a committed one does",
    );
    assert_eq!(
        (
            under(parent, settling.record()),
            under(parent, settling.taken())
        ),
        (1, 1),
    );

    let (block, inputs) = settling.block(2);
    let (_, parent_root) = commit_raising(parent, block.clone(), &inputs);
    let left_root = left.follow_block_writes(&block, &[], &inputs).unwrap();
    let right_root = right.follow_block_writes(&block, &[], &inputs).unwrap();
    assert!(
        left.cell(settling.record()).is_none(),
        "the left half retires the record"
    );
    assert!(
        right.cell(settling.taken()).is_none(),
        "the right half deletes the answer"
    );
    assert_eq!(
        (
            under(left, settling.record()),
            under(right, settling.taken())
        ),
        (0, 0),
        "and drops the rows the fold removed",
    );
    assert!(
        SplitChildRoots {
            left: left_root,
            right: right_root,
        }
        .composes_to(parent_root),
        "the followed halves recompose the parent's root",
    );
}

/// A chain of three blocks from height `first` whose one member
/// reserves `RESERVED_OF_VAULT` of its payer's vault: the first commits
/// it on stated terms, the second names it to run, and the third lets it
/// go as a member nobody can answer for, with the discard that releases
/// it and the fate that deletes its row.
struct Reserving {
    blocks: [Block; 3],
    /// What the member's commit holds against its payer's vault.
    fee: FeeTerms,
    /// What its fate burns out of that vault.
    charge: AbortCharge,
}

fn reserving_chain(first: u64) -> Reserving {
    let tx = test_transaction(1);
    let fee = FeeTerms::of(&tx);
    let mut stated = stub_stated_terms(tx.hash(), 1);
    let vault = fee.vault;
    stated.terms.charge.vault = vault;
    let charge = stated.terms.charge;
    stated.terms.reserves = Capped::from_array([(vault, RESERVED_OF_VAULT)]);
    let named = TickLine::Member {
        tx: tx.hash(),
        joins: Joins::Executes,
        settlement: Settlement::Shared,
        holds: Capped::empty(),
        reach: stated.terms.reach.clone(),
        awaits: stated.terms.awaits.clone(),
        charge: stated.terms.charge,
        share: stated.terms.share,
        reserves: stated.terms.reserves.clone(),
        deadline: Deadline::of_transaction(&tx),
        nevers: Capped::empty(),
    };
    let dropped = TickLine::Discard {
        tick: TickId::new(ShardId::ROOT, BlockHeight::new(first + 1)),
        cause: DiscardCause::Unanswerable(tx.hash()),
    };
    let fated = TickLine::Fate {
        tx: tx.hash(),
        charge,
    };
    let at = |height: u64| make_test_block(BlockHeight::new(height));
    Reserving {
        blocks: [
            with_member_sections(
                with_transactions(at(first), vec![Arc::new(Verifiable::from(tx))]),
                Vec::new(),
                vec![stated],
            ),
            with_member_sections(at(first + 1), vec![named], Vec::new()),
            with_member_sections(at(first + 2), vec![dropped, fated], Vec::new()),
        ],
        fee,
        charge,
    }
}

/// What the member of [`reserving_chain`] reserves of its vault.
const RESERVED_OF_VAULT: u128 = 85;

/// Attach `lines` and `stated` to a live block, preserving everything
/// else.
fn with_member_sections(mut block: Block, lines: Vec<TickLine>, stated: Vec<StatedTerms>) -> Block {
    if let Block::Live {
        tick_manifest,
        terms,
        ..
    } = &mut block
    {
        *tick_manifest = Arc::new(Capped::new(lines).expect("a list written out in a test"));
        *terms = Arc::new(Capped::new(stated).expect("a list written out in a test"));
    }
    block
}

/// The half of `(left, right)` holding the rows of the root chain's
/// family, then the half without them, once a block committing a member
/// has been followed.
fn halves_by_rows<'s, S: SubstateStore>(left: &'s S, right: &'s S) -> (&'s S, &'s S) {
    let rows = |half: &S| {
        !MemberIndex::load(&half.snapshot(), ShardId::ROOT)
            .members
            .is_empty()
    };
    assert_ne!(rows(left), rows(right), "one half holds the family");
    if rows(left) {
        (left, right)
    } else {
        (right, left)
    }
}

/// Shared: a split follower on the half that does not hold the chain's
/// member rows writes no reserved total, whatever the chain's blocks do
/// to the rows.
///
/// A store following one half folds the member family over that half
/// alone, so only the half holding the rows can keep their sum, and the
/// total lives with them. The other half reads no row, differences
/// nothing, and keeps none of the family.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_follower_of_the_half_without_the_rows_writes_no_total<S>(left: &S, right: &S)
where
    S: BoundaryStore + TestStore,
{
    let Reserving { blocks, fee, .. } = reserving_chain(1);
    let vault = fee.vault;
    let still = FrontierInputs::still(ShardId::ROOT);
    let mut without = None;
    for block in &blocks {
        left.follow_block_writes(block, &[], &still).unwrap();
        right.follow_block_writes(block, &[], &still).unwrap();
        let half = *without.get_or_insert_with(|| halves_by_rows(left, right).1);
        assert_eq!(
            reserved_total(&half.snapshot(), ShardId::ROOT, vault),
            0,
            "no total at {:?}",
            block.height(),
        );
        assert_eq!(
            MemberIndex::load(&half.snapshot(), ShardId::ROOT),
            MemberIndex::empty(ShardId::ROOT),
            "and none of the family at {:?}",
            block.height(),
        );
    }
}

/// Shared: a split follower on the half holding the chain's member rows
/// keeps the reserved total the chain itself keeps, block for block,
/// and the followed halves recompose the chain's root.
///
/// `parent` holds the whole keyspace and commits each block through the
/// one commit path; `left` and `right` hold one half each and follow
/// the same blocks. The member's reservation stands from the block
/// that commits it, through its naming, to the block that deletes its
/// row.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_follower_of_the_half_with_them_writes_the_chains<S>(parent: &S, left: &S, right: &S)
where
    S: BoundaryStore + TestStore,
{
    let Reserving { blocks, fee, .. } = reserving_chain(2);
    let vault = fee.vault;
    let fated = blocks[2].height();
    let mut with = None;
    funded_and_followed(parent, left, right, vault, &blocks, |block| {
        let standing = if block.height() == fated {
            0
        } else {
            RESERVED_OF_VAULT
        };
        let half = *with.get_or_insert_with(|| halves_by_rows(left, right).0);
        assert_eq!(
            reserved_total(&parent.snapshot(), ShardId::ROOT, vault),
            standing,
            "the chain's total at {:?}",
            block.height(),
        );
        assert_eq!(
            reserved_total(&half.snapshot(), ShardId::ROOT, vault),
            standing,
            "the follower's at {:?}",
            block.height(),
        );
        assert_eq!(
            MemberIndex::load(&half.snapshot(), ShardId::ROOT),
            MemberIndex::load(&parent.snapshot(), ShardId::ROOT),
            "and the family whole at {:?}",
            block.height(),
        );
    });
}

/// What a fated member's payer holds once funded.
const FUNDED: u128 = 1_000;

/// Commit to `parent`, and follow into `left` and `right`, a block at
/// height 1 funding `vault` and then each block of `blocks`, asserting
/// the halves recompose the chain's root at every one. `after` is handed
/// each of `blocks` once all three stores hold it.
///
/// The funding block also writes a cell that stands on each half, so
/// the tree keeps both children whatever the blocks after it delete.
fn funded_and_followed<S>(
    parent: &S,
    left: &S,
    right: &S,
    vault: SubstateKey,
    blocks: &[Block],
    after: impl FnMut(&Block),
) where
    S: BoundaryStore + TestStore,
{
    seeded_and_followed(
        parent,
        left,
        right,
        &[(vault, encode_amount(FUNDED).to_vec())],
        blocks,
        after,
    );
}

/// [`funded_and_followed`], the block at height 1 writing each of
/// `seeded`.
fn seeded_and_followed<S>(
    parent: &S,
    left: &S,
    right: &S,
    seeded: &[(SubstateKey, Vec<u8>)],
    blocks: &[Block],
    mut after: impl FnMut(&Block),
) where
    S: BoundaryStore + TestStore,
{
    let mut funding = StateWrites::default();
    for (key, value) in seeded {
        funding.cells.insert(*key, Some(value.clone()));
    }
    for standing in [state_key(0x01, 1), state_key(0xF1, 1)] {
        funding.cells.insert(standing, Some(vec![1]));
    }
    let height = BlockHeight::new(1);
    let funded = push_certificate(make_test_block(height), settling(height, funding));
    let still = FrontierInputs::still(ShardId::ROOT);
    let witness = empty_witness();
    for block in std::iter::once(&funded).chain(blocks) {
        let parent_root = commit_folding(
            parent,
            &make_test_certified(block.clone()),
            &[],
            &[],
            &witness,
            &MemberInputs::of(block, still.windows),
        );
        let left_root = left.follow_block_writes(block, &[], &still).unwrap();
        let right_root = right.follow_block_writes(block, &[], &still).unwrap();
        assert!(
            SplitChildRoots {
                left: left_root,
                right: right_root,
            }
            .composes_to(parent_root),
            "the followed halves recompose the chain's root at {:?}",
            block.height(),
        );
        if block.height() != height {
            after(block);
        }
    }
}

/// The transaction whose record [`declining_block`] reads.
#[must_use]
pub fn unclaimed_issuer() -> TxHash {
    TxHash::from(Hash::from_bytes(b"never committed here"))
}

/// A block of the root chain at `height` that declines an escrowed
/// record, with the record's crossing.
///
/// The crossing's consumer sits under the left half of the root chain.
/// The block reads the record [`unclaimed_issuer`] issued, at its
/// validity end, beside the chain's own row of that transaction read
/// absent at the parent.
///
/// # Panics
///
/// Never: the record is within a held value's bound.
#[must_use]
pub fn declining_block(height: BlockHeight) -> (CrossingId, Block) {
    let id = CrossingId {
        producer: Address::new([0x91; 31], AddressClass::Component),
        consumer: Address::new([0x11; 31], AddressClass::Component),
        intent: IntentHash(Hash32([0x31; 32])),
        local: 0,
        output: 0,
    };
    let record = id.record_key(&ProtocolHasher);
    let cell = id.cell(
        unclaimed_issuer(),
        ResourceAddr::new([0xE1; 31]),
        250,
        0,
        Terms::Escrowed { credit: record },
    );
    let anchor = |shard: ShardId| Anchor {
        shard,
        height: BlockHeight::new(height.inner().saturating_sub(1)),
        state_root: StateRoot::ZERO,
        ts: WeightedTimestamp::ZERO,
    };
    let held = StateClaim::new(
        anchor(ShardId::leaf(1, 1)),
        [(
            record,
            Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits")),
        )],
        MerkleInclusionProof::dummy(),
    )
    .naming([(record, id)]);
    let rowless = StateClaim::new(
        anchor(ShardId::ROOT),
        [(
            member_row_leaf(ShardId::ROOT, unclaimed_issuer()),
            Inclusion::Absent,
        )],
        MerkleInclusionProof::new(Vec::new()),
    );
    (
        id,
        with_state_claims(make_test_block(height), vec![held, rowless]),
    )
}

/// Shared: a block declining an escrowed record lands its `Never` on
/// the chain's own commit and on the follower of the half holding the
/// record's consumer, and on no other.
///
/// `parent` holds the whole keyspace and commits each block through the
/// one commit path; `left` and `right` hold one half each and follow
/// the same blocks, and recompose the chain's root at every one. The
/// decline is read off the block alone, so the half holding the
/// consumer's cells writes it whichever half holds the chain's rows.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_declining_block_lands_on_the_chain_and_the_half_holding_its_consumer<S>(
    parent: &S,
    left: &S,
    right: &S,
) where
    S: BoundaryStore + TestStore,
{
    let (id, block) = declining_block(BlockHeight::new(2));
    let never = id.answer_key(&ProtocolHasher, Answered::Never);
    let decline = id.answer(unclaimed_issuer(), Answered::Never, 0).to_bytes();
    funded_and_followed(parent, left, right, state_key(0x02, 1), &[block], |_| {
        assert_eq!(parent.cell(never), Some(decline.clone()), "the chain's");
        assert_eq!(left.cell(never), Some(decline.clone()), "the left half's");
        assert_eq!(right.cell(never), None, "the right half holds none of it");
    });
}

/// Shared: a fate on a block that carries content burns its member's
/// charge and ends its fee hold.
///
/// The charge comes out of the payer's vault, the fee hold the member's
/// commit placed is deleted and the vault's held total falls by that
/// hold, on the chain's own commit and on a follower of the half holding
/// the vault alike; and the row the fate deletes takes its reservation
/// with it.
///
/// `parent` holds the whole keyspace and commits each block through the
/// one commit path; `left` and `right` hold one half each and follow
/// the same blocks.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_fate_burn_applies_and_lowers_the_held_total<S>(parent: &S, left: &S, right: &S)
where
    S: BoundaryStore + TestStore,
{
    let Reserving {
        blocks,
        fee,
        charge,
    } = reserving_chain(2);
    assert_eq!(charge.vault, fee.vault);
    assert!(charge.amount != 0 && charge.amount <= fee.max_fee);
    let fated = blocks[2].height();
    funded_and_followed(parent, left, right, fee.vault, &blocks, |block| {
        let half = if left.cell(fee.vault).is_some() {
            left
        } else {
            right
        };
        let ended = block.height() == fated;
        for (store, name) in [(parent, "the chain"), (half, "the follower")] {
            let state = store.snapshot();
            assert_eq!(
                amount_at(store, fee.vault),
                if ended {
                    FUNDED - charge.amount
                } else {
                    FUNDED
                },
                "{name}'s vault at {:?}",
                block.height(),
            );
            assert_eq!(
                state.cell(fee.hold_key()).is_some(),
                !ended,
                "{name}'s hold at {:?}",
                block.height(),
            );
            assert_eq!(
                held_total(&state, fee.vault),
                if ended { 0 } else { fee.max_fee },
                "{name}'s held total at {:?}",
                block.height(),
            );
        }
        assert_eq!(
            reserved_total(&parent.snapshot(), ShardId::ROOT, fee.vault),
            if ended { 0 } else { RESERVED_OF_VAULT },
            "the chain's reserved total at {:?}",
            block.height(),
        );
        assert_eq!(
            MemberIndex::load(&parent.snapshot(), ShardId::ROOT)
                .members
                .len(),
            usize::from(!ended),
            "the rows standing at {:?}",
            block.height(),
        );
    });
}

/// Shared: a fate's burn and the release of its hold are in the baseline
/// of every tick above the fate's block and of none at or below it.
///
/// A tick reads the base as of the block below it, and a fate's writes
/// fold into the base at its own block, so the tick chain holds nothing
/// of one: the tick at the fate's height reads the vault whole under the
/// hold still standing, and the tick above reads the burn with the hold
/// gone.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_fate_is_in_the_baseline_of_the_tick_above_its_block<S>(
    parent: &S,
    left: &S,
    right: &S,
) where
    S: BoundaryStore + TestStore + VersionedStore,
{
    let Reserving {
        blocks,
        fee,
        charge,
    } = reserving_chain(2);
    let fated = blocks[2].height();
    funded_and_followed(parent, left, right, fee.vault, &blocks, |_| {});
    let prefix = NibblePath::empty();
    let chain = TickChain::new(Arc::new(parent.clone()));
    let reads = |tick: BlockHeight| {
        let view = chain.view_at(tick);
        (
            view.snapshot()
                .cell(fee.vault)
                .map_or(0, |bytes| read_amount(&bytes).expect("an amount cell")),
            view.fee_holds(&[], &prefix).standing(fee.vault),
            view.fee_holds(&[], &prefix).own(fee.vault, fee.tx),
        )
    };
    let below = fated.prev().expect("a fate above genesis");
    assert_eq!(
        reads(below),
        (FUNDED, fee.max_fee, fee.max_fee),
        "the tick at the fate's block reads the vault whole and the hold standing",
    );
    assert_eq!(
        reads(fated),
        (FUNDED - charge.amount, 0, 0),
        "the tick above it reads the burn, and no hold",
    );
}

/// Two escrowed crossings of the root chain whose records each return
/// their value to a cell under the other half of the root split, with
/// their consumers' `Never` standing beside them: what the root chain
/// holds both ends of, and takes back at its own parent.
struct Returning {
    /// The record on the left half, crediting a cell on the right.
    left: CrossingId,
    /// The record on the right half, crediting a cell on the left.
    right: CrossingId,
}

impl Returning {
    const RESOURCE: ResourceAddr = ResourceAddr::new([0xE4; 31]);
    const AMOUNT: u128 = 250;

    const fn new() -> Self {
        Self {
            left: straddling_crossing(0x23),
            right: CrossingId {
                producer: Address::new([0xA4; 31], AddressClass::Component),
                consumer: Address::new([0xA5; 31], AddressClass::Component),
                intent: IntentHash(Hash32([0x24; 32])),
                local: 0,
                output: 0,
            },
        }
    }

    /// The cell `id`'s record returns to: on the half its record is not.
    const fn credit(id: &CrossingId) -> SubstateKey {
        let (left, _) = ShardId::ROOT.children();
        let byte = if ShardTrie::shard_owns_prefix(left, id.producer) {
            0xA3
        } else {
            0x23
        };
        SubstateKey {
            owner: Address::new([byte; 31], AddressClass::Component),
            local: LocalKey([0x77; 16]),
        }
    }

    fn record(id: &CrossingId) -> Vec<u8> {
        id.cell(
            Self::issuer(),
            Self::RESOURCE,
            Self::AMOUNT,
            0,
            Terms::Escrowed {
                credit: Self::credit(id),
            },
        )
        .to_bytes()
    }

    fn never(id: &CrossingId) -> Vec<u8> {
        id.answer(Self::issuer(), Answered::Never, 0).to_bytes()
    }

    fn issuer() -> TxHash {
        TxHash::from(Hash::from_bytes(b"refused elsewhere"))
    }

    /// What the root chain holds before it takes either back: both
    /// records, both `Never`s and both credit cells funded.
    fn seeded(&self) -> Vec<(SubstateKey, Vec<u8>)> {
        [self.left, self.right]
            .iter()
            .flat_map(|id| {
                [
                    (id.record_key(&ProtocolHasher), Self::record(id)),
                    (
                        id.answer_key(&ProtocolHasher, Answered::Never),
                        Self::never(id),
                    ),
                    (Self::credit(id), encode_amount(FUNDED).to_vec()),
                ]
            })
            .collect()
    }

    /// The root chain's block at `height` taking both records back: each
    /// record and its `Never` read at the block's parent.
    fn block(&self, height: BlockHeight) -> Block {
        let parent = Anchor {
            shard: ShardId::ROOT,
            height: height.prev().expect("a block above genesis"),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::ZERO,
        };
        let read: Vec<(SubstateKey, Stated, CrossingId)> = [self.left, self.right]
            .iter()
            .flat_map(|id| {
                [
                    (
                        id.record_key(&ProtocolHasher),
                        Stated::Held(Bytes::new(Self::record(id)).expect("a record fits")),
                        *id,
                    ),
                    (
                        id.answer_key(&ProtocolHasher, Answered::Never),
                        Inclusion::Present(jmt_value_hash(&Self::never(id))).into(),
                        *id,
                    ),
                ]
            })
            .collect();
        let claim = StateClaim::new(
            parent,
            read.iter().map(|(key, stated, _)| (*key, stated.clone())),
            MerkleInclusionProof::new(Vec::new()),
        )
        .naming(read.iter().map(|(key, _, id)| (*key, *id)));
        with_state_claims(make_test_block(height), vec![claim])
    }
}

/// Shared: a block taking back records whose credit cells sit under the
/// other half lands each write on the half holding its cell.
///
/// The record's removal lands where the record stands, the credit where
/// the cell does. Neither half holds both, and each writes its own share
/// unread, so the halves recompose the chain's root.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_split_follower_applies_the_half_of_a_reclaim_it_holds<S>(
    parent: &S,
    left: &S,
    right: &S,
) where
    S: BoundaryStore + TestStore,
{
    let returning = Returning::new();
    let (left_shard, right_shard) = ShardId::ROOT.children();
    let (on_left, on_right) = (returning.left, returning.right);
    assert!(ShardTrie::shard_owns_prefix(left_shard, on_left.producer));
    assert!(ShardTrie::shard_owns_prefix(right_shard, on_right.producer));
    let block = returning.block(BlockHeight::new(2));
    seeded_and_followed(parent, left, right, &returning.seeded(), &[block], |_| {
        for id in [on_left, on_right] {
            let record = id.record_key(&ProtocolHasher);
            let credit = Returning::credit(&id);
            assert_eq!(parent.cell(record), None, "the chain returns the record");
            assert_eq!(
                amount_at(parent, credit),
                FUNDED + Returning::AMOUNT,
                "the chain credits its cell",
            );
            let (holding, crediting) = if id == on_left {
                (left, right)
            } else {
                (right, left)
            };
            assert_eq!(holding.cell(record), None, "the half holding the record");
            assert_eq!(
                amount_at(crediting, credit),
                FUNDED + Returning::AMOUNT,
                "the half holding the credit cell",
            );
            assert_eq!(amount_at(holding, credit), 0, "and nowhere else");
        }
    });
}

/// Shared: a record taken back is credited into the baseline of every
/// tick above the block that takes it back, and of none at or below it.
///
/// So a debit spends a returned credit from the committed base, one tick
/// after the return.
///
/// A tick reads the base as of the block below it, and the return
/// folds into the base at its own block, so the tick chain holds
/// nothing of it.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_debit_spends_a_fold_reclaims_credit_from_the_committed_base<S>(
    parent: &S,
    left: &S,
    right: &S,
) where
    S: BoundaryStore + TestStore + VersionedStore,
{
    let returning = Returning::new();
    let returned = BlockHeight::new(2);
    seeded_and_followed(
        parent,
        left,
        right,
        &returning.seeded(),
        &[returning.block(returned)],
        |_| {},
    );
    let credit = Returning::credit(&returning.left);
    let chain = TickChain::new(Arc::new(parent.clone()));
    let reads = |tick: BlockHeight| {
        chain
            .view_at(tick)
            .snapshot()
            .cell(credit)
            .map_or(0, |bytes| read_amount(&bytes).expect("an amount cell"))
    };
    assert_eq!(
        reads(returned.prev().expect("a return above genesis")),
        FUNDED,
        "the tick at the returning block reads the cell without the return",
    );
    assert_eq!(
        reads(returned),
        FUNDED + Returning::AMOUNT,
        "the tick above it reads the return",
    );
}

/// One owed crossing of `straddling_crossing`'s: its record on the left
/// half of the root split, and the consumer's vault and `Taken` on the
/// right, where the consumer's fold credits it.
struct Owed {
    id: CrossingId,
}

impl Owed {
    const RESOURCE: ResourceAddr = ResourceAddr::new([0xE3; 31]);
    const AMOUNT: u128 = 250;

    /// The producer's shard, which owns the record's prefix.
    const PRODUCER: ShardId = ShardId::leaf(1, 0);

    const fn new(seed: u8) -> Self {
        Self {
            id: straddling_crossing(seed),
        }
    }

    fn record(&self) -> SubstateKey {
        self.id.record_key(&ProtocolHasher)
    }

    fn taken(&self) -> SubstateKey {
        self.id.answer_key(&ProtocolHasher, Answered::Taken)
    }

    /// The consumer's vault for the crossing's resource: where the
    /// credit lands.
    fn vault(&self) -> SubstateKey {
        self.id.owed_credit(&ProtocolHasher, Self::RESOURCE)
    }

    /// The record's value, as the producer's state holds it.
    fn held(&self) -> Stated {
        let cell = self.id.cell(
            VmTxHash(Hash32([0xC2; 32])),
            Self::RESOURCE,
            Self::AMOUNT,
            1_000,
            Terms::Owed,
        );
        Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits"))
    }

    /// A claim at the producer's height `read_at` reading the record as
    /// `stated`, naming its crossing.
    fn claim(&self, read_at: u64, stated: Stated) -> StateClaim {
        StateClaim::new(
            Anchor {
                shard: Self::PRODUCER,
                height: BlockHeight::new(read_at),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(read_at * 1_000),
            },
            [(self.record(), stated)],
            MerkleInclusionProof::dummy(),
        )
        .naming([(self.record(), self.id)])
    }

    /// The fence a later block's presence of the record at `read_at`
    /// meets, built as the voter builds it.
    fn presence_at(&self, read_at: u64) -> ReadFence {
        let anchor = self.claim(read_at, self.held()).anchor;
        ReadFence {
            presences: vec![Reading {
                key: self.record(),
                shard: anchor.shard,
                mark: ReadMark::of(&anchor, EpochWindows::new(FRONTIER_WINDOW_MS)),
            }],
            absences: Vec::new(),
            deletions: Vec::new(),
        }
    }
}

/// A block at `height` carrying `claims` and settling one receipt of
/// `writes` where one is given, and the frontier inputs its shard reads
/// off it.
fn owed_block(
    height: u64,
    claims: Vec<StateClaim>,
    writes: Option<StateWrites>,
) -> (Block, FrontierInputs) {
    let height = BlockHeight::new(height);
    let base = writes.map_or_else(
        || make_test_block(height),
        |writes| push_certificate(make_test_block(height), settling(height, writes)),
    );
    let block = with_state_claims(base, claims);
    let inputs = FrontierInputs::of_block(&block, EpochWindows::new(FRONTIER_WINDOW_MS));
    (block, inputs)
}

/// Writes moving `vault` by `movement` and nothing else.
fn moving(vault: SubstateKey, movement: Movement) -> StateWrites {
    let mut writes = StateWrites::default();
    writes.movements.insert(vault, movement);
    writes
}

/// What `store` holds at `key` as an amount, absent as zero.
fn amount_at<S: SubstateStore>(store: &S, key: SubstateKey) -> u128 {
    store
        .cell(key)
        .map_or(0, |bytes| read_amount(&bytes).expect("an amount cell"))
}

/// Shared: a block crediting an owed crossing lands one root on every
/// path.
///
/// Build, the vote's verification and a QC-only replica all prepare the
/// block through `parent`'s commit path; a follower holding the whole
/// keyspace and the two halves of a split follow it. The whole follower
/// lands the parent's root, the halves recompose it, and the credit and
/// `Taken` land on the consumer's half alone.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_an_owed_credit_lands_one_root_on_every_path<S>(
    parent: &S,
    whole: &S,
    left: &S,
    right: &S,
) where
    S: BoundaryStore + TestStore,
{
    let owed = Owed::new(0x31);
    let (block, inputs) = owed_block(1, vec![owed.claim(7, owed.held())], None);

    let before = parent.state_root();
    let (prepared, committed) = commit_raising(parent, block.clone(), &inputs);
    assert_ne!(prepared, before, "the credit moves the root");
    assert_eq!(committed, prepared);
    assert_eq!(amount_at(parent, owed.vault()), Owed::AMOUNT);
    assert!(
        parent.cell(owed.taken()).is_some(),
        "the credit writes Taken"
    );

    let whole_root = whole.follow_block_writes(&block, &[], &inputs).unwrap();
    assert_eq!(
        whole_root, committed,
        "a follower holding the consumer's prefix lands the committed root",
    );
    let left_root = left.follow_block_writes(&block, &[], &inputs).unwrap();
    let right_root = right.follow_block_writes(&block, &[], &inputs).unwrap();
    assert_eq!(amount_at(right, owed.vault()), Owed::AMOUNT);
    assert!(right.cell(owed.taken()).is_some());
    assert_eq!(
        (amount_at(left, owed.vault()), left.cell(owed.taken())),
        (0, None),
        "nothing of the credit lands on the producer's half",
    );
    assert!(
        SplitChildRoots {
            left: left_root,
            right: right_root,
        }
        .composes_to(committed),
        "the followed halves recompose the committed root",
    );
}

/// Shared: an owed credit into a vault it would carry past `u128` lands
/// what fits and burns the rest, one root on every path.
///
/// The consumer's vault holds ten short of `u128::MAX`: the credit fills
/// it and writes `Taken`, and the replica committing the block, a
/// follower holding the whole keyspace and the two halves of a split all
/// fold that one result rather than halting on it.
///
/// `burned` reads a store's count of what the blocks it committed burned
/// on a cell. The replica counts the burn once: not for a preparation it
/// never applies, nor for a second commit of the block it already holds.
/// A follower counts nothing.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_an_owed_credit_into_a_full_vault_lands_one_root_on_every_path<S>(
    parent: &S,
    whole: &S,
    left: &S,
    right: &S,
    burned: impl Fn(&S, SubstateKey) -> u128,
) where
    S: BoundaryStore + TestStore,
{
    const ROOM: u128 = 10;
    let owed = Owed::new(0x35);
    let mut seed = StateWrites::default();
    seed.cells
        .insert(owed.vault(), Some(encode_amount(u128::MAX - ROOM).to_vec()));
    let (block, inputs) = owed_block(1, Vec::new(), Some(seed));
    let (_, seeded) = commit_raising(parent, block.clone(), &inputs);
    for follower in [whole, left, right] {
        follower.follow_block_writes(&block, &[], &inputs).unwrap();
    }
    assert_eq!(whole.state_root(), seeded);

    let (block, inputs) = owed_block(2, vec![owed.claim(7, owed.held())], None);
    let (unapplied, never) = prepare_raising(parent, &block, &inputs);
    drop(never);
    let (again, second) = prepare_raising(parent, &block, &inputs);
    let (prepared, committed) = commit_raising(parent, block.clone(), &inputs);
    assert_eq!(committed, prepared);
    assert_eq!((unapplied, again), (prepared, prepared));
    assert_eq!(
        amount_at(parent, owed.vault()),
        u128::MAX,
        "the credit lands the room the vault has and burns the rest",
    );
    assert_eq!(
        burned(parent, owed.vault()),
        Owed::AMOUNT - ROOM,
        "the commit counts the burn, and a preparation never applied counts none",
    );
    assert_eq!(
        second(
            SyncHint::FlushNow,
            &make_test_certified(block.clone()),
            &empty_witness(),
        ),
        committed,
    );
    assert_eq!(
        burned(parent, owed.vault()),
        Owed::AMOUNT - ROOM,
        "a second commit of the block the store holds counts nothing",
    );
    assert!(
        parent.cell(owed.taken()).is_some(),
        "the credit writes Taken"
    );

    let whole_root = whole.follow_block_writes(&block, &[], &inputs).unwrap();
    assert_eq!(whole_root, committed);
    let left_root = left.follow_block_writes(&block, &[], &inputs).unwrap();
    let right_root = right.follow_block_writes(&block, &[], &inputs).unwrap();
    assert_eq!(amount_at(right, owed.vault()), u128::MAX);
    assert!(right.cell(owed.taken()).is_some());
    assert!(
        SplitChildRoots {
            left: left_root,
            right: right_root,
        }
        .composes_to(committed),
        "the followed halves recompose the committed root",
    );
    for follower in [whole, left, right] {
        assert_eq!(
            burned(follower, owed.vault()),
            0,
            "a follower counts nothing"
        );
    }
}

/// Shared: receipt credits that carry a vault past `u128` land what
/// fits and burn the rest, one root on every path.
///
/// The vault holds ten short of `u128::MAX`. Two receipts in one block
/// credit it six each, and a third in the next block credits six more:
/// the vault settles at `u128::MAX` on the replica committing the
/// blocks, on a follower holding the whole keyspace, and on the half of
/// a split holding the vault, whose halves recompose every root.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_receipt_credits_past_u128_land_one_root_on_every_path<S>(
    parent: &S,
    whole: &S,
    left: &S,
    right: &S,
) where
    S: BoundaryStore + TestStore,
{
    const ROOM: u128 = 10;
    let owed = Owed::new(0x36);
    let vault = owed.vault();
    let credit = |amount| {
        moving(
            vault,
            Movement {
                resource: Owed::RESOURCE,
                credit: amount,
                debit: 0,
                unjudged_debit: 0,
            },
        )
    };
    let mut seed = StateWrites::default();
    seed.cells
        .insert(vault, Some(encode_amount(u128::MAX - ROOM).to_vec()));
    // A cell on the other half, so neither half's tree is empty and the
    // two compose under one internal node.
    seed.cells.insert(owed.record(), Some(vec![1]));
    let (seeding, _) = owed_block(1, Vec::new(), Some(seed));
    let (two, _) = owed_block(2, Vec::new(), Some(credit(6)));
    let two = push_certificate(two, settling(BlockHeight::new(2), credit(6)));
    let (next, _) = owed_block(3, Vec::new(), Some(credit(6)));
    for block in [seeding, two, next] {
        let inputs = FrontierInputs::of_block(&block, EpochWindows::new(FRONTIER_WINDOW_MS));
        let (prepared, committed) = commit_raising(parent, block.clone(), &inputs);
        assert_eq!(committed, prepared);
        let whole_root = whole.follow_block_writes(&block, &[], &inputs).unwrap();
        assert_eq!(whole_root, committed);
        let left_root = left.follow_block_writes(&block, &[], &inputs).unwrap();
        let right_root = right.follow_block_writes(&block, &[], &inputs).unwrap();
        assert!(
            SplitChildRoots {
                left: left_root,
                right: right_root,
            }
            .composes_to(committed),
            "the followed halves recompose the committed root",
        );
    }
    assert_eq!(amount_at(parent, vault), u128::MAX);
    assert_eq!(amount_at(whole, vault), u128::MAX);
    assert_eq!(amount_at(right, vault), u128::MAX, "the vault's half");
    assert_eq!(amount_at(left, vault), 0, "nothing lands on the other half");
}

/// Shared: a receipt and an owed credit in one block fill a vault, one
/// root committed and followed whole.
///
/// A receipt credit of 4 and an owed credit of the record's amount into
/// a vault ten short of `u128::MAX` settle it at `u128::MAX`.
/// A later block's receipt writing bytes into the vault outright leaves
/// a second owed credit beside it unlanded.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_receipt_and_an_owed_credit_fill_a_vault_on_every_path<S>(parent: &S, whole: &S)
where
    S: BoundaryStore + TestStore,
{
    let owed = Owed::new(0x37);
    let mut seed = StateWrites::default();
    seed.cells
        .insert(owed.vault(), Some(encode_amount(u128::MAX - 10).to_vec()));
    let (block, inputs) = owed_block(1, Vec::new(), Some(seed));
    commit_raising(parent, block.clone(), &inputs);
    whole.follow_block_writes(&block, &[], &inputs).unwrap();
    let receipt = moving(
        owed.vault(),
        Movement {
            resource: Owed::RESOURCE,
            credit: 4,
            debit: 0,
            unjudged_debit: 0,
        },
    );
    let (block, inputs) = owed_block(2, vec![owed.claim(7, owed.held())], Some(receipt));
    let (prepared, committed) = commit_raising(parent, block.clone(), &inputs);
    assert_eq!(prepared, committed);
    assert_eq!(amount_at(parent, owed.vault()), u128::MAX);
    assert!(parent.cell(owed.taken()).is_some());
    assert_eq!(
        whole.follow_block_writes(&block, &[], &inputs).unwrap(),
        committed
    );
    assert_eq!(amount_at(whole, owed.vault()), u128::MAX);

    // A receipt writing bytes into the vault outright, beside a second
    // owed credit into it: the credit lands nothing and the bytes stand,
    // judged against the receipt's write on every path.
    let second = Owed {
        id: CrossingId {
            local: 1,
            ..owed.id
        },
    };
    let mut bytes = StateWrites::default();
    bytes.cells.insert(owed.vault(), Some(vec![0xAB; 3]));
    let (block, inputs) = owed_block(3, vec![second.claim(8, second.held())], Some(bytes));
    let (prepared, committed) = commit_raising(parent, block.clone(), &inputs);
    assert_eq!(prepared, committed);
    assert_eq!(parent.cell(owed.vault()), Some(vec![0xAB; 3]));
    assert!(parent.cell(second.taken()).is_some());
    assert_eq!(
        whole.follow_block_writes(&block, &[], &inputs).unwrap(),
        committed
    );
    assert_eq!(whole.cell(owed.vault()), Some(vec![0xAB; 3]));
}

/// Shared: a receipt credit into a vault an owed credit filled settles
/// it full.
///
/// The owed credit fills the vault to `u128::MAX`, and the next block
/// settles a receipt crediting that vault by 5, a credit the kernel
/// judged against a baseline below the owed credit's block. It burns,
/// and the vault stays full.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_filled_vault_takes_the_next_receipt_credit<S: TestStore>(storage: &S) {
    const ROOM: u128 = 10;
    let owed = Owed::new(0x36);
    let mut seed = StateWrites::default();
    seed.cells
        .insert(owed.vault(), Some(encode_amount(u128::MAX - ROOM).to_vec()));
    let (block, inputs) = owed_block(1, Vec::new(), Some(seed));
    commit_raising(storage, block, &inputs);
    let (block, inputs) = owed_block(2, vec![owed.claim(7, owed.held())], None);
    commit_raising(storage, block, &inputs);
    assert_eq!(amount_at(storage, owed.vault()), u128::MAX);
    let receipt = moving(
        owed.vault(),
        Movement {
            resource: Owed::RESOURCE,
            credit: 5,
            debit: 0,
            unjudged_debit: 0,
        },
    );
    let (block, inputs) = owed_block(3, Vec::new(), Some(receipt));
    let (prepared, committed) = commit_raising(storage, block, &inputs);
    assert_eq!(prepared, committed);
    assert_eq!(amount_at(storage, owed.vault()), u128::MAX);
}

/// Shared: a credit that burned and the debit after it settle where the
/// tick view reads them.
///
/// The vault is full through block 2. Over that base, tick 1 credits 5,
/// judged before the vault filled, and tick 2 debits 5. The view the
/// tick at height 3 reads over both holds the vault at `u128::MAX - 5`:
/// the credit burns before the debit is taken. Blocks 3 and 4 settle the
/// two, and block 5 settles a third tick's debit of everything that view
/// read, down to nothing.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_burned_credit_and_a_later_debit_settle_where_the_view_reads_them<S>(storage: &S)
where
    S: TestStore + VersionedStore,
{
    let owed = Owed::new(0x38);
    let vault = owed.vault();
    let mut seed = StateWrites::default();
    seed.cells
        .insert(vault, Some(encode_amount(u128::MAX).to_vec()));
    let (block, inputs) = owed_block(1, Vec::new(), Some(seed));
    commit_raising(storage, block, &inputs);
    let (block, inputs) = owed_block(2, Vec::new(), None);
    commit_raising(storage, block, &inputs);
    let moved = |credit, debit| {
        moving(
            vault,
            Movement {
                resource: Owed::RESOURCE,
                credit,
                debit,
                unjudged_debit: 0,
            },
        )
    };
    let chain = TickChain::new(Arc::new(storage.clone()));
    for (tick, writes) in [(1u64, moved(5, 0)), (2, moved(0, 5))] {
        chain.append(
            BlockHeight::new(tick),
            TickOutput {
                determined: vec![(TxHash::from(Hash::from_bytes(&tick.to_le_bytes())), writes)],
                provisional: Vec::new(),
            },
            &[],
        );
    }
    let viewed = baseline_at(&chain, 2, vault);
    assert_eq!(viewed, u128::MAX - 5, "the view burns the credit first");
    let (block, inputs) = owed_block(3, Vec::new(), Some(moved(5, 0)));
    commit_raising(storage, block, &inputs);
    assert_eq!(amount_at(storage, vault), u128::MAX, "the credit burned");
    let (block, inputs) = owed_block(4, Vec::new(), Some(moved(0, 5)));
    commit_raising(storage, block, &inputs);
    assert_eq!(amount_at(storage, vault), viewed);
    let (block, inputs) = owed_block(5, Vec::new(), Some(moved(0, viewed)));
    let (prepared, committed) = commit_raising(storage, block, &inputs);
    assert_eq!(prepared, committed);
    assert_eq!(amount_at(storage, vault), 0);
}

/// Shared: a block whose only write is an owed credit folds it.
///
/// The first claim at an anchor raises the read frontier, which is a
/// write of its own; a second claim of the producer at that same anchor
/// raises nothing, carries no receipt and creates nothing, and still
/// credits its crossing.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_an_owed_credit_alone_is_a_write<S: TestStore>(storage: &S) {
    let first = Owed::new(0x34);
    let second = Owed {
        id: CrossingId {
            local: 1,
            ..first.id
        },
    };
    let (block, inputs) = owed_block(1, vec![first.claim(7, first.held())], None);
    commit_raising(storage, block, &inputs);
    assert_eq!(amount_at(storage, first.vault()), Owed::AMOUNT);

    let before = storage.state_root();
    let (block, inputs) = owed_block(2, vec![second.claim(7, second.held())], None);
    let (prepared, committed) = commit_raising(storage, block, &inputs);
    assert_ne!(prepared, before, "the credit alone moves the root");
    assert_eq!(committed, prepared);
    assert_eq!(amount_at(storage, first.vault()), 2 * Owed::AMOUNT);
    assert!(
        storage.cell(second.taken()).is_some(),
        "the second crossing is taken"
    );
}

/// Shared: an owed credit composes with a receipt's movement on the
/// same vault.
///
/// A receipt settled in the block that credits a crossing moves the
/// consumer's vault from the parent's balance, and the credit folds
/// after it: a debit and the credit settle to their net, and a second
/// block's receipt credit and a second crossing's credit both land.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_an_owed_credit_composes_with_a_receipt_on_its_vault<S: TestStore>(storage: &S) {
    const SEED: u128 = 1_000;
    let first = Owed::new(0x33);
    let second = Owed {
        id: CrossingId {
            local: 1,
            ..first.id
        },
    };
    assert_eq!(first.vault(), second.vault(), "one consumer, one vault");
    let vault = first.vault();
    commit_writes(
        storage,
        &SettledWrites::from_absolutes(BTreeMap::from([(
            vault,
            Some(encode_amount(SEED).to_vec()),
        )])),
    );

    let debit = moving(
        vault,
        Movement {
            resource: Owed::RESOURCE,
            credit: 0,
            debit: 30,
            unjudged_debit: 0,
        },
    );
    let (block, inputs) = owed_block(2, vec![first.claim(7, first.held())], Some(debit));
    commit_raising(storage, block, &inputs);
    assert_eq!(
        amount_at(storage, vault),
        SEED - 30 + Owed::AMOUNT,
        "the debit and the credit settle to their net",
    );

    let credit = moving(
        vault,
        Movement {
            resource: Owed::RESOURCE,
            credit: 10,
            debit: 0,
            unjudged_debit: 0,
        },
    );
    let (block, inputs) = owed_block(3, vec![second.claim(8, second.held())], Some(credit));
    commit_raising(storage, block, &inputs);
    assert_eq!(
        amount_at(storage, vault),
        SEED - 30 + Owed::AMOUNT + 10 + Owed::AMOUNT,
        "a receipt credit and a second crossing's credit both land",
    );
}

/// Shared: a fresh absence deletes no answer on either write path.
///
/// The block reads the producing member's exit beside the absence, so
/// the claim's age against the block's anchor is all that keeps the
/// `Taken`, on the store committing the block and on the split half
/// following it: both date the block by its parent QC's clock.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_fresh_absence_with_its_exit_read_deletes_no_answer<S>(parent: &S, left: &S, right: &S)
where
    S: BoundaryStore + TestStore,
{
    let owed = Owed::new(0x36);
    let follow = |(block, inputs): &(Block, FrontierInputs)| {
        commit_raising(parent, block.clone(), inputs);
        left.follow_block_writes(block, &[], inputs).unwrap();
        right.follow_block_writes(block, &[], inputs).unwrap();
    };
    follow(&owed_block(1, vec![owed.claim(7, owed.held())], None));
    assert!(parent.cell(owed.taken()).is_some() && right.cell(owed.taken()).is_some());

    let absence = owed.claim(9, Stated::from(Inclusion::Absent));
    let exited = StateClaim::new(
        absence.anchor,
        [(
            member_row_leaf(Owed::PRODUCER, VmTxHash(Hash32([0xC2; 32]))),
            Inclusion::Absent,
        )],
        MerkleInclusionProof::dummy(),
    );
    let block = owed_block(2, vec![absence, exited], None);
    assert!(
        block
            .0
            .state_claims()
            .iter()
            .all(|claim| !claim.at_boundary(block.1.anchor)),
        "both claims are fresh to the block",
    );
    follow(&block);
    assert!(
        parent.cell(owed.taken()).is_some(),
        "the committing store keeps the Taken",
    );
    assert!(
        right.cell(owed.taken()).is_some(),
        "the following half keeps the Taken",
    );
}

/// Shared: a crossing's `Taken` outlives a fresh absence of its record
/// and goes on the absence read at a boundary.
///
/// On the consumer's store and on the split half holding it alike, with
/// the record credited once throughout.
///
/// Block 1 credits on a reading at 7. Block 2 carries the record read
/// absent at 9, fresh: the `Taken` stands, and the frontier each store
/// holds refuses a presence at 7 and at 8 and passes one at 10, which
/// the standing `Taken` credits nothing for. Block 3, anchored more
/// than a retention horizon past the producer's height 12, carries the
/// record read absent there with its producing member's row gone: the
/// `Taken` goes, and the claim leaves the frontier as it stood.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_an_answer_outlives_a_fresh_absence_and_goes_at_a_boundary<S>(
    parent: &S,
    left: &S,
    right: &S,
) where
    S: BoundaryStore + TestStore,
{
    let owed = Owed::new(0x35);
    let absent = || Stated::from(Inclusion::Absent);
    let follow = |(block, inputs): &(Block, FrontierInputs)| {
        commit_raising(parent, block.clone(), inputs);
        left.follow_block_writes(block, &[], inputs).unwrap();
        right.follow_block_writes(block, &[], inputs).unwrap();
    };
    follow(&owed_block(1, vec![owed.claim(7, owed.held())], None));
    follow(&owed_block(2, vec![owed.claim(9, absent())], None));
    assert!(
        parent.cell(owed.taken()).is_some() && right.cell(owed.taken()).is_some(),
        "a fresh absence leaves the Taken standing",
    );

    let (_, consumer_half) = ShardId::ROOT.children();
    let frontiers = || {
        [
            ("the consumer's store", parent.read_frontier(ShardId::ROOT)),
            (
                "the half holding the consumer",
                right.read_frontier(consumer_half),
            ),
        ]
    };
    for (name, frontier) in frontiers() {
        for below in [7, 8] {
            assert!(
                owed.presence_at(below).check(&frontier).is_err(),
                "{name} refuses a presence at {below}, below the absence at 9",
            );
        }
        assert_eq!(
            owed.presence_at(10).check(&frontier),
            Ok(()),
            "{name} passes a presence above the absence",
        );
    }
    follow(&owed_block(3, vec![owed.claim(10, owed.held())], None));
    assert_eq!(
        amount_at(parent, owed.vault()),
        Owed::AMOUNT,
        "the record read again under its standing Taken is credited no second time",
    );

    let before = frontiers();
    let boundary = owed.claim(12, absent());
    let exited = StateClaim::new(
        boundary.anchor,
        [(
            member_row_leaf(Owed::PRODUCER, VmTxHash(Hash32([0xC2; 32]))),
            Inclusion::Absent,
        )],
        MerkleInclusionProof::dummy(),
    );
    let past = boundary
        .anchor
        .ts
        .plus(RETENTION_HORIZON)
        .plus(Duration::from_millis(1));
    let block = with_state_claims(
        make_test_block_with_anchor_wt(BlockHeight::new(4), past.as_millis()),
        vec![boundary, exited],
    );
    let inputs = FrontierInputs::of_block(&block, EpochWindows::new(FRONTIER_WINDOW_MS));
    assert!(inputs.marks.is_empty(), "a boundary claim raises nothing");
    follow(&(block, inputs));
    assert!(
        parent.cell(owed.taken()).is_none() && right.cell(owed.taken()).is_none(),
        "the absence at a boundary, its member exited, deletes the Taken",
    );
    assert_eq!(frontiers(), before, "and leaves the frontier as it stood");
    assert_eq!(amount_at(parent, owed.vault()), Owed::AMOUNT);
    assert_eq!(amount_at(right, owed.vault()), Owed::AMOUNT);
}

/// One block seeding `vault` with `amount`.
fn seeding(vault: SubstateKey, amount: u128) -> SettledWrites {
    SettledWrites::from_absolutes(BTreeMap::from([(
        vault,
        Some(encode_amount(amount).to_vec()),
    )]))
}

/// Commit at `height` a block carrying the finalization of the tick at
/// `tick`, whose one receipt is `tx_hash` leaving `writes`.
fn commit_finalizing<S: TestStore>(
    storage: &S,
    height: u64,
    tick: u64,
    tx_hash: TxHash,
    writes: StateWrites,
) {
    let finalization = make_finalization_leaving(BlockHeight::new(tick), tx_hash, writes);
    let block = push_certificate(
        make_test_block(BlockHeight::new(height)),
        Arc::new(finalization.into()),
    );
    commit_settled_at(
        storage,
        &make_test_certified(block),
        &[],
        &[],
        &empty_witness(),
    );
}

/// What the tick after `tick` reads at `vault` through `chain`, absent
/// as zero.
fn baseline_at<S: VersionedStore>(chain: &TickChain<S>, tick: u64, vault: SubstateKey) -> u128 {
    chain
        .view_at(BlockHeight::new(tick))
        .snapshot()
        .cell(vault)
        .map_or(0, |bytes| read_amount(&bytes).expect("an amount cell"))
}

/// Whether `chain` refuses to build the baseline of the tick after
/// `tick`.
fn refuses_baseline_at<S: VersionedStore>(chain: &TickChain<S>, tick: u64) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        let _ = chain.view_at(BlockHeight::new(tick));
    }))
    .is_err()
}

/// Shared: a tick's baseline stands on the block below it as the store
/// wrote it, and is refused past what the store has written.
///
/// A block's commit writes into the base what no tick's output carries,
/// and settles an unjudged debit against what its vault held at that
/// commit. A view built over a base short of that block would be another
/// baseline than the one a replica that had written it reads, so the
/// chain builds none: the tick waits for the write.
///
/// On `credited`, block 2 credits the consumer's vault in its commit
/// fold, which no tick produced. On `charged`, the tick at height 2
/// charges a refused member more than its vault holds, unjudged; block 3
/// settles that tick, and the tick at height 3 credits the vault.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_baseline_stands_on_the_block_below_its_tick<S>(credited: &S, charged: &S)
where
    S: TestStore + VersionedStore,
{
    a_baseline_carries_its_blocks_owed_credit(credited);
    a_baseline_carries_its_blocks_settled_debit(charged);
}

/// The owed credit half of
/// [`test_a_baseline_stands_on_the_block_below_its_tick`].
fn a_baseline_carries_its_blocks_owed_credit<S>(credited: &S)
where
    S: TestStore + VersionedStore,
{
    const SEED: u128 = 1_000;
    let owed = Owed::new(0x36);
    commit_writes(credited, &seeding(owed.vault(), SEED));
    let chain = TickChain::new(Arc::new(credited.clone()));
    assert!(
        refuses_baseline_at(&chain, 2),
        "block 2 is unwritten, so the tick at height 3 has no baseline yet",
    );
    let (block, inputs) = owed_block(2, vec![owed.claim(7, owed.held())], None);
    commit_raising(credited, block, &inputs);
    chain.prune_persisted(BlockHeight::new(2), BlockHeight::GENESIS);
    assert_eq!(
        baseline_at(&chain, 2, owed.vault()),
        SEED + Owed::AMOUNT,
        "written, block 2's credit is in the baseline no entry carries it into",
    );
    assert_eq!(
        baseline_at(&TickChain::new(Arc::new(credited.clone())), 2, owed.vault()),
        SEED + Owed::AMOUNT,
        "a chain opened over the store stands on the tip the store serves",
    );
}

/// The unjudged debit half of
/// [`test_a_baseline_stands_on_the_block_below_its_tick`].
fn a_baseline_carries_its_blocks_settled_debit<S>(charged: &S)
where
    S: TestStore + VersionedStore,
{
    const HELD: u128 = 5;
    const CHARGE: u128 = 10;
    const CREDIT: u128 = 20;
    let vault = state_key(0x63, 1);
    let refused = TxHash::from(Hash::from_bytes(b"refused"));
    let crediting = TxHash::from(Hash::from_bytes(b"crediting"));
    let charge = moving(vault, Movement::unjudged(Owed::RESOURCE, CHARGE));
    let credit = moving(
        vault,
        Movement {
            resource: Owed::RESOURCE,
            credit: CREDIT,
            debit: 0,
            unjudged_debit: 0,
        },
    );
    // The vault, and the fee hold the refused member's commit placed on
    // it: an unjudged charge settles only against a hold that stands.
    let hold = FeeHold {
        vault: vault.local,
        tx: refused,
        fee: CHARGE,
    };
    let (mut seeded, entries) = seeding(vault, HELD).into_parts();
    seeded.insert(
        hold.key(&ProtocolHasher, vault.owner),
        Some(hold.to_bytes()),
    );
    commit_writes(charged, &SettledWrites::from_parts(seeded, entries));
    commit_writes(charged, &SettledWrites::default());
    let chain = TickChain::new(Arc::new(charged.clone()));
    chain.append(
        BlockHeight::new(2),
        TickOutput {
            determined: vec![(refused, charge.clone())],
            provisional: Vec::new(),
        },
        &[],
    );
    chain.resolve(
        &TickId::new(ShardId::ROOT, BlockHeight::new(2)),
        &TickResolution::Settled {
            height: BlockHeight::new(3),
            members: BTreeSet::from([refused]),
            aborted: BTreeSet::from([refused]),
        },
    );
    chain.append(
        BlockHeight::new(3),
        TickOutput {
            determined: vec![(crediting, credit)],
            provisional: Vec::new(),
        },
        &[],
    );
    assert!(
        refuses_baseline_at(&chain, 3),
        "block 3 is unwritten, so the tick at height 4 has no baseline yet",
    );
    commit_finalizing(charged, 3, 2, refused, charge);
    chain.prune_persisted(BlockHeight::new(3), BlockHeight::new(3));
    assert_eq!(
        baseline_at(&chain, 3, vault),
        CREDIT,
        "written, the debit took what the vault held and the credit lands after it",
    );
}

/// Shared: a split observer following the parent's blocks into one half
/// rebuilds the parent's raise from the copy on that half alone.
///
/// `parent` holds the whole keyspace and commits a block carrying a
/// claim through the one commit path; `left` and `right` hold one half
/// each and follow the same block. Each half's root moves, the two
/// recompose the parent's, and each child reads the table the parent
/// wrote from its own half.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_followed_halves_hold_the_read_frontier<S>(parent: &S, left: &S, right: &S)
where
    S: BoundaryStore + TestStore,
{
    let producer = ShardId::leaf(2, 3);
    let (block, inputs) = block_reading(1, producer, 7);
    let (_, parent_root) = commit_raising(parent, block.clone(), &inputs);

    let left_before = left.state_root();
    let right_before = right.state_root();
    let left_root = left.follow_block_writes(&block, &[], &inputs).unwrap();
    let right_root = right.follow_block_writes(&block, &[], &inputs).unwrap();
    assert_ne!(left_root, left_before, "the left half holds the table");
    assert_ne!(right_root, right_before, "and the right half its copy");
    assert!(
        SplitChildRoots {
            left: left_root,
            right: right_root,
        }
        .composes_to(parent_root),
        "the followed halves recompose the parent's root",
    );

    let expected = frontier_of(producer, 7);
    let (left_child, right_child) = ShardId::ROOT.children();
    assert_eq!(
        left.read_frontier(left_child),
        expected,
        "the left child reads the table off its half",
    );
    assert_eq!(
        right.read_frontier(right_child),
        expected,
        "and the right child off its own",
    );
}

/// Shared prepare-path test: a block that carries a transaction and no
/// certificates still writes its committed cell.
///
/// The prepare path treats a block with nothing to write as a no-op
/// whose root is its parent's, and a block carrying only transactions
/// has no receipts. Its committed cells are writes all the same — the
/// prober asking whether this shard committed the transaction reads
/// them off the root — so the root moves and the cell is served under
/// it.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_prepared_commit_writes_committed_cells<S>(storage: &Arc<S>)
where
    S: ShardChainReader + ShardChainWriter + SubstateStore,
{
    let tx = test_transaction(1);
    let cell = committed_tx_cell_key(
        ShardId::ROOT,
        tx.hash(),
        tx.validity_range().end_timestamp_exclusive,
    );
    let block = with_transactions(
        make_test_block(BlockHeight::new(1)),
        vec![Arc::new(Verifiable::from(tx))],
    );
    let creations = committed_tx_cells(
        block.header().shard_id(),
        block.transactions().iter().map(|tx| tx.as_unverified()),
    );

    let parent_root = storage.state_root();
    let (spec_root, _snapshot, commit) = storage.prepare_block_commit(
        ParentAnchor {
            state_root: parent_root,
            height: BlockHeight::GENESIS,
            state: &storage.snapshot(),
            pending: &[],
            base_reads: None,
        },
        &[],
        ChainWrites {
            creations: &creations,
            removals: &[],
            sweep_frontier: SweepFrontier::ZERO,
            frontier: &FrontierInputs::still(ShardId::ROOT),
            state_claims: &[],
            members: &MemberInputs::still(ShardId::ROOT),
        },
        BlockHeight::new(1),
    );
    let certified = make_test_certified(block);
    let committed_root = commit(SyncHint::FlushNow, &certified, &empty_witness());
    assert_ne!(spec_root, parent_root, "a committed cell moves the root");
    assert_eq!(committed_root, spec_root);
    assert!(
        matches!(
            storage.get_substate_at_height(cell, BlockHeight::new(1)),
            Some(Some(_))
        ),
        "the prepared commit serves the committed cell under its root",
    );
}

/// Shared: a transaction's committed marker refuses its re-inclusion
/// through every view a voter reads, whatever the voter remembers.
///
/// The voter's rule reads the anchored view and nothing node-local, so
/// a replica that restarted with nothing folded, one whose store begins
/// at a snap-sync boundary, and one that has persisted nothing past a
/// pending ancestor carrying the transaction all refuse it as a live
/// replica does.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_committed_marker_refuses_its_transaction_on_every_view<S>(
    serving: &S,
    fresh: &S,
    unpersisted: &S,
) where
    S: BoundaryStore + TestStore + VersionedStore + TreeReader + ShardChainReader + Sync + 'static,
{
    let tx = test_transaction(1);
    let block = with_transactions(
        make_test_block(BlockHeight::new(1)),
        vec![Arc::new(Verifiable::from(tx.clone()))],
    );
    let creations = committed_tx_cells(ShardId::ROOT, [&tx]);
    let rows = committed_here(ShardId::ROOT, WeightedTimestamp::ZERO, [&tx]);
    let marker = rows[0].key;
    let chain_over = |store: &S| {
        Arc::new(PendingChain::new(
            Arc::new(store.clone()),
            ChainOrigin::ROOT,
        ))
    };

    commit_settled_at(
        serving,
        &make_test_certified(block.clone()),
        &creations,
        &[],
        &empty_witness(),
    );
    let restarted = chain_over(serving);
    assert_eq!(
        colliding_committed_cell(&rows, &restarted.view_at_persisted_tip().snapshot()),
        Some(marker),
        "a restarted replica reads the marker off its store",
    );

    let leaves = boundary_leaves(serving, BlockHeight::new(1));
    import_boundary_state(fresh, BlockHeight::new(1), &leaves, WitnessSeed::default()).unwrap();
    let synced = chain_over(fresh);
    assert_eq!(
        colliding_committed_cell(&rows, &synced.view_at_persisted_tip().snapshot()),
        Some(marker),
        "a snap-synced replica reads the marker off the imported state",
    );

    let pending = chain_over(unpersisted);
    assert_eq!(
        colliding_committed_cell(&rows, &pending.view_at_persisted_tip().snapshot()),
        None,
        "nothing is committed yet",
    );
    let base = Arc::new(unpersisted.clone());
    let (_, jmt_snapshot, _) = base.prepare_block_commit(
        ParentAnchor {
            state_root: base.state_root(),
            height: BlockHeight::GENESIS,
            state: &base.snapshot(),
            pending: &[],
            base_reads: None,
        },
        &[],
        ChainWrites {
            creations: &creations,
            removals: &[],
            sweep_frontier: SweepFrontier::ZERO,
            frontier: &FrontierInputs::still(ShardId::ROOT),
            state_claims: &[],
            members: &MemberInputs::still(ShardId::ROOT),
        },
        BlockHeight::new(1),
    );
    pending.insert(
        block.hash(),
        ChainEntry {
            parent_block_hash: block.header().parent_block_hash(),
            height: BlockHeight::new(1),
            settled_txs: Vec::new(),
            jmt_snapshot,
            certified_block: None,
        },
    );
    assert_eq!(
        colliding_committed_cell(
            &rows,
            &pending
                .view_at(block.hash(), BlockHeight::new(1))
                .snapshot()
        ),
        Some(marker),
        "a pending ancestor's marker is read through the overlay",
    );
    assert_eq!(unpersisted.jmt_height(), BlockHeight::GENESIS);
}

/// A prepared commit whose height the tree already reached refuses when
/// the store holds a *different* block there.
///
/// The benign cause of that skip is the same block going in twice — a
/// sync commit landing between prepare and flush, or a second vnode on
/// the store. A different block is a fork that reached the writer, and
/// skipping it would hand back a root for a block the store never
/// applied while the caller took the commit as done.
///
/// # Panics
///
/// By design, on the second commit: that is what the caller asserts.
pub fn test_prepared_commit_refuses_a_different_block_at_one_height<S>(storage: &Arc<S>)
where
    S: ShardChainReader + ShardChainWriter + SubstateStore,
{
    // Both prepared off the one parent, as two proposals at one height
    // are, then committed in turn.
    let prepare = || {
        let (_, _, commit) = storage.prepare_block_commit(
            ParentAnchor {
                state_root: storage.state_root(),
                height: BlockHeight::GENESIS,
                state: &storage.snapshot(),
                pending: &[],
                base_reads: None,
            },
            &[],
            ChainWrites {
                creations: &[],
                removals: &[],
                sweep_frontier: SweepFrontier::ZERO,
                frontier: &FrontierInputs::still(ShardId::ROOT),
                state_claims: &[],
                members: &MemberInputs::still(ShardId::ROOT),
            },
            BlockHeight::new(1),
        );
        commit
    };

    let first = make_test_block_at(BlockHeight::new(1), 1_000);
    let other = make_test_block_at(BlockHeight::new(1), 2_000);
    assert_ne!(first.hash(), other.hash(), "the fixture builds two blocks");

    let (commit_first, commit_other) = (prepare(), prepare());
    commit_first(
        SyncHint::FlushNow,
        &make_test_certified(first),
        &empty_witness(),
    );
    commit_other(
        SyncHint::FlushNow,
        &make_test_certified(other),
        &empty_witness(),
    );
}

/// Shared: a prepared commit whose base root the store has moved off
/// applies nothing and answers with the root it computed.
///
/// The benign cause is the same block arriving twice — a synced copy, or
/// a co-hosted vnode's — so the batch is dropped rather than replayed
/// onto a store that already holds the block. The block carries a write,
/// because a root unchanged by an empty commit is the one case both
/// backends wave through on purpose.
///
/// # Panics
///
/// If the refused batch moved the store's root or its version.
pub fn test_prepared_commit_for_a_committed_block_applies_nothing<S>(storage: &Arc<S>)
where
    S: ShardChainReader + ShardChainWriter + SubstateStore + Clone,
{
    let tx = test_transaction(1);
    let block = with_transactions(
        make_test_block(BlockHeight::new(1)),
        vec![Arc::new(Verifiable::from(tx))],
    );
    let creations = committed_tx_cells(
        block.header().shard_id(),
        block.transactions().iter().map(|tx| tx.as_unverified()),
    );
    let (spec_root, _, prepared) = storage.prepare_block_commit(
        ParentAnchor {
            state_root: storage.state_root(),
            height: BlockHeight::GENESIS,
            state: &storage.snapshot(),
            pending: &[],
            base_reads: None,
        },
        &[],
        ChainWrites {
            creations: &creations,
            removals: &[],
            sweep_frontier: SweepFrontier::ZERO,
            frontier: &FrontierInputs::still(ShardId::ROOT),
            state_claims: &[],
            members: &MemberInputs::still(ShardId::ROOT),
        },
        BlockHeight::new(1),
    );

    // The block goes in by the other route first: the store now holds it,
    // at a root the prepared batch was not built on.
    let certified = make_test_certified(block);
    let direct = commit_settled_at(&**storage, &certified, &creations, &[], &empty_witness());
    let (height, root) = (storage.jmt_height(), storage.state_root());

    assert_eq!(
        prepared(SyncHint::FlushNow, &certified, &empty_witness()),
        spec_root,
        "the refused batch still answers with the root it computed",
    );
    assert_eq!(spec_root, direct, "and the two routes computed one root");
    assert_eq!(
        storage.jmt_height(),
        height,
        "the refusal advanced no version"
    );
    assert_eq!(storage.state_root(), root, "and wrote nothing");
}

/// Commit a block at `height` carrying one provision bundle, and return
/// the bundle's hash. The bundle's transaction varies with the height, so
/// each block's bundle has its own identity.
fn commit_block_with_provisions(
    storage: &impl TestStore,
    height: u64,
    step_ms: u64,
) -> ProvisionHash {
    let seed = u8::try_from(height).expect("small fixture");
    let block = with_provisions(
        make_test_block_at(BlockHeight::new(height), height * step_ms),
        ShardId::leaf(1, 1),
        TxHash::from(Hash::from_bytes(&[seed; 32])),
    );
    let hash = block
        .provisions()
        .first()
        .expect("the block carries one")
        .hash();
    commit_settled_at(
        storage,
        &make_test_certified(block),
        &[],
        &[],
        &empty_witness(),
    );
    hash
}

/// Shared recovery test: a durable lock comes back with the certificate
/// that justifies it.
///
/// A validator refuses to vote for a block whose `parent_qc` sits below
/// `locked_round`. A record that keeps the round and drops the
/// certificate therefore describes a position nothing can satisfy: every
/// proposal extends a lower QC, and the QC that would raise the lock can
/// only form out of the votes being refused.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_registers_recover_their_justification(
    storage: &impl SafeVoteRegisterStore,
    recovered: impl Fn() -> RecoveredState,
) {
    let validator = ValidatorId::new(1);
    let certified = make_test_block(BlockHeight::new(4));
    let justification = make_test_qc(&certified);
    let locked = SafeVoteRegisters {
        locked_round: Round::new(6),
        last_voted_round: Round::new(7),
        high_qc: Some((*justification).clone()),
        high_tc: None,
    };
    storage.persist_vote_position(
        validator,
        &VotePosition {
            registers: locked,
            justification: vec![Arc::new(certified.clone())],
        },
    );

    assert_eq!(
        storage
            .safe_vote_registers(validator)
            .and_then(|r| r.high_qc),
        Some((*justification).clone()),
        "the lock's justification is part of the record",
    );
    assert_eq!(
        storage
            .voted_blocks_above(BlockHeight::new(3))
            .iter()
            .map(|b| b.hash())
            .collect::<Vec<_>>(),
        vec![certified.hash()],
        "the certificate's block is stored beside the record that names it",
    );
    assert!(
        storage.voted_blocks_above(BlockHeight::new(4)).is_empty(),
        "a block the chain has committed is the chain's to keep",
    );

    // A later write that raises nothing keeps the justification: the
    // certificate travels with the higher lock, not with the newer write.
    storage.persist_vote_position(
        validator,
        &VotePosition {
            registers: SafeVoteRegisters {
                locked_round: Round::new(2),
                last_voted_round: Round::new(9),
                high_qc: None,
                high_tc: None,
            },
            justification: Vec::new(),
        },
    );
    let merged = recovered()
        .safe_vote_registers
        .get(&validator)
        .cloned()
        .expect("the record survives into recovery");
    assert_eq!(merged.locked_round, Round::new(6));
    assert_eq!(merged.last_voted_round, Round::new(9));
    assert_eq!(
        merged.high_qc,
        Some((*justification).clone()),
        "a write that lowers the lock cannot strip the justification off it",
    );
    assert_eq!(
        recovered()
            .voted_blocks
            .iter()
            .map(|b| b.hash())
            .collect::<Vec<_>>(),
        vec![certified.hash()],
        "recovery hands back what the record's certificate names",
    );
}

/// Shared recovery test: the committed tip's drain total comes back off
/// its stored header.
///
/// A block extending the tip claims a total the vote path checks against
/// the parent's, and skips the vote when it cannot resolve one. A replica
/// that recovers no total therefore cannot vote until a commit reseats it
/// — and a commit needs a quorum it is part of, so a shard where enough
/// replicas restart together never forms one.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_recovery_carries_the_tip_drain_total(
    storage: &impl TestStore,
    recovered: impl Fn() -> RecoveredState,
) {
    let in_flight = TxsInFlight::new(7);
    let mut block = make_test_block(BlockHeight::new(1));
    let Block::Live { header, .. } = &mut block else {
        panic!("the fixture builds a live block");
    };
    *header = BlockHeader::new(BlockHeaderParts {
        height: header.height(),
        parent_block_hash: header.parent_block_hash(),
        parent_qc: header.parent_qc().clone().into(),
        timestamp: header.timestamp(),
        txs_in_flight: in_flight,
        ..Default::default()
    });
    commit_settled_at(
        storage,
        &make_test_certified(block),
        &[],
        &[],
        &empty_witness(),
    );

    assert_eq!(
        recovered().committed_tip.map(|tip| tip.txs_in_flight),
        Some(in_flight),
        "the tip's drain total is on its stored header, so recovery reads it",
    );
}

/// Shared retention test: sealing a block keeps its bundles' hashes and
/// drops their bodies, so the bodies live beside it and a restart reads
/// them back.
///
/// `recovered` loads recovered state the way the backend does — the
/// `RocksDB` caller reopens the store first, which is the crossing the
/// bodies have to survive.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_committed_bundle_outlives_sealing(
    storage: &(impl ShardChainReader + TestStore),
    recovered: impl Fn() -> RecoveredState,
) {
    let hash = commit_block_with_provisions(storage, 1, 1_000);

    assert!(
        storage
            .get_block(BlockHeight::new(1))
            .expect("the block committed")
            .block()
            .provisions()
            .is_empty(),
        "the stored block is sealed and carries no bodies",
    );
    assert_eq!(
        recovered()
            .retained_provisions
            .iter()
            .map(|bundle| bundle.hash())
            .collect::<Vec<_>>(),
        vec![hash],
        "and the body it dropped is recovered from storage",
    );
}

/// Shared sweep test: a body outlives the depth a replay could start
/// from, and no longer.
///
/// The floor is the history retention floor — below it `snapshot_at`
/// cannot serve the baseline a replayed tick reads, so a body kept there
/// could never be replayed against. The chain is paced so `blocks` of it
/// fit inside the retention horizon, which is what fixes where the floor
/// stands: a chain running faster keeps more versions and one running
/// slower keeps fewer, and the count is a consequence of the pace rather
/// than a setting.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_retained_bundle_drops_below_the_history_floor(
    storage: &(impl ShardChainReader + TestStore),
    blocks: u64,
    recovered: impl Fn() -> RecoveredState,
) {
    let step_ms = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX) / blocks;
    let first = commit_block_with_provisions(storage, 1, step_ms);
    for height in 2..=blocks + 1 {
        commit_block_with_provisions(storage, height, step_ms);
    }
    assert!(
        recovered()
            .retained_provisions
            .iter()
            .any(|bundle| bundle.hash() == first),
        "at the floor the body is still readable",
    );

    commit_block_with_provisions(storage, blocks + 2, step_ms);
    let retained = recovered().retained_provisions;
    assert!(
        !retained.iter().any(|bundle| bundle.hash() == first),
        "past it the sweep drops it",
    );
    assert_eq!(
        retained.len() as u64,
        blocks + 1,
        "and keeps the readable window, plus the block of slack at its floor",
    );
}

/// Shared rebuild test: a replica that lost its execution state replays
/// the chain and names exactly the transactions it committed and never
/// resolved.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_unresolved_fold(storage: &(impl ShardChainReader + TestStore)) {
    let resolved = test_transaction(1);
    let open = test_transaction(2);
    let source = ShardId::leaf(1, 1);

    // An empty block below everything, whose clock the window carries.
    commit_empty_blocks_below(storage, BlockHeight::new(2));
    let committing = with_transactions(
        make_test_block(BlockHeight::new(2)),
        vec![
            Arc::new(Verifiable::from(resolved.clone())),
            Arc::new(Verifiable::from(open.clone())),
        ],
    );
    commit_settled_at(
        storage,
        &make_test_certified(committing),
        &[],
        &[],
        &empty_witness(),
    );

    // A counterpart's bundle for the one that stays open, so the sealed
    // block below is read against a height that actually carried one.
    let provisioning = with_provisions(make_test_block(BlockHeight::new(3)), source, open.hash());
    commit_settled_at(
        storage,
        &make_test_certified(provisioning),
        &[],
        &[],
        &empty_witness(),
    );

    // Only one of them gets an outcome. An abort resolves a transaction
    // exactly as a settlement does, and owes no receipt — which is what
    // lets the rebuilt block carry it on every backend.
    let resolving = push_certificate(
        make_test_block(BlockHeight::new(4)),
        Arc::new(Verifiable::from(make_finalization(
            BlockHeight::new(4),
            resolved.hash(),
            TransactionDecision::Aborted,
        ))),
    );
    commit_settled_at(
        storage,
        &make_test_certified(resolving),
        &[],
        &[],
        &empty_witness(),
    );

    // The floor is the height that committed the one still open. The
    // one resolved at height 4 committed there too, and does not hold
    // the floor down: an outcome is what releases it.
    assert_eq!(
        unresolved_replay_floor(
            storage,
            BlockHeight::new(4),
            WeightedTimestamp::ZERO,
            ChainOrigin::ROOT
        ),
        Some(BlockHeight::new(2)),
        "the replay starts at the block committing what is still owed",
    );
    assert!(
        storage
            .get_block(BlockHeight::new(3))
            .expect("committed")
            .block()
            .provisions()
            .is_empty(),
        "a stored block keeps its bundles' hashes, not their contents",
    );

    // And the window puts them back, so replaying it composes the leg
    // rather than waiting on evidence nothing will send again.
    assert_replayed_window(storage);
}

/// What the window hands back: every block from the floor to the tip, in
/// the shape a commit runs on, with the clock below it and the bundles
/// sealing dropped reattached.
fn assert_replayed_window(storage: &(impl ShardChainReader + TestStore)) {
    let window = replay_window(
        storage,
        BlockHeight::new(4),
        WeightedTimestamp::ZERO,
        BlockHeight::GENESIS,
        ChainOrigin::ROOT,
    );
    let heights: Vec<BlockHeight> = window
        .blocks
        .iter()
        .map(|certified| certified.block().height())
        .collect();
    assert_eq!(
        heights,
        vec![
            BlockHeight::new(2),
            BlockHeight::new(3),
            BlockHeight::new(4)
        ],
        "opening at the floor and running to the tip",
    );
    assert_eq!(
        window.anchor_wt,
        Some(WeightedTimestamp::ZERO),
        "carrying the clock of the block below it, so the first block replayed keeps the carry",
    );
    assert_eq!(
        window.dispatch_from,
        BlockHeight::new(2),
        "with nothing retired, composition starts where the fold does",
    );
    assert_compose_floor_follows_retention(storage);
    assert_eq!(
        window.blocks[1]
            .block()
            .provisions()
            .iter()
            .map(|p| p.hash())
            .collect::<Vec<_>>(),
        storage
            .provisions_at(BlockHeight::new(3))
            .iter()
            .map(|p| p.hash())
            .collect::<Vec<_>>(),
        "with the bodies sealing dropped reattached",
    );

    // Every one of them live, including the floor — which carried no
    // bundles at all. A sealed block owes nothing and composes nothing,
    // so a window handing one back would skip the very transaction that
    // put the block in the window.
    assert!(
        window
            .blocks
            .iter()
            .all(|certified| certified.block().is_live()),
        "a replayed block arrives in the shape a commit runs on, bundles or not",
    );
}

/// A store that has retired history below the replay floor still folds
/// the whole window and composes only above what it can anchor: a tick
/// at height `H` reads its baseline at `H - 1`, so a floor at 2 puts the
/// first composable tick at 3.
fn assert_compose_floor_follows_retention(storage: &impl ShardChainReader) {
    let retired = replay_window(
        storage,
        BlockHeight::new(4),
        WeightedTimestamp::ZERO,
        BlockHeight::new(2),
        ChainOrigin::ROOT,
    );
    assert_eq!(
        retired.blocks.len(),
        3,
        "the fold's reach is what is owed an outcome, whatever the store retired",
    );
    assert_eq!(
        retired.dispatch_from,
        BlockHeight::new(3),
        "and composition starts at the first height whose baseline is readable",
    );
}

/// Shared rebuild test: a replay starts low enough to seat every tick a
/// finalization it dispatches from settles, with the members that
/// finalization names, though nothing there is owed at the tip.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_settled_tick_pulls_the_replay_down(storage: &(impl ShardChainReader + TestStore)) {
    let settled = test_transaction(1);
    let open = test_transaction(2);
    let witness = empty_witness();
    commit_empty_blocks_below(storage, BlockHeight::new(2));

    // The settled member commits at 2 and is seated in the tick at 3; the
    // open one commits at 4; the tick's finalization commits at 5.
    let committing = with_transactions(
        make_test_block(BlockHeight::new(2)),
        vec![Arc::new(Verifiable::from(settled.clone()))],
    );
    commit_settled_at(
        storage,
        &make_test_certified(committing),
        &[],
        &[],
        &witness,
    );
    let seating = make_test_certified(make_test_block(BlockHeight::new(3)));
    commit_settled_at(storage, &seating, &[], &[], &witness);
    let owing = with_transactions(
        make_test_block(BlockHeight::new(4)),
        vec![Arc::new(Verifiable::from(open))],
    );
    commit_settled_at(storage, &make_test_certified(owing), &[], &[], &witness);
    let settling = push_certificate(
        make_test_block(BlockHeight::new(5)),
        Arc::new(Verifiable::from(make_finalization(
            BlockHeight::new(3),
            settled.hash(),
            TransactionDecision::Aborted,
        ))),
    );
    commit_settled_at(storage, &make_test_certified(settling), &[], &[], &witness);

    let window = |retention_floor: u64| {
        let window = replay_window(
            storage,
            BlockHeight::new(5),
            WeightedTimestamp::ZERO,
            BlockHeight::new(retention_floor),
            ChainOrigin::ROOT,
        );
        let first = window
            .blocks
            .first()
            .map(|certified| certified.block().height());
        (first, window.dispatch_from)
    };
    assert_eq!(
        unresolved_replay_floor(
            storage,
            BlockHeight::new(5),
            WeightedTimestamp::ZERO,
            ChainOrigin::ROOT
        ),
        Some(BlockHeight::new(4)),
        "fixture precondition: only the open transaction is owed",
    );
    assert_eq!(
        window(0),
        (Some(BlockHeight::new(2)), BlockHeight::new(4)),
        "the replay reaches the settled member's commit, below its tick, and dispatches \
         from what is owed",
    );
    assert_eq!(
        window(4),
        (Some(BlockHeight::new(2)), BlockHeight::new(5)),
        "a finalization committed where the replay dispatches still pulls it down",
    );
    assert_eq!(
        window(5),
        (Some(BlockHeight::new(4)), BlockHeight::new(6)),
        "one the first dispatched baseline already carries does not",
    );
}

/// Shared rebuild test: an undischarged record holds the replay floor.
///
/// It does so from a window of its own — the transaction it names
/// committed arbitrarily far below, so the record is what a rebuild has to
/// reach.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_undischarged_record_holds_the_floor(storage: &(impl ShardChainReader + TestStore)) {
    let stranded = test_transaction(3);
    let record = AbandonmentRecord::new(
        ShardId::leaf(1, 1),
        WeightedTimestamp::from_millis(1_000),
        [UnsettledTx {
            tx_hash: stranded.hash(),
            deadline: Deadline::of(WeightedTimestamp::from_millis(500)),
            charged: stranded.price(&PriceTable::GENESIS),
            charge: AbortCharge {
                vault: stranded.fee_vault(),
                amount: stranded.price(&PriceTable::GENESIS),
            },
            committed: CommittedAt {
                height: BlockHeight::new(1),
                anchor: WeightedTimestamp::from_millis(100),
                committee_anchor: WeightedTimestamp::from_millis(100),
            },
            reach: stranded.routing().all_routes(),
        }],
    );

    // The record commits without its transaction ever appearing: the block
    // that carried it is below anything this chain holds, which is the
    // rebuild the record exists to repair.
    commit_empty_blocks_below(storage, BlockHeight::new(2));
    let naming = with_abandonment(make_test_block(BlockHeight::new(2)), record);
    commit_settled_at(
        storage,
        &make_test_certified(naming),
        &[],
        &[],
        &empty_witness(),
    );
    commit_settled_at(
        storage,
        &make_test_certified(make_test_block(BlockHeight::new(3))),
        &[],
        &[],
        &empty_witness(),
    );

    assert_eq!(
        unresolved_replay_floor(
            storage,
            BlockHeight::new(3),
            WeightedTimestamp::ZERO,
            ChainOrigin::ROOT
        ),
        Some(BlockHeight::new(2)),
        "the replay opens at the record, which is where the entry comes from",
    );

    // The abort discharges it, and the floor lifts with it.
    let aborting = push_certificate(
        make_test_block(BlockHeight::new(4)),
        Arc::new(Verifiable::from(make_finalization(
            BlockHeight::new(4),
            stranded.hash(),
            TransactionDecision::Aborted,
        ))),
    );
    commit_settled_at(
        storage,
        &make_test_certified(aborting),
        &[],
        &[],
        &empty_witness(),
    );

    assert_eq!(
        unresolved_replay_floor(
            storage,
            BlockHeight::new(4),
            WeightedTimestamp::ZERO,
            ChainOrigin::ROOT
        ),
        None,
        "a discharged record holds nothing down",
    );
}

/// Shared rebuild test: a leg entry holds the replay floor to its own
/// horizon.
///
/// A whole entry's fate is decided inside [`RETENTION_HORIZON`] of its
/// commit, and that is as far as a rebuild reads for one. A leg entry
/// stands one [`CLAIM_WINDOW`] past its deadline, so its commit sits
/// below that reach while the entry is still live, and the fold has to
/// reach it, or a restart drops an entry the ledger still holds.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_leg_entry_holds_the_floor_to_its_horizon(
    storage: &(impl ShardChainReader + TestStore),
) {
    let leg = test_transaction(5);
    let committed_ms = 1_000;

    commit_empty_blocks_below(storage, BlockHeight::new(1));
    let committing = with_transactions(
        make_test_block_with_anchor_wt(BlockHeight::new(1), committed_ms),
        vec![Arc::new(Verifiable::from(leg.clone()))],
    );
    commit_settled_at(
        storage,
        &make_test_certified(committing),
        &[],
        &[],
        &empty_witness(),
    );
    let settling = push_certificate(
        make_test_block_with_anchor_wt(BlockHeight::new(2), committed_ms + 1_000),
        Arc::new(Verifiable::from(make_leg_finalization(
            BlockHeight::new(2),
            leg.hash(),
        ))),
    );
    commit_settled_at(
        storage,
        &make_test_certified(settling),
        &[],
        &[],
        &empty_witness(),
    );

    let committed = WeightedTimestamp::from_millis(committed_ms);
    let past_retention = committed
        .plus(RETENTION_HORIZON)
        .plus(Duration::from_secs(1));
    assert_eq!(
        unresolved_replay_floor(
            storage,
            BlockHeight::new(2),
            past_retention,
            ChainOrigin::ROOT
        ),
        Some(BlockHeight::new(1)),
        "past the retention horizon a whole entry is gone, but a leg entry \
         stands, so its commit still holds the floor",
    );
    let past_horizon = past_retention.plus(CLAIM_WINDOW);
    assert_eq!(
        unresolved_replay_floor(
            storage,
            BlockHeight::new(2),
            past_horizon,
            ChainOrigin::ROOT
        ),
        None,
        "and past its own horizon nothing is owed, so nothing holds it down",
    );
}

/// Shared rebuild test: the replay floor stops at the chain's own origin.
///
/// A split child's `RocksDB` store is a hard-linked clone of its
/// parent's and carries the parent's whole chain under the child's
/// genesis height. Measured in time alone the walk reads those blocks as
/// this chain's and replays parts no peer seeded from the same clone
/// ever held; nothing below the origin is this chain's to owe.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_the_replay_floor_stops_at_the_chain_origin(
    storage: &(impl ShardChainReader + TestStore),
) {
    let inherited = test_transaction(6);
    let own = test_transaction(7);

    // Height 1 is the predecessor's: it commits a transaction no
    // certificate resolves, exactly what would hold the floor down.
    let below = with_transactions(
        make_test_block(BlockHeight::new(1)),
        vec![Arc::new(Verifiable::from(inherited))],
    );
    commit_settled_at(
        storage,
        &make_test_certified(below),
        &[],
        &[],
        &empty_witness(),
    );
    let above = with_transactions(
        make_test_block(BlockHeight::new(2)),
        vec![Arc::new(Verifiable::from(own))],
    );
    commit_settled_at(
        storage,
        &make_test_certified(above),
        &[],
        &[],
        &empty_witness(),
    );

    let origin = ChainOrigin {
        genesis_height: BlockHeight::new(2),
        anchor_wt: WeightedTimestamp::ZERO,
    };
    assert_eq!(
        unresolved_replay_floor(
            storage,
            BlockHeight::new(2),
            WeightedTimestamp::ZERO,
            origin
        ),
        Some(BlockHeight::new(2)),
        "the walk stops at the origin, so the predecessor's unresolved \
         transaction is not this chain's to replay",
    );
    assert_eq!(
        unresolved_replay_floor(
            storage,
            BlockHeight::new(2),
            WeightedTimestamp::ZERO,
            ChainOrigin::ROOT,
        ),
        Some(BlockHeight::new(1)),
        "and a chain that really does begin at the root reaches both",
    );
}

/// Shared rebuild test: a leg's own finalization does not retire it from
/// the replay floor.
///
/// Its entry is closed by the commit fold on the records it issued,
/// which no finalization names, so only a deciding outcome naming the
/// transaction releases the floor.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_legs_own_finalization_keeps_the_floor(storage: &(impl ShardChainReader + TestStore)) {
    let leg = test_transaction(4);

    commit_empty_blocks_below(storage, BlockHeight::new(1));
    let committing = with_transactions(
        make_test_block(BlockHeight::new(1)),
        vec![Arc::new(Verifiable::from(leg.clone()))],
    );
    commit_settled_at(
        storage,
        &make_test_certified(committing),
        &[],
        &[],
        &empty_witness(),
    );

    let settling = push_certificate(
        make_test_block(BlockHeight::new(2)),
        Arc::new(Verifiable::from(make_leg_finalization(
            BlockHeight::new(2),
            leg.hash(),
        ))),
    );
    commit_settled_at(
        storage,
        &make_test_certified(settling),
        &[],
        &[],
        &empty_witness(),
    );
    assert_eq!(
        unresolved_replay_floor(
            storage,
            BlockHeight::new(2),
            WeightedTimestamp::ZERO,
            ChainOrigin::ROOT
        ),
        Some(BlockHeight::new(1)),
        "a leg that succeeded is still unresolved, so its commit holds the floor",
    );

    let deciding = push_certificate(
        make_test_block(BlockHeight::new(3)),
        Arc::new(Verifiable::from(make_finalization(
            BlockHeight::new(3),
            leg.hash(),
            TransactionDecision::Aborted,
        ))),
    );
    commit_settled_at(
        storage,
        &make_test_certified(deciding),
        &[],
        &[],
        &empty_witness(),
    );
    assert_eq!(
        unresolved_replay_floor(
            storage,
            BlockHeight::new(3),
            WeightedTimestamp::ZERO,
            ChainOrigin::ROOT
        ),
        None,
        "a deciding finalization releases the floor",
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Backend conformance: what both stores answer identically
// ═══════════════════════════════════════════════════════════════════════

/// A fresh store holds nothing: no tree, no chain, no block.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_fresh_store_holds_nothing<S: TestStore + ShardChainReader>(storage: &S) {
    assert_eq!(storage.jmt_height(), BlockHeight::GENESIS);
    assert_eq!(storage.state_root(), StateRoot::ZERO);
    assert_eq!(storage.committed_head(), (BlockHeight::GENESIS, None));
    assert!(storage.latest_qc().is_none());
    assert!(storage.get_block(BlockHeight::new(999)).is_none());
    assert!(
        storage
            .get_transactions_batch(&[TxHash::from(Hash::from_bytes(&[1; 32]))])
            .is_empty()
    );
}

/// A committed cell reads back, and a snapshot keeps reading the version
/// it was taken at while the store moves on.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_committed_cell_reads_back_and_a_snapshot_keeps_its_version(storage: &impl TestStore) {
    let key = state_key(3, 10);
    assert!(storage.cell(key).is_none());
    commit_writes(storage, &make_settled_writes(3, 10, vec![1]));
    assert_eq!(storage.cell(key), Some(vec![1]));

    let snapshot = storage.snapshot();
    commit_writes(storage, &make_settled_writes(3, 10, vec![2]));
    assert_eq!(
        snapshot.cell(key),
        Some(vec![1]),
        "the snapshot is its version"
    );
    assert_eq!(storage.cell(key), Some(vec![2]));
}

/// Every commit advances the version — an empty one too — and one that
/// writes something moves the root.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_commits_advance_the_version_and_writes_move_the_root(storage: &impl TestStore) {
    let root0 = storage.state_root();
    commit_writes(storage, &make_settled_writes(1, 10, vec![1]));
    let root1 = storage.state_root();
    assert_eq!(storage.jmt_height(), BlockHeight::new(1));
    assert_ne!(root0, root1, "the first write moves the root");

    commit_writes(storage, &make_settled_writes(4, 20, vec![2]));
    let root2 = storage.state_root();
    assert_eq!(storage.jmt_height(), BlockHeight::new(2));
    assert_ne!(root1, root2, "the second write moves it again");

    commit_writes(storage, &SettledWrites::default());
    assert_eq!(
        storage.jmt_height(),
        BlockHeight::new(3),
        "an empty commit still advances the version"
    );
    assert_eq!(
        storage.state_root(),
        root2,
        "and leaves the root where it was"
    );
}

/// The root is a function of the writes: two stores committing the same
/// writes agree, and different writes disagree.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_the_root_is_a_function_of_the_writes<S: TestStore>(fresh: impl Fn() -> S) {
    let (same_a, same_b, other) = (fresh(), fresh(), fresh());
    let writes = make_settled_writes(1, 10, vec![42]);
    commit_writes(&same_a, &writes);
    commit_writes(&same_b, &writes);
    assert_eq!(same_a.state_root(), same_b.state_root());
    assert_eq!(same_a.jmt_height(), same_b.jmt_height());

    commit_writes(&other, &make_settled_writes(1, 10, vec![43]));
    assert_ne!(same_a.state_root(), other.state_root());
}

/// A committed block reads back by height and for sync, with the header
/// and certificate it carried.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_committed_block_reads_back<S: TestStore + ShardChainReader>(storage: &S) {
    let block = make_test_block(BlockHeight::new(1));
    assert!(storage.get_block(BlockHeight::new(1)).is_none());
    commit_settled_at(
        storage,
        &make_test_certified(block.clone()),
        &[],
        &[],
        &empty_witness(),
    );

    let stored = storage.get_block(BlockHeight::new(1)).expect("committed");
    assert_eq!(stored.block().height(), BlockHeight::new(1));
    assert_eq!(
        stored.block().header().timestamp(),
        ProposerTimestamp::from_millis(1_000)
    );
    assert_eq!(stored.qc().block_hash(), block.hash());

    let for_sync = storage
        .get_block_for_sync(BlockHeight::new(1))
        .expect("served");
    assert_eq!(for_sync.block.height(), BlockHeight::new(1));
    assert!(storage.get_block_for_sync(BlockHeight::new(999)).is_none());
}

/// A block carrying transaction `seed` and a finalization settling a
/// receipt for it.
fn block_with_a_settled_transaction(height: BlockHeight, seed: u8) -> Block {
    let tx = test_transaction(seed);
    let tx_hash = tx.hash();
    let block = with_transactions(
        make_test_block(height),
        vec![Arc::new(Verifiable::from(
            Verified::<Transaction>::from_persisted(tx),
        ))],
    );
    push_certificate(
        block,
        Arc::new(make_finalization_leaving(height, tx_hash, StateWrites::default()).into()),
    )
}

/// `certified` reads back from `storage` through both full-block readers
/// as exactly its sealed form: the same encoded block, the same QC, and
/// its provision hashes beside it for sync.
fn assert_reads_back_sealed<S: ShardChainReader>(storage: &S, certified: &CertifiedBlock) {
    let height = certified.block().height();
    let expected = certified.block().clone().into_sealed();
    let expected_block = to_vec(&expected).expect("a block encodes");
    let expected_qc = to_vec(certified.qc()).expect("a QC encodes");

    let stored = storage.get_block(height).expect("the block rebuilds");
    assert_eq!(
        to_vec(stored.block()).expect("a block encodes"),
        expected_block,
        "the block reads back as its sealed form",
    );
    assert_eq!(to_vec(stored.qc()).expect("a QC encodes"), expected_qc);

    let served = storage
        .get_block_for_sync(height)
        .expect("the block serves");
    assert_eq!(
        to_vec(&served.block).expect("a block encodes"),
        expected_block,
        "and serves as its sealed form",
    );
    assert_eq!(to_vec(&served.qc).expect("a QC encodes"), expected_qc);
    assert_eq!(
        served.provision_hashes,
        expected.provision_hashes().into_inner()
    );
}

/// A committed block and a historically imported one read back through
/// both full-block readers as exactly their sealed form.
///
/// Each carries a transaction and a finalization settling its receipt.
/// Every backend rebuilds a block from the same rows through the same
/// reconstruction, so passing on each backend is reading back
/// identically on all of them.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_committed_and_imported_blocks_read_back_sealed<S>(committing: &S, importing: &S)
where
    S: TestStore + ShardChainReader + BoundaryStore,
{
    let committed = make_test_certified(block_with_a_settled_transaction(BlockHeight::new(1), 1));
    commit_settled_at(committing, &committed, &[], &[], &empty_witness());
    assert_reads_back_sealed(committing, &committed);

    let imported = make_test_certified(block_with_a_settled_transaction(BlockHeight::new(4), 2));
    importing.import_historical_block(&imported);
    assert_reads_back_sealed(importing, &imported);
}

/// A stored block keeps its terms section byte for byte on both
/// full-block readers, committed or historically imported, under the
/// root its header commits.
///
/// The section rides the metadata row the block's manifest is kept in,
/// which every backend rebuilds a block from through the same
/// reconstruction.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_stored_block_keeps_its_terms<S>(committing: &S, importing: &S)
where
    S: TestStore + ShardChainReader + BoundaryStore,
{
    let stating_terms = |height: u64, seed: u8| {
        let block = block_with_a_settled_transaction(BlockHeight::new(height), seed);
        let tx = block.transactions()[0].hash();
        make_test_certified(rebound(stating(block, vec![stub_stated_terms(tx, seed)])))
    };
    let assert_keeps = |storage: &S, certified: &CertifiedBlock| {
        let height = certified.block().height();
        let stated = to_vec(certified.block().terms()).expect("a terms section encodes");
        assert_eq!(certified.block().terms().len(), 1);
        assert_reads_back_sealed(storage, certified);
        let stored = storage.get_block(height).expect("the block rebuilds");
        let served = storage
            .get_block_for_sync(height)
            .expect("the block serves");
        for block in [stored.block(), &served.block] {
            assert_eq!(
                to_vec(block.terms()).expect("a terms section encodes"),
                stated
            );
            assert_eq!(block.check_body_bound(), Ok(()));
        }
    };

    let committed = stating_terms(1, 1);
    commit_settled_at(committing, &committed, &[], &[], &empty_witness());
    assert_keeps(committing, &committed);

    let imported = stating_terms(4, 2);
    importing.import_historical_block(&imported);
    assert_keeps(importing, &imported);
}

/// The receipts a block's ticks settled reach state — one receipt, two,
/// or none.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_committed_receipts_reach_state(storage: &impl TestStore) {
    let root = commit_writes(storage, &make_settled_writes(1, 10, vec![42]));
    assert_ne!(root, StateRoot::ZERO);
    assert_eq!(storage.cell(state_key(1, 10)), Some(vec![42]));

    let merged = union_of(&[
        make_settled_writes(2, 20, vec![1]),
        make_settled_writes(3, 30, vec![2]),
    ]);
    commit_writes(storage, &merged);
    assert_eq!(storage.cell(state_key(2, 20)), Some(vec![1]));
    assert_eq!(storage.cell(state_key(3, 30)), Some(vec![2]));

    commit_writes(storage, &SettledWrites::default());
    assert_eq!(storage.jmt_height(), BlockHeight::new(3));
}

/// The per-version substate byte total: inserts raise it, value updates
/// leave it, deletes lower it, and every version's total stays
/// readable.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_substate_bytes_track_commits<S: TestStore + VersionedStore>(storage: &S) {
    commit_writes(
        storage,
        &union_of(&[
            make_settled_writes(3, 7, vec![1]),
            make_settled_writes(4, 8, vec![2]),
        ]),
    );
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(1)), Some(2));

    commit_writes(storage, &make_settled_writes(3, 7, vec![9]));
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(2)), Some(2));

    commit_writes(storage, &make_state_delete(3, 7));
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(3)), Some(1));
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(1)), Some(2));
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(4)), None);
}

/// History walk-through: a key created at V1, deleted at V2, recreated
/// at V3 reads back correctly at every version — the "smallest history
/// entry after V" rule end to end.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_history_reads_through_create_delete_create<S: TestStore + VersionedStore>(storage: &S) {
    let key = state_key(7, 42);
    // A second key stays alive throughout so the tree never empties out;
    // the history behaviour under test is independent of it.
    let anchor = make_settled_writes(99, 0xFF, vec![0xFF]);
    commit_writes(
        storage,
        &union_of(&[make_settled_writes(7, 42, vec![0xAA]), anchor]),
    );
    commit_writes(storage, &make_state_delete(7, 42));
    commit_writes(storage, &make_settled_writes(7, 42, vec![0xBB]));

    let expected: &[(u64, Option<Vec<u8>>)] = &[
        (0, None),
        (1, Some(vec![0xAA])),
        (2, None),
        (3, Some(vec![0xBB])),
    ];
    for (version, want) in expected {
        let got = storage.snapshot_at(BlockHeight::new(*version)).cell(key);
        assert_eq!(&got, want, "history read at V={version}");
    }
}

/// A historical read answers the value at that version, `Some(None)`
/// for a cell absent there, and `None` for a height the store does not
/// hold.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_historical_reads_resolve_per_version(storage: &impl TestStore) {
    let key = state_key(1, 10);
    let root_v1 = commit_writes(storage, &make_settled_writes(1, 10, vec![100]));
    let root_v2 = commit_writes(storage, &make_settled_writes(1, 10, vec![200]));
    assert_ne!(root_v1, root_v2);

    assert_eq!(
        storage.get_substate_at_height(key, BlockHeight::new(1)),
        Some(Some(vec![100]))
    );
    assert_eq!(
        storage.get_substate_at_height(key, BlockHeight::new(2)),
        Some(Some(vec![200]))
    );
    assert_eq!(
        storage.get_substate_at_height(state_key(99, 10), BlockHeight::new(1)),
        Some(None),
        "an unwritten cell reads as absent, not as an unavailable height",
    );
    assert!(
        storage
            .get_substate_at_height(key, BlockHeight::new(99))
            .is_none(),
        "a future height is unavailable",
    );
}

/// Ten empty commits paced two to the horizon, so the tip at 10 floors
/// at 8; then `snapshot_at(1)`, which the backend's test expects to
/// panic — the DA-assumption guard for internal callers.
///
/// # Panics
///
/// Always: that is what the caller asserts.
pub fn test_snapshot_at_below_the_floor_panics<S: TestStore + VersionedStore>(storage: &S) {
    for height in 1..=10u64 {
        commit_writes_at(storage, &SettledWrites::default(), paced(height, 2));
    }
    let _snapshot = storage.snapshot_at(BlockHeight::new(1));
}

/// A historical read of a height outside retention answers `None`
/// rather than panicking: the external-facing spelling.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_historical_reads_respect_retention(storage: &impl TestStore) {
    let key = SubstateKey {
        owner: Address::new([9u8; 31], AddressClass::Component),
        local: LocalKey([1u8; 16]),
    };
    for height in 1..=10u64 {
        let value = vec![u8::try_from(height).expect("small fixture")];
        commit_writes_at(
            storage,
            &SettledWrites::from_absolutes(BTreeMap::from([(key, Some(value))])),
            paced(height, 2),
        );
    }
    // Two blocks fit the horizon, so a tip at 10 floors at 8.
    assert_eq!(
        storage.get_substate_at_height(key, BlockHeight::new(9)),
        Some(Some(vec![9])),
        "a height within retention is served",
    );
    assert!(
        storage
            .get_substate_at_height(key, BlockHeight::new(1))
            .is_none(),
        "a height below the floor is not",
    );
    assert!(
        storage
            .get_substate_at_height(key, BlockHeight::new(99))
            .is_none(),
        "nor is one above the tip",
    );
}

/// Witness retention follows the commit-carried floor with one window
/// of hysteresis, and recovery rebuilds the accumulator window from the
/// tip header's base — entries below it are serving stock only.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_witness_window_retention_and_recovery<S: TestStore + ShardChainReader>(
    storage: &S,
    recovered: impl Fn() -> RecoveredState,
) {
    let deposits: Vec<_> = (0u64..6).map(stake_deposit).collect();

    // Window [0, 4): all four leaves appended, nothing pruned.
    commit_block_with_witness_window(
        storage,
        BlockHeight::new(1),
        0,
        &deposits[0..4],
        &deposits[0..4],
        None,
    );
    // Window [2, 6): the tail appends, persisted floor untouched.
    commit_block_with_witness_window(
        storage,
        BlockHeight::new(2),
        2,
        &deposits[2..6],
        &deposits[4..6],
        None,
    );
    // Window [4, 6): the base advance carries the previous window's
    // base as the persisted floor — leaves below 2 drop, [2, 4) stays
    // as hysteresis stock.
    commit_block_with_witness_window(
        storage,
        BlockHeight::new(3),
        4,
        &deposits[4..6],
        &[],
        Some(BeaconWitnessLeafCount::new(2)),
    );

    // A read spanning the dropped range comes back short; the retained
    // hysteresis range answers in full.
    assert_eq!(storage.get_beacon_witness_payload_range(0, 6).len(), 4);
    assert_eq!(
        storage.get_beacon_witness_payload_range(2, 6),
        deposits[2..6].to_vec(),
    );

    // Recovery starts the accumulator window at the tip's base.
    let recovered = recovered();
    assert_eq!(
        recovered.beacon_witness_start,
        BeaconWitnessLeafCount::new(4)
    );
    let expected: Vec<_> = deposits[4..6]
        .iter()
        .map(ShardWitnessPayload::leaf_hash)
        .collect();
    assert_eq!(recovered.beacon_witness_leaf_hashes, expected);
}

/// Safe-vote registers locked at `locked`, last voted at `last_voted`,
/// with no justification.
#[must_use]
pub const fn registers(locked: u64, last_voted: u64) -> SafeVoteRegisters {
    SafeVoteRegisters {
        locked_round: Round::new(locked),
        last_voted_round: Round::new(last_voted),
        high_qc: None,
        high_tc: None,
    }
}

/// A signing position carrying `r` and one justification block — a
/// vote's shape, so a test over the record covers the blocks written
/// beside it too.
#[must_use]
pub fn position(r: SafeVoteRegisters) -> VotePosition {
    VotePosition {
        registers: r,
        justification: vec![Arc::new(make_test_block(BlockHeight::new(4)))],
    }
}

/// Register writes merge field-wise max, so a lower or mixed write can
/// never regress either register, and recovery hands the merge back.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_registers_are_monotone_and_recoverable(
    storage: &impl SafeVoteRegisterStore,
    recovered: impl Fn() -> RecoveredState,
) {
    let validator = ValidatorId::new(1);
    storage.persist_vote_position(validator, &position(registers(4, 6)));
    storage.persist_vote_position(validator, &position(registers(2, 9)));
    assert_eq!(
        storage.safe_vote_registers(validator),
        Some(registers(4, 9))
    );
    assert_eq!(
        recovered().safe_vote_registers.get(&validator),
        Some(&registers(4, 9))
    );
}

/// A record written under a different chain origin is invisible to
/// reads and recovery.
///
/// A checkpoint-seeded child store inherits the parent's records but
/// must not apply them to the child chain's unrelated round numbering.
/// The next write starts a fresh record under the new origin.
/// `set_origin` moves the store's recorded origin the way the backend
/// records one.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_registers_ignore_a_stale_chain_incarnation(
    storage: &impl SafeVoteRegisterStore,
    set_origin: impl Fn(ChainOrigin),
    recovered: impl Fn() -> RecoveredState,
) {
    let validator = ValidatorId::new(1);
    storage.persist_vote_position(validator, &position(registers(8, 8)));
    set_origin(ChainOrigin {
        genesis_height: BlockHeight::new(11),
        anchor_wt: WeightedTimestamp::from_millis(999),
    });

    assert_eq!(storage.safe_vote_registers(validator), None);
    let recovered = recovered();
    assert!(recovered.safe_vote_registers.is_empty());
    assert!(
        recovered.voted_blocks.is_empty(),
        "a block justifying a lock on another chain justifies nothing here",
    );

    storage.persist_vote_position(validator, &position(registers(1, 2)));
    assert_eq!(
        storage.safe_vote_registers(validator),
        Some(registers(1, 2))
    );
    assert_eq!(storage.voted_blocks_above(BlockHeight::new(3)).len(), 1);
}

/// A store rebuilt in place of another takes over the rounds signed on
/// it, durably and into the state its coordinators boot from.
///
/// A coordinator seated there then refuses the rounds the replaced store
/// consumed. The certificate and the blocks beside the record stay
/// behind, and a validator the replaced store never recorded gains no
/// record. `recovered` is the rebuilt store's state before the carry.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_rebuilt_store_carries_signed_rounds(
    replaced: &impl SafeVoteRegisterStore,
    rebuilt: &impl SafeVoteRegisterStore,
    mut recovered: RecoveredState,
) {
    let signer = ValidatorId::new(1);
    let silent = ValidatorId::new(2);

    recovered.carry_signed_rounds(replaced, rebuilt);
    assert!(
        recovered.safe_vote_registers.is_empty() && rebuilt.all_safe_vote_registers().is_empty(),
        "a replaced store that recorded nothing hands nothing over",
    );

    let certified = make_test_block(BlockHeight::new(4));
    replaced.persist_vote_position(
        signer,
        &VotePosition {
            registers: SafeVoteRegisters {
                locked_round: Round::new(6),
                last_voted_round: Round::new(7),
                high_qc: Some((*make_test_qc(&certified)).clone()),
                high_tc: None,
            },
            justification: vec![Arc::new(certified)],
        },
    );
    recovered.carry_signed_rounds(replaced, rebuilt);

    assert_eq!(
        rebuilt.safe_vote_registers(signer),
        Some(registers(6, 7)),
        "the rebuilt store holds the rounds signed on the one it replaces",
    );
    assert_eq!(
        recovered.safe_vote_registers.get(&signer),
        Some(&registers(6, 7)),
        "the state a coordinator boots from floors its registers at them",
    );
    assert!(
        rebuilt.voted_blocks_above(BlockHeight::GENESIS).is_empty(),
        "the replaced store's uncommitted blocks are not the rebuilt chain's",
    );
    assert_eq!(rebuilt.safe_vote_registers(silent), None);
    assert!(!recovered.safe_vote_registers.contains_key(&silent));

    // A signature on the rebuilt store ratchets the carried record like
    // any other, and a second carry never lowers it.
    rebuilt.persist_vote_position(signer, &position(registers(6, 9)));
    recovered.carry_signed_rounds(replaced, rebuilt);
    assert_eq!(rebuilt.safe_vote_registers(signer), Some(registers(6, 9)));
}

/// A committed cell that self-identifies as a package lands in the
/// artifact index; an ordinary cell beside it does not.
///
/// The judgement is the installed statics', so the stub's marker stands
/// in for a package. Returns the artifact, for a backend's own tail.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_package_cell_lands_in_the_artifact_index<S: TestStore + PackageArtifactStore>(
    storage: &S,
) -> Vec<u8> {
    install_stub_protocol_statics();
    let artifact = vec![7u8; 64];
    let mut cells = BTreeMap::from([(state_key(1, STUB_PACKAGE_MARKER), Some(artifact.clone()))]);
    cells.insert(state_key(1, 10), Some(vec![9, 9, 9]));
    commit_writes(storage, &SettledWrites::from_absolutes(cells));
    assert_eq!(
        storage.package_artifacts(),
        vec![artifact.clone()],
        "the package-marked cell is indexed; the ordinary cell is not"
    );
    artifact
}

fn beacon_vote1(epoch: u64, view: u32, tag: u8) -> BeaconVote {
    BeaconVote::pc_vote1(
        Epoch::new(epoch),
        SpcView::new(view),
        &PcVector::new([PcValueElement::new([tag; 32])]),
    )
}

/// Shared beacon vote register test: a slot is taken once.
///
/// The same content re-signs, different content is refused, each
/// validator holds its own slots, and a newer epoch supersedes the
/// record while an older one is refused.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_beacon_vote_register_takes_a_slot_once<S: BeaconVoteRegisterStore>(store: &S) {
    let (v, w) = (ValidatorId::new(1), ValidatorId::new(2));
    assert!(store.admit_beacon_vote(v, &beacon_vote1(5, 1, 0xA)));
    assert!(
        store.admit_beacon_vote(v, &beacon_vote1(5, 1, 0xA)),
        "the content a slot holds re-signs"
    );
    assert!(
        !store.admit_beacon_vote(v, &beacon_vote1(5, 1, 0xB)),
        "other content at a held slot is refused"
    );
    assert!(
        store.admit_beacon_vote(w, &beacon_vote1(5, 1, 0xB)),
        "another validator's slot is its own"
    );
    assert!(store.admit_beacon_vote(v, &beacon_vote1(5, 2, 0xB)));
    assert!(
        store.admit_beacon_vote(v, &beacon_vote1(6, 1, 0xB)),
        "a newer epoch supersedes the record"
    );
    assert!(
        !store.admit_beacon_vote(v, &beacon_vote1(5, 2, 0xB)),
        "a superseded epoch is refused, even with content it held"
    );
}

/// Shared beacon vote register test: what it admitted survives `crash`.
///
/// The store `crash` returns refuses the conflicting signatures the
/// store before it would have refused.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_beacon_vote_register_survives_a_crash<S: BeaconVoteRegisterStore>(
    store: S,
    crash: impl FnOnce(S) -> S,
) {
    let v = ValidatorId::new(1);
    assert!(store.admit_beacon_vote(v, &beacon_vote1(5, 1, 0xA)));
    assert!(store.admit_beacon_vote(v, &beacon_vote1(5, 2, 0xA)));
    let store = crash(store);
    assert!(
        !store.admit_beacon_vote(v, &beacon_vote1(5, 1, 0xB)),
        "a slot signed before the crash is still held"
    );
    assert!(!store.admit_beacon_vote(v, &beacon_vote1(5, 2, 0xB)));
    assert!(store.admit_beacon_vote(v, &beacon_vote1(5, 2, 0xA)));
    assert!(!store.admit_beacon_vote(v, &beacon_vote1(4, 3, 0xA)));
}

/// Shared fetched-record test: a kept record survives `crash`, and an
/// address keeps the first record stored under it.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_fetched_instance_survives_a_crash<S: FetchedInstanceStore>(
    store: S,
    crash: impl FnOnce(S) -> S,
) {
    let kept = Address::new([0x1A; 31], AddressClass::Component);
    let never = Address::new([0x2B; 31], AddressClass::Component);
    assert_eq!(
        store.fetched_instance(kept),
        None,
        "a fresh store keeps none"
    );
    store.store_fetched_instances(&[(kept, vec![1, 2, 3])]);
    store.store_fetched_instances(&[(kept, vec![9])]);
    let store = crash(store);
    assert_eq!(
        store.fetched_instance(kept),
        Some(vec![1, 2, 3]),
        "the first record kept under an address is the one read back"
    );
    assert_eq!(store.fetched_instance(never), None);
}

/// A block at `height` carrying `txs`, stating stub terms for each: it
/// runs none of them, so each stands on a row from its commit.
fn block_carrying(height: u64, txs: &[&Transaction]) -> Block {
    stating(
        with_transactions(
            make_test_block(BlockHeight::new(height)),
            txs.iter()
                .map(|tx| Arc::new(Verifiable::from((*tx).clone())))
                .collect(),
        ),
        txs.iter()
            .map(|tx| stub_stated_terms(tx.hash(), 1))
            .collect(),
    )
}

/// A block at `height` whose one finalization settles the member rows of
/// `txs`, each the member its committing block reserved a place for.
fn block_settling_members(height: u64, txs: &[&Transaction]) -> Block {
    let height = BlockHeight::new(height);
    let outcomes = txs
        .iter()
        .map(|tx| {
            TxOutcome::new(
                tx.hash(),
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )
            .charging(0)
        })
        .collect();
    push_certificate(
        make_test_block(height),
        Arc::new(finalization_of(height, outcomes).into()),
    )
}

/// Whether `storage` holds the body of `tx`.
fn holds_body(storage: &impl ShardChainReader, tx: &Transaction) -> bool {
    storage.get_transactions_batch(&[tx.hash()]).len() == 1
}

/// Shared chain-floor test: beneath the floor a block goes whole, except
/// what a standing member row keeps.
///
/// A height no standing row names loses its metadata row and every row
/// its manifest names; a transaction whose row stands keeps its body and
/// the metadata rows at its height and the one below, until a
/// finalization settles the row; the floor never moves down; and every
/// height at or above it still rebuilds.
///
/// `collect` runs the backend's collection pass, for a backend that
/// deletes beneath the floor apart from moving it.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_chain_floor_prunes_beneath_it<S: ShardChainReader + TestStore>(
    storage: &S,
    collect: impl Fn(&S),
) {
    let txs: Vec<Transaction> = (1..=5u8).map(test_transaction).collect();
    let [below, first, sibling, second, late] = &txs[..] else {
        unreachable!("five transactions");
    };
    // `first` is the one transaction beneath the floor whose row stands.
    // Its sibling in the block and the transaction in the block below
    // are settled, as is `second`, with a receipt. `late` stands too, in
    // a block whose own row and the one below sit at or above the floor.
    let settling_second = push_certificate(
        make_test_block(BlockHeight::new(4)),
        Arc::new(
            make_finalization_settling(
                BlockHeight::new(4),
                TxOutcome::new(
                    second.hash(),
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
                .charging(0),
                StateWrites::default(),
            )
            .into(),
        ),
    );
    let settled = settling_second.certificates()[0].receipt_hash();
    let chain = [
        block_carrying(1, &[below]),
        block_carrying(2, &[first, sibling]),
        block_carrying(3, &[second]),
        settling_second,
        block_settling_members(5, &[below, sibling]),
        make_test_block(BlockHeight::new(6)),
        block_carrying(7, &[late]),
    ];
    for block in chain {
        commit_with_members(storage, &make_test_certified(block));
    }
    let metadata_at = |height: u64| {
        storage
            .get_block_metadata(BlockHeight::new(height))
            .is_some()
    };
    let rebuilds = |height: u64| storage.get_block(BlockHeight::new(height)).is_some();
    assert_eq!(storage.get_consensus_receipts(&second.hash()).len(), 1);

    let floor = BlockHeight::new(6);
    storage.advance_chain_floor(ShardId::ROOT, floor);
    collect(storage);
    assert_eq!(storage.chain_floor(), floor);
    assert!(
        !rebuilds(3) && !metadata_at(3) && !holds_body(storage, second),
        "a height no standing row names goes whole",
    );
    assert!(
        !metadata_at(4)
            && !metadata_at(5)
            && storage.get_certificates_batch(&[settled]).is_empty()
            && storage.get_consensus_receipts(&second.hash()).is_empty(),
        "a settling height goes with its finalization and the receipt it settled",
    );
    assert!(
        metadata_at(2) && holds_body(storage, first) && !holds_body(storage, sibling),
        "a standing row keeps its body and its height's metadata row, and nothing else there",
    );
    assert!(
        metadata_at(1) && !holds_body(storage, below),
        "and the metadata row of the height below, without what that height carried",
    );
    assert!(
        (1..=2).all(|height| storage
            .get_certified_header(BlockHeight::new(height))
            .is_some()),
        "so the headers a record's check reads off the two heights answer",
    );
    assert!(
        !rebuilds(1) && !rebuilds(2),
        "and no partial block rebuilds from what is held",
    );
    assert!(
        rebuilds(6) && rebuilds(7),
        "a height at or above the floor rebuilds",
    );

    storage.advance_chain_floor(ShardId::ROOT, BlockHeight::new(2));
    assert_eq!(storage.chain_floor(), floor, "the floor never moves down");

    commit_with_members(
        storage,
        &make_test_certified(block_settling_members(8, &[first])),
    );
    storage.advance_chain_floor(ShardId::ROOT, floor);
    collect(storage);
    assert!(
        !metadata_at(2) && !metadata_at(1) && !holds_body(storage, first),
        "a row a finalization settles releases its rows at the next collection",
    );
    assert!(
        rebuilds(6) && rebuilds(7),
        "and nothing at or above the floor goes with them"
    );
}

/// Shared chain-floor test: a standing member row keeps its rows beneath
/// the floor on the store's own reading, with nothing told to it.
///
/// `reopen` hands back the store as a process that opened it afresh
/// holds it — the identity for a store that is not reopened — and the
/// collection runs on what it returns, so what is kept is read off what
/// the store committed and nothing a process holds beside it.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_standing_member_row_keeps_its_rows<S: ShardChainReader + TestStore>(
    storage: S,
    reopen: impl FnOnce(S) -> S,
    collect: impl Fn(&S),
) {
    let txs: Vec<Transaction> = (1..=2u8).map(test_transaction).collect();
    let [below, standing] = &txs[..] else {
        unreachable!("two transactions");
    };
    let chain = [
        make_test_block(BlockHeight::new(1)),
        block_carrying(2, &[below]),
        block_carrying(3, &[standing]),
        block_settling_members(4, &[below]),
        make_test_block(BlockHeight::new(5)),
        make_test_block(BlockHeight::new(6)),
    ];
    for block in chain {
        commit_with_members(&storage, &make_test_certified(block));
    }
    let anchors: Vec<WeightedTimestamp> = (2..=3)
        .map(|height| {
            storage
                .get_certified_header(BlockHeight::new(height))
                .expect("a committed height")
                .header()
                .parent_qc()
                .weighted_timestamp()
        })
        .collect();

    let storage = reopen(storage);
    // Twice, so what the first pass kept is walked again by the second.
    for _ in 0..2 {
        storage.advance_chain_floor(ShardId::ROOT, BlockHeight::new(6));
        collect(&storage);
        assert!(
            holds_body(&storage, standing),
            "a standing row keeps its transaction's body",
        );
        let held: Vec<WeightedTimestamp> = (2..=3)
            .filter_map(|height| storage.get_certified_header(BlockHeight::new(height)))
            .map(|header| header.header().parent_qc().weighted_timestamp())
            .collect();
        assert_eq!(
            held, anchors,
            "and the headers at its height and the one below, each with its anchor",
        );
        assert!(
            !holds_body(&storage, below),
            "the height below keeps its row alone",
        );
        for height in [1, 4, 5] {
            assert!(
                storage
                    .get_block_metadata(BlockHeight::new(height))
                    .is_none(),
                "height {height}, which no standing row names, goes",
            );
        }
    }
}

/// Shared chain-floor test: a member row naming a height the store holds
/// no block at keeps nothing.
///
/// A store that began at an imported anchor carries the rows of its
/// state, and they name commits beneath its first block.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_member_row_naming_an_unheld_height_keeps_nothing<S: ShardChainReader + TestStore>(
    storage: &S,
    collect: impl Fn(&S),
) {
    for height in 1..=4u64 {
        commit_with_members(
            storage,
            &make_test_certified(make_test_block(BlockHeight::new(height))),
        );
    }
    storage.advance_chain_floor(ShardId::ROOT, BlockHeight::new(3));
    collect(storage);
    let metadata_at = |height: u64| {
        storage
            .get_block_metadata(BlockHeight::new(height))
            .is_some()
    };
    assert!(!metadata_at(1) && !metadata_at(2));

    let unheld = test_transaction(1);
    let naming = MemberInputs {
        height: BlockHeight::new(2),
        transactions: vec![(unheld.hash(), Deadline::of_transaction(&unheld))],
        terms: vec![stub_stated_terms(unheld.hash(), 1)],
        ..MemberInputs::still(ShardId::ROOT)
    };

    commit_folding(
        storage,
        &make_test_certified(make_test_block(BlockHeight::new(5))),
        &[],
        &[],
        &empty_witness(),
        &naming,
    );
    storage.advance_chain_floor(ShardId::ROOT, BlockHeight::new(5));
    collect(storage);
    assert!(
        (1..=4).all(|height| !metadata_at(height)) && !holds_body(storage, &unheld),
        "a row naming a height with no block keeps nothing",
    );
    assert!(metadata_at(5));
}

/// A block of `shard` at height 1 committing `tx` and running it as a
/// member `counterpart` shares the verdict on.
fn core_run_at_one(
    shard: ShardId,
    counterpart: ShardId,
    tx: TxHash,
    deadline: Deadline,
) -> MemberInputs {
    MemberInputs {
        height: BlockHeight::new(1),
        transactions: vec![(tx, deadline)],
        manifest: Arc::new(Capped::from_array([TickLine::Member {
            tx,
            joins: Joins::Executes,
            settlement: Settlement::Shared,
            holds: Capped::empty(),
            reach: Capped::from_array([counterpart]),
            awaits: Capped::from_array([counterpart]),
            charge: AbortCharge {
                vault: state_key(0x77, 1),
                amount: 0,
            },
            share: 1,
            reserves: Capped::empty(),
            deadline,
            nevers: Capped::empty(),
        }])),
        ..MemberInputs::still(shard)
    }
}

/// A block of `shard` at `height` carrying `half` of its tick at height
/// 1 for `tx`: a stating half stating its yes, any other deleting its
/// row.
fn core_settled_of_one(shard: ShardId, height: u64, half: TickHalf, tx: TxHash) -> MemberInputs {
    let stated = half == TickHalf::Stated;
    MemberInputs {
        height: BlockHeight::new(height),
        settled: vec![SettledHalf {
            tick: TickId::new(shard, BlockHeight::new(1)),
            half,
            deleted: if stated { Vec::new() } else { vec![tx] },
            stated: if stated {
                vec![(tx, GlobalReceiptHash::ZERO)]
            } else {
                Vec::new()
            },
            accepted: Vec::new(),
        }],
        ..MemberInputs::still(shard)
    }
}

/// A block of `shard` at `height` carrying a legs half of its tick at
/// height 1 that accepts `tx`.
fn core_accepted_of_one(shard: ShardId, height: u64, tx: TxHash) -> MemberInputs {
    MemberInputs {
        height: BlockHeight::new(height),
        settled: vec![SettledHalf {
            tick: TickId::new(shard, BlockHeight::new(1)),
            half: TickHalf::Legs,
            deleted: Vec::new(),
            stated: Vec::new(),
            accepted: vec![tx],
        }],
        ..MemberInputs::still(shard)
    }
}

/// Commit two blocks through `storage`'s own commit path that leave
/// `tx` standing stated on `shard`, a member `counterpart` shares the
/// verdict on: run at height 1, its yes stated at height 2.
pub fn commit_a_stated_row<S: TestStore>(
    storage: &S,
    shard: ShardId,
    counterpart: ShardId,
    tx: TxHash,
    deadline: Deadline,
) {
    for (height, members) in [
        (1, core_run_at_one(shard, counterpart, tx, deadline)),
        (2, core_settled_of_one(shard, 2, TickHalf::Stated, tx)),
    ] {
        commit_folding(
            storage,
            &make_test_certified(make_test_block(BlockHeight::new(height))),
            &[],
            &[],
            &empty_witness(),
            &members,
        );
    }
}

/// A claim at `writer`'s `height` under `state_root` over `keys`, proven
/// against `storage`'s tree there and naming `tx`'s verdict.
fn verdict_claim_at<S: TestStore + TreeReader>(
    storage: &S,
    writer: ShardId,
    tx: TxHash,
    keys: &[SubstateKey],
    height: u64,
    state_root: StateRoot,
) -> StateClaim {
    let proof = generate_proof(storage, keys, BlockHeight::new(height))
        .expect("the committed height is provable");
    let cells = proof
        .inclusions(state_root, writer, keys)
        .expect("the proof answers for its keys");
    let anchor = Anchor {
        shard: writer,
        height: BlockHeight::new(height),
        state_root,
        ts: WeightedTimestamp::from_millis(height),
    };
    let claim = StateClaim::new(anchor, cells, proof).hearing([tx]);
    assert!(claim.is_well_formed());
    assert_eq!(claim.verify(), Ok(()));
    claim
}

/// Shared verdict test: the hash a reader derives for a sibling's yes
/// is the value hash the sibling's tree proves at its verdict cell.
///
/// One shard commits a member a counterpart shares the verdict on, runs
/// it and states its yes, each through the store's own fold and commit.
/// A state claim proven against the committed root reads the verdict
/// cell present at exactly the hash the counterpart derives from its own
/// row, and the counterpart's fold over that claim hears a yes. Once a
/// legs half accepts the member, a claim at the later root reads the
/// cell at the hash the counterpart derives for an accept, and the
/// counterpart hears it. Once an end line deletes the row, a claim
/// reads the cell and the row absent beside the committed marker, and
/// the counterpart hears that the shard has left.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_stated_rows_leaf_proves_the_hash_its_sibling_derives<S: TestStore + TreeReader>(
    storage: &S,
) {
    let (writer, reader) = (ShardId::ROOT, ShardId::leaf(1, 1));
    let transaction = test_transaction(1);
    let tx = transaction.hash();
    let deadline = Deadline::of_transaction(&transaction);
    let running = |shard, counterpart| core_run_at_one(shard, counterpart, tx, deadline);
    let settling = |shard, height, half| core_settled_of_one(shard, height, half, tx);
    let commit = |height: u64, creations: &[(SubstateKey, Vec<u8>)], members: &MemberInputs| {
        commit_folding(
            storage,
            &make_test_certified(make_test_block(BlockHeight::new(height))),
            creations,
            &[],
            &empty_witness(),
            members,
        )
    };

    commit(
        1,
        &committed_tx_cells(writer, [&transaction]),
        &running(writer, reader),
    );
    let stated_root = commit(2, &[], &settling(writer, 2, TickHalf::Stated));

    let leaf = verdict_leaf(writer, tx);
    let mut keys = vec![
        leaf,
        member_row_leaf(writer, tx),
        committed_tx_cell_key(writer, tx, deadline.validity_end()),
    ];
    keys.sort_unstable();
    let claim_at = |height: u64, state_root: StateRoot| {
        verdict_claim_at(storage, writer, tx, &keys, height, state_root)
    };

    let stated = claim_at(2, stated_root);
    let as_the_reader_derives_it = VerdictLeaf::yes(tx, &Capped::from_array([writer]), reader);
    assert_eq!(
        stated.reading(leaf),
        Some(Inclusion::Present(verdict_hash(
            writer,
            tx,
            &as_the_reader_derives_it,
        ))),
        "the tree's leaf holds the hash a reader derives from its own row",
    );

    let windows = EpochWindows::new(FRONTIER_WINDOW_MS);
    let mut rows = MemberIndex::empty(reader);
    rows.advance(&running(reader, writer));
    rows.advance(&settling(reader, 2, TickHalf::Stated));
    let hearing = |rows: &mut MemberIndex, claim: &StateClaim| {
        rows.advance(&MemberInputs {
            heard: AnchorReadings::among(from_ref(claim), windows),
            ..MemberInputs::still(reader)
        });
        rows.members[&tx]
            .hearing
            .iter()
            .copied()
            .collect::<Vec<_>>()
    };
    let saying = |claim: &StateClaim, said: Said| {
        vec![Heard {
            shard: writer,
            mark: ReadMark::of(&claim.anchor, windows),
            said: Some(said),
        }]
    };
    assert_eq!(hearing(&mut rows, &stated), saying(&stated, Said::Yes));

    let accepted = claim_at(3, commit(3, &[], &core_accepted_of_one(writer, 3, tx)));
    assert_eq!(
        accepted.reading(leaf),
        Some(Inclusion::Present(verdict_hash(
            writer,
            tx,
            &VerdictLeaf::accepted(tx, &Capped::from_array([writer]), reader),
        ))),
        "an accepted row's leaf holds the accept its sibling derives",
    );
    assert_eq!(
        hearing(&mut rows, &accepted),
        saying(&accepted, Said::Accepted)
    );

    let ending = MemberInputs {
        height: BlockHeight::new(4),
        manifest: Arc::new(Capped::from_array([TickLine::End { tx }])),
        ..MemberInputs::still(writer)
    };
    let left = claim_at(4, commit(4, &[], &ending));
    assert_eq!(left.reading(leaf), Some(Inclusion::Absent));
    assert_eq!(
        hearing(&mut rows, &left),
        saying(&left, Said::Left),
        "the row and the leaf gone beside the committed marker is an exit",
    );
}

/// What each sibling `row` awaits last said of it, beside what the row
/// may do as an accepted one where every sibling still runs, records no
/// recovery and is judged in the epoch of `mark`.
fn accepted_row_decides(row: &MemberRow, mark: ReadMark) -> (Vec<Option<Said>>, Decision) {
    let view = SiblingView {
        epoch: mark.epoch,
        terminating: Some(false),
        recovery: Ok(None),
        evidence: Ok(Evidence::Live { terminating: false }),
        formed: Ok(None),
        ended: None,
    };
    let values: Vec<Value> = row
        .awaits
        .iter()
        .map(|sibling| {
            let entry = row.hearing.iter().find(|heard| heard.shard == *sibling);
            value_of(entry, Some(Source::Live), &view, row.committed)
        })
        .collect();
    let said = row.hearing.iter().map(|heard| heard.said).collect();
    (said, decide(Hears::Accepted, &values))
}

/// The line aborting `tx`, a released member reaching `counterpart`:
/// awaiting nobody and answering no crossing.
fn abort_of_a_released_row(tx: TxHash, counterpart: ShardId, deadline: Deadline) -> TickLine {
    TickLine::Member {
        tx,
        joins: Joins::Aborted,
        settlement: Settlement::Awaited,
        holds: Capped::empty(),
        reach: Capped::from_array([counterpart]),
        awaits: Capped::empty(),
        charge: AbortCharge {
            vault: state_key(0x77, 1),
            amount: 0,
        },
        share: 0,
        reserves: Capped::empty(),
        deadline,
        nevers: Capped::empty(),
    }
}

/// A block of `shard` at `height` carrying the stating half of its
/// tick at `tick`, which settles the abort of `tx` and deletes its row.
fn abort_settled_of_one(shard: ShardId, tick: u64, height: u64, tx: TxHash) -> MemberInputs {
    MemberInputs {
        height: BlockHeight::new(height),
        settled: vec![SettledHalf {
            tick: TickId::new(shard, BlockHeight::new(tick)),
            half: TickHalf::Stated,
            deleted: vec![tx],
            stated: Vec::new(),
            accepted: Vec::new(),
        }],
        ..MemberInputs::still(shard)
    }
}

/// Shared verdict test: a sibling reads a row a recovery released as
/// having stated nothing, and the row's abort as an exit.
///
/// One shard runs a member a counterpart shares the verdict on and
/// states its yes; the counterpart hears the yes and accepts. A
/// recovery's discard of the tick releases the row and deletes its leaf,
/// and a claim at that root reads the verdict cell absent beside the
/// row: nothing is stated, so the counterpart's accepted row waits.
/// `named` is the lines a block names over the rows the store holds at
/// an anchor: short of the row's deadline it names none, and at the
/// deadline the row's abort. The reading is the same while the abort's
/// tick holds the row. Once that tick's stating half deletes it, a claim
/// reads the cell and the row absent beside the committed marker, the
/// counterpart hears that the shard has left, and its accepted row ends.
/// That reading is the one way the counterpart learns of the exit: the
/// abort's certificate tells it nothing.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_sibling_reads_a_released_rows_abort_as_an_exit<S: TestStore + TreeReader>(
    storage: &S,
    named: &dyn Fn(&MemberIndex, WeightedTimestamp) -> Vec<TickLine>,
) {
    let (writer, reader) = (ShardId::ROOT, ShardId::leaf(1, 1));
    let transaction = test_transaction(1);
    let tx = transaction.hash();
    let deadline = Deadline::of_transaction(&transaction);
    let commit = |height: u64, creations: &[(SubstateKey, Vec<u8>)], members: &MemberInputs| {
        commit_folding(
            storage,
            &make_test_certified(make_test_block(BlockHeight::new(height))),
            creations,
            &[],
            &empty_witness(),
            members,
        )
    };
    let naming = |height: u64, lines: Vec<TickLine>| MemberInputs {
        height: BlockHeight::new(height),
        manifest: Arc::new(Capped::new(lines).expect("one block's lines")),
        ..MemberInputs::still(writer)
    };

    commit(
        1,
        &committed_tx_cells(writer, [&transaction]),
        &core_run_at_one(writer, reader, tx, deadline),
    );
    let stated_root = commit(
        2,
        &[],
        &core_settled_of_one(writer, 2, TickHalf::Stated, tx),
    );

    let leaf = verdict_leaf(writer, tx);
    let mut keys = vec![
        leaf,
        member_row_leaf(writer, tx),
        committed_tx_cell_key(writer, tx, deadline.validity_end()),
    ];
    keys.sort_unstable();
    let claim_at = |height: u64, state_root: StateRoot| {
        verdict_claim_at(storage, writer, tx, &keys, height, state_root)
    };

    let windows = EpochWindows::new(FRONTIER_WINDOW_MS);
    let mut rows = MemberIndex::empty(reader);
    rows.advance(&core_run_at_one(reader, writer, tx, deadline));
    rows.advance(&core_settled_of_one(reader, 2, TickHalf::Stated, tx));
    let hear = |rows: &mut MemberIndex, claim: &StateClaim| {
        rows.advance(&MemberInputs {
            heard: AnchorReadings::among(from_ref(claim), windows),
            ..MemberInputs::still(reader)
        });
        accepted_row_decides(&rows.members[&tx], ReadMark::of(&claim.anchor, windows))
    };

    hear(&mut rows, &claim_at(2, stated_root));
    rows.advance(&core_accepted_of_one(reader, 3, tx));
    assert_eq!(rows.members[&tx].state, RowState::Accepted);

    let discard = TickLine::Discard {
        tick: TickId::new(writer, BlockHeight::new(1)),
        cause: DiscardCause::Recovery,
    };
    let released = claim_at(3, commit(3, &[], &naming(3, vec![discard])));
    assert_eq!(released.reading(leaf), Some(Inclusion::Absent));
    assert_eq!(
        hear(&mut rows, &released),
        (vec![None], Decision::Wait),
        "a released row has stated nothing and may still be named",
    );

    let standing = MemberIndex::load(&storage.snapshot(), writer);
    assert_eq!(
        standing.members[&tx].state,
        RowState::Released {
            settlement: Settlement::Shared,
        },
    );
    assert_eq!(
        named(&standing, deadline.at().minus(Duration::from_millis(1))),
        vec![],
        "the released row stands short of its deadline",
    );
    let abort = named(&standing, deadline.at());
    assert_eq!(abort, vec![abort_of_a_released_row(tx, reader, deadline)]);
    let aborting = claim_at(4, commit(4, &[], &naming(4, abort)));
    assert_eq!(
        hear(&mut rows, &aborting),
        (vec![None], Decision::Wait),
        "the row stands until the abort's tick settles it",
    );

    let left = claim_at(5, commit(5, &[], &abort_settled_of_one(writer, 4, 5, tx)));
    assert_eq!(
        hear(&mut rows, &left),
        (vec![Some(Said::Left)], Decision::End),
        "the row gone beside the committed marker is an exit, and the accepted row ends",
    );
}

/// One chain of four blocks on the root shard, held by a replica that
/// has persisted some of them and holds the rest pending.
///
/// A member is run at height 1, its yes stated at height 2, the member
/// accepted at height 3 and its row ended at height 4. The member's row
/// and verdict leaf are entry leaves that stand, change and go across
/// the four blocks, so replicas of the chain at different depths differ
/// in which of those writes sit in their stores and which in their
/// pending chains, and in nothing a reader may see.
pub struct StatedRowChain<S> {
    chain: Arc<PendingChain<S>>,
    blocks: Vec<Block>,
    roots: Vec<StateRoot>,
}

impl<S> StatedRowChain<S>
where
    S: ShardChainReader + ShardChainWriter + SubstateStore + VersionedStore + TreeReader,
    S: Send + Sync + 'static,
{
    /// The shard the member's verdict is shared with.
    pub const COUNTERPART: ShardId = ShardId::leaf(1, 1);
    /// The heights of the chain.
    pub const HEIGHTS: u64 = 4;

    /// The chain over `store`, which starts empty and ends with the
    /// first `persisted` blocks flushed.
    ///
    /// # Panics
    ///
    /// Panics if the store does not end at `persisted`.
    #[must_use]
    pub fn at_depth(store: S, persisted: u64) -> Self {
        let transaction = test_transaction(1);
        let tx = transaction.hash();
        let deadline = Deadline::of_transaction(&transaction);
        let marker = committed_tx_cells(ShardId::ROOT, [&transaction]);
        let base = Arc::new(store);
        let chain = Arc::new(PendingChain::new(Arc::clone(&base), ChainOrigin::ROOT));
        let mut blocks: Vec<Block> = Vec::new();
        let mut roots = vec![base.state_root()];
        let mut pending: Vec<Arc<JmtSnapshot>> = Vec::new();
        for height in 1..=Self::HEIGHTS {
            let (block, members) = match height {
                1 => (
                    make_test_block(BlockHeight::new(1)),
                    core_run_at_one(ShardId::ROOT, Self::COUNTERPART, tx, deadline),
                ),
                2 => (
                    make_test_block(BlockHeight::new(2)),
                    core_settled_of_one(ShardId::ROOT, 2, TickHalf::Stated, tx),
                ),
                3 => (
                    make_test_block(BlockHeight::new(3)),
                    core_accepted_of_one(ShardId::ROOT, 3, tx),
                ),
                _ => (
                    with_member_sections(
                        make_test_block(BlockHeight::new(height)),
                        vec![TickLine::End { tx }],
                        Vec::new(),
                    ),
                    MemberInputs {
                        height: BlockHeight::new(height),
                        manifest: Arc::new(Capped::from_array([TickLine::End { tx }])),
                        ..MemberInputs::still(ShardId::ROOT)
                    },
                ),
            };
            let parent_height = BlockHeight::new(height - 1);
            let parent = blocks.last().map_or_else(
                || chain.view_at_persisted_tip(),
                |parent| chain.view_at(parent.hash(), parent_height),
            );
            let (root, snapshot, commit) = base.prepare_block_commit(
                ParentAnchor {
                    state_root: roots[roots.len() - 1],
                    height: parent_height,
                    state: &parent.snapshot(),
                    pending: &pending,
                    base_reads: None,
                },
                &[],
                ChainWrites {
                    creations: if height == 1 { &marker } else { &[] },
                    removals: &[],
                    sweep_frontier: SweepFrontier::ZERO,
                    frontier: &FrontierInputs::still(ShardId::ROOT),
                    state_claims: &[],
                    members: &members,
                },
                BlockHeight::new(height),
            );
            if height <= persisted {
                commit(
                    SyncHint::FlushNow,
                    &make_test_certified(block.clone()),
                    &empty_witness(),
                );
            } else {
                pending.push(Arc::clone(&snapshot));
                chain.insert(
                    block.hash(),
                    ChainEntry {
                        parent_block_hash: blocks
                            .last()
                            .map_or_else(|| block.header().parent_block_hash(), Block::hash),
                        height: BlockHeight::new(height),
                        settled_txs: Vec::new(),
                        jmt_snapshot: snapshot,
                        certified_block: None,
                    },
                );
            }
            blocks.push(block);
            roots.push(root);
        }
        assert_eq!(base.jmt_height(), BlockHeight::new(persisted));
        Self {
            chain,
            blocks,
            roots,
        }
    }

    /// The member the chain runs, states and ends.
    #[must_use]
    pub fn member() -> TxHash {
        test_transaction(1).hash()
    }

    /// The block at `height`.
    ///
    /// # Panics
    ///
    /// Panics if the chain has no such height.
    #[must_use]
    pub fn block(&self, height: u64) -> &Block {
        &self.blocks[usize::try_from(height - 1).expect("a height of the chain")]
    }

    /// The state root the block at `height` left.
    ///
    /// # Panics
    ///
    /// Panics if the chain has no such height.
    #[must_use]
    pub fn root(&self, height: u64) -> StateRoot {
        self.roots[usize::try_from(height).expect("a height of the chain")]
    }

    /// The chain the replica reads through, its persisted tip at the
    /// depth it was built to.
    #[must_use]
    pub const fn chain(&self) -> &Arc<PendingChain<S>> {
        &self.chain
    }

    /// The replica's view anchored on the block at `height`.
    ///
    /// # Panics
    ///
    /// Panics if the chain has no such height.
    #[must_use]
    pub fn view(&self, height: u64) -> Arc<SubstateView<S>> {
        self.chain
            .view_at(self.block(height).hash(), BlockHeight::new(height))
    }
}

/// Shared: an entry's tree leaf reads as the cell its block's state
/// root proves, through the pending view of every replica of a chain.
///
/// However much of the chain a replica has persisted, the read is one.
/// The member row and the verdict leaf of a [`StatedRowChain`] are read
/// at each of its blocks: standing in a pending ancestor, deleted in a
/// pending ancestor, and written then deleted across pending ancestors,
/// against the replica that has flushed up to the block read. Each is
/// read as a cell of the view, as a cell of its snapshot, and at the
/// block's height.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_pending_views_read_an_entry_leaf_alike_at_every_depth<S>(fresh: impl Fn() -> S)
where
    S: ShardChainReader + ShardChainWriter + SubstateStore + VersionedStore + TreeReader,
    S: Send + Sync + 'static,
{
    let tx = StatedRowChain::<S>::member();
    let leaves = [
        member_row_leaf(ShardId::ROOT, tx),
        verdict_leaf(ShardId::ROOT, tx),
    ];
    let stands = [[true, false], [true, true], [true, true], [false, false]];
    for (height, stands) in (1..=StatedRowChain::<S>::HEIGHTS).zip(stands) {
        for persisted in 0..=height {
            let replica = StatedRowChain::at_depth(fresh(), persisted);
            let view = replica.view(height);
            let proof = generate_proof(view.as_ref(), &leaves, BlockHeight::new(height))
                .expect("the block's height is provable");
            let proven = proof
                .inclusions(replica.root(height), ShardId::ROOT, &leaves)
                .expect("the proof answers for its keys");
            for ((leaf, stands), (_, proven)) in leaves.into_iter().zip(stands).zip(proven) {
                let at = format!("height {height}, {persisted} persisted");
                assert_eq!(
                    proven != Inclusion::Absent,
                    stands,
                    "the tree's leaf at {at}"
                );
                let as_proven = |cell: Option<Vec<u8>>| {
                    cell.map_or(Inclusion::Absent, |value| {
                        Inclusion::Present(jmt_value_hash(&value))
                    })
                };
                assert_eq!(as_proven(view.cell(leaf)), proven, "the view at {at}");
                assert_eq!(
                    as_proven(view.snapshot().cell(leaf)),
                    proven,
                    "the snapshot at {at}",
                );
                assert_eq!(
                    view.get_substate_at_height(leaf, BlockHeight::new(height))
                        .map(as_proven),
                    Some(proven),
                    "the versioned read at {at}",
                );
            }
        }
    }
}

/// One block of a [`test_pending_views_serve_random_leaf_chains`]
/// chain, with what its tree holds.
struct RandomLeafBlock {
    block: Block,
    height: u64,
    root: StateRoot,
    /// Every leaf under the store's prefix, laid block by block from
    /// each block's own writes: its cells, then each entry encoded to
    /// its leaf, the last write of a key winning.
    leaves: BTreeMap<SubstateKey, Option<Vec<u8>>>,
}

/// Shared: random chains of entry and cell writes read through pending
/// views at every persistence depth, against the leaves derived from
/// each block's own writes and against the tree's proof.
///
/// Each of `seeds` chains has five blocks over four entries and two
/// cells, each block writing, overwriting, deleting, re-deleting or
/// leaving each key, some blocks writing nothing, with a fork of the
/// pending chain at height 2 to 4. At every block of trunk and fork,
/// every leaf is read as a cell of the view, as a cell of its snapshot,
/// and at each ancestor's height. `shard` is the prefix the store is
/// rooted at; a leaf under no prefix of it is held by nobody and reads
/// absent.
///
/// # Panics
///
/// Panics if any reading differs (this is a test helper).
#[allow(clippy::too_many_lines)] // one chain built and read at every depth, fork included
pub fn test_pending_views_serve_random_leaf_chains<S>(
    fresh: impl Fn() -> S,
    shard: ShardId,
    seeds: u64,
) where
    S: ShardChainReader + ShardChainWriter + SubstateStore + VersionedStore + TreeReader,
    S: Send + Sync + 'static,
{
    const HEIGHTS: u64 = 5;
    let prefix = shard_prefix_path(shard);
    let entries: Vec<EntryKey> = [(0x10u8, 1u128), (0x10, 2), (0x90, 1), (0x90, 2)]
        .into_iter()
        .map(|(owner, order)| entry_key(owner, order))
        .collect();
    let cells = [state_key(0x10, 7), state_key(0x90, 7)];
    let leaves: Vec<SubstateKey> = entries
        .iter()
        .map(|entry| entry_leaf_key(&ProtocolHasher, *entry))
        .chain(cells)
        .collect();
    let held: Vec<SubstateKey> = leaves
        .iter()
        .copied()
        .filter(|leaf| key_under_prefix(&leaf.to_bytes(), &prefix))
        .collect();
    assert!(!held.is_empty(), "the store holds some leaf");
    let as_proven = |cell: Option<Vec<u8>>| {
        cell.map_or(Inclusion::Absent, |value| {
            Inclusion::Present(jmt_value_hash(&value))
        })
    };
    for seed in 0..seeds {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let writes_of_a_block = |next: &mut dyn FnMut() -> u64| {
            let mut writes = StateWrites::default();
            if next().is_multiple_of(6) {
                return writes;
            }
            let change = |next: &mut dyn FnMut() -> u64, len: usize| match next() % 5 {
                0 | 1 => Some(Some(vec![u8::try_from(next() % 3).unwrap(); len])),
                2 => Some(None),
                _ => None,
            };
            for entry in &entries {
                if let Some(change) = change(next, 3) {
                    writes.entries.insert(*entry, change);
                }
            }
            for cell in cells {
                if let Some(change) = change(next, 2) {
                    writes.cells.insert(cell, change);
                }
            }
            // A chain's receipts write under its own prefix alone.
            filter_state_writes_to_prefix(&writes, &prefix)
        };
        let fork_at = 2 + next() % 3;
        let trunk_writes: Vec<StateWrites> = (1..=HEIGHTS)
            .map(|_| writes_of_a_block(&mut next))
            .collect();
        let fork_writes: Vec<StateWrites> = (fork_at..=HEIGHTS)
            .map(|_| writes_of_a_block(&mut next))
            .collect();

        for persisted in 0..=HEIGHTS {
            let base = Arc::new(fresh());
            let chain = Arc::new(PendingChain::new(Arc::clone(&base), ChainOrigin::ROOT));
            let genesis_root = base.state_root();
            let land = |parent: Option<&RandomLeafBlock>,
                        height: u64,
                        writes: &StateWrites,
                        forked: bool,
                        flush: bool| {
                let mut block =
                    make_test_block_with_anchor_wt(BlockHeight::new(height), u64::from(forked));
                if writes.cells.len() + writes.entries.len() > 0 {
                    block =
                        push_certificate(block, settling(BlockHeight::new(height), writes.clone()));
                }
                let view = parent.map_or_else(
                    || chain.view_at_persisted_tip(),
                    |parent| chain.view_at(parent.block.hash(), BlockHeight::new(parent.height)),
                );
                let (root, snapshot, commit) = base.prepare_block_commit(
                    ParentAnchor {
                        state_root: parent.map_or(genesis_root, |parent| parent.root),
                        height: BlockHeight::new(height - 1),
                        state: &view.snapshot(),
                        pending: view.pending_snapshots(),
                        base_reads: None,
                    },
                    &block.certificates()[..],
                    ChainWrites {
                        creations: &[],
                        removals: &[],
                        sweep_frontier: SweepFrontier::ZERO,
                        frontier: &FrontierInputs::still(ShardId::ROOT),
                        state_claims: &[],
                        members: &MemberInputs::still(ShardId::ROOT),
                    },
                    BlockHeight::new(height),
                );
                if flush {
                    commit(
                        SyncHint::FlushNow,
                        &make_test_certified(block.clone()),
                        &empty_witness(),
                    );
                } else {
                    chain.insert(
                        block.hash(),
                        ChainEntry {
                            parent_block_hash: parent.map_or_else(
                                || block.header().parent_block_hash(),
                                |parent| parent.block.hash(),
                            ),
                            height: BlockHeight::new(height),
                            settled_txs: Vec::new(),
                            jmt_snapshot: snapshot,
                            certified_block: None,
                        },
                    );
                }
                let mut leaves = parent.map_or_else(BTreeMap::new, |parent| parent.leaves.clone());
                for (cell, change) in &writes.cells {
                    leaves.insert(*cell, change.clone());
                }
                for (entry, change) in &writes.entries {
                    leaves.insert(
                        entry_leaf_key(&ProtocolHasher, *entry),
                        change.as_ref().map(|row| entry_leaf_value(entry, row)),
                    );
                }
                RandomLeafBlock {
                    block,
                    height,
                    root,
                    leaves,
                }
            };

            let mut trunk: Vec<RandomLeafBlock> = Vec::new();
            for (height, writes) in (1..=HEIGHTS).zip(&trunk_writes) {
                let built = land(trunk.last(), height, writes, false, height <= persisted);
                trunk.push(built);
            }
            assert_eq!(base.jmt_height(), BlockHeight::new(persisted));
            // The fork leaves the trunk above the persisted tip, as an
            // uncommitted sibling does.
            let mut branch: Vec<RandomLeafBlock> = Vec::new();
            if fork_at > persisted {
                for (height, writes) in (fork_at..=HEIGHTS).zip(&fork_writes) {
                    let parent = branch.last().or_else(|| {
                        usize::try_from(height - 2)
                            .ok()
                            .and_then(|at| (height >= 2).then(|| &trunk[at]))
                    });
                    let built = land(parent, height, writes, true, false);
                    branch.push(built);
                }
            }

            let lines: [Vec<&RandomLeafBlock>; 2] = [
                trunk.iter().collect(),
                if branch.is_empty() {
                    Vec::new()
                } else {
                    trunk
                        .iter()
                        .take(usize::try_from(fork_at - 1).unwrap())
                        .chain(&branch)
                        .collect()
                },
            ];
            for (forked, line) in lines.iter().enumerate() {
                for (at, tip) in line.iter().enumerate() {
                    if forked == 1 && tip.height < fork_at {
                        continue;
                    }
                    let whence = format!(
                        "seed {seed}, {persisted} persisted, line {forked} forking at {fork_at}, \
                         height {}",
                        tip.height
                    );
                    let view = chain.view_at(tip.block.hash(), BlockHeight::new(tip.height));
                    let derived = |block: &RandomLeafBlock, leaf: SubstateKey| {
                        as_proven(block.leaves.get(&leaf).cloned().flatten())
                    };
                    if tip.height >= persisted {
                        match generate_proof(view.as_ref(), &held, BlockHeight::new(tip.height)) {
                            // An empty tree has no root node to prove under.
                            None => assert!(
                                tip.leaves.values().all(Option::is_none)
                                    && tip.root == genesis_root,
                                "no proof of a tree that holds leaves at {whence}",
                            ),
                            Some(proof) => {
                                let proven = proof
                                    .inclusions(tip.root, shard, &held)
                                    .unwrap_or_else(|why| panic!("{why:?} at {whence}"));
                                for (leaf, proven) in proven {
                                    assert_eq!(
                                        derived(tip, leaf),
                                        proven,
                                        "the derived leaves at {whence}"
                                    );
                                }
                            }
                        }
                    }
                    let snapshot = view.snapshot();
                    for leaf in &leaves {
                        let expected = derived(tip, *leaf);
                        if tip.height >= persisted {
                            assert_eq!(
                                as_proven(view.cell(*leaf)),
                                expected,
                                "the view at {whence}, leaf {leaf:?}"
                            );
                        }
                        assert_eq!(
                            as_proven(snapshot.cell(*leaf)),
                            expected,
                            "the snapshot at {whence}, leaf {leaf:?}"
                        );
                        for below in &line[..=at] {
                            assert_eq!(
                                view.get_substate_at_height(*leaf, BlockHeight::new(below.height))
                                    .map(as_proven),
                                Some(derived(below, *leaf)),
                                "the read at height {} at {whence}, leaf {leaf:?}",
                                below.height,
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Shared: the verdict leaf a block deleted is one change read through
/// the pending views of replicas at every persistence depth.
///
/// The last block of a [`StatedRowChain`] ends its member, and the
/// change is for the counterpart the verdict is shared with, beside the
/// row the parent held, whether the block and its parent are flushed or
/// pending.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_pending_views_read_a_verdict_change_alike_at_every_depth<S>(fresh: impl Fn() -> S)
where
    S: ShardChainReader + ShardChainWriter + SubstateStore + VersionedStore + TreeReader,
    S: Send + Sync + 'static,
{
    let tx = StatedRowChain::<S>::member();
    let deadline = Deadline::of_transaction(&test_transaction(1));
    let ended = VerdictChange {
        target: StatedRowChain::<S>::COUNTERPART,
        tx,
        leaf: verdict_leaf(ShardId::ROOT, tx),
        beside: Some((
            member_row_leaf(ShardId::ROOT, tx),
            committed_tx_cell_key(ShardId::ROOT, tx, deadline.validity_end()),
        )),
    };
    let height = StatedRowChain::<S>::HEIGHTS;
    for persisted in 0..=height {
        let replica = StatedRowChain::at_depth(fresh(), persisted);
        let (before, after) = (replica.view(height - 1), replica.view(height));
        assert_eq!(
            verdict_changes(
                replica.block(height),
                |key| {
                    before
                        .get_substate_at_height(key, BlockHeight::new(height - 1))
                        .flatten()
                },
                |key| {
                    after
                        .get_substate_at_height(key, BlockHeight::new(height))
                        .flatten()
                },
            ),
            [ended],
            "the ending block's change with {persisted} persisted",
        );
    }
}

/// Shared chain-floor test: a successor keeps the block its genesis
/// follows.
///
/// A split child's store begins as its parent's, and the height below the
/// child's genesis is the parent's terminal. An observer of the split that
/// applied the terminal asks the child's committee for it, certified, to
/// derive the genesis from; every other height beneath the origin is the
/// predecessor's alone.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_a_successor_keeps_its_predecessors_terminal(
    storage: &(impl ShardChainReader + TestStore),
) {
    for height in 1..=4u64 {
        commit_settled_at(
            storage,
            &make_test_certified(make_test_block(BlockHeight::new(height))),
            &[],
            &[],
            &empty_witness(),
        );
    }
    let origin = ChainOrigin {
        genesis_height: BlockHeight::new(4),
        anchor_wt: WeightedTimestamp::ZERO,
    };
    let floor = chain_floor(
        storage,
        FloorInputs {
            origin,
            oldest_pin: None,
            settled_window_floor: None,
        },
    );
    assert_eq!(
        floor,
        BlockHeight::new(3),
        "the predecessor's terminal stays above the floor",
    );
}

/// Shared chain-floor test: the floor never names a height the store
/// holds no block at.
///
/// Each reach keeps the block below the first one it dates, when the
/// store has it. A store that began at an imported anchor holds nothing
/// beneath its first block, and a floor one below that would answer a
/// request for the height as not found rather than as beneath the floor.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_the_floor_stops_at_the_lowest_block_held(
    storage: &(impl ShardChainReader + TestStore),
) {
    for height in 5..=8u64 {
        commit_settled_at(
            storage,
            &make_test_certified(make_test_block(BlockHeight::new(height))),
            &[],
            &[],
            &empty_witness(),
        );
    }
    let floor = chain_floor(
        storage,
        FloorInputs {
            origin: ChainOrigin::ROOT,
            oldest_pin: Some(BlockHeight::new(8)),
            settled_window_floor: None,
        },
    );
    assert_eq!(
        floor,
        BlockHeight::new(5),
        "the floor sits on the lowest block the store holds",
    );
}

/// A sweepable cell of owner `[owner; 31]` expiring at the start of
/// `bucket`, and the value that makes it one.
fn sweepable_in(owner: u8, bucket: u64) -> (SubstateKey, Vec<u8>) {
    let (local, value) = stub_sweepable_cell(bucket * SWEEP_BUCKET_MS, owner);
    (
        SubstateKey {
            owner: Address::new([owner; 31], AddressClass::Component),
            local,
        },
        value,
    )
}

/// A block at `height` whose header names `swept_to` and whose one
/// finalization settles a receipt writing `cells`.
fn block_sweeping_to(
    height: BlockHeight,
    swept_to: SweepFrontier,
    cells: &[(SubstateKey, Vec<u8>)],
) -> Block {
    let mut writes = StateWrites::default();
    for (key, value) in cells {
        writes.cells.insert(*key, Some(value.clone()));
    }
    let receipt = StoredReceipt::new(
        TxHash::from(Hash::from_bytes(&height.to_le_bytes())),
        Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes,
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        }),
    );
    let block = if cells.is_empty() {
        make_test_block(height)
    } else {
        block_settling(height, vec![receipt])
    };
    naming_sweep_frontier(block, swept_to)
}

/// `block` with a header naming `swept_to` as where its sweep landed.
fn naming_sweep_frontier(mut block: Block, swept_to: SweepFrontier) -> Block {
    if let Block::Live { header, .. } = &mut block {
        *header = BlockHeader::new(BlockHeaderParts {
            height: header.height(),
            parent_block_hash: header.parent_block_hash(),
            parent_qc: header.parent_qc().clone().into(),
            timestamp: header.timestamp(),
            sweep_frontier: swept_to,
            ..Default::default()
        });
    }
    block
}

/// Shared: a split follower's halves recompose the chain's root across
/// a block that takes records back and settles a sweepable write below
/// its own frontier, on each half.
///
/// The reclaim lands each write on the half holding its cell; the late
/// write is dropped by the chain and by both halves alike.
///
/// # Panics
///
/// If the halves do not recompose the chain's root, the reclaim does not
/// land, or a late write stands anywhere.
pub fn test_a_split_follower_drops_a_late_write_beside_a_reclaim<S>(parent: &S, left: &S, right: &S)
where
    S: BoundaryStore + TestStore + SweepIndex,
{
    install_stub_protocol_statics();
    let returning = Returning::new();
    let late = [sweepable_in(0x10, 5), sweepable_in(0xF0, 5)];
    let mut writes = StateWrites::default();
    for (key, value) in &late {
        writes.cells.insert(*key, Some(value.clone()));
    }
    let height = BlockHeight::new(2);
    let block = naming_sweep_frontier(
        push_certificate(returning.block(height), settling(height, writes)),
        SweepFrontier::start_of(SweepBucket(20)),
    );
    seeded_and_followed(parent, left, right, &returning.seeded(), &[block], |_| {
        for id in [returning.left, returning.right] {
            assert_eq!(parent.cell(id.record_key(&ProtocolHasher)), None);
            assert_eq!(
                amount_at(parent, Returning::credit(&id)),
                FUNDED + Returning::AMOUNT,
            );
        }
        for store in [parent, left, right] {
            assert!(late.iter().all(|(key, _)| store.cell(*key).is_none()));
        }
    });
}

/// Commit `block` on `storage`'s tip as a chain does: its sweep is the
/// interval from `parent` to the frontier its header names, read off
/// the store before the block. Returns the committed root.
fn commit_swept<S: TestStore + SweepIndex>(
    storage: &S,
    block: Block,
    parent: SweepFrontier,
) -> StateRoot {
    let swept_to = block.header().sweep_frontier();
    let removals = sweep_through(storage, parent, swept_to);
    let members = MemberInputs::of(&block, FrontierInputs::still(ShardId::ROOT).windows);
    commit_folding(
        storage,
        &make_test_certified(block),
        &[],
        &removals,
        &empty_witness(),
        &members,
    )
}

/// Shared: a split follower's halves recompose the chain's root across
/// a block that settles a sweepable write below its own frontier, and
/// across the block after it.
///
/// The late write is what a tick finalizing past its nullifier's expiry
/// settles. A follower walks from the chain's start, so it reads every
/// sweepable cell at or below a frontier as one the block removed; a
/// chain that kept the late write would leave it standing there while
/// the next block's follower took it.
///
/// # Panics
///
/// If the halves do not recompose the parent's root, or a late write
/// stands anywhere.
pub fn test_followed_halves_drop_a_late_sweepable_write<S>(parent: &S, left: &S, right: &S)
where
    S: BoundaryStore + TestStore + SweepIndex,
{
    install_stub_protocol_statics();
    let late_left = sweepable_in(0x10, 5);
    let late_right = sweepable_in(0xF0, 5);
    // A cell standing on each half, so the parent's root is the node
    // the two halves hang from.
    let timely = [sweepable_in(0x20, 40), sweepable_in(0xE0, 40)];
    let still = FrontierInputs::still(ShardId::ROOT);
    let first_frontier = SweepFrontier::start_of(SweepBucket(20));
    let first = block_sweeping_to(
        BlockHeight::new(1),
        first_frontier,
        &[
            late_left.clone(),
            late_right.clone(),
            timely[0].clone(),
            timely[1].clone(),
        ],
    );
    let second = block_sweeping_to(
        BlockHeight::new(2),
        SweepFrontier::start_of(SweepBucket(21)),
        &[],
    );
    for (block, parent_frontier) in [(first, SweepFrontier::ZERO), (second, first_frontier)] {
        let parent_root = commit_swept(parent, block.clone(), parent_frontier);
        let left_root = left.follow_block_writes(&block, &[], &still).unwrap();
        let right_root = right.follow_block_writes(&block, &[], &still).unwrap();
        assert!(
            SplitChildRoots {
                left: left_root,
                right: right_root,
            }
            .composes_to(parent_root),
            "the followed halves recompose the parent's root at {:?}",
            block.height(),
        );
    }
    for store in [parent, left, right] {
        assert!(store.cell(late_left.0).is_none() && store.cell(late_right.0).is_none());
    }
    assert!(
        timely.iter().all(|(key, _)| parent.cell(*key).is_some()),
        "a write above the frontier stands",
    );
}

/// Shared: over a chain whose block settled a sweepable write below its
/// own frontier, a walk from the chain's start removes the cells and
/// lands on the frontier a walk from the parent's frontier does.
///
/// A replica that cannot resolve its parent's header walks from the
/// start, as a follower does; the two walks agree only while nothing
/// sweepable stands at or below the parent's frontier.
///
/// # Panics
///
/// If the two walks differ.
pub fn test_a_walk_from_the_chains_start_lands_where_the_parents_frontier_does<S>(storage: &S)
where
    S: TestStore + SweepIndex,
{
    install_stub_protocol_statics();
    let late = sweepable_in(0x30, 5);
    let expiring = sweepable_in(0x31, 30);
    let parent_frontier = SweepFrontier::start_of(SweepBucket(20));
    commit_swept(
        storage,
        block_sweeping_to(
            BlockHeight::new(1),
            parent_frontier,
            &[late, expiring.clone()],
        ),
        SweepFrontier::ZERO,
    );
    let clock = WeightedTimestamp::from_millis(40 * SWEEP_BUCKET_MS);
    let from_parent = sweep_for_block(storage, BlockSweep::From(parent_frontier), clock);
    assert_eq!(
        from_parent,
        (vec![expiring.0], SweepFrontier::ceiling_at(clock))
    );
    assert_eq!(
        sweep_for_block(storage, BlockSweep::From(SweepFrontier::ZERO), clock),
        from_parent,
        "a walk from the chain's start takes what the parent's frontier does",
    );
}
