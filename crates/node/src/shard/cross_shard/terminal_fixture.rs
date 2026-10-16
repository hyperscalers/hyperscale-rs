//! A committed chain ending at a terminal block, for the tests of the
//! terminal-lines serve and of the fetch that checks its answers.
//!
//! Every block's header commits the whole body it is stored with, so the
//! lines served off the terminal are bound to its hash as a real block's
//! are.

use std::sync::Arc;

use hyperscale_hbor::Capped;
use hyperscale_storage::test_helpers::{commit_settled_at, make_test_certified};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    AggregateSignature, BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash, BlockHeader,
    BlockHeaderParts, BlockHeight, BodyRoot, ConsensusReceipt, ExecutionCertificate,
    ExecutionOutcome, Finalization, GlobalReceiptHash, Hash, ProposerTimestamp, QuorumCertificate,
    Role, Round, SectionRoots, SettledTxsRoot, ShardId, SignerBitfield, StateWrites, StoredReceipt,
    TickHalf, TickId, TickLine, TxHash, TxOutcome, Verifiable, WeightedTimestamp, WitnessSources,
    compute_global_receipt_root,
};

/// The shard whose chain the fixture commits.
pub(super) const SHARD: ShardId = ShardId::ROOT;

/// The transaction the block at `height` settles.
fn settled_tx(height: u64) -> TxHash {
    TxHash::from(Hash::from_bytes(&height.to_le_bytes()))
}

/// The transaction the end line of `seed` names.
pub(super) fn ended_tx(seed: u8) -> TxHash {
    TxHash::from(Hash::from_bytes(&[b'e', seed]))
}

/// An end line naming a transaction of its own per `seed`.
pub(super) fn end_line(seed: u8) -> TickLine {
    TickLine::End { tx: ended_tx(seed) }
}

fn certificate(tick: TickId, height: u64) -> Arc<ExecutionCertificate> {
    let outcomes = vec![
        TxOutcome::new(
            settled_tx(height),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )
        .as_role(Role::Leg),
    ];
    Arc::new(ExecutionCertificate::new(
        tick,
        WeightedTimestamp::from_millis(1),
        compute_global_receipt_root(&outcomes),
        Capped::new(outcomes).expect("a tick's outcomes within the block cap"),
        AggregateSignature::new([0u8; 96]),
        SignerBitfield::new(4),
    ))
}

/// A finalization settling one leg that ran, so the block's certificate,
/// receipt and settled sections have roots of their own for the header
/// to commit.
fn finalization(height: u64) -> Arc<Verifiable<Finalization>> {
    let tick = TickId::new(SHARD, BlockHeight::new(height));
    let receipt = StoredReceipt::new(
        settled_tx(height),
        Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes: StateWrites::default(),
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        }),
    );
    Arc::new(Verifiable::from(Finalization::new(
        tick,
        TickHalf::Determined,
        Some(certificate(tick, height)),
        Capped::from_array([receipt]),
    )))
}

/// Commit the block at `height` over `parent`, carrying `lines` as its
/// tick manifest, and return it.
///
/// Every block carries a terminal settled root, as every block of a
/// terminating window does.
pub(super) fn commit_block(
    storage: &SimShardStorage,
    height: u64,
    parent: BlockHash,
    lines: &[TickLine],
) -> Block {
    let header = |body_root: BodyRoot| {
        let parent_qc = QuorumCertificate::new(
            parent,
            SHARD,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::new([0u8; 96]),
            WeightedTimestamp::from_millis(1_000 * height),
        );
        BlockHeader::new(BlockHeaderParts {
            shard_id: SHARD,
            height: BlockHeight::new(height),
            parent_block_hash: parent,
            parent_qc: parent_qc.into(),
            timestamp: ProposerTimestamp::from_millis(1_000 * height),
            body_root,
            provision_tx_roots: Capped::default(),
            terminal_settled_txs: Some(SettledTxsRoot::ZERO),
            ..Default::default()
        })
    };
    let certificates = Arc::new(Capped::from_array([finalization(height)]));
    let tick_manifest =
        Arc::new(Capped::new(lines.to_vec()).expect("a manifest within the line cap"));
    let body = |header: BlockHeader| Block::Live {
        header,
        transactions: Arc::new(Capped::empty()),
        certificates: Arc::clone(&certificates),
        provisions: Arc::new(Capped::empty()),
        abandonment_records: Arc::new(Capped::empty()),
        state_claims: Arc::new(Capped::empty()),
        tick_manifest: Arc::clone(&tick_manifest),
        terms: Arc::new(Capped::empty()),
        witness_sources: Arc::new(WitnessSources::empty()),
    };
    let sections = SectionRoots::of(&body(header(BodyRoot::ZERO)));
    let block = body(header(sections.root()));
    commit_settled_at(
        storage,
        &make_test_certified(block.clone()),
        &[],
        &[],
        &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
    );
    block
}
