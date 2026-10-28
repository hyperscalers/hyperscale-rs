//! Shared test fixtures for state-module tests. Each submodule's
//! `#[cfg(test)] mod tests` pulls these in via
//! `use crate::test_fixtures::*` so common scaffolding
//! (keypair derivation, VRF-signed proposals, single-pool state)
//! lives in one place.

#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_crypto_bls::BlsVerifier;
pub use hyperscale_crypto_bls::{
    public_key_from_u64_seed as pubkey, signer_from_u64_seed as keypair,
};
use hyperscale_hbor::Capped;
use hyperscale_types::test_utils::test_pool;
use hyperscale_types::{
    Admission, AggregateSignature, BeaconChainConfig, BeaconProposal, BeaconState,
    BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader, BlockHeaderParts,
    BlockHeight, ConsensusSignature, DeclaredWork, Epoch, Hash, MIN_STAKE_FLOOR, NetworkDefinition,
    PcVoteEquivocation, PendingReshape, PendingWithdrawal, QuorumCertificate, Round, Settling,
    ShardBoundary, ShardCommittee, ShardEpochContribution, ShardId, ShardLoad,
    ShardVoteEquivocation, ShardWitnessPayload, SignerBitfield, SlotEffects, Stake, StakePool,
    StakePoolId, StateRoot, ValidatorId, ValidatorRecord, ValidatorStatus, VrfProof,
    WeightedTimestamp, beacon_reveal_sign, compute_merkle_root, compute_range_proof,
    validator_possession_proof_sign,
};

use crate::state::witness::apply_shard_payload;
use crate::state::{ApplyEpochInput, apply_epoch};

pub fn net() -> NetworkDefinition {
    NetworkDefinition::simulator()
}

/// A valid proof-of-possession for `pubkey(seed)` claimed under `id` in
/// `pool`.
pub fn possession_proof(seed: u64, id: ValidatorId, pool: StakePoolId) -> ConsensusSignature {
    validator_possession_proof_sign(&keypair(seed), &net(), id, pool).expect("sign")
}

/// Build an honest VRF-signed empty `BeaconProposal` for validator
/// `id` at `epoch`. No witnesses (witness ingestion is a later
/// stage); just a deterministic VRF reveal.
pub fn vrf_proposal(id: u64, epoch: Epoch) -> BeaconProposal {
    let sk = keypair(id);
    let proof = beacon_reveal_sign(&sk, &net(), epoch).expect("sign");
    BeaconProposal::new(
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
        Vec::new(),
        proof,
    )
}

/// Build a `BeaconProposal` whose VRF proof has been tampered with so
/// verification fails — the signature is broken. The derived output
/// tracks the tampered proof automatically.
pub fn malformed_vrf_proposal(id: u64, epoch: Epoch) -> BeaconProposal {
    let p = vrf_proposal(id, epoch);
    let mut bytes = *p.vrf_proof().as_bytes();
    bytes[0] ^= 1;
    BeaconProposal::new(
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
        Vec::new(),
        VrfProof::new(bytes),
    )
}

pub fn validator_record(id: u64, pool: u32, status: ValidatorStatus) -> ValidatorRecord {
    ValidatorRecord {
        id: ValidatorId::new(id),
        pool: test_pool(pool),
        status,
        registered_at_epoch: Epoch::GENESIS,
        pubkey: pubkey(id),
    }
}

/// A live shard's boundary record at height 5, `misses` folds without a
/// crossing.
pub fn live_boundary(misses: u32) -> ShardBoundary {
    ShardBoundary {
        boundary_qc: None,
        state_root: StateRoot::ZERO,
        block_hash: BlockHash::from_raw(Hash::from_bytes(b"live")),
        height: BlockHeight::new(5),
        weighted_timestamp: WeightedTimestamp::ZERO,
        witness_leaf_count: BeaconWitnessLeafCount::ZERO,
        witness_base: BeaconWitnessLeafCount::ZERO,
        used: DeclaredWork::ZERO,
        blocks: 0,
        cumulative_fees: 0,
        substate_bytes: 0,
        formed: Epoch::GENESIS,
        last_live_epoch: Epoch::new(1),
        consecutive_misses: misses,
        terminal_epoch: None,
        handoff_complete: None,
        terminal_delivered: false,
        terminal_settled_txs: None,
        reshape_admitted_epoch: None,
    }
}

/// The boundary record genesis seeds for every shard it seats: no chain
/// behind it, its first crossing still to fold.
pub fn genesis_boundary() -> ShardBoundary {
    ShardBoundary {
        block_hash: BlockHash::ZERO,
        height: BlockHeight::GENESIS,
        last_live_epoch: Epoch::GENESIS,
        ..live_boundary(0)
    }
}

pub fn empty_state() -> BeaconState {
    BeaconState::empty(BeaconChainConfig::at_unix_epoch())
}

/// Build a state with one shard, one pool, and `n_active` validators
/// placed `OnShard { ready: true }`. The pool's `total_stake` is
/// `n_active * MIN_STAKE_FLOOR` — just enough to cover the active
/// set at the floor.
pub fn single_pool_state(n_active: u64) -> BeaconState {
    let mut state = empty_state();
    let pool_id = test_pool(0);
    let shard = ShardId::leaf(1, 0);

    let mut pool_validators = BTreeSet::new();
    let mut members = Vec::new();
    for i in 0..n_active {
        let id = ValidatorId::new(i);
        pool_validators.insert(id);
        members.push(id);
        state.validators.insert(
            id,
            validator_record(
                i,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
    }
    state.pools.insert(
        pool_id,
        StakePool {
            id: pool_id,
            total_stake: Stake::from_quanta(u128::from(n_active) * MIN_STAKE_FLOOR.quanta()),
            validators: pool_validators,
            pending_withdrawals: Vec::new(),
            released_cumulative: Stake::ZERO,
            conviction: None,
        },
    );
    state
        .next_shard_committees
        .insert(shard, ShardCommittee { members });
    state
}

/// [`single_pool_state`] whose shard carries the boundary record genesis
/// seeds, as every seated shard does: a shard contributes its crossings
/// only under a record.
pub fn single_pool_state_at_genesis(n_active: u64) -> BeaconState {
    let mut state = single_pool_state(n_active);
    state
        .boundaries
        .insert(ShardId::leaf(1, 0), genesis_boundary());
    state
}

/// Seat one more ready member, on a shard of its own, so the beacon-eligible
/// set sits above [`hyperscale_types::MIN_BEACON_COMMITTEE_SIZE`] and a jail
/// is never spared to keep the beacon able to propose.
pub fn lift_above_the_beacon_floor(state: &mut BeaconState) {
    let id = ValidatorId::new(99);
    let pool_id = test_pool(0);
    let pool = state
        .pools
        .get_mut(&pool_id)
        .expect("the fixture's one pool");
    pool.validators.insert(id);
    pool.total_stake = Stake::from_quanta(pool.total_stake.quanta() + MIN_STAKE_FLOOR.quanta());
    state.validators.insert(
        id,
        validator_record(
            99,
            0,
            ValidatorStatus::OnShard {
                shard: ShardId::leaf(1, 1),
                ready: true,
                placed_at_epoch: Epoch::GENESIS,
            },
        ),
    );
}

/// Run one `apply_epoch` against `state.current_epoch.next()`. The
/// helper exists to dodge a `&mut` / `&` aliasing complaint when
/// callers want to thread the next-epoch number from inside the
/// borrow.
pub fn apply_next_epoch(
    state: &mut BeaconState,
    committed: &[(ValidatorId, BeaconProposal)],
) -> SlotEffects {
    let next = state.current_epoch.next();
    apply_epoch(
        &BlsVerifier,
        state,
        &net(),
        next,
        ApplyEpochInput::Normal {
            committed,
            shard_contributions: &BTreeMap::new(),
        },
    )
}

/// The applied witness watermark for shard `shard_n` —
/// `boundaries[shard].witness_leaf_count`. Zero when the shard has no
/// boundary record.
pub fn applied_count(state: &BeaconState, shard_n: u64) -> u64 {
    state
        .boundaries
        .get(&ShardId::leaf(1, shard_n))
        .map_or(0, |b| b.witness_leaf_count.inner())
}

/// Build a `BeaconProposal` carrying `equivocations` and no boundary QCs.
pub fn vrf_proposal_with_equivocations(
    id: u64,
    epoch: Epoch,
    equivocations: Vec<PcVoteEquivocation>,
) -> BeaconProposal {
    let sk = keypair(id);
    let proof = beacon_reveal_sign(&sk, &net(), epoch).expect("sign");
    BeaconProposal::new(
        BTreeMap::new(),
        equivocations,
        BTreeMap::new(),
        Vec::new(),
        proof,
    )
}

/// Build a valid `BeaconProposal` carrying shard double-vote pairs on
/// the gossip-fed lane.
pub fn vrf_proposal_with_vote_equivocations(
    id: u64,
    epoch: Epoch,
    vote_equivocations: Vec<ShardVoteEquivocation>,
) -> BeaconProposal {
    let sk = keypair(id);
    let proof = beacon_reveal_sign(&sk, &net(), epoch).expect("sign");
    BeaconProposal::new(
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
        vote_equivocations,
        proof,
    )
}

/// Build shard `shard_n`'s boundary block `B` and the witness chunk
/// `[prior, prior + payloads.len())` that proves against it. `B`'s
/// accumulator is the full `[0, prior + n)` — filler hashes below the
/// applied watermark `prior`, the `payloads` at and above it — so the
/// returned range proof lifts the chunk into `B.beacon_witness_root`.
/// Returns the boundary header, the chunk's payloads, and its proof; the
/// caller seats them into a contribution (or tampers with one to exercise
/// rejection).
pub fn boundary_chunk(
    shard_n: u64,
    prior: u64,
    payloads: Vec<ShardWitnessPayload>,
) -> (BlockHeader, Vec<ShardWitnessPayload>, Vec<Hash>) {
    boundary_chunk_at(shard_n, BlockHeight::new(5), prior, 0, payloads)
}

/// [`boundary_chunk`] under a boundary header at `height`, claiming the
/// shard's chain has committed `blocks` blocks over its history.
fn boundary_chunk_at(
    shard_n: u64,
    height: BlockHeight,
    prior: u64,
    blocks: u64,
    payloads: Vec<ShardWitnessPayload>,
) -> (BlockHeader, Vec<ShardWitnessPayload>, Vec<Hash>) {
    let shard = ShardId::leaf(1, shard_n);
    let n = payloads.len() as u64;

    let mut leaf_hashes: Vec<Hash> = (0..prior)
        .map(|i| Hash::from_bytes(format!("filler-{shard_n}-{i}").as_bytes()))
        .collect();
    leaf_hashes.extend(payloads.iter().map(ShardWitnessPayload::leaf_hash));
    let boundary_count = prior + n;

    let root = compute_merkle_root(&leaf_hashes);
    let header = boundary_header(
        shard,
        height,
        BeaconWitnessRoot::from_raw(root),
        boundary_count,
        blocks,
    );

    let lo = usize::try_from(prior).expect("leaf index fits usize");
    let hi = usize::try_from(boundary_count).expect("leaf count fits usize");
    let range_proof = compute_range_proof(&leaf_hashes, lo, hi);
    (header, payloads, range_proof)
}

/// Apply `payloads` as shard `shard_n`'s witness chunk through one
/// `apply_epoch`, building a real boundary contribution: a boundary block
/// `B` whose `beacon_witness_root` commits the accumulator
/// `[0, prior + payloads.len())` (filler hashes below the applied
/// watermark `prior`, the payloads at `[prior, prior + n)`), the matching
/// per-leaf merkle proofs, and a committed proposal carrying `B`'s
/// boundary QC. `B` is a genuine epoch-boundary crossing
/// (`parent_qc.wt = 1 ≤ cut < qc.wt`), so the fold records it and applies
/// the chunk. `B` sits one block above the shard's recorded boundary, as a
/// chain's next crossing does. The boundary QC's signature is not checked
/// by the fold (admission-gated), so a placeholder QC suffices.
pub fn apply_witness_chunk(
    state: &mut BeaconState,
    shard_n: u64,
    payloads: Vec<ShardWitnessPayload>,
) -> SlotEffects {
    apply_witness_chunk_after(state, shard_n, 0, payloads)
}

/// [`apply_witness_chunk`] from a boundary block claiming the shard's
/// chain has committed `blocks` blocks over its history.
///
/// A shard contributes only under a boundary record, which every seated
/// shard carries from genesis on. The bare fixtures seat a shard without
/// one, so a shard that has none is given the record genesis seeds.
pub fn apply_witness_chunk_after(
    state: &mut BeaconState,
    shard_n: u64,
    blocks: u64,
    payloads: Vec<ShardWitnessPayload>,
) -> SlotEffects {
    state
        .boundaries
        .entry(ShardId::leaf(1, shard_n))
        .or_insert_with(genesis_boundary);
    fold_witness_chunk(state, shard_n, blocks, payloads)
}

/// [`apply_witness_chunk_after`] over the boundary records exactly as
/// `state` holds them.
pub fn fold_witness_chunk(
    state: &mut BeaconState,
    shard_n: u64,
    blocks: u64,
    payloads: Vec<ShardWitnessPayload>,
) -> SlotEffects {
    let shard = ShardId::leaf(1, shard_n);
    let dur = state.chain_config.epoch_duration_ms;
    let record = state.boundaries.get(&shard);
    let prior = record.map_or(0, |b| b.witness_leaf_count.inner());
    let height = record.map_or(BlockHeight::new(5), |b| b.height.next());

    let block = boundary_chunk_at(shard_n, height, prior, blocks, payloads);
    fold_blocks(state, dur + 1, vec![block])
}

/// A block of `shard` at `height` whose parent QC carries `anchor_ms` and
/// whose witness accumulator holds exactly `payloads`, beside the proof
/// lifting them to its root. `rest` supplies every other header field.
pub fn block_carrying(
    shard: ShardId,
    height: u64,
    anchor_ms: u64,
    payloads: Vec<ShardWitnessPayload>,
    rest: BlockHeaderParts,
) -> (BlockHeader, Vec<ShardWitnessPayload>, Vec<Hash>) {
    let leaf_hashes: Vec<Hash> = payloads
        .iter()
        .map(ShardWitnessPayload::leaf_hash)
        .collect();
    let root = if leaf_hashes.is_empty() {
        BeaconWitnessRoot::ZERO
    } else {
        BeaconWitnessRoot::from_raw(compute_merkle_root(&leaf_hashes))
    };
    let parent_qc = QuorumCertificate::new(
        BlockHash::ZERO,
        shard,
        BlockHeight::new(height.saturating_sub(1)),
        BlockHash::ZERO,
        Round::INITIAL,
        SignerBitfield::new(4),
        AggregateSignature::ZERO,
        WeightedTimestamp::from_millis(anchor_ms),
    );
    let header = BlockHeader::new(BlockHeaderParts {
        shard_id: shard,
        height: BlockHeight::new(height),
        parent_qc: parent_qc.into(),
        beacon_witness_root: root,
        beacon_witness_leaf_count: BeaconWitnessLeafCount::new(leaf_hashes.len() as u64),
        ..rest
    });
    let range_proof = compute_range_proof(&leaf_hashes, 0, leaf_hashes.len());
    (header, payloads, range_proof)
}

/// Fold the next epoch over `blocks`, each the one contribution of its
/// shard: a block, the witness chunk the fold's watermark calls for and
/// the proof lifting the chunk to the block's root. Every block is
/// certified at `certified_ms` by a QC every committed proposal carries.
/// The fold binds a QC by hash and does not check its signature, which
/// admission does, so an unsigned QC stands in.
pub fn fold_blocks(
    state: &mut BeaconState,
    certified_ms: u64,
    blocks: Vec<(BlockHeader, Vec<ShardWitnessPayload>, Vec<Hash>)>,
) -> SlotEffects {
    let boundary_qcs: BTreeMap<ShardId, Option<QuorumCertificate>> = blocks
        .iter()
        .map(|(header, _, _)| {
            let qc = QuorumCertificate::new(
                header.hash(),
                header.shard_id(),
                header.height(),
                header.parent_block_hash(),
                Round::INITIAL,
                SignerBitfield::new(4),
                AggregateSignature::ZERO,
                WeightedTimestamp::from_millis(certified_ms),
            );
            (header.shard_id(), Some(qc))
        })
        .collect();
    // Every beacon committee member proposes (each with its own valid
    // VRF), so the absence pass reads full participation and the fold
    // under test is the contributions alone. An empty committee (the
    // bare fixtures) falls back to a single stand-in proposer.
    let next_epoch = state.current_epoch.next();
    let proposers: Vec<ValidatorId> = if state.committee.is_empty() {
        vec![ValidatorId::new(0)]
    } else {
        state.committee.clone()
    };
    let committed: Vec<(ValidatorId, BeaconProposal)> = proposers
        .into_iter()
        .map(|id| {
            (
                id,
                BeaconProposal::new(
                    boundary_qcs.clone(),
                    Vec::new(),
                    BTreeMap::new(),
                    Vec::new(),
                    beacon_reveal_sign(&keypair(id.inner()), &net(), next_epoch).expect("sign"),
                ),
            )
        })
        .collect();
    let contributions: BTreeMap<ShardId, ShardEpochContribution> = blocks
        .into_iter()
        .map(|(header, payloads, range_proof)| {
            (
                header.shard_id(),
                ShardEpochContribution {
                    boundary_header: header,
                    payloads: Capped::new(payloads)
                        .expect("a list under the cap its source already met"),
                    range_proof: Capped::new(range_proof)
                        .expect("a list under the cap its source already met"),
                },
            )
        })
        .collect();

    apply_epoch(
        &BlsVerifier,
        state,
        &net(),
        next_epoch,
        ApplyEpochInput::Normal {
            committed: &committed,
            shard_contributions: &contributions,
        },
    )
}

/// A source-shard boundary block header at `height` committing `root` /
/// `leaf_count`, crossing the first epoch boundary (predecessor at
/// weighted timestamp 1, before the cut). Only the fields the boundary
/// fold reads carry meaning.
fn boundary_header(
    shard: ShardId,
    height: BlockHeight,
    root: BeaconWitnessRoot,
    leaf_count: u64,
    blocks: u64,
) -> BlockHeader {
    let parent_qc = QuorumCertificate::new(
        BlockHash::ZERO,
        shard,
        height.prev().unwrap_or(BlockHeight::GENESIS),
        BlockHash::ZERO,
        Round::INITIAL,
        SignerBitfield::new(4),
        AggregateSignature::ZERO,
        WeightedTimestamp::from_millis(1),
    );
    BlockHeader::new(BlockHeaderParts {
        shard_id: shard,
        height,
        parent_block_hash: BlockHash::ZERO,
        parent_qc: parent_qc.into(),
        beacon_witness_root: root,
        beacon_witness_leaf_count: BeaconWitnessLeafCount::new(leaf_count),
        load: ShardLoad {
            blocks,
            ..ShardLoad::ZERO
        },
        ..Default::default()
    })
}

/// Build a single-pool state with `n_actives` active validators
/// (placed `OnShard`) and one pre-loaded `PendingWithdrawal`. The
/// fixture parks `current_epoch` at a value past the unbonding
/// window so the test can run `apply_epoch` and watch the
/// withdrawal mature.
pub fn state_with_pending_withdrawal(
    n_actives: u64,
    total_stake: Stake,
    withdrawal_amount: Stake,
    initiated_at_epoch: Epoch,
    current_epoch: Epoch,
) -> BeaconState {
    let mut state = empty_state();
    state.current_epoch = current_epoch;
    let pool_id = test_pool(0);
    let shard = ShardId::leaf(1, 0);
    let mut pool_validators = BTreeSet::new();
    let mut members = Vec::new();
    for i in 0..n_actives {
        let id = ValidatorId::new(i);
        pool_validators.insert(id);
        members.push(id);
        state.validators.insert(
            id,
            validator_record(
                i,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
    }
    state.pools.insert(
        pool_id,
        StakePool {
            id: pool_id,
            total_stake,
            validators: pool_validators,
            pending_withdrawals: vec![PendingWithdrawal {
                amount: withdrawal_amount,
                initiated_at_epoch,
            }],
            released_cumulative: Stake::ZERO,
            conviction: None,
        },
    );
    state
        .next_shard_committees
        .insert(shard, ShardCommittee { members });
    state.committee = (0..n_actives).map(ValidatorId::new).collect();
    state
}

/// The quiet assertion each shard a latched reshape drains makes once no
/// row of it hears, naming its record's admission: a split's target, and
/// both children of a merge, each from its own chain.
pub fn quiet_assertions(state: &BeaconState) -> Vec<(ShardId, ShardWitnessPayload)> {
    let settling = |admitted: Admission| {
        admitted.drain_by.map(|_| Settling {
            admitted: admitted.at,
            quiet: true,
        })
    };
    let mut assertions = Vec::new();
    for (target, reshape) in &state.pending_reshapes {
        match reshape {
            PendingReshape::Split { admitted, .. } => {
                if let Some(settling) = settling(*admitted) {
                    assertions.push((
                        *target,
                        ShardWitnessPayload::ScheduleSplit {
                            shard: *target,
                            epoch: state.current_epoch,
                            settling: Some(settling),
                        },
                    ));
                }
            }
            PendingReshape::Merge { admitted, .. } => {
                if let Some(settling) = admitted.and_then(settling) {
                    for child in <[ShardId; 2]>::from(target.children()) {
                        assertions.push((
                            child,
                            ShardWitnessPayload::ScheduleMerge {
                                parent: *target,
                                epoch: state.current_epoch,
                                settling: Some(settling),
                            },
                        ));
                    }
                }
            }
        }
    }
    assertions
}

/// Fold [`quiet_assertions`]: every latched reshape's shards say they are
/// quiet.
pub fn assert_quiet(state: &mut BeaconState) {
    for (source, payload) in quiet_assertions(state) {
        apply_shard_payload(&BlsVerifier, state, &net(), source, &payload);
    }
}
