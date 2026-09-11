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
use hyperscale_types::{
    AggregateSignature, BeaconChainConfig, BeaconProposal, BeaconState, BeaconWitnessLeafCount,
    BeaconWitnessRoot, BlockHash, BlockHeader, BlockHeaderParts, BlockHeight, ConsensusSignature,
    Epoch, Hash, MIN_STAKE_FLOOR, NetworkDefinition, PcVoteEquivocation, PendingWithdrawal,
    QuorumCertificate, Round, ShardCommittee, ShardEpochContribution, ShardId,
    ShardVoteEquivocation, ShardWitnessPayload, SignerBitfield, SlotEffects, Stake, StakePool,
    StakePoolId, ValidatorId, ValidatorRecord, ValidatorStatus, VrfProof, WeightedTimestamp,
    beacon_reveal_sign, compute_merkle_root, compute_range_proof, validator_possession_proof_sign,
};

use crate::state::{ApplyEpochInput, apply_epoch};

pub fn net() -> NetworkDefinition {
    NetworkDefinition::simulator()
}

/// A valid proof-of-possession for `pubkey(seed)` claimed under `id`.
pub fn possession_proof(seed: u64, id: ValidatorId) -> ConsensusSignature {
    validator_possession_proof_sign(&keypair(seed), &net(), id).expect("sign")
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
        pool: StakePoolId::new(pool),
        status,
        registered_at_epoch: Epoch::GENESIS,
        pubkey: pubkey(id),
    }
}

pub fn empty_state() -> BeaconState {
    BeaconState::empty(BeaconChainConfig::default())
}

/// Build a state with one shard, one pool, and `n_active` validators
/// placed `OnShard { ready: true }`. The pool's `total_stake` is
/// `n_active * MIN_STAKE_FLOOR` — just enough to cover the active
/// set at the floor.
pub fn single_pool_state(n_active: u64) -> BeaconState {
    let mut state = empty_state();
    let pool_id = StakePoolId::new(0);
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
    let shard = ShardId::leaf(1, shard_n);
    let n = payloads.len() as u64;

    let mut leaf_hashes: Vec<Hash> = (0..prior)
        .map(|i| Hash::from_bytes(format!("filler-{shard_n}-{i}").as_bytes()))
        .collect();
    leaf_hashes.extend(payloads.iter().map(ShardWitnessPayload::leaf_hash));
    let boundary_count = prior + n;

    let root = compute_merkle_root(&leaf_hashes);
    let header = boundary_header(shard, BeaconWitnessRoot::from_raw(root), boundary_count);

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
/// the chunk. The boundary QC's signature is not checked by the fold
/// (admission-gated), so a placeholder QC suffices.
pub fn apply_witness_chunk(
    state: &mut BeaconState,
    shard_n: u64,
    payloads: Vec<ShardWitnessPayload>,
) -> SlotEffects {
    let shard = ShardId::leaf(1, shard_n);
    let dur = state.chain_config.epoch_duration_ms;
    let prior = state
        .boundaries
        .get(&shard)
        .map_or(0, |b| b.witness_leaf_count.inner());

    let (header, payloads, range_proof) = boundary_chunk(shard_n, prior, payloads);
    let block_hash = header.hash();

    // A placeholder boundary QC over `B` at a weighted timestamp past the
    // first epoch cut, naming `B` by hash. The fold binds by hash and
    // checks the crossing bound; it does not re-verify the signature.
    let qc = QuorumCertificate::new(
        block_hash,
        shard,
        header.height(),
        header.parent_block_hash(),
        Round::INITIAL,
        SignerBitfield::new(4),
        AggregateSignature::ZERO,
        WeightedTimestamp::from_millis(dur + 1),
    );
    // Every beacon committee member proposes (each with its own valid
    // VRF), so the absence pass reads full participation and the fold
    // under test is the witness chunk alone. An empty committee (the
    // bare fixtures) falls back to a single stand-in proposer.
    let boundary_qcs: BTreeMap<ShardId, Option<QuorumCertificate>> =
        std::iter::once((shard, Some(qc))).collect();
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
    let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
        shard,
        ShardEpochContribution {
            boundary_header: header,
            payloads,
            range_proof,
        },
    ))
    .collect();

    let next = state.current_epoch.next();
    apply_epoch(
        &BlsVerifier,
        state,
        &net(),
        next,
        ApplyEpochInput::Normal {
            committed: &committed,
            shard_contributions: &contributions,
        },
    )
}

/// A source-shard boundary block header committing `root` /
/// `leaf_count`, crossing the first epoch boundary (predecessor at
/// weighted timestamp 1, before the cut). Only the fields the boundary
/// fold reads carry meaning.
fn boundary_header(shard: ShardId, root: BeaconWitnessRoot, leaf_count: u64) -> BlockHeader {
    let parent_qc = QuorumCertificate::new(
        BlockHash::ZERO,
        shard,
        BlockHeight::new(4),
        BlockHash::ZERO,
        Round::INITIAL,
        SignerBitfield::new(4),
        AggregateSignature::ZERO,
        WeightedTimestamp::from_millis(1),
    );
    BlockHeader::new(BlockHeaderParts {
        shard_id: shard,
        height: BlockHeight::new(5),
        parent_block_hash: BlockHash::ZERO,
        parent_qc: parent_qc.into(),
        beacon_witness_root: root,
        beacon_witness_leaf_count: BeaconWitnessLeafCount::new(leaf_count),
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
    let pool_id = StakePoolId::new(0);
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
