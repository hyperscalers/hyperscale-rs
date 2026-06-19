//! Shared test fixtures for state-module tests. Each submodule's
//! `#[cfg(test)] mod tests` pulls these in via
//! `use crate::test_fixtures::*` so common scaffolding
//! (keypair derivation, VRF-signed proposals, single-pool state)
//! lives in one place.

#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconChainConfig, BeaconProposal, BeaconState, BeaconWitnessLeafCount, BeaconWitnessRoot,
    BlockHash, BlockHeader, BlockHeight, Bls12381G1PrivateKey, Bls12381G1PublicKey,
    CertificateRoot, Epoch, Hash, InFlightCount, LeafIndex, LocalReceiptRoot, MIN_STAKE_FLOOR,
    NetworkDefinition, NetworkParams, PcVoteEquivocation, PendingWithdrawal, ProposerTimestamp,
    ProvisionsRoot, QuorumCertificate, Randomness, Round, ShardCommittee, ShardEpochContribution,
    ShardId, ShardWitness, ShardWitnessPayload, ShardWitnessProof, SignerBitfield, SlotEffects,
    Stake, StakePool, StakePoolId, StateRoot, TransactionRoot, ValidatorId, ValidatorRecord,
    ValidatorStatus, VrfProof, WeightedTimestamp, bls_keypair_from_seed,
    compute_merkle_root_with_proof, vrf_sign, zero_bls_signature,
};

use crate::state::{ApplyEpochInput, apply_epoch};

pub fn keypair(seed: u64) -> Bls12381G1PrivateKey {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&seed.to_le_bytes());
    bls_keypair_from_seed(&s)
}

pub fn pubkey(seed: u64) -> Bls12381G1PublicKey {
    keypair(seed).public_key()
}

pub fn net() -> NetworkDefinition {
    NetworkDefinition::simulator()
}

/// Build an honest VRF-signed empty `BeaconProposal` for validator
/// `id` at `epoch`. No witnesses (witness ingestion is a later
/// stage); just a deterministic VRF reveal.
pub fn vrf_proposal(id: u64, epoch: Epoch) -> BeaconProposal {
    let sk = keypair(id);
    let proof = vrf_sign(&sk, &net(), epoch);
    BeaconProposal::new(BTreeMap::new(), Vec::new(), proof)
}

/// Build a `BeaconProposal` whose VRF proof has been tampered with so
/// verification fails — the BLS sig is broken. The derived output
/// tracks the tampered proof automatically.
pub fn malformed_vrf_proposal(id: u64, epoch: Epoch) -> BeaconProposal {
    let p = vrf_proposal(id, epoch);
    let mut bytes = *p.vrf_proof().as_bytes();
    bytes[0] ^= 1;
    BeaconProposal::new(BTreeMap::new(), Vec::new(), VrfProof::new(bytes))
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
    BeaconState {
        chain_config: BeaconChainConfig::default(),
        params: NetworkParams::default(),
        param_votes: BTreeMap::new(),
        current_epoch: Epoch::GENESIS,
        validators: BTreeMap::new(),
        pools: BTreeMap::new(),
        randomness: Randomness::ZERO,
        committee: Vec::new(),
        shard_committees: BTreeMap::new(),
        next_shard_committees: BTreeMap::new(),
        shard_consensus_members: BTreeMap::new(),
        witness_window_bases: BTreeMap::new(),
        split_pending_window: BTreeSet::new(),
        reshape_observers_window: BTreeMap::new(),
        reshape_keepers_window: BTreeMap::new(),
        boundaries: BTreeMap::new(),
        pending_reshapes: BTreeMap::new(),
        miss_counters: BTreeMap::new(),
    }
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
            total_stake: Stake::from_attos(u128::from(n_active) * MIN_STAKE_FLOOR.attos()),
            validators: pool_validators,
            pending_withdrawals: Vec::new(),
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
    let proof = vrf_sign(&sk, &net(), epoch);
    BeaconProposal::new(BTreeMap::new(), equivocations, proof)
}

/// Build shard `shard_n`'s boundary block `B` and the witness chunk
/// `[prior, prior + payloads.len())` that proves against it. `B`'s
/// accumulator is the full `[0, prior + n)` — filler hashes below the
/// applied watermark `prior`, the `payloads` at and above it — so every
/// returned witness merkle-proves into `B.beacon_witness_root`. Returns
/// the boundary header and its chunk; the caller seats them into a
/// contribution (or tampers with the chunk to exercise rejection).
pub fn boundary_chunk(
    shard_n: u64,
    prior: u64,
    payloads: Vec<ShardWitnessPayload>,
) -> (BlockHeader, Vec<ShardWitness>) {
    let shard = ShardId::leaf(1, shard_n);
    let n = payloads.len() as u64;

    let mut leaf_hashes: Vec<Hash> = (0..prior)
        .map(|i| Hash::from_bytes(format!("filler-{shard_n}-{i}").as_bytes()))
        .collect();
    leaf_hashes.extend(payloads.iter().map(ShardWitnessPayload::leaf_hash));
    let boundary_count = prior + n;

    let (root, _, _) = compute_merkle_root_with_proof(&leaf_hashes, 0);
    let header = boundary_header(shard, BeaconWitnessRoot::from_raw(root), boundary_count);
    let block_hash = header.hash();

    let witnesses: Vec<ShardWitness> = payloads
        .into_iter()
        .enumerate()
        .map(|(offset, payload)| {
            let leaf = prior + offset as u64;
            let (_, siblings, _) = compute_merkle_root_with_proof(
                &leaf_hashes,
                usize::try_from(leaf).expect("leaf index fits usize"),
            );
            ShardWitness {
                payload,
                proof: ShardWitnessProof {
                    shard_id: shard,
                    committed_block_hash: block_hash,
                    leaf_index: LeafIndex::new(leaf),
                    siblings: siblings.into(),
                },
            }
        })
        .collect();
    (header, witnesses)
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

    let (header, witnesses) = boundary_chunk(shard_n, prior, payloads);
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
        zero_bls_signature(),
        WeightedTimestamp::from_millis(dur + 1),
    );
    let proposal = BeaconProposal::new(
        std::iter::once((shard, Some(qc))).collect(),
        Vec::new(),
        vrf_sign(&keypair(0), &net(), state.current_epoch.next()),
    );
    let committed = vec![(ValidatorId::new(0), proposal)];
    let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
        shard,
        ShardEpochContribution {
            boundary_header: header,
            witnesses: witnesses.into(),
        },
    ))
    .collect();

    let next = state.current_epoch.next();
    apply_epoch(
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
        zero_bls_signature(),
        WeightedTimestamp::from_millis(1),
    );
    BlockHeader::new(
        shard,
        BlockHeight::new(5),
        BlockHash::ZERO,
        parent_qc,
        ValidatorId::new(0),
        ProposerTimestamp::ZERO,
        Round::INITIAL,
        false,
        StateRoot::ZERO,
        TransactionRoot::ZERO,
        CertificateRoot::ZERO,
        LocalReceiptRoot::ZERO,
        ProvisionsRoot::ZERO,
        Vec::new(),
        BTreeMap::new(),
        InFlightCount::ZERO,
        root,
        BeaconWitnessLeafCount::new(leaf_count),
        BeaconWitnessLeafCount::ZERO,
        None,
        None,
    )
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
        },
    );
    state
        .next_shard_committees
        .insert(shard, ShardCommittee { members });
    state.committee = (0..n_actives).map(ValidatorId::new).collect();
    state
}
