//! Test utilities.

use std::sync::Arc;

use hyperscale_crypto::{Signer, Verifier};
use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
use hyperscale_hbor::Hash32;
use hyperscale_vm_types::{
    Address, AddressClass, LegRole, LegShape, LocalKey, Mode, Moves, PrincipalAddr,
    SWEEP_BUCKET_BYTES, SchemeId, SubintentHash, SubstateKey, SweepBucket, ValueEdge,
};

use crate::crypto::Ed25519PrivateKey;
use crate::{
    AbortCharge, AggregateSignature, Block, BlockHash, BlockHeader, BlockHeaderParts, BlockHeight,
    BlockVoteMessage, CertifiedBlock, CertifiedBlockHeader, ChainOrigin, CommitProof,
    ConsensusPublicKey, ConsensusReceipt, ConsensusSignature, DeclaredKey, Derivation,
    DerivationError, Derived, EnvelopeExt, ExecutionCertificate, ExecutionOutcome, Finalization,
    GlobalReceiptHash, Hash, MerkleInclusionProof, NetworkDefinition, NetworkId, ProposerTimestamp,
    ProtocolStatics, QuorumCertificate, Role, Round, Routing, ShardForkProof, ShardId,
    SignerBitfield, StateRoot, StateWrites, StoredReceipt, SubintentSig, TickHalf, TickId,
    TimestampRange, TopologySnapshot, Transaction, TransactionBody, TransactionDecision,
    TransactionEnvelope, TxHash, TxOutcome, ValidatorId, ValidatorInfo, ValidatorSet, Verifiable,
    Verified, WeightedTimestamp, WitnessSources, compute_global_receipt_root, declared_work,
    install_protocol_statics, protocol_statics_installed, signed_bytes,
};

/// Create a test transaction the [`StubVmStatics`] derivation routes to
/// `read_prefixes` as shared keys and `write_prefixes` as exclusive ones.
///
/// `seed_bytes` varies the fee payer, so transactions differing only in
/// seed are distinct by hash while routing identically.
#[must_use]
pub fn test_transaction_with_prefixes(
    seed_bytes: &[u8],
    read_prefixes: &[Address],
    write_prefixes: &[Address],
) -> Transaction {
    let mut body = [0u8; 31];
    for (slot, &byte) in body.iter_mut().zip(seed_bytes) {
        *slot = byte;
    }
    stub_transaction_with_reads(
        PrincipalAddr::new(body),
        read_prefixes,
        write_prefixes,
        1_000,
        test_validity_range(),
    )
}

/// Validity range used for test transactions.
///
/// A wide window centred on `WeightedTimestamp::ZERO` so test fixtures
/// don't need to thread a real anchor through every helper. Tests that
/// exercise expiry should build their own range.
#[must_use]
pub fn test_validity_range() -> TimestampRange {
    use std::time::Duration;
    TimestampRange::new(
        WeightedTimestamp::ZERO,
        WeightedTimestamp::ZERO.plus(Duration::from_mins(1)),
    )
}

/// Create a test owner prefix from a seed byte.
#[must_use]
pub const fn test_prefix(seed: u8) -> Address {
    Address::new([seed; 31], AddressClass::Component)
}

/// A principal prefix from a seed byte — an account, whose class is what
/// resolves it to the protocol's blueprint.
#[must_use]
pub const fn test_principal(seed: u8) -> PrincipalAddr {
    PrincipalAddr::new([seed; 31])
}

/// A substate key seeded by one byte: the owner prefix and the local half
/// both filled with it.
#[must_use]
pub const fn test_key(seed: u8) -> SubstateKey {
    SubstateKey {
        owner: test_prefix(seed),
        local: LocalKey([seed; 16]),
    }
}

/// Create a simple test transaction.
#[must_use]
pub fn test_transaction(seed: u8) -> Transaction {
    test_transaction_with_prefixes(
        &[seed, seed.wrapping_add(1), seed.wrapping_add(2)],
        &[test_prefix(seed)],
        &[test_prefix(seed.wrapping_add(10))],
    )
}

/// [`test_transaction`] reported as running `packages` — the fixture for
/// anything gated on what code a transaction needs.
#[must_use]
pub fn test_transaction_running(seed: u8, packages: &[Hash]) -> Transaction {
    let mut body = [0u8; 31];
    for (slot, &byte) in body
        .iter_mut()
        .zip(&[seed, seed.wrapping_add(1), seed.wrapping_add(2)])
    {
        *slot = byte;
    }
    stub_transaction_running(
        PrincipalAddr::new(body),
        packages,
        &[test_prefix(seed)],
        &[test_prefix(seed.wrapping_add(10))],
        1_000,
        test_validity_range(),
    )
}

/// Convenience: wrap [`test_transaction`] in a `Verified` witness via
/// the test-only gate.
///
/// Use at any test call site that needs a pre-validated transaction
/// (mempool admission API, event payloads carrying
/// `Arc<Verified<Transaction>>`).
#[must_use]
pub fn verified_test_transaction(seed: u8) -> Verified<Transaction> {
    Verified::new_unchecked_for_test(test_transaction(seed))
}

/// A test committee of validators with deterministic BLS keypairs.
///
/// Provides easy access to keypairs, public keys, and validator IDs
/// for creating signed test fixtures. Seeded generation means tests sign
/// and verify against real cryptographic paths rather than bypassing them
/// with zero signatures.
pub struct TestCommittee {
    signers: Vec<Arc<BlsSigner>>,
    public_keys: Vec<ConsensusPublicKey>,
    validator_ids: Vec<ValidatorId>,
}

impl std::fmt::Debug for TestCommittee {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCommittee")
            .field("size", &self.signers.len())
            .field("validator_ids", &self.validator_ids)
            .finish_non_exhaustive()
    }
}

/// Mixing constant for this fixture's consensus-key derivation.
///
/// Deliberately different from the one `hyperscale-network-libp2p`'s
/// test fixtures use: the two are independent families, and the same
/// `(seed, index)` must not name the same key in both.
const KEY_DERIVATION_MIX: u64 = 0x517c_c1b7_2722_0a95;

impl TestCommittee {
    /// Create a new test committee with the given size and seed.
    ///
    /// The seed ensures deterministic key generation for reproducible tests.
    /// Different seeds produce different committees.
    #[must_use]
    pub fn new(size: usize, seed: u64) -> Self {
        let mut signers = Vec::with_capacity(size);
        let mut public_keys = Vec::with_capacity(size);
        let mut validator_ids = Vec::with_capacity(size);

        for i in 0..size {
            // Generate deterministic seed for this validator
            let mut seed_bytes = [0u8; 32];
            let key_seed = seed.wrapping_add(i as u64).wrapping_mul(KEY_DERIVATION_MIX);
            seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
            seed_bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
            seed_bytes[16..24].copy_from_slice(&seed.to_le_bytes());

            let signer = BlsSigner::from_seed(&seed_bytes);
            let pk = signer.public_key();

            signers.push(Arc::new(signer));
            public_keys.push(pk);
            validator_ids.push(ValidatorId::new(i as u64));
        }

        Self {
            signers,
            public_keys,
            validator_ids,
        }
    }

    /// Create a test committee for a specific shard with offset validator IDs.
    ///
    /// Useful for multi-shard tests where validator IDs need to be globally
    /// unique: shard 0 seats validators `0..size`, shard 1 seats
    /// `size..2*size`, and so on.
    #[must_use]
    pub fn for_shard(size: usize, seed: u64, shard_index: u64) -> Self {
        let mut committee = Self::new(size, seed.wrapping_add(shard_index * 1000));

        // Offset validator IDs by shard
        let offset = shard_index * size as u64;
        for (i, vid) in committee.validator_ids.iter_mut().enumerate() {
            *vid = ValidatorId::new(offset + i as u64);
        }

        committee
    }

    /// Get the number of validators in the committee.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.signers.len()
    }

    /// Get a signer by index.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= size()`.
    #[must_use]
    pub fn signer(&self, idx: usize) -> Arc<dyn Signer> {
        let signer: Arc<BlsSigner> = Arc::clone(&self.signers[idx]);
        signer
    }

    /// Get a public key by index.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= size()`.
    #[must_use]
    pub fn public_key(&self, idx: usize) -> &ConsensusPublicKey {
        &self.public_keys[idx]
    }

    /// Get a validator ID by index.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= size()`.
    #[must_use]
    pub fn validator_id(&self, idx: usize) -> ValidatorId {
        self.validator_ids[idx]
    }

    /// Get all public keys.
    #[must_use]
    pub fn public_keys(&self) -> &[ConsensusPublicKey] {
        &self.public_keys
    }

    /// Get all validator IDs.
    #[must_use]
    pub fn validator_ids(&self) -> &[ValidatorId] {
        &self.validator_ids
    }

    /// Calculate quorum threshold (2f+1 where n = 3f+1).
    ///
    /// For a committee of size n, quorum is ceil(2n/3) + 1.
    #[must_use]
    pub const fn quorum_threshold(&self) -> usize {
        (self.size() * 2 / 3) + 1
    }

    /// Get the indices needed for a minimal quorum.
    ///
    /// Returns the first `quorum_threshold()` indices.
    #[must_use]
    pub fn quorum_indices(&self) -> Vec<usize> {
        (0..self.quorum_threshold()).collect()
    }

    /// Build a [`TopologySnapshot`] from this committee with uniform voting
    /// power. `num_shards` sets the shard count for tx routing. Network
    /// defaults to [`NetworkDefinition::simulator`]. Identity-agnostic —
    /// callers carry their own `(me, shard)`.
    #[must_use]
    pub fn topology_snapshot(&self, num_shards: u64) -> TopologySnapshot {
        let validators: Vec<ValidatorInfo> = (0..self.size())
            .map(|i| ValidatorInfo {
                validator_id: self.validator_id(i),
                public_key: *self.public_key(i),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        TopologySnapshot::new(NetworkDefinition::simulator(), num_shards, validator_set)
    }
}

/// Build a minimal `Block::Live` fixture for driving state machines.
///
/// Every non-essential header field takes a zero default: all merkle roots
/// are `Hash::ZERO`, `parent_qc` is the ZERO-anchored root-shard genesis QC,
/// `round` is `Round::INITIAL`, and there are no tick roots or provisions.
/// Callers pass only the bits that vary between tests.
///
/// Transactions are wrapped as `Verifiable::Unverified` — adequate for the
/// `on_block_committed` path (`TickState` lifts via
/// [`Verified::<Transaction>::from_persisted`]) and for storage
/// fixtures. The pre-vote path (`validate_block_for_vote`) refuses to vote
/// on blocks with any un-`Verified` entry; tests targeting that path must
/// construct `Block` directly with `Vec<Arc<Verifiable<Transaction>>>`
/// holding `Verified` entries.
#[must_use]
pub fn make_live_block(
    shard_id: ShardId,
    height: BlockHeight,
    timestamp_ms: u64,
    proposer: ValidatorId,
    transactions: Vec<Arc<Transaction>>,
    certificates: Vec<Arc<Verifiable<Finalization>>>,
) -> Block {
    let header = BlockHeader::new(BlockHeaderParts {
        shard_id,
        height,
        parent_block_hash: BlockHash::ZERO,
        parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
        proposer,
        timestamp: ProposerTimestamp::from_millis(timestamp_ms),
        provision_tx_roots: std::collections::BTreeMap::new(),
        ..Default::default()
    });
    let transactions: Vec<Arc<Verifiable<Transaction>>> = transactions
        .into_iter()
        .map(|tx| Arc::new(Verifiable::from((*tx).clone())))
        .collect();
    Block::Live {
        header,
        transactions: Arc::new(transactions),
        certificates: Arc::new(certificates),
        provisions: Arc::new(Vec::new()),
        abandonment_records: Arc::new(Vec::new()),
        state_claims: Arc::new(Vec::new()),
        witness_sources: Arc::new(WitnessSources::empty()),
    }
}

/// Pair a block with a minimal valid `QuorumCertificate` so it satisfies
/// the `CertifiedBlock` pairing invariant.
///
/// `weighted_timestamp_ms` stamps the block's time anchor. The commit clock
/// reads the block's `parent_qc` weighted timestamp (the hash-pinned anchor),
/// so the value is stamped there — kept genesis-shaped so `is_genesis()` still
/// holds — and mirrored onto the certifying QC for callers that read it
/// directly. Pass `0` when retention-window behavior doesn't matter.
#[must_use]
pub fn certify(block: Block, weighted_timestamp_ms: u64) -> CertifiedBlock {
    let block = stamp_parent_qc_weighted_timestamp(block, weighted_timestamp_ms);
    let qc = {
        let __qc = QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT);
        QuorumCertificate::new(
            block.hash(),
            __qc.shard_id(),
            __qc.height(),
            __qc.parent_block_hash(),
            __qc.round(),
            __qc.signers().clone(),
            __qc.aggregated_signature(),
            WeightedTimestamp::from_millis(weighted_timestamp_ms),
        )
    };
    // SAFETY: synthetic test fixture. Wrapped `Verified` because every
    // commit path stores a verified QC — consumers of committed blocks
    // (e.g. `certified_header()`) rely on that invariant.
    CertifiedBlock::new_unchecked(block, Verified::new_unchecked_for_test(qc))
}

/// Build a real-BLS [`ShardForkProof::ConflictingCommits`] for `shard` at
/// `height`, signed by `committee`.
///
/// Two direct-commit branches with distinct block hashes (their proposer
/// timestamps differ), each a round-contiguous two-chain — a self-proving
/// committee-level fork that verifies against a schedule built from
/// `committee` (`TopologySchedule::single(committee.topology_snapshot(..))`).
/// The branches sit at distinct rounds, so no seat signs twice at one
/// `(height, round)` — a round-invariant proof with no same-round sub-pair.
#[must_use]
pub fn shard_fork_proof(
    committee: &TestCommittee,
    shard: ShardId,
    height: BlockHeight,
) -> ShardForkProof {
    let parent = BlockHash::from_raw(Hash::from_bytes(b"shard-fork-fixture-parent"));
    let round_a = Round::new(height.inner().saturating_add(4));
    let round_b = Round::new(height.inner().saturating_add(6));
    ShardForkProof::ConflictingCommits {
        a: direct_commit_proof(committee, shard, height, round_a, parent, 1),
        b: direct_commit_proof(committee, shard, height, round_b, parent, 2),
    }
}

/// Build a real-BLS same-round [`ShardForkProof::ConflictingCommits`] for
/// `shard` at `height`, with each branch signed by a distinct signer set.
///
/// Both branches' certified blocks sit at the same `(height, round)` with
/// different hashes, so [`ShardForkProof::same_round_conflict`] extracts
/// the pair and the intersection `signers_a ∩ signers_b` names the seats
/// that double-signed. `signers_a`/`signers_b` are committee indices; each
/// must be a valid quorum (`>= committee.quorum_threshold()`) or its QC
/// won't authenticate.
#[must_use]
pub fn shard_fork_proof_same_round(
    committee: &TestCommittee,
    shard: ShardId,
    height: BlockHeight,
    signers_a: &[usize],
    signers_b: &[usize],
) -> ShardForkProof {
    let parent = BlockHash::from_raw(Hash::from_bytes(b"shard-fork-fixture-parent"));
    let round = Round::new(height.inner().saturating_add(4));
    ShardForkProof::ConflictingCommits {
        a: direct_commit_proof_signed(committee, shard, height, round, parent, 1, signers_a),
        b: direct_commit_proof_signed(committee, shard, height, round, parent, 2, signers_b),
    }
}

/// A direct-commit [`CommitProof`] for a block at `(height, round)` on
/// `shard` with a round-contiguous child, signed by `committee`'s minimal
/// quorum. `salt` distinguishes sibling branches by varying the proposer
/// timestamp (and so the block hash).
#[must_use]
pub(crate) fn direct_commit_proof(
    committee: &TestCommittee,
    shard: ShardId,
    height: BlockHeight,
    round: Round,
    parent: BlockHash,
    salt: u64,
) -> CommitProof {
    direct_commit_proof_signed(
        committee,
        shard,
        height,
        round,
        parent,
        salt,
        &committee.quorum_indices(),
    )
}

/// [`direct_commit_proof`] with an explicit signer set for the certified
/// block (its round-contiguous child keeps the same quorum).
#[must_use]
fn direct_commit_proof_signed(
    committee: &TestCommittee,
    shard: ShardId,
    height: BlockHeight,
    round: Round,
    parent: BlockHash,
    salt: u64,
    signers: &[usize],
) -> CommitProof {
    // The proof carries the certified block's parent, so build it first and
    // hang the two-chain off it; `parent` becomes the grandparent hash.
    let parent_header = fork_header(
        shard,
        height.prev().expect("fork fixtures start above genesis"),
        round,
        parent,
        salt + 900,
    );
    let block = certify_header(
        committee,
        fork_header(shard, height, round, parent_header.hash(), salt),
        signers,
    );
    let child = certify_header(
        committee,
        fork_header(
            shard,
            height.next(),
            round.next(),
            block.block_hash(),
            salt + 500,
        ),
        &committee.quorum_indices(),
    );
    CommitProof::direct(block, child, Some(parent_header))
}

/// A minimal `BlockHeader` on `shard` distinguished by `salt` (varies the
/// proposer timestamp, and so the hash). The genesis parent QC carries the
/// anchor weighted timestamp the fork verifier reads.
pub(crate) fn fork_header(
    shard: ShardId,
    height: BlockHeight,
    round: Round,
    parent_block_hash: BlockHash,
    salt: u64,
) -> BlockHeader {
    BlockHeader::new(BlockHeaderParts {
        shard_id: shard,
        height,
        parent_block_hash,
        parent_qc: QuorumCertificate::genesis(shard, ChainOrigin::ROOT).into(),
        timestamp: ProposerTimestamp::from_millis(salt),
        round,
        provision_tx_roots: std::collections::BTreeMap::new(),
        ..Default::default()
    })
}

/// Pair a fork-fixture header with a genuine QC signed by `committee`'s
/// `signers` (committee indices), so the resulting two-chain verifies.
pub(crate) fn certify_header(
    committee: &TestCommittee,
    header: BlockHeader,
    signers: &[usize],
) -> CertifiedBlockHeader {
    let net = NetworkDefinition::simulator();
    let block_hash = header.hash();
    let msg = signed_bytes(
        &BlockVoteMessage {
            shard_group: header.shard_id(),
            height: header.height(),
            round: header.round(),
            block_hash,
            parent_block_hash: header.parent_block_hash(),
        },
        &net,
    );
    let sigs: Vec<ConsensusSignature> = signers
        .iter()
        .map(|&i| committee.signer(i).sign(&msg).expect("sign"))
        .collect();
    let agg = BlsVerifier.aggregate(&sigs).expect("aggregate");
    let mut signer_bits = SignerBitfield::new(committee.size());
    for &i in signers {
        signer_bits.set(i);
    }
    let qc = QuorumCertificate::new(
        block_hash,
        header.shard_id(),
        header.height(),
        header.parent_block_hash(),
        header.round(),
        signer_bits,
        agg,
        WeightedTimestamp::from_millis(header.height().inner() * 1_000),
    );
    CertifiedBlockHeader::new(header, qc)
}

/// Build a real-BLS [`ShardForkProof::ConflictingCommits`] for `shard` at
/// `height`, signed by an explicit seated committee.
///
/// `committee_keys` are the private keys of the shard's
/// `consensus_committee_for_shard`, in bitfield order (`committee_keys[p]` is
/// the seat at bitfield position `p`); every seat signs each branch's
/// two-chain. Every QC — and both headers' `parent_qc` — carries weighted
/// timestamp `wt`, so the fork verifier resolves the seated committee
/// (committee resolution keys on the anchor `parent_qc().weighted_timestamp()`).
/// The branches sit at distinct rounds: a round-invariant proof with no
/// same-round sub-pair.
///
/// Unlike [`shard_fork_proof`], which signs with a self-contained
/// [`TestCommittee`], this signs with caller-supplied keys — so a harness can
/// forge a proof that authenticates against a *running* committee, whose keys
/// a `TestCommittee` cannot reproduce. `verifier` must be the harness's own
/// scheme (its aggregation builds the QCs the harness will re-verify). `wt`
/// must resolve that committee in the verifier's schedule; sourcing it from
/// the shard's committed-tip anchor timestamp guarantees it.
#[must_use]
pub fn shard_fork_proof_signed_by(
    verifier: &dyn Verifier,
    committee_keys: &[Arc<dyn Signer>],
    shard: ShardId,
    height: BlockHeight,
    wt: WeightedTimestamp,
) -> ShardForkProof {
    let parent = BlockHash::from_raw(Hash::from_bytes(b"shard-fork-live-parent"));
    let round_a = Round::new(height.inner().saturating_add(4));
    let round_b = Round::new(height.inner().saturating_add(6));
    ShardForkProof::ConflictingCommits {
        a: live_commit_proof(
            verifier,
            committee_keys,
            shard,
            height,
            round_a,
            parent,
            wt,
            1,
        ),
        b: live_commit_proof(
            verifier,
            committee_keys,
            shard,
            height,
            round_b,
            parent,
            wt,
            2,
        ),
    }
}

/// A direct-commit [`CommitProof`] whose two-chain is signed by
/// `committee_keys` (all seats) at `wt`.
#[allow(clippy::too_many_arguments)] // fixture internals; mirrors the proof's fields
fn live_commit_proof(
    verifier: &dyn Verifier,
    committee_keys: &[Arc<dyn Signer>],
    shard: ShardId,
    height: BlockHeight,
    round: Round,
    parent: BlockHash,
    wt: WeightedTimestamp,
    salt: u64,
) -> CommitProof {
    // The proof carries the certified block's parent, so build it first and
    // hang the two-chain off it; `parent` becomes the grandparent hash. It
    // anchors at `wt` like the rest, so the whole proof resolves one window.
    let parent_header = live_fork_header(
        shard,
        height.prev().expect("fork fixtures start above genesis"),
        round,
        parent,
        wt,
        salt + 900,
    );
    let block = live_certify(
        verifier,
        committee_keys,
        live_fork_header(shard, height, round, parent_header.hash(), wt, salt),
        wt,
    );
    let child = live_certify(
        verifier,
        committee_keys,
        live_fork_header(
            shard,
            height.next(),
            round.next(),
            block.block_hash(),
            wt,
            salt + 500,
        ),
        wt,
    );
    CommitProof::direct(block, child, Some(parent_header))
}

/// A minimal `BlockHeader` on `shard` whose `parent_qc` carries weighted
/// timestamp `wt` — the anchor the fork verifier resolves the committee by.
/// `salt` varies the proposer timestamp (and so the hash).
pub(crate) fn live_fork_header(
    shard: ShardId,
    height: BlockHeight,
    round: Round,
    parent_block_hash: BlockHash,
    wt: WeightedTimestamp,
    salt: u64,
) -> BlockHeader {
    BlockHeader::new(BlockHeaderParts {
        shard_id: shard,
        height,
        parent_block_hash,
        parent_qc: anchor_qc(shard, wt).into(),
        timestamp: ProposerTimestamp::from_millis(salt),
        round,
        provision_tx_roots: std::collections::BTreeMap::new(),
        ..Default::default()
    })
}

/// A placeholder `parent_qc` carrying only a weighted timestamp. The fork
/// verifier reads `parent_qc().weighted_timestamp()` as the committee anchor
/// and never authenticates the parent QC itself, so its other fields are
/// inert.
pub(crate) fn anchor_qc(shard: ShardId, wt: WeightedTimestamp) -> QuorumCertificate {
    let zero = BlockHash::from_raw(Hash::from_bytes(b"shard-fork-live-anchor"));
    QuorumCertificate::new(
        zero,
        shard,
        BlockHeight::new(0),
        zero,
        Round::new(0),
        SignerBitfield::new(0),
        AggregateSignature::new([0u8; 96]),
        wt,
    )
}

/// Pair a header with a genuine QC signed by every key in `committee_keys`
/// (bitfield position `p` set to `committee_keys[p]`'s signature), stamped at
/// `wt`, so the two-chain verifies against the seated committee.
fn live_certify(
    verifier: &dyn Verifier,
    committee_keys: &[Arc<dyn Signer>],
    header: BlockHeader,
    wt: WeightedTimestamp,
) -> CertifiedBlockHeader {
    let net = NetworkDefinition::simulator();
    let block_hash = header.hash();
    let msg = signed_bytes(
        &BlockVoteMessage {
            shard_group: header.shard_id(),
            height: header.height(),
            round: header.round(),
            block_hash,
            parent_block_hash: header.parent_block_hash(),
        },
        &net,
    );
    let sigs: Vec<ConsensusSignature> = committee_keys
        .iter()
        .map(|k| k.sign(&msg).expect("sign"))
        .collect();
    let agg = verifier.aggregate(&sigs).expect("aggregate");
    let mut signer_bits = SignerBitfield::new(committee_keys.len());
    for p in 0..committee_keys.len() {
        signer_bits.set(p);
    }
    let qc = QuorumCertificate::new(
        block_hash,
        header.shard_id(),
        header.height(),
        header.parent_block_hash(),
        header.round(),
        signer_bits,
        agg,
        wt,
    );
    CertifiedBlockHeader::new(header, qc)
}

/// Re-stamp a block's `parent_qc` weighted timestamp, keeping the QC
/// genesis-shaped. The commit clock anchors on `parent_qc().weighted_timestamp()`,
/// so fixtures that want a committed block "at time T" must carry T there.
fn stamp_parent_qc_weighted_timestamp(block: Block, weighted_timestamp_ms: u64) -> Block {
    let restamp = |header: BlockHeader| -> BlockHeader {
        let parts = header.into_parts();
        let parent_qc = parts.parent_qc.clone();
        let pqc = parent_qc.as_unverified();
        let stamped = QuorumCertificate::new(
            pqc.block_hash(),
            pqc.shard_id(),
            pqc.height(),
            pqc.parent_block_hash(),
            pqc.round(),
            pqc.signers().clone(),
            pqc.aggregated_signature(),
            WeightedTimestamp::from_millis(weighted_timestamp_ms),
        );
        BlockHeader::new(BlockHeaderParts {
            parent_qc: stamped.into(),
            ..parts
        })
    };
    match block {
        Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            witness_sources,
        } => Block::Live {
            header: restamp(header),
            transactions,
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            witness_sources,
        },
        Block::Sealed {
            header,
            transactions,
            certificates,
            provision_hashes,
            abandonment_records,
            state_claims,
            witness_sources,
        } => Block::Sealed {
            header: restamp(header),
            transactions,
            certificates,
            provision_hashes,
            abandonment_records,
            state_claims,
            witness_sources,
        },
    }
}

/// Build a minimal `Finalization` carrying a single tx decision.
///
/// The tick is anchored on `ShardId::ROOT` with `block_height` as its
/// identity and no remote shard dependencies — sufficient for driving
/// `on_block_committed` when tests only care about tx-terminal-state side
/// effects. The inner EC carries a zeroed signature and a 4-seat
/// signer bitfield, so callers should not feed the result through
/// verification paths.
#[must_use]
pub fn make_finalization(
    block_height: BlockHeight,
    tx_hash: TxHash,
    decision: TransactionDecision,
) -> Finalization {
    finalization_of(
        block_height,
        vec![TxOutcome::new(tx_hash, outcome_of(decision))],
    )
}

/// A finalization at `block_height` deciding `tx_hash` a success whose
/// settlement awaits `counterparts`: what a member of a multi-shard core
/// attests, and the one success the deadline does not bound.
#[must_use]
pub fn make_finalization_awaiting(
    block_height: BlockHeight,
    tx_hash: TxHash,
    counterparts: impl IntoIterator<Item = ShardId>,
) -> Finalization {
    finalization_of(
        block_height,
        vec![
            TxOutcome::new(tx_hash, outcome_of(TransactionDecision::Accept)).awaiting(counterparts),
        ],
    )
}

/// A finalization at `block_height` deciding `tx_hash` a success that is
/// no execution of it — a reclaim's, an abandonment's — which settles
/// past the deadline by construction and is not held to it.
#[must_use]
pub fn make_settling_finalization(block_height: BlockHeight, tx_hash: TxHash) -> Finalization {
    finalization_of(
        block_height,
        vec![
            TxOutcome::new(tx_hash, outcome_of(TransactionDecision::Accept))
                .as_role(Role::Settling),
        ],
    )
}

/// The outcome a decision reads back as, for a fixture that states the
/// decision and nothing else about the execution.
const fn outcome_of(decision: TransactionDecision) -> ExecutionOutcome {
    match decision {
        TransactionDecision::Accept => ExecutionOutcome::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
        },
        TransactionDecision::Reject => ExecutionOutcome::Failed,
        TransactionDecision::Aborted => ExecutionOutcome::Aborted,
    }
}

/// A finalization at `block_height` deciding `tx_hash` a success, with
/// the receipt stating what it left.
///
/// What the commit path applies to the base, and what a replay reads a
/// settled tick's contribution off where it re-ran no tick to produce
/// one.
#[must_use]
pub fn make_finalization_leaving(
    block_height: BlockHeight,
    tx_hash: TxHash,
    writes: StateWrites,
) -> Finalization {
    let receipt = StoredReceipt::synced(
        tx_hash,
        Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes,
            beacon_witness_events: Vec::new(),
            events: Vec::new(),
        }),
    );
    let outcomes = vec![TxOutcome::new(
        tx_hash,
        outcome_of(TransactionDecision::Accept),
    )];
    let tick_id = TickId::new(ShardId::ROOT, block_height);
    let ec = ExecutionCertificate::new(
        tick_id,
        WeightedTimestamp::from_millis(block_height.inner() + 1),
        compute_global_receipt_root(&outcomes),
        outcomes,
        AggregateSignature::new([0u8; 96]),
        SignerBitfield::new(4),
    );
    Finalization::new(
        tick_id,
        TickHalf::Determined,
        vec![Arc::new(ec)],
        vec![receipt],
    )
}

/// A single-certificate finalization at `block_height` over `outcomes`.
#[must_use]
pub fn finalization_of(block_height: BlockHeight, outcomes: Vec<TxOutcome>) -> Finalization {
    let tick_id = TickId::new(ShardId::ROOT, block_height);
    let ec = ExecutionCertificate::new(
        tick_id,
        WeightedTimestamp::from_millis(block_height.inner() + 1),
        // The real root over the real outcomes: anything else fails the
        // rebuild every decode runs, so the fixture would not survive a
        // round trip through storage.
        compute_global_receipt_root(&outcomes),
        outcomes,
        AggregateSignature::new([0u8; 96]),
        SignerBitfield::new(4),
    );
    Finalization::new(tick_id, TickHalf::Determined, vec![Arc::new(ec)], vec![])
}

/// A leg's finalization at `block_height`: `tx_hash` succeeded here and
/// the outcome decides nothing, since the transaction's core decides it.
#[must_use]
pub fn make_leg_finalization(block_height: BlockHeight, tx_hash: TxHash) -> Finalization {
    make_undecided_finalization(block_height, tx_hash, TransactionDecision::Accept)
}

/// A finalization at `block_height` whose outcome for `tx_hash` decides
/// nothing whichever way it went: a leg's success, or a delivery's
/// outcome either way.
#[must_use]
pub fn make_undecided_finalization(
    block_height: BlockHeight,
    tx_hash: TxHash,
    decision: TransactionDecision,
) -> Finalization {
    finalization_of(
        block_height,
        vec![TxOutcome::new(tx_hash, outcome_of(decision)).as_role(Role::Delivery)],
    )
}

/// The one synthetic cell the stub declares per owner. All of an
/// owner's stubbed accesses collapse to this cell, so two stubbed
/// transactions conflict exactly when they share an owner — the
/// owner-granular contention the fixtures are written against.
const fn stub_cell(owner: Address) -> DeclaredKey {
    DeclaredKey::substate(owner, [0u8; 16])
}

/// A stub charge for a record fixture: a vault under `seed`'s own
/// prefix, at a nominal price.
///
/// The consensus fixtures that carry one are about what a record names
/// and how it validates, never about what the burn comes to — so the
/// figures need only be a function of the seed.
#[must_use]
pub const fn stub_abort_charge(seed: u8) -> AbortCharge {
    AbortCharge {
        vault: SubstateKey {
            owner: Address::new([seed; 31], AddressClass::Component),
            local: LocalKey([seed; 16]),
        },
        amount: 13,
    }
}

/// A deterministic [`Derivation`](crate::Derivation) stub for consensus-crate
/// tests.
///
/// The envelope's tree is a leading read count followed by that many
/// 32-byte shared-mode owner prefixes and then the exclusive ones, and
/// its message is a run of 32-byte package addresses the transaction
/// runs. Routing and package set are thus fully controlled per
/// transaction by [`stub_transaction`] and
/// [`stub_transaction_running`], with no effects-bridge dependency.
pub struct StubVmStatics;

impl Derivation for StubVmStatics {
    fn derive(&self, vm: &TransactionEnvelope) -> Result<Derived, DerivationError> {
        let tree = vm.call_tree().unwrap_or_default();
        let Some((&read_count, prefixes)) = tree.split_first() else {
            return Err(DerivationError::Refused("stub tree is empty".into()));
        };
        if !prefixes.len().is_multiple_of(32) || usize::from(read_count) * 32 > prefixes.len() {
            return Err(DerivationError::Refused(
                "stub tree must be a read count then 32-byte owner prefixes".into(),
            ));
        }
        let canonical = |chunks: &[u8]| -> Result<Vec<Address>, DerivationError> {
            let mut prefixes: Vec<Address> = chunks
                .as_chunks::<32>()
                .0
                .iter()
                .map(|bytes| {
                    Address::from_bytes(*bytes)
                        .map_err(|err| DerivationError::Refused(format!("stub prefix: {err}")))
                })
                .collect::<Result<_, _>>()?;
            prefixes.sort_unstable();
            prefixes.dedup();
            Ok(prefixes)
        };
        let (reads, writes) = prefixes.split_at(usize::from(read_count) * 32);
        let read_prefixes = canonical(reads)?;
        let write_prefixes = canonical(writes)?;
        if !vm.message.len().is_multiple_of(32) {
            return Err(DerivationError::Refused(
                "stub message must be 32-byte package addresses".into(),
            ));
        }
        let packages: Vec<Hash> = vm
            .message
            .as_chunks::<32>()
            .0
            .iter()
            .map(|bytes| Hash::from_hash_bytes(bytes))
            .collect();
        Ok(Derived {
            // A stub derives no tree, so the envelope's own window is
            // the whole of it.
            effective_window: vm.validity_window(),
            routing: Routing {
                read_keys: read_prefixes.iter().copied().map(stub_cell).collect(),
                write_keys: write_prefixes.iter().copied().map(stub_cell).collect(),
                provision_keys: read_prefixes.iter().copied().map(stub_cell).collect(),
                provision_prefixes: read_prefixes.clone(),
                read_prefixes: read_prefixes.clone(),
                write_prefixes: write_prefixes.clone(),
                // The stub's two classes map to the two exclusive modes:
                // a shared read and an exclusive write. It has no way to
                // express a delta or a reservation, so a test that needs
                // commutative contention builds its declaration through
                // the effects bridge instead.
                declared_modes: read_prefixes
                    .iter()
                    .copied()
                    .map(|owner| (stub_cell(owner), Mode::Read))
                    .chain(
                        write_prefixes
                            .iter()
                            .copied()
                            .map(|owner| (stub_cell(owner), Mode::Write { moves: Moves::Both })),
                    )
                    .collect(),
            },
            subintent_hashes: Vec::new(),
            // The stub cannot derive an address from a key, so it binds
            // the signer to the payer field — every stubbed
            // transaction's payer admits its signer.
            signer: vm.fee_payer,
            fee_vault_local: [0xEE; 16],
            auth_cell_local: [0xAE; 16],
            packages,
            // The stub prices a declared key like the real derivation
            // prices an effect — one unit each — and hands the total to
            // the same schedule, so a stubbed transaction and a derived
            // one are priced by the same function.
            work: declared_work(
                (read_prefixes.len() + write_prefixes.len()) as u64,
                vm.gas_limit,
                vm.signature_work(),
            ),
            footprint: (read_prefixes.len() + write_prefixes.len()) as u64,
            // A stub derives no manifest, so it has no legs to divide;
            // its payer is the one party its routing declares.
            legs: Vec::new(),
            owners: vec![vm.fee_payer.address()],
            // One per bound signature, which is what a real derivation
            // files: a subintent's signature and its nullifier come in a
            // pair. Under the payer, since the stub cannot derive the
            // signer's address from a key. Every fixture that binds none
            // creates nothing, so a test opts in by binding.
            nullifiers: (0..vm.subintent_sigs.len())
                .map(|bound| {
                    let mut local = [0xAF; 16];
                    local[..8].copy_from_slice(&(bound as u64).to_le_bytes());
                    SubstateKey {
                        owner: vm.fee_payer.address(),
                        local: LocalKey(local),
                    }
                })
                .collect(),
        })
    }
}

impl ProtocolStatics for StubVmStatics {
    fn package_cell(&self, _owner: [u8; 32], local: [u8; 16], value: &[u8]) -> Option<Hash> {
        (local[0] == STUB_PACKAGE_MARKER)
            .then(|| Hash::from_hash_bytes(&[*value.first().unwrap_or(&0); 32]))
    }

    fn sweepable_cell(&self, _owner: [u8; 32], local: [u8; 16], value: &[u8]) -> Option<u64> {
        let expiry = u64::from_le_bytes(value.get(1..9)?.try_into().ok()?);
        (value.first() == Some(&STUB_SWEEPABLE_MARKER)
            && SweepBucket::claimed_by(LocalKey(local)) == SweepBucket::of(expiry))
        .then_some(expiry)
    }

    fn record_cell(&self, _owner: [u8; 32], _local: [u8; 16], value: &[u8]) -> bool {
        value.first() == Some(&STUB_RECORD_MARKER)
    }
}

/// The local-key first byte the stub judges a package cell by, in place
/// of the content-address re-derivation the bridge statics perform.
pub const STUB_PACKAGE_MARKER: u8 = 0xAB;

/// The value's first byte the stub judges a sweepable cell by, in place
/// of the whole-key re-derivation the bridge statics perform. The eight
/// bytes after it are the expiry, little-endian.
///
/// The bucket check is not stubbed out: the layout rule a sweep walks by
/// — the expiry in the value agrees with the bucket leading the key — is
/// the half of the judgement a storage backend's index depends on, so a
/// stub that skipped it would be testing nothing.
pub const STUB_SWEEPABLE_MARKER: u8 = 0xCD;

/// The value's first byte the stub judges an escrow record by.
///
/// No key rule stands beside it, which is the point: a record's key
/// carries no bucket, so nothing about where it sits says what it is and
/// the value is the whole of the judgement.
pub const STUB_RECORD_MARKER: u8 = 0xEF;

/// A stub escrow record's value, which [`StubVmStatics`] judges a record
/// wherever it sits.
#[must_use]
pub fn stub_record_cell(body: u8) -> Vec<u8> {
    vec![STUB_RECORD_MARKER, body]
}

/// A stub sweepable cell's value and the local key it must sit at for
/// [`StubVmStatics`] to judge it sweepable.
#[must_use]
pub fn stub_sweepable_cell(expiry_ms: u64, body: u8) -> (LocalKey, Vec<u8>) {
    let mut local = [body; 16];
    local[..SWEEP_BUCKET_BYTES].copy_from_slice(&SweepBucket::of(expiry_ms).to_bytes());
    let mut value = vec![STUB_SWEEPABLE_MARKER];
    value.extend_from_slice(&expiry_ms.to_le_bytes());
    (LocalKey(local), value)
}

/// Install [`StubVmStatics`]'s protocol answers for this process.
/// First-install-wins, like the production install — a test binary uses
/// either the stub or the effects-bridge answers, never both.
///
/// The stub's derivation is not installed anywhere, because a derivation
/// is a node's: the fixtures below derive their transactions through
/// [`StubVmStatics`] as they build them, and a test that needs a
/// derivation in hand names the stub directly.
pub fn install_stub_protocol_statics() {
    if !protocol_statics_installed() {
        install_protocol_statics(Box::new(StubVmStatics));
    }
}

/// A manifest node's shape for the classifier: a leg at `target` in
/// `role`, consuming `edges` as `(source node, output)`.
///
/// What a test hands [`Transaction::with_legs`] to give a stub
/// transaction a shape the stub derivation cannot produce.
#[must_use]
pub fn leg_shape(target: Address, role: LegRole, edges: &[(u32, u32)]) -> LegShape {
    LegShape {
        target,
        role,
        edges: edges
            .iter()
            .map(|&(source, output)| ValueEdge {
                source,
                output,
                non_fungible: false,
            })
            .collect(),
        presents: Vec::new(),
        declares: vec![target],
        intent: SubintentHash(Hash32([7; 32])),
        local: 0,
        expiry_ms: 1_000,
    }
}

/// A transaction the [`StubVmStatics`] derivation reports as creating
/// `bound` sweepable cells — the fixture for anything gated on how many
/// a block may create.
///
/// The signatures are placeholders: nothing in the stub verifies them,
/// and what they stand for here is the pairing a real derivation has
/// between a bound subintent's signature and the nullifier it takes.
///
/// # Panics
///
/// Panics if the fixture signing key fails to construct.
#[must_use]
pub fn stub_transaction_binding(seed: u32, bound: usize, validity: TimestampRange) -> Transaction {
    // A four-byte seed: filling a creation cap sized in thousands of
    // transactions takes more distinct payers than a byte names.
    let mut key_bytes = [0x5Eu8; 32];
    key_bytes[..4].copy_from_slice(&seed.to_le_bytes());
    let key = Ed25519PrivateKey::from_bytes(&key_bytes).expect("fixture key");
    let mut payer = [0x5Eu8; 31];
    payer[..4].copy_from_slice(&seed.to_le_bytes());
    let vm = TransactionEnvelope {
        body: TransactionBody::Call(vec![0]),
        subintent_sigs: (0..bound)
            .map(|_| SubintentSig {
                scheme: SchemeId::ED25519,
                public_key: vec![0x11; 32],
                signature: vec![0x22; 64],
            })
            .collect(),
        fee_payer: PrincipalAddr::new(payer),
        max_fee: 1_000,
        gas_limit: 1_000_000,
        validity_start_ms: validity.start_timestamp_inclusive.as_millis(),
        validity_end_ms: validity.end_timestamp_exclusive.as_millis(),
        message: Vec::new(),
        network: NetworkId::from(&NetworkDefinition::simulator()),
        signer_scheme: SchemeId::NONE,
        signer: Vec::new(),
        signature: Vec::new(),
    }
    .sign(&key);
    let tx = Transaction::new(vm);
    tx.try_derived(&StubVmStatics)
        .expect("the fixture builds a tree the stub derivation routes");
    tx
}

/// Build a signed transaction the [`StubVmStatics`] derivation routes to
/// exactly `owner_prefixes` as exclusive keys, paying from `fee_payer`.
#[must_use]
pub fn stub_transaction(
    fee_payer: PrincipalAddr,
    owner_prefixes: &[Address],
    max_fee: u128,
    validity: TimestampRange,
) -> Transaction {
    stub_transaction_with_reads(fee_payer, &[], owner_prefixes, max_fee, validity)
}

/// Build a signed transaction the [`StubVmStatics`] derivation routes to
/// `read_prefixes` as shared keys and `write_prefixes` as exclusive ones.
///
/// The envelope's tree is the read count followed by both prefix runs;
/// `max_fee` is the signed ceiling.
///
/// # Panics
///
/// Panics if the fixture signing key fails to construct, or if the read
/// set exceeds what a one-byte count can name.
#[must_use]
pub fn stub_transaction_with_reads(
    fee_payer: PrincipalAddr,
    read_prefixes: &[Address],
    write_prefixes: &[Address],
    max_fee: u128,
    validity: TimestampRange,
) -> Transaction {
    stub_transaction_running(
        fee_payer,
        &[],
        read_prefixes,
        write_prefixes,
        max_fee,
        validity,
    )
}

/// Build a signed transaction the [`StubVmStatics`] derivation routes as
/// [`stub_transaction_with_reads`] does and reports as running
/// `packages`.
///
/// The package set rides in the envelope's message, which the stub reads
/// as a run of 32-byte addresses — the fixture for anything gated on
/// what code a transaction needs.
///
/// # Panics
///
/// Panics if the fixture signing key fails to construct, or if the read
/// set exceeds what a one-byte count can name.
#[must_use]
pub fn stub_transaction_running(
    fee_payer: PrincipalAddr,
    packages: &[Hash],
    read_prefixes: &[Address],
    write_prefixes: &[Address],
    max_fee: u128,
    validity: TimestampRange,
) -> Transaction {
    install_stub_protocol_statics();
    let key = Ed25519PrivateKey::from_bytes(&[0x5A; 32]).expect("fixture key");
    let mut tree = vec![u8::try_from(read_prefixes.len()).expect("stub read set fits a byte")];
    for prefix in read_prefixes.iter().chain(write_prefixes) {
        tree.extend_from_slice(&prefix.to_bytes());
    }
    let mut message = Vec::with_capacity(packages.len() * 32);
    for package in packages {
        message.extend_from_slice(package.as_bytes());
    }
    let vm = TransactionEnvelope {
        body: TransactionBody::Call(tree),
        subintent_sigs: Vec::new(),
        fee_payer,
        max_fee,
        gas_limit: 1_000_000,
        validity_start_ms: validity.start_timestamp_inclusive.as_millis(),
        validity_end_ms: validity.end_timestamp_exclusive.as_millis(),
        message,
        network: NetworkId::from(&NetworkDefinition::simulator()),
        signer_scheme: SchemeId::NONE,
        signer: Vec::new(),
        signature: Vec::new(),
    }
    .sign(&key);
    let tx = Transaction::new(vm);
    tx.try_derived(&StubVmStatics)
        .expect("the fixture builds a tree the stub derivation routes");
    tx
}

/// A one-version state tree for `shard` holding `present`, and a proof
/// over `asked` against it: the root the proof reconstructs, and the
/// proof.
///
/// What a test hands a coordinator in place of a fetch: a key in
/// `present` reads back present under the root, any other absent. The
/// tree always holds one unrelated leaf besides, so a chain whose
/// state is otherwise empty still has a root to prove against — a
/// counterpart chain always holds something.
///
/// Rooted at `shard`'s prefix, as a shard's tree is, so a proof built
/// here is checkable the way a served one is: every key it speaks for
/// must be one `shard` owns.
///
/// # Panics
///
/// If `asked` names the unrelated leaf, whose presence would be an
/// answer the caller did not ask for, or if any key falls outside
/// `shard`'s prefix.
#[must_use]
pub fn state_and_proof(
    shard: ShardId,
    present: &[SubstateKey],
    asked: &[SubstateKey],
) -> (StateRoot, MerkleInclusionProof) {
    use std::collections::BTreeMap;

    use hyperscale_jmt::{
        Blake3Hasher, Key as JmtKey, LeafValue, MemoryStore, NibblePath, NodeKey, Tree,
    };

    use crate::shard_prefix_path;
    use crate::state_key::jmt_value_hash;

    let root_path = shard_prefix_path(shard);
    let under = |key: &SubstateKey| {
        NibblePath::from_key_prefix(&key.to_bytes(), root_path.len()) == root_path
    };
    // The spare leaf sits under the same prefix, so it is a cell this
    // shard could hold rather than one no proof of its could name.
    let mut unrelated = test_key(0xEE);
    let mut owner = unrelated.owner.to_bytes();
    let shard_first = root_path.as_bytes().first().copied().unwrap_or(0);
    let keep = u8::try_from(root_path.len().min(8)).unwrap_or(8);
    if keep > 0 {
        let mask = 0xFFu8 << (8 - keep);
        owner[0] = (owner[0] & !mask) | (shard_first & mask);
        unrelated = SubstateKey {
            owner: Address::from_bytes(owner).expect("the class byte is untouched"),
            local: unrelated.local,
        };
    }
    assert!(
        !asked.contains(&unrelated),
        "the tree's unrelated leaf is not a key a test may ask about",
    );
    assert!(
        present.iter().chain(asked).all(under),
        "a fixture proof for a shard speaks only for keys that shard owns",
    );
    let mut store = MemoryStore::new();
    let updates: BTreeMap<JmtKey, Option<LeafValue>> = present
        .iter()
        .chain(std::iter::once(&unrelated))
        .map(|key| {
            let value = key.to_bytes().to_vec();
            (
                key.to_bytes(),
                Some(LeafValue::new(jmt_value_hash(&value), value.len() as u64)),
            )
        })
        .collect();
    let result = Tree::<Blake3Hasher, 1>::apply_updates_at(&store, None, 1, &root_path, &updates)
        .expect("a fresh tree takes its first version");
    let root = StateRoot::from_raw(Hash::from_hash_bytes(&result.root_hash));
    store.apply(&result);
    let jmt_keys: Vec<JmtKey> = asked.iter().map(SubstateKey::to_bytes).collect();
    let proof = Tree::<Blake3Hasher, 1>::prove(&store, &NodeKey::new(1, root_path), &jmt_keys)
        .expect("every key proves against a held version");
    (root, MerkleInclusionProof::new(proof.encode()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_committee_creation() {
        let committee = TestCommittee::new(4, 42);

        assert_eq!(committee.size(), 4);
        assert_eq!(committee.validator_id(0), ValidatorId::new(0));
        assert_eq!(committee.validator_id(3), ValidatorId::new(3));
    }

    #[test]
    fn test_committee_deterministic() {
        let c1 = TestCommittee::new(4, 42);
        let c2 = TestCommittee::new(4, 42);

        // Same seed should produce same keys
        for i in 0..4 {
            assert_eq!(c1.public_key(i), c2.public_key(i));
        }
    }

    #[test]
    fn test_committee_different_seeds() {
        let c1 = TestCommittee::new(4, 42);
        let c2 = TestCommittee::new(4, 43);

        // Different seeds should produce different keys
        assert_ne!(c1.public_key(0), c2.public_key(0));
    }

    #[test]
    fn test_for_shard() {
        let shard0 = TestCommittee::for_shard(4, 42, 0);
        let shard1 = TestCommittee::for_shard(4, 42, 1);

        // Shard 0 has validators 0-3
        assert_eq!(shard0.validator_id(0), ValidatorId::new(0));
        assert_eq!(shard0.validator_id(3), ValidatorId::new(3));

        // Shard 1 has validators 4-7
        assert_eq!(shard1.validator_id(0), ValidatorId::new(4));
        assert_eq!(shard1.validator_id(3), ValidatorId::new(7));
    }

    #[test]
    fn test_quorum_threshold() {
        // n=4: f=1, quorum=3
        assert_eq!(TestCommittee::new(4, 0).quorum_threshold(), 3);

        // n=7: f=2, quorum=5
        assert_eq!(TestCommittee::new(7, 0).quorum_threshold(), 5);

        // n=10: f=3, quorum=7
        assert_eq!(TestCommittee::new(10, 0).quorum_threshold(), 7);
    }

    #[test]
    fn test_keypair_signing() {
        let committee = TestCommittee::new(4, 42);

        let message = b"test message";
        let signature = committee.signer(0).sign(message).expect("sign");

        // Verify with the corresponding public key
        assert!(BlsVerifier.verify(committee.public_key(0), message, &signature));

        // Should not verify with different public key
        assert!(!BlsVerifier.verify(committee.public_key(1), message, &signature));
    }
}
