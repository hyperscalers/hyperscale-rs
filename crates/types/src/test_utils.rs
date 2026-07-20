//! Test utilities.

use std::collections::BTreeSet;
use std::sync::Arc;

use radix_common::constants::PACKAGE_PACKAGE;
use radix_common::crypto::{Ed25519PrivateKey, IsHash, PublicKey as RadixPublicKey};
use radix_common::prelude::Epoch;
use radix_common::types::BlueprintId;
use radix_engine_interface::types::{Emitter, EventTypeIdentifier};
use radix_transactions::model::{
    BlobsV1, HasSignedTransactionIntentHash, InstructionsV1, IntentSignaturesV1, IntentV1,
    MessageV1, NotarizedTransactionV1, NotarySignatureV1, SignatureV1, SignedIntentV1,
    TransactionHeaderV1, TransactionPayload, UserTransaction,
};
use radix_transactions::prelude::PreparationSettings;

use crate::{
    BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash, BlockHeader, BlockHeight,
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, BoundedVec, CertificateRoot,
    CertifiedBlock, ChainOrigin, ExecutionCertificate, ExecutionOutcome, FinalizedWave,
    GlobalReceiptHash, GlobalReceiptRoot, InFlightCount, LocalReceiptRoot, NetworkDefinition,
    NodeId, ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Round, RoutableTransaction,
    ShardId, SignerBitfield, StateRoot, TimestampRange, TopologySnapshot, TransactionDecision,
    TransactionRoot, TxHash, TxOutcome, ValidatorId, ValidatorInfo, ValidatorSet, Verifiable,
    Verified, WaveCertificate, WaveId, WeightedTimestamp, WitnessSources, bls_keypair_from_seed,
};

/// Create a test `NodeId` from a seed byte.
#[must_use]
pub const fn test_node(seed: u8) -> NodeId {
    NodeId([seed; 30])
}

/// Create a deterministic [`EventTypeIdentifier`] for tests.
///
/// Uses the well-known `PACKAGE_PACKAGE` address so the underlying
/// `PackageAddress` constructor accepts the bytes; the seed varies the
/// blueprint and event names so different seeds produce different identifiers
/// (and therefore different event hashes).
#[must_use]
pub fn test_event_type_identifier(seed: u8) -> EventTypeIdentifier {
    EventTypeIdentifier(
        Emitter::Function(BlueprintId::new(
            &PACKAGE_PACKAGE,
            format!("TestBlueprint{seed}"),
        )),
        format!("TestEvent{seed}"),
    )
}

/// Fixed Ed25519 keypair used as the notary for every fixture-built
/// transaction. Deterministic across runs so test fixtures produce
/// repeatable tx hashes.
fn test_notary_key() -> Ed25519PrivateKey {
    // 32 bytes of 0x42, fixed and unprivileged.
    Ed25519PrivateKey::from_bytes(&[0x42u8; 32]).expect("static 32-byte seed is valid")
}

/// Create a minimal test `NotarizedTransactionV1` from seed bytes.
///
/// The resulting transaction has a properly-computed notary signature
/// against the intent hash (using a fixed test keypair) and no intent
/// signatures, so Radix's `prepare_and_validate` accepts it. The
/// transaction won't execute successfully — its manifest is empty —
/// but admission-time validation passes, which is what test fixtures
/// downstream of the validation pool need.
///
/// # Panics
///
/// Panics if intent or signed-intent preparation fails. Both are
/// deterministic over the fixture's constant header / empty
/// instructions, so a panic here indicates a Radix-side breaking
/// change to preparation rather than a runtime condition.
#[must_use]
pub fn test_notarized_transaction_v1(seed_bytes: &[u8]) -> NotarizedTransactionV1 {
    let notary = test_notary_key();
    let header = TransactionHeaderV1 {
        network_id: NetworkDefinition::simulator().id,
        start_epoch_inclusive: Epoch::of(0),
        end_epoch_exclusive: Epoch::of(100),
        nonce: {
            let mut nonce_bytes = [0u8; 4];
            for (i, &b) in seed_bytes.iter().take(4).enumerate() {
                nonce_bytes[i] = b;
            }
            u32::from_le_bytes(nonce_bytes)
        },
        notary_public_key: RadixPublicKey::Ed25519(notary.public_key()),
        notary_is_signatory: true,
        tip_percentage: 0,
    };

    let intent = IntentV1 {
        header,
        instructions: InstructionsV1(vec![]),
        blobs: BlobsV1 { blobs: vec![] },
        message: MessageV1::None,
    };

    let signed_intent = SignedIntentV1 {
        intent,
        intent_signatures: IntentSignaturesV1 { signatures: vec![] },
    };

    let prepared_signed = signed_intent
        .prepare(&PreparationSettings::latest())
        .expect("test signed intent always prepares");
    let signed_intent_hash = *prepared_signed
        .signed_transaction_intent_hash()
        .as_hash()
        .as_bytes();

    let notary_signature = SignatureV1::Ed25519(notary.sign(signed_intent_hash));

    NotarizedTransactionV1 {
        signed_intent,
        notary_signature: NotarySignatureV1(notary_signature),
    }
}

/// Create a test transaction with specific read/write nodes.
#[must_use]
pub fn test_transaction_with_nodes(
    seed_bytes: &[u8],
    read_nodes: Vec<NodeId>,
    write_nodes: Vec<NodeId>,
) -> RoutableTransaction {
    let tx = test_notarized_transaction_v1(seed_bytes);
    RoutableTransaction::new(
        UserTransaction::V1(tx),
        read_nodes,
        write_nodes,
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

/// Create a simple test transaction.
#[must_use]
pub fn test_transaction(seed: u8) -> RoutableTransaction {
    test_transaction_with_nodes(
        &[seed, seed + 1, seed + 2],
        vec![test_node(seed)],
        vec![test_node(seed + 10)],
    )
}

/// Convenience: wrap [`test_transaction`] in a `Verified` witness via
/// the test-only gate.
///
/// Use at any test call site that needs a pre-validated transaction
/// (mempool admission API, event payloads carrying
/// `Arc<Verified<RoutableTransaction>>`).
#[must_use]
pub fn verified_test_transaction(seed: u8) -> Verified<RoutableTransaction> {
    Verified::new_unchecked_for_test(test_transaction(seed))
}

/// A test committee of validators with deterministic BLS keypairs.
///
/// Provides easy access to keypairs, public keys, and validator IDs
/// for creating signed test fixtures. Seeded generation means tests sign
/// and verify against real cryptographic paths rather than bypassing them
/// with zero signatures.
pub struct TestCommittee {
    keypairs: Vec<Bls12381G1PrivateKey>,
    public_keys: Vec<Bls12381G1PublicKey>,
    validator_ids: Vec<ValidatorId>,
}

impl std::fmt::Debug for TestCommittee {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCommittee")
            .field("size", &self.keypairs.len())
            .field("validator_ids", &self.validator_ids)
            .finish_non_exhaustive()
    }
}

impl TestCommittee {
    /// Create a new test committee with the given size and seed.
    ///
    /// The seed ensures deterministic key generation for reproducible tests.
    /// Different seeds produce different committees.
    #[must_use]
    pub fn new(size: usize, seed: u64) -> Self {
        let mut keypairs = Vec::with_capacity(size);
        let mut public_keys = Vec::with_capacity(size);
        let mut validator_ids = Vec::with_capacity(size);

        for i in 0..size {
            // Generate deterministic seed for this validator
            let mut seed_bytes = [0u8; 32];
            let key_seed = seed
                .wrapping_add(i as u64)
                .wrapping_mul(0x517c_c1b7_2722_0a95);
            seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
            seed_bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
            seed_bytes[16..24].copy_from_slice(&seed.to_le_bytes());

            let kp = bls_keypair_from_seed(&seed_bytes);
            let pk = kp.public_key();

            keypairs.push(kp);
            public_keys.push(pk);
            validator_ids.push(ValidatorId::new(i as u64));
        }

        Self {
            keypairs,
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
        self.keypairs.len()
    }

    /// Get a keypair by index.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= size()`.
    #[must_use]
    pub fn keypair(&self, idx: usize) -> &Bls12381G1PrivateKey {
        &self.keypairs[idx]
    }

    /// Get a public key by index.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= size()`.
    #[must_use]
    pub fn public_key(&self, idx: usize) -> &Bls12381G1PublicKey {
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
    pub fn public_keys(&self) -> &[Bls12381G1PublicKey] {
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
/// `round` is `Round::INITIAL`, and there are no wave roots or provisions.
/// Callers pass only the bits that vary between tests.
///
/// Transactions are wrapped as `Verifiable::Unverified` — adequate for the
/// `on_block_committed` path (`WaveState` lifts via
/// [`Verified::<RoutableTransaction>::from_persisted`]) and for storage
/// fixtures. The pre-vote path (`validate_block_for_vote`) refuses to vote
/// on blocks with any un-`Verified` entry; tests targeting that path must
/// construct `Block` directly with `Vec<Arc<Verifiable<RoutableTransaction>>>`
/// holding `Verified` entries.
#[must_use]
pub fn make_live_block(
    shard_id: ShardId,
    height: BlockHeight,
    timestamp_ms: u64,
    proposer: ValidatorId,
    transactions: Vec<Arc<RoutableTransaction>>,
    certificates: Vec<Arc<Verifiable<FinalizedWave>>>,
) -> Block {
    let header = BlockHeader::new(
        shard_id,
        height,
        BlockHash::ZERO,
        QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
        proposer,
        ProposerTimestamp::from_millis(timestamp_ms),
        Round::INITIAL,
        false,
        StateRoot::ZERO,
        TransactionRoot::ZERO,
        CertificateRoot::ZERO,
        LocalReceiptRoot::ZERO,
        ProvisionsRoot::ZERO,
        Vec::new(),
        std::collections::BTreeMap::new(),
        InFlightCount::ZERO,
        BeaconWitnessRoot::ZERO,
        BeaconWitnessLeafCount::ZERO,
        BeaconWitnessLeafCount::ZERO,
        None,
        None,
    );
    let transactions: Vec<Arc<Verifiable<RoutableTransaction>>> = transactions
        .into_iter()
        .map(|tx| Arc::new(Verifiable::from((*tx).clone())))
        .collect();
    Block::Live {
        header,
        transactions: Arc::new(transactions.into()),
        certificates: Arc::new(certificates.into()),
        provisions: Arc::new(BoundedVec::new()),
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

/// Re-stamp a block's `parent_qc` weighted timestamp, keeping the QC
/// genesis-shaped. The commit clock anchors on `parent_qc().weighted_timestamp()`,
/// so fixtures that want a committed block "at time T" must carry T there.
fn stamp_parent_qc_weighted_timestamp(block: Block, weighted_timestamp_ms: u64) -> Block {
    let restamp = |header: BlockHeader| -> BlockHeader {
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
            split_child_roots,
            settled_waves_root,
        ) = header.into_parts();
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
        BlockHeader::new(
            shard_id,
            height,
            parent_block_hash,
            stamped,
            proposer,
            timestamp,
            round,
            is_fallback,
            state_root,
            transaction_root,
            certificate_root,
            local_receipt_root,
            provision_root,
            waves.0,
            provision_tx_roots.0,
            in_flight,
            beacon_witness_root,
            beacon_witness_leaf_count,
            beacon_witness_base,
            split_child_roots,
            settled_waves_root,
        )
    };
    match block {
        Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            witness_sources,
        } => Block::Live {
            header: restamp(header),
            transactions,
            certificates,
            provisions,
            witness_sources,
        },
        Block::Sealed {
            header,
            transactions,
            certificates,
            provision_hashes,
            witness_sources,
        } => Block::Sealed {
            header: restamp(header),
            transactions,
            certificates,
            provision_hashes,
            witness_sources,
        },
    }
}

/// Build a minimal `FinalizedWave` carrying a single tx decision.
///
/// The wave is anchored on `ShardId::ROOT` with `block_height` as its
/// identity and no remote shard dependencies — sufficient for driving
/// `on_block_committed` when tests only care about tx-terminal-state side
/// effects. The inner EC carries a zeroed BLS signature and a 4-seat
/// signer bitfield, so callers should not feed the result through
/// verification paths.
#[must_use]
pub fn make_finalized_wave(
    block_height: BlockHeight,
    tx_hash: TxHash,
    decision: TransactionDecision,
) -> FinalizedWave {
    let outcome = match decision {
        TransactionDecision::Accept => ExecutionOutcome::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
        },
        TransactionDecision::Reject => ExecutionOutcome::Failed,
        TransactionDecision::Aborted => ExecutionOutcome::Aborted,
    };
    let wave_id = WaveId::new(ShardId::ROOT, block_height, BTreeSet::new());
    let ec = ExecutionCertificate::new(
        wave_id.clone(),
        WeightedTimestamp::from_millis(block_height.inner() + 1),
        GlobalReceiptRoot::ZERO,
        vec![TxOutcome::new(tx_hash, outcome)],
        Bls12381G2Signature([0u8; 96]),
        SignerBitfield::new(4),
    );
    FinalizedWave::new(
        Arc::new(WaveCertificate::new(wave_id, vec![Arc::new(ec)])),
        vec![],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_bls12381_v1;

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
            assert_eq!(c1.public_key(i).0, c2.public_key(i).0);
        }
    }

    #[test]
    fn test_committee_different_seeds() {
        let c1 = TestCommittee::new(4, 42);
        let c2 = TestCommittee::new(4, 43);

        // Different seeds should produce different keys
        assert_ne!(c1.public_key(0).0, c2.public_key(0).0);
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
        let signature = committee.keypair(0).sign_v1(message);

        // Verify with the corresponding public key
        assert!(verify_bls12381_v1(
            message,
            committee.public_key(0),
            &signature
        ));

        // Should not verify with different public key
        assert!(!verify_bls12381_v1(
            message,
            committee.public_key(1),
            &signature
        ));
    }
}
