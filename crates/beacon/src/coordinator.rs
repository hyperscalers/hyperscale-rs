//! Top-level beacon FSM.
//!
//! [`BeaconCoordinator`] is the per-vnode state machine; it owns the
//! committed [`BeaconState`], the optional current-epoch
//! [`SpcInstance`], and the wall-clock anchor that drives
//! epoch-cadence timers.
//!
//! Constructor is pure synchronous data assembly — the runner is
//! responsible for loading `(latest_block, latest_state)` from
//! [`BeaconChainReader::latest_committed`](hyperscale_storage::BeaconChainReader::latest_committed)
//! and asserting the `header.state_root` ↔ `state_root(&state)`
//! binding before invoking [`BeaconCoordinator::new`]. Same code path
//! handles fresh-genesis and warm-restart: the runner builds and
//! commits the genesis pair on an empty store, then loads it back via
//! the same `latest_committed()` call.

use std::sync::Arc;

use hyperscale_types::{
    BeaconBlock, BeaconState, Bls12381G1PrivateKey, Epoch, LocalTimestamp, NetworkDefinition,
    ValidatorId, state_root,
};

use crate::pending_blocks::PendingBeaconBlocks;
use crate::recovery_tracker::RecoveryTracker;
use crate::spc::SpcInstance;
use crate::verification::BeaconVerificationPipeline;
use crate::witness_fetcher::ShardWitnessFetchTracker;

/// Per-vnode beacon-chain coordinator.
///
/// Synchronous event-driven FSM. Mirrors `ShardCoordinator`'s public
/// shape: handlers take `&mut self` plus a per-call
/// `&TopologySnapshot` and return `Vec<Action>`. Multiple vnodes
/// share an `Arc<dyn BeaconStorage>` at the runner layer but each
/// holds an independent coordinator, so determinism is per-vnode.
pub struct BeaconCoordinator {
    state: BeaconState,

    /// Latest committed beacon block. Carried so SPC instance
    /// bootstrap can read `prev_block_hash` without a storage
    /// roundtrip.
    latest_block: Arc<BeaconBlock>,

    /// `None` between bootstrap and the first epoch-boundary
    /// trigger, and again briefly between an epoch's commit and the
    /// next instance's bootstrap.
    spc: Option<SpcInstance>,

    /// Gossip-arrival cache for beacon blocks awaiting verification.
    /// Pruned past `state.current_epoch` after every committed epoch.
    pending_blocks: PendingBeaconBlocks,

    /// In-flight and verified slot tracking for async crypto checks
    /// (block aggregate sigs, cert sigs, VRF reveals, witness
    /// Merkle paths).
    verification: BeaconVerificationPipeline,

    /// Per-shard header records, validated-witness pool, and
    /// in-flight fetches; drives proposal-readiness and the
    /// witness drain.
    witness_fetcher: ShardWitnessFetchTracker,

    /// Buckets observed recovery requests and aggregates them into
    /// a `RecoveryCertificate` once quorum lands.
    recovery_tracker: RecoveryTracker,

    me: ValidatorId,

    /// Threaded into per-epoch [`SpcInstance`]s so they can sign
    /// without an out-of-band key-store roundtrip.
    #[allow(dead_code)] // read by SPC bootstrap once handlers wire it in
    me_sk: Arc<Bls12381G1PrivateKey>,

    /// Mixed into every signing helper's domain bytes; carried so
    /// per-epoch SPC instances don't re-thread it from the runner.
    #[allow(dead_code)] // read by SPC bootstrap once handlers wire it in
    network: NetworkDefinition,

    /// Local wall-clock time. Drives the epoch-cadence timers; never
    /// fed into deterministic consensus computations — use
    /// `state.current_epoch` or weighted timestamps for that.
    now: LocalTimestamp,
}

impl BeaconCoordinator {
    /// Construct a coordinator from a pre-loaded `(latest_block,
    /// latest_state)` pair.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if
    /// `latest_block.header().state_root() != state_root(&latest_state)`.
    /// The runner is contractually obliged to assert this before
    /// constructing; the `debug_assert!` here is a backstop, not the
    /// primary check.
    #[must_use]
    pub fn new(
        latest_block: Arc<BeaconBlock>,
        latest_state: BeaconState,
        me: ValidatorId,
        me_sk: Arc<Bls12381G1PrivateKey>,
        network: NetworkDefinition,
    ) -> Self {
        debug_assert_eq!(
            latest_block.header().state_root(),
            state_root(&latest_state),
            "BeaconCoordinator::new: header.state_root != state_root(&state); \
             runner must verify the binding before construction",
        );
        Self {
            state: latest_state,
            latest_block,
            spc: None,
            pending_blocks: PendingBeaconBlocks::new(),
            verification: BeaconVerificationPipeline::new(),
            witness_fetcher: ShardWitnessFetchTracker::new(),
            recovery_tracker: RecoveryTracker::new(),
            me,
            me_sk,
            network,
            now: LocalTimestamp::ZERO,
        }
    }

    /// Whether the local validator sits on the current beacon
    /// committee. The runner gates committee-only event forwarding
    /// (PC votes, SPC messages) on this.
    #[must_use]
    pub fn is_on_committee(&self) -> bool {
        self.state.committee.contains(&self.me)
    }

    /// Runner calls this once before each batch of handler invocations
    /// so every handler in the batch reads a consistent `now`.
    pub const fn set_now(&mut self, now: LocalTimestamp) {
        self.now = now;
    }
}

// Flat accessors; their names and return types are the documentation.
#[allow(missing_docs)]
impl BeaconCoordinator {
    #[must_use]
    pub const fn current_state(&self) -> &BeaconState {
        &self.state
    }

    #[must_use]
    pub const fn current_epoch(&self) -> Epoch {
        self.state.current_epoch
    }

    #[must_use]
    pub const fn latest_block(&self) -> &Arc<BeaconBlock> {
        &self.latest_block
    }

    #[must_use]
    pub const fn me(&self) -> ValidatorId {
        self.me
    }

    #[must_use]
    pub const fn now(&self) -> LocalTimestamp {
        self.now
    }
}

impl std::fmt::Debug for BeaconCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconCoordinator")
            .field("current_epoch", &self.state.current_epoch)
            .field("latest_block_hash", &self.latest_block.block_hash())
            .field("me", &self.me)
            .field("spc_active", &self.spc.is_some())
            .field("pending_blocks", &self.pending_blocks.len())
            .field(
                "verifications_in_flight",
                &self.verification.in_flight_count(),
            )
            .field("witness_pool", &self.witness_fetcher.total_pool_len())
            .field("recovery_buckets", &self.recovery_tracker.bucket_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{
        BeaconBlock, Bls12381G1PublicKey, Epoch, NetworkDefinition, Randomness, ShardGroupId,
        Stake, StakePoolId, ValidatorId, bls_keypair_from_seed, state_root,
    };

    use super::*;
    use crate::constants::MIN_STAKE_FLOOR;
    use crate::genesis::{
        BeaconGenesisConfig, GenesisPool, GenesisValidator, build_genesis_beacon_state,
    };

    fn pubkey(seed: u64) -> Bls12381G1PublicKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s).public_key()
    }

    fn signing_key(seed: u64) -> Arc<Bls12381G1PrivateKey> {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        Arc::new(bls_keypair_from_seed(&s))
    }

    /// 4 validators, all on the beacon committee, all placed on shard 0.
    fn sample_genesis() -> BeaconGenesisConfig {
        let pool_id = StakePoolId::new(0);
        let shard = ShardGroupId::new(0);
        let validators: Vec<GenesisValidator> = (0u64..4)
            .map(|i| GenesisValidator {
                id: ValidatorId::new(i),
                pool: pool_id,
                pubkey: pubkey(i),
            })
            .collect();
        let members: Vec<ValidatorId> = (0u64..4).map(ValidatorId::new).collect();
        BeaconGenesisConfig {
            initial_validators: validators,
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
            }],
            initial_beacon_committee: members.clone(),
            initial_shard_committees: std::iter::once((shard, members)).collect(),
            initial_randomness: Randomness([0xAB; 32]),
        }
    }

    /// The (block, state) pair the runner would produce on an empty
    /// store: build genesis state, hash it, wrap in a genesis block.
    fn genesis_pair() -> (Arc<BeaconBlock>, BeaconState) {
        let state = build_genesis_beacon_state(&sample_genesis());
        let block = BeaconBlock::genesis(state_root(&state));
        (Arc::new(block), state)
    }

    #[test]
    fn new_from_genesis_pair_resumes_at_genesis_epoch() {
        let (block, state) = genesis_pair();
        let coord = BeaconCoordinator::new(
            block,
            state,
            ValidatorId::new(0),
            signing_key(0),
            NetworkDefinition::simulator(),
        );
        assert_eq!(coord.current_epoch(), Epoch::GENESIS);
        assert!(coord.is_on_committee());
        assert_eq!(coord.now(), LocalTimestamp::ZERO);
    }

    #[test]
    fn new_carries_latest_block() {
        let (block, state) = genesis_pair();
        let block_hash = block.block_hash();
        let coord = BeaconCoordinator::new(
            Arc::clone(&block),
            state,
            ValidatorId::new(0),
            signing_key(0),
            NetworkDefinition::simulator(),
        );
        assert_eq!(coord.latest_block().block_hash(), block_hash);
    }

    #[test]
    fn off_committee_validator_reports_not_on_committee() {
        let (block, state) = genesis_pair();
        // 99 isn't in the 0..4 committee.
        let coord = BeaconCoordinator::new(
            block,
            state,
            ValidatorId::new(99),
            signing_key(99),
            NetworkDefinition::simulator(),
        );
        assert!(!coord.is_on_committee());
    }

    #[test]
    fn set_now_advances_local_clock() {
        let (block, state) = genesis_pair();
        let mut coord = BeaconCoordinator::new(
            block,
            state,
            ValidatorId::new(0),
            signing_key(0),
            NetworkDefinition::simulator(),
        );
        let t = LocalTimestamp::from_millis(123_456);
        coord.set_now(t);
        assert_eq!(coord.now(), t);
    }

    #[test]
    #[should_panic(expected = "header.state_root != state_root(&state)")]
    #[cfg(debug_assertions)]
    fn debug_assertion_catches_runner_skipping_binding_check() {
        use hyperscale_types::BeaconStateRoot;
        let state = build_genesis_beacon_state(&sample_genesis());
        let mismatched_block = BeaconBlock::genesis(BeaconStateRoot::ZERO);
        let _coord = BeaconCoordinator::new(
            Arc::new(mismatched_block),
            state,
            ValidatorId::new(0),
            signing_key(0),
            NetworkDefinition::simulator(),
        );
    }

    #[test]
    fn coordinator_owns_state_independently_from_input() {
        let (block, state) = genesis_pair();
        let original = state.clone();
        let coord = BeaconCoordinator::new(
            block,
            state,
            ValidatorId::new(0),
            signing_key(0),
            NetworkDefinition::simulator(),
        );
        assert_eq!(coord.current_state(), &original);
        assert_eq!(coord.current_state().miss_counters, BTreeMap::new());
    }
}
