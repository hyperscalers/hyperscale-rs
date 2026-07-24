//! Genesis configuration for a beacon chain.
//!
//! Pure data shapes describing the operator-supplied bootstrap inputs
//! plus the canonical-hash function that pins the chain identity. The
//! builder that turns a [`BeaconGenesisConfig`] into a live
//! `BeaconState` lives in `hyperscale_beacon::genesis` — it needs
//! beacon-side protocol constants (committee sizes, stake floors) and
//! is not part of the consumer-facing type surface.

use std::time::Duration;

use blake3::Hasher;
use sbor::prelude::*;

use crate::{
    BEACON_SIGNER_COUNT, Bls12381G1PublicKey, EPOCH_DURATION, EpochWindows, GenesisConfigHash,
    Hash, IMPOUND_EPOCHS_DEFAULT, NetworkDefinition, PRODUCTION_BEACON_COMMITTEE_SIZE, Randomness,
    ReshapeThresholds, SHARD_CAPACITY, SHUFFLE_SYNC_HEADROOM, Stake, StakePoolId, ValidatorId,
};

/// Domain tag for the genesis-config hash. Binds the digest to "beacon
/// genesis v1" so it can't collide with any other 32-byte BLAKE3 hash
/// in the codebase, and so a future hash-input layout change forces a
/// version bump rather than silently shifting chain identity.
const DOMAIN_BEACON_GENESIS: &[u8] = b"HYPERSCALE_BEACON_GENESIS_v1";

/// Sizing knobs for a beacon chain. Lives on [`BeaconGenesisConfig`]
/// and is copied verbatim into `BeaconState.chain_config` at genesis,
/// where every consensus-critical sizing decision reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub struct BeaconChainConfig {
    /// Wall-clock milliseconds per epoch. Drives the
    /// `BeaconCommitteeStart` timer and the skip-trigger window.
    /// Stored as `u64` ms rather than [`Duration`] because the radix
    /// SBOR derive in this workspace doesn't impl `Encode`/`Decode`
    /// for `Duration`.
    pub epoch_duration_ms: u64,
    /// Max validators per shard committee.
    pub shard_size: u32,
    /// Beacon committee size cap. PC requires `>= 4`.
    pub beacon_committee_size: u32,
    /// Substate-count thresholds for automatic shard reshaping.
    /// Consensus-critical: replicas reject blocks whose reshape
    /// assertion diverges from their own predicate, so every validator
    /// must run the same values. Disabled by default.
    pub reshape_thresholds: ReshapeThresholds,
    /// Wall-clock instant (ms since the Unix epoch) at which the chain's
    /// genesis epoch begins — the origin the consensus clock measures
    /// against, so weighted-time and the synthetic beacon epoch clock
    /// (`epoch × epoch_duration_ms`) both start near zero at `Epoch::GENESIS`
    /// instead of ~1.7e12 ms into the Unix epoch. Without this anchor a
    /// runner started against raw wall-clock would have to cascade through
    /// every epoch between the Unix epoch and now before it could pace.
    /// Consensus-critical and agreed across validators via the genesis
    /// config hash. Zero (the default) leaves the clock at raw wall-clock —
    /// correct for the simulator, whose logical clock already starts at zero.
    pub genesis_timestamp_ms: u64,
    /// Epochs a placed validator may sit `OnShard { ready: false }` before
    /// the fold auto-flips it to `ready: true` — the network's
    /// consensus-agreed sync budget. A physical, per-network quantity like
    /// `epoch_duration_ms`: a dev sim syncs a shard in an epoch or two,
    /// while a production shard takes hours, so no single value fits both.
    pub ready_timeout_epochs: u64,
    /// Genesis seed for the `impound_epochs` governance parameter —
    /// epochs a convicted pool's withdrawals stay frozen. Governable
    /// after genesis via [`NetworkParams`](crate::NetworkParams); the
    /// live value is read from `BeaconState.params`, never from here.
    pub impound_epochs: u64,
}

impl BeaconChainConfig {
    /// The production sizing: [`Self::default`] with the beacon committee
    /// capped at [`PRODUCTION_BEACON_COMMITTEE_SIZE`] rather than the small
    /// dev/sim [`BEACON_SIGNER_COUNT`], and the ready timeout stretched to a
    /// production sync budget (hours of snap-sync plus tail sync at 5-minute
    /// epochs, where the dev default assumes a sim that syncs in one or two).
    /// The validator binary seats this so a live network runs the
    /// grind-hardened committee while simulations keep the small defaults.
    #[must_use]
    pub fn production() -> Self {
        Self {
            beacon_committee_size: u32::try_from(PRODUCTION_BEACON_COMMITTEE_SIZE)
                .unwrap_or(u32::MAX),
            ready_timeout_epochs: 32,
            ..Self::default()
        }
    }

    /// `epoch_duration_ms` typed as a [`Duration`].
    #[must_use]
    pub const fn epoch_duration(&self) -> Duration {
        Duration::from_millis(self.epoch_duration_ms)
    }

    /// The chain's epoch-window grid — the single home for every
    /// weighted-timestamp-to-epoch and boundary-crossing computation the fold
    /// performs.
    #[must_use]
    pub const fn epoch_windows(&self) -> EpochWindows {
        EpochWindows::new(self.epoch_duration_ms)
    }

    /// Epochs between committee-rotation events — the trickle shuffle's
    /// cadence, derived rather than stored:
    /// `max(1, ⌈SHUFFLE_SYNC_HEADROOM · ready_timeout_epochs / shard_size⌉)`.
    ///
    /// Per-seat tenure is `shard_size × interval` epochs, so the formula
    /// pins tenure at `≥ SHUFFLE_SYNC_HEADROOM × ready_timeout_epochs`
    /// whatever the committee size. Rotation is the defense against
    /// adaptive corruption of seated validators, and its resistance grows
    /// exponentially in the rotation rate while the honest cost grows
    /// linearly — so the interval sits at the fastest cadence the ready
    /// margin allows ([`SHUFFLE_SYNC_HEADROOM`]), and no faster. A pure
    /// function of genesis-frozen config: every replica derives the same
    /// cadence, with no stored copy to diverge.
    #[must_use]
    pub const fn shuffle_interval_epochs(&self) -> u64 {
        let shard_size = if self.shard_size == 0 {
            1
        } else {
            self.shard_size as u64
        };
        let interval = SHUFFLE_SYNC_HEADROOM
            .saturating_mul(self.ready_timeout_epochs)
            .div_ceil(shard_size);
        if interval == 0 { 1 } else { interval }
    }

    /// Boundary checkpoints a serving store retains, derived rather than
    /// stored: `ready_timeout_epochs + 2`.
    ///
    /// A joiner's whole ready budget must fit inside the serving window
    /// of the boundary it syncs against, and retaining exactly the
    /// budget falls short twice over: the anchor a joiner selects at
    /// placement is typically attested one epoch behind (its boundary QC
    /// rides a later beacon block), and a retention ring that evicts at
    /// exactly the deadline leaves zero slack for the join that consumes
    /// its full budget. One extra epoch absorbs the attestation lag; the
    /// other keeps the anchor serving through the deadline itself.
    #[must_use]
    pub const fn boundary_retention_epochs(&self) -> u64 {
        self.ready_timeout_epochs + 2
    }
}

impl Default for BeaconChainConfig {
    /// Defaults: 5-minute epochs, shard size 4, beacon committee 4, ready
    /// timeout 8 — test-grade sizing (sims sync in one or two epochs; the
    /// timeout leaves slack over that without parking a wedged joiner for
    /// long).
    fn default() -> Self {
        Self {
            epoch_duration_ms: u64::try_from(EPOCH_DURATION.as_millis()).unwrap_or(u64::MAX),
            shard_size: u32::try_from(SHARD_CAPACITY).unwrap_or(u32::MAX),
            beacon_committee_size: u32::try_from(BEACON_SIGNER_COUNT).unwrap_or(u32::MAX),
            reshape_thresholds: ReshapeThresholds::DISABLED,
            genesis_timestamp_ms: 0,
            ready_timeout_epochs: 8,
            impound_epochs: IMPOUND_EPOCHS_DEFAULT,
        }
    }
}

/// One validator as supplied at genesis.
///
/// Pool linkage lives on the validator (a validator belongs to exactly
/// one pool); the pool's validator set is derived by filtering
/// `initial_validators` on `pool == this_pool_id` during state
/// construction.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GenesisValidator {
    /// Validator id.
    pub id: ValidatorId,
    /// Pool this validator operates under.
    pub pool: StakePoolId,
    /// Compressed BLS pubkey.
    pub pubkey: Bls12381G1PublicKey,
}

/// One stake pool as supplied at genesis.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GenesisPool {
    /// Pool id.
    pub id: StakePoolId,
    /// Total stake credited to this pool at genesis.
    pub total_stake: Stake,
}

/// Genesis configuration for a beacon chain.
///
/// Loaded from TOML at the validator binary's startup; consumed once by
/// the state builder. Every field is consensus-critical — two
/// validators with different `BeaconGenesisConfig`s produce divergent
/// `BeaconState`s at epoch 0 and never converge. The SBOR-canonical
/// hash of this struct is the [`GenesisConfigHash`] carried by
/// [`BeaconCert::Genesis`](crate::BeaconCert), binding the chain
/// identity to operator-supplied TOML; see [`genesis_config_hash`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconGenesisConfig {
    /// Sizing knobs (`epoch_duration_ms`, `shard_size`,
    /// `beacon_committee_size`). Copied into `BeaconState.chain_config`
    /// at genesis and read from there forever after.
    pub chain_config: BeaconChainConfig,
    /// Initial validator set.
    pub initial_validators: Vec<GenesisValidator>,
    /// Initial stake pools. Each pool's validator set is derived from
    /// `initial_validators` filtered on the pool id.
    pub initial_pools: Vec<GenesisPool>,
    /// Explicit initial beacon committee. Stored sorted in
    /// `BeaconState.committee`; the genesis builder sorts on the way
    /// in so the input order is incidental.
    pub initial_beacon_committee: Vec<ValidatorId>,
    /// The initial shard committee, seated on the sole genesis shard
    /// [`ShardId::ROOT`]. A chain always genesises with one shard and
    /// splits later, so this is a single committee rather than a
    /// per-shard map. Members get `OnShard { ready: true,
    /// placed_at_epoch: GENESIS }` — presumed synced by construction at
    /// chain bootstrap.
    pub initial_shard_committee: Vec<ValidatorId>,
    /// Seed for the very first epoch's randomness. Mixed straight into
    /// `state.randomness`; subsequent slots roll it through accepted
    /// VRF outputs.
    pub initial_randomness: Randomness,
}

/// Hash a [`BeaconGenesisConfig`] into the [`GenesisConfigHash`] carried
/// by [`BeaconCert::Genesis`](crate::BeaconCert).
///
/// Pure function over the SBOR-canonical encoding plus the network's
/// id byte. Two operators with byte-identical TOML produce the same
/// hash *only* when bootstrapping the same network — mainnet and
/// stokenet operators using identical genesis TOML still get distinct
/// chain identities. Any divergent field (validator pubkey, pool stake,
/// initial randomness, ...) likewise yields a different hash and a
/// different [`BeaconBlockHash`](crate::BeaconBlockHash) at genesis.
///
/// Layout: `BLAKE3(DOMAIN_BEACON_GENESIS || network.id || SBOR(config))`.
/// The domain tag bumps with any future layout change.
///
/// # Panics
///
/// Never in practice: every field is `BasicSbor` and the struct is
/// closed, so encoding is total.
#[must_use]
pub fn genesis_config_hash(
    config: &BeaconGenesisConfig,
    network: &NetworkDefinition,
) -> GenesisConfigHash {
    let mut h = Hasher::new();
    h.update(DOMAIN_BEACON_GENESIS);
    h.update(&[network.id]);
    let bytes = basic_encode(config).expect("BeaconGenesisConfig SBOR encode is infallible");
    h.update(&bytes);
    GenesisConfigHash::from_raw(Hash::from_hash_bytes(h.finalize().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls_keypair_from_seed;

    fn pubkey(seed: u64) -> Bls12381G1PublicKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s).public_key()
    }

    fn sample_config() -> BeaconGenesisConfig {
        let pool_id = StakePoolId::new(0);
        let validators = (0u64..4)
            .map(|i| GenesisValidator {
                id: ValidatorId::new(i),
                pool: pool_id,
                pubkey: pubkey(i),
            })
            .collect();
        let members: Vec<ValidatorId> = (0u64..4).map(ValidatorId::new).collect();
        BeaconGenesisConfig {
            chain_config: BeaconChainConfig::default(),
            initial_validators: validators,
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_whole_tokens(1_000_000),
            }],
            initial_beacon_committee: members.clone(),
            initial_shard_committee: members,
            initial_randomness: Randomness::new([0xAB; 32]),
        }
    }

    #[test]
    fn config_sbor_round_trip() {
        let original = sample_config();
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconGenesisConfig = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    /// The production config differs from the dev/sim default in exactly
    /// two knobs — the beacon committee size
    /// (`PRODUCTION_BEACON_COMMITTEE_SIZE`) and the ready timeout — with
    /// every other sizing knob unchanged.
    #[test]
    fn production_scales_committee_and_ready_timeout() {
        let prod = BeaconChainConfig::production();
        let dev = BeaconChainConfig::default();
        assert_eq!(
            prod.beacon_committee_size,
            u32::try_from(PRODUCTION_BEACON_COMMITTEE_SIZE).unwrap(),
        );
        assert!(
            prod.ready_timeout_epochs > dev.ready_timeout_epochs,
            "production must budget more sync epochs than a sim",
        );
        assert_eq!(
            prod,
            BeaconChainConfig {
                beacon_committee_size: prod.beacon_committee_size,
                ready_timeout_epochs: prod.ready_timeout_epochs,
                ..dev
            },
        );
    }

    /// The derived shuffle interval at the operating points the security
    /// analysis names: dev defaults keep today's 16-epoch cadence, the
    /// production target (n = 128, S = 32) lands on spec Rider 1's
    /// recommendation, and n = 256 sits exactly on the one-epoch floor.
    #[test]
    fn shuffle_interval_derives_from_sync_budget_and_shard_size() {
        let at = |shard_size: u32, ready_timeout_epochs: u64| {
            BeaconChainConfig {
                shard_size,
                ready_timeout_epochs,
                ..BeaconChainConfig::default()
            }
            .shuffle_interval_epochs()
        };
        assert_eq!(BeaconChainConfig::default().shuffle_interval_epochs(), 16);
        assert_eq!(at(128, 32), 2);
        assert_eq!(at(256, 32), 1);
        // Past the floor the clamp holds: tenure headroom is already met.
        assert_eq!(at(1024, 32), 1);
        // Degenerate sizes clamp rather than divide by zero or stall.
        assert_eq!(at(0, 8), 64);
        assert_eq!(at(4, 0), 1);
    }

    /// Serving retention outlives the ready budget: one epoch for the
    /// attestation lag of the anchor a joiner selects, one so eviction
    /// never lands exactly on the deadline.
    #[test]
    fn boundary_retention_outlives_the_ready_budget() {
        let production = BeaconChainConfig::production();
        assert_eq!(
            production.boundary_retention_epochs(),
            production.ready_timeout_epochs + 2,
        );
    }

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn config_hash_is_deterministic() {
        let a = sample_config();
        assert_eq!(
            genesis_config_hash(&a, &net()),
            genesis_config_hash(&a, &net())
        );
    }

    #[test]
    fn config_hash_changes_on_any_field() {
        let base = sample_config();
        let base_hash = genesis_config_hash(&base, &net());

        let mut diff_randomness = base.clone();
        diff_randomness.initial_randomness = Randomness::new([0xCD; 32]);
        assert_ne!(genesis_config_hash(&diff_randomness, &net()), base_hash);

        let mut diff_pool_stake = base.clone();
        diff_pool_stake.initial_pools[0].total_stake = Stake::from_whole_tokens(2_000_000);
        assert_ne!(genesis_config_hash(&diff_pool_stake, &net()), base_hash);

        let mut diff_pubkey = base;
        diff_pubkey.initial_validators[0].pubkey = pubkey(99);
        assert_ne!(genesis_config_hash(&diff_pubkey, &net()), base_hash);
    }

    /// Identical TOML on different networks must produce different
    /// chain identities — locks the network-id binding into the
    /// genesis hash.
    #[test]
    fn config_hash_differs_across_networks() {
        let config = sample_config();
        assert_ne!(
            genesis_config_hash(&config, &NetworkDefinition::mainnet()),
            genesis_config_hash(&config, &NetworkDefinition::stokenet()),
        );
    }
}
