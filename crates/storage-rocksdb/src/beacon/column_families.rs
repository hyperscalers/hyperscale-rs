//! Column family definitions for the beacon `RocksDB` instance.
//!
//! Three live CFs plus the default. Each commit writes the (block,
//! state) pair atomically:
//!
//! - `beacon_blocks_by_epoch` — primary block store, BE-`u64` keyed
//! - `beacon_hash_to_epoch` — secondary `BeaconBlockHash → Epoch`
//!   index so hash lookups stay O(1) without duplicating the block
//!   payload
//! - `beacon_state_by_epoch` — parallel `BeaconState` store; written
//!   in the same `WriteBatch` so the pair on disk can never drift
//!
//! `RocksDbBeaconStorage` opens its own database directory; this CF
//! set is disjoint from the per-shard tier.

use hyperscale_types::{BeaconState, CertifiedBeaconBlock, Hash, RatifyVoteRecord, ValidatorId};
use rocksdb::{ColumnFamily, DB};

use crate::shard::column_families::ValidatorIdCodec;
use crate::typed_cf::{BeU64Codec, HashCodec, SborCodec, TypedCf};

/// Default CF (presence required by `RocksDB`; unused by beacon today).
pub const DEFAULT_CF: &str = "default";

/// Primary block store keyed by `Epoch` (big-endian `u64` for lex
/// ordering). Value: SBOR-encoded
/// [`BeaconBlock`](hyperscale_types::BeaconBlock).
pub const BEACON_BLOCKS_BY_EPOCH_CF: &str = "beacon_blocks_by_epoch";

/// Secondary index `BeaconBlockHash → Epoch` so hash lookups stay
/// O(1) without duplicating the block payload. Value: big-endian
/// `u64` epoch.
pub const BEACON_HASH_TO_EPOCH_CF: &str = "beacon_hash_to_epoch";

/// Per-epoch `BeaconState` snapshot store keyed by `Epoch`. Value:
/// SBOR-encoded [`BeaconState`](hyperscale_types::BeaconState).
/// Written in the same `WriteBatch` as the block CFs so the
/// (block, state) pair is atomically consistent on disk.
pub const BEACON_STATE_BY_EPOCH_CF: &str = "beacon_state_by_epoch";

/// Per-validator durable ratification registers, keyed by validator id
/// (big-endian `u64`). Value: SBOR-encoded
/// [`RatifyVoteRecord`](hyperscale_types::RatifyVoteRecord) — the
/// validator's prevote/precommit per round for its newest epoch.
/// Written with a synchronous (fsynced) write before the corresponding
/// ratify-vote signature leaves the process.
pub const RATIFY_REGISTERS_CF: &str = "ratify_registers";

/// Full CF set passed to `DB::open_cf_descriptors` when initialising the
/// beacon database.
pub const ALL_COLUMN_FAMILIES: &[&str] = &[
    DEFAULT_CF,
    BEACON_BLOCKS_BY_EPOCH_CF,
    BEACON_HASH_TO_EPOCH_CF,
    BEACON_STATE_BY_EPOCH_CF,
    RATIFY_REGISTERS_CF,
];

// ─── CfHandles ───────────────────────────────────────────────────────────────

/// Beacon-side column-family handles resolved from a `DB` reference.
///
/// Distinct from the per-shard tier's `CfHandles` because beacon runs
/// its own `RocksDB` instance with a disjoint CF set.
pub struct CfHandles<'a> {
    blocks_by_epoch: &'a ColumnFamily,
    hash_to_epoch: &'a ColumnFamily,
    state_by_epoch: &'a ColumnFamily,
    ratify_registers: &'a ColumnFamily,
}

impl<'a> CfHandles<'a> {
    /// Resolve all beacon column-family handles from the database.
    ///
    /// # Panics
    ///
    /// Panics if any expected column family is missing.
    pub fn resolve(db: &'a DB) -> Self {
        let resolve = |name: &str| -> &'a ColumnFamily {
            db.cf_handle(name)
                .unwrap_or_else(|| panic!("beacon column family '{name}' must exist"))
        };
        Self {
            blocks_by_epoch: resolve(BEACON_BLOCKS_BY_EPOCH_CF),
            hash_to_epoch: resolve(BEACON_HASH_TO_EPOCH_CF),
            state_by_epoch: resolve(BEACON_STATE_BY_EPOCH_CF),
            ratify_registers: resolve(RATIFY_REGISTERS_CF),
        }
    }
}

// ─── Typed CF definitions ────────────────────────────────────────────────────

/// Primary beacon-blocks-by-epoch CF. Key: `u64` epoch (BE-encoded for
/// lex ordering). Value: SBOR-encoded `CertifiedBeaconBlock`.
pub struct BeaconBlocksByEpochCf;
impl TypedCf for BeaconBlocksByEpochCf {
    const NAME: &'static str = BEACON_BLOCKS_BY_EPOCH_CF;
    type Key = u64;
    type Value = CertifiedBeaconBlock;
    type KeyCodec = BeU64Codec;
    type ValueCodec = SborCodec<CertifiedBeaconBlock>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.blocks_by_epoch
    }
}

/// Secondary hash-to-epoch index CF. Key: 32-byte block hash. Value:
/// `u64` epoch (BE-encoded for consistency with the primary CF).
pub struct BeaconHashToEpochCf;
impl TypedCf for BeaconHashToEpochCf {
    const NAME: &'static str = BEACON_HASH_TO_EPOCH_CF;
    type Key = Hash;
    type Value = u64;
    type KeyCodec = HashCodec;
    type ValueCodec = BeU64Codec;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.hash_to_epoch
    }
}

/// Per-epoch `BeaconState` CF. Key: `u64` epoch (BE-encoded). Value:
/// SBOR-encoded `BeaconState`.
pub struct BeaconStateByEpochCf;
impl TypedCf for BeaconStateByEpochCf {
    const NAME: &'static str = BEACON_STATE_BY_EPOCH_CF;
    type Key = u64;
    type Value = BeaconState;
    type KeyCodec = BeU64Codec;
    type ValueCodec = SborCodec<BeaconState>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.state_by_epoch
    }
}

/// Per-validator ratification registers; see [`RATIFY_REGISTERS_CF`].
pub struct RatifyRegistersCf;
impl TypedCf for RatifyRegistersCf {
    const NAME: &'static str = RATIFY_REGISTERS_CF;
    type Key = ValidatorId;
    type Value = RatifyVoteRecord;
    type KeyCodec = ValidatorIdCodec;
    type ValueCodec = SborCodec<RatifyVoteRecord>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.ratify_registers
    }
}
