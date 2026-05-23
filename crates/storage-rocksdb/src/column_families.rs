//! Column family definitions, constants, and handle resolution.
//!
//! This is the single source of truth for what column families exist,
//! what they store, and how their keys/values are encoded.

use hyperscale_types::{
    BlockMetadata, ConsensusReceipt, ExecutionCertificate, ExecutionMetadata, Hash,
    RoutableTransaction, ShardGroupId, ShardWitnessPayload, WaveCertificate, WaveId,
};
use radix_substate_store_interface::interface::{DbPartitionKey, DbSortKey};
use rocksdb::{ColumnFamily, DB};

use crate::jmt_stored::{StaleTreePart, StoredNodeKey, VersionedStoredNode};
use crate::substate_key::SubstateKeyCodec;
use crate::typed_cf::{
    BeU64Codec, DbCodec, DbEncode, HashCodec, JmtKeyCodec, RawCodec, SborCodec, TypedCf,
};
use crate::versioned_key::VersionedSubstateKeyCodec;

// ─── CF name constants ───────────────────────────────────────────────────────

/// Column family name for the default CF (chain metadata, JMT metadata).
pub const DEFAULT_CF: &str = "default";

/// Column family name for substate data. Stores the current value per
/// unversioned `(partition_key, sort_key)`. History for recent writes
/// lives in `STATE_HISTORY_CF` (same `storage_key` + write-version suffix,
/// value is the pre-write prior state). Current-state reads are a
/// direct point lookup; historical reads at version V seek the smallest
/// state-history entry for the key with `write_version > V` and return
/// its prior value.
pub const STATE_CF: &str = "state";

/// Column family name for the per-write state-history log used by
/// historical reads.
/// Key: `((partition_key, sort_key), write_version)`; value: the prior
/// value at that key immediately before the write at `write_version`.
/// A `None` value means "key was absent before the write."
pub const STATE_HISTORY_CF: &str = "state_history";

/// Column family name for block metadata (header + manifest) keyed by height.
pub const BLOCKS_CF: &str = "blocks";

/// Column family name for transactions keyed by hash.
pub const TRANSACTIONS_CF: &str = "transactions";

/// Column family name for wave certificates keyed by hash.
pub const CERTIFICATES_CF: &str = "certificates";

/// Column family name for JMT tree nodes.
pub const JMT_NODES_CF: &str = "jmt_nodes";

/// Column family for stale JMT nodes pending garbage collection.
/// Key: `version_BE_8B` (the version at which nodes became stale).
/// Value: SBOR-encoded `Vec<StaleTreePart>`.
/// GC deletes entries older than `current_version - jmt_history_length`.
pub const STALE_JMT_NODES_CF: &str = "stale_jmt_nodes";

/// Column family indexing `state_history` entries by their write version so
/// GC can delete retention-expired history without scanning the whole
/// `state_history` CF.
///
/// Key: `version_BE_8B` — the `write_version` at which these history entries
/// were created (one entry per block commit).
/// Value: SBOR-encoded `Vec<Vec<u8>>` — the list of raw `state_history` keys
/// (i.e. `storage_key_bytes ++ BE8(version)`) written at that version.
///
/// Written alongside every `state_history` entry. GC iterates this CF in
/// version order (cheap — version-keyed), breaks at `version >= cutoff`, and
/// issues one `delete_cf` per listed history key plus one for the stale-set
/// entry itself. Mirrors the `stale_jmt_nodes` pattern.
pub const STALE_STATE_HISTORY_CF: &str = "stale_state_history";

/// Column family for the consensus portion of stored receipts, keyed by
/// tx hash. Companion to [`EXECUTION_METADATA_CF`] (same key, separate CF
/// so metadata can be pruned on its own cycle).
pub const CONSENSUS_RECEIPTS_CF: &str = "consensus_receipts";

/// Column family for the local-only [`ExecutionMetadata`] (fees, logs,
/// error), keyed by tx hash. Absent when the tx was synced from a peer.
pub const EXECUTION_METADATA_CF: &str = "execution_metadata";

/// Column family for execution certificates keyed by [`WaveId`].
pub const EXECUTION_CERTS_CF: &str = "execution_certs";

/// Column family for per-shard beacon-witness leaves.
///
/// Key: `(shard_id, leaf_index)` as two big-endian `u64`s — within a
/// shard, lex order matches monotonic leaf order so the fetch responder
/// can range-scan to reconstruct an accumulator at any committed block.
/// Value: SBOR-encoded [`ShardWitnessPayload`]. Append-only; pruning
/// follows the retention horizon configured at the runtime layer.
pub const BEACON_WITNESSES_CF: &str = "beacon_witnesses";

// Default-CF metadata keys are defined as MetadataEntry types in typed_cf.rs.
// See CommittedHeightEntry, CommittedHashEntry, CommittedQcEntry, JmtMetadataEntry.

/// CFs with high write throughput — get larger write buffers and tiered compression.
/// State, state-history log, and JMT nodes are updated on every block commit.
pub const HOT_WRITE_COLUMN_FAMILIES: &[&str] = &[STATE_CF, STATE_HISTORY_CF, JMT_NODES_CF];

/// All column families used by the storage layer.
pub const ALL_COLUMN_FAMILIES: &[&str] = &[
    DEFAULT_CF,
    BLOCKS_CF,
    TRANSACTIONS_CF,
    STATE_CF,
    STATE_HISTORY_CF,
    STALE_STATE_HISTORY_CF,
    CERTIFICATES_CF,
    JMT_NODES_CF,
    STALE_JMT_NODES_CF,
    CONSENSUS_RECEIPTS_CF,
    EXECUTION_METADATA_CF,
    EXECUTION_CERTS_CF,
    BEACON_WITNESSES_CF,
];

// ─── CfHandles ───────────────────────────────────────────────────────────────

/// Column family handles resolved from a `DB` reference.
///
/// Provides typed field access to all column families without repeating
/// `.cf_handle(NAME).expect(...)`. Cheap to construct (`HashMap` lookups only).
/// Column family handles — fields are private, access only through
/// [`TypedCf::handle()`](crate::typed_cf::TypedCf::handle).
pub struct CfHandles<'a> {
    state: &'a ColumnFamily,
    state_history: &'a ColumnFamily,
    stale_state_history: &'a ColumnFamily,
    blocks: &'a ColumnFamily,
    transactions: &'a ColumnFamily,
    certificates: &'a ColumnFamily,
    jmt_nodes: &'a ColumnFamily,
    stale_jmt_nodes: &'a ColumnFamily,
    consensus_receipts: &'a ColumnFamily,
    execution_metadata: &'a ColumnFamily,
    execution_certs: &'a ColumnFamily,
    beacon_witnesses: &'a ColumnFamily,
}

impl<'a> CfHandles<'a> {
    /// Resolve all column family handles from the database.
    ///
    /// # Panics
    /// Panics if any expected column family is missing.
    pub fn resolve(db: &'a DB) -> Self {
        let resolve = |name: &str| -> &'a ColumnFamily {
            db.cf_handle(name)
                .unwrap_or_else(|| panic!("column family '{name}' must exist"))
        };
        Self {
            state: resolve(STATE_CF),
            state_history: resolve(STATE_HISTORY_CF),
            stale_state_history: resolve(STALE_STATE_HISTORY_CF),
            blocks: resolve(BLOCKS_CF),
            transactions: resolve(TRANSACTIONS_CF),
            certificates: resolve(CERTIFICATES_CF),
            jmt_nodes: resolve(JMT_NODES_CF),
            stale_jmt_nodes: resolve(STALE_JMT_NODES_CF),
            consensus_receipts: resolve(CONSENSUS_RECEIPTS_CF),
            execution_metadata: resolve(EXECUTION_METADATA_CF),
            execution_certs: resolve(EXECUTION_CERTS_CF),
            beacon_witnesses: resolve(BEACON_WITNESSES_CF),
        }
    }
}

// ─── Typed CF definitions ────────────────────────────────────────────────────

// Block / Transaction storage

pub struct BlocksCf;
impl TypedCf for BlocksCf {
    const NAME: &'static str = BLOCKS_CF;
    type Key = u64; // block height
    type Value = BlockMetadata;
    type KeyCodec = BeU64Codec;
    type ValueCodec = SborCodec<BlockMetadata>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a ColumnFamily {
        cf.blocks
    }
}

pub struct TransactionsCf;
impl TypedCf for TransactionsCf {
    const NAME: &'static str = TRANSACTIONS_CF;
    type Key = Hash;
    type Value = RoutableTransaction;
    type KeyCodec = HashCodec;
    type ValueCodec = SborCodec<RoutableTransaction>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a ColumnFamily {
        cf.transactions
    }
}

pub struct CertificatesCf;
impl TypedCf for CertificatesCf {
    const NAME: &'static str = CERTIFICATES_CF;
    type Key = WaveId;
    type Value = WaveCertificate;
    type KeyCodec = SborCodec<WaveId>;
    type ValueCodec = SborCodec<WaveCertificate>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a ColumnFamily {
        cf.certificates
    }
}

// JMT

pub struct JmtNodesCf;
impl TypedCf for JmtNodesCf {
    const NAME: &'static str = JMT_NODES_CF;
    type Key = StoredNodeKey;
    type Value = VersionedStoredNode;
    type KeyCodec = JmtKeyCodec;
    type ValueCodec = SborCodec<VersionedStoredNode>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a ColumnFamily {
        cf.jmt_nodes
    }
}

pub struct StaleJmtNodesCf;
impl TypedCf for StaleJmtNodesCf {
    const NAME: &'static str = STALE_JMT_NODES_CF;
    type Key = u64; // version at which nodes became stale
    type Value = Vec<StaleTreePart>;
    type KeyCodec = BeU64Codec;
    type ValueCodec = SborCodec<Vec<StaleTreePart>>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a ColumnFamily {
        cf.stale_jmt_nodes
    }
}

/// Version-indexed list of `state_history` keys written at each version.
/// Enables incremental GC of `state_history` — GC walks this CF in version
/// order, deletes the listed history keys for each version ≤ cutoff, and
/// drops the stale-set entry itself. No full `state_history` scan.
pub struct StaleStateHistoryCf;
impl TypedCf for StaleStateHistoryCf {
    const NAME: &'static str = STALE_STATE_HISTORY_CF;
    type Key = u64; // write_version
    type Value = Vec<Vec<u8>>; // raw `state_history` keys (storage_key ++ BE8(version))
    type KeyCodec = BeU64Codec;
    type ValueCodec = SborCodec<Vec<Vec<u8>>>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a ColumnFamily {
        cf.stale_state_history
    }
}

/// State — current-value-per-key source of truth.
///
/// Key: `(partition_key, sort_key)` encoded as `storage_key_bytes`.
/// Value: opaque substate bytes. An absent row means "no value for this
/// key" — deletions do `batch.delete_cf(state_cf, K)`, not a tombstone
/// sentinel.
///
/// Current reads are direct point lookups. Historical reads at version V
/// go through the companion `StateHistoryCf`: seek the smallest history
/// entry for K with `write_version > V` and return its stored prior value.
///
/// No prefix extractor: the dominant op is `get_cf(K)` (point reads plus
/// the commit path's `capture_history` `multi_get`), gated by whole-key
/// bloom (rocksdb default). A prefix extractor would add a second bloom
/// per SST, doubling filter-cache footprint and evicting data blocks
/// without improving point-read latency. `list_at_prefix` still works
/// without a prefix extractor — it just can't short-circuit SSTs via
/// prefix bloom.
pub struct StateCf;
impl TypedCf for StateCf {
    const NAME: &'static str = STATE_CF;
    type Key = (DbPartitionKey, DbSortKey);
    type Value = Vec<u8>;
    type KeyCodec = SubstateKeyCodec;
    type ValueCodec = RawCodec;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a ColumnFamily {
        cf.state
    }
}

/// State-history log — per-write prior-value entries for historical reads.
///
/// Key: `((partition_key, sort_key), write_version)` encoded as
/// `storage_key_bytes ++ write_version_BE_8B`. Value:
/// `Option<Vec<u8>>` — the value the key held immediately before the
/// write at `write_version`. `None` means "key was absent before the
/// write."
///
/// Every write to `StateCf` at version V captures a history entry at
/// `(K, V)` (except during genesis / bootstrap, which skips history
/// writes). GC deletes entries older than the retention window; `StateCf`
/// is always authoritative for the current tip.
///
/// Read-only: historical reads reconstruct the value-at-V by seeking the
/// smallest entry for K with `v' > V`. Nothing ever mutates `StateCf`
/// from this log.
pub struct StateHistoryCf;
impl TypedCf for StateHistoryCf {
    const NAME: &'static str = STATE_HISTORY_CF;
    type Key = ((DbPartitionKey, DbSortKey), u64); // ((partition_key, sort_key), write_version)
    type Value = Option<Vec<u8>>;
    type KeyCodec = VersionedSubstateKeyCodec;
    type ValueCodec = SborCodec<Option<Vec<u8>>>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a ColumnFamily {
        cf.state_history
    }
}

// Receipts

pub struct ConsensusReceiptsCf;
impl TypedCf for ConsensusReceiptsCf {
    const NAME: &'static str = CONSENSUS_RECEIPTS_CF;
    type Key = Hash;
    type Value = ConsensusReceipt;
    type KeyCodec = HashCodec;
    type ValueCodec = SborCodec<ConsensusReceipt>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a ColumnFamily {
        cf.consensus_receipts
    }
}

pub struct ExecutionMetadataCf;
impl TypedCf for ExecutionMetadataCf {
    const NAME: &'static str = EXECUTION_METADATA_CF;
    type Key = Hash;
    type Value = ExecutionMetadata;
    type KeyCodec = HashCodec;
    type ValueCodec = SborCodec<ExecutionMetadata>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a ColumnFamily {
        cf.execution_metadata
    }
}

// Execution Certificates

pub struct ExecutionCertsCf;
impl TypedCf for ExecutionCertsCf {
    const NAME: &'static str = EXECUTION_CERTS_CF;
    type Key = WaveId;
    type Value = ExecutionCertificate;
    type KeyCodec = SborCodec<WaveId>;
    type ValueCodec = SborCodec<ExecutionCertificate>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a ColumnFamily {
        cf.execution_certs
    }
}

// Beacon witnesses.

/// Key codec for the [`BeaconWitnessesCf`] CF: a `(shard, leaf_index)`
/// pair encoded as two big-endian `u64`s. BE preserves lexicographic
/// order so a per-shard scan returns leaves in monotonic index order.
#[derive(Default)]
pub struct BeaconWitnessKeyCodec;

impl DbEncode<(ShardGroupId, u64)> for BeaconWitnessKeyCodec {
    fn encode_to(&self, value: &(ShardGroupId, u64), buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.0.inner().to_be_bytes());
        buf.extend_from_slice(&value.1.to_be_bytes());
    }
}

impl DbCodec<(ShardGroupId, u64)> for BeaconWitnessKeyCodec {
    fn decode(&self, bytes: &[u8]) -> (ShardGroupId, u64) {
        assert_eq!(bytes.len(), 16, "beacon-witness key must be 16 bytes");
        let shard = u64::from_be_bytes(bytes[..8].try_into().expect("split bounds checked"));
        let leaf_index = u64::from_be_bytes(bytes[8..].try_into().expect("split bounds checked"));
        (ShardGroupId::new(shard), leaf_index)
    }
}

pub struct BeaconWitnessesCf;
impl TypedCf for BeaconWitnessesCf {
    const NAME: &'static str = BEACON_WITNESSES_CF;
    type Key = (ShardGroupId, u64);
    type Value = ShardWitnessPayload;
    type KeyCodec = BeaconWitnessKeyCodec;
    type ValueCodec = SborCodec<ShardWitnessPayload>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a ColumnFamily {
        cf.beacon_witnesses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_witness_key_codec_round_trip() {
        let codec = BeaconWitnessKeyCodec;
        let cases = [
            (ShardGroupId::new(0), 0u64),
            (ShardGroupId::new(7), 42u64),
            (ShardGroupId::new(u64::MAX), u64::MAX),
        ];
        for (shard, leaf) in cases {
            let mut buf = Vec::new();
            codec.encode_to(&(shard, leaf), &mut buf);
            assert_eq!(buf.len(), 16);
            assert_eq!(codec.decode(&buf), (shard, leaf));
        }
    }

    /// Per-shard scan order must match monotonic leaf order — that's
    /// why the key is BE-encoded. Sorting encoded keys lexicographically
    /// must yield ascending `(shard, leaf_index)`.
    #[test]
    fn beacon_witness_key_codec_preserves_per_shard_order() {
        let codec = BeaconWitnessKeyCodec;
        let mut encoded: Vec<Vec<u8>> = [
            (ShardGroupId::new(1), 10u64),
            (ShardGroupId::new(1), 0u64),
            (ShardGroupId::new(0), 5u64),
            (ShardGroupId::new(1), 1u64),
            (ShardGroupId::new(0), 1u64),
        ]
        .iter()
        .map(|kv| {
            let mut buf = Vec::new();
            codec.encode_to(kv, &mut buf);
            buf
        })
        .collect();
        encoded.sort();
        let decoded: Vec<(ShardGroupId, u64)> = encoded.iter().map(|b| codec.decode(b)).collect();
        assert_eq!(
            decoded,
            vec![
                (ShardGroupId::new(0), 1),
                (ShardGroupId::new(0), 5),
                (ShardGroupId::new(1), 0),
                (ShardGroupId::new(1), 1),
                (ShardGroupId::new(1), 10),
            ]
        );
    }
}
