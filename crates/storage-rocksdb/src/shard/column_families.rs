//! Column family definitions, constants, and handle resolution.
//!
//! This is the single source of truth for what column families exist,
//! what they store, and how their keys/values are encoded.

use hyperscale_types::{
    BlockMetadata, ConsensusReceipt, ExecutionCertificate, ExecutionMetadata, Hash,
    RoutableTransaction, ShardWitnessPayload, WaveCertificate, WaveId,
};
use radix_substate_store_interface::interface::{DbPartitionKey, DbSortKey};
use rocksdb::{ColumnFamily, DB};

use super::jmt_stored::{StaleTreePart, StoredNodeKey, VersionedStoredNode};
use super::substate_key::SubstateKeyCodec;
use super::versioned_key::VersionedSubstateKeyCodec;
use crate::typed_cf::{
    BeU64Codec, DbCodec, DbEncode, HashCodec, JmtKeyCodec, RawCodec, SborCodec, TypedCf,
};

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

/// Column family for beacon-witness leaves on this shard.
///
/// Key: `leaf_index` as a big-endian `u64` — lex order matches
/// monotonic leaf order so the fetch responder can range-scan to
/// reconstruct an accumulator at any committed block. Storage is
/// scoped per-shard, so the shard id is implicit in the key.
/// Value: SBOR-encoded [`ShardWitnessPayload`]. Append-only; pruning
/// follows the retention horizon configured at the runtime layer.
pub const BEACON_WITNESSES_CF: &str = "beacon_witnesses";

/// Column family mapping hashed JMT leaf keys back to raw substate
/// storage keys.
///
/// Key: the 32-byte hashed leaf key (`jmt_leaf_key` output). Value: the
/// raw storage key (`db_node_key ++ partition_num ++ sort_key`). The
/// mapping is deterministic and immutable per key; entries are deleted
/// when their substate is deleted, so the CF mirrors `STATE_CF`'s live
/// key set. Snap-sync range serving resolves enumerated leaves through
/// it — keyed in hashed order, a range walk reads it sequentially.
/// Hard-link checkpoints pin it alongside the tree, making a checkpoint
/// self-contained for serving.
pub const LEAF_ASSOCIATIONS_CF: &str = "leaf_associations";

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
    LEAF_ASSOCIATIONS_CF,
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
    leaf_associations: &'a ColumnFamily,
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
            leaf_associations: resolve(LEAF_ASSOCIATIONS_CF),
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
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
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
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
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
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
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
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
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
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.stale_jmt_nodes
    }
}

/// Hashed-leaf-key → raw-storage-key mapping; see [`LEAF_ASSOCIATIONS_CF`].
pub struct LeafAssociationsCf;
impl TypedCf for LeafAssociationsCf {
    const NAME: &'static str = LEAF_ASSOCIATIONS_CF;
    type Key = Hash; // 32-byte hashed JMT leaf key
    type Value = Vec<u8>; // raw substate storage key
    type KeyCodec = HashCodec;
    type ValueCodec = RawCodec;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.leaf_associations
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
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
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
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
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
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
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
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
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
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
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
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.execution_certs
    }
}

// Beacon witnesses.

/// Key codec for the [`BeaconWitnessesCf`] CF: a `u64` leaf index
/// encoded big-endian. BE preserves lexicographic order so a full scan
/// returns leaves in monotonic index order. The shard is implicit —
/// storage is scoped per-shard.
#[derive(Default)]
pub struct BeaconWitnessKeyCodec;

impl DbEncode<u64> for BeaconWitnessKeyCodec {
    fn encode_to(&self, value: &u64, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

impl DbCodec<u64> for BeaconWitnessKeyCodec {
    fn decode(&self, bytes: &[u8]) -> u64 {
        assert_eq!(bytes.len(), 8, "beacon-witness key must be 8 bytes");
        u64::from_be_bytes(bytes.try_into().expect("length checked above"))
    }
}

pub struct BeaconWitnessesCf;
impl TypedCf for BeaconWitnessesCf {
    const NAME: &'static str = BEACON_WITNESSES_CF;
    type Key = u64;
    type Value = ShardWitnessPayload;
    type KeyCodec = BeaconWitnessKeyCodec;
    type ValueCodec = SborCodec<ShardWitnessPayload>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.beacon_witnesses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_witness_key_codec_round_trip() {
        let codec = BeaconWitnessKeyCodec;
        for leaf in [0u64, 42, u64::MAX] {
            let mut buf = Vec::new();
            codec.encode_to(&leaf, &mut buf);
            assert_eq!(buf.len(), 8);
            assert_eq!(codec.decode(&buf), leaf);
        }
    }

    /// BE encoding so sorting encoded keys lexicographically matches
    /// ascending leaf-index order — the responder's prefix scan relies
    /// on this for monotonic iteration.
    #[test]
    fn beacon_witness_key_codec_preserves_monotonic_order() {
        let codec = BeaconWitnessKeyCodec;
        let mut encoded: Vec<Vec<u8>> = [10u64, 0, 5, 1, 256]
            .iter()
            .map(|leaf| {
                let mut buf = Vec::new();
                codec.encode_to(leaf, &mut buf);
                buf
            })
            .collect();
        encoded.sort();
        let decoded: Vec<u64> = encoded.iter().map(|b| codec.decode(b)).collect();
        assert_eq!(decoded, vec![0, 1, 5, 10, 256]);
    }
}
