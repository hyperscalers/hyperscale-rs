//! Column family definitions, constants, and handle resolution.
//!
//! This is the single source of truth for what column families exist,
//! what they store, and how their keys/values are encoded.

use std::collections::BTreeSet;
use std::marker::PhantomData;

use hyperscale_hbor::{HborDecode, HborEncode};
use hyperscale_jmt::{Node, NodeKey};
use hyperscale_types::{
    Address, Block, BlockHash, BlockHeight, BlockMetadata, ChainOrigin, ConsensusReceipt, EntryKey,
    ExecutionCertificate, ExecutionMetadata, Finalization, FinalizationHash, Hash, ProvisionHash,
    Provisions, SafeVoteRegisters, ShardWitnessPayload, SubstateKey, SweepBucket, TickId,
    Transaction, ValidatorId,
};
use rocksdb::{ColumnFamily, DB};

use super::entry_key::{EntryKeyCodec, VersionedEntryKeyCodec};
use super::substate_key::SubstateKeyCodec;
use super::sweep_key::SweepRowCodec;
use super::versioned_key::VersionedSubstateKeyCodec;
use crate::typed_cf::{
    BeU64Codec, ChainOriginCodec, DbCodec, DbEncode, HashCodec, HborCodec, JmtKeyCodec,
    JmtNodeCodec, JmtStaleKeysCodec, RawCodec, TypedCf,
};

// ─── CF name constants ───────────────────────────────────────────────────────

/// Column family name for the default CF (chain metadata, JMT metadata).
pub const DEFAULT_CF: &str = "default";

/// Column family name for substate data. Stores the current value per
/// unversioned substate key. History for recent writes lives in
/// `STATE_HISTORY_CF` (same key + write-version suffix, value is the
/// pre-write prior state). Current-state reads are a direct point
/// lookup; historical reads at version V seek the smallest
/// state-history entry for the key with `write_version > V` and return
/// its prior value.
pub const STATE_CF: &str = "state";

/// Column family name for the per-write state-history log used by
/// historical reads.
/// Key: `(substate_key, write_version)`; value: the prior value at that
/// key immediately before the write at `write_version`. A `None` value
/// means "key was absent before the write."
pub const STATE_HISTORY_CF: &str = "state_history";

/// Ordered-collection entry index — current live entries, keyed
/// `owner ++ collection ++ order_BE` so one collection's entries are
/// contiguous and iterate ascending.
pub const ENTRIES_CF: &str = "entries";

/// Entry-index history log — per-write prior values, keyed
/// `entry_key ++ write_version_BE`, mirroring `state_history`.
pub const ENTRIES_HISTORY_CF: &str = "entries_history";

/// Version-indexed list of `entries_history` keys written at each
/// version, mirroring `stale_state_history` for the entry index's GC.
pub const STALE_ENTRIES_HISTORY_CF: &str = "stale_entries_history";

/// Column family name for block metadata (header + manifest) keyed by height.
pub const BLOCKS_CF: &str = "blocks";

/// Column family name for transactions keyed by hash.
pub const TRANSACTIONS_CF: &str = "transactions";

/// Column family name for finalizations keyed by hash.
pub const CERTIFICATES_CF: &str = "certificates";

/// Column family name for JMT tree nodes.
pub const JMT_NODES_CF: &str = "jmt_nodes";

/// Column family for stale JMT nodes pending garbage collection.
/// Key: `version_BE_8B` (the version at which nodes became stale).
/// Value: HBOR-encoded `Vec<StaleTreePart>`.
/// GC deletes entries below the retention floor.
pub const STALE_JMT_NODES_CF: &str = "stale_jmt_nodes";

/// Column family indexing `state_history` entries by their write version so
/// GC can delete retention-expired history without scanning the whole
/// `state_history` CF.
///
/// Key: `version_BE_8B` — the `write_version` at which these history entries
/// were created (one entry per block commit).
/// Value: HBOR-encoded `Vec<Vec<u8>>` — the list of raw `state_history` keys
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

/// Column family for execution certificates keyed by [`TickId`].
pub const EXECUTION_CERTS_CF: &str = "execution_certs";

/// Column family mapping a transaction to the certificate carrying its
/// outcome, keyed by tx hash with a [`TickId`] value.
///
/// A counterpart shard asks for outcomes by transaction — it learned of
/// the transaction from our committed header and has no way to know which
/// certificate we ended up putting it in. This index is how the fetch
/// responder answers that from storage once the in-memory cache has
/// evicted. Written in the same batch as [`EXECUTION_CERTS_CF`], one entry
/// per attested outcome.
pub const TX_CERT_INDEX_CF: &str = "tx_cert_index";

/// Column family for beacon-witness leaves on this shard.
///
/// Key: `leaf_index` as a big-endian `u64` — lex order matches
/// monotonic leaf order so the fetch responder can range-scan to
/// reconstruct an accumulator at any committed block. Storage is
/// scoped per-shard, so the shard id is implicit in the key.
/// Value: HBOR-encoded [`ShardWitnessPayload`]. Append-only; pruning
/// follows the retention horizon configured at the runtime layer.
pub const BEACON_WITNESSES_CF: &str = "beacon_witnesses";

/// Column family for the committed substate byte total per version.
///
/// Key: `version_BE_8B`; value: HBOR-encoded `u64` — the sum of every JMT
/// leaf's value byte length after the commit at that version. Written in
/// the same batch as the commit (crash-consistent with the tree), one
/// entry per committed version. Consensus-critical: shard-witness
/// derivation reads the byte total behind a block's parent state, so it
/// must be identical on every replica. GC prunes entries below the same
/// retention floor as historical tree data.
pub const SUBSTATE_BYTES_CF: &str = "substate_bytes";

/// Column family for each version's weighted timestamp.
///
/// Key: `version_BE_8B`; value: HBOR-encoded `u64` — the milliseconds of
/// the weighted timestamp on the QC that certified the block at that
/// version. Written in the same batch as the commit, one entry per
/// committed version, and it is what makes retention a span of time
/// rather than a count of blocks: the floor is the oldest version still
/// inside `RETENTION_HORIZON` of the tip, which is a question only these
/// rows can answer. Kept here rather than read back off the block store
/// so retention answers for itself — a version this shard holds tree
/// data for is one it can date, whatever else has been pruned.
pub const VERSION_TIME_CF: &str = "version_time";

/// Column family for durable safe-vote registers, keyed by validator.
///
/// Key: `validator_id_BE_8B`. Value: packed 32-byte record
/// `[chain_origin_16B][locked_round_BE_8B][last_voted_round_BE_8B]`.
/// The chain-origin tag binds the record to the chain incarnation that
/// wrote it — a child store seeded from a parent shard's checkpoint
/// carries the parent's records, and reads ignore any record whose tag
/// differs from the store's current origin. Written with a synchronous
/// (fsynced) write before the corresponding vote or timeout signature
/// leaves the process.
pub const SAFE_VOTE_REGISTERS_CF: &str = "safe_vote_registers";

/// Column family holding the uncommitted blocks that justify a
/// validator's safe-vote registers, keyed by height then block hash.
///
/// A certificate is only usable while the block it names still exists,
/// so these are written in the same synchronous batch as the registers
/// and dropped by one range delete once the chain commits past them.
/// The hash follows the height because two blocks can sit at one height
/// across a fork, and the committed chain's view of that height belongs
/// to [`BLOCKS_CF`].
pub const VOTED_BLOCKS_CF: &str = "voted_blocks";

/// Column family staging verified snap-sync chunks before finalize.
///
/// Key: the substate key's 32 bytes — its JMT leaf key, so the bytewise
/// comparator makes a full scan leaf-sorted, which the chunked finalize
/// build relies on. Value: the raw substate value. Written one atomic
/// batch per verified chunk together with the import progress record in
/// the default CF; the store proper is untouched until
/// `finalize_boundary_import` builds the state from the staged leaves
/// and clears this CF.
pub const IMPORT_STAGING_CF: &str = "import_staging";

/// Column family for the provision bundles a committed block carried.
///
/// Key: `(committing_height_BE_8B, provision_hash_32B)`; value:
/// HBOR-encoded [`Provisions`]. A stored block keeps only its bundles'
/// hashes, so this is where the bodies live between the block that
/// carried them and the finalization that resolves what they provisioned
/// — the window a restart has to replay across.
///
/// The committing height leads the key so the retention sweep is one
/// range delete. It is the height of *our* block that carried the
/// bundle, not `Provisions::block_height`, which is the source shard's.
pub const PROVISIONS_CF: &str = "provisions";

/// Column family indexing committed package artifacts by content address.
///
/// Key: the 32-byte package hash; value: the artifact bytes, verbatim —
/// the same bytes the package cell stores. Derived state, written in the
/// commit batch whenever a committed cell self-identifies as a package,
/// so a restarted node re-learns published code from here without
/// scanning cells it cannot name. Content-addressed, so re-writing an
/// entry is writing the same bytes.
pub const PACKAGE_ARTIFACTS_CF: &str = "package_artifacts";

/// Column family indexing which owners hold sweepable cells in each
/// expiry bucket.
///
/// Key: `bucket_BE ++ owner`; value: how many of that owner's cells fall
/// in that bucket. Derived state on the same terms as [`ENTRIES_CF`]:
/// maintained in the commit batch where priors are already resolved,
/// rebuilt from the leaves at boundary import, and equal at every height
/// to what the tree's sweepable leaves say.
///
/// Bucket-major because a sweep enumerates by expiry and the state
/// keyspace is owner-major. What the index does *not* have to say is
/// which cells: the bucket leads a sweepable cell's local half, so one
/// owner's bucket is a contiguous leaf-key range and completeness within
/// an owner is answerable from the state root alone.
pub const SWEEP_INDEX_CF: &str = "sweep_index";

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
    ENTRIES_CF,
    ENTRIES_HISTORY_CF,
    STALE_ENTRIES_HISTORY_CF,
    CERTIFICATES_CF,
    JMT_NODES_CF,
    STALE_JMT_NODES_CF,
    CONSENSUS_RECEIPTS_CF,
    EXECUTION_METADATA_CF,
    EXECUTION_CERTS_CF,
    TX_CERT_INDEX_CF,
    BEACON_WITNESSES_CF,
    SUBSTATE_BYTES_CF,
    VERSION_TIME_CF,
    SAFE_VOTE_REGISTERS_CF,
    VOTED_BLOCKS_CF,
    IMPORT_STAGING_CF,
    PROVISIONS_CF,
    PACKAGE_ARTIFACTS_CF,
    SWEEP_INDEX_CF,
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
    entries: &'a ColumnFamily,
    entries_history: &'a ColumnFamily,
    stale_entries_history: &'a ColumnFamily,
    blocks: &'a ColumnFamily,
    transactions: &'a ColumnFamily,
    certificates: &'a ColumnFamily,
    jmt_nodes: &'a ColumnFamily,
    stale_jmt_nodes: &'a ColumnFamily,
    consensus_receipts: &'a ColumnFamily,
    execution_metadata: &'a ColumnFamily,
    execution_certs: &'a ColumnFamily,
    tx_cert_index: &'a ColumnFamily,
    beacon_witnesses: &'a ColumnFamily,
    substate_bytes: &'a ColumnFamily,
    version_time: &'a ColumnFamily,
    safe_vote_registers: &'a ColumnFamily,
    voted_blocks: &'a ColumnFamily,
    import_staging: &'a ColumnFamily,
    provisions: &'a ColumnFamily,
    package_artifacts: &'a ColumnFamily,
    sweep_index: &'a ColumnFamily,
}

impl<'a> CfHandles<'a> {
    /// Resolve all column family handles from the database.
    ///
    /// # Panics
    /// Panics if any expected column family is missing.
    pub(crate) fn resolve(db: &'a DB) -> Self {
        let resolve = |name: &str| -> &'a ColumnFamily {
            db.cf_handle(name)
                .unwrap_or_else(|| panic!("column family '{name}' must exist"))
        };
        Self {
            state: resolve(STATE_CF),
            state_history: resolve(STATE_HISTORY_CF),
            stale_state_history: resolve(STALE_STATE_HISTORY_CF),
            entries: resolve(ENTRIES_CF),
            entries_history: resolve(ENTRIES_HISTORY_CF),
            stale_entries_history: resolve(STALE_ENTRIES_HISTORY_CF),
            blocks: resolve(BLOCKS_CF),
            transactions: resolve(TRANSACTIONS_CF),
            certificates: resolve(CERTIFICATES_CF),
            jmt_nodes: resolve(JMT_NODES_CF),
            stale_jmt_nodes: resolve(STALE_JMT_NODES_CF),
            consensus_receipts: resolve(CONSENSUS_RECEIPTS_CF),
            execution_metadata: resolve(EXECUTION_METADATA_CF),
            execution_certs: resolve(EXECUTION_CERTS_CF),
            tx_cert_index: resolve(TX_CERT_INDEX_CF),
            beacon_witnesses: resolve(BEACON_WITNESSES_CF),
            substate_bytes: resolve(SUBSTATE_BYTES_CF),
            version_time: resolve(VERSION_TIME_CF),
            safe_vote_registers: resolve(SAFE_VOTE_REGISTERS_CF),
            voted_blocks: resolve(VOTED_BLOCKS_CF),
            import_staging: resolve(IMPORT_STAGING_CF),
            package_artifacts: resolve(PACKAGE_ARTIFACTS_CF),
            sweep_index: resolve(SWEEP_INDEX_CF),
            provisions: resolve(PROVISIONS_CF),
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
    type ValueCodec = HborCodec<BlockMetadata>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.blocks
    }
}

pub struct TransactionsCf;
impl TypedCf for TransactionsCf {
    const NAME: &'static str = TRANSACTIONS_CF;
    type Key = Hash;
    type Value = Transaction;
    type KeyCodec = HashCodec;
    type ValueCodec = HborCodec<Transaction>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.transactions
    }
}

pub struct CertificatesCf;
impl TypedCf for CertificatesCf {
    const NAME: &'static str = CERTIFICATES_CF;
    type Key = FinalizationHash;
    type Value = Finalization;
    type KeyCodec = HborCodec<FinalizationHash>;
    type ValueCodec = HborCodec<Finalization>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.certificates
    }
}

// JMT

pub struct JmtNodesCf;
impl TypedCf for JmtNodesCf {
    const NAME: &'static str = JMT_NODES_CF;
    type Key = NodeKey;
    type Value = Node;
    type KeyCodec = JmtKeyCodec;
    type ValueCodec = JmtNodeCodec;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.jmt_nodes
    }
}

pub struct StaleJmtNodesCf;
impl TypedCf for StaleJmtNodesCf {
    const NAME: &'static str = STALE_JMT_NODES_CF;
    type Key = u64; // version at which nodes became stale
    type Value = Vec<NodeKey>;
    type KeyCodec = BeU64Codec;
    type ValueCodec = JmtStaleKeysCodec;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.stale_jmt_nodes
    }
}

/// Committed substate byte total per version; see [`SUBSTATE_BYTES_CF`].
pub struct SubstateBytesCf;
impl TypedCf for SubstateBytesCf {
    const NAME: &'static str = SUBSTATE_BYTES_CF;
    type Key = u64; // version
    type Value = u64; // byte total after this version's commit
    type KeyCodec = BeU64Codec;
    type ValueCodec = HborCodec<u64>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.substate_bytes
    }
}

/// Each version's weighted timestamp; see [`VERSION_TIME_CF`].
pub struct VersionTimeCf;
impl TypedCf for VersionTimeCf {
    const NAME: &'static str = VERSION_TIME_CF;
    type Key = u64; // version
    type Value = u64; // weighted timestamp of the QC certifying it, in ms
    type KeyCodec = BeU64Codec;
    type ValueCodec = HborCodec<u64>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.version_time
    }
}

/// Committed package artifacts by content address; see
/// [`PACKAGE_ARTIFACTS_CF`].
pub struct PackageArtifactsCf;
impl TypedCf for PackageArtifactsCf {
    const NAME: &'static str = PACKAGE_ARTIFACTS_CF;
    type Key = Hash; // the package's content address
    type Value = Vec<u8>; // the artifact bytes, verbatim
    type KeyCodec = HashCodec;
    type ValueCodec = RawCodec;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.package_artifacts
    }
}

/// Sweep index — which owners hold sweepable cells in each expiry
/// bucket, and how many. See [`SWEEP_INDEX_CF`].
pub struct SweepIndexCf;
impl TypedCf for SweepIndexCf {
    const NAME: &'static str = SWEEP_INDEX_CF;
    type Key = (SweepBucket, Address);
    type Value = u32; // live sweepable cells of this owner in this bucket
    type KeyCodec = SweepRowCodec;
    type ValueCodec = HborCodec<u32>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.sweep_index
    }
}

/// Staged snap-sync leaves awaiting finalize; see [`IMPORT_STAGING_CF`].
pub struct ImportStagingCf;
impl TypedCf for ImportStagingCf {
    const NAME: &'static str = IMPORT_STAGING_CF;
    type Key = SubstateKey; // the leaf key by identity
    type Value = Vec<u8>; // raw substate value
    type KeyCodec = SubstateKeyCodec;
    type ValueCodec = RawCodec;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.import_staging
    }
}

/// Key codec for [`ProvisionsCf`]: the committing height big-endian,
/// then the bundle's hash. BE first so the bytewise comparator groups a
/// block's bundles together and orders the groups by height, which is
/// what makes the retention sweep a single range delete.
#[derive(Default)]
pub struct ProvisionKeyCodec;

impl DbEncode<(BlockHeight, ProvisionHash)> for ProvisionKeyCodec {
    fn encode_to(&self, value: &(BlockHeight, ProvisionHash), buf: &mut Vec<u8>) {
        let (height, hash) = value;
        buf.extend_from_slice(&height.inner().to_be_bytes());
        buf.extend_from_slice(Hash::from(*hash).as_bytes());
    }
}

impl DbCodec<(BlockHeight, ProvisionHash)> for ProvisionKeyCodec {
    fn decode(&self, bytes: &[u8]) -> (BlockHeight, ProvisionHash) {
        assert_eq!(bytes.len(), 40, "provision key must be 8 + 32 bytes");
        let (height, hash) = bytes.split_at(8);
        (
            BlockHeight::new(u64::from_be_bytes(
                height.try_into().expect("length checked above"),
            )),
            ProvisionHash::from_raw(Hash::from_hash_bytes(hash)),
        )
    }
}

/// Provision bodies a committed block carried; see [`PROVISIONS_CF`].
pub struct ProvisionsCf;
impl TypedCf for ProvisionsCf {
    const NAME: &'static str = PROVISIONS_CF;
    type Key = (BlockHeight, ProvisionHash);
    type Value = Provisions;
    type KeyCodec = ProvisionKeyCodec;
    type ValueCodec = HborCodec<Provisions>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.provisions
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
    type ValueCodec = HborCodec<Vec<Vec<u8>>>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.stale_state_history
    }
}

/// State — current-value-per-key source of truth.
///
/// Key: the substate key's 32 bytes. Value: opaque substate bytes. An
/// absent row means "no value for this key" — deletions do
/// `batch.delete_cf(state_cf, K)`, not a tombstone sentinel.
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
    type Key = SubstateKey;
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
/// Key: `(substate_key, write_version)` encoded as
/// `substate_key_bytes ++ write_version_BE_8B`. Value:
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
    type Key = (SubstateKey, u64); // (substate key, write_version)
    type Value = Option<Vec<u8>>;
    type KeyCodec = VersionedSubstateKeyCodec;
    type ValueCodec = HborCodec<Option<Vec<u8>>>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.state_history
    }
}

/// Ordered-collection entry index — current-value-per-entry, the
/// order-native mirror of the entry leaves in `StateCf`.
///
/// Key: `owner ++ collection ++ order_BE`. Value: the raw entry value.
/// An absent row means "no entry at this order" — removals delete.
/// Derived state: at every height the index equals the tree's entry
/// leaves, and the snap-sync import re-derives it from them.
pub struct EntriesCf;
impl TypedCf for EntriesCf {
    const NAME: &'static str = ENTRIES_CF;
    type Key = EntryKey;
    type Value = Vec<u8>;
    type KeyCodec = EntryKeyCodec;
    type ValueCodec = RawCodec;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.entries
    }
}

/// Entry-index history log — per-write prior values for historical
/// range reads, mirroring `StateHistoryCf` row for row.
///
/// Key: `(entry_key, write_version)`. Value: the value the entry held
/// immediately before the write; `None` means it was absent.
pub struct EntriesHistoryCf;
impl TypedCf for EntriesHistoryCf {
    const NAME: &'static str = ENTRIES_HISTORY_CF;
    type Key = (EntryKey, u64);
    type Value = Option<Vec<u8>>;
    type KeyCodec = VersionedEntryKeyCodec;
    type ValueCodec = HborCodec<Option<Vec<u8>>>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.entries_history
    }
}

/// Version-indexed list of `entries_history` keys written at each
/// version, for the same incremental GC `StaleStateHistoryCf` gives the
/// cell history.
pub struct StaleEntriesHistoryCf;
impl TypedCf for StaleEntriesHistoryCf {
    const NAME: &'static str = STALE_ENTRIES_HISTORY_CF;
    type Key = u64; // write_version
    type Value = Vec<Vec<u8>>; // raw `entries_history` keys
    type KeyCodec = BeU64Codec;
    type ValueCodec = HborCodec<Vec<Vec<u8>>>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.stale_entries_history
    }
}

// Receipts

pub struct ConsensusReceiptsCf;
impl TypedCf for ConsensusReceiptsCf {
    const NAME: &'static str = CONSENSUS_RECEIPTS_CF;
    type Key = Hash;
    type Value = ConsensusReceipt;
    type KeyCodec = HashCodec;
    type ValueCodec = HborCodec<ConsensusReceipt>;
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
    type ValueCodec = HborCodec<ExecutionMetadata>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.execution_metadata
    }
}

// Execution Certificates

pub struct ExecutionCertsCf;
impl TypedCf for ExecutionCertsCf {
    const NAME: &'static str = EXECUTION_CERTS_CF;
    type Key = TickId;
    type Value = ExecutionCertificate;
    type KeyCodec = HborCodec<TickId>;
    type ValueCodec = HborCodec<ExecutionCertificate>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.execution_certs
    }
}

pub struct TxCertIndexCf;
impl TypedCf for TxCertIndexCf {
    const NAME: &'static str = TX_CERT_INDEX_CF;
    type Key = Hash;
    /// Every tick of this shard's that carried an outcome for the
    /// transaction, not the newest: a shard certifies one transaction
    /// its verdict and then again whatever settles what the verdict left
    /// — a retirement, a reclaim, an abandonment — and a counterpart
    /// fetching by transaction cannot name which of them it wants.
    type Value = BTreeSet<TickId>;
    type KeyCodec = HashCodec;
    type ValueCodec = HborCodec<BTreeSet<TickId>>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.tx_cert_index
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
    type ValueCodec = HborCodec<ShardWitnessPayload>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.beacon_witnesses
    }
}

// Safe-vote registers.

/// Key codec for [`SafeVoteRegistersCf`]: validator id as a big-endian
/// `u64`, so recovery's full scan decodes in stable validator order.
#[derive(Default)]
pub struct ValidatorIdCodec;

impl DbEncode<ValidatorId> for ValidatorIdCodec {
    fn encode_to(&self, value: &ValidatorId, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.inner().to_be_bytes());
    }
}

impl DbCodec<ValidatorId> for ValidatorIdCodec {
    fn decode(&self, bytes: &[u8]) -> ValidatorId {
        let arr: [u8; 8] = bytes.try_into().expect("validator key must be 8 bytes");
        ValidatorId::new(u64::from_be_bytes(arr))
    }
}

/// Value codec for a record bound to a chain incarnation: a 16-byte
/// chain origin followed by the HBOR-encoded value.
///
/// The origin stays a raw prefix so a record's incarnation reads without
/// decoding the rest, which is what lets a store adopted from a parent
/// shard ignore the parent's records rather than act on rounds and blocks
/// belonging to an unrelated chain.
pub struct OriginTaggedCodec<T>(PhantomData<T>);

impl<T> Default for OriginTaggedCodec<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

/// Bytes the [`ChainOrigin`] prefix occupies in an origin-tagged record.
const CHAIN_ORIGIN_BYTES: usize = 16;

impl<T: HborEncode> DbEncode<(ChainOrigin, T)> for OriginTaggedCodec<T> {
    fn encode_to(&self, value: &(ChainOrigin, T), buf: &mut Vec<u8>) {
        ChainOriginCodec.encode_to(&value.0, buf);
        HborCodec::<T>::default().encode_to(&value.1, buf);
    }
}

impl<T: HborEncode + HborDecode> DbCodec<(ChainOrigin, T)> for OriginTaggedCodec<T> {
    fn decode(&self, bytes: &[u8]) -> (ChainOrigin, T) {
        assert!(
            bytes.len() > CHAIN_ORIGIN_BYTES,
            "an origin-tagged record must carry an origin and a value"
        );
        let origin = ChainOriginCodec.decode(&bytes[..CHAIN_ORIGIN_BYTES]);
        let value = HborCodec::<T>::default().decode(&bytes[CHAIN_ORIGIN_BYTES..]);
        (origin, value)
    }
}

/// Durable safe-vote registers per validator; see [`SAFE_VOTE_REGISTERS_CF`].
pub struct SafeVoteRegistersCf;
impl TypedCf for SafeVoteRegistersCf {
    const NAME: &'static str = SAFE_VOTE_REGISTERS_CF;
    type Key = ValidatorId;
    type Value = (ChainOrigin, SafeVoteRegisters);
    type KeyCodec = ValidatorIdCodec;
    type ValueCodec = OriginTaggedCodec<SafeVoteRegisters>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.safe_vote_registers
    }
}

/// Key codec for [`VotedBlocksCf`]: big-endian height then the block
/// hash, so the commit sweep is one range delete and a fork sibling
/// keeps its own key.
#[derive(Default)]
pub struct VotedBlockKeyCodec;

impl DbEncode<(BlockHeight, BlockHash)> for VotedBlockKeyCodec {
    fn encode_to(&self, value: &(BlockHeight, BlockHash), buf: &mut Vec<u8>) {
        let (height, hash) = value;
        buf.extend_from_slice(&height.inner().to_be_bytes());
        buf.extend_from_slice(Hash::from(*hash).as_bytes());
    }
}

impl DbCodec<(BlockHeight, BlockHash)> for VotedBlockKeyCodec {
    fn decode(&self, bytes: &[u8]) -> (BlockHeight, BlockHash) {
        assert_eq!(bytes.len(), 40, "voted-block key must be 8 + 32 bytes");
        let (height, hash) = bytes.split_at(8);
        (
            BlockHeight::new(u64::from_be_bytes(
                height.try_into().expect("length checked above"),
            )),
            BlockHash::from_raw(Hash::from_hash_bytes(hash)),
        )
    }
}

/// Uncommitted blocks justifying the safe-vote registers; see
/// [`VOTED_BLOCKS_CF`].
pub struct VotedBlocksCf;
impl TypedCf for VotedBlocksCf {
    const NAME: &'static str = VOTED_BLOCKS_CF;
    type Key = (BlockHeight, BlockHash);
    type Value = (ChainOrigin, Block);
    type KeyCodec = VotedBlockKeyCodec;
    type ValueCodec = OriginTaggedCodec<Block>;
    type Handles<'a> = CfHandles<'a>;
    fn handle<'a>(cf: &Self::Handles<'a>) -> &'a ColumnFamily {
        cf.voted_blocks
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
