//! Provision absorption and readiness tracking for cross-shard
//! transactions.
//!
//! One absorption per source shard and transaction —
//! [`absorbed`](ProvisioningTracker::absorbed) — holds the part that
//! shard's committing block sent: the environment it stated and its
//! leaves, by key. It is what a cross-shard dispatch carries and
//! the evidence that the shard committed the transaction. Beside it,
//! `required` is what each candidate waits for, as one set of
//! [`Requirement`]s, and `arrived` the crossing records committed
//! claims have read for the candidates that consume them.
//!
//! Whether a member is ready is not asked here: the tick's member lines
//! name it, off committed inputs every replica reads alike, and this
//! tracker holds what the member then runs with.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use hyperscale_engine::legs::Member;
use hyperscale_engine::tick_select::Requirement;
use hyperscale_storage::live_record;
use hyperscale_types::{
    BlockHeight, MAX_FINALIZATION_DELAY, Provision, RETENTION_HORIZON, Role, ShardId, StateClaim,
    SubstateEntry, SubstateKey, TxHash, Verified, WeightedTimestamp,
};
use hyperscale_vm_effects::CrossingCell;

/// A crossing record a consumer here waits on and has no arrival for:
/// what the fallback read asks a producer's chain for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WantedRecord {
    /// The record cell.
    pub key: SubstateKey,
    /// The transaction the record must name as its issuer.
    pub tx: TxHash,
    /// The committed clock past which the read arms on the clock alone:
    /// one finalization delay past the commit that filed the want, for
    /// a requirement filed here, by when the producer's leg has
    /// finalized or never will and a push that was coming has come.
    /// `None` where only the producer's certificate arms it. The
    /// certificate arms either sooner.
    pub arms_at: Option<WeightedTimestamp>,
}

/// The environment a source block's bundle carries for the transactions
/// that block committed: the clock, checked against the commit-proven
/// source header at verification.
///
/// One field, and it stays a record because what a bundle carries about
/// the environment is a set rather than a value — a seed is the
/// beacon's, so it needs no carrying, and what else might is answered
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceAnchor {
    /// The parent-QC weighted timestamp of the source block that commits
    /// the transaction, as the part's leaf binds it.
    pub(crate) clock: WeightedTimestamp,
}

/// What one source shard's committed part carried for a transaction:
/// the part read off the source block that committed it.
#[derive(Debug, Clone)]
pub struct Absorbed {
    /// The height of the source block the part was read off.
    height: BlockHeight,
    /// The environment that block fixes for the transaction.
    anchor: SourceAnchor,
    /// The leaves the part carried, sorted by key.
    entries: Arc<Vec<SubstateEntry>>,
    /// The commit clock at the latest absorption, which bounds an
    /// absorption no candidate here has filed for.
    at: WeightedTimestamp,
}

impl Absorbed {
    fn new(
        at: WeightedTimestamp,
        height: BlockHeight,
        anchor: SourceAnchor,
        entries: &[SubstateEntry],
    ) -> Self {
        let mut entries = entries.to_vec();
        entries.sort_by_key(|entry| entry.key);
        entries.dedup_by_key(|entry| entry.key);
        Self {
            height,
            anchor,
            entries: Arc::new(entries),
            at,
        }
    }

    /// Fold another part from the same shard in.
    ///
    /// A part off the block already held restates it and adds nothing:
    /// one source block reads one transaction once. A part off another
    /// block replaces the entries and the anchor whole. A source commits
    /// a transaction in a second block only once a recovery has let go
    /// of the first, and admission takes the second block's part only
    /// under an anchor that orphans the first, so the part committed
    /// later is the one that stands. Its entries are a reading of the
    /// recovered chain's state, so none of the first block's are kept
    /// beside them, an absent cell included.
    fn absorb(
        &mut self,
        at: WeightedTimestamp,
        height: BlockHeight,
        anchor: SourceAnchor,
        entries: &[SubstateEntry],
    ) {
        if self.height == height && self.anchor == anchor {
            self.at = at;
        } else {
            *self = Self::new(at, height, anchor, entries);
        }
    }
}

/// A crossing a committed claim has handed this shard, read off the
/// record cell the claim carried.
///
/// The one thing a delivery cannot be composed without, so this is
/// exactly the set of crossings this shard could still run a delivery
/// for. An execution input and nothing more: a core member still waits
/// on the producer's certificate, and an arrival never stands in for
/// it.
#[derive(Debug, Clone, Copy)]
pub struct Arrival {
    /// The record cell itself, as the producer committed it.
    ///
    /// Carried whole rather than reduced to the terms each reader wants,
    /// because one of them wants all of it: a refusal is composed from
    /// the cell and carries it into the member that writes the decline,
    /// where the producer's own bytes are what the kernel reads its
    /// terms off. The deadline and the transaction the other readers ask
    /// for are the cell's own — and they are the producer's bytes for
    /// the same reason, proven against its committed state root by the
    /// claim that carried them.
    pub(crate) cell: CrossingCell,
}

impl Arrival {
    /// The transaction the crossing belongs to, so the arrival goes when
    /// its candidate does.
    #[must_use]
    pub(crate) const fn tx(&self) -> TxHash {
        self.cell.tx
    }
}

pub struct ProvisioningTracker {
    /// What each source shard's committed bundles carried for each
    /// transaction. Written when a bundle is absorbed; read when a
    /// candidate is composed, for its dispatch and for the arrivals its
    /// legs consume.
    absorbed: HashMap<TxHash, BTreeMap<ShardId, Absorbed>>,

    /// Every crossing a committed claim has handed this shard, by the
    /// record cell that carried it.
    ///
    /// Folded from the claims committed blocks carry, for the
    /// requirements filed here, and dropped with the candidate that
    /// filed them, so it never outlives what reads it. Kept by cell
    /// rather than by transaction because what asks about it asks one
    /// question per record, of one shard. A restart rebuilds it by
    /// replaying the blocks from the oldest transaction still owed an
    /// outcome, whose claims ride inline through sealing.
    arrived: BTreeMap<SubstateKey, Arrival>,

    /// What each candidate waits for, and the clock it was filed at.
    /// One set per transaction, indexed by nothing else, filed when the
    /// candidate is registered.
    ///
    /// The stamp is the anchor of the block that committed the
    /// transaction here, which a replay re-derives from the block, so a
    /// restarted replica arms its record reads at the instant its
    /// peers did.
    required: BTreeMap<TxHash, (WeightedTimestamp, BTreeSet<Requirement>)>,

    /// The payer shard of each cross-shard transaction whose payer is
    /// remote, recorded beside `required`. Resolves which absorption
    /// carries the transaction's environment without re-deriving
    /// topology at dispatch.
    payer_shards: HashMap<TxHash, ShardId>,

    /// Latest BFT-attested local-commit weighted timestamp seen via
    /// [`advance_clock`](Self::advance_clock). What an absorption is
    /// stamped with, deterministically across validators.
    now: WeightedTimestamp,
}

impl ProvisioningTracker {
    pub(crate) fn new() -> Self {
        Self {
            absorbed: HashMap::new(),
            arrived: BTreeMap::new(),
            required: BTreeMap::new(),
            payer_shards: HashMap::new(),
            now: WeightedTimestamp::ZERO,
        }
    }

    /// Update the shard consensus-attested local-commit clock absorptions
    /// are stamped with. Called once per `on_block_committed`. Monotone —
    /// out-of-order or stale calls are ignored.
    pub(crate) fn advance_clock(&mut self, now: WeightedTimestamp) {
        if now > self.now {
            self.now = now;
        }
    }

    // ─── Required / absorbed ────────────────────────────────────────────

    /// Record what `tx_hash` waits for. Overwrites any previous entry —
    /// callers set this once per candidate. Arrival order does not
    /// matter: a bundle absorbed before its requirement is filed still
    /// answers it.
    pub(crate) fn record_required(&mut self, tx_hash: TxHash, requirements: BTreeSet<Requirement>) {
        self.required.insert(tx_hash, (self.now, requirements));
    }

    /// Record the remote payer shard of a cross-shard transaction, so
    /// dispatch can read the transaction's environment off the payer's
    /// bundle.
    pub(crate) fn record_payer_shard(&mut self, tx_hash: TxHash, payer_shard: ShardId) {
        self.payer_shards.insert(tx_hash, payer_shard);
    }

    /// Whether a bundle from `shard` has been absorbed for `tx_hash`.
    /// For a transaction's payer shard this is the transaction commit
    /// proof held: absorption admits a bundle only against a
    /// commit-proven source header, committed into the local chain.
    #[must_use]
    pub(crate) fn has_received_from(&self, tx_hash: TxHash, shard: ShardId) -> bool {
        self.absorbed
            .get(&tx_hash)
            .is_some_and(|by_shard| by_shard.contains_key(&shard))
    }

    /// The clock `member` of `tx_hash` executes under, where `own` is
    /// the parent-QC weighted timestamp of the block that committed it
    /// here.
    ///
    /// One value for every shard that runs the same nodes, read off
    /// anchors each of them holds before it runs:
    ///
    /// - A whole member runs under its payer's committing clock: its
    ///   own where the payer is local, the remote payer's bundle's
    ///   otherwise.
    /// - A core member runs under the earliest of the core shards'
    ///   committing clocks, its own included. It runs only once every
    ///   other core shard's bundle is in hand, and each bundle carries
    ///   its committing block's clock, bound by its leaf, so every core
    ///   shard takes the minimum over one set.
    /// - A leg runs alone and under its own.
    ///
    /// `None` while a bundle the clock is read off is not absorbed: a
    /// core member's from another core shard, or a whole member's from
    /// its remote payer. A node short of one is short of what the
    /// member's line names it to run on, and its peers run under a clock
    /// it cannot read.
    #[must_use]
    pub(crate) fn transaction_clock(
        &self,
        tx_hash: TxHash,
        member: &Member,
        own: WeightedTimestamp,
    ) -> Option<WeightedTimestamp> {
        let absorbed = self.absorbed.get(&tx_hash);
        let clock_of = |shard: &ShardId| absorbed?.get(shard).map(|part| part.anchor.clock);
        match member.role() {
            Role::Whole => self.payer_shards.get(&tx_hash).map_or(Some(own), clock_of),
            Role::Core => member
                .classified()
                .core()
                .iter()
                .filter(|&&shard| shard != member.local())
                .try_fold(own, |earliest, shard| Some(earliest.min(clock_of(shard)?))),
            Role::Leg | Role::Settling => Some(own),
        }
    }

    /// Whether every requirement for `tx_hash` is met. Returns `false`
    /// for txs with no recorded requirements (single-shard txs or txs we
    /// aren't tracking). A recorded empty set is immediately satisfied —
    /// the member that waits on nothing and dispatches without waiting.
    #[cfg(test)]
    pub(crate) fn is_fully_provisioned(&self, tx_hash: TxHash) -> bool {
        self.required.get(&tx_hash).is_some_and(|(_, required)| {
            required.iter().all(|requirement| match requirement {
                Requirement::CommittedState(shard) => self.has_received_from(tx_hash, *shard),
                Requirement::Crossing { key } => self.arrived.contains_key(key),
            })
        })
    }

    /// Every crossing a candidate here waits on with no arrival for it,
    /// with the transaction the record must name and the clock its read
    /// arms on: one finalization delay past the commit that filed it,
    /// so a pushed reading has its chance to land before any ask.
    ///
    /// The records alone, and not the shard a requirement might name:
    /// who holds a record now is its own prefix, read against the
    /// current trie by whoever asks. A cut moves a prefix, and asking
    /// the shard that used to hold it is asking somebody who cannot
    /// answer.
    pub(crate) fn wanted_records(&self) -> Vec<WantedRecord> {
        let mut wanted = Vec::new();
        for (tx_hash, (filed_at, required)) in &self.required {
            for requirement in required {
                let Requirement::Crossing { key } = requirement else {
                    continue;
                };
                if !self.arrived.contains_key(key) {
                    wanted.push(WantedRecord {
                        key: *key,
                        tx: *tx_hash,
                        arms_at: Some(filed_at.plus(MAX_FINALIZATION_DELAY)),
                    });
                }
            }
        }
        wanted.sort_unstable_by_key(|wanted| (wanted.key, wanted.tx));
        wanted
    }

    /// Fold the crossing records a committed block's claims read, for
    /// the requirements filed here.
    ///
    /// Every claim the block carries is read, whatever question this
    /// replica had open, so a reading pushed to the proposer folds with
    /// no ask ever put. A live record naming the requirement's own
    /// transaction as its issuer is the arrival; a tombstone, a bare
    /// presence and a record of another transaction are not. Read after
    /// the block's transactions are registered, so a reading that rides
    /// in the transaction's own block counts, and only for requirements
    /// already filed, so a reading in a block before the transaction's
    /// commit here is never an arrival and the key is read again.
    pub(crate) fn fold_record_readings(&mut self, state_claims: &[StateClaim]) {
        if state_claims.is_empty() {
            return;
        }
        for (tx_hash, (_, required)) in &self.required {
            for requirement in required {
                let Requirement::Crossing { key } = requirement else {
                    continue;
                };
                if self.arrived.contains_key(key) {
                    continue;
                }
                if let Some((_, cell)) = live_record(state_claims, *key)
                    && cell.tx == *tx_hash
                {
                    self.arrived.insert(*key, Arrival { cell });
                }
            }
        }
    }

    // ─── Batch absorption ───────────────────────────────────────────────

    /// Absorb a committed part: what it carries for its transaction is
    /// folded into the source shard's absorption for it
    /// ([`Absorbed::absorb`]), so a re-broadcast restates what is held
    /// rather than doubling it.
    ///
    /// Returns the `tx_hash` touched — the caller uses it to compute
    /// which local ticks are affected and to drive the dispatch check.
    pub(crate) fn absorb_provisions(&mut self, part: &Verified<Provision>) -> TxHash {
        let tx_hash = part.tx_hash();
        let height = part.block_height();
        let anchor = SourceAnchor {
            clock: part.clock(),
        };
        self.absorbed
            .entry(tx_hash)
            .or_default()
            .entry(part.source_shard())
            .and_modify(|absorbed| absorbed.absorb(self.now, height, anchor, part.entries()))
            .or_insert_with(|| Absorbed::new(self.now, height, anchor, part.entries()));
        tx_hash
    }

    // ─── Retention ──────────────────────────────────────────────────────

    /// Drop what no candidate waits for.
    ///
    /// A requirement is a candidate's and goes with it: once a tick has
    /// taken the member, or nothing will, the entry answers nobody. An
    /// absorption no candidate has filed for lives one horizon past its
    /// last bundle — a bundle can land before its transaction commits
    /// here, and past `RETENTION_HORIZON` the transaction is provably
    /// terminal everywhere, so no candidate can still consume it.
    /// Returns the number of transactions whose absorptions were swept.
    pub(crate) fn sweep(
        &mut self,
        now: WeightedTimestamp,
        waiting: impl Fn(TxHash) -> bool,
    ) -> usize {
        self.required.retain(|tx_hash, _| waiting(*tx_hash));
        self.payer_shards.retain(|tx_hash, _| waiting(*tx_hash));
        let before = self.absorbed.len();
        self.absorbed.retain(|tx_hash, by_shard| {
            waiting(*tx_hash)
                || by_shard
                    .values()
                    .any(|absorbed| absorbed.at.plus(RETENTION_HORIZON) > now)
        });
        self.arrived.retain(|_, arrival| waiting(arrival.tx()));
        before - self.absorbed.len()
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// What was absorbed for `tx_hash` from the shards its candidate
    /// requires, one entry list per source shard in shard order — what a
    /// cross-shard execution request carries.
    ///
    /// Only a required source's list: the requirement was filed off the
    /// committing block, so it names the sources the member's readiness
    /// judged, by exact shard. A predecessor whose block a successor
    /// re-committed the transaction past, or a shard shipping content
    /// the member's scope never reads, would otherwise ride into a tick
    /// baseline every member of the batch reads.
    #[must_use]
    pub(crate) fn provisions_for(&self, tx_hash: TxHash) -> Vec<Arc<Vec<SubstateEntry>>> {
        let (Some(by_shard), Some((_, required))) =
            (self.absorbed.get(&tx_hash), self.required.get(&tx_hash))
        else {
            return Vec::new();
        };
        by_shard
            .iter()
            .filter(|(shard, _)| required.contains(&Requirement::CommittedState(**shard)))
            .map(|(_, absorbed)| Arc::clone(&absorbed.entries))
            .collect()
    }

    /// Hand this shard a crossing, as a committed claim would.
    ///
    /// The fold itself is [`fold_record_readings`](Self::fold_record_readings)'
    /// and tested there; this is for the readers of what it leaves,
    /// which are a question of their own.
    #[cfg(test)]
    pub(crate) fn handed(&mut self, record: SubstateKey, cell: CrossingCell) {
        self.arrived.insert(record, Arrival { cell });
    }

    /// Every crossing a committed claim has handed this shard, by the
    /// record cell that carried it.
    #[must_use]
    pub(crate) const fn arrived(&self) -> &BTreeMap<SubstateKey, Arrival> {
        &self.arrived
    }

    /// Transactions with at least one bundle absorbed.
    pub(crate) fn absorbed_len(&self) -> usize {
        self.absorbed.len()
    }

    /// Transactions with a requirement filed.
    pub(crate) fn required_len(&self) -> usize {
        self.required.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_engine::legs::Classified;
    use hyperscale_engine::tick_select::divided_requirements;
    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{
        BlockHeight, Hash, LeafPath, MAX_PROVISION_WEIGHT, MerkleInclusionProof, ProvisionParts,
        ShardTrie,
    };
    use hyperscale_vm_types::{LegShape, ProtocolHasher};

    use super::*;
    use crate::fixtures;

    fn shard(n: u64) -> ShardId {
        ShardId::leaf(2, n)
    }

    fn make_provisions_at(
        source: ShardId,
        block_height: BlockHeight,
        anchor: SourceAnchor,
        tx_hash: TxHash,
    ) -> Verified<Provision> {
        Verified::<Provision>::new_unchecked_for_test(Provision::dummy_at(
            source,
            ShardId::leaf(2, 0),
            block_height,
            anchor.clock,
            tx_hash,
        ))
    }

    fn make_provisions(
        source: ShardId,
        block_height: BlockHeight,
        tx_hash: TxHash,
    ) -> Verified<Provision> {
        make_provisions_at(source, block_height, anchor(0), tx_hash)
    }

    /// A keyless part from `source` for `tx`, whose transaction the
    /// source committed at `clock_ms` and a block anchored [`SERVE_LAG_MS`]
    /// later roots.
    fn served_late(
        source: ShardId,
        block_height: BlockHeight,
        clock_ms: u64,
        tx_hash: TxHash,
    ) -> Verified<Provision> {
        Verified::<Provision>::new_unchecked_for_test(Provision::new(ProvisionParts {
            source_shard: source,
            target_shard: ShardId::leaf(2, 0),
            block_height,
            source_block_ts: anchor(clock_ms + SERVE_LAG_MS).clock,
            clock: anchor(clock_ms).clock,
            tx_hash,
            entries: Capped::empty(),
            proof: MerkleInclusionProof::new(Vec::new()),
            leaf: LeafPath {
                count: 1,
                index: 0,
                siblings: Capped::empty(),
            },
        }))
    }

    /// How long after its commit a [`served_late`] part's rooting block
    /// is anchored: past every clock the clock tests compare, so a reader
    /// of the rooting clock reads none of them.
    const SERVE_LAG_MS: u64 = 10_000;

    fn bundle_for(
        source: ShardId,
        tx_hash: TxHash,
        entries: Capped<Vec<SubstateEntry>, MAX_PROVISION_WEIGHT>,
    ) -> Verified<Provision> {
        Verified::<Provision>::new_unchecked_for_test(Provision::new(ProvisionParts {
            source_shard: source,
            target_shard: ShardId::leaf(2, 0),
            block_height: BlockHeight::new(5),
            source_block_ts: anchor(0).clock,
            clock: anchor(0).clock,
            tx_hash,
            entries,
            proof: MerkleInclusionProof::dummy(),
            leaf: LeafPath {
                count: 1,
                index: 0,
                siblings: Capped::empty(),
            },
        }))
    }

    fn anchor(clock_ms: u64) -> SourceAnchor {
        SourceAnchor {
            clock: WeightedTimestamp::from_millis(clock_ms),
        }
    }

    /// File `tx` as waiting on the committed state of `shards`.
    fn require(t: &mut ProvisioningTracker, tx: TxHash, shards: &[ShardId]) {
        t.record_required(
            tx,
            shards
                .iter()
                .copied()
                .map(Requirement::CommittedState)
                .collect(),
        );
    }

    /// A list of `key` holding `value`, or absent.
    fn list(entries: &[(SubstateKey, Option<u8>)]) -> Arc<Vec<SubstateEntry>> {
        Arc::new(
            entries
                .iter()
                .map(|(key, value)| {
                    SubstateEntry::new(*key, value.map(|byte| Bytes::from_array([byte])))
                })
                .collect(),
        )
    }

    /// A part from `source` at `height`, anchored at `clock_ms`, carrying
    /// `entries` for `tx`.
    fn part(
        source: ShardId,
        height: u64,
        clock_ms: u64,
        tx: TxHash,
        entries: &[(SubstateKey, Option<u8>)],
    ) -> Verified<Provision> {
        Verified::<Provision>::new_unchecked_for_test(Provision::new(ProvisionParts {
            source_shard: source,
            target_shard: ShardId::leaf(2, 0),
            block_height: BlockHeight::new(height),
            source_block_ts: anchor(clock_ms).clock,
            clock: anchor(clock_ms).clock,
            tx_hash: tx,
            entries: Capped::new(list(entries).to_vec()).expect("a list written out in a test"),
            proof: MerkleInclusionProof::dummy(),
            leaf: LeafPath {
                count: 1,
                index: 0,
                siblings: Capped::empty(),
            },
        }))
    }

    /// A source re-committed past its predecessor's orphaned block: the
    /// target holds both parts, and the dispatch carries the successor's
    /// list alone. Neither a cell the predecessor read nor a value it
    /// held for a cell the successor carries as absent reaches it.
    #[test]
    fn provisions_for_carries_only_the_required_sources() {
        let s = ShardId::leaf(1, 0);
        let s1 = s.children().1;
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let (a, b) = (test_key(1), test_key(2));
        let mut t = ProvisioningTracker::new();
        require(&mut t, tx, &[s1]);
        t.absorb_provisions(&part(s, 7, 20_500, tx, &[(a, Some(1)), (b, Some(2))]));
        t.absorb_provisions(&part(s1, 3, 41_000, tx, &[(a, None)]));

        assert!(t.has_received_from(tx, s), "the orphaned part is held");
        assert_eq!(t.provisions_for(tx), vec![list(&[(a, None)])]);
    }

    /// A shard the candidate does not wait on can ship it content, and
    /// the dispatch leaves that out.
    #[test]
    fn an_unrequired_absorption_stays_out_of_the_dispatch() {
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let (a, b) = (test_key(1), test_key(2));
        let mut t = ProvisioningTracker::new();
        require(&mut t, tx, &[shard(1)]);
        t.absorb_provisions(&part(shard(1), 5, 1_000, tx, &[(a, Some(1))]));
        t.absorb_provisions(&part(shard(2), 5, 1_000, tx, &[(b, Some(2))]));

        assert_eq!(t.provisions_for(tx), vec![list(&[(a, Some(1))])]);
    }

    /// A remote payer is required, so its list rides beside the read
    /// set's and its anchor is the one the member runs under.
    #[test]
    fn a_remote_payer_stays_in_the_dispatch() {
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let (a, b) = (test_key(1), test_key(2));
        let mut t = ProvisioningTracker::new();
        require(&mut t, tx, &[shard(1), shard(2)]);
        t.record_payer_shard(tx, shard(2));
        t.absorb_provisions(&part(shard(1), 5, 7_000, tx, &[(a, Some(1))]));
        t.absorb_provisions(&part(shard(2), 9, 9_500, tx, &[(b, Some(2))]));

        assert_eq!(
            t.provisions_for(tx),
            vec![list(&[(a, Some(1))]), list(&[(b, Some(2))])],
        );
        assert_eq!(whole_clock(&t, tx), Some(anchor(9_500).clock));
    }

    #[test]
    fn fresh_tracker_reports_no_state() {
        let t = ProvisioningTracker::new();
        assert_eq!(t.absorbed_len(), 0);
        assert_eq!(t.required_len(), 0);
        assert!(!t.is_fully_provisioned(TxHash::from(Hash::from_bytes(b"missing"))));
    }

    #[test]
    fn has_received_from_tracks_absorbed_sources() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        assert!(!t.has_received_from(tx, shard(1)));

        // An empty-entry bundle — the payer shard's engagement evidence
        // for a commutative leg — counts exactly like a state-carrying
        // one: absorption is the commitment axis.
        let batch = make_provisions(shard(1), BlockHeight::new(5), tx);
        t.absorb_provisions(&batch);
        assert!(t.has_received_from(tx, shard(1)));
        assert!(!t.has_received_from(tx, shard(2)));
    }

    #[test]
    fn is_fully_provisioned_requires_required_subset_of_received() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        t.record_required(
            tx,
            [shard(1), shard(2)]
                .into_iter()
                .map(Requirement::CommittedState)
                .collect(),
        );

        assert!(!t.is_fully_provisioned(tx));

        // Only shard 1 landed.
        let batch1 = make_provisions(shard(1), BlockHeight::new(5), tx);
        t.absorb_provisions(&batch1);
        assert!(!t.is_fully_provisioned(tx));

        // Shard 2 lands → fully provisioned.
        let batch2 = make_provisions(shard(2), BlockHeight::new(5), tx);
        t.absorb_provisions(&batch2);
        assert!(t.is_fully_provisioned(tx));
    }

    /// A crossing is answered by a live record read off a committed
    /// claim naming its transaction, and by nothing else: a record of
    /// another transaction, a tombstone, a bare presence and a reading
    /// folded before the requirement was filed answer nothing, and once
    /// answered the cell is the arrival every reader runs against.
    #[test]
    fn a_crossing_is_met_by_a_live_reading_naming_its_transaction() {
        use hyperscale_hbor::Bytes;
        use hyperscale_types::{
            Address, AddressClass, Anchor, Inclusion, LocalKey, StateRoot, Stated,
        };
        use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash, Terms};
        use hyperscale_vm_types::ResourceAddr;

        let id = CrossingId {
            producer: Address::new([0xC1; 31], AddressClass::Component),
            consumer: Address::new([0xC2; 31], AddressClass::Component),
            intent: IntentHash(Hash32([0xC3; 32])),
            local: 1,
            output: 0,
        };
        let record = id.record_key(&ProtocolHasher);
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let other_tx = TxHash::from(Hash::from_bytes(b"other"));
        let cell_of = |tx: TxHash, terms: Terms| {
            id.cell(tx, ResourceAddr::new([0xE1; 31]), 500, 9_000, terms)
        };
        let claim_of = |height: u64, stated: Stated| {
            StateClaim::new(
                Anchor {
                    shard: ShardId::ROOT,
                    height: BlockHeight::new(height),
                    state_root: StateRoot::ZERO,
                    ts: WeightedTimestamp::from_millis(height * 1_000),
                },
                [(record, stated)],
                MerkleInclusionProof::dummy(),
            )
        };
        let held = |cell: CrossingCell| Stated::Held(Bytes::new(cell.to_bytes()).unwrap());
        let requirement = Requirement::Crossing { key: record };

        // Folded before the requirement is filed: never an arrival.
        let mut early = ProvisioningTracker::new();
        early.fold_record_readings(&[claim_of(3, held(cell_of(tx, Terms::Owed)))]);
        early.record_required(tx, BTreeSet::from([requirement]));
        assert!(!early.is_fully_provisioned(tx));
        assert_eq!(early.wanted_records().len(), 1, "and the key stays wanted");

        // Another transaction's record and a bare presence answer
        // nothing.
        let mut wrong = ProvisioningTracker::new();
        wrong.record_required(tx, BTreeSet::from([requirement]));
        wrong.fold_record_readings(&[claim_of(3, held(cell_of(other_tx, Terms::Owed)))]);
        assert!(!wrong.is_fully_provisioned(tx));
        wrong.fold_record_readings(&[claim_of(5, Inclusion::Present([7; 32]).into())]);
        assert!(
            !wrong.is_fully_provisioned(tx),
            "a bare presence licenses nothing"
        );

        // The live record naming the transaction is the arrival, in the
        // transaction's own block or a later one, and it is the cell
        // every reader runs against.
        wrong.fold_record_readings(&[claim_of(6, held(cell_of(tx, Terms::Owed)))]);
        assert!(wrong.is_fully_provisioned(tx));
        assert!(wrong.wanted_records().is_empty());
        assert_eq!(wrong.arrived().get(&record).map(Arrival::tx), Some(tx));

        // A committed-state requirement beside it is a different key:
        // the claim does not answer it.
        let mut both = ProvisioningTracker::new();
        both.record_required(
            tx,
            BTreeSet::from([requirement, Requirement::CommittedState(shard(2))]),
        );
        both.fold_record_readings(&[claim_of(6, held(cell_of(tx, Terms::Owed)))]);
        assert!(!both.is_fully_provisioned(tx));
        both.absorb_provisions(&make_provisions(shard(2), BlockHeight::new(5), tx));
        assert!(both.is_fully_provisioned(tx));

        // The want names what arms it: the commit that filed it.
        let mut waiting = ProvisioningTracker::new();
        waiting.advance_clock(WeightedTimestamp::from_millis(7_000));
        waiting.record_required(tx, BTreeSet::from([requirement]));
        assert_eq!(
            waiting.wanted_records(),
            vec![WantedRecord {
                key: record,
                tx,
                arms_at: Some(WeightedTimestamp::from_millis(7_000).plus(MAX_FINALIZATION_DELAY)),
            }]
        );
        let _ = LocalKey([0; 16]);
    }

    /// The record cell the edge `node` leaves on its first output.
    fn record_of(legs: &[LegShape], node: u32) -> SubstateKey {
        use hyperscale_vm_effects::CrossingId;
        use hyperscale_vm_types::ProtocolHasher;

        // The consumer is not in a record's key.
        let producer = &legs[node as usize];
        CrossingId::of_edge(producer, producer.target, 0).record_key(&ProtocolHasher)
    }

    /// A divided member files its scope minus itself, the records of the
    /// remote components it calls, and the crossings its side consumes.
    /// Every fixture target is a component, so each member here waits for
    /// the record of every remote node — a leg reaching only accounts
    /// would file none.
    #[test]
    fn a_divided_member_files_its_scope_minus_itself() {
        let trie = ShardTrie::uniform(2);
        let (low, high) = (ShardId::leaf(2, 0), ShardId::leaf(2, 1));

        // A swap: sign-in, withdraw and deposit on the low shard, the
        // venue on the high one. The core is the venue alone.
        let swap = fixtures::swap();
        let crossings = [record_of(&swap, 1), record_of(&swap, 2)];
        let classified = Classified::freeze(&swap, swap[0].target, &[], &trie);
        assert!(classified.decomposed());

        // The caller runs one member, which waits on the venue's record
        // and no crossing: its withdraw is what the venue waits for, and
        // the venue's output back to it is its commit fold's to credit.
        assert!(classified.commits_at(low));
        assert_eq!(
            divided_requirements(&swap, &classified, low),
            BTreeSet::from([Requirement::CommittedState(high)]),
            "the caller's member waits on the venue's record and no crossing",
        );
        assert!(
            !divided_requirements(&swap, &classified, low)
                .contains(&Requirement::Crossing { key: crossings[1] }),
            "and never on the venue's output",
        );
        let venue = divided_requirements(&swap, &classified, high);
        assert_eq!(
            venue,
            BTreeSet::from([
                Requirement::CommittedState(low),
                Requirement::Crossing { key: crossings[0] },
            ]),
            "a single-shard core waits on its arrival and its caller's records",
        );
    }

    /// Two core nodes on two shards fed by an inbound leg on a third:
    /// each core member files the other's committed state, and both
    /// claim the inbound crossing, since neither runs its producer.
    #[test]
    fn a_multi_shard_core_files_its_peers_and_its_arrival() {
        let trie = ShardTrie::uniform(2);
        let (low, high, third) = (
            ShardId::leaf(2, 0),
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 2),
        );
        let route = fixtures::route();
        let crossings = [record_of(&route, 0), record_of(&route, 1)];
        let classified = Classified::freeze(&route, route[0].target, &[], &trie);
        assert!(classified.decomposed());
        assert_eq!(classified.core(), &BTreeSet::from([high, third]));
        let arrival = Requirement::Crossing { key: crossings[0] };
        assert_eq!(
            divided_requirements(&route, &classified, high),
            BTreeSet::from([
                Requirement::CommittedState(third),
                Requirement::CommittedState(low),
                arrival,
            ]),
        );
        assert_eq!(
            divided_requirements(&route, &classified, third),
            BTreeSet::from([
                Requirement::CommittedState(high),
                Requirement::CommittedState(low),
                arrival,
            ]),
        );
        assert_eq!(
            divided_requirements(&route, &classified, low),
            BTreeSet::from([
                Requirement::CommittedState(high),
                Requirement::CommittedState(third),
            ]),
            "the inbound leg waits on nothing but the records of the venues it calls",
        );
    }

    #[test]
    fn an_empty_requirement_is_immediately_satisfied() {
        // The dependency-free cross-shard leg: requirements recorded as
        // the empty set dispatch without any provision landing.
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from(Hash::from_bytes(b"delta-only"));
        t.record_required(tx, BTreeSet::new());
        assert!(t.is_fully_provisioned(tx));
    }

    #[test]
    fn is_fully_provisioned_false_without_required_entry() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        // Absorbed provisions records `received[tx]` but there's no `required` —
        // the query must not report fully-provisioned just because
        // anything landed.
        let provisions = make_provisions(shard(1), BlockHeight::new(5), tx);
        t.absorb_provisions(&provisions);
        assert!(!t.is_fully_provisioned(tx));
    }

    #[test]
    fn absorb_provisions_returns_the_touched_tx_hash() {
        let mut t = ProvisioningTracker::new();
        let tx_a = TxHash::from(Hash::from_bytes(b"a"));
        let provisions = make_provisions(shard(1), BlockHeight::new(5), tx_a);
        assert_eq!(t.absorb_provisions(&provisions), tx_a);
    }

    #[test]
    fn absorb_provisions_records_the_source_once() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let provisions = make_provisions(shard(1), BlockHeight::new(5), tx);
        require(&mut t, tx, &[shard(1)]);
        t.absorb_provisions(&provisions);

        assert_eq!(t.absorbed_len(), 1);
        assert_eq!(
            t.provisions_for(tx).len(),
            1,
            "one absorption per source shard"
        );
    }

    #[test]
    fn absorb_multiple_batches_for_same_tx_accumulates() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        require(&mut t, tx, &[shard(1), shard(2)]);
        t.absorb_provisions(&make_provisions(shard(1), BlockHeight::new(5), tx));
        t.absorb_provisions(&make_provisions(shard(2), BlockHeight::new(5), tx));

        assert_eq!(
            t.provisions_for(tx).len(),
            2,
            "one absorption per source shard"
        );
        assert!(t.has_received_from(tx, shard(1)));
        assert!(t.has_received_from(tx, shard(2)));
    }

    /// A part off the block already held restates it: the dispatch
    /// carries the part once, and another part off the same block adds
    /// nothing beside it.
    #[test]
    fn a_part_off_the_held_block_restates_it() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let a = test_key(1);
        let b = test_key(2);
        let first = || {
            bundle_for(
                shard(1),
                tx,
                Capped::from_array([SubstateEntry::new(a, Some(Bytes::from_array([1])))]),
            )
        };
        require(&mut t, tx, &[shard(1)]);
        t.absorb_provisions(&first());
        t.absorb_provisions(&first());
        t.absorb_provisions(&bundle_for(
            shard(1),
            tx,
            Capped::from_array([SubstateEntry::new(b, Some(Bytes::from_array([2])))]),
        ));
        assert_eq!(
            t.provisions_for(tx),
            vec![Arc::new(vec![SubstateEntry::new(
                a,
                Some(Bytes::from_array([1]))
            )])],
        );
    }

    /// A part off another block of the same shard replaces what is held
    /// whole: the dispatch carries the later block's entries and the
    /// environment it fixes, and a cell it carries as absent stays
    /// absent whatever the first block read. A block at the held height
    /// under another anchor is another block.
    #[test]
    fn a_part_off_another_block_replaces_entries_and_anchor_whole() {
        let (a, b) = (test_key(1), test_key(2));
        let off = |height: u64, clock_ms: u64, entries: Vec<SubstateEntry>| {
            Verified::<Provision>::new_unchecked_for_test(Provision::new(ProvisionParts {
                source_shard: shard(1),
                target_shard: ShardId::leaf(2, 0),
                block_height: BlockHeight::new(height),
                source_block_ts: anchor(clock_ms).clock,
                clock: anchor(clock_ms).clock,
                tx_hash: TxHash::from(Hash::from_bytes(b"tx")),
                entries: Capped::new(entries).expect("a list written out in a test"),
                proof: MerkleInclusionProof::dummy(),
                leaf: LeafPath {
                    count: 1,
                    index: 0,
                    siblings: Capped::empty(),
                },
            }))
        };
        let first = off(
            7,
            20_500,
            vec![
                SubstateEntry::new(a, Some(Bytes::from_array([1]))),
                SubstateEntry::new(b, Some(Bytes::from_array([2]))),
            ],
        );
        for (height, clock_ms) in [(9, 21_500), (7, 21_500)] {
            let mut t = ProvisioningTracker::new();
            let tx = first.tx_hash();
            require(&mut t, tx, &[shard(1)]);
            t.record_payer_shard(tx, shard(1));
            t.absorb_provisions(&first);
            t.absorb_provisions(&off(height, clock_ms, vec![SubstateEntry::new(a, None)]));
            assert_eq!(
                t.provisions_for(tx),
                vec![Arc::new(vec![SubstateEntry::new(a, None)])],
                "at height {height}",
            );
            assert_eq!(whole_clock(&t, tx), Some(anchor(clock_ms).clock));
        }
    }

    /// The clock a whole member on leaf 0 runs under, committed here at
    /// [`OWN_CLOCK_MS`].
    fn whole_clock(t: &ProvisioningTracker, tx: TxHash) -> Option<WeightedTimestamp> {
        t.transaction_clock(tx, &Member::whole(shard(0)), anchor(OWN_CLOCK_MS).clock)
    }

    /// Where the member under test committed its transaction.
    const OWN_CLOCK_MS: u64 = 8_000;

    #[test]
    fn a_whole_member_runs_under_its_payers_clock() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        t.record_required(
            tx,
            [shard(1), shard(2)]
                .into_iter()
                .map(Requirement::CommittedState)
                .collect(),
        );
        t.record_payer_shard(tx, shard(2));

        // A read-set owner's bundle lands first: its clock is not the
        // payer's, so the member has none until the payer's lands.
        t.absorb_provisions(&make_provisions_at(
            shard(1),
            BlockHeight::new(5),
            anchor(7_000),
            tx,
        ));
        assert_eq!(whole_clock(&t, tx), None);

        // The payer's bundle carries its committing block's clock, which
        // every participant executes the transaction under.
        t.absorb_provisions(&make_provisions_at(
            shard(2),
            BlockHeight::new(9),
            anchor(9_500),
            tx,
        ));
        assert_eq!(whole_clock(&t, tx), Some(anchor(9_500).clock));

        // A payer's part rooted by a later block than the one committing
        // the transaction carries the committing clock, and that is the
        // clock the member runs under, not the rooting block's.
        let mut t = ProvisioningTracker::new();
        t.record_payer_shard(tx, shard(2));
        t.absorb_provisions(&served_late(shard(2), BlockHeight::new(12), 9_500, tx));
        assert_eq!(whole_clock(&t, tx), Some(anchor(9_500).clock));
    }

    /// The member `local` runs of a core over leaf(1, 0) and leaf(2, 2),
    /// fed by an inbound leg on leaf(2, 3).
    fn divided_member(local: ShardId) -> Member {
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::leg;

        let legs = [
            leg(3, LegRole::Inbound, &[]),
            leg(0, LegRole::Core, &[(0, 0)]),
            leg(2, LegRole::Core, &[(1, 0)]),
        ];
        let shards = [
            ShardId::leaf(1, 0),
            ShardId::leaf(2, 2),
            ShardId::leaf(2, 3),
        ];
        let classified =
            Classified::freeze(&legs, legs[0].target, &[], &ShardTrie::from_leaves(shards));
        assert_eq!(
            classified.core(),
            &BTreeSet::from([ShardId::leaf(1, 0), ShardId::leaf(2, 2)])
        );
        Member::of(classified, local, shards.into_iter().collect())
    }

    /// Both core shards run every core node, so both run it under the
    /// earliest of their committing clocks: each takes its own and the
    /// other's bundle, and neither reads the leg's, though the leg pays
    /// and committed first, nor that of a shard outside the core holding
    /// a component the transaction calls, which also committed before
    /// either. The leg runs alone, under its own. Each bundle is rooted
    /// by a block later than the one committing the transaction, and the
    /// clock is the committing block's.
    #[test]
    fn every_core_member_runs_under_the_earliest_core_clock() {
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let (early, late) = (ShardId::leaf(2, 2), ShardId::leaf(1, 0));
        let (leg, holder) = (ShardId::leaf(2, 3), ShardId::leaf(2, 1));
        let tracker_beside = |other: ShardId, other_ms: u64| {
            let mut t = ProvisioningTracker::new();
            t.record_payer_shard(tx, leg);
            for (source, ms) in [(other, other_ms), (leg, 1_000), (holder, 3_000)] {
                t.absorb_provisions(&served_late(source, BlockHeight::new(5), ms, tx));
            }
            t
        };

        let on_late = tracker_beside(early, 7_000);
        let on_early = tracker_beside(late, 9_000);
        let clock = |t: &ProvisioningTracker, local, own_ms| {
            t.transaction_clock(tx, &divided_member(local), anchor(own_ms).clock)
        };
        assert_eq!(clock(&on_late, late, 9_000), Some(anchor(7_000).clock));
        assert_eq!(clock(&on_early, early, 7_000), Some(anchor(7_000).clock));
        assert_eq!(
            tracker_beside(early, 7_000).transaction_clock(
                tx,
                &divided_member(leg),
                anchor(1_000).clock
            ),
            Some(anchor(1_000).clock),
        );
        // Short of the other core shard's bundle, a core member has no
        // clock, whatever else is in hand.
        assert_eq!(clock(&on_late, early, 7_000), None);
    }

    /// A requirement is its candidate's: the sweep drops it the moment
    /// no candidate waits, and keeps it however long one does, past the
    /// horizon a stray absorption gets.
    #[test]
    fn a_requirement_lives_with_its_candidate_and_no_longer() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        t.advance_clock(WeightedTimestamp::from_millis(1_000));
        t.record_required(
            tx,
            std::iter::once(Requirement::CommittedState(shard(1))).collect(),
        );
        t.absorb_provisions(&make_provisions(shard(1), BlockHeight::new(5), tx));
        assert!(t.is_fully_provisioned(tx));

        let long_after = WeightedTimestamp::from_millis(1_000)
            .plus(RETENTION_HORIZON)
            .plus(RETENTION_HORIZON);
        assert_eq!(
            t.sweep(long_after, |_| true),
            0,
            "the horizon is not what bounds it"
        );
        assert!(t.is_fully_provisioned(tx));

        assert_eq!(t.sweep(long_after, |_| false), 1);
        assert!(!t.is_fully_provisioned(tx));
        assert_eq!(t.absorbed_len(), 0);
        assert_eq!(t.required_len(), 0);
        assert_eq!(whole_clock(&t, tx), Some(anchor(OWN_CLOCK_MS).clock));
    }

    #[test]
    fn record_required_overwrites_existing_entry() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        t.record_required(
            tx,
            std::iter::once(Requirement::CommittedState(shard(1))).collect(),
        );
        // Re-record with a different requirement set.
        t.record_required(
            tx,
            [shard(1), shard(2)]
                .into_iter()
                .map(Requirement::CommittedState)
                .collect(),
        );
        assert_eq!(t.required.get(&tx).map_or(0, |(_, r)| r.len()), 2);
    }

    /// An absorption no candidate has filed for lives one horizon past
    /// its last bundle, whichever shard's it was.
    #[test]
    fn a_stray_absorption_is_swept_one_horizon_past_its_last_bundle() {
        let mut t = ProvisioningTracker::new();
        let tx_old = TxHash::from(Hash::from_bytes(b"old"));
        let tx_fresh = TxHash::from(Hash::from_bytes(b"fresh"));

        t.advance_clock(WeightedTimestamp::from_millis(1_000));
        t.absorb_provisions(&make_provisions(shard(1), BlockHeight::new(5), tx_old));
        t.absorb_provisions(&make_provisions(shard(1), BlockHeight::new(5), tx_fresh));
        t.advance_clock(WeightedTimestamp::from_millis(60_000));
        t.absorb_provisions(&make_provisions(shard(2), BlockHeight::new(6), tx_fresh));

        // Past the first bundle's horizon but not the second's.
        let now = WeightedTimestamp::from_millis(1_001).plus(RETENTION_HORIZON);
        assert_eq!(t.sweep(now, |_| false), 1);
        assert!(!t.has_received_from(tx_old, shard(1)));
        assert!(
            t.has_received_from(tx_fresh, shard(1)),
            "the later bundle holds the whole absorption"
        );
        assert!(t.has_received_from(tx_fresh, shard(2)));
    }
}
