//! Provision absorption and readiness tracking for cross-shard
//! transactions.
//!
//! One absorption per source shard and transaction —
//! [`absorbed`](ProvisioningTracker::absorbed) — holds what that shard's
//! committed bundles carried: the environment its earliest bundle stated
//! and every leaf, by key. It is what a cross-shard dispatch carries and
//! the evidence that the shard committed the transaction. Beside it,
//! `required` is what each candidate waits for, as one set of
//! [`Requirement`]s, and `arrived` the crossing records committed
//! claims have read for the candidates that consume them.
//!
//! A tx is fully provisioned when every requirement is met; that predicate
//! is surfaced as [`is_fully_provisioned`](ProvisioningTracker::is_fully_provisioned)
//! so callers never inspect the underlying maps.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use hyperscale_engine::legs::{Classified, Member, Side, live_record};
use hyperscale_types::{
    MAX_FINALIZATION_DELAY, Provisions, RETENTION_HORIZON, ShardId, StateClaim, SubstateEntry,
    SubstateKey, TxHash, Verified, WeightedTimestamp,
};
use hyperscale_vm_effects::{CrossingCell, Kind};
use hyperscale_vm_types::{AddressClass, LegShape, ProtocolHasher};

/// One thing a cross-shard member waits for before it can run.
///
/// The kind is part of the key, because a shard can owe both and an
/// arrival of one must not read as an answer to the other. What a member
/// files is its execution scope minus itself: a member running only its
/// own legs files no [`CommittedState`](Self::CommittedState) at all, a
/// core member files one per other core shard, and any member consuming
/// a value edge its own shard does not produce files the
/// [`Crossing`](Self::Crossing) for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Requirement {
    /// A counterpart's committed state for the transaction, carried by a
    /// bundle from that shard.
    CommittedState(ShardId),
    /// A crossing's record cell, read live by a committed state claim
    /// naming the transaction as its issuer.
    ///
    /// The key alone: the record sits under the producer's prefix, and
    /// admission holds the claim's anchor to the shard that owned that
    /// prefix at the anchor's own clock, so whoever wrote it, a claim
    /// that admits speaks for the one root the record means anything
    /// under. The same claim is what the arrival is read from.
    Crossing {
        /// The record cell.
        key: SubstateKey,
    },
}

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
    /// finalized or never will and a push that was coming has come; or
    /// the body's validity end, for a delivering body the pool holds.
    /// `None` where only the producer's certificate arms it. The
    /// certificate arms either sooner.
    pub arms_at: Option<WeightedTimestamp>,
}

/// What `member`, a divided member of a transaction with these `legs`,
/// files before it can run: its execution scope minus itself, and the
/// crossings the legs it runs consume.
#[must_use]
pub fn requirements_of(member: &Member, legs: &[LegShape]) -> BTreeSet<Requirement> {
    divided_requirements(legs, member.classified(), member.local(), member.side())
}

/// What a divided member of a transaction files: its execution scope
/// minus itself, and the crossings the legs it runs consume.
///
/// A member running only its own legs is in no core set and files no
/// committed state at all; a core member files one per other core shard;
/// and either files a crossing for every value edge landing on it from a
/// node it does not run. Nothing else — the engagement exchange a whole
/// shape files is not here, since a divided member's inbound escrow is
/// its engagement and the crossing bundle it consumes is its
/// counterpart's commitment.
#[must_use]
pub fn divided_requirements(
    legs: &[LegShape],
    classified: &Classified,
    local: ShardId,
    side: Side,
) -> BTreeSet<Requirement> {
    let mut requirements: BTreeSet<Requirement> = BTreeSet::new();
    let core = classified.core();

    if side == Side::Issuing && core.contains(&local) {
        requirements.extend(
            core.iter()
                .filter(|&&shard| shard != local)
                .map(|&shard| Requirement::CommittedState(shard)),
        );
    }
    // Every member admits the whole manifest, and admission resolves a
    // component call against the target's own record — a declared read
    // of its leaf, provisioned by the shard holding it. So a member waits
    // for the commit-time bundle of every remote shard holding a
    // component the transaction calls, which is where the records it
    // cannot read itself arrive. A principal has no record to read, so a
    // transaction reaching only accounts waits on nobody here.
    if let Some(trie) = classified.placement() {
        requirements.extend(
            legs.iter()
                .filter(|leg| leg.target.class() == AddressClass::Component)
                .map(|leg| trie.shard_for_prefix(leg.target))
                .filter(|&shard| shard != local)
                .map(Requirement::CommittedState),
        );
    }
    // A member waits only on the arrivals its own side's legs consume:
    // the issuing side on what feeds its core share, the delivering side
    // on what the core returned. An inbound leg consumes nothing that
    // crosses, so a shard's issuing member on the far side of a core
    // waits on nothing at all — which is what lets the core's arrival
    // exist in the first place.
    requirements.extend(
        classified
            .edges()
            .iter()
            .filter(|edge| {
                edge.to.contains(&local)
                    && (edge.crossing.kind == Kind::Owed) == (side == Side::Delivering)
            })
            .map(|edge| Requirement::Crossing {
                key: edge.crossing.id.record_key(&ProtocolHasher),
            }),
    );
    requirements
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
    /// The source block's parent-QC weighted timestamp.
    pub(crate) clock: WeightedTimestamp,
}

/// What one source shard's committed bundles carried for a transaction.
#[derive(Debug, Clone)]
pub struct Absorbed {
    /// The environment the shard's earliest bundle carried.
    anchor: SourceAnchor,
    /// Every leaf the shard's bundles carried, sorted by key. A shard
    /// sends a transaction bundles off several of its blocks — its
    /// committed state when the transaction commits there, the record
    /// cells its certificate wrote when that commits, and those cells
    /// again off any later block that offers the crossing anew — and
    /// each restates or adds keys, never taking one away.
    entries: Arc<Vec<SubstateEntry>>,
    /// The commit clock at the latest absorption, which bounds an
    /// absorption no candidate here has filed for.
    at: WeightedTimestamp,
}

impl Absorbed {
    fn new(at: WeightedTimestamp, anchor: SourceAnchor, entries: &[SubstateEntry]) -> Self {
        let mut entries = entries.to_vec();
        entries.sort_by_key(|entry| entry.key);
        entries.dedup_by_key(|entry| entry.key);
        Self {
            anchor,
            entries: Arc::new(entries),
            at,
        }
    }

    /// Fold another bundle from the same shard in. A bundle restating
    /// what is held adds nothing.
    ///
    /// The anchor kept is the earliest a bundle from this shard carried,
    /// never the latest. It is the environment the transaction runs
    /// under, which the block that committed it on the source shard
    /// fixes — and that block is the earliest of that shard's that can
    /// name the transaction at all. Taking the latest instead would let
    /// a shard offering a crossing anew restamp the clock its consumer
    /// executes under, so two consumers reached by different bundles
    /// would run one transaction in two environments; and it would make
    /// the answer turn on the order two bundles happened to arrive in,
    /// where the earliest does not.
    ///
    /// The merge is anchor blind — one anchor over the whole held set —
    /// and what makes that sound is that the bundle kinds a shard sends
    /// carry **disjoint keys**, so a key is added by one kind or
    /// restated by a re-broadcast of the same kind, never carried by
    /// both at two anchors with two values. Were they to overlap, the
    /// held set would mix anchors while `anchor` named only one, and a
    /// consumer proving a reading against that anchor would be proving
    /// it against a value taken at another.
    ///
    /// Stated rather than enforced, deliberately: the bundles are a
    /// counterpart's committed content, so refusing a contradiction here
    /// would let one shard halt another.
    fn absorb(&mut self, at: WeightedTimestamp, anchor: SourceAnchor, entries: &[SubstateEntry]) {
        self.at = at;
        self.anchor.clock = self.anchor.clock.min(anchor.clock);
        let restated = entries.iter().all(|entry| {
            self.entries
                .binary_search_by_key(&entry.key, |held| held.key)
                .is_ok_and(|index| self.entries[index].value == entry.value)
        });
        if restated {
            return;
        }
        let mut merged: BTreeMap<SubstateKey, SubstateEntry> = self
            .entries
            .iter()
            .map(|entry| (entry.key, entry.clone()))
            .collect();
        merged.extend(entries.iter().map(|entry| (entry.key, entry.clone())));
        self.entries = Arc::new(merged.into_values().collect());
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
    required: HashMap<TxHash, (WeightedTimestamp, BTreeSet<Requirement>)>,

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
            required: HashMap::new(),
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

    /// The environment carried by the remote payer's bundle: the
    /// payer-shard committing block's parent-QC weighted timestamp.
    /// `None` when the payer is local (the tick block is the anchor) or
    /// the bundle has not been absorbed.
    #[must_use]
    pub(crate) fn payer_anchor(&self, tx_hash: TxHash) -> Option<SourceAnchor> {
        let payer = self.payer_shards.get(&tx_hash)?;
        Some(self.absorbed.get(&tx_hash)?.get(payer)?.anchor)
    }

    /// Whether every requirement for `tx_hash` is met. Returns `false`
    /// for txs with no recorded requirements (single-shard txs or txs we
    /// aren't tracking). A recorded empty set is immediately satisfied —
    /// the member that waits on nothing and dispatches without waiting.
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

    /// Absorb a committed bundle: what it carries for each transaction
    /// is folded into the source shard's absorption for it, so a
    /// re-broadcast restates what is held rather than doubling it.
    ///
    /// Returns the `tx_hash`es touched — the caller uses these to compute
    /// which local ticks are affected and to drive the dispatch check.
    /// Preserves iteration order of `provisions.transactions` (callers sort
    /// batches upstream for determinism).
    pub(crate) fn absorb_provisions(&mut self, provisions: &Verified<Provisions>) -> Vec<TxHash> {
        let mut touched = Vec::with_capacity(provisions.transactions().len());
        let source_shard = provisions.source_shard();
        let anchor = SourceAnchor {
            clock: provisions.source_block_ts(),
        };
        for tx_entry in provisions.transactions() {
            let tx_hash = tx_entry.tx_hash;
            self.absorbed
                .entry(tx_hash)
                .or_default()
                .entry(source_shard)
                .and_modify(|absorbed| absorbed.absorb(self.now, anchor, &tx_entry.entries))
                .or_insert_with(|| Absorbed::new(self.now, anchor, &tx_entry.entries));
            touched.push(tx_hash);
        }
        touched
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

    /// What was absorbed for `tx_hash`, one entry list per source shard
    /// in shard order — what a cross-shard execution request carries.
    #[must_use]
    pub(crate) fn provisions_for(&self, tx_hash: TxHash) -> Vec<Arc<Vec<SubstateEntry>>> {
        self.absorbed
            .get(&tx_hash)
            .map_or_else(Vec::new, |by_shard| {
                by_shard
                    .values()
                    .map(|absorbed| Arc::clone(&absorbed.entries))
                    .collect()
            })
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
    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{
        BlockHeight, Hash, MAX_STATE_ENTRIES_PER_TX, MerkleInclusionProof, ProvisionEntry,
        ShardTrie,
    };

    use super::*;
    use crate::fixtures;

    fn shard(n: u64) -> ShardId {
        ShardId::leaf(2, n)
    }

    fn make_provisions_at(
        source: ShardId,
        block_height: BlockHeight,
        anchor: SourceAnchor,
        tx_hashes: Vec<TxHash>,
    ) -> Verified<Provisions> {
        let transactions: Vec<ProvisionEntry> = tx_hashes
            .into_iter()
            .map(|tx_hash| ProvisionEntry::new(tx_hash, Capped::from_array([])))
            .collect();
        Verified::<Provisions>::new_unchecked_for_test(Provisions::new(
            source,
            ShardId::leaf(2, 0),
            block_height,
            anchor.clock,
            MerkleInclusionProof::dummy(),
            Capped::new(transactions).expect("a list written out in a test"),
        ))
    }

    fn make_provisions(
        source: ShardId,
        block_height: BlockHeight,
        tx_hashes: Vec<TxHash>,
    ) -> Verified<Provisions> {
        make_provisions_at(source, block_height, anchor(0), tx_hashes)
    }

    fn bundle_for(
        source: ShardId,
        tx_hash: TxHash,
        entries: Capped<Vec<SubstateEntry>, MAX_STATE_ENTRIES_PER_TX>,
    ) -> Verified<Provisions> {
        Verified::<Provisions>::new_unchecked_for_test(Provisions::new(
            source,
            ShardId::leaf(2, 0),
            BlockHeight::new(5),
            anchor(0).clock,
            MerkleInclusionProof::dummy(),
            Capped::from_array([ProvisionEntry::new(tx_hash, entries)]),
        ))
    }

    fn anchor(clock_ms: u64) -> SourceAnchor {
        SourceAnchor {
            clock: WeightedTimestamp::from_millis(clock_ms),
        }
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
        let batch = make_provisions(shard(1), BlockHeight::new(5), vec![tx]);
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
        let batch1 = make_provisions(shard(1), BlockHeight::new(5), vec![tx]);
        t.absorb_provisions(&batch1);
        assert!(!t.is_fully_provisioned(tx));

        // Shard 2 lands → fully provisioned.
        let batch2 = make_provisions(shard(2), BlockHeight::new(5), vec![tx]);
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

        // Another transaction's record, a tombstone and a bare presence
        // answer nothing.
        let mut wrong = ProvisioningTracker::new();
        wrong.record_required(tx, BTreeSet::from([requirement]));
        wrong.fold_record_readings(&[claim_of(3, held(cell_of(other_tx, Terms::Owed)))]);
        assert!(!wrong.is_fully_provisioned(tx));
        wrong.fold_record_readings(&[claim_of(4, held(cell_of(tx, Terms::Retired)))]);
        assert!(
            !wrong.is_fully_provisioned(tx),
            "a tombstone is not an arrival"
        );
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
        both.absorb_provisions(&make_provisions(shard(2), BlockHeight::new(5), vec![tx]));
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

        // The caller's issuing member waits on the venue's record and no
        // crossing: its withdraw is what the venue waits for. Its
        // delivering member waits on the venue's output as well.
        assert!(classified.mixed_at(low));
        let issuing = divided_requirements(&swap, &classified, low, Side::Issuing);
        assert_eq!(
            issuing,
            BTreeSet::from([Requirement::CommittedState(high)]),
            "the caller's issuing member waits on the venue's record and no crossing",
        );
        let delivering = divided_requirements(&swap, &classified, low, Side::Delivering);
        assert_eq!(
            delivering,
            BTreeSet::from([
                Requirement::CommittedState(high),
                Requirement::Crossing { key: crossings[1] },
            ]),
            "the caller's delivering member waits on the venue's output",
        );
        let venue = divided_requirements(&swap, &classified, high, Side::Issuing);
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
            divided_requirements(&route, &classified, high, Side::Issuing),
            BTreeSet::from([
                Requirement::CommittedState(third),
                Requirement::CommittedState(low),
                arrival,
            ]),
        );
        assert_eq!(
            divided_requirements(&route, &classified, third, Side::Issuing),
            BTreeSet::from([
                Requirement::CommittedState(high),
                Requirement::CommittedState(low),
                arrival,
            ]),
        );
        assert_eq!(
            divided_requirements(&route, &classified, low, Side::Issuing),
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
        let provisions = make_provisions(shard(1), BlockHeight::new(5), vec![tx]);
        t.absorb_provisions(&provisions);
        assert!(!t.is_fully_provisioned(tx));
    }

    #[test]
    fn absorb_provisions_returns_touched_tx_hashes_in_order() {
        let mut t = ProvisioningTracker::new();
        let tx_a = TxHash::from(Hash::from_bytes(b"a"));
        let tx_b = TxHash::from(Hash::from_bytes(b"b"));
        let provisions = make_provisions(shard(1), BlockHeight::new(5), vec![tx_a, tx_b]);
        let touched = t.absorb_provisions(&provisions);
        assert_eq!(touched, vec![tx_a, tx_b]);
    }

    #[test]
    fn absorb_provisions_records_the_source_once() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let provisions = make_provisions(shard(1), BlockHeight::new(5), vec![tx]);
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
        t.absorb_provisions(&make_provisions(shard(1), BlockHeight::new(5), vec![tx]));
        t.absorb_provisions(&make_provisions(shard(2), BlockHeight::new(5), vec![tx]));

        assert_eq!(
            t.provisions_for(tx).len(),
            2,
            "one absorption per source shard"
        );
        assert!(t.has_received_from(tx, shard(1)));
        assert!(t.has_received_from(tx, shard(2)));
    }

    /// A re-broadcast restates what is held: the dispatch carries the
    /// bundle once, and a second bundle from the same shard adds its
    /// cells beside the first's rather than beneath a second copy.
    #[test]
    fn a_shards_later_bundle_restates_or_adds_and_never_doubles() {
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
        t.absorb_provisions(&first());
        t.absorb_provisions(&first());
        assert_eq!(
            t.provisions_for(tx).len(),
            1,
            "a re-broadcast is absorbed once"
        );
        let value_of = |t: &ProvisioningTracker, key: SubstateKey| {
            t.provisions_for(tx)[0]
                .iter()
                .find(|entry| entry.key == key)
                .and_then(|entry| entry.value.as_ref().map(|v| v.to_vec()))
        };
        assert_eq!(value_of(&t, a), Some(vec![1]));

        t.absorb_provisions(&bundle_for(
            shard(1),
            tx,
            Capped::from_array([SubstateEntry::new(b, Some(Bytes::from_array([2])))]),
        ));
        let carried = t.provisions_for(tx);
        assert_eq!(carried.len(), 1, "still one absorption for the shard");
        assert_eq!(carried[0].len(), 2, "holding both bundles' cells");
        assert_eq!(value_of(&t, a), Some(vec![1]));
        assert_eq!(value_of(&t, b), Some(vec![2]));
    }

    #[test]
    fn payer_anchor_reads_the_payer_bundles_clock_and_draw() {
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

        // A read-set owner's bundle lands first: no payer anchor yet.
        t.absorb_provisions(&make_provisions_at(
            shard(1),
            BlockHeight::new(5),
            anchor(7_000),
            vec![tx],
        ));
        assert_eq!(t.payer_anchor(tx), None);

        // The payer's bundle carries the committing block's clock and
        // reveal chain — the environment every participant executes the
        // transaction under.
        t.absorb_provisions(&make_provisions_at(
            shard(2),
            BlockHeight::new(9),
            anchor(9_500),
            vec![tx],
        ));
        assert_eq!(t.payer_anchor(tx), Some(anchor(9_500)));
    }

    /// A requirement is its candidate's: the sweep drops it the moment
    /// no candidate waits, and keeps it however long one does — a
    /// delivery is admissible to the delivery window's close, a whole
    /// validity range past the horizon a stray absorption gets.
    #[test]
    fn a_requirement_lives_with_its_candidate_and_no_longer() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        t.advance_clock(WeightedTimestamp::from_millis(1_000));
        t.record_required(
            tx,
            std::iter::once(Requirement::CommittedState(shard(1))).collect(),
        );
        t.absorb_provisions(&make_provisions(shard(1), BlockHeight::new(5), vec![tx]));
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
        assert_eq!(t.payer_anchor(tx), None);
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
        t.absorb_provisions(&make_provisions(
            shard(1),
            BlockHeight::new(5),
            vec![tx_old, tx_fresh],
        ));
        t.advance_clock(WeightedTimestamp::from_millis(60_000));
        t.absorb_provisions(&make_provisions(
            shard(2),
            BlockHeight::new(6),
            vec![tx_fresh],
        ));

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
