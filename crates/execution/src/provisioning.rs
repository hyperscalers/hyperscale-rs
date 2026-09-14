//! Provision absorption and readiness tracking for cross-shard
//! transactions.
//!
//! One absorption per source shard and transaction —
//! [`absorbed`](ProvisioningTracker::absorbed) — holds what that shard's
//! committed bundles carried: the environment its latest bundle stated
//! and every leaf, by key. It is what a cross-shard dispatch carries,
//! where a crossing's record cell is read from, and the evidence that
//! the shard committed the transaction. Beside it, `required` is what
//! each candidate waits for, as one set of [`Requirement`]s.
//!
//! A tx is fully provisioned when every requirement is met; that predicate
//! is surfaced as [`is_fully_provisioned`](ProvisioningTracker::is_fully_provisioned)
//! so callers never inspect the underlying maps.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use hyperscale_engine::legs::{Classified, Member, Side};
use hyperscale_types::{
    Provisions, RETENTION_HORIZON, ShardId, SubstateEntry, SubstateKey, TxHash, Verified,
    WeightedTimestamp,
};
use hyperscale_vm_types::{AddressClass, LegShape};

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
    /// A crossing's record cell, present in a committed bundle from the
    /// shard that wrote it.
    ///
    /// Satisfied only by a present value at `key` carried by a bundle
    /// from `source`: the record sits under the producer's prefix, so
    /// the producer's root is the one root a proof of it means anything
    /// under, and a bundle from any other shard carrying the key is a
    /// quorum there planting a cell it does not own. The same bundle is
    /// what the arrival is read from.
    Crossing {
        /// The shard that writes the record.
        source: ShardId,
        /// The record cell.
        key: SubstateKey,
    },
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
            .filter(|edge| edge.to.contains(&local) && edge.delivers == (side == Side::Delivering))
            .map(|edge| Requirement::Crossing {
                source: edge.from,
                key: edge.record.key(),
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
    pub clock: WeightedTimestamp,
}

/// What one source shard's committed bundles carried for a transaction.
#[derive(Debug, Clone)]
pub struct Absorbed {
    /// The environment the shard's latest bundle carried.
    anchor: SourceAnchor,
    /// Every leaf the shard's bundles carried, sorted by key. A shard
    /// sends a transaction two bundles at most — its committed state
    /// when the transaction commits there, and the record cells its
    /// certificate wrote when that commits — and a re-broadcast restates
    /// one of them, so a later bundle restates or adds keys and never
    /// takes one away.
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

    /// Fold a later bundle from the same shard in. A bundle restating
    /// what is held changes nothing but the clock.
    ///
    /// The merge is anchor blind — one anchor is stamped over the whole
    /// held set — and what makes that sound is that the two bundle kinds
    /// a shard sends carry **disjoint keys**: its committed state for
    /// the transaction, and the record cells its certificate wrote. A
    /// key is therefore added by one kind or restated by a re-broadcast
    /// of the same kind, never carried by both at two anchors with two
    /// values. Were they to overlap, [`Self::present`] would answer from
    /// a set mixed across anchors while `anchor` named only the latest,
    /// and a consumer proving a reading against that anchor would be
    /// proving it against a value taken at another.
    ///
    /// Stated rather than enforced, deliberately: the bundles are a
    /// counterpart's committed content, so refusing a contradiction here
    /// would let one shard halt another.
    fn absorb(&mut self, at: WeightedTimestamp, anchor: SourceAnchor, entries: &[SubstateEntry]) {
        self.at = at;
        self.anchor = anchor;
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

    fn present(&self, key: SubstateKey) -> Option<&[u8]> {
        let index = self
            .entries
            .binary_search_by_key(&key, |held| held.key)
            .ok()?;
        self.entries[index].value.as_deref()
    }
}

pub struct ProvisioningTracker {
    /// What each source shard's committed bundles carried for each
    /// transaction. Written when a bundle is absorbed; read when a
    /// candidate is composed, for its dispatch and for the arrivals its
    /// legs consume.
    absorbed: HashMap<TxHash, BTreeMap<ShardId, Absorbed>>,

    /// What each candidate waits for. One set per transaction, indexed
    /// by nothing else, filed when the candidate is registered.
    required: HashMap<TxHash, BTreeSet<Requirement>>,

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
    pub fn new() -> Self {
        Self {
            absorbed: HashMap::new(),
            required: HashMap::new(),
            payer_shards: HashMap::new(),
            now: WeightedTimestamp::ZERO,
        }
    }

    /// Update the shard consensus-attested local-commit clock absorptions
    /// are stamped with. Called once per `on_block_committed`. Monotone —
    /// out-of-order or stale calls are ignored.
    pub fn advance_clock(&mut self, now: WeightedTimestamp) {
        if now > self.now {
            self.now = now;
        }
    }

    // ─── Required / absorbed ────────────────────────────────────────────

    /// Record what `tx_hash` waits for. Overwrites any previous entry —
    /// callers set this once per candidate. Arrival order does not
    /// matter: a bundle absorbed before its requirement is filed still
    /// answers it.
    pub fn record_required(&mut self, tx_hash: TxHash, requirements: BTreeSet<Requirement>) {
        self.required.insert(tx_hash, requirements);
    }

    /// Record the remote payer shard of a cross-shard transaction, so
    /// dispatch can read the transaction's environment off the payer's
    /// bundle.
    pub fn record_payer_shard(&mut self, tx_hash: TxHash, payer_shard: ShardId) {
        self.payer_shards.insert(tx_hash, payer_shard);
    }

    /// Whether a bundle from `shard` has been absorbed for `tx_hash`.
    /// For a transaction's payer shard this is the transaction commit
    /// proof held: absorption admits a bundle only against a
    /// commit-proven source header, committed into the local chain.
    #[must_use]
    pub fn has_received_from(&self, tx_hash: TxHash, shard: ShardId) -> bool {
        self.absorbed
            .get(&tx_hash)
            .is_some_and(|by_shard| by_shard.contains_key(&shard))
    }

    /// The environment carried by the remote payer's bundle: the
    /// payer-shard committing block's parent-QC weighted timestamp.
    /// `None` when the payer is local (the tick block is the anchor) or
    /// the bundle has not been absorbed.
    #[must_use]
    pub fn payer_anchor(&self, tx_hash: TxHash) -> Option<SourceAnchor> {
        let payer = self.payer_shards.get(&tx_hash)?;
        Some(self.absorbed.get(&tx_hash)?.get(payer)?.anchor)
    }

    /// Whether every requirement for `tx_hash` is met. Returns `false`
    /// for txs with no recorded requirements (single-shard txs or txs we
    /// aren't tracking). A recorded empty set is immediately satisfied —
    /// the member that waits on nothing and dispatches without waiting.
    pub fn is_fully_provisioned(&self, tx_hash: TxHash) -> bool {
        self.required.get(&tx_hash).is_some_and(|required| {
            required.iter().all(|requirement| match requirement {
                Requirement::CommittedState(shard) => self.has_received_from(tx_hash, *shard),
                Requirement::Crossing { source, key } => {
                    self.present_cell(tx_hash, *source, *key).is_some()
                }
            })
        })
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
    pub fn absorb_provisions(&mut self, provisions: &Verified<Provisions>) -> Vec<TxHash> {
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
    pub fn sweep(&mut self, now: WeightedTimestamp, waiting: impl Fn(TxHash) -> bool) -> usize {
        self.required.retain(|tx_hash, _| waiting(*tx_hash));
        self.payer_shards.retain(|tx_hash, _| waiting(*tx_hash));
        let before = self.absorbed.len();
        self.absorbed.retain(|tx_hash, by_shard| {
            waiting(*tx_hash)
                || by_shard
                    .values()
                    .any(|absorbed| absorbed.at.plus(RETENTION_HORIZON) > now)
        });
        before - self.absorbed.len()
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// What was absorbed for `tx_hash`, one entry list per source shard
    /// in shard order — what a cross-shard execution request carries.
    #[must_use]
    pub fn provisions_for(&self, tx_hash: TxHash) -> Vec<Arc<Vec<SubstateEntry>>> {
        self.absorbed
            .get(&tx_hash)
            .map_or_else(Vec::new, |by_shard| {
                by_shard
                    .values()
                    .map(|absorbed| Arc::clone(&absorbed.entries))
                    .collect()
            })
    }

    /// The bytes of `key` as a committed bundle from `source` carried
    /// them present for `tx_hash` — a crossing's record, read from the
    /// one bundle whose root says anything about it.
    #[must_use]
    pub fn present_cell(
        &self,
        tx_hash: TxHash,
        source: ShardId,
        key: SubstateKey,
    ) -> Option<&[u8]> {
        self.absorbed.get(&tx_hash)?.get(&source)?.present(key)
    }

    /// Transactions with at least one bundle absorbed.
    pub fn absorbed_len(&self) -> usize {
        self.absorbed.len()
    }

    /// Transactions with a requirement filed.
    pub fn required_len(&self) -> usize {
        self.required.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{BlockHeight, Hash, MerkleInclusionProof, ProvisionEntry, ShardTrie};

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
            .map(|tx_hash| ProvisionEntry::new(tx_hash, vec![]))
            .collect();
        Verified::<Provisions>::new_unchecked_for_test(Provisions::new(
            source,
            ShardId::leaf(2, 0),
            block_height,
            anchor.clock,
            MerkleInclusionProof::dummy(),
            transactions,
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
        entries: Vec<SubstateEntry>,
    ) -> Verified<Provisions> {
        Verified::<Provisions>::new_unchecked_for_test(Provisions::new(
            source,
            ShardId::leaf(2, 0),
            BlockHeight::new(5),
            anchor(0).clock,
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(tx_hash, entries)],
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

    /// A crossing is answered by a present value at its cell carried by
    /// the named source and nothing else — a bundle from another shard
    /// carrying the key, an absent value, or the source carrying other
    /// cells, answers nothing — and a bundle absorbed before the
    /// requirement was filed still answers it, with the bytes it carried.
    #[test]
    fn a_crossing_is_met_only_by_the_cell_its_source_carried() {
        use hyperscale_types::{Address, AddressClass, LocalKey};

        let record = SubstateKey {
            owner: Address::new([0xC1; 31], AddressClass::Component),
            local: LocalKey([1; 16]),
        };
        let other = SubstateKey {
            owner: Address::new([0xC1; 31], AddressClass::Component),
            local: LocalKey([2; 16]),
        };
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let bundle = |source: ShardId, entries: Vec<SubstateEntry>| {
            Verified::<Provisions>::new_unchecked_for_test(Provisions::new(
                source,
                ShardId::leaf(2, 0),
                BlockHeight::new(5),
                anchor(0).clock,
                MerkleInclusionProof::dummy(),
                vec![ProvisionEntry::new(tx, entries)],
            ))
        };
        let requirement = Requirement::Crossing {
            source: shard(1),
            key: record,
        };

        // A stranger carrying the key answers nothing, and its bytes are
        // never the arrival.
        let mut planted = ProvisioningTracker::new();
        planted.record_required(tx, BTreeSet::from([requirement]));
        planted.absorb_provisions(&bundle(
            shard(3),
            vec![SubstateEntry::new(record, Some(vec![9]))],
        ));
        assert!(
            !planted.is_fully_provisioned(tx),
            "only the producer's bundle carries the record"
        );
        assert_eq!(planted.present_cell(tx, shard(1), record), None);

        // Absorbed first, filed second.
        let mut early = ProvisioningTracker::new();
        early.absorb_provisions(&bundle(
            shard(1),
            vec![SubstateEntry::new(record, Some(vec![7]))],
        ));
        early.record_required(tx, BTreeSet::from([requirement]));
        assert!(early.is_fully_provisioned(tx));
        assert_eq!(
            early.present_cell(tx, shard(1), record),
            Some(&[7u8][..]),
            "and the arrival is read off the same bundle"
        );

        // The named source, carrying the wrong cell or an absent value.
        let mut wrong = ProvisioningTracker::new();
        wrong.record_required(tx, BTreeSet::from([requirement]));
        wrong.absorb_provisions(&bundle(
            shard(1),
            vec![SubstateEntry::new(other, Some(vec![7]))],
        ));
        assert!(!wrong.is_fully_provisioned(tx));
        wrong.absorb_provisions(&bundle(shard(1), vec![SubstateEntry::new(record, None)]));
        assert!(!wrong.is_fully_provisioned(tx), "absent answers nothing");
        wrong.absorb_provisions(&bundle(
            shard(1),
            vec![SubstateEntry::new(record, Some(vec![7]))],
        ));
        assert!(wrong.is_fully_provisioned(tx));

        // A committed-state requirement beside it is a different key: the
        // crossing's bundle does not answer it.
        let mut both = ProvisioningTracker::new();
        both.record_required(
            tx,
            BTreeSet::from([requirement, Requirement::CommittedState(shard(2))]),
        );
        both.absorb_provisions(&bundle(
            shard(1),
            vec![SubstateEntry::new(record, Some(vec![7]))],
        ));
        assert!(!both.is_fully_provisioned(tx));
        both.absorb_provisions(&bundle(shard(2), Vec::new()));
        assert!(both.is_fully_provisioned(tx));
    }

    /// The record cell the edge `node` leaves on its first output.
    fn record_of(legs: &[LegShape], node: u32) -> SubstateKey {
        use hyperscale_vm_effects::CrossingSite;
        use hyperscale_vm_types::ProtocolHasher;

        CrossingSite::record_of(&ProtocolHasher, &legs[node as usize], 0).key()
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
        let classified = Classified::freeze(&swap, &[], &trie);
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
                Requirement::Crossing {
                    source: high,
                    key: crossings[1],
                },
            ]),
            "the caller's delivering member waits on the venue's output",
        );
        let venue = divided_requirements(&swap, &classified, high, Side::Issuing);
        assert_eq!(
            venue,
            BTreeSet::from([
                Requirement::CommittedState(low),
                Requirement::Crossing {
                    source: low,
                    key: crossings[0],
                },
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
        let classified = Classified::freeze(&route, &[], &trie);
        assert!(classified.decomposed());
        assert_eq!(classified.core(), &BTreeSet::from([high, third]));
        let arrival = Requirement::Crossing {
            source: low,
            key: crossings[0],
        };
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
        let first = || bundle_for(shard(1), tx, vec![SubstateEntry::new(a, Some(vec![1]))]);
        t.absorb_provisions(&first());
        t.absorb_provisions(&first());
        assert_eq!(
            t.provisions_for(tx).len(),
            1,
            "a re-broadcast is absorbed once"
        );
        assert_eq!(t.present_cell(tx, shard(1), a), Some(&[1][..]));

        t.absorb_provisions(&bundle_for(
            shard(1),
            tx,
            vec![SubstateEntry::new(b, Some(vec![2]))],
        ));
        let carried = t.provisions_for(tx);
        assert_eq!(carried.len(), 1, "still one absorption for the shard");
        assert_eq!(carried[0].len(), 2, "holding both bundles' cells");
        assert_eq!(t.present_cell(tx, shard(1), a), Some(&[1][..]));
        assert_eq!(t.present_cell(tx, shard(1), b), Some(&[2][..]));
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
        assert_eq!(t.required.get(&tx).map_or(0, BTreeSet::len), 2);
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
