//! Deduplication index for committed artifacts referenced by block contents.
//!
//! The shard consensus layer enforces a single contract: every committed
//! artifact appears in the chain exactly once. For a finalization, a
//! verdict and a provision batch this index is the mechanism — proposers
//! consult it to filter candidates, validators consult it to reject
//! duplicate inclusions. A transaction is the exception: its committed
//! marker sits in the chain's own state, and the verifier reads it there.
//!
//! Per-artifact deadline maps bound the index by artifact-specific
//! BFT-attested horizons:
//!
//! - **certs**: `vote_anchor_ts + RETENTION_HORIZON` from the tick's local
//!   EC.
//! - **provisions**: the committing block's own anchor plus
//!   `RETENTION_HORIZON`, a conservative surrogate for the source block's
//!   (the source committed before this block carried its batch).
//! - **engagements**: the committing block's own anchor plus
//!   `RETENTION_HORIZON`, folded from the engagement list every block
//!   commits — derived from a live block's bodies, kept by a sealed one —
//!   so the live commit, a synced commit and a restart's seed fold the
//!   same entries under the same clock.
//! - **arrivals**: the committing block's own anchor plus
//!   `RETENTION_HORIZON`, one per record a committed claim read live,
//!   kept at the height of the block that carried the claim, since an
//!   arrival counts for a transaction only from its own block on.
//!
//! One clock: every lookup is judged at the anchor of the block being
//! admitted, an entry answering while its deadline is past that anchor,
//! and every tier prunes at the committed tip's own anchor. The per-vote
//! timestamp floor keeps every block a voter judges anchored at or above
//! the tip's, so a prune never changes an answer, and two voters at
//! different tips answer alike. Past expiry, independent rules reject
//! re-inclusion, so the entry is no longer correctness-bearing.
//!
//! Registration is synchronous with shard commit (called from
//! [`crate::coordinator::ShardCoordinator::record_block_committed`]) so the
//! just-committed block's contents are visible to any subsequent
//! `try_propose` in the same tick — closing the on-qc-formed re-inclusion
//! race without a separate bridge buffer.

#[cfg(test)]
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_storage::{CommittedProvisions, DedupWindow};
use hyperscale_types::{
    BlockHeight, DEDUP_WINDOW, Engagement, Finalization, FinalizationHash, ProvisionHash,
    RETENTION_HORIZON, ShardId, SubstateKey, TopologySnapshot, TxHash, Verifiable,
    WeightedTimestamp,
};

#[allow(clippy::struct_field_names)] // shared `_retention` postfix is the artifact-tier convention
pub struct CommitDedupIndex {
    /// `tx_hash → vote_anchor_ts + RETENTION_HORIZON` of the finalization
    /// that resolved it. Every transaction a committed finalization
    /// reached a verdict for, under whichever verdict — which is what
    /// makes settlement and abandonment exclusive rather than two rules
    /// that have to agree, and what a tick key could never express, since
    /// a tick can settle in more than one part.
    resolved_tx_retention: HashMap<TxHash, WeightedTimestamp>,
    /// `receipt_hash → deadline` of every finalization a committed block
    /// carried. The question `resolved_tx_retention` cannot answer for a
    /// certificate that resolves nothing.
    finalization_retention: HashMap<FinalizationHash, WeightedTimestamp>,
    /// The committed-provision window, shared with the provisions
    /// coordinator rather than mirrored by it: the shard asks at
    /// admission and provisions asks at the receipt seam, and two copies
    /// of one window are two things that have to agree. Chain-lifetime,
    /// so a restart seeds it from the store instead of re-verifying every
    /// already-committed batch that re-arrives.
    provision_retention: Arc<CommittedProvisions>,
    /// `(source, tx_hash) → [(source_height, deadline)]`: every committed
    /// engagement of a transaction by a batch from `source`, one element
    /// per source height, each at its committing block's anchor plus
    /// [`RETENTION_HORIZON`].
    ///
    /// Heights stay apart rather than merging into one deadline, because
    /// a recovery can fence one source height and not another: an
    /// expired unfenced entry and a live fenced one must not combine into
    /// an engagement neither gives alone.
    engagements: HashMap<(ShardId, TxHash), Vec<(BlockHeight, WeightedTimestamp)>>,
    /// `(record, issuer) → [(height, deadline)]`: every committed claim
    /// that read `record` live naming `issuer`, one element per local
    /// block height that carried one, each at that block's anchor plus
    /// [`RETENTION_HORIZON`].
    arrivals: HashMap<(SubstateKey, TxHash), Vec<(BlockHeight, WeightedTimestamp)>>,
    /// The oldest block anchor this index has folded, or `None` before it
    /// has folded any.
    ///
    /// The maps cannot express what this does: "nothing was committed"
    /// and "what was committed is unknown" are both an empty map, and
    /// they call for opposite treatment. Depth is what separates them.
    covered_from: Option<WeightedTimestamp>,
    /// Whether the coverage bottoms out at the chain's own origin, below
    /// which there is nothing to have missed.
    reached_origin: bool,
}

impl CommitDedupIndex {
    /// An index covering nothing and knowing it.
    ///
    /// Only for a coordinator that has no chain to fold — a genuinely new
    /// chain. Anything resuming one seeds from [`Self::seeded`] instead,
    /// because an unseeded index refuses no duplicate at all.
    pub(crate) fn new() -> Self {
        Self {
            resolved_tx_retention: HashMap::new(),
            finalization_retention: HashMap::new(),
            provision_retention: Arc::new(CommittedProvisions::new()),
            engagements: HashMap::new(),
            arrivals: HashMap::new(),
            covered_from: None,
            reached_origin: false,
        }
    }

    /// An index rebuilt from a window folded off committed blocks.
    ///
    /// The resolution, finalization and engagement tiers reproduce what
    /// the live path registered, because no deadline among them depends
    /// on when the fold ran.
    #[must_use]
    pub(crate) fn seeded(window: &DedupWindow, now: WeightedTimestamp) -> Self {
        let mut index = Self::new();
        index
            .resolved_tx_retention
            .extend(window.resolved.iter().copied());
        index
            .finalization_retention
            .extend(window.finalizations.iter().copied());
        index
            .provision_retention
            .seed(window.provisions.iter().copied());
        for (engagement, deadline) in &window.engagements {
            index.engage(*engagement, *deadline);
        }
        for (arrival, height, deadline) in &window.arrivals {
            index.arrive(*arrival, *height, *deadline);
        }
        index.covered_from = window.covered_from;
        index.reached_origin = window.reached_origin;
        // Pruned at the clock the chain resumes at, not left to the first
        // commit. The walk is floored at the widest tier's window, so it
        // folds entries the narrower tiers have already let go of — and
        // this index is a consensus admission gate, so carrying them
        // means refusing artifacts every peer that stayed up admits.
        index.prune(now);
        index
    }

    /// Whether the index covers the whole window a chain at `now` has to
    /// refuse duplicates across.
    ///
    /// True once the coverage runs a full [`DEDUP_WINDOW`] behind `now`,
    /// or bottoms out at the chain's own origin — below which nothing was
    /// ever committed to be missed.
    ///
    /// Diagnostic, not a gate. A false answer means the index under-refuses
    /// by an unknown amount, and nothing here holds a vote back over it: the
    /// pre-cut rule is what covers the categorical case, and a shallow node
    /// among a committee that holds the window costs a round rather than a
    /// commit. What this separates is "nothing was committed" from "what was
    /// committed is not all known", which the lookups cannot say apart.
    #[must_use]
    pub(crate) fn is_complete(&self, now: WeightedTimestamp) -> bool {
        self.reached_origin
            || self
                .covered_from
                .is_some_and(|from| now.elapsed_since(from) >= DEDUP_WINDOW)
    }

    /// Record that the coverage bottoms out at the chain's origin.
    ///
    /// For a chain with no committed tip: nothing beneath it was ever
    /// committed, so there is nothing to have missed and no span to wait
    /// out.
    pub(crate) const fn cover_to_origin(&mut self) {
        self.reached_origin = true;
    }

    /// Deepen the coverage to include a block anchored at `anchor`.
    ///
    /// Coverage only ever extends backwards to the oldest block folded,
    /// so a chain that starts short of the horizon reaches it by
    /// committing across it — the blocks it commits are the same evidence
    /// a walk would have read.
    pub(crate) fn cover(&mut self, anchor: WeightedTimestamp) {
        self.covered_from = Some(self.covered_from.map_or(anchor, |from| from.min(anchor)));
    }

    /// Record every transaction a block's finalizations resolved. Each
    /// entry's deadline is the resolving tick's local EC
    /// `vote_anchor_ts + RETENTION_HORIZON`.
    ///
    /// The deciding outcomes only: a leg's finalization names its hash
    /// without resolving it, and the reclaim's finalization naming the
    /// hash later is the one this index must not refuse.
    ///
    /// The certificate's own identity is recorded beside them, because
    /// the deciding set is empty for a tick whose every member reaches no
    /// verdict — a retirement's, which settles records under a
    /// transaction whose verdict belongs to another chain. Keyed on the
    /// deciding names alone, such a certificate is never seen as already
    /// carried, and the proposer offers it again on every block.
    pub(crate) fn register_committed_certs(
        &mut self,
        finalizations: &[Arc<Verifiable<Finalization>>],
    ) {
        for fw in finalizations {
            let deadline = fw.local_ec().deadline();
            self.finalization_retention
                .entry(fw.receipt_hash())
                .or_insert(deadline);
            for tx_hash in fw.deciding_tx_hashes() {
                self.resolved_tx_retention
                    .entry(tx_hash)
                    .or_insert(deadline);
            }
        }
    }

    /// Record a block's provisions in the retention lookup, each until
    /// the committing block's `anchor` plus the horizon. Keyed by
    /// `ProvisionHash` so the caller can source from the block's manifest
    /// (which is independent of `Block::Live`/`Sealed`) rather than
    /// depending on `block.provisions()` (which is empty for `Sealed`).
    pub(crate) fn register_committed_provisions(
        &self,
        provision_hashes: &[ProvisionHash],
        anchor: WeightedTimestamp,
    ) {
        self.provision_retention
            .register(provision_hashes.iter().copied(), anchor);
    }

    /// The committed-provision window, for a coordinator that asks the
    /// same question of it. See [`Self::provision_retention`].
    #[must_use]
    pub(crate) const fn committed_provisions(&self) -> &Arc<CommittedProvisions> {
        &self.provision_retention
    }

    /// Record the engagements a committed block names, each until its
    /// committing block's `anchor` plus [`RETENTION_HORIZON`].
    ///
    /// Called with the block's own list on every commit path, so a sealed
    /// block feeds the tier exactly as a live one does.
    pub(crate) fn register_committed_engagements(
        &mut self,
        engagements: &[Engagement],
        anchor: WeightedTimestamp,
    ) {
        let deadline = anchor.plus(RETENTION_HORIZON);
        for engagement in engagements {
            self.engage(*engagement, deadline);
        }
    }

    /// One engagement until `deadline`; the first registration of a
    /// source height stands.
    fn engage(&mut self, engagement: Engagement, deadline: WeightedTimestamp) {
        let heights = self
            .engagements
            .entry((engagement.source, engagement.tx_hash))
            .or_default();
        if !heights
            .iter()
            .any(|(height, _)| *height == engagement.source_height)
        {
            heights.push((engagement.source_height, deadline));
        }
    }

    /// Record the records a committed block's claims read live, each at
    /// the block's `height` until its `anchor` plus [`RETENTION_HORIZON`].
    pub(crate) fn register_committed_arrivals(
        &mut self,
        arrivals: impl IntoIterator<Item = (SubstateKey, TxHash)>,
        height: BlockHeight,
        anchor: WeightedTimestamp,
    ) {
        let deadline = anchor.plus(RETENTION_HORIZON);
        for arrival in arrivals {
            self.arrive(arrival, height, deadline);
        }
    }

    fn arrive(
        &mut self,
        arrival: (SubstateKey, TxHash),
        height: BlockHeight,
        deadline: WeightedTimestamp,
    ) {
        let heights = self.arrivals.entry(arrival).or_default();
        if !heights.iter().any(|(held, _)| *held == height) {
            heights.push((height, deadline));
        }
    }

    /// Whether a committed claim read `record` live naming `tx` in a
    /// block at or above `since`, for an admission anchored at `at`.
    pub(crate) fn arrived(
        &self,
        record: SubstateKey,
        tx: TxHash,
        since: BlockHeight,
        at: WeightedTimestamp,
    ) -> bool {
        self.arrivals.get(&(record, tx)).is_some_and(|heights| {
            heights
                .iter()
                .any(|(height, deadline)| *height >= since && *deadline > at)
        })
    }

    /// Drop every entry whose deadline is at or below `tip_anchor`, the
    /// committed tip's own anchor.
    ///
    /// Every block a voter judges anchors at or above the committed
    /// tip's anchor, so an entry dropped here answers no lookup any voter
    /// can still make, and the prune never changes a verdict. Past
    /// expiry, independent rules (tx validity check;
    /// finalization-deadline) reject any re-inclusion.
    pub(crate) fn prune(&mut self, tip_anchor: WeightedTimestamp) {
        self.resolved_tx_retention
            .retain(|_, deadline| *deadline > tip_anchor);
        self.finalization_retention
            .retain(|_, deadline| *deadline > tip_anchor);
        self.provision_retention.prune(tip_anchor);
        self.engagements.retain(|_, heights| {
            heights.retain(|(_, deadline)| *deadline > tip_anchor);
            !heights.is_empty()
        });
        self.arrivals.retain(|_, heights| {
            heights.retain(|(_, deadline)| *deadline > tip_anchor);
            !heights.is_empty()
        });
    }

    /// Whether a committed finalization already reached a verdict for
    /// `tx_hash`, for an admission anchored at `at`.
    pub(crate) fn contains_resolved_tx(&self, tx_hash: &TxHash, at: WeightedTimestamp) -> bool {
        self.resolved_tx_retention
            .get(tx_hash)
            .is_some_and(|deadline| *deadline > at)
    }

    /// Whether the chain already carries this exact finalization, for an
    /// admission anchored at `at`.
    pub(crate) fn contains_finalization(
        &self,
        receipt_hash: &FinalizationHash,
        at: WeightedTimestamp,
    ) -> bool {
        self.finalization_retention
            .get(receipt_hash)
            .is_some_and(|deadline| *deadline > at)
    }

    /// Whether the chain already carries this batch, for an admission
    /// anchored at `at`.
    pub(crate) fn contains_provision(
        &self,
        provision_hash: &ProvisionHash,
        at: WeightedTimestamp,
    ) -> bool {
        self.provision_retention.contains_at(provision_hash, at)
    }

    /// Whether a committed batch from `source` engages `tx_hash` for an
    /// admission anchored at `at`: an entry whose deadline is past `at`,
    /// at a source height no recovery in `snapshot` fences.
    ///
    /// The fence is read here rather than at registration because the
    /// recovery record is committed beacon state, so the answer is a
    /// function of the admitting anchor's snapshot, and an entry a later
    /// recovery fences stops engaging on every replica at once.
    pub(crate) fn engaged(
        &self,
        source: ShardId,
        tx_hash: TxHash,
        at: WeightedTimestamp,
        snapshot: &TopologySnapshot,
    ) -> bool {
        self.engagements
            .get(&(source, tx_hash))
            .is_some_and(|heights| {
                heights.iter().any(|(height, deadline)| {
                    *deadline > at && !snapshot.recovery_fences(source, *height)
                })
            })
    }

    /// Every engagement the tier holds, with its deadline, in one order
    /// whatever order the feed registered them in.
    #[cfg(test)]
    pub(crate) fn engagement_rows(
        &self,
    ) -> BTreeSet<(ShardId, TxHash, BlockHeight, WeightedTimestamp)> {
        self.engagements
            .iter()
            .flat_map(|((source, tx_hash), heights)| {
                heights
                    .iter()
                    .map(move |(height, deadline)| (*source, *tx_hash, *height, *deadline))
            })
            .collect()
    }

    pub(crate) fn resolved_tx_retention_len(&self) -> usize {
        self.resolved_tx_retention.len()
    }

    pub(crate) fn provision_retention_len(&self) -> usize {
        self.provision_retention.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Capped;
    use hyperscale_types::test_utils::make_finalization;
    use hyperscale_types::{
        Address, AddressClass, BlockHeight, Hash, LocalKey, MerkleInclusionProof,
        NetworkDefinition, ProvisionEntry, Provisions, ShardId, TransactionDecision, ValidatorSet,
    };

    use super::*;

    /// A seeded index holds nothing already past its deadline.
    ///
    /// The recovery walk is floored at the widest tier's window, so it
    /// folds entries the narrower tiers have already let go of. Carried
    /// into the index, they make a just-restarted node refuse artifacts
    /// every peer that stayed up admits — and this index is a consensus
    /// admission gate.
    #[test]
    fn a_seeded_index_holds_nothing_past_its_deadline() {
        let live = TxHash::from(Hash::from_bytes(b"live"));
        let expired = TxHash::from(Hash::from_bytes(b"expired"));
        let receipt_live = FinalizationHash::from_raw(Hash::from_bytes(b"fw-live"));
        let receipt_expired = FinalizationHash::from_raw(Hash::from_bytes(b"fw-expired"));
        let now = WeightedTimestamp::from_millis(10_000);

        let window = DedupWindow {
            resolved: vec![
                (live, WeightedTimestamp::from_millis(10_001)),
                (expired, WeightedTimestamp::from_millis(9_999)),
            ],
            finalizations: vec![
                (receipt_live, WeightedTimestamp::from_millis(10_001)),
                (receipt_expired, WeightedTimestamp::from_millis(9_999)),
            ],
            ..DedupWindow::default()
        };

        let index = CommitDedupIndex::seeded(&window, now);

        let before = WeightedTimestamp::ZERO;
        assert!(index.contains_resolved_tx(&live, before));
        assert!(!index.contains_resolved_tx(&expired, before));
        assert!(index.contains_finalization(&receipt_live, before));
        assert!(!index.contains_finalization(&receipt_expired, before));
    }

    fn make_fw(height: u64) -> Arc<Verifiable<Finalization>> {
        Arc::new(
            make_finalization(
                BlockHeight::new(height),
                TxHash::from(Hash::from_bytes(
                    &[u8::try_from(height).unwrap_or(u8::MAX); 32],
                )),
                TransactionDecision::Accept,
            )
            .into(),
        )
    }

    fn make_provisions(seed: u8) -> Arc<Provisions> {
        let tx_hash = TxHash::from(Hash::from_bytes(&[seed; 32]));
        Arc::new(Provisions::new(
            ShardId::leaf(1, 0),
            ShardId::leaf(1, 1),
            BlockHeight::new(u64::from(seed)),
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::dummy(),
            Capped::from_array([ProvisionEntry::new(tx_hash, Capped::empty())]),
        ))
    }

    // ─── Resolutions ────────────────────────────────────────────────────

    /// A committed finalization records every transaction it reached a
    /// verdict for, so a later block naming one of them under a different
    /// tick is refusable. Identity is the transaction and only the
    /// transaction: a tick can settle in more than one part, so its id
    /// answers no question this index is asked.
    #[test]
    fn register_certs_records_what_they_resolved() {
        // make_finalization sets vote_anchor_ts = block_height + 1, so the
        // deadline is that plus RETENTION_HORIZON.
        let mut idx = CommitDedupIndex::new();
        let fw = make_fw(1);
        let tx_hash = fw.tx_hashes().next().expect("a tick names its members");
        idx.register_committed_certs(std::slice::from_ref(&fw));
        assert!(idx.contains_resolved_tx(&tx_hash, WeightedTimestamp::ZERO));

        idx.prune(WeightedTimestamp::ZERO);
        assert!(
            idx.contains_resolved_tx(&tx_hash, WeightedTimestamp::ZERO),
            "still within the window"
        );

        idx.prune(
            fw.local_ec()
                .deadline()
                .plus(std::time::Duration::from_millis(1)),
        );
        assert!(!idx.contains_resolved_tx(&tx_hash, WeightedTimestamp::ZERO));
    }

    // ─── Engagements ────────────────────────────────────────────────────

    fn engagement(source: ShardId, seed: u8, height: u64) -> Engagement {
        Engagement {
            source,
            tx_hash: TxHash::from(Hash::from_bytes(&[seed; 32])),
            source_height: BlockHeight::new(height),
        }
    }

    fn plain() -> TopologySnapshot {
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        )
    }

    /// `source` under a pending recovery attested to `frontier`.
    fn recovering(source: ShardId, frontier: u64) -> TopologySnapshot {
        use hyperscale_types::{Epoch, RecoveryCause, ShardRecovery};
        plain().with_pending_recoveries(
            std::iter::once((
                source,
                ShardRecovery {
                    cause: RecoveryCause::Halt,
                    rotated_at: Epoch::new(2),
                    retained: Vec::new(),
                    attested_frontier: BlockHeight::new(frontier),
                },
            ))
            .collect(),
        )
    }

    /// An entry engages an admission anchored before its committing
    /// block's anchor plus the horizon and none at or after it, and a
    /// prune at any tip anchor at or below the admitting one changes no
    /// verdict.
    #[test]
    fn an_engagement_is_judged_at_the_admitting_anchor() {
        let source = ShardId::leaf(1, 1);
        let entry = engagement(source, 1, 5);
        let anchor = WeightedTimestamp::from_millis(1_000);
        let deadline = anchor.plus(RETENTION_HORIZON);
        let before = deadline.minus(std::time::Duration::from_millis(1));
        let snapshot = plain();

        let mut idx = CommitDedupIndex::new();
        idx.register_committed_engagements(&[entry], anchor);
        assert!(idx.engaged(source, entry.tx_hash, before, &snapshot));
        assert!(!idx.engaged(source, entry.tx_hash, deadline, &snapshot));
        assert!(
            !idx.engaged(ShardId::leaf(1, 0), entry.tx_hash, before, &snapshot),
            "another source's word is not the payer's"
        );

        for tip in [anchor, before] {
            let mut pruned = CommitDedupIndex::new();
            pruned.register_committed_engagements(&[entry], anchor);
            pruned.prune(tip);
            assert!(pruned.engaged(source, entry.tx_hash, before, &snapshot));
        }
        idx.prune(deadline);
        assert!(
            !idx.engaged(source, entry.tx_hash, WeightedTimestamp::ZERO, &snapshot),
            "the prune at the deadline drops it"
        );
    }

    /// A recovery fencing one source height stops that height's entry
    /// engaging, while an entry for the same pair at an unfenced height
    /// still does; an expired unfenced entry beside a live fenced one
    /// engages nothing.
    #[test]
    fn a_fenced_source_height_does_not_engage() {
        let source = ShardId::leaf(1, 1);
        let fenced = engagement(source, 1, 9);
        let unfenced = engagement(source, 1, 4);
        let snapshot = recovering(source, 5);
        let early = WeightedTimestamp::from_millis(1_000);
        let late = WeightedTimestamp::from_millis(2_000);
        let at = late
            .plus(RETENTION_HORIZON)
            .minus(std::time::Duration::from_millis(1));

        let mut only_fenced = CommitDedupIndex::new();
        only_fenced.register_committed_engagements(&[fenced], late);
        assert!(only_fenced.engaged(source, fenced.tx_hash, at, &plain()));
        assert!(!only_fenced.engaged(source, fenced.tx_hash, at, &snapshot));

        let mut both_live = CommitDedupIndex::new();
        both_live.register_committed_engagements(&[fenced, unfenced], late);
        assert!(both_live.engaged(source, fenced.tx_hash, at, &snapshot));

        let mut expired_beside_fenced = CommitDedupIndex::new();
        expired_beside_fenced.register_committed_engagements(&[unfenced], early);
        expired_beside_fenced.register_committed_engagements(&[fenced], late);
        assert!(
            early.plus(RETENTION_HORIZON) <= at,
            "the unfenced entry has lapsed at the admitting anchor"
        );
        assert!(!expired_beside_fenced.engaged(source, fenced.tx_hash, at, &snapshot));
    }

    /// A seeded index engages what the live feed engaged: the window
    /// stamps each entry with the same deadline, and an entry already
    /// past the seed's clock is gone.
    #[test]
    fn a_seeded_index_engages_what_the_live_feed_did() {
        let source = ShardId::leaf(1, 1);
        let old = engagement(source, 1, 2);
        let young = engagement(source, 2, 3);
        let old_anchor = WeightedTimestamp::from_millis(1_000);
        let young_anchor = WeightedTimestamp::from_millis(5_000);
        let now = old_anchor.plus(RETENTION_HORIZON);

        let mut live = CommitDedupIndex::new();
        live.register_committed_engagements(&[old], old_anchor);
        live.register_committed_engagements(&[young], young_anchor);
        live.prune(now);

        let window = DedupWindow {
            engagements: vec![
                (old, old_anchor.plus(RETENTION_HORIZON)),
                (young, young_anchor.plus(RETENTION_HORIZON)),
            ],
            ..DedupWindow::default()
        };
        let seeded = CommitDedupIndex::seeded(&window, now);
        assert_eq!(seeded.engagements, live.engagements);
        assert!(!seeded.engaged(source, old.tx_hash, now, &plain()));
        assert!(seeded.engaged(source, young.tx_hash, now, &plain()));
    }

    /// An arrival counts from the block that carried its claim on: not
    /// for a transaction committed above it, and not past its deadline.
    /// A seeded index arrives what the live feed did.
    #[test]
    fn an_arrival_counts_from_its_block_and_seeds_as_it_arrived() {
        let record = SubstateKey {
            owner: Address::new([7; 31], AddressClass::Component),
            local: LocalKey([7; 16]),
        };
        let tx = TxHash::from(Hash::from_bytes(b"issuer"));
        let anchor = WeightedTimestamp::from_millis(2_000);
        let mut live = CommitDedupIndex::new();
        live.register_committed_arrivals([(record, tx)], BlockHeight::new(5), anchor);

        assert!(live.arrived(record, tx, BlockHeight::new(5), anchor));
        assert!(live.arrived(record, tx, BlockHeight::new(3), anchor));
        assert!(
            !live.arrived(record, tx, BlockHeight::new(6), anchor),
            "a transaction committed above the reading has not had it arrive",
        );
        assert!(
            !live.arrived(
                record,
                TxHash::from(Hash::from_bytes(b"other")),
                BlockHeight::new(1),
                anchor
            ),
            "a reading naming another issuer arrives nothing for this one",
        );
        let expiry = anchor.plus(RETENTION_HORIZON);
        assert!(!live.arrived(record, tx, BlockHeight::new(5), expiry));

        let window = DedupWindow {
            arrivals: vec![((record, tx), BlockHeight::new(5), expiry)],
            ..DedupWindow::default()
        };
        let seeded = CommitDedupIndex::seeded(&window, anchor);
        assert_eq!(seeded.arrivals, live.arrivals);
    }

    // ─── Provisions ─────────────────────────────────────────────────────

    #[test]
    fn register_provisions_populates_retention() {
        let idx = CommitDedupIndex::new();
        let p = make_provisions(1);
        idx.register_committed_provisions(&[p.hash()], WeightedTimestamp::from_millis(1_000));
        assert!(idx.contains_provision(&p.hash(), WeightedTimestamp::ZERO));
        assert_eq!(idx.provision_retention_len(), 1);
    }

    /// A batch is held until its committing block's anchor plus the
    /// horizon, and a prune at the tip's anchor drops it there.
    #[test]
    fn prune_drops_provisions_past_their_deadline() {
        let mut idx = CommitDedupIndex::new();
        let p = make_provisions(1);
        let anchor = WeightedTimestamp::from_millis(1_000);
        idx.register_committed_provisions(&[p.hash()], anchor);

        idx.prune(anchor);
        assert!(idx.contains_provision(&p.hash(), anchor));

        let deadline = anchor.plus(RETENTION_HORIZON);
        idx.prune(deadline);
        assert!(!idx.contains_provision(&p.hash(), WeightedTimestamp::ZERO));
    }

    /// Every tier answers a lookup at `a` the same way whether or not
    /// the index was pruned at any tip anchor at or below `a`: an entry
    /// answers while its deadline is past `a`, so a voter at a lower tip
    /// and one at a higher tip agree.
    #[test]
    fn a_dedup_lookup_is_judged_at_the_admitting_anchor() {
        let fw = make_fw(1);
        let tx_hash = fw.tx_hashes().next().expect("a tick names its members");
        let deadline = fw.local_ec().deadline();
        let p = make_provisions(1);
        let batch_anchor = deadline.minus(RETENTION_HORIZON);
        let build = || {
            let mut idx = CommitDedupIndex::new();
            idx.register_committed_certs(std::slice::from_ref(&fw));
            idx.register_committed_provisions(&[p.hash()], batch_anchor);
            idx
        };
        let answers = |idx: &CommitDedupIndex, at| {
            (
                idx.contains_resolved_tx(&tx_hash, at),
                idx.contains_finalization(&fw.receipt_hash(), at),
                idx.contains_provision(&p.hash(), at),
            )
        };
        let before = deadline.minus(std::time::Duration::from_millis(1));
        for at in [WeightedTimestamp::ZERO, before, deadline] {
            let unpruned = answers(&build(), at);
            for tip in [WeightedTimestamp::ZERO, at] {
                let mut pruned = build();
                pruned.prune(tip);
                assert_eq!(answers(&pruned, at), unpruned, "at {at:?}, tip {tip:?}");
            }
        }
        assert_eq!(answers(&build(), before), (true, true, true));
        assert_eq!(answers(&build(), deadline), (false, false, false));
    }

    /// A batch registered by the live commit and one seeded from the
    /// recovery walk carry one deadline: both stamp the committing
    /// block's own anchor plus the horizon.
    #[test]
    fn a_live_and_a_seeded_provision_window_stamp_alike() {
        let p = make_provisions(1);
        let anchor = WeightedTimestamp::from_millis(7_000);
        let live = CommitDedupIndex::new();
        live.register_committed_provisions(&[p.hash()], anchor);
        let window = DedupWindow {
            provisions: vec![(p.hash(), anchor.plus(RETENTION_HORIZON))],
            ..DedupWindow::default()
        };
        let seeded = CommitDedupIndex::seeded(&window, anchor);
        let deadline = anchor.plus(RETENTION_HORIZON);
        for at in [
            anchor,
            deadline.minus(std::time::Duration::from_millis(1)),
            deadline,
        ] {
            assert_eq!(
                live.contains_provision(&p.hash(), at),
                seeded.contains_provision(&p.hash(), at),
                "at {at:?}"
            );
        }
        assert!(!live.contains_provision(&p.hash(), deadline));
    }

    /// A leg's finalization names its hash without resolving it, so the
    /// reclaim's finalization naming the hash later is not a duplicate.
    #[test]
    fn a_leg_finalization_does_not_resolve_its_transaction() {
        use hyperscale_types::test_utils::{make_finalization, make_leg_finalization};
        use hyperscale_types::{BlockHeight, TransactionDecision};

        let tx_hash = TxHash::from(Hash::from_bytes(b"leg"));
        let mut index = CommitDedupIndex::new();
        index.register_committed_certs(&[Arc::new(Verifiable::from(make_leg_finalization(
            BlockHeight::new(1),
            tx_hash,
        )))]);
        assert!(
            !index.contains_resolved_tx(&tx_hash, WeightedTimestamp::ZERO),
            "the leg decided nothing"
        );

        index.register_committed_certs(&[Arc::new(Verifiable::from(make_finalization(
            BlockHeight::new(5),
            tx_hash,
            TransactionDecision::Accept,
        )))]);
        assert!(
            index.contains_resolved_tx(&tx_hash, WeightedTimestamp::ZERO),
            "the reclaim's finalization does"
        );
    }
}
