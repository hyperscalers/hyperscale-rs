//! What a block is judged by against its parent state, and how a
//! proposer builds the claims that pass it.
//!
//! A voter reads its own anchored parent view and refuses a block whose
//! committed markers or member rows collide with it, whose claims the
//! read frontier fences, whose parent-anchored readings disagree with
//! it, which takes back a record its commit fold could not return,
//! whose departures name a crossing it does not hold as named, or whose
//! fees a payer this shard holds cannot cover beside what its vault has
//! already promised.
//! These are validity rules at vote time: a replica following a
//! certified block never evaluates them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use hyperscale_jmt::NibblePath;
use hyperscale_storage::{
    CommittedHere, FeeTerms, MemberInputs, Substates, colliding_committed_cell,
    colliding_member_row, decline_rows, held_total, key_under_prefix, load_read_frontier,
    reclaim_credits, reclaimed, reserved_total, settling_writes,
};
use hyperscale_types::{
    Anchor, Finalization, FrontierInputs, FrontierRefusal, ReadFence, ShardId, SharedTransactions,
    StateClaim, StateWrites, Stated, StoredReceipt, SubstateKey, Transaction, TxHash, Verifiable,
    shard_prefix_path,
};
use hyperscale_vm_effects::{Answered, CrossingId, ProtocolHasher};

use crate::local_crossings::{disagreeing_parent_reading, parent_claims};
use crate::read_fence::{Dropped, drop_refused};

/// The parts of a block its parent state judges.
pub struct AtParent<'a> {
    /// The chain the block extends.
    pub local: ShardId,
    /// The committed markers the block writes.
    pub creations: &'a [CommittedHere],
    /// What the block writes to tick membership.
    pub members: &'a MemberInputs,
    /// What the read frontier judges of the block's claims.
    pub fence: &'a ReadFence,
    /// The block's claims.
    pub state_claims: &'a [StateClaim],
    /// The block's transactions, whose fees its payers must cover.
    pub transactions: &'a SharedTransactions,
    /// The block's finalizations, whose settling receipts a record it
    /// takes back is returned beside.
    pub finalizations: &'a [Arc<Verifiable<Finalization>>],
}

/// Why the parent state refuses a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentRefusal {
    /// A committed marker the parent already holds, or one two of the
    /// block's transactions name: the transaction was committed here.
    CommittedCell(SubstateKey),
    /// A member row key a standing row or another of the block's
    /// transactions takes: one row would stand for two.
    MemberRow(TxHash),
    /// A reading the read frontier fences.
    Frontier(Box<FrontierRefusal>),
    /// A parent-anchored reading the parent state does not bear out.
    ParentReading(SubstateKey),
    /// A record the block takes back that its commit fold would leave
    /// standing.
    Reclaim(SubstateKey),
    /// A fee the payer's stored rule does not let this transaction's
    /// attesting set engage.
    UnadmittedPayer(SubstateKey),
    /// A fee vault whose balance does not cover what it already holds,
    /// what the members in flight reserve of it, and what the block
    /// charges it.
    UncoveredPayer(SubstateKey),
}

impl fmt::Display for ParentRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommittedCell(key) => {
                write!(f, "committed cell {key:?} already present or named twice")
            }
            Self::MemberRow(tx) => write!(f, "member row of {tx:?} already taken"),
            Self::Frontier(refusal) => write!(f, "read frontier refuses: {refusal}"),
            Self::ParentReading(key) => {
                write!(
                    f,
                    "parent-anchored reading of {key:?} disagrees with the parent"
                )
            }
            Self::Reclaim(key) => {
                write!(f, "record {key:?} taken back where it cannot be returned")
            }
            Self::UnadmittedPayer(vault) => {
                write!(f, "payer of {vault:?} does not admit the attesting set")
            }
            Self::UncoveredPayer(vault) => {
                write!(
                    f,
                    "fee vault {vault:?} does not cover its holds, reservations and charges"
                )
            }
        }
    }
}

/// Judge `block` against `parent`, the voter's own anchored view of the
/// block's parent.
///
/// # Errors
///
/// The first [`ParentRefusal`] the parent state gives.
pub fn refused_at_parent(
    block: &AtParent<'_>,
    parent: &(impl Substates + ?Sized),
) -> Result<(), ParentRefusal> {
    if let Some(key) = colliding_committed_cell(block.creations, parent) {
        return Err(ParentRefusal::CommittedCell(key));
    }
    if let Some(tx) = colliding_member_row(
        block.members.shard,
        block.members.transactions.iter().map(|(tx, _)| *tx),
        parent,
    ) {
        return Err(ParentRefusal::MemberRow(tx));
    }
    block
        .fence
        .check(&load_read_frontier(parent, block.local))
        .map_err(ParentRefusal::Frontier)?;
    if let Some(key) = disagreeing_parent_reading(block.state_claims, block.local, parent) {
        return Err(ParentRefusal::ParentReading(key));
    }
    let settling: Vec<StoredReceipt> = block
        .finalizations
        .iter()
        .flat_map(|fw| fw.settling_receipts())
        .collect();
    let merged = settling_writes(
        &settling,
        block.state_claims,
        block.members,
        parent,
        &shard_prefix_path(block.local),
    );
    if let Some(key) = reclaim_stands(block.state_claims, block.members, &merged, parent)
        .into_iter()
        .next()
    {
        return Err(ParentRefusal::Reclaim(key));
    }
    let mut charges = PayerCharges::new(block.local, parent);
    for tx in block.transactions.iter() {
        charges.charge(tx.as_unverified())?;
    }
    Ok(())
}

/// The records a block takes back that its commit fold would leave
/// standing, ascending.
///
/// The block carries `state_claims` and writes `members`; what it takes
/// back is [`reclaimed`], landed over `parent` beside `merged`, the
/// block's other value writes ([`settling_writes`]). Every reclaim a
/// committed block carries lands, so a follower holding the credit cell
/// and not the record writes the return unread.
#[must_use]
pub fn reclaim_stands(
    state_claims: &[StateClaim],
    members: &MemberInputs,
    merged: &StateWrites,
    parent: &(impl Substates + ?Sized),
) -> Vec<SubstateKey> {
    let local = members.shard;
    let taken = reclaimed(state_claims, local, members.committed);
    let landed = reclaim_credits(&taken, local, merged, parent);
    taken
        .into_iter()
        .map(|(key, _)| key)
        .filter(|key| !landed.cells.contains_key(key))
        .collect()
}

/// `claims` less the consumer's `Never` of every record their block
/// would take back and leave standing.
///
/// The block writes `members`, and its commit fold lands over `parent`
/// beside `merged`. What is left is what the proposer carries, so its
/// block is not refused at the vote. A record left behind is taken back
/// by a later block.
///
/// The `Never` is read only at a boundary of the consumer's shard, or at
/// the parent of a chain holding both ends, where it rides in a claim no
/// read frontier, arrival or member reads: cutting it moves nothing the
/// block's other sections were built on. A record whose `Never` was read
/// at a boundary is read at the parent for its return alone, so its
/// reading goes with the `Never`; one whose ends this chain both holds
/// is read there for its other settlements too, and stays. A parent
/// claim left reading nothing goes, and the read mark it raised with it.
#[must_use]
pub fn without_refused_reclaims(
    claims: Vec<StateClaim>,
    members: &MemberInputs,
    merged: &StateWrites,
    parent: &(impl Substates + ?Sized),
) -> Vec<StateClaim> {
    let local = members.shard;
    let standing: BTreeSet<SubstateKey> = reclaim_stands(&claims, members, merged, parent)
        .into_iter()
        .collect();
    if standing.is_empty() {
        return claims;
    }
    let refused = |claim: &StateClaim, key: SubstateKey| {
        claim.crossing_of(key).is_some_and(|id| {
            key == id.answer_key(&ProtocolHasher, Answered::Never)
                && standing.contains(&id.record_key(&ProtocolHasher))
        })
    };
    let returned_alone: BTreeSet<SubstateKey> = claims
        .iter()
        .filter(|claim| claim.anchor.shard != local)
        .flat_map(|claim| {
            claim
                .keys()
                .into_iter()
                .filter(|key| refused(claim, *key))
                .filter_map(|key| claim.crossing_of(key))
                .map(|id| id.record_key(&ProtocolHasher))
        })
        .collect();
    let cut = |claim: &StateClaim, key: SubstateKey| {
        refused(claim, key) || (claim.anchor.shard == local && returned_alone.contains(&key))
    };
    claims
        .into_iter()
        .filter_map(|claim| {
            if !claim.keys().into_iter().any(|key| cut(&claim, key)) {
                return Some(claim);
            }
            if claim.anchor.shard != local {
                return claim.restrict(|key| !cut(&claim, key));
            }
            // Read at the parent under the empty proof, so the reading is
            // dropped from the claim rather than cut from a proof.
            let cells: Vec<(SubstateKey, Stated)> = claim
                .cells
                .iter()
                .filter(|(key, _)| !cut(&claim, *key))
                .cloned()
                .collect();
            let named: Vec<(SubstateKey, CrossingId)> = claim
                .crossings
                .iter()
                .filter(|(key, _)| !cut(&claim, *key))
                .copied()
                .collect();
            (!cells.is_empty())
                .then(|| StateClaim::new(claim.anchor, cells, claim.proof.clone()).naming(named))
        })
        .collect()
}

/// What each fee vault this shard holds is charged, judged against one
/// state: the parent's for a voter, and the same parent for the proposer
/// building on it, so a proposal never refuses itself.
///
/// A vault has promised two things a new hold must fit beside. A fee
/// hold is state, written by the block that includes its transaction
/// and deleted in the write set that burns its price, so the parent's
/// held total is every ceiling the chain still carries against the
/// vault. A member's declared reservation stands on its row from the
/// block that commits it to the block that deletes the row, so the
/// parent's reserved total is everything the members in flight may yet
/// take from the vault. Nothing but the block's own charges is added to
/// the two.
///
/// What a transaction of the block itself reserves is not counted
/// against the others the block carries, its own ceiling included: its
/// row is not in the parent, and execution judges its reservation under
/// every hold the block adds.
pub struct PayerCharges<'s, S: ?Sized> {
    local: ShardId,
    prefix: NibblePath,
    state: &'s S,
    charged: BTreeMap<SubstateKey, u128>,
}

impl<'s, S: Substates + ?Sized> PayerCharges<'s, S> {
    /// No charges yet against `state`, for the vaults under `local`'s
    /// prefix: the ones this shard writes holds for.
    pub fn new(local: ShardId, state: &'s S) -> Self {
        Self {
            local,
            prefix: shard_prefix_path(local),
            state,
            charged: BTreeMap::new(),
        }
    }

    /// Charge `tx`'s ceiling to its payer's vault, or say why the payer
    /// refuses it. A payer this shard does not hold is another shard's
    /// to judge, and a refused charge leaves the vault's figure as it
    /// was.
    ///
    /// # Errors
    ///
    /// [`ParentRefusal::UnadmittedPayer`] where the payer's stored rule
    /// does not admit the attesting set, and
    /// [`ParentRefusal::UncoveredPayer`] where the vault's balance falls
    /// short of its held total, its reserved total, every charge so far
    /// and this one.
    pub fn charge(&mut self, tx: &Transaction) -> Result<(), ParentRefusal> {
        let terms = FeeTerms::of(tx);
        if !key_under_prefix(&terms.vault.to_bytes(), &self.prefix) {
            return Ok(());
        }
        if !tx.payer_admits_attesters(self.state.cell(tx.auth_cell()).as_deref()) {
            return Err(ParentRefusal::UnadmittedPayer(terms.vault));
        }
        let charged = self.charged.entry(terms.vault).or_insert_with(|| {
            held_total(self.state, terms.vault).saturating_add(reserved_total(
                self.state,
                self.local,
                terms.vault,
            ))
        });
        let wanted = charged.saturating_add(terms.max_fee);
        if wanted > vault_balance(self.state, terms.vault) {
            return Err(ParentRefusal::UncoveredPayer(terms.vault));
        }
        *charged = wanted;
        Ok(())
    }
}

/// A vault's balance of the protocol resource as `state` holds it: zero
/// where the vault is absent.
fn vault_balance(state: &(impl Substates + ?Sized), vault: SubstateKey) -> u128 {
    state
        .cell(vault)
        .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
        .map_or(0, u128::from_le_bytes)
}

/// A proposal's claims, built to pass [`refused_at_parent`].
pub struct ProposalClaims {
    /// The claims the block carries, in the section's order.
    pub claims: Vec<StateClaim>,
    /// What those claims do to the read frontier.
    pub frontier: FrontierInputs,
    /// How many readings the fence refused and the proposer dropped.
    pub refused: usize,
}

/// The claims a proposer carries: `selected` with every reading `fence`
/// refuses against `parent` cut, and what the block reads at
/// `parent_anchor` beside them.
///
/// At the parent it reads the crossings whose ends share this shard,
/// and the member rows a decline of the block reads
/// ([`decline_rows`]), of those `rowless` names, that the parent does
/// not hold. The rows are chosen off the claims the block carries once
/// the cut is made and the crossings are read, so no row is read for a
/// record the cut took or a parent reading shows absent, and none for a
/// record the parent already answers: a row reading rides only beside
/// the record whose decline reads it. `rowless` is what the proposer
/// left room for.
///
/// The parent-anchored readings join after the cut. They pass the fence
/// without one: each is read at the parent itself, so no floor the
/// parent's own table holds sits above it.
#[must_use]
pub fn proposal_claims(
    selected: Vec<StateClaim>,
    fence: &ReadFence,
    frontier: &FrontierInputs,
    local_crossings: &[CrossingId],
    rowless: &[TxHash],
    parent_anchor: Anchor,
    parent: &(impl Substates + ?Sized),
) -> ProposalClaims {
    let Dropped {
        mut claims,
        refused,
    } = drop_refused(
        selected,
        fence,
        frontier.windows,
        &load_read_frontier(parent, frontier.local),
    );
    let kept = claims.len();
    claims.extend(parent_claims(local_crossings, &[], parent_anchor, parent));
    let declined = decline_rows(&claims, frontier.local, frontier.anchor, parent);
    let rows: Vec<TxHash> = rowless
        .iter()
        .copied()
        .filter(|tx| declined.values().any(|issuer| issuer == tx))
        .collect();
    if !rows.is_empty() {
        claims.truncate(kept);
        claims.extend(parent_claims(local_crossings, &rows, parent_anchor, parent));
    }
    claims.sort_unstable();
    let frontier =
        FrontierInputs::for_block(&claims, frontier.windows, frontier.anchor, frontier.local);
    ProposalClaims {
        claims,
        frontier,
        refused,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::slice::from_ref;
    use std::sync::Arc;
    use std::time::Duration;

    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_storage::{
        SettledHalf, committed_tx_cell_key, crossing_settlements, entry_leaf_value,
        member_row_leaf, member_writes, owed_credits, read_frontier_writes, reclaim_credits,
        reclaimed, unclaimed_declines,
    };
    use hyperscale_types::state_key::jmt_value_hash;
    use hyperscale_types::test_utils::{
        state_and_proof, state_and_proof_holding, stub_stated_terms, stub_transaction, test_key,
    };
    use hyperscale_types::{
        Address, AddressClass, BlockHeight, CollectionId, Deadline, EntryKey, Epoch, EpochWindows,
        Hash, Inclusion, LocalKey, MerkleInclusionProof, PrincipalAddr, RETENTION_HORIZON,
        ReadFrontier, ReadMark, Reading, SettledEntries, SettledWrites, StateRoot, StateWrites,
        Stated, TickHalf, TickId, TimestampRange, Verifiable, WeightedTimestamp, encode_amount,
        entry_leaf_key,
    };
    use hyperscale_vm_effects::{
        Answered, CrossingCell, Hash32, IntentHash, ProtocolHasher, Terms, fee_hold_total_key,
    };
    use hyperscale_vm_types::{Movement, ResourceAddr};

    use super::*;
    use crate::read_fence::read_fence;

    const WINDOW_MS: u64 = 1_000_000;

    fn windows() -> EpochWindows {
        EpochWindows::new(WINDOW_MS)
    }

    /// A parent state of cells and collection entries, each entry's
    /// leaf read as a cell under its leaf key.
    #[derive(Default, Clone)]
    struct Parent {
        cells: BTreeMap<SubstateKey, Vec<u8>>,
        entries: BTreeMap<EntryKey, Vec<u8>>,
    }

    impl Parent {
        fn apply(&mut self, writes: &SettledEntries) {
            for (key, change) in writes {
                match change {
                    Some(bytes) => {
                        self.entries.insert(*key, bytes.clone());
                    }
                    None => {
                        self.entries.remove(key);
                    }
                }
            }
        }

        /// Raise the read frontier `local`'s table holds for each of
        /// `marks`.
        fn raise(&mut self, local: ShardId, marks: &[(ShardId, ReadMark)]) {
            let writes = read_frontier_writes(
                self,
                &FrontierInputs {
                    local,
                    anchor: WeightedTimestamp::from_millis(100),
                    windows: windows(),
                    marks: marks.iter().copied().collect(),
                },
            );
            self.apply(&writes);
        }
    }

    impl Substates for Parent {
        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            self.cells.get(&key).cloned().or_else(|| {
                self.entries
                    .iter()
                    .find(|(entry, _)| entry_leaf_key(&ProtocolHasher, **entry) == key)
                    .map(|(entry, row)| entry_leaf_value(entry, row))
            })
        }

        fn entries_in_range(
            &self,
            owner: Address,
            collection: CollectionId,
            lo: u128,
            hi: u128,
            limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            self.entries
                .iter()
                .filter(|(key, _)| {
                    key.owner == owner
                        && key.collection == collection
                        && (lo..=hi).contains(&key.order)
                })
                .map(|(key, bytes)| (key.order, bytes.clone()))
                .take(limit)
                .collect()
        }
    }

    fn mark(height: u64) -> ReadMark {
        ReadMark {
            epoch: Epoch::GENESIS,
            height: BlockHeight::new(height),
        }
    }

    fn anchor(shard: ShardId, height: u64) -> Anchor {
        Anchor {
            shard,
            height: BlockHeight::new(height),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::from_millis(height * 1_000),
        }
    }

    fn crossing(seed: u8) -> CrossingId {
        CrossingId {
            producer: Address::new([seed; 31], AddressClass::Component),
            consumer: Address::new([seed + 1; 31], AddressClass::Component),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        }
    }

    fn record_cell(id: CrossingId, terms: Terms) -> CrossingCell {
        id.cell(
            TxHash(Hash32([9; 32])),
            ResourceAddr::new([0xE0; 31]),
            5,
            9_000,
            terms,
        )
    }

    /// A parent holding an owed record of a crossing both of whose ends
    /// share the shard.
    fn holding_an_owed_record(id: CrossingId) -> Parent {
        let mut parent = Parent::default();
        parent.cells.insert(
            id.record_key(&ProtocolHasher),
            record_cell(id, Terms::Owed).to_bytes(),
        );
        parent
    }

    /// A counterpart's claim at `height` carrying a live owed record.
    fn remote_record_claim(producer: ShardId, height: u64) -> StateClaim {
        let id = crossing(0xAA);
        let record = id.record_key(&ProtocolHasher);
        let (state_root, proof) = state_and_proof(producer, &[record], &[record]);
        StateClaim::new(
            Anchor {
                state_root,
                ..anchor(producer, height)
            },
            [(
                record,
                Stated::Held(Bytes::new(record_cell(id, Terms::Owed).to_bytes()).unwrap()),
            )],
            proof,
        )
    }

    struct Block {
        local: ShardId,
        creations: Vec<CommittedHere>,
        members: MemberInputs,
        fence: ReadFence,
        state_claims: Vec<StateClaim>,
        transactions: SharedTransactions,
        finalizations: Vec<Arc<Verifiable<Finalization>>>,
    }

    impl Block {
        fn empty(local: ShardId) -> Self {
            Self {
                local,
                creations: Vec::new(),
                members: MemberInputs::still(local),
                fence: ReadFence::default(),
                state_claims: Vec::new(),
                transactions: Arc::new(Capped::empty()),
                finalizations: Vec::new(),
            }
        }

        fn judged(&self, parent: &Parent) -> Result<(), ParentRefusal> {
            refused_at_parent(
                &AtParent {
                    local: self.local,
                    creations: &self.creations,
                    members: &self.members,
                    fence: &self.fence,
                    state_claims: &self.state_claims,
                    transactions: &self.transactions,
                    finalizations: &self.finalizations,
                },
                parent,
            )
        }
    }

    /// Each rule the parent state judges a block by refuses under its
    /// own name, and a block none of them touches passes.
    #[test]
    fn each_parent_rule_refuses_by_its_own_name() {
        let local = ShardId::leaf(1, 0);
        let producer = ShardId::leaf(1, 1);
        let parent = Parent::default();
        assert_eq!(Block::empty(local).judged(&parent), Ok(()));

        let marker = test_key(0x30);
        let twice = CommittedHere {
            key: marker,
            value: vec![1],
            inherited: None,
        };
        let block = Block {
            creations: vec![twice.clone(), twice],
            ..Block::empty(local)
        };
        assert_eq!(
            block.judged(&parent),
            Err(ParentRefusal::CommittedCell(marker))
        );

        let tx = TxHash::from(Hash::from_bytes(b"twice"));
        let deadline = Deadline::of(WeightedTimestamp::from_millis(90_000));
        let block = Block {
            members: MemberInputs {
                transactions: vec![(tx, deadline), (tx, deadline)],
                ..MemberInputs::still(local)
            },
            ..Block::empty(local)
        };
        assert_eq!(block.judged(&parent), Err(ParentRefusal::MemberRow(tx)));

        let mut raised = Parent::default();
        raised.raise(local, &[(producer, mark(9))]);
        let block = Block {
            fence: ReadFence {
                presences: vec![Reading {
                    key: test_key(0x40),
                    shard: producer,
                    mark: mark(5),
                }],
                ..ReadFence::default()
            },
            ..Block::empty(local)
        };
        assert!(
            matches!(
                block.judged(&raised),
                Err(ParentRefusal::Frontier(refusal))
                    if matches!(*refusal, FrontierRefusal::BelowFloor { .. })
            ),
            "a presence below its producer's floor",
        );
        assert_eq!(block.judged(&parent), Ok(()), "and passes with no floor");

        let id = crossing(0x41);
        let held = holding_an_owed_record(id);
        let block = Block {
            state_claims: parent_claims(&[id], &[], anchor(local, 4), &held),
            ..Block::empty(local)
        };
        assert_eq!(block.judged(&held), Ok(()));
        assert_eq!(
            block.judged(&parent),
            Err(ParentRefusal::ParentReading(id.record_key(&ProtocolHasher))),
            "read at a parent holding the record, judged at one without it",
        );
    }

    /// A proposal cuts the counterpart reading its parent's floor
    /// refuses, carries its parent-anchored readings uncut, and the block
    /// it builds passes every rule its voters judge it by: the fence
    /// defers nothing read at the parent, even with this shard's own
    /// entry raised by the parent's own parent reading.
    #[test]
    fn a_proposal_passes_its_own_parent_checks() {
        let local = ShardId::leaf(1, 0);
        let producer = ShardId::leaf(1, 1);
        let id = crossing(0x41);
        let mut parent = holding_an_owed_record(id);
        parent.raise(local, &[(producer, mark(9)), (local, mark(3))]);

        let stale = remote_record_claim(producer, 5);
        let fence = read_fence(from_ref(&stale), windows());
        let built = proposal_claims(
            vec![stale],
            &fence,
            &FrontierInputs::for_block(
                &[],
                windows(),
                WeightedTimestamp::from_millis(4_500),
                local,
            ),
            &[id],
            &[],
            anchor(local, 4),
            &parent,
        );
        assert_eq!(built.refused, 1, "the counterpart's stale presence");
        assert_eq!(built.claims.len(), 1, "the parent reading alone");
        assert_eq!(built.claims[0].anchor.shard, local);
        assert_eq!(built.frontier.marks.get(&local), Some(&mark(4)));

        let block = Block {
            fence: read_fence(&built.claims, windows()),
            state_claims: built.claims,
            ..Block::empty(local)
        };
        assert_eq!(block.fence.presences.len(), 1, "the owed record is fenced");
        assert_eq!(block.judged(&parent), Ok(()));
    }

    /// A reading taken at the parent raises this shard's own entry, and
    /// a split child inherits it: a reading of the parent's older than
    /// that entry is refused on the right child as on the left.
    #[test]
    fn a_parent_reading_raises_the_local_entry_and_a_child_refuses_an_older_one() {
        let local = ShardId::leaf(1, 0);
        let id = crossing(0x41);
        let mut parent = holding_an_owed_record(id);
        let read = parent_claims(&[id], &[], anchor(local, 4), &parent);
        let inputs = FrontierInputs::for_block(
            &read,
            windows(),
            WeightedTimestamp::from_millis(4_500),
            local,
        );
        assert_eq!(inputs.marks.get(&local), Some(&mark(4)));
        let writes = read_frontier_writes(&parent, &inputs);
        parent.apply(&writes);

        let older = read_fence(
            &parent_claims(&[id], &[], anchor(local, 3), &parent),
            windows(),
        );
        let same = read_fence(&read, windows());
        for child in <[ShardId; 2]>::from(local.children()) {
            let table = load_read_frontier(&parent, child);
            assert_eq!(
                table.floor(local),
                Some(mark(4)),
                "{child:?} inherits the entry"
            );
            assert!(
                matches!(
                    older.check(&table).map_err(|refusal| *refusal),
                    Err(FrontierRefusal::BelowFloor { .. })
                ),
                "{child:?} refuses the older reading",
            );
            assert_eq!(
                same.check(&table),
                Ok(()),
                "{child:?} admits the entry's own mark"
            );
        }
        assert_eq!(
            load_read_frontier(&parent, local),
            ReadFrontier::from_entries([(local, mark(4))]),
        );
    }

    /// The transaction [`record_cell`] says issued its record, and the
    /// end of its validity range.
    const ISSUER: TxHash = TxHash(Hash32([9; 32]));
    const ISSUER_VALIDITY_END_MS: u64 = 9_000;

    /// A counterpart's claim at `height` reading `cells` with no proof,
    /// naming nothing.
    fn remote_claim(
        producer: ShardId,
        height: u64,
        cells: Vec<(SubstateKey, Inclusion)>,
    ) -> StateClaim {
        StateClaim::new(
            anchor(producer, height),
            cells,
            MerkleInclusionProof::dummy(),
        )
    }

    /// `parent` after a block of `local`'s carrying `claims` raises the
    /// read frontier, with the marks it raised.
    fn carry(
        parent: &mut Parent,
        local: ShardId,
        claims: &[StateClaim],
    ) -> BTreeMap<ShardId, ReadMark> {
        let inputs = FrontierInputs::for_block(
            claims,
            windows(),
            WeightedTimestamp::from_millis(100),
            local,
        );
        let writes = read_frontier_writes(parent, &inputs);
        parent.apply(&writes);
        inputs.marks
    }

    /// `claims` as a block of `local`'s the parent state judges.
    fn carrying_claims(local: ShardId, claims: &[StateClaim]) -> Block {
        Block {
            fence: read_fence(claims, windows()),
            state_claims: claims.to_vec(),
            ..Block::empty(local)
        }
    }

    /// The anchor of a block `claim` is at a boundary of: a millisecond
    /// more than a retention horizon past its anchor.
    fn past(claim: &StateClaim) -> WeightedTimestamp {
        claim
            .anchor
            .ts
            .plus(RETENTION_HORIZON)
            .plus(Duration::from_millis(1))
    }

    /// A record presence that names its crossing marks an unseen `Never`
    /// seen and raises the frontier to its anchor without carrying the
    /// record's value. An absence of the record is then admitted
    /// wherever it was read, below that mark as at it, and deletes
    /// nothing while it is fresh; read at a boundary of the block, which
    /// sits below every mark a fresh claim raised, with the producing
    /// member's exit beside it, it deletes the answer.
    #[test]
    fn an_absence_below_the_floor_deletes_only_at_a_boundary() {
        let local = ShardId::leaf(1, 0);
        let producer = ShardId::leaf(1, 1);
        let id = crossing(0xAA);
        let record = id.record_key(&ProtocolHasher);
        let never = id.answer_key(&ProtocolHasher, Answered::Never);
        let read = |height: u64, inclusion: Inclusion| {
            remote_claim(producer, height, vec![(record, inclusion)]).naming([(record, id)])
        };
        let mut parent = Parent::default();
        parent.cells.insert(
            never,
            id.unseen_never(ISSUER, ISSUER_VALIDITY_END_MS).to_bytes(),
        );

        let seeing = [read(50, Inclusion::Present([7; 32]))];
        assert!(!seeing[0].holds_a_value(), "an inclusion-only presence");
        assert_eq!(carrying_claims(local, &seeing).judged(&parent), Ok(()));
        let fresh = WeightedTimestamp::from_millis(100);
        let settled =
            crossing_settlements(&seeing, local, fresh, &SettledWrites::default(), &parent);
        assert_eq!(settled.seen.len(), 1, "the presence marks the Never seen");
        parent.cells.extend(settled.seen);
        assert_eq!(
            carry(&mut parent, local, &seeing),
            BTreeMap::from([(producer, mark(50))]),
        );

        let row = member_row_leaf(producer, ISSUER);
        for height in [40, 50] {
            let absence = [StateClaim::new(
                anchor(producer, height),
                [(record, Inclusion::Absent), (row, Inclusion::Absent)],
                MerkleInclusionProof::dummy(),
            )
            .naming([(record, id)])];
            assert_eq!(carrying_claims(local, &absence).judged(&parent), Ok(()));
            let removed = |block: WeightedTimestamp| {
                crossing_settlements(&absence, local, block, &SettledWrites::default(), &parent)
                    .removed
            };
            assert!(
                removed(fresh).is_empty(),
                "a fresh absence at height {height} deletes nothing, seen as the answer is",
            );
            assert_eq!(removed(past(&absence[0])), vec![never]);
            assert!(
                FrontierInputs::for_block(&absence, windows(), past(&absence[0]), local)
                    .marks
                    .is_empty(),
                "and a boundary claim raises nothing",
            );
        }
    }

    /// A claim that names no crossing and holds no value raises nothing,
    /// so a record read below it in a later block is admitted, and the
    /// fold credits it once: the record's own claim raises the frontier
    /// to its anchor, and the `Taken` the credit writes refuses a second.
    #[test]
    fn a_bare_reading_above_a_record_does_not_fence_it() {
        let local = ShardId::leaf(1, 0);
        let producer = ShardId::leaf(1, 1);
        let mut parent = Parent::default();

        let bare = [remote_claim(
            producer,
            60,
            vec![(test_key(0x90), Inclusion::Absent)],
        )];
        assert_eq!(carrying_claims(local, &bare).judged(&parent), Ok(()));
        assert!(carry(&mut parent, local, &bare).is_empty());
        assert!(load_read_frontier(&parent, local).is_empty());

        let id = crossing(0xAA);
        let record = id.record_key(&ProtocolHasher);
        let held = [remote_record_claim(producer, 50).naming([(record, id)])];
        let block = carrying_claims(local, &held);
        assert_eq!(block.fence.presences.len(), 1, "the record is fenced");
        assert_eq!(block.judged(&parent), Ok(()));

        let credit = owed_credits(&held, &StateWrites::default(), &parent);
        assert_eq!(credit.movements.len(), 1, "the record is credited");
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        assert_eq!(credit.cells.keys().collect::<Vec<_>>(), [&taken]);
        for (key, value) in credit.cells {
            parent
                .cells
                .insert(key, value.expect("a credit writes its Taken"));
        }
        assert_eq!(
            carry(&mut parent, local, &held),
            BTreeMap::from([(producer, mark(50))]),
        );
        assert!(
            owed_credits(&held, &StateWrites::default(), &parent)
                .movements
                .is_empty(),
            "and never twice",
        );
        assert!(matches!(
            carrying_claims(local, &[remote_record_claim(producer, 49)]).judged(&parent),
            Err(ParentRefusal::Frontier(_))
        ));
    }

    /// An answer goes on its record's absence at a boundary beside the
    /// proof that the producer's member exited, wherever the section's
    /// cut left the proof: the absence names its crossing, and the
    /// member row and committed marker ride a second claim at the same
    /// anchor that names nothing. Neither claim raises the frontier.
    #[test]
    fn an_exit_proof_cut_from_its_absence_still_deletes() {
        let local = ShardId::leaf(1, 0);
        let producer = ShardId::leaf(1, 1);
        let id = crossing(0xAA);
        let record = id.record_key(&ProtocolHasher);
        let never = id.answer_key(&ProtocolHasher, Answered::Never);
        let mut parent = Parent::default();
        parent.cells.insert(
            never,
            id.unseen_never(ISSUER, ISSUER_VALIDITY_END_MS).to_bytes(),
        );
        let row = member_row_leaf(producer, ISSUER);
        let marker = committed_tx_cell_key(
            producer,
            ISSUER,
            WeightedTimestamp::from_millis(ISSUER_VALIDITY_END_MS),
        );

        let absence =
            remote_claim(producer, 8, vec![(record, Inclusion::Absent)]).naming([(record, id)]);
        let exit = remote_claim(
            producer,
            8,
            vec![
                (row, Inclusion::Absent),
                (marker, Inclusion::Present([3; 32])),
            ],
        );
        assert!(exit.crossings.is_empty() && !exit.holds_a_value());
        let block = past(&absence);
        let fold = |claims: &[StateClaim]| {
            crossing_settlements(claims, local, block, &SettledWrites::default(), &parent).removed
        };
        assert!(fold(from_ref(&absence)).is_empty());
        assert!(fold(from_ref(&exit)).is_empty());

        let cut = [absence, exit];
        assert_eq!(carrying_claims(local, &cut).judged(&parent), Ok(()));
        assert_eq!(fold(&cut), vec![never]);
        assert!(
            FrontierInputs::for_block(&cut, windows(), block, local)
                .marks
                .is_empty(),
            "a block of boundary claims raises nothing",
        );
    }

    /// A reading the fence judges, anchored at or above the floor and
    /// below a claim an earlier block carried that names no crossing and
    /// holds no value, is admitted: a deleting absence and a held record
    /// alike. Below the floor the record is refused and the absence is
    /// not: the fold deletes on none but a boundary reading, which sits
    /// below every floor.
    #[test]
    fn a_fenced_reading_between_the_floor_and_a_bare_claim_is_admitted() {
        let local = ShardId::leaf(1, 0);
        let producer = ShardId::leaf(1, 1);
        let id = crossing(0xAA);
        let record = id.record_key(&ProtocolHasher);
        let other = crossing(0xBB);
        let other_record = other.record_key(&ProtocolHasher);
        let mut parent = Parent::default();
        let floor = [
            remote_claim(producer, 40, vec![(other_record, Inclusion::Absent)])
                .naming([(other_record, other)]),
        ];
        assert_eq!(
            carry(&mut parent, local, &floor),
            BTreeMap::from([(producer, mark(40))]),
        );
        let bare = [remote_claim(
            producer,
            60,
            vec![(test_key(0x90), Inclusion::Present([1; 32]))],
        )];
        assert!(carry(&mut parent, local, &bare).is_empty());
        assert_eq!(
            load_read_frontier(&parent, local).floor(producer),
            Some(mark(40)),
            "the bare claim at 60 left the floor at 40",
        );

        let deletion = |height: u64| {
            [
                remote_claim(producer, height, vec![(record, Inclusion::Absent)])
                    .naming([(record, id)]),
            ]
        };
        let presence = |height: u64| [remote_record_claim(producer, height)];
        assert_eq!(
            carrying_claims(local, &deletion(50)).fence.deletions.len(),
            1,
            "the absence is one the fence judges",
        );
        assert_eq!(
            carrying_claims(local, &deletion(50)).judged(&parent),
            Ok(())
        );
        assert_eq!(
            carrying_claims(local, &presence(50)).judged(&parent),
            Ok(())
        );
        assert_eq!(
            carrying_claims(local, &deletion(39)).judged(&parent),
            Ok(())
        );
        assert!(matches!(
            carrying_claims(local, &presence(39)).judged(&parent),
            Err(ParentRefusal::Frontier(refusal))
                if matches!(*refusal, FrontierRefusal::BelowFloor { .. })
        ));
    }

    /// A crossing whose record another shard holds and whose consumer
    /// `leaf(1, 0)` holds.
    fn inbound_crossing() -> CrossingId {
        CrossingId {
            producer: Address::new([0xC1; 31], AddressClass::Component),
            consumer: Address::new([0x42; 31], AddressClass::Component),
            intent: IntentHash(Hash32([0x61; 32])),
            local: 0,
            output: 0,
        }
    }

    /// A counterpart's claim at `height` holding the escrowed record of
    /// [`inbound_crossing`], named for it.
    fn escrowed_record_claim(producer: ShardId, height: u64) -> StateClaim {
        let id = inbound_crossing();
        let record = id.record_key(&ProtocolHasher);
        let cell = record_cell(id, Terms::Escrowed { credit: record });
        StateClaim::new(
            anchor(producer, height),
            [(record, Stated::Held(Bytes::new(cell.to_bytes()).unwrap()))],
            MerkleInclusionProof::dummy(),
        )
        .naming([(record, id)])
    }

    /// A claim at `local`'s parent reading `tx`'s member row as
    /// `reading`.
    fn row_claim(local: ShardId, tx: TxHash, reading: Inclusion) -> StateClaim {
        StateClaim::new(
            anchor(local, 4),
            [(member_row_leaf(local, tx), reading)],
            MerkleInclusionProof::new(Vec::new()),
        )
    }

    /// `parent` after a block of `chain` commits `tx`, whose row then
    /// stands.
    fn commit_member(parent: &mut Parent, chain: ShardId, tx: TxHash) {
        let writes = member_writes(
            parent,
            &MemberInputs {
                transactions: vec![(tx, Deadline::of(WeightedTimestamp::from_millis(90_000)))],
                terms: vec![stub_stated_terms(tx, 1)],
                ..MemberInputs::still(chain)
            },
        );
        parent.apply(&writes);
    }

    /// A decline is written on the chain's own row of the record's
    /// transaction read absent at the parent, and every voter holds that
    /// reading to the rows its own parent view holds. A block reading
    /// the row absent over a parent where it stands is refused, so no
    /// decline commits while a member of the transaction can still take;
    /// the same block over a parent without the row passes and declines;
    /// and a reading that states the standing row passes and declines
    /// nothing.
    #[test]
    fn a_decline_whose_row_reading_disagrees_with_the_parent_is_refused() {
        let local = ShardId::leaf(1, 0);
        let producer = ShardId::leaf(1, 1);
        let id = inbound_crossing();
        let never = id.answer_key(&ProtocolHasher, Answered::Never);
        let row = member_row_leaf(local, ISSUER);
        let past_end = WeightedTimestamp::from_millis(ISSUER_VALIDITY_END_MS);
        let rowless = Parent::default();
        let mut standing = Parent::default();
        commit_member(&mut standing, local, ISSUER);
        let declines = |claims: &[StateClaim], parent: &Parent| {
            unclaimed_declines(claims, local, past_end, parent)
                .cells
                .contains_key(&never)
        };

        let read_absent = [
            escrowed_record_claim(producer, 5),
            row_claim(local, ISSUER, Inclusion::Absent),
        ];
        assert!(
            declines(&read_absent, &standing),
            "the fold declines on the reading the block carries",
        );
        assert_eq!(
            carrying_claims(local, &read_absent).judged(&standing),
            Err(ParentRefusal::ParentReading(row)),
            "so a voter whose parent holds the row refuses the block",
        );
        assert_eq!(
            carrying_claims(local, &read_absent).judged(&rowless),
            Ok(())
        );
        assert!(declines(&read_absent, &rowless));

        let read_standing = [
            escrowed_record_claim(producer, 5),
            row_claim(
                local,
                ISSUER,
                Inclusion::Present(jmt_value_hash(&standing.cell(row).expect("the row stands"))),
            ),
        ];
        assert_eq!(
            carrying_claims(local, &read_standing).judged(&standing),
            Ok(())
        );
        assert!(!declines(&read_standing, &standing));
        assert_eq!(
            carrying_claims(local, &read_standing).judged(&rowless),
            Err(ParentRefusal::ParentReading(row)),
            "a row stated standing over a parent without it is refused alike",
        );
    }

    /// A proposal reads the row of a record's issuer at its parent
    /// where the parent holds none, and the block it builds passes its
    /// voters' checks and declines the record; over a parent where the
    /// row stands it reads nothing of the row and declines nothing.
    #[test]
    fn a_proposal_reads_the_row_its_decline_stands_on() {
        let local = ShardId::leaf(1, 0);
        let producer = ShardId::leaf(1, 1);
        let never = inbound_crossing().answer_key(&ProtocolHasher, Answered::Never);
        let row = member_row_leaf(local, ISSUER);
        let past_end = WeightedTimestamp::from_millis(ISSUER_VALIDITY_END_MS);
        let mut standing = Parent::default();
        commit_member(&mut standing, local, ISSUER);
        let proposed = |parent: &Parent| {
            let selected = vec![escrowed_record_claim(producer, 5)];
            let fence = read_fence(&selected, windows());
            let frontier = FrontierInputs::for_block(&selected, windows(), past_end, local);
            proposal_claims(
                selected,
                &fence,
                &frontier,
                &[],
                &[ISSUER],
                anchor(local, 4),
                parent,
            )
            .claims
        };

        let rowless = Parent::default();
        let claims = proposed(&rowless);
        assert_eq!(
            claims
                .iter()
                .filter_map(|claim| claim.reading(row))
                .collect::<Vec<_>>(),
            [Inclusion::Absent],
        );
        assert_eq!(carrying_claims(local, &claims).judged(&rowless), Ok(()));
        assert!(
            unclaimed_declines(&claims, local, past_end, &rowless)
                .cells
                .contains_key(&never)
        );

        let claims = proposed(&standing);
        assert!(claims.iter().all(|claim| claim.reading(row).is_none()));
        assert_eq!(carrying_claims(local, &claims).judged(&standing), Ok(()));
        assert_eq!(
            unclaimed_declines(&claims, local, past_end, &standing),
            StateWrites::default(),
        );
    }

    /// A proposal reads a row only for a decline its block carries. The
    /// proposer names its rows off the claims it selected, and the build
    /// cuts what the parent's read frontier refuses afterwards. Where
    /// the cut takes the record reading, the row reading goes with it:
    /// alone it is a parent reading no decline reads, which costs its
    /// bytes and declines nothing. Where the record survives, its row is
    /// read, and no row is read for a record the parent already answers
    /// or whose validity end the block's clock is short of.
    #[test]
    fn a_proposal_reads_no_row_whose_record_the_build_cut() {
        let local = ShardId::leaf(1, 0);
        let producer = ShardId::leaf(1, 1);
        let id = inbound_crossing();
        let row = member_row_leaf(local, ISSUER);
        let past_end = WeightedTimestamp::from_millis(ISSUER_VALIDITY_END_MS);
        let built = |parent: &Parent, clock: WeightedTimestamp| {
            let selected = vec![escrowed_record_claim(producer, 5)];
            let fence = read_fence(&selected, windows());
            let frontier = FrontierInputs::for_block(&selected, windows(), clock, local);
            proposal_claims(
                selected,
                &fence,
                &frontier,
                &[],
                &[ISSUER],
                anchor(local, 4),
                parent,
            )
        };
        let rows_read = |built: &ProposalClaims| {
            built
                .claims
                .iter()
                .filter_map(|claim| claim.reading(row))
                .collect::<Vec<_>>()
        };

        let kept = built(&Parent::default(), past_end);
        assert_eq!(kept.refused, 0);
        assert_eq!(rows_read(&kept), [Inclusion::Absent]);
        assert_eq!(
            decline_rows(&kept.claims, local, past_end, &Parent::default())
                .into_keys()
                .collect::<Vec<_>>(),
            [row],
            "the row read is the one the block's decline reads",
        );

        let mut raised = Parent::default();
        raised.raise(local, &[(producer, mark(9))]);
        let cut = built(&raised, past_end);
        assert_eq!(cut.refused, 1, "the record's stale presence is cut");
        assert!(
            cut.claims.is_empty(),
            "and no row reading rides without it: {:?}",
            cut.claims,
        );

        let mut answered = Parent::default();
        answered.cells.insert(
            id.answer_key(&ProtocolHasher, Answered::Never),
            id.answer(ISSUER, Answered::Never, ISSUER_VALIDITY_END_MS)
                .to_bytes(),
        );
        assert!(
            rows_read(&built(&answered, past_end)).is_empty(),
            "a record its own transaction's answer stands over",
        );
        assert!(
            rows_read(&built(
                &Parent::default(),
                WeightedTimestamp::from_millis(ISSUER_VALIDITY_END_MS - 1),
            ))
            .is_empty(),
            "a record short of its validity end",
        );
    }

    /// A fixture payer and a transaction of `max_fee` it signs alone.
    fn paid(max_fee: u128) -> (Transaction, SubstateKey) {
        let payer = PrincipalAddr::new([0x42; 31]);
        let tx = stub_transaction(
            payer,
            &[payer.address()],
            max_fee,
            TimestampRange::new(
                WeightedTimestamp::ZERO,
                WeightedTimestamp::from_millis(60_000),
            ),
        );
        let vault = FeeTerms::of(&tx).vault;
        (tx, vault)
    }

    /// `parent` holding `balance` in `vault` and `held` reserved against it.
    fn funded(vault: SubstateKey, balance: u128, held: u128) -> Parent {
        let mut parent = Parent::default();
        parent.cells.insert(vault, balance.to_le_bytes().to_vec());
        if held != 0 {
            parent.cells.insert(
                fee_hold_total_key(&ProtocolHasher, vault),
                held.to_le_bytes().to_vec(),
            );
        }
        parent
    }

    /// A vault this shard holds covers what it already holds plus every
    /// charge so far: charges accumulate, and a refused one moves nothing.
    #[test]
    fn a_held_payer_covers_its_holds_and_charges() {
        let (tx, vault) = paid(300);
        let parent = funded(vault, 1_000, 700);
        let mut charges = PayerCharges::new(ShardId::ROOT, &parent);
        assert_eq!(charges.charge(&tx), Ok(()), "700 held + 300 fits 1_000");
        assert_eq!(
            charges.charge(&tx),
            Err(ParentRefusal::UncoveredPayer(vault)),
            "a second 300 does not"
        );
        let (one, _) = paid(0);
        assert_eq!(
            charges.charge(&one),
            Ok(()),
            "the refused charge left the figure at 1_000"
        );

        let empty = Parent::default();
        assert_eq!(
            PayerCharges::new(ShardId::ROOT, &empty).charge(&tx),
            Err(ParentRefusal::UncoveredPayer(vault)),
            "an absent vault holds nothing"
        );
    }

    /// A stored rule that does not admit the attesting set refuses the
    /// fee before any balance is read.
    #[test]
    fn a_payer_whose_rule_refuses_the_signer_refuses_the_fee() {
        let (tx, vault) = paid(1);
        let mut parent = funded(vault, 1_000, 0);
        parent.cells.insert(tx.auth_cell(), vec![0xAB]);
        assert_eq!(
            PayerCharges::new(ShardId::ROOT, &parent).charge(&tx),
            Err(ParentRefusal::UnadmittedPayer(vault))
        );
    }

    /// A payer whose vault another shard holds is that shard's to judge.
    #[test]
    fn a_payer_another_shard_holds_is_not_judged_here() {
        let (tx, vault) = paid(1_000);
        let (left, right) = ShardId::ROOT.children();
        let elsewhere = if key_under_prefix(&vault.to_bytes(), &shard_prefix_path(left)) {
            right
        } else {
            left
        };
        let empty = Parent::default();
        assert_eq!(PayerCharges::new(elsewhere, &empty).charge(&tx), Ok(()));
    }

    /// `parent` after a block of `chain` commits a member reserving
    /// `amount` of `vault`.
    fn reserve(parent: &mut Parent, chain: ShardId, vault: SubstateKey, amount: u128) -> TxHash {
        let member = TxHash::from(Hash::from_bytes(b"reserving"));
        let mut stated = stub_stated_terms(member, 1);
        stated.terms.reserves = Capped::from_array([(vault, amount)]);
        let writes = member_writes(
            parent,
            &MemberInputs {
                transactions: vec![(member, Deadline::of(WeightedTimestamp::from_millis(90_000)))],
                terms: vec![stated],
                ..MemberInputs::still(chain)
            },
        );
        parent.apply(&writes);
        member
    }

    /// `parent` after a block of `chain` settles `member`.
    fn settle(parent: &mut Parent, chain: ShardId, member: TxHash) {
        let writes = member_writes(
            parent,
            &MemberInputs {
                settled: vec![SettledHalf {
                    tick: TickId::new(chain, BlockHeight::new(1)),
                    half: TickHalf::Determined,
                    deleted: vec![member],
                    stated: Vec::new(),
                    accepted: Vec::new(),
                }],
                ..MemberInputs::still(chain)
            },
        );
        parent.apply(&writes);
    }

    /// A vault covers a new hold only beside what a member in flight
    /// reserves of it: the reservation counts as a standing hold does,
    /// to the unit, and a block carrying a hold past it is refused by
    /// the rule's name.
    #[test]
    fn a_hold_behind_a_standing_reservation_is_refused() {
        let (over, vault) = paid(201);
        let (fits, _) = paid(200);
        let mut parent = funded(vault, 1_000, 200);
        assert_eq!(
            PayerCharges::new(ShardId::ROOT, &parent).charge(&over),
            Ok(()),
            "200 held + 201 fits 1_000 with nothing reserved"
        );

        reserve(&mut parent, ShardId::ROOT, vault, 600);
        assert_eq!(
            PayerCharges::new(ShardId::ROOT, &parent).charge(&over),
            Err(ParentRefusal::UncoveredPayer(vault)),
            "200 held + 600 reserved + 201 does not"
        );
        let mut charges = PayerCharges::new(ShardId::ROOT, &parent);
        assert_eq!(charges.charge(&fits), Ok(()), "and 200 does, exactly");
        let (dust, _) = paid(1);
        assert_eq!(
            charges.charge(&dust),
            Err(ParentRefusal::UncoveredPayer(vault)),
            "the block's own charges stand beside both"
        );

        let mut block = Block::empty(ShardId::ROOT);
        block.transactions = Arc::new(Capped::from_array([Arc::new(Verifiable::from(over))]));
        assert_eq!(
            block.judged(&parent),
            Err(ParentRefusal::UncoveredPayer(vault))
        );
    }

    /// The hold a reservation in flight refuses is admitted by the first
    /// parent that no longer holds the reserving member's row.
    #[test]
    fn the_same_hold_is_admitted_once_it_settles() {
        let (tx, vault) = paid(201);
        let mut parent = funded(vault, 1_000, 200);
        let member = reserve(&mut parent, ShardId::ROOT, vault, 600);
        assert_eq!(
            PayerCharges::new(ShardId::ROOT, &parent).charge(&tx),
            Err(ParentRefusal::UncoveredPayer(vault))
        );

        settle(&mut parent, ShardId::ROOT, member);
        assert_eq!(
            PayerCharges::new(ShardId::ROOT, &parent).charge(&tx),
            Ok(())
        );
        let (rest, _) = paid(800);
        assert_eq!(
            PayerCharges::new(ShardId::ROOT, &parent).charge(&rest),
            Ok(()),
            "nothing of the reservation is left behind"
        );
    }

    /// A reserved total is its own chain's: a row of another chain's
    /// family naming this vault counts nothing against the chain that
    /// holds it, and a payer another shard holds is still not judged.
    #[test]
    fn a_reservation_on_another_shards_vault_counts_nothing_here() {
        let (tx, vault) = paid(1_000);
        let (left, right) = ShardId::ROOT.children();
        let (home, elsewhere) = if key_under_prefix(&vault.to_bytes(), &shard_prefix_path(left)) {
            (left, right)
        } else {
            (right, left)
        };
        let mut parent = funded(vault, 1_000, 0);
        reserve(&mut parent, elsewhere, vault, 600);
        assert_eq!(PayerCharges::new(home, &parent).charge(&tx), Ok(()));
        assert_eq!(PayerCharges::new(elsewhere, &parent).charge(&tx), Ok(()));

        reserve(&mut parent, home, vault, 1);
        assert_eq!(
            PayerCharges::new(home, &parent).charge(&tx),
            Err(ParentRefusal::UncoveredPayer(vault)),
            "its own chain's row does"
        );
    }

    /// A proposer drops exactly what its voters would refuse behind a
    /// reservation in flight: the block of what it keeps passes the
    /// parent checks, and the one it would have built without the drop
    /// does not.
    #[test]
    fn a_proposer_keeps_what_its_voters_admit_behind_a_reservation() {
        let selected: Vec<Transaction> = [300, 250, 200]
            .into_iter()
            .map(|max_fee| paid(max_fee).0)
            .collect();
        let (_, vault) = paid(0);
        let mut parent = funded(vault, 1_000, 0);
        reserve(&mut parent, ShardId::ROOT, vault, 500);

        let mut charges = PayerCharges::new(ShardId::ROOT, &parent);
        let kept: Vec<Transaction> = selected
            .iter()
            .filter(|tx| charges.charge(tx).is_ok())
            .cloned()
            .collect();
        assert_eq!(
            kept.iter().map(Transaction::hash).collect::<Vec<_>>(),
            [selected[0].hash(), selected[2].hash()],
            "500 reserved + 300 + 200 fits 1_000, and 250 between them does not"
        );

        let carrying = |txs: &[Transaction]| {
            let mut block = Block::empty(ShardId::ROOT);
            block.transactions = Arc::new(
                Capped::new(
                    txs.iter()
                        .cloned()
                        .map(|tx| Arc::new(Verifiable::from(tx)))
                        .collect(),
                )
                .expect("a few transactions"),
            );
            block
        };
        assert_eq!(carrying(&kept).judged(&parent), Ok(()));
        assert_eq!(
            carrying(&selected).judged(&parent),
            Err(ParentRefusal::UncoveredPayer(vault))
        );
    }

    /// The parent state refuses a block whose payer cannot cover it, by
    /// that rule's name.
    #[test]
    fn a_block_its_payer_cannot_cover_is_refused() {
        let (tx, vault) = paid(301);
        let mut block = Block::empty(ShardId::ROOT);
        block.transactions = Arc::new(Capped::from_array([Arc::new(Verifiable::from(tx))]));
        assert_eq!(
            block.judged(&funded(vault, 1_000, 700)),
            Err(ParentRefusal::UncoveredPayer(vault))
        );
        assert_eq!(block.judged(&funded(vault, 1_001, 700)), Ok(()));
    }

    /// The chain taking records back, and the shard holding their
    /// consumers.
    const PRODUCER: ShardId = ShardId::leaf(1, 0);
    const CONSUMER: ShardId = ShardId::leaf(1, 1);
    const RETURNED: u128 = 250;

    /// A crossing of `output` produced under `PRODUCER` and consumed
    /// under `CONSUMER`.
    fn returnable(output: u32) -> CrossingId {
        CrossingId {
            producer: Address::new([0x21; 31], AddressClass::Component),
            consumer: Address::new([0xA1; 31], AddressClass::Component),
            intent: IntentHash(Hash32([0x21; 32])),
            local: 0,
            output,
        }
    }

    /// The cell a record of the producer's returns to.
    fn credit_cell() -> SubstateKey {
        SubstateKey {
            owner: Address::new([0x21; 31], AddressClass::Component),
            local: LocalKey([0x77; 16]),
        }
    }

    fn issuing() -> TxHash {
        TxHash(Hash32([9; 32]))
    }

    /// `id`'s record, crediting `credit` on its return.
    fn returning_cell(id: CrossingId, credit: SubstateKey) -> CrossingCell {
        id.cell(
            issuing(),
            ResourceAddr::new([0xE0; 31]),
            RETURNED,
            9_000,
            Terms::Escrowed { credit },
        )
    }

    /// A parent holding each of `ids`' records crediting `credit`, and
    /// `credit` holding `held`.
    fn producing(ids: &[CrossingId], credit: SubstateKey, held: Vec<u8>) -> Parent {
        let mut parent = Parent::default();
        for id in ids {
            parent.cells.insert(
                id.record_key(&ProtocolHasher),
                returning_cell(*id, credit).to_bytes(),
            );
        }
        parent.cells.insert(credit, held);
        parent
    }

    /// The consumer's `Never` of the issuing transaction for each of
    /// `ids`, read at one boundary of its shard under one proof.
    fn declined_at_a_boundary(ids: &[CrossingId]) -> StateClaim {
        let held: Vec<(SubstateKey, Vec<u8>)> = ids
            .iter()
            .map(|id| {
                (
                    id.answer_key(&ProtocolHasher, Answered::Never),
                    id.answer(issuing(), Answered::Never, 9_000).to_bytes(),
                )
            })
            .collect();
        let keys: Vec<SubstateKey> = held.iter().map(|(key, _)| *key).collect();
        let (state_root, proof) = state_and_proof_holding(CONSUMER, &held, &keys);
        StateClaim::new(
            Anchor {
                state_root,
                ..anchor(CONSUMER, 2)
            },
            held.iter()
                .map(|(key, bytes)| (*key, Inclusion::Present(jmt_value_hash(bytes)))),
            proof,
        )
        .naming(
            ids.iter()
                .map(|id| (id.answer_key(&ProtocolHasher, Answered::Never), *id)),
        )
    }

    /// Whether any of `claims` reads `key`.
    fn reads(claims: &[StateClaim], key: SubstateKey) -> bool {
        claims
            .iter()
            .any(|claim| claim.keys().into_iter().any(|read| read == key))
    }

    /// A block of `PRODUCER`'s, at a boundary of the consumer's claim,
    /// reading each of `ids`' records at `parent` beside the consumer's
    /// `Never`.
    fn taking_back(ids: &[CrossingId], parent: &Parent) -> Block {
        let mut state_claims = parent_claims(ids, &[], anchor(PRODUCER, 4), parent);
        state_claims.push(declined_at_a_boundary(ids));
        Block {
            members: MemberInputs {
                committed: past(&declined_at_a_boundary(ids)),
                ..MemberInputs::still(PRODUCER)
            },
            state_claims,
            ..Block::empty(PRODUCER)
        }
    }

    /// A block taking back a record its fold would leave standing is
    /// refused at its parent, one refusal for each reason the fold
    /// skips, and passes once the proposer cuts that record's `Never`.
    #[test]
    fn a_block_carrying_a_reclaim_that_cannot_land_is_refused() {
        let id = returnable(0);
        let record = id.record_key(&ProtocolHasher);
        let amount = |held: u128| encode_amount(held).to_vec();
        let lands = producing(&[id], credit_cell(), amount(40));
        assert_eq!(taking_back(&[id], &lands).judged(&lands), Ok(()));

        let elsewhere = SubstateKey {
            owner: id.consumer,
            local: LocalKey([0x77; 16]),
        };
        let mut cases: Vec<(&str, Parent)> = vec![
            (
                "a credit cell outside the chain's prefix",
                producing(&[id], elsewhere, amount(40)),
            ),
            (
                "a credit cell that is the record itself, which holds no amount",
                producing(&[id], record, amount(40)),
            ),
            (
                "a credit cell holding no amount",
                producing(&[id], credit_cell(), vec![1, 2, 3]),
            ),
            (
                "a credit past u128 over what the cell holds",
                producing(&[id], credit_cell(), amount(u128::MAX - RETURNED + 1)),
            ),
        ];
        // The record the credit cell reads as, where it is the record.
        let itself = &mut cases[1].1;
        itself
            .cells
            .insert(record, returning_cell(id, record).to_bytes());
        for (case, parent) in &cases {
            let block = taking_back(&[id], parent);
            assert_eq!(
                block.judged(parent),
                Err(ParentRefusal::Reclaim(record)),
                "{case}"
            );
            let merged = StateWrites::default();
            let cut = Block {
                state_claims: without_refused_reclaims(
                    block.state_claims.clone(),
                    &block.members,
                    &merged,
                    parent,
                ),
                ..taking_back(&[id], parent)
            };
            assert_eq!(cut.judged(parent), Ok(()), "{case}, cut");
            assert!(reclaimed(&cut.state_claims, PRODUCER, cut.members.committed).is_empty());
            assert!(
                !reads(&cut.state_claims, record),
                "{case}: the record's reading goes with its Never"
            );
        }

        // What the block's receipts write beside the return.
        let block = taking_back(&[id], &lands);
        let stands = |merged: StateWrites| {
            reclaim_stands(&block.state_claims, &block.members, &merged, &lands)
        };
        assert!(stands(StateWrites::default()).is_empty());
        let mut outright = StateWrites::default();
        outright.cells.insert(credit_cell(), Some(amount(7)));
        assert_eq!(
            stands(outright),
            vec![record],
            "a credit cell the block writes outright"
        );
        let mut rewritten = StateWrites::default();
        rewritten.cells.insert(record, None);
        assert_eq!(stands(rewritten), vec![record], "a record the block writes");
        let mut other = StateWrites::default();
        other.movements.insert(
            credit_cell(),
            Movement::debit(ResourceAddr::new([0xE7; 31]), 1),
        );
        let cut =
            without_refused_reclaims(block.state_claims.clone(), &block.members, &other, &lands);
        assert!(
            reclaimed(&cut, PRODUCER, block.members.committed).is_empty() && !reads(&cut, record),
            "a return beside another resource's movement is cut with its reading",
        );
        assert_eq!(
            stands(other),
            vec![record],
            "a credit cell the block moves another resource on"
        );
        let mut same = StateWrites::default();
        same.movements.insert(
            credit_cell(),
            Movement::debit(ResourceAddr::new([0xE0; 31]), 1),
        );
        assert!(
            stands(same).is_empty(),
            "a movement of the record's own resource composes"
        );
    }

    /// Two records returning to one cell whose credits together run past
    /// `u128` are not both taken back in one block: the first in key
    /// order lands, the proposer cuts the second's `Never`, and the
    /// second lands in a later block once the cell has room.
    #[test]
    fn same_block_credits_past_u128_wait_a_block() {
        let (first, second) = (returnable(0), returnable(1));
        let ids = if first.record_key(&ProtocolHasher) < second.record_key(&ProtocolHasher) {
            [first, second]
        } else {
            [second, first]
        };
        let near = u128::MAX - RETURNED - RETURNED / 2;
        let parent = producing(&ids, credit_cell(), encode_amount(near).to_vec());
        let block = taking_back(&ids, &parent);
        assert_eq!(
            block.judged(&parent),
            Err(ParentRefusal::Reclaim(ids[1].record_key(&ProtocolHasher)))
        );
        let merged = StateWrites::default();
        let cut = Block {
            state_claims: without_refused_reclaims(
                block.state_claims.clone(),
                &block.members,
                &merged,
                &parent,
            ),
            ..taking_back(&ids, &parent)
        };
        assert_eq!(cut.judged(&parent), Ok(()));
        let landed = reclaim_credits(
            &reclaimed(&cut.state_claims, PRODUCER, cut.members.committed),
            PRODUCER,
            &merged,
            &parent,
        );
        assert_eq!(
            landed.cells.keys().copied().collect::<Vec<_>>(),
            vec![ids[0].record_key(&ProtocolHasher)],
        );

        // The next block, over a cell something has drawn down since.
        let mut after = producing(&ids[1..], credit_cell(), encode_amount(near).to_vec());
        after
            .cells
            .insert(credit_cell(), encode_amount(u128::MAX - RETURNED).to_vec());
        let next = taking_back(&ids[1..], &after);
        assert_eq!(next.judged(&after), Ok(()));
        assert_eq!(
            reclaimed(&next.state_claims, PRODUCER, next.members.committed).len(),
            1
        );
    }

    /// A block reads at its parent only the keys of a crossing its own
    /// chain holds: of a record whose consumer is elsewhere, the record
    /// alone, never the answer keys another shard holds.
    #[test]
    fn a_record_is_read_at_the_parent_without_its_consumers_cells() {
        let id = returnable(0);
        let parent = producing(&[id], credit_cell(), encode_amount(40).to_vec());
        let claims = parent_claims(&[id], &[], anchor(PRODUCER, 4), &parent);
        let keys: Vec<SubstateKey> = claims.iter().flat_map(StateClaim::keys).collect();
        assert_eq!(keys, vec![id.record_key(&ProtocolHasher)]);
    }

    /// A chain holding both ends of a crossing reads its record and its
    /// `Never` at its own parent, and takes the record back there: no
    /// boundary of another shard is read.
    #[test]
    fn a_merged_chain_takes_back_at_its_own_parent() {
        let id = CrossingId {
            consumer: Address::new([0x22; 31], AddressClass::Component),
            ..returnable(0)
        };
        let record = id.record_key(&ProtocolHasher);
        let mut parent = producing(&[id], credit_cell(), encode_amount(40).to_vec());
        parent.cells.insert(
            id.answer_key(&ProtocolHasher, Answered::Never),
            id.answer(issuing(), Answered::Never, 9_000).to_bytes(),
        );
        let block = Block {
            members: MemberInputs {
                committed: WeightedTimestamp::from_millis(5_000),
                ..MemberInputs::still(PRODUCER)
            },
            state_claims: parent_claims(&[id], &[], anchor(PRODUCER, 4), &parent),
            ..Block::empty(PRODUCER)
        };
        assert_eq!(block.judged(&parent), Ok(()));
        let taken = reclaimed(&block.state_claims, PRODUCER, block.members.committed);
        assert_eq!(taken.len(), 1);
        let landed = reclaim_credits(&taken, PRODUCER, &StateWrites::default(), &parent);
        assert_eq!(landed.cells, BTreeMap::from([(record, None)]));
        assert_eq!(landed.movements[&credit_cell()].credit, RETURNED);

        // A return to a cell holding no amount: the `Never` is cut, and
        // the record, read at the parent for more than its return, stays.
        parent.cells.insert(credit_cell(), vec![1, 2, 3]);
        let cut = without_refused_reclaims(
            block.state_claims.clone(),
            &block.members,
            &StateWrites::default(),
            &parent,
        );
        assert!(reclaimed(&cut, PRODUCER, block.members.committed).is_empty());
        assert!(!reads(
            &cut,
            id.answer_key(&ProtocolHasher, Answered::Never)
        ));
        assert!(reads(&cut, record));
    }
}
