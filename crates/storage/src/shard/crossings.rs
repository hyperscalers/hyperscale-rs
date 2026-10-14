//! The crossing settlements and credits a block's claims license,
//! applied in its commit fold.
//!
//! A producer's record is removed once its consumer's `Taken` of the
//! record's own transaction is read present, and a consumer's answer is
//! removed once the record it answers for is read absent, with its
//! producing member's exit, at a boundary the beacon recorded for the
//! record's shard. Each is a value-free write the evidence for is a
//! reading the block carries, so every voter recomputes it inside
//! `state_root` and no member runs for it. What retires a record is the
//! claim's own rule, [`StateClaim::retires`]; what removes an answer
//! reads the answer, so it is decided here, where the readings meet the
//! state the block lands on.
//!
//! An answer is the one trace that its record was taken or refused. A
//! recovery of the record's shard discards that shard's chain above its
//! last recorded boundary, and a retirement discarded with it leaves the
//! record standing again: with the answer still here the record meets
//! it, is credited or taken no second time and is retired again. So an
//! answer goes only on a reading no recovery discards.
//!
//! An owed crossing's consumer runs no member either: a valued reading
//! of the record, with no `Taken` of its transaction standing in the
//! parent, credits the consumer's vault and writes the `Taken` in the
//! same fold.
//!
//! An escrowed crossing's consumer declines in the fold too: a valued
//! reading of the record past its transaction's validity end, with no
//! answer of that transaction standing in the parent and the chain's own
//! row of it read absent there, writes the `Never` a refusal would have
//! written, for a record no member of this chain can take any more.
//!
//! And an escrowed record's producer takes it back in the fold: the
//! record as the parent holds it, read beside its consumer's `Never` of
//! the record's own transaction at a boundary of the consumer's shard,
//! is removed and its amount credited to the cell it left. A `Never` a
//! recovery of the consumer's shard can discard takes nothing back.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    Anchor, Inclusion, Issuer, Movement, ProtocolHasher, SettledWrites, ShardId, ShardTrie,
    StateClaim, StateWrites, SubstateKey, TxHash, WeightedTimestamp, read_amount,
};
use hyperscale_vm_effects::{
    Answered, Crossing, CrossingAnswer, CrossingCell, CrossingId, CrossingLeaf, Terms,
};

use crate::Substates;
use crate::shard::members::member_row_leaf;
use crate::shard::sweep::committed_tx_cell_key;
use crate::shard::writes::fold_state_writes;

/// Among the held readings of the key the block carries, the one at
/// the newest anchor by weighted time, decoded as a crossing leaf.
///
/// `Some` only for a record, and a bare presence of the key licenses
/// nothing — a reading that carries no value says nothing an arrival
/// can be composed from.
///
/// The arrival a consuming core runs against. The answer does not
/// depend on how many readings of the key a block carries or in what
/// order.
#[must_use]
pub fn live_record(
    state_claims: &[StateClaim],
    key: SubstateKey,
) -> Option<(Crossing, CrossingCell)> {
    state_claims
        .iter()
        .filter_map(|claim| claim.held(key).map(|bytes| (claim.anchor.ts, bytes)))
        .max_by_key(|(ts, _)| *ts)
        .and_then(
            |(_, bytes)| match CrossingLeaf::read(&ProtocolHasher, key, bytes)? {
                CrossingLeaf::Record { crossing, cell } => Some((crossing, cell)),
                CrossingLeaf::Answer { .. } => None,
            },
        )
}

/// Every record `state_claims` read live, with the transaction that
/// issued it.
///
/// The crossings a consumer here waiting on them counts as arrived. Off
/// [`live_record`], so the reading a member runs against is the one that
/// counts.
#[must_use]
pub fn record_arrivals(state_claims: &[StateClaim]) -> BTreeSet<(SubstateKey, TxHash)> {
    let keys: BTreeSet<SubstateKey> = state_claims.iter().flat_map(StateClaim::keys).collect();
    keys.into_iter()
        .filter_map(|key| live_record(state_claims, key).map(|(_, cell)| (key, cell.tx)))
        .collect()
}

/// Every key `state_claims` read absent.
fn absences(state_claims: &[StateClaim]) -> BTreeSet<SubstateKey> {
    state_claims
        .iter()
        .flat_map(|claim| claim.cells.iter())
        .filter(|(_, stated)| stated.inclusion() == Inclusion::Absent)
        .map(|(key, _)| *key)
        .collect()
}

/// The credits the owed records `state_claims` read license, with the
/// `Taken` answer each writes: what the consumer's commit fold lands in
/// place of a member taking the crossing.
///
/// A reading credits where it names its crossing at the crossing's own
/// record key, carries the record's value, the value reads as an owed
/// record of that crossing, and `state` holds no `Taken` of the
/// record's transaction for it. The guard is read in the parent, and a
/// record credits at most once in a block, and not at all beside an
/// absence of the same key the block carries. So one owed record is
/// credited once: within a block by the last rule, and across blocks by
/// the `Taken` it writes, which stands until a boundary of the record's
/// shard shows the record gone for good.
///
/// A `Taken` of another transaction answered a record that stood at
/// this key before and guards nothing of this one: the credit lands and
/// its own `Taken` is written over the other.
///
/// Reads block content and one parent point per reading, and never
/// fails: a reading that does not decode licenses nothing.
#[must_use]
pub fn owed_credits(state_claims: &[StateClaim], state: &(impl Substates + ?Sized)) -> StateWrites {
    let absent = absences(state_claims);
    let mut credited: BTreeSet<SubstateKey> = BTreeSet::new();
    let mut writes = StateWrites::default();
    for claim in state_claims {
        for (key, id) in claim.crossings.iter() {
            if *key != id.record_key(&ProtocolHasher) || absent.contains(key) {
                continue;
            }
            let Some(bytes) = claim.held(*key) else {
                continue;
            };
            let Some(CrossingLeaf::Record { crossing, cell }) =
                CrossingLeaf::read(&ProtocolHasher, *key, bytes)
            else {
                continue;
            };
            if cell.terms != Terms::Owed || crossing.id != *id {
                continue;
            }
            let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
            let answered = state
                .cell(taken)
                .is_some_and(|value| Issuer::from(&cell).answered_by(id, Answered::Taken, &value));
            if answered || !credited.insert(*key) {
                continue;
            }
            let mut credit = StateWrites::default();
            credit.cells.insert(
                taken,
                Some(
                    id.answer(cell.tx, Answered::Taken, cell.validity_end_ms)
                        .to_bytes(),
                ),
            );
            credit.movements.insert(
                id.owed_credit(&ProtocolHasher, cell.resource),
                Movement {
                    resource: cell.resource,
                    credit: cell.amount,
                    debit: 0,
                    unjudged_debit: 0,
                },
            );
            fold_state_writes(&mut writes, &credit);
        }
    }
    writes
}

/// The escrowed records `state_claims` read live for a consumer `local`
/// holds, each with the crossing its reading names, ascending by record
/// key and each once.
///
/// A reading counts where it names its crossing and carries the
/// record's value, the value reads as an escrowed record of that
/// crossing, it is the newest held reading of the key the block carries
/// ([`live_record`]), and the block carries no absence of the key. A
/// record's key names its producer, intent and output and no consumer,
/// so the crossing a reading names is held to the one its value states:
/// a reading named for another consumer is no record of that consumer's.
#[must_use]
pub fn unclaimed_records(
    state_claims: &[StateClaim],
    local: ShardId,
) -> Vec<(CrossingId, CrossingCell)> {
    let absent = absences(state_claims);
    let mut records: BTreeMap<SubstateKey, (CrossingId, CrossingCell)> = BTreeMap::new();
    for claim in state_claims {
        for (key, id) in claim.crossings.iter() {
            if absent.contains(key) || !ShardTrie::shard_owns_prefix(local, id.consumer) {
                continue;
            }
            let Some(CrossingLeaf::Record { crossing, cell }) = claim
                .held(*key)
                .and_then(|bytes| CrossingLeaf::read(&ProtocolHasher, *key, bytes))
            else {
                continue;
            };
            if matches!(cell.terms, Terms::Escrowed { .. })
                && crossing.id == *id
                && live_record(state_claims, *key) == Some((crossing, cell))
            {
                records.insert(*key, (*id, cell));
            }
        }
    }
    records.into_values().collect()
}

/// The records of [`unclaimed_records`] that `local`'s chain declines
/// in the block it commits at `anchor` over `state`, once the block
/// reads the row of the record's transaction absent.
///
/// `anchor` is at or past the record's validity end, and `state` holds
/// no `Taken` and no `Never` of the record's transaction for the
/// crossing.
fn declinable(
    state_claims: &[StateClaim],
    local: ShardId,
    anchor: WeightedTimestamp,
    state: &(impl Substates + ?Sized),
) -> Vec<(CrossingId, CrossingCell)> {
    unclaimed_records(state_claims, local)
        .into_iter()
        .filter(|(id, cell)| {
            let issuer = Issuer::from(cell);
            anchor >= WeightedTimestamp::from_millis(cell.validity_end_ms)
                && ![Answered::Taken, Answered::Never]
                    .into_iter()
                    .any(|answered| {
                        state
                            .cell(id.answer_key(&ProtocolHasher, answered))
                            .is_some_and(|value| issuer.answered_by(id, answered, &value))
                    })
        })
        .collect()
}

/// The member rows a decline of `state_claims` reads on `local`, in the
/// block it commits at `anchor` over `state`.
///
/// The row leaf of the transaction that issued each record the block
/// would decline, with that transaction.
/// A claim anchored on `local` reading one of these leaves absent is
/// the reading [`unclaimed_declines`] writes on, and a row leaf this
/// does not name is one no decline of the block reads. So these are the
/// rows a builder reads at its parent.
#[must_use]
pub fn decline_rows(
    state_claims: &[StateClaim],
    local: ShardId,
    anchor: WeightedTimestamp,
    state: &(impl Substates + ?Sized),
) -> BTreeMap<SubstateKey, TxHash> {
    declinable(state_claims, local, anchor, state)
        .into_iter()
        .map(|(_, cell)| (member_row_leaf(local, cell.tx), cell.tx))
        .collect()
}

/// The `Never` answers `local`'s chain writes, in the block it commits
/// at `anchor`, for the escrowed records `state_claims` read that no
/// member here can take any more.
///
/// A reading declines where it names its crossing, carries the record's
/// value, the value reads as an escrowed record of that crossing whose
/// consumer sits under `local`, the block carries no absence of the
/// key, `anchor` is at or past the record's validity end, `state` holds
/// no `Taken` and no `Never` of the record's transaction for the
/// crossing, and a claim anchored on `local` reads the member row of
/// that transaction on `local` absent. The `Never` names the record's
/// own transaction and is written seen: its record was read.
///
/// No member of the transaction takes the record at or after such a
/// block. A row is written only by a block committing the transaction,
/// a block admits a transaction only while its validity range holds the
/// block's anchor, and a member holds its row from its commit to the
/// block that lands its writes. So with the clock at or past the end
/// and the row absent at the parent, no member of this chain stands and
/// none can be made on it.
///
/// Nor can one be made on a successor. A block anchored past its
/// shard's cut is a coast block, which voters refuse where it carries
/// any state claim, so every declining block is anchored at or below
/// the cut and declines a record whose validity end is at or below it.
/// A merged chain's first anchor is the cut and a split child's is its
/// parent's final clock, neither below any anchor a predecessor
/// declined at, and a validity range excludes its end, so no block of a
/// successor admits the transaction. A successor reads its own row for
/// a record its predecessor left undeclined.
///
/// The row is read in the block, at its parent, and never from `state`:
/// a follower holding one prefix of the chain's tree holds the
/// consumer's cells or the rows and not always both, and every voter
/// held the reading to its own parent view before the block committed.
/// A `Taken` of the transaction standing in `state` is a record taken
/// once and standing again after a recovery of its shard, which is
/// retired on that `Taken` and not declined. A `Never` of another
/// transaction answered a record that stood at this key before and is
/// written over.
///
/// Reads block content and two parent points per record, and never
/// fails: a reading that does not decode licenses nothing.
#[must_use]
pub fn unclaimed_declines(
    state_claims: &[StateClaim],
    local: ShardId,
    anchor: WeightedTimestamp,
    state: &(impl Substates + ?Sized),
) -> StateWrites {
    let rowless = |tx: TxHash| {
        let row = member_row_leaf(local, tx);
        state_claims.iter().any(|claim| {
            claim.anchor.shard == local && claim.reading(row) == Some(Inclusion::Absent)
        })
    };
    let mut writes = StateWrites::default();
    for (id, cell) in declinable(state_claims, local, anchor, state) {
        if !rowless(cell.tx) {
            continue;
        }
        writes.cells.insert(
            id.answer_key(&ProtocolHasher, Answered::Never),
            Some(
                id.answer(cell.tx, Answered::Never, cell.validity_end_ms)
                    .to_bytes(),
            ),
        );
    }
    writes
}

/// The escrowed records a block of `local`'s chain, committed at
/// `anchor`, takes back, each with its value as the block reads it,
/// ascending by key and each once.
///
/// A record is taken back where the block carries both its consumer's
/// `Never` of the record's own transaction and the record itself as the
/// parent holds it, and does not retire it. The record is a held
/// reading of its key, named for its crossing, in a claim anchored on
/// `local`: the parent, which every voter re-reads from its own view.
/// The `Never` is a reading of the crossing's decline key present, named
/// for the crossing, stating the hash of a `Never` that transaction
/// writes ([`StateClaim::answers`]), at a boundary of the block
/// ([`StateClaim::at_boundary`]) or at the parent of a chain holding
/// both ends. A recovery of the consumer's shard discards none of its
/// state at a boundary the beacon recorded, which is what the vote
/// fence holds a boundary claim's anchor to, so no `Never` it discards
/// takes anything back. A block reading the record's `Taken` of the
/// same transaction present retires the record and credits nothing
/// back.
///
/// Reads the block alone: the record's issuer is the parent reading's,
/// so a follower holding the half without the record names what the
/// committer named.
#[must_use]
pub fn reclaimed(
    state_claims: &[StateClaim],
    local: ShardId,
    anchor: WeightedTimestamp,
) -> Vec<(SubstateKey, CrossingCell)> {
    let mut held: BTreeMap<SubstateKey, (CrossingId, CrossingCell)> = BTreeMap::new();
    for claim in state_claims
        .iter()
        .filter(|claim| claim.anchor.shard == local)
    {
        for (key, id) in claim.crossings.iter() {
            if *key != id.record_key(&ProtocolHasher) {
                continue;
            }
            let Some(CrossingLeaf::Record { crossing, cell }) = claim
                .held(*key)
                .and_then(|bytes| CrossingLeaf::read(&ProtocolHasher, *key, bytes))
            else {
                continue;
            };
            if crossing.id == *id && matches!(cell.terms, Terms::Escrowed { .. }) {
                held.insert(*key, (*id, cell));
            }
        }
    }
    held.into_iter()
        .filter(|(_, (id, cell))| {
            let issuer = Issuer::from(cell);
            let never = id.answer_key(&ProtocolHasher, Answered::Never);
            let declined = state_claims.iter().any(|claim| {
                (claim.anchor.shard == local || claim.at_boundary(anchor))
                    && claim.crossing_of(never) == Some(*id)
                    && claim.answers(id, issuer, Answered::Never)
            });
            let retired = state_claims.iter().any(|claim| {
                !claim
                    .retires(|named| (named == id).then_some(issuer))
                    .is_empty()
            });
            declined && !retired
        })
        .map(|(key, (_, cell))| (key, cell))
        .collect()
}

/// The cell an escrowed record's return credits, and what it moves
/// there. Nothing for an owed record, which no cell takes back.
const fn credit_of(cell: &CrossingCell) -> Option<(SubstateKey, Movement)> {
    let Terms::Escrowed { credit } = cell.terms else {
        return None;
    };
    Some((
        credit,
        Movement {
            resource: cell.resource,
            credit: cell.amount,
            debit: 0,
            unjudged_debit: 0,
        },
    ))
}

/// What taking back the record `cell` at `key` writes: the record
/// removed, and its amount credited to the cell its terms name. Nothing
/// for an owed record.
fn returned(key: SubstateKey, cell: &CrossingCell) -> StateWrites {
    let mut writes = StateWrites::default();
    if let Some((credit, movement)) = credit_of(cell) {
        writes.cells.insert(key, None);
        writes.movements.insert(credit, movement);
    }
    writes
}

/// What taking back every record of `reclaimed` writes, none skipped.
///
/// A follower's, holding one prefix of the chain's tree, which may hold
/// the credit cell and not the record. Every voter held the block to
/// [`reclaim_credits`] landing each one, so this is what the committer
/// wrote.
#[must_use]
pub(crate) fn reclaim_writes(reclaimed: &[(SubstateKey, CrossingCell)]) -> StateWrites {
    let mut writes = StateWrites::default();
    for (key, cell) in reclaimed {
        fold_state_writes(&mut writes, &returned(*key, cell));
    }
    writes
}

/// What taking back the records of `reclaimed` writes on `local`'s
/// chain over `state`, the parent.
///
/// Each record is removed and its amount credited to the cell its terms
/// name, records crediting one cell composing into one movement, beside
/// `merged`, what the block's receipts, owed credits, declines and fates
/// write.
///
/// Total, and in key order. A record is left standing, and writes
/// nothing, where `state` does not hold it as the block read it;
/// `merged` writes the record's key; its credit cell is outside
/// `local`'s prefix; `merged` writes the credit cell outright; the cell
/// holds bytes that are no amount, the record's own among them;
/// `merged` moves another resource on it; or the credit,
/// composed with what `merged` moves there and the returns before it,
/// runs past `u128` over what the cell holds. A block carrying a record
/// this leaves standing is refused at the vote, so every one a
/// committed block carries lands.
#[must_use]
pub fn reclaim_credits(
    reclaimed: &[(SubstateKey, CrossingCell)],
    local: ShardId,
    merged: &StateWrites,
    state: &(impl Substates + ?Sized),
) -> StateWrites {
    let mut writes = StateWrites::default();
    for (key, cell) in reclaimed {
        let Terms::Escrowed { credit } = cell.terms else {
            continue;
        };
        let stands = state
            .cell(*key)
            .and_then(|bytes| CrossingCell::from_bytes(&bytes))
            .is_some_and(|standing| standing == *cell);
        if !stands || merged.cells.contains_key(key) || merged.cells.contains_key(&credit) {
            continue;
        }
        let before = [&merged.movements, &writes.movements]
            .into_iter()
            .filter_map(|movements| movements.get(&credit).copied());
        if credit_lands(cell, local, state.cell(credit).as_deref(), before) {
            fold_state_writes(&mut writes, &returned(*key, cell));
        }
    }
    writes
}

/// Whether returning the escrowed record `cell` lands its credit on
/// `local`'s chain, where the credit cell holds `held`, after `before`,
/// what the block already moves on that cell.
///
/// It lands where the credit cell is under `local`'s prefix, holds no
/// bytes or an amount, and the credit, composed after `before`, moves
/// one resource and stays within `u128` over what the cell holds. The
/// one rule a return's credit is judged by: the fold's, and the
/// producer's before it offers the return.
#[must_use]
pub fn credit_lands(
    cell: &CrossingCell,
    local: ShardId,
    held: Option<&[u8]>,
    before: impl IntoIterator<Item = Movement>,
) -> bool {
    let Some((credit, movement)) = credit_of(cell) else {
        return false;
    };
    let Some(held) = held.map_or(Some(0), read_amount) else {
        return false;
    };
    ShardTrie::shard_owns_prefix(local, credit.owner)
        && before
            .into_iter()
            .chain([movement])
            .try_fold(Movement::none(cell.resource), |composed, next| {
                composed.then(next).ok()
            })
            .and_then(|composed| composed.apply(held))
            .is_some()
}

/// What a block's claims do to the crossing families, read against the
/// state it lands on.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CrossingSettlements {
    /// The cells removed, ascending and each once.
    pub removed: Vec<SubstateKey>,
    /// The unseen `Never`s a presence of their record marks seen, with
    /// their bytes.
    pub seen: Vec<(SubstateKey, Vec<u8>)>,
}

/// What `state_claims` do to the crossing families of `state`, the
/// block `local`'s chain commits at `anchor` landing on it.
///
/// Every key `written` writes is left alone: a receipt is its member's
/// own decision and always lands.
///
/// - A record whose `Taken` is read present as the answer to it is
///   removed ([`StateClaim::retires`], over the record `state` holds).
/// - An answer whose record is read absent, under the crossing's name,
///   is removed where the claim is anchored on this chain itself (a
///   crossing a merge brought together, read at the parent), or where
///   the claim is at a boundary of the block
///   ([`StateClaim::at_boundary`]) and its producer member's exit is
///   proven at that anchor ([`exit_proven`]). A fresh absence removes
///   nothing, whatever the answer says of itself.
/// - An unseen `Never` whose record is read present is marked seen.
///
/// The fold tells a boundary reading by its age against the block, and
/// reads no schedule: that the anchor is a boundary the beacon recorded
/// is what every voter held the block to before it committed.
///
/// A key absent from `state` has nothing to remove: a record already
/// reclaimed, an answer already deleted, or a cell under a prefix a
/// follower does not hold.
#[must_use]
pub fn crossing_settlements(
    state_claims: &[StateClaim],
    local: ShardId,
    anchor: WeightedTimestamp,
    written: &SettledWrites,
    state: &(impl Substates + ?Sized),
) -> CrossingSettlements {
    let untouched = |key: &SubstateKey| !written.cells().contains_key(key);
    let standing = |id: &CrossingId| {
        state
            .cell(id.record_key(&ProtocolHasher))
            .and_then(|value| Issuer::of_record(id, &value))
    };
    let mut removed: BTreeSet<SubstateKey> = state_claims
        .iter()
        .flat_map(|claim| claim.retires(standing))
        .map(|(key, _)| key)
        .filter(untouched)
        .collect();
    for claim in state_claims {
        for (key, id) in claim.crossings.iter() {
            if *key != id.record_key(&ProtocolHasher)
                || claim.reading(*key) != Some(Inclusion::Absent)
            {
                continue;
            }
            for answered in [Answered::Taken, Answered::Never] {
                let answer_key = id.answer_key(&ProtocolHasher, answered);
                if !untouched(&answer_key) {
                    continue;
                }
                let Some(bytes) = state.cell(answer_key) else {
                    continue;
                };
                let deletes = claim.anchor.shard == local
                    || (claim.at_boundary(anchor)
                        && CrossingAnswer::from_bytes(&bytes).is_none_or(|answer| {
                            exit_proven(state_claims, &claim.anchor, &answer)
                        }));
                if deletes {
                    removed.insert(answer_key);
                }
            }
        }
    }
    let mut seen: BTreeMap<SubstateKey, Vec<u8>> = BTreeMap::new();
    for claim in state_claims {
        for (key, id) in claim.crossings.iter() {
            if *key != id.record_key(&ProtocolHasher)
                || !matches!(claim.reading(*key), Some(Inclusion::Present(_)))
            {
                continue;
            }
            let never = id.answer_key(&ProtocolHasher, Answered::Never);
            if !untouched(&never) || removed.contains(&never) {
                continue;
            }
            let Some(answer) = state
                .cell(never)
                .as_deref()
                .and_then(CrossingAnswer::from_bytes)
            else {
                continue;
            };
            if !answer.seen {
                seen.insert(never, answer.seen_now().to_bytes());
            }
        }
    }
    CrossingSettlements {
        removed: removed.into_iter().collect(),
        seen: seen.into_iter().collect(),
    }
}

/// Whether the claims prove, at exactly `anchor`, that the producing
/// member of `answer`'s transaction on the anchor's shard has exited or
/// never existed and can never commit: its member row read absent, and
/// either the transaction's committed marker read present or the anchor
/// at or past the transaction's validity end.
///
/// With either, the shard cannot commit the transaction after the
/// anchor: it commits a transaction once, and admits none past its
/// validity end. A row is written by the block committing the
/// transaction and goes with its member's finalization, which lands the
/// member's own writes in the same block, or with a fate. Neither a fate
/// nor a return writes the record, and no line runs a member whose row
/// is gone, so with the row gone nothing writes the record again on any
/// chain extending the anchor, and its absence there stands for good. A
/// return deletes no row: a leg whose record went back without its ever
/// running keeps its row until its fate at the close of its leg entry
/// window, and proves no exit before it. A boundary taken
/// before the record was written shows the row standing, or the clock
/// short of the validity end with no marker, and proves nothing.
/// Readings at different anchors never combine.
fn exit_proven(state_claims: &[StateClaim], anchor: &Anchor, answer: &CrossingAnswer) -> bool {
    let validity_end = WeightedTimestamp::from_millis(answer.validity_end_ms);
    let row = member_row_leaf(anchor.shard, answer.tx);
    let marker = committed_tx_cell_key(anchor.shard, answer.tx, validity_end);
    let at_anchor = || state_claims.iter().filter(|claim| claim.anchor == *anchor);
    let row_gone = at_anchor().any(|claim| claim.reading(row) == Some(Inclusion::Absent));
    let committed =
        at_anchor().any(|claim| matches!(claim.reading(marker), Some(Inclusion::Present(_))));
    row_gone && (committed || anchor.ts >= validity_end)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::iter::once;
    use std::slice::from_ref;
    use std::sync::Arc;
    use std::time::Duration;

    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_types::state_key::jmt_value_hash;
    use hyperscale_types::test_utils::{stub_abort_charge, stub_stated_terms, test_key};
    use hyperscale_types::{
        Address, AddressClass, Anchor, BlockHeight, CollectionId, Deadline, EpochWindows,
        FrontierInputs, Hash, LocalKey, MemberTerms, MerkleInclusionProof, RETENTION_HORIZON,
        ReadFence, ReadFrontier, ReadMark, Reading, ResourceAddr, Settlement, ShardId, StateRoot,
        Stated, StatedTerms, TickHalf, TickId, TickLine, TxHash, WeightedTimestamp, encode_amount,
    };
    use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash};
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::*;
    use crate::shard::members::{MemberIndex, MemberInputs, RowState, SettledHalf};

    /// A store of cells alone.
    struct Cells(BTreeMap<SubstateKey, Vec<u8>>);

    impl Substates for Cells {
        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            self.0.get(&key).cloned()
        }

        fn entries_in_range(
            &self,
            _owner: Address,
            _collection: CollectionId,
            _lo: u128,
            _hi: u128,
            _limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            Vec::new()
        }
    }

    fn crossing(seed: u8) -> CrossingId {
        CrossingId {
            producer: Address::new([seed; 31], AddressClass::Component),
            consumer: Address::new([seed | 0x80; 31], AddressClass::Component),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        }
    }

    fn claim(readings: Vec<(SubstateKey, Inclusion, CrossingId)>) -> StateClaim {
        StateClaim::new(
            Anchor {
                shard: ShardId::leaf(1, 1),
                height: BlockHeight::new(4),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(4_000),
            },
            readings
                .iter()
                .map(|(key, inclusion, _)| (*key, *inclusion)),
            MerkleInclusionProof::dummy(),
        )
        .naming(readings.into_iter().map(|(key, _, id)| (key, id)))
    }

    /// The fold removes what the claims license and the state holds,
    /// leaves a key a receipt writes to the receipt, writes nothing for
    /// a key absent from the state, and names a key licensed twice once.
    #[test]
    fn the_fold_removes_what_is_licensed_and_present() {
        let retired = crossing(0x11);
        let answered = crossing(0x12);
        let gone = crossing(0x13);
        let written = crossing(0x14);
        let key = |id: &CrossingId, answered: Option<Answered>| {
            answered.map_or_else(
                || id.record_key(&ProtocolHasher),
                |answered| id.answer_key(&ProtocolHasher, answered),
            )
        };
        let state = Cells(BTreeMap::from([
            (key(&retired, None), escrowed(&retired, issuer())),
            (
                key(&answered, Some(Answered::Taken)),
                answered
                    .answer(issuer(), Answered::Taken, VALIDITY_END_MS)
                    .to_bytes(),
            ),
            (key(&written, None), escrowed(&written, issuer())),
            (test_key(0x50), vec![5]),
        ]));
        let receipts =
            SettledWrites::from_absolutes(BTreeMap::from([(key(&written, None), Some(vec![9]))]));
        let (row, _) = exit_keys();
        let claims = vec![
            claim_at(
                4,
                VALIDITY_END_MS,
                vec![
                    taken_by(&retired, issuer()),
                    (key(&answered, None), Inclusion::Absent, answered),
                    taken_by(&gone, issuer()),
                    taken_by(&written, issuer()),
                ],
                vec![(row, Inclusion::Absent)],
            ),
            claim_at(
                5,
                VALIDITY_END_MS,
                vec![taken_by(&retired, issuer())],
                vec![],
            ),
        ];
        let mut expected = vec![key(&retired, None), key(&answered, Some(Answered::Taken))];
        expected.sort_unstable();
        assert_eq!(
            crossing_settlements(&claims, ELSEWHERE, past(&claims), &receipts, &state).removed,
            expected,
            "the retired record and the answered crossing's Taken go; the Never absent from \
             the state, the record already gone and the key a receipt writes do not",
        );
        assert!(
            crossing_settlements(&[], ELSEWHERE, WeightedTimestamp::ZERO, &receipts, &state)
                == CrossingSettlements::default(),
            "no claim licenses nothing",
        );
    }

    /// The escrowed record of `id` that `tx` issued, as its cell holds
    /// it.
    fn escrowed(id: &CrossingId, tx: TxHash) -> Vec<u8> {
        id.cell(
            tx,
            RESOURCE,
            AMOUNT,
            VALIDITY_END_MS,
            Terms::Escrowed {
                credit: test_key(0x60),
            },
        )
        .to_bytes()
    }

    /// `id`'s `Taken` read present, stating the answer `tx`'s take
    /// writes.
    fn taken_by(id: &CrossingId, tx: TxHash) -> (SubstateKey, Inclusion, CrossingId) {
        let taken = id.answer(tx, Answered::Taken, VALIDITY_END_MS).to_bytes();
        (
            id.answer_key(&ProtocolHasher, Answered::Taken),
            Inclusion::Present(jmt_value_hash(&taken)),
            *id,
        )
    }

    /// A transaction carrying the same intent after `issuer()`'s record
    /// at the key has gone.
    fn later() -> TxHash {
        TxHash::from(Hash::from_bytes(b"a later transaction"))
    }

    /// A record key names its edge and no transaction. A `Taken` one
    /// transaction's consumer wrote is no answer to the record a later
    /// transaction issued on the same edge, and retires nothing of it;
    /// the later transaction's own `Taken` does.
    #[test]
    fn an_old_take_retires_nothing_of_a_later_transactions_record() {
        let id = crossing(0x15);
        let record = id.record_key(&ProtocolHasher);
        let state = Cells(BTreeMap::from([(record, escrowed(&id, later()))]));
        assert_eq!(
            fold(&[claim(vec![taken_by(&id, issuer())])], &state),
            CrossingSettlements::default(),
            "the earlier transaction's Taken leaves the later record standing",
        );
        assert_eq!(
            fold(&[claim(vec![taken_by(&id, later())])], &state).removed,
            vec![record],
            "and the later transaction's own Taken retires it",
        );
        let restated = id
            .answer(later(), Answered::Taken, VALIDITY_END_MS + 1)
            .to_bytes();
        let unbound = (
            id.answer_key(&ProtocolHasher, Answered::Taken),
            Inclusion::Present(jmt_value_hash(&restated)),
            id,
        );
        assert_eq!(
            fold(&[claim(vec![unbound])], &state),
            CrossingSettlements::default(),
            "an answer stating another validity end is not the record's",
        );
    }

    /// The chain committing the block, other than the producer's.
    const ELSEWHERE: ShardId = ShardId::leaf(1, 0);
    /// The producer's shard, where every reading below is taken.
    const PRODUCER: ShardId = ShardId::leaf(1, 1);

    /// A claim of `PRODUCER`'s state at `height` and `ts_ms`, naming the
    /// crossing readings and leaving the rest unnamed.
    fn claim_at(
        height: u64,
        ts_ms: u64,
        named: Vec<(SubstateKey, Inclusion, CrossingId)>,
        unnamed: Vec<(SubstateKey, Inclusion)>,
    ) -> StateClaim {
        StateClaim::new(
            Anchor {
                shard: PRODUCER,
                height: BlockHeight::new(height),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(ts_ms),
            },
            named
                .iter()
                .map(|(key, inclusion, _)| (*key, *inclusion))
                .chain(unnamed),
            MerkleInclusionProof::dummy(),
        )
        .naming(named.into_iter().map(|(key, _, id)| (key, id)))
    }

    /// A consumer's state holding `id`'s `Never`, seen or not.
    fn declined(id: &CrossingId, seen: bool) -> Cells {
        let never = if seen {
            id.answer(issuer(), Answered::Never, VALIDITY_END_MS)
        } else {
            id.unseen_never(issuer(), VALIDITY_END_MS)
        };
        Cells(BTreeMap::from([(
            id.answer_key(&ProtocolHasher, Answered::Never),
            never.to_bytes(),
        )]))
    }

    fn never_of(id: &CrossingId) -> SubstateKey {
        id.answer_key(&ProtocolHasher, Answered::Never)
    }

    fn absent(id: &CrossingId) -> (SubstateKey, Inclusion, CrossingId) {
        (id.record_key(&ProtocolHasher), Inclusion::Absent, *id)
    }

    fn present(id: &CrossingId) -> (SubstateKey, Inclusion, CrossingId) {
        (
            id.record_key(&ProtocolHasher),
            Inclusion::Present([7; 32]),
            *id,
        )
    }

    /// The anchor of a block every one of `claims` is at a boundary of:
    /// a millisecond more than a retention horizon past the newest.
    fn past(claims: &[StateClaim]) -> WeightedTimestamp {
        claims
            .iter()
            .map(|claim| claim.anchor.ts)
            .max()
            .unwrap_or(WeightedTimestamp::ZERO)
            .plus(RETENTION_HORIZON)
            .plus(Duration::from_millis(1))
    }

    /// The anchor of a block every one of `claims` is fresh to: exactly
    /// a retention horizon past the oldest, the last instant admission
    /// carries it as a fresh claim.
    fn fresh_to(claims: &[StateClaim]) -> WeightedTimestamp {
        claims
            .iter()
            .map(|claim| claim.anchor.ts)
            .min()
            .unwrap_or(WeightedTimestamp::ZERO)
            .plus(RETENTION_HORIZON)
    }

    /// What a block carrying `claims`, each at a boundary of it, does on
    /// a chain other than the producer's.
    fn fold(claims: &[StateClaim], state: &Cells) -> CrossingSettlements {
        crossing_settlements(
            claims,
            ELSEWHERE,
            past(claims),
            &SettledWrites::default(),
            state,
        )
    }

    /// What a block carrying `claims`, each fresh to it, does on a chain
    /// other than the producer's.
    fn fold_fresh(claims: &[StateClaim], state: &Cells) -> CrossingSettlements {
        crossing_settlements(
            claims,
            ELSEWHERE,
            fresh_to(claims),
            &SettledWrites::default(),
            state,
        )
    }

    /// A consumer's state holding `id`'s `Taken`.
    fn took(id: &CrossingId) -> Cells {
        Cells(BTreeMap::from([(
            id.answer_key(&ProtocolHasher, Answered::Taken),
            id.answer(issuer(), Answered::Taken, VALIDITY_END_MS)
                .to_bytes(),
        )]))
    }

    /// A fresh absence of the record deletes no answer, whatever the
    /// answer says of itself and whatever the block reads beside it: a
    /// `Taken`, a `Never` its consumer read the record for and one it
    /// did not each stand, with the producing member's exit proven at
    /// the same anchor or with the record read present below it. The
    /// absence is on a chain a recovery of the producer can still
    /// discard, up to the last instant it is fresh.
    #[test]
    fn a_fresh_absence_deletes_no_answer() {
        let id = crossing(0x21);
        let (row, marker) = exit_keys();
        let exited = claim_at(
            90,
            VALIDITY_END_MS,
            vec![absent(&id)],
            vec![
                (row, Inclusion::Absent),
                (marker, Inclusion::Present([3; 32])),
            ],
        );
        let read_before = claim_at(80, VALIDITY_END_MS - 1_000, vec![present(&id)], vec![]);
        for state in [took(&id), declined(&id, true), declined(&id, false)] {
            assert_eq!(
                fold_fresh(from_ref(&exited), &state).removed,
                Vec::new(),
                "a fresh absence with its producer's exit deletes nothing",
            );
            assert_eq!(
                fold_fresh(&[read_before.clone(), exited.clone()], &state).removed,
                Vec::new(),
                "nor does one the block read the record present below",
            );
            assert_eq!(
                fold(from_ref(&exited), &state).removed.len(),
                1,
                "the same reading a millisecond past the horizon is a boundary's",
            );
        }
    }

    /// A record read absent at a boundary deletes its answers once the
    /// producing member's exit is proven at that boundary: the row gone
    /// with the anchor at or past the transaction's validity end, or
    /// with its committed marker present. A `Taken` and a `Never` go
    /// alike, seen or not.
    #[test]
    fn a_boundary_absence_deletes_an_answer_once_its_producers_member_has_exited() {
        let id = crossing(0x22);
        let (row, marker) = exit_keys();
        let by_clock = claim_at(
            90,
            VALIDITY_END_MS,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent)],
        );
        let by_marker = claim_at(
            8,
            8_000,
            vec![absent(&id)],
            vec![
                (row, Inclusion::Absent),
                (marker, Inclusion::Present([3; 32])),
            ],
        );
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        for proof in [by_clock, by_marker] {
            let proof = from_ref(&proof);
            assert_eq!(fold(proof, &took(&id)).removed, vec![taken]);
            assert_eq!(
                fold(proof, &declined(&id, true)).removed,
                vec![never_of(&id)]
            );
            assert_eq!(
                fold(proof, &declined(&id, false)).removed,
                vec![never_of(&id)]
            );
        }

        // The exit's readings ride in another claim at the same anchor.
        let split = [
            claim_at(90, VALIDITY_END_MS, vec![absent(&id)], vec![]),
            claim_at(90, VALIDITY_END_MS, vec![], vec![(row, Inclusion::Absent)]),
        ];
        assert_eq!(fold(&split, &took(&id)).removed, vec![taken]);

        // Both answers of one crossing, each of its own transaction.
        let mut both = took(&id);
        both.0.insert(
            never_of(&id),
            id.answer(later(), Answered::Never, VALIDITY_END_MS)
                .to_bytes(),
        );
        assert_eq!(
            fold(&split, &both).removed,
            vec![taken],
            "an answer whose own transaction's row is not read stands",
        );
    }

    /// An answer whose producer's shard has departed goes at a boundary
    /// of the shard holding the record's prefix since, on that shard's
    /// own row leaf: the predecessor's terminal fated every row, so the
    /// successor's leaf is what says no member of the transaction writes
    /// on the chain extending the anchor. The departed shard's leaf read
    /// at the successor's anchor proves nothing of that chain.
    #[test]
    fn an_answer_of_a_departed_producer_goes_at_its_successors_boundary() {
        let id = crossing(0x23);
        let (successor, _) = PRODUCER.children();
        let at_successor = |row: SubstateKey| {
            StateClaim::new(
                Anchor {
                    shard: successor,
                    height: BlockHeight::new(91),
                    state_root: StateRoot::ZERO,
                    ts: WeightedTimestamp::from_millis(VALIDITY_END_MS),
                },
                [
                    (id.record_key(&ProtocolHasher), Inclusion::Absent),
                    (row, Inclusion::Absent),
                ],
                MerkleInclusionProof::dummy(),
            )
            .naming([(id.record_key(&ProtocolHasher), id)])
        };
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        assert_eq!(
            fold(
                &[at_successor(member_row_leaf(successor, issuer()))],
                &took(&id)
            )
            .removed,
            vec![taken],
        );
        assert!(
            fold(&[at_successor(exit_keys().0)], &took(&id))
                .removed
                .is_empty()
        );
    }

    /// A boundary at which the record reads absent because it is not
    /// yet written deletes nothing: the producing member's row stands
    /// there, or the transaction is uncommitted with its validity still
    /// open, or nothing is read of the member at all.
    #[test]
    fn a_boundary_before_the_record_was_written_deletes_nothing() {
        let id = crossing(0x24);
        let (row, marker) = exit_keys();
        let standing = claim_at(
            8,
            VALIDITY_END_MS,
            vec![absent(&id)],
            vec![
                (row, Inclusion::Present([2; 32])),
                (marker, Inclusion::Present([3; 32])),
            ],
        );
        let uncommitted = claim_at(
            8,
            VALIDITY_END_MS - 1,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent), (marker, Inclusion::Absent)],
        );
        let unread = claim_at(8, VALIDITY_END_MS, vec![absent(&id)], vec![]);
        for state in [took(&id), declined(&id, true), declined(&id, false)] {
            for boundary in [&standing, &uncommitted, &unread] {
                assert_eq!(
                    fold(from_ref(boundary), &state),
                    CrossingSettlements::default(),
                );
            }
        }
    }

    /// A presence of the record marks an unseen `Never` seen, and leaves
    /// a seen one alone.
    #[test]
    fn a_presence_marks_an_unseen_never_seen() {
        let id = crossing(0x23);
        let settled = fold(
            &[claim_at(4, 4_000, vec![present(&id)], vec![])],
            &declined(&id, false),
        );
        assert_eq!(
            settled.seen,
            vec![(
                never_of(&id),
                id.answer(issuer(), Answered::Never, VALIDITY_END_MS)
                    .to_bytes()
            )],
        );
        let settled = fold(
            &[claim_at(4, 4_000, vec![present(&id)], vec![])],
            &declined(&id, true),
        );
        assert!(settled.seen.is_empty());
    }

    /// A `Never` a receipt writes is the receipt's, and no presence
    /// marks it.
    #[test]
    fn a_receipt_written_never_is_not_marked() {
        let id = crossing(0x24);
        let receipts =
            SettledWrites::from_absolutes(BTreeMap::from([(never_of(&id), Some(vec![1]))]));
        let settled = crossing_settlements(
            &[claim_at(4, 4_000, vec![present(&id)], vec![])],
            ELSEWHERE,
            WeightedTimestamp::from_millis(4_000),
            &receipts,
            &declined(&id, false),
        );
        assert!(settled.seen.is_empty());
    }

    /// The member row and committed marker of the issuing transaction on
    /// the producer's shard.
    fn exit_keys() -> (SubstateKey, SubstateKey) {
        (
            member_row_leaf(PRODUCER, issuer()),
            committed_tx_cell_key(
                PRODUCER,
                issuer(),
                WeightedTimestamp::from_millis(VALIDITY_END_MS),
            ),
        )
    }

    /// A `Never` goes once its producer's leg is fated, and not at the
    /// leg's reclaim. The producer's chain commits the issuing
    /// transaction as a leg that waits; a reclaim's finalization names it
    /// and releases the row, which stands, so a reading of the row beside
    /// the record's absence proves no exit; the fate deletes the row, and
    /// the reading taken past it does.
    #[test]
    fn an_unseen_never_goes_once_its_producers_leg_is_fated() {
        let id = crossing(0x2B);
        let state = declined(&id, false);
        let (row, _) = exit_keys();
        let mut producer = MemberIndex::empty(PRODUCER);
        let removed = |producer: &MemberIndex, height: u64| {
            let reading = if producer.members.contains_key(&issuer()) {
                Inclusion::Present([2; 32])
            } else {
                Inclusion::Absent
            };
            let read = claim_at(
                height,
                VALIDITY_END_MS,
                vec![absent(&id)],
                vec![(row, reading)],
            );
            fold(&[read], &state).removed
        };
        let state_of =
            |producer: &MemberIndex| producer.members.get(&issuer()).map(|row| row.state);

        let stub = stub_stated_terms(issuer(), 1);
        producer.advance(&MemberInputs {
            height: BlockHeight::new(1),
            transactions: vec![(
                issuer(),
                Deadline::of(WeightedTimestamp::from_millis(VALIDITY_END_MS)),
            )],
            terms: vec![StatedTerms {
                terms: MemberTerms {
                    leg: true,
                    settlement: Settlement::Alone,
                    ..stub.terms
                },
                ..stub
            }],
            ..MemberInputs::still(PRODUCER)
        });
        assert_eq!(state_of(&producer), Some(RowState::Pending));
        assert!(removed(&producer, 91).is_empty());

        producer.advance(&MemberInputs {
            height: BlockHeight::new(2),
            settled: vec![SettledHalf {
                tick: TickId::new(PRODUCER, BlockHeight::new(2)),
                half: TickHalf::Determined,
                stated: Vec::new(),
                deleted: Vec::new(),
                accepted: Vec::new(),
                reclaimed: vec![issuer()],
            }],
            ..MemberInputs::still(PRODUCER)
        });
        assert_eq!(
            state_of(&producer),
            Some(RowState::Released {
                settlement: Settlement::Alone
            }),
        );
        assert!(
            removed(&producer, 92).is_empty(),
            "the reclaim deletes no row, so the leg has not exited",
        );

        producer.advance(&MemberInputs {
            height: BlockHeight::new(3),
            manifest: Arc::new(Capped::from_array([TickLine::Fate {
                tx: issuer(),
                charge: stub_abort_charge(1),
            }])),
            ..MemberInputs::still(PRODUCER)
        });
        assert_eq!(state_of(&producer), None);
        assert_eq!(removed(&producer, 93), vec![never_of(&id)]);
    }

    /// A standing member row proves no exit.
    #[test]
    fn a_standing_member_row_proves_no_exit() {
        let id = crossing(0x27);
        let (row, marker) = exit_keys();
        let standing = claim_at(
            8,
            VALIDITY_END_MS,
            vec![absent(&id)],
            vec![
                (row, Inclusion::Present([2; 32])),
                (marker, Inclusion::Present([3; 32])),
            ],
        );
        assert!(fold(&[standing], &declined(&id, false)).removed.is_empty());
    }

    /// A transaction not yet committed and not yet past its validity end
    /// may still commit, so its missing row proves no exit.
    #[test]
    fn an_uncommitted_transaction_before_its_end_proves_no_exit() {
        let id = crossing(0x28);
        let (row, marker) = exit_keys();
        let early = claim_at(
            8,
            VALIDITY_END_MS - 1,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent), (marker, Inclusion::Absent)],
        );
        assert!(fold(&[early], &declined(&id, false)).removed.is_empty());
    }

    /// The row and the marker read at two anchors prove nothing together.
    #[test]
    fn exit_readings_at_two_anchors_do_not_combine() {
        let id = crossing(0x29);
        let (row, marker) = exit_keys();
        let claims = [
            claim_at(8, 8_000, vec![absent(&id)], vec![(row, Inclusion::Absent)]),
            claim_at(
                9,
                9_000,
                vec![],
                vec![(marker, Inclusion::Present([3; 32]))],
            ),
        ];
        assert!(fold(&claims, &declined(&id, false)).removed.is_empty());
    }

    /// Where both ends are this chain's, a record read absent at the
    /// parent deletes an answer on its own, fresh as the reading is.
    #[test]
    fn a_parent_anchored_absence_deletes_a_local_unseen_never() {
        let id = crossing(0x2A);
        let settled = crossing_settlements(
            &[claim_at(4, 4_000, vec![absent(&id)], vec![])],
            PRODUCER,
            WeightedTimestamp::from_millis(4_000),
            &SettledWrites::default(),
            &declined(&id, false),
        );
        assert_eq!(settled.removed, vec![never_of(&id)]);
    }

    fn read(readings: Vec<(SubstateKey, Stated, CrossingId)>) -> StateClaim {
        StateClaim::new(
            Anchor {
                shard: ShardId::leaf(1, 1),
                height: BlockHeight::new(4),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(4_000),
            },
            readings
                .iter()
                .map(|(key, stated, _)| (*key, stated.clone())),
            MerkleInclusionProof::dummy(),
        )
        .naming(readings.into_iter().map(|(key, _, id)| (key, id)))
    }

    const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);
    const AMOUNT: u128 = 250;
    const VALIDITY_END_MS: u64 = 60_000;

    fn issuer() -> TxHash {
        TxHash::from(Hash::from_bytes(b"issuer"))
    }

    /// The record `id` names on `terms`, read held at its key.
    fn held(id: &CrossingId, terms: Terms) -> (SubstateKey, Stated, CrossingId) {
        let cell = id.cell(issuer(), RESOURCE, AMOUNT, VALIDITY_END_MS, terms);
        (
            id.record_key(&ProtocolHasher),
            Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits")),
            *id,
        )
    }

    /// What `owed_credits` credits at `id`'s vault, and the `Taken` it
    /// writes, out of `writes`.
    fn credit_of(writes: &StateWrites, id: &CrossingId) -> (Option<u128>, Option<Vec<u8>>) {
        (
            writes
                .movements
                .get(&id.owed_credit(&ProtocolHasher, RESOURCE))
                .map(|movement| movement.credit),
            writes
                .cells
                .get(&id.answer_key(&ProtocolHasher, Answered::Taken))
                .cloned()
                .flatten(),
        )
    }

    /// A held owed reading with no `Taken` in the parent credits the
    /// consumer's vault and writes the `Taken` a take would have written.
    #[test]
    fn an_owed_reading_credits_its_consumer_once() {
        let id = crossing(0x21);
        let empty = Cells(BTreeMap::new());
        let taken = id
            .answer(issuer(), Answered::Taken, VALIDITY_END_MS)
            .to_bytes();

        let writes = owed_credits(&[read(vec![held(&id, Terms::Owed)])], &empty);
        assert_eq!(credit_of(&writes, &id), (Some(AMOUNT), Some(taken)));
        assert_eq!(
            writes.movements.len() + writes.cells.len(),
            2,
            "and nothing else"
        );

        let twice = owed_credits(
            &[
                read(vec![held(&id, Terms::Owed)]),
                read(vec![held(&id, Terms::Owed)]),
            ],
            &empty,
        );
        assert_eq!(
            credit_of(&twice, &id).0,
            Some(AMOUNT),
            "two readings of one record in one block credit it once",
        );
    }

    /// A claim of `PRODUCER`'s state at `height` and `ts_ms` holding
    /// `id`'s owed record.
    fn owed_at(height: u64, ts_ms: u64, id: &CrossingId) -> StateClaim {
        let (key, stated, id) = held(id, Terms::Owed);
        StateClaim::new(
            Anchor {
                shard: PRODUCER,
                height: BlockHeight::new(height),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(ts_ms),
            },
            [(key, stated)],
            MerkleInclusionProof::dummy(),
        )
        .naming([(key, id)])
    }

    const EPOCH_MS: u64 = 300_000;

    /// An owed record written at or below its producer's last boundary,
    /// credited, and retired above the boundary stands again once the
    /// producer is recovered to the boundary, and is credited once. The
    /// retirement's absence is fresh, so the consumer's `Taken` outlives
    /// it; the recovered chain's reading of the record passes the read
    /// frontier, whose mark orders the later epoch above the discarded
    /// suffix and is long pruned, and meets the `Taken`, which credits
    /// nothing and retires the standing record again.
    #[test]
    fn a_recovered_producers_owed_record_is_credited_once() {
        let windows = EpochWindows::new(EPOCH_MS);
        let id = crossing(0x31);
        let record = id.record_key(&ProtocolHasher);
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let mut frontier = ReadFrontier::default();
        let mut state = Cells(BTreeMap::new());
        let mut credited = 0u128;

        // The producer's boundary is height 95. Its suffix writes nothing
        // of the record, written at or below 95, and retires it at 103.
        let credit = [owed_at(100, EPOCH_MS + 9_000, &id)];
        let writes = owed_credits(&credit, &state);
        credited += credit_of(&writes, &id)
            .0
            .expect("the first reading credits");
        state
            .0
            .insert(taken, credit_of(&writes, &id).1.expect("and writes Taken"));
        frontier.advance(&FrontierInputs::for_block(
            &credit,
            windows,
            WeightedTimestamp::from_millis(EPOCH_MS + 10_000),
            ELSEWHERE,
        ));

        let (row, _) = exit_keys();
        let retired = [claim_at(
            103,
            EPOCH_MS + 15_000,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent)],
        )];
        let block = WeightedTimestamp::from_millis(EPOCH_MS + 16_000);
        assert_eq!(
            crossing_settlements(
                &retired,
                ELSEWHERE,
                block,
                &SettledWrites::default(),
                &state
            ),
            CrossingSettlements::default(),
            "the retirement's absence is fresh and deletes nothing",
        );
        frontier.advance(&FrontierInputs::for_block(
            &retired, windows, block, ELSEWHERE,
        ));
        assert_eq!(
            frontier.entry(PRODUCER),
            Some(ReadMark {
                epoch: windows.epoch_for(WeightedTimestamp::from_millis(EPOCH_MS + 15_000)),
                height: BlockHeight::new(103),
            }),
        );

        // The producer is recovered to height 95 sixteen epochs on; its
        // fresh chain reaches 97 with the record standing as 95 held it.
        let bridge_ms = 18 * EPOCH_MS;
        let again = [owed_at(97, bridge_ms + 5_000, &id)];
        let reading = Reading {
            key: record,
            shard: PRODUCER,
            mark: ReadMark::of(&again[0].anchor, windows),
        };
        let fence = ReadFence {
            presences: vec![reading],
            ..ReadFence::default()
        };
        assert!(
            fence.check(&frontier).is_ok(),
            "a mark at a lower height in a later epoch sits above the frontier's entry",
        );
        frontier.advance(&FrontierInputs::for_block(
            &[],
            windows,
            WeightedTimestamp::from_millis(bridge_ms + 6_000),
            ELSEWHERE,
        ));
        assert_eq!(
            frontier.entry(PRODUCER),
            None,
            "and the entry is long pruned"
        );

        let writes = owed_credits(&again, &state);
        credited += credit_of(&writes, &id).0.unwrap_or(0);
        assert_eq!(credited, AMOUNT, "the record is credited once");
        assert!(writes.cells.is_empty() && writes.movements.is_empty());

        // The recovered producer reads the standing Taken and retires
        // the record again.
        let standing = Cells(BTreeMap::from([(
            record,
            id.cell(issuer(), RESOURCE, AMOUNT, VALIDITY_END_MS, Terms::Owed)
                .to_bytes(),
        )]));
        let answer = [claim(vec![taken_by(&id, issuer())])];
        assert_eq!(
            crossing_settlements(
                &answer,
                PRODUCER,
                fresh_to(&answer),
                &SettledWrites::default(),
                &standing,
            )
            .removed,
            vec![record],
        );
    }

    /// A record a recovered producer writes again for the same
    /// transaction, its first retirement discarded, is retired on the
    /// `Taken` that still stands on its consumer: the answer binds to
    /// the record by its transaction, so the record written a second
    /// time is the one it answers. The answer then goes at the first
    /// boundary of the recovered chain that shows the record gone and
    /// its member exited, and at none before.
    #[test]
    fn a_record_a_recovered_producer_writes_again_is_retired_on_the_standing_taken() {
        let id = crossing(0x32);
        let record = id.record_key(&ProtocolHasher);
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let (row, _) = exit_keys();
        let consumer = took(&id);

        // The discarded suffix retired the record, and the consumer read
        // the absence fresh.
        let retired = [claim_at(
            103,
            EPOCH_MS + 15_000,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent)],
        )];
        assert_eq!(
            fold_fresh(&retired, &consumer),
            CrossingSettlements::default()
        );

        // The recovered chain runs the standing leg again and writes the
        // record of the same transaction.
        let producer = Cells(BTreeMap::from([(record, escrowed(&id, issuer()))]));
        let answer = [claim(vec![taken_by(&id, issuer())])];
        assert_eq!(
            crossing_settlements(
                &answer,
                PRODUCER,
                fresh_to(&answer),
                &SettledWrites::default(),
                &producer,
            )
            .removed,
            vec![record],
            "the standing Taken retires the record written again",
        );

        // A boundary of the recovered chain taken while the leg's row
        // stands deletes nothing; the one after its exit deletes.
        let running = [claim_at(
            96,
            18 * EPOCH_MS,
            vec![absent(&id)],
            vec![(row, Inclusion::Present([2; 32]))],
        )];
        assert_eq!(fold(&running, &consumer), CrossingSettlements::default());
        let exited = [claim_at(
            140,
            19 * EPOCH_MS,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent)],
        )];
        assert_eq!(fold(&exited, &consumer).removed, vec![taken]);
    }

    /// An owed record a later transaction issued where an earlier one's
    /// was taken is credited once: the earlier `Taken` standing at the
    /// key guards nothing of it, the credit's own `Taken` is written
    /// over it, and with that standing a second reading credits nothing.
    #[test]
    fn an_owed_credit_lands_beside_another_transactions_taken() {
        let id = crossing(0x23);
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let record = id.cell(later(), RESOURCE, AMOUNT, VALIDITY_END_MS, Terms::Owed);
        let reading = || {
            read(vec![(
                id.record_key(&ProtocolHasher),
                Stated::Held(Bytes::new(record.to_bytes()).expect("a record fits")),
                id,
            )])
        };
        let old = id
            .answer(issuer(), Answered::Taken, VALIDITY_END_MS)
            .to_bytes();
        let own = id
            .answer(later(), Answered::Taken, VALIDITY_END_MS)
            .to_bytes();
        let mut state = Cells(BTreeMap::from([(taken, old)]));

        let writes = owed_credits(&[reading()], &state);
        assert_eq!(
            credit_of(&writes, &id),
            (Some(AMOUNT), Some(own.clone())),
            "the later record is credited and its own Taken written over the earlier one",
        );
        state.0.insert(taken, own);
        let again = owed_credits(&[reading()], &state);
        assert!(
            again.cells.is_empty() && again.movements.is_empty(),
            "with its own Taken standing it is not credited twice: {again:?}",
        );
    }

    /// Nothing but a held owed record of the named crossing, with no
    /// `Taken` standing and no absence beside it, credits anything.
    #[test]
    fn an_owed_credit_needs_the_whole_licence() {
        let id = crossing(0x22);
        let empty = Cells(BTreeMap::new());
        let nothing = |claims: &[StateClaim], state: &Cells| {
            let writes = owed_credits(claims, state);
            assert!(
                writes.cells.is_empty() && writes.movements.is_empty(),
                "{writes:?}"
            );
        };
        let record = id.record_key(&ProtocolHasher);

        let answered = Cells(BTreeMap::from([(
            id.answer_key(&ProtocolHasher, Answered::Taken),
            id.answer(issuer(), Answered::Taken, VALIDITY_END_MS)
                .to_bytes(),
        )]));
        nothing(&[read(vec![held(&id, Terms::Owed)])], &answered);
        nothing(
            &[read(vec![(
                record,
                Stated::from(Inclusion::Present([7; 32])),
                id,
            )])],
            &empty,
        );
        nothing(
            &[read(vec![held(
                &id,
                Terms::Escrowed {
                    credit: test_key(0x60),
                },
            )])],
            &empty,
        );
        nothing(
            &[read(vec![(record, Stated::from(Inclusion::Absent), id)])],
            &empty,
        );
        nothing(
            &[
                read(vec![held(&id, Terms::Owed)]),
                read(vec![(record, Stated::from(Inclusion::Absent), id)]),
            ],
            &empty,
        );

        // A record whose consumer is not the one its reading names.
        let stranger = CrossingId {
            consumer: Address::new([0x7F; 31], AddressClass::Component),
            ..id
        };
        let (key, _, _) = held(&id, Terms::Owed);
        let misnamed = stranger.cell(issuer(), RESOURCE, AMOUNT, VALIDITY_END_MS, Terms::Owed);
        nothing(
            &[read(vec![(
                key,
                Stated::Held(Bytes::new(misnamed.to_bytes()).expect("a record fits")),
                id,
            )])],
            &empty,
        );
    }

    /// The shard holding each homed crossing's record.
    const HOLDER: ShardId = ShardId::leaf(2, 0);
    /// The shard holding each homed crossing's consumer when its record
    /// was issued.
    const HOME: ShardId = ShardId::leaf(2, 1);
    /// A shard holding neither end.
    const SIBLING: ShardId = ShardId::leaf(2, 2);

    /// A crossing whose producer sits under `HOLDER` and whose consumer
    /// sits under `HOME`.
    fn homed_crossing(seed: u8) -> CrossingId {
        let id = CrossingId {
            producer: Address::new([seed & 0x3F; 31], AddressClass::Component),
            consumer: Address::new([(seed & 0x3F) | 0x40; 31], AddressClass::Component),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        };
        assert!(ShardTrie::shard_owns_prefix(HOLDER, id.producer));
        assert!(ShardTrie::shard_owns_prefix(HOME, id.consumer));
        id
    }

    /// The child of `HOME` holding `id`'s consumer.
    fn consumer_child(id: &CrossingId) -> ShardId {
        let (left, right) = HOME.children();
        if ShardTrie::shard_owns_prefix(left, id.consumer) {
            left
        } else {
            right
        }
    }

    fn at(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    /// A claim of `shard`'s state at `height`, a millisecond a height.
    fn claim_on(
        shard: ShardId,
        height: u64,
        cells: Vec<(SubstateKey, Stated)>,
        named: Vec<(SubstateKey, CrossingId)>,
    ) -> StateClaim {
        StateClaim::new(
            Anchor {
                shard,
                height: BlockHeight::new(height),
                state_root: StateRoot::ZERO,
                ts: at(height),
            },
            cells,
            MerkleInclusionProof::dummy(),
        )
        .naming(named)
    }

    /// A claim of `HOLDER`'s state at `height` holding `id`'s record as
    /// `tx` issued it on `terms`, named for the crossing.
    fn record_held(height: u64, id: &CrossingId, tx: TxHash, terms: Terms) -> StateClaim {
        let record = id.record_key(&ProtocolHasher);
        let cell = id.cell(tx, RESOURCE, AMOUNT, VALIDITY_END_MS, terms);
        claim_on(
            HOLDER,
            height,
            vec![(
                record,
                Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits")),
            )],
            vec![(record, *id)],
        )
    }

    /// The terms [`escrowed`] issues a record on.
    fn escrowed_terms() -> Terms {
        Terms::Escrowed {
            credit: test_key(0x60),
        }
    }

    /// A claim of `local`'s own state reading `tx`'s member row on
    /// `local` as `reading`.
    fn row_read(local: ShardId, tx: TxHash, reading: Inclusion) -> StateClaim {
        claim_on(
            local,
            20,
            vec![(member_row_leaf(local, tx), reading.into())],
            vec![],
        )
    }

    /// `state` after `writes` land on it.
    fn land(state: &mut Cells, writes: &StateWrites) {
        assert!(writes.movements.is_empty() && writes.entries.is_empty());
        for (key, change) in &writes.cells {
            match change {
                Some(value) => state.0.insert(*key, value.clone()),
                None => state.0.remove(key),
            };
        }
    }

    /// One case of the decline's table.
    #[derive(Debug, Clone, Copy)]
    struct DeclineCase {
        /// The chain committing the block.
        local: ShardId,
        /// The block's clock.
        clock: u64,
        /// Whether the chain's row of the issuer stands at the parent.
        row: bool,
        /// Which answer of the issuer's own stands, if either.
        answered: Option<Answered>,
        /// Whether the record is owed.
        owed: bool,
        /// How the block reads the record: held, as a bare presence, or
        /// held beside an absence of it.
        shape: u8,
        /// Whether another transaction's answer stands at each key the
        /// issuer's own does not.
        foreign: bool,
    }

    impl DeclineCase {
        fn all(locals: [ShardId; 6]) -> Vec<Self> {
            let mut cases = Vec::new();
            for local in locals {
                for clock in [VALIDITY_END_MS - 1, VALIDITY_END_MS, VALIDITY_END_MS + 1] {
                    for row in [false, true] {
                        for answered in [None, Some(Answered::Taken), Some(Answered::Never)] {
                            for owed in [false, true] {
                                for shape in 0..3u8 {
                                    cases.extend([false, true].map(|foreign| Self {
                                        local,
                                        clock,
                                        row,
                                        answered,
                                        owed,
                                        shape,
                                        foreign,
                                    }));
                                }
                            }
                        }
                    }
                }
            }
            cases
        }

        /// The parent state the block lands on.
        fn state(self, id: &CrossingId) -> Cells {
            let mut state = Cells(BTreeMap::new());
            for answered in [Answered::Taken, Answered::Never] {
                let own = self.answered == Some(answered);
                let by = match (own, self.foreign) {
                    (true, _) => issuer(),
                    (false, true) => later(),
                    (false, false) => continue,
                };
                state.0.insert(
                    id.answer_key(&ProtocolHasher, answered),
                    id.answer(by, answered, VALIDITY_END_MS).to_bytes(),
                );
            }
            state
        }

        /// The claims the block carries.
        fn claims(self, id: &CrossingId) -> Vec<StateClaim> {
            let record = id.record_key(&ProtocolHasher);
            let terms = if self.owed {
                Terms::Owed
            } else {
                escrowed_terms()
            };
            let held = record_held(9, id, issuer(), terms);
            let mut claims = match self.shape {
                0 => vec![held],
                1 => vec![claim_on(
                    HOLDER,
                    9,
                    vec![(record, Inclusion::Present([7; 32]).into())],
                    vec![(record, *id)],
                )],
                _ => vec![
                    held,
                    claim_on(HOLDER, 11, vec![(record, Inclusion::Absent.into())], vec![]),
                ],
            };
            let row = if self.row {
                Inclusion::Present([2; 32])
            } else {
                Inclusion::Absent
            };
            claims.push(row_read(self.local, issuer(), row));
            claims
        }

        /// Whether the block declines.
        fn declines(self, id: &CrossingId) -> bool {
            ShardTrie::shard_owns_prefix(self.local, id.consumer)
                && !self.owed
                && self.shape == 0
                && !self.row
                && self.answered.is_none()
                && self.clock >= VALIDITY_END_MS
        }

        /// Whether a member of the committing chain could still take
        /// the record: one takes it only off a row, and a row is written
        /// only by a block whose clock is short of the validity end.
        fn can_still_take(self, id: &CrossingId) -> bool {
            ShardTrie::shard_owns_prefix(self.local, id.consumer)
                && !self.owed
                && (self.row || self.clock < VALIDITY_END_MS)
        }
    }

    /// The whole table of the consumer's decline.
    ///
    /// A `Never` of the record's transaction is written exactly where
    /// the record is held and named, escrowed, addressed to a prefix the
    /// committing chain holds, read absent nowhere in the block, the
    /// block's clock is at or past the validity end, no answer of the
    /// transaction stands, and the chain's own row of the transaction is
    /// read absent at its parent. An answer of another transaction
    /// standing at either key changes nothing. In every case where a
    /// member of the committing chain could still take the record, none
    /// is written.
    #[test]
    fn a_decline_is_written_exactly_where_no_member_can_take() {
        let id = homed_crossing(0x21);
        let successor = consumer_child(&id);
        let stranger = successor.sibling().expect("a child has a sibling");
        let merged = HOME.parent().expect("a leaf has a parent");
        let decline = id
            .answer(issuer(), Answered::Never, VALIDITY_END_MS)
            .to_bytes();
        let written = StateWrites {
            cells: BTreeMap::from([(never_of(&id), Some(decline.clone()))]),
            ..StateWrites::default()
        };
        let cases = DeclineCase::all([HOME, successor, stranger, merged, SIBLING, HOLDER]);
        assert_eq!(cases.len(), 1_296);
        let mut declined = 0u32;
        for case in cases {
            let writes = unclaimed_declines(
                &case.claims(&id),
                case.local,
                at(case.clock),
                &case.state(&id),
            );
            if case.declines(&id) {
                declined += 1;
                assert!(!case.can_still_take(&id), "{case:?}");
                assert_eq!(writes, written, "{case:?}");
            } else {
                assert_eq!(writes, StateWrites::default(), "{case:?}");
            }
        }
        assert_eq!(
            declined, 12,
            "HOME, its child holding the consumer and its parent, at and past the end, under \
             no answer and under another transaction's",
        );
        let answer = CrossingAnswer::from_bytes(&decline).expect("an answer");
        assert!(
            answer.seen,
            "the decline read its record and is written seen"
        );
        assert!(issuer_of().answered_by(&id, Answered::Never, &decline));
    }

    /// The issuer of every record [`record_held`] holds for `issuer()`.
    fn issuer_of() -> Issuer {
        Issuer {
            tx: issuer(),
            validity_end_ms: VALIDITY_END_MS,
        }
    }

    /// The row reading a decline is written on is the committing chain's
    /// own, of its own row of the record's transaction, absent: no
    /// reading, a reading of the row taken on another shard, another
    /// shard's row, and the row of another transaction each decline
    /// nothing. Of two held readings of one record key, the newest is
    /// the record declined.
    #[test]
    fn a_decline_reads_its_own_chains_row_of_the_records_transaction() {
        let id = homed_crossing(0x23);
        let empty = Cells(BTreeMap::new());
        let held = record_held(9, &id, issuer(), escrowed_terms());
        let past_end = at(VALIDITY_END_MS);
        let declines = |rows: Vec<StateClaim>| {
            let claims: Vec<StateClaim> = once(held.clone()).chain(rows).collect();
            !unclaimed_declines(&claims, HOME, past_end, &empty)
                .cells
                .is_empty()
        };
        assert!(declines(vec![row_read(HOME, issuer(), Inclusion::Absent)]));
        assert!(!declines(vec![]), "the row unread");
        let elsewhere = claim_on(
            HOLDER,
            20,
            vec![(member_row_leaf(HOME, issuer()), Inclusion::Absent.into())],
            vec![],
        );
        assert!(!declines(vec![elsewhere]), "the row read on another shard");
        assert!(
            !declines(vec![claim_on(
                HOME,
                20,
                vec![(member_row_leaf(HOLDER, issuer()), Inclusion::Absent.into())],
                vec![],
            )]),
            "another shard's row",
        );
        assert!(
            !declines(vec![row_read(HOME, later(), Inclusion::Absent)]),
            "another transaction's row",
        );

        let reissued = record_held(10, &id, later(), escrowed_terms());
        let both_rows = claim_on(
            HOME,
            20,
            {
                let mut rows = vec![
                    (member_row_leaf(HOME, issuer()), Inclusion::Absent.into()),
                    (member_row_leaf(HOME, later()), Inclusion::Absent.into()),
                ];
                rows.sort_unstable_by_key(|(key, _): &(SubstateKey, Stated)| *key);
                rows
            },
            vec![],
        );
        let writes = unclaimed_declines(&[held, reissued, both_rows], HOME, past_end, &empty);
        assert_eq!(
            writes.cells.get(&never_of(&id)),
            Some(&Some(
                id.answer(later(), Answered::Never, VALIDITY_END_MS)
                    .to_bytes()
            )),
            "the record the block reads live is the one declined",
        );
    }

    /// A reading named for a crossing that shares the record's key and
    /// not its consumer declines nothing. A record key names no
    /// consumer, so a claim can name the key of a record addressed
    /// elsewhere for a crossing whose consumer this chain holds; the
    /// record's own value says whose it is, and no `Never` is written at
    /// the misnamed crossing's key.
    #[test]
    fn a_record_named_for_another_consumer_declines_nothing() {
        let id = homed_crossing(0x29);
        let misnamed = CrossingId {
            consumer: Address::new([0x7F; 31], AddressClass::Component),
            ..id
        };
        assert!(ShardTrie::shard_owns_prefix(HOME, misnamed.consumer));
        let record = id.record_key(&ProtocolHasher);
        assert_eq!(misnamed.record_key(&ProtocolHasher), record);
        let cell = id.cell(
            issuer(),
            RESOURCE,
            AMOUNT,
            VALIDITY_END_MS,
            escrowed_terms(),
        );
        let held = claim_on(
            HOLDER,
            9,
            vec![(
                record,
                Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits")),
            )],
            vec![(record, misnamed)],
        );
        let claims = [held, row_read(HOME, issuer(), Inclusion::Absent)];
        assert!(unclaimed_records(&claims, HOME).is_empty());
        assert_eq!(
            unclaimed_declines(&claims, HOME, at(VALIDITY_END_MS), &Cells(BTreeMap::new())),
            StateWrites::default(),
        );
    }

    /// Of two held readings of one record key, the newest by its
    /// anchor's clock is the record declined, in whichever order the
    /// block's claims stand.
    #[test]
    fn the_newest_reading_is_declined_in_either_claim_order() {
        let id = homed_crossing(0x2A);
        let held = record_held(9, &id, issuer(), escrowed_terms());
        let reissued = record_held(10, &id, later(), escrowed_terms());
        let rows = [issuer(), later()].map(|tx| row_read(HOME, tx, Inclusion::Absent));
        let newest = Some(
            id.answer(later(), Answered::Never, VALIDITY_END_MS)
                .to_bytes(),
        );
        for order in [[held.clone(), reissued.clone()], [reissued, held]] {
            let claims: Vec<StateClaim> = order.into_iter().chain(rows.clone()).collect();
            let writes =
                unclaimed_declines(&claims, HOME, at(VALIDITY_END_MS), &Cells(BTreeMap::new()));
            assert_eq!(
                writes.cells.into_iter().collect::<Vec<_>>(),
                [(never_of(&id), newest.clone())],
            );
        }
    }

    /// A record taken once and standing again after a recovery of its
    /// producer is not declined. The consumer's `Taken` of the record's
    /// transaction outlives the retirement the recovery discarded, so a
    /// reading of the record past its validity end, with no row of its
    /// transaction standing, meets that `Taken` and writes nothing; the
    /// same `Taken` retires the record again on the recovered chain. A
    /// `Taken` another transaction left at the key guards nothing of it.
    #[test]
    fn a_record_standing_again_after_its_producers_recovery_is_not_declined() {
        let id = homed_crossing(0x24);
        let record = id.record_key(&ProtocolHasher);
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let mut consumer = Cells(BTreeMap::from([(
            taken,
            id.answer(issuer(), Answered::Taken, VALIDITY_END_MS)
                .to_bytes(),
        )]));
        let again = [
            record_held(97, &id, issuer(), escrowed_terms()),
            row_read(HOME, issuer(), Inclusion::Absent),
        ];
        let block = at(18 * EPOCH_MS);
        assert_eq!(
            unclaimed_declines(&again, HOME, block, &consumer),
            StateWrites::default(),
            "the standing Taken refuses the decline",
        );

        let producer = Cells(BTreeMap::from([(record, escrowed(&id, issuer()))]));
        let answer = [claim(vec![taken_by(&id, issuer())])];
        assert_eq!(
            crossing_settlements(
                &answer,
                HOLDER,
                fresh_to(&answer),
                &SettledWrites::default(),
                &producer,
            )
            .removed,
            vec![record],
            "and retires the record standing again",
        );

        consumer.0.insert(
            taken,
            id.answer(later(), Answered::Taken, VALIDITY_END_MS)
                .to_bytes(),
        );
        assert_eq!(
            unclaimed_declines(&again, HOME, block, &consumer)
                .cells
                .len(),
            1,
            "another transaction's Taken refuses nothing",
        );
    }

    /// A split child declines a record its parent could not. The parent
    /// committed the record's transaction, so its row stands there and
    /// the parent declines nothing past the validity end; the parent's
    /// terminal fates the row; the child holding the consumer reads its
    /// own row of the transaction, which it never had, and declines. The
    /// child that does not hold the consumer declines nothing, and
    /// neither does a reading of the departed parent's row.
    #[test]
    fn a_split_child_declines_what_its_parent_fated() {
        let id = homed_crossing(0x25);
        let child = consumer_child(&id);
        let other = child.sibling().expect("a child has a sibling");
        let empty = Cells(BTreeMap::new());
        let held = record_held(9, &id, issuer(), escrowed_terms());
        let past_end = at(VALIDITY_END_MS + 1);
        let row_on = |index: &MemberIndex, shard: ShardId| {
            let reading = if index.members.contains_key(&issuer()) {
                Inclusion::Present([2; 32])
            } else {
                Inclusion::Absent
            };
            row_read(shard, issuer(), reading)
        };
        let declined = |local: ShardId, row: StateClaim| {
            !unclaimed_declines(&[held.clone(), row], local, past_end, &empty)
                .cells
                .is_empty()
        };

        let mut parent = MemberIndex::empty(HOME);
        parent.advance(&MemberInputs {
            height: BlockHeight::new(1),
            transactions: vec![(issuer(), Deadline::of(at(VALIDITY_END_MS)))],
            terms: vec![stub_stated_terms(issuer(), 1)],
            ..MemberInputs::still(HOME)
        });
        assert!(
            !declined(HOME, row_on(&parent, HOME)),
            "the parent's member may still take",
        );

        parent.advance(&MemberInputs {
            height: BlockHeight::new(2),
            manifest: Arc::new(Capped::from_array([TickLine::Fate {
                tx: issuer(),
                charge: stub_abort_charge(1),
            }])),
            ..MemberInputs::still(HOME)
        });
        assert!(!parent.members.contains_key(&issuer()));

        let own = MemberIndex::empty(child);
        assert!(declined(child, row_on(&own, child)));
        assert!(
            !declined(child, row_on(&parent, HOME)),
            "the departed parent's row is no reading of the child's",
        );
        assert!(
            !declined(other, row_on(&MemberIndex::empty(other), other)),
            "the child without the consumer declines nothing",
        );
    }

    /// A decline on whichever chain holds its record's consumer's
    /// prefix: the home, the split child holding the consumer, and the
    /// merged parent. The holder declines the record it reads; the
    /// `Never` it wrote binds to the record as a refusal's does, and to
    /// no record of another transaction; a second reading of the record
    /// declines nothing; and once the record is gone and its producing
    /// member has exited, a boundary of the record's shard deletes the
    /// `Never`.
    #[test]
    fn a_decline_binds_its_record_once_and_goes_at_a_boundary_on_whoever_holds_the_prefix() {
        let id = homed_crossing(0x22);
        let record = id.record_key(&ProtocolHasher);
        let never = never_of(&id);
        let child = consumer_child(&id);
        for holder in [HOME, child, HOME.parent().expect("a leaf has a parent")] {
            let mut consumer = Cells(BTreeMap::new());
            let reading = [
                record_held(9, &id, issuer(), escrowed_terms()),
                row_read(holder, issuer(), Inclusion::Absent),
            ];
            let block = at(VALIDITY_END_MS);

            let declines = unclaimed_declines(&reading, holder, block, &consumer);
            assert_eq!(
                declines.cells.keys().collect::<Vec<_>>(),
                [&never],
                "{holder:?}"
            );
            let written = crossing_settlements(
                &reading,
                holder,
                block,
                &SettledWrites::from_absolutes(declines.cells.clone()),
                &consumer,
            );
            assert_eq!(
                written,
                CrossingSettlements::default(),
                "the settlements leave the decline's own write alone",
            );
            land(&mut consumer, &declines);

            let stated = consumer.cell(never).expect("the decline stands");
            let read_by_producer = claim_on(
                holder,
                30,
                vec![(never, Inclusion::Present(jmt_value_hash(&stated)).into())],
                vec![(never, id)],
            );
            assert!(
                read_by_producer.answers(&id, issuer_of(), Answered::Never),
                "the producer binds the decline to its record",
            );
            assert!(!read_by_producer.answers(
                &id,
                Issuer {
                    tx: later(),
                    validity_end_ms: VALIDITY_END_MS
                },
                Answered::Never,
            ));

            assert_eq!(
                unclaimed_declines(&reading, holder, at(VALIDITY_END_MS + 5), &consumer),
                StateWrites::default(),
                "a record read again under its own Never is declined once",
            );

            // The record's shard is the holder itself where a merge
            // brought both ends together.
            let producer = if ShardTrie::shard_owns_prefix(holder, id.producer) {
                holder
            } else {
                HOLDER
            };
            let gone = [StateClaim::new(
                Anchor {
                    shard: producer,
                    height: BlockHeight::new(40),
                    state_root: StateRoot::ZERO,
                    ts: at(VALIDITY_END_MS + 10),
                },
                [
                    (record, Inclusion::Absent),
                    (member_row_leaf(producer, issuer()), Inclusion::Absent),
                ],
                MerkleInclusionProof::dummy(),
            )
            .naming([(record, id)])];
            let removed = |block: WeightedTimestamp| {
                crossing_settlements(&gone, holder, block, &SettledWrites::default(), &consumer)
                    .removed
            };
            assert_eq!(
                removed(fresh_to(&gone)),
                if producer == holder {
                    vec![never]
                } else {
                    Vec::new()
                },
                "a fresh absence deletes only where both ends are the chain's own",
            );
            assert_eq!(
                removed(past(&gone)),
                vec![never],
                "{holder:?} forgets the decline at the boundary",
            );
        }
    }

    /// The cell `id`'s record returns its value to: under `HOLDER`'s
    /// prefix, beside the producer.
    fn credit_cell(id: &CrossingId) -> SubstateKey {
        SubstateKey {
            owner: id.producer,
            local: LocalKey([0x77; 16]),
        }
    }

    /// The terms of a record of `id` returning its value to its credit
    /// cell.
    fn returning(id: &CrossingId) -> Terms {
        Terms::Escrowed {
            credit: credit_cell(id),
        }
    }

    /// The bytes of `id`'s record as `tx` issued it on `terms`.
    fn record_bytes(id: &CrossingId, tx: TxHash, terms: Terms) -> Vec<u8> {
        id.cell(tx, RESOURCE, AMOUNT, VALIDITY_END_MS, terms)
            .to_bytes()
    }

    /// `HOLDER`'s parent state: `id`'s record as `tx` issued it, and the
    /// credit cell holding `held`.
    fn producing(id: &CrossingId, tx: TxHash, held: u128) -> Cells {
        Cells(BTreeMap::from([
            (
                id.record_key(&ProtocolHasher),
                record_bytes(id, tx, returning(id)),
            ),
            (credit_cell(id), encode_amount(held).to_vec()),
        ]))
    }

    /// The record of `id` as `HOLDER`'s parent holds it, read at the
    /// parent and named for its crossing.
    fn parent_record(id: &CrossingId, tx: TxHash) -> StateClaim {
        let record = id.record_key(&ProtocolHasher);
        claim_on(
            HOLDER,
            50,
            vec![(
                record,
                Stated::Held(
                    Bytes::new(record_bytes(id, tx, returning(id))).expect("a record fits"),
                ),
            )],
            vec![(record, *id)],
        )
    }

    /// `HOME`'s reading at `height` of `id`'s decline key, present as the
    /// `Never` of `tx`, named for the crossing.
    fn never_read(id: &CrossingId, tx: TxHash, height: u64) -> StateClaim {
        let never = never_of(id);
        let bytes = id.answer(tx, Answered::Never, VALIDITY_END_MS).to_bytes();
        claim_on(
            HOME,
            height,
            vec![(never, Inclusion::Present(jmt_value_hash(&bytes)).into())],
            vec![(never, *id)],
        )
    }

    /// What a block of `HOLDER`'s anchored at `anchor` carrying `claims`
    /// returns over `state`, beside nothing else it writes.
    fn returned_over(
        claims: &[StateClaim],
        anchor: WeightedTimestamp,
        state: &Cells,
    ) -> StateWrites {
        reclaim_credits(
            &reclaimed(claims, HOLDER, anchor),
            HOLDER,
            &StateWrites::default(),
            state,
        )
    }

    /// A record read at the parent beside its consumer's `Never` of its
    /// own transaction, read at a boundary of the consumer's shard, is
    /// removed and its amount credited to the cell it left, as one
    /// movement. A second fold of the block, over the state the first
    /// left, returns nothing.
    #[test]
    fn a_never_at_a_boundary_takes_the_record_back() {
        let id = homed_crossing(0x51);
        let mut state = producing(&id, issuer(), 40);
        let claims = [parent_record(&id, issuer()), never_read(&id, issuer(), 9)];
        let anchor = past(&claims[1..]);
        assert_eq!(
            reclaimed(&claims, HOLDER, anchor),
            vec![(
                id.record_key(&ProtocolHasher),
                id.cell(issuer(), RESOURCE, AMOUNT, VALIDITY_END_MS, returning(&id))
            )],
        );
        let back = returned_over(&claims, anchor, &state);
        assert_eq!(
            back.cells,
            BTreeMap::from([(id.record_key(&ProtocolHasher), None)])
        );
        assert_eq!(
            back.movements,
            BTreeMap::from([(
                credit_cell(&id),
                Movement {
                    resource: RESOURCE,
                    credit: AMOUNT,
                    debit: 0,
                    unjudged_debit: 0,
                }
            )]),
        );
        state.0.remove(&id.record_key(&ProtocolHasher));
        assert_eq!(
            returned_over(&claims, anchor, &state),
            StateWrites::default(),
            "a record already returned is returned once",
        );
    }

    /// A `Never` read at an anchor fresh to the block returns nothing,
    /// however it binds: what the consumer's shard wrote there a
    /// recovery of that shard may discard.
    #[test]
    fn a_fresh_never_returns_nothing_in_the_fold() {
        let id = homed_crossing(0x52);
        let state = producing(&id, issuer(), 40);
        let claims = [parent_record(&id, issuer()), never_read(&id, issuer(), 9)];
        assert!(reclaimed(&claims, HOLDER, fresh_to(&claims[1..])).is_empty());
        assert_eq!(
            returned_over(&claims, fresh_to(&claims[1..]), &state),
            StateWrites::default()
        );
        assert_eq!(reclaimed(&claims, HOLDER, past(&claims[1..])).len(), 1);
    }

    /// A record the same block retires on its consumer's `Taken` of its
    /// transaction is not credited back, whatever `Never` the block
    /// reads beside it.
    #[test]
    fn a_record_its_block_retires_is_not_credited_back() {
        let id = homed_crossing(0x53);
        let taken = id
            .answer(issuer(), Answered::Taken, VALIDITY_END_MS)
            .to_bytes();
        let taken_key = id.answer_key(&ProtocolHasher, Answered::Taken);
        let took = claim_on(
            HOME,
            30,
            vec![(taken_key, Inclusion::Present(jmt_value_hash(&taken)).into())],
            vec![(taken_key, id)],
        );
        let claims = [
            parent_record(&id, issuer()),
            never_read(&id, issuer(), 9),
            took,
        ];
        let anchor = past(&claims[1..]);
        assert!(reclaimed(&claims, HOLDER, anchor).is_empty());
        let other = claim_on(
            HOME,
            30,
            vec![(
                taken_key,
                Inclusion::Present(jmt_value_hash(
                    &id.answer(later(), Answered::Taken, VALIDITY_END_MS)
                        .to_bytes(),
                ))
                .into(),
            )],
            vec![(taken_key, id)],
        );
        assert_eq!(
            reclaimed(
                &[
                    parent_record(&id, issuer()),
                    never_read(&id, issuer(), 9),
                    other
                ],
                HOLDER,
                anchor,
            )
            .len(),
            1,
            "a take of another transaction retires nothing of this record",
        );
    }

    /// The `Never` alone takes nothing back, and neither does a record
    /// read anywhere but at the parent: the fold returns the record the
    /// parent holds, which every voter read for itself.
    #[test]
    fn a_reclaim_without_its_parent_reading_takes_nothing_back() {
        let id = homed_crossing(0x54);
        let state = producing(&id, issuer(), 40);
        let never = never_read(&id, issuer(), 9);
        let anchor = past(from_ref(&never));
        assert!(reclaimed(from_ref(&never), HOLDER, anchor).is_empty());
        let elsewhere = record_held(12, &id, issuer(), returning(&id));
        let read_away = StateClaim {
            anchor: Anchor {
                shard: HOME,
                ..elsewhere.anchor
            },
            ..elsewhere
        };
        assert!(reclaimed(&[read_away, never.clone()], HOLDER, anchor).is_empty());
        let unnamed = parent_record(&id, issuer()).naming([]);
        assert!(reclaimed(&[unnamed, never.clone()], HOLDER, anchor).is_empty());
        assert_eq!(
            returned_over(&[parent_record(&id, issuer()), never], anchor, &state)
                .cells
                .len(),
            1
        );
    }

    /// A record is taken back only on a `Never` named for the crossing
    /// the record states: a reading named for a crossing with another
    /// consumer, whose record key is the same, returns nothing on that
    /// crossing's `Never`, and an unnamed `Never` returns nothing.
    #[test]
    fn a_never_returns_only_the_record_of_the_crossing_it_names() {
        let id = homed_crossing(0x56);
        let elsewhere = CrossingId {
            consumer: Address::new([0x7F; 31], AddressClass::Component),
            ..id
        };
        assert_eq!(
            elsewhere.record_key(&ProtocolHasher),
            id.record_key(&ProtocolHasher)
        );
        let misnamed =
            parent_record(&id, issuer()).naming([(id.record_key(&ProtocolHasher), elsewhere)]);
        let foreign = never_read(&elsewhere, issuer(), 9);
        let anchor = past(from_ref(&foreign));
        assert!(reclaimed(&[misnamed, foreign], HOLDER, anchor).is_empty());

        let unnamed = never_read(&id, issuer(), 9).naming([]);
        let anchor = past(from_ref(&unnamed));
        assert!(reclaimed(&[parent_record(&id, issuer()), unnamed], HOLDER, anchor).is_empty());
    }

    /// A `Never` another transaction's take or refusal left at the
    /// decline key returns nothing of this transaction's record, and a
    /// record the parent no longer holds as the block read it stands.
    #[test]
    fn a_never_of_another_transaction_takes_nothing_back() {
        let id = homed_crossing(0x55);
        let claims = [parent_record(&id, issuer()), never_read(&id, later(), 9)];
        let anchor = past(&claims[1..]);
        assert!(reclaimed(&claims, HOLDER, anchor).is_empty());
        let reissued = producing(&id, later(), 40);
        let claims = [parent_record(&id, issuer()), never_read(&id, issuer(), 9)];
        assert_eq!(reclaimed(&claims, HOLDER, anchor).len(), 1);
        assert_eq!(
            returned_over(&claims, anchor, &reissued),
            StateWrites::default(),
            "the record the parent holds is another transaction's",
        );
    }

    /// An owed record read at the parent beside a bound `Never` at a
    /// boundary is taken back by nobody: nothing takes an owed record
    /// back, so `reclaimed` names it for no ledger, voter or metric.
    /// Reachable on a merged chain holding both ends of an owed crossing
    /// whose `Never` stands.
    #[test]
    fn an_owed_record_is_never_reclaimed() {
        let id = homed_crossing(0x57);
        let record = id.record_key(&ProtocolHasher);
        let owed = claim_on(
            HOLDER,
            50,
            vec![(
                record,
                Stated::Held(
                    Bytes::new(record_bytes(&id, issuer(), Terms::Owed)).expect("a record fits"),
                ),
            )],
            vec![(record, id)],
        );
        let never = never_read(&id, issuer(), 9);
        let anchor = past(from_ref(&never));
        assert!(reclaimed(&[owed, never], HOLDER, anchor).is_empty());
    }

    /// A record the block's own receipts write is not taken back in that
    /// block: the return would erase the write with no credit for it.
    #[test]
    fn a_record_its_block_writes_is_not_taken_back() {
        let id = homed_crossing(0x58);
        let state = producing(&id, issuer(), 40);
        let claims = [parent_record(&id, issuer()), never_read(&id, issuer(), 9)];
        let anchor = past(&claims[1..]);
        let record = id.record_key(&ProtocolHasher);
        let mut merged = StateWrites::default();
        merged
            .cells
            .insert(record, Some(record_bytes(&id, later(), returning(&id))));
        assert_eq!(
            reclaim_credits(&reclaimed(&claims, HOLDER, anchor), HOLDER, &merged, &state),
            StateWrites::default(),
        );
    }

    proptest! {
        /// A block whose claims all name no crossing and hold no value
        /// moves nothing in the crossings fold, whatever cells they read
        /// and whatever the state holds: no record retired, no answer
        /// deleted or marked seen, no credit and no arrival, on a
        /// consumer's chain and on the producer's own, fresh to the
        /// block or at a boundary of it. Such a claim acts
        /// only beside a named or valued reading of its own block, and
        /// here there is none. Nor does one offer the fence anything to
        /// judge: none retires a record or reads a deleting absence.
        #[test]
        fn bare_claims_move_nothing_in_the_crossings_fold(
            readings in vec((0usize..10, any::<bool>(), 1u64..12), 1..16),
        ) {
            let (unseen, seen, owed) = (crossing(0x31), crossing(0x32), crossing(0x33));
            let (row, marker) = exit_keys();
            let record = |id: &CrossingId| id.record_key(&ProtocolHasher);
            let taken = |id: &CrossingId| id.answer_key(&ProtocolHasher, Answered::Taken);
            let keys = [
                record(&unseen),
                never_of(&unseen),
                record(&seen),
                never_of(&seen),
                taken(&seen),
                record(&owed),
                taken(&owed),
                row,
                marker,
                test_key(0x50),
            ];
            let (owed_record, owed_value, _) = held(&owed, Terms::Owed);
            let state = Cells(BTreeMap::from([
                (
                    never_of(&unseen),
                    unseen.unseen_never(issuer(), VALIDITY_END_MS).to_bytes(),
                ),
                (
                    never_of(&seen),
                    seen.answer(issuer(), Answered::Never, VALIDITY_END_MS).to_bytes(),
                ),
                (
                    taken(&seen),
                    seen.answer(issuer(), Answered::Taken, VALIDITY_END_MS).to_bytes(),
                ),
                (record(&seen), escrowed(&seen, issuer())),
                (
                    owed_record,
                    owed_value.held().expect("a held record").to_vec(),
                ),
            ]));
            let claims: Vec<StateClaim> = readings
                .into_iter()
                .map(|(key, present, height)| {
                    // A presence states what the state holds at the
                    // key, so an answer read bare is the very answer a
                    // named reading would bind on.
                    let inclusion = if present {
                        Inclusion::Present(
                            state
                                .cell(keys[key])
                                .map_or([7; 32], |value| jmt_value_hash(&value)),
                        )
                    } else {
                        Inclusion::Absent
                    };
                    claim_at(
                        height,
                        VALIDITY_END_MS + height,
                        vec![],
                        vec![(keys[key], inclusion)],
                    )
                })
                .collect();
            let holder = Issuer {
                tx: issuer(),
                validity_end_ms: VALIDITY_END_MS,
            };
            for claim in &claims {
                prop_assert!(claim.crossings.is_empty() && !claim.holds_a_value());
                prop_assert!(claim.retires(|_| Some(holder)).is_empty());
                prop_assert_eq!(claim.deleting().count(), 0);
            }
            for local in [ELSEWHERE, PRODUCER] {
                for anchor in [fresh_to(&claims), past(&claims)] {
                    prop_assert_eq!(
                        crossing_settlements(
                            &claims,
                            local,
                            anchor,
                            &SettledWrites::default(),
                            &state,
                        ),
                        CrossingSettlements::default(),
                    );
                }
            }
            prop_assert_eq!(owed_credits(&claims, &state), StateWrites::default());
            prop_assert!(record_arrivals(&claims).is_empty());
        }

        /// Whatever a block's claims read of four crossings and their
        /// producing member, named or not, fresh to the block or at a
        /// boundary of it, the crossings fold is a function of the block
        /// and the state it lands on, and folding the block again over
        /// what its first fold left writes nothing. An answer goes only
        /// where a named absence of its record is at a boundary of the
        /// block with the member's exit read at the same anchor, or is
        /// read on the chain itself. A decline is written only on the
        /// chain holding the record's consumer, where the record is held
        /// under its name and read absent nowhere and the chain reads
        /// its own row of the issuer absent, and the `Never` it writes
        /// refuses a second.
        #[test]
        fn a_block_folded_twice_writes_what_one_fold_does(
            readings in vec((0usize..9, any::<bool>(), any::<bool>(), 0u64..3), 1..12),
            boundary in any::<bool>(),
            seen in any::<bool>(),
        ) {
            let ids = [crossing(0x41), crossing(0x42), crossing(0x43), crossing(0x44)];
            prop_assert!(ShardTrie::shard_owns_prefix(PRODUCER, ids[3].consumer));
            let (row, marker) = exit_keys();
            let record = |id: &CrossingId| id.record_key(&ProtocolHasher);
            let taken = |id: &CrossingId| id.answer_key(&ProtocolHasher, Answered::Taken);
            let never = if seen {
                ids[1].answer(issuer(), Answered::Never, VALIDITY_END_MS)
            } else {
                ids[1].unseen_never(issuer(), VALIDITY_END_MS)
            };
            let state = Cells(BTreeMap::from([
                (
                    taken(&ids[0]),
                    ids[0].answer(issuer(), Answered::Taken, VALIDITY_END_MS).to_bytes(),
                ),
                (never_of(&ids[1]), never.to_bytes()),
                (record(&ids[2]), escrowed(&ids[2], issuer())),
            ]));
            // One reading a key at each anchor, as a block carries them.
            let mut at: BTreeMap<(u64, SubstateKey), (Stated, Option<CrossingId>)> =
                BTreeMap::new();
            for (pick, present, named, height) in readings {
                let (key, id) = match pick {
                    0..=2 => (record(&ids[pick]), Some(ids[pick])),
                    3 => (taken(&ids[2]), Some(ids[2])),
                    4 => (row, None),
                    5 => (marker, None),
                    6 => (never_of(&ids[1]), Some(ids[1])),
                    7 => (record(&ids[3]), Some(ids[3])),
                    _ => (test_key(0x50), None),
                };
                let stated = if !present {
                    Inclusion::Absent.into()
                } else if pick == 7 {
                    Stated::Held(
                        Bytes::new(escrowed(&ids[3], issuer())).expect("a record fits"),
                    )
                } else {
                    Inclusion::Present(jmt_value_hash(
                        &ids[2]
                            .answer(issuer(), Answered::Taken, VALIDITY_END_MS)
                            .to_bytes(),
                    ))
                    .into()
                };
                at.insert((height, key), (stated, id.filter(|_| named)));
            }
            let mut claims: Vec<StateClaim> = Vec::new();
            for height in 0..3u64 {
                let read: Vec<(SubstateKey, Stated, Option<CrossingId>)> = at
                    .iter()
                    .filter(|((read_at, _), _)| *read_at == height)
                    .map(|((_, key), (stated, id))| (*key, stated.clone(), *id))
                    .collect();
                if read.is_empty() {
                    continue;
                }
                claims.push(
                    StateClaim::new(
                        Anchor {
                            shard: PRODUCER,
                            height: BlockHeight::new(height + 1),
                            state_root: StateRoot::ZERO,
                            ts: WeightedTimestamp::from_millis(VALIDITY_END_MS + height),
                        },
                        read.iter().map(|(key, stated, _)| (*key, stated.clone())),
                        MerkleInclusionProof::dummy(),
                    )
                    .naming(read.iter().filter_map(|(key, _, id)| Some((*key, (*id)?)))),
                );
            }
            let anchor = if boundary { past(&claims) } else { fresh_to(&claims) };
            for local in [ELSEWHERE, PRODUCER] {
                let declines =
                    |state: &Cells| unclaimed_declines(&claims, local, anchor, state);
                let fold = |state: &Cells| {
                    crossing_settlements(
                        &claims,
                        local,
                        anchor,
                        &SettledWrites::from_absolutes(declines(state).cells),
                        state,
                    )
                };
                let declined = declines(&state);
                prop_assert_eq!(&declined, &declines(&state), "the decline reads its inputs");
                let licensed = local == PRODUCER
                    && claims.iter().any(|claim| {
                        claim.crossing_of(record(&ids[3])) == Some(ids[3])
                            && claim.held(record(&ids[3])).is_some()
                    })
                    && !claims
                        .iter()
                        .any(|claim| claim.reading(record(&ids[3])) == Some(Inclusion::Absent))
                    && claims
                        .iter()
                        .any(|claim| claim.reading(row) == Some(Inclusion::Absent));
                prop_assert_eq!(
                    declined.cells.keys().copied().collect::<Vec<_>>(),
                    if licensed {
                        vec![never_of(&ids[3])]
                    } else {
                        Vec::new()
                    },
                );
                let first = fold(&state);
                prop_assert_eq!(&first, &fold(&state), "the fold reads nothing but its inputs");
                if local == ELSEWHERE {
                    for key in [taken(&ids[0]), never_of(&ids[1])] {
                        let licensed = boundary
                            && claims.iter().any(|claim| {
                                claim.deleting().any(|read| {
                                    read == record(&ids[0]) && key == taken(&ids[0])
                                        || read == record(&ids[1]) && key == never_of(&ids[1])
                                }) && claims.iter().any(|beside| {
                                    beside.anchor == claim.anchor
                                        && beside.reading(row) == Some(Inclusion::Absent)
                                })
                            });
                        prop_assert_eq!(first.removed.contains(&key), licensed);
                    }
                }
                let mut left = Cells(state.0.clone());
                land(&mut left, &declined);
                for key in &first.removed {
                    left.0.remove(key);
                }
                for (key, bytes) in &first.seen {
                    left.0.insert(*key, bytes.clone());
                }
                prop_assert_eq!(
                    fold(&left),
                    CrossingSettlements::default(),
                    "a second fold of the block writes nothing",
                );
                prop_assert_eq!(declines(&left), StateWrites::default());
            }
        }
    }
}
