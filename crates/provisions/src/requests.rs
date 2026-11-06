//! What a source block owes each target: one request per transaction
//! it commits, derived from the envelope and the shard trie, and one per
//! member it makes head, derived from the member's row.
//!
//! The one targeting rule. The commit-time builder, the fetch serve and
//! the provision roots a header commits all read it, so a part is built
//! exactly where a root counts a leaf.
//!
//! A member that shares its verdict and is keyed here is served to the
//! targets it shares that verdict with from the block that makes it
//! head, once nothing ahead of it can still move what it reads, and to
//! every other target from the block committing it. Each target is
//! served it once.

use std::collections::BTreeSet;

use hyperscale_core::ProvisionsRequest;
use hyperscale_engine::legs::Member;
use hyperscale_engine::tick_select::{member_of, settlement_of};
use hyperscale_storage::{MemberRow, Substates, pinned_holds, served_from_head, served_rows};
use hyperscale_types::{
    BlockHeight, DeclaredKey, DeclaredRange, Mode, ShardId, ShardTrie, SubstateKey, Transaction,
    Verifiable, WeightedTimestamp, pins_of,
};

/// One transaction's provision request from the block committing it.
///
/// It serves the locally owned read-set keys (fresh reads and
/// read-modify-write priors) to every remote participant that commits
/// it, save those its member here shares its verdict with where it is
/// served from its head ([`served_from_head`]).
///
/// The payer shard's part flows even with nothing to serve — it is the
/// engagement evidence a counterpart demands before proposing the
/// transaction — and a counterpart with nothing to serve emits an empty
/// part to the payer alone: the engagement echo the payer's vote waits
/// for. A transaction placed on one shard owes nobody anything, and one
/// whose every target is served from its head owes nothing here.
///
/// `None` for a transaction this node could not route. A replica commits
/// a certified block whose transactions name records it has never held,
/// and their read sets come off a derivation only the nodes holding those
/// records reach: this node has nothing to say about them, and a
/// requester asks a peer that does.
///
/// `clock` is the parent-QC weighted timestamp of the block committing
/// `tx`, which the request's leaf binds.
#[must_use]
pub fn provision_request(
    trie: &ShardTrie,
    tx: &Verifiable<Transaction>,
    local_shard: ShardId,
    clock: WeightedTimestamp,
) -> Option<ProvisionsRequest> {
    let (mut request, member) = committed_request(trie, tx, local_shard, clock)?;
    let pins = pins_of(&tx.routing().declared_modes, local_shard);
    if served_from_head(settlement_of(&member), &pins) {
        let sharing = member.awaited();
        request.targets.retain(|target| !sharing.contains(target));
    }
    (!request.targets.is_empty()).then_some(request)
}

/// `tx`'s request toward every target its commit names, before any is
/// left to its member's head, beside its member here.
fn committed_request(
    trie: &ShardTrie,
    tx: &Verifiable<Transaction>,
    local_shard: ShardId,
    clock: WeightedTimestamp,
) -> Option<(ProvisionsRequest, Member)> {
    if !tx.as_unverified().is_routed() {
        return None;
    }
    let member = member_of(tx, trie, local_shard);
    let participants = member.reach();
    if participants.len() <= 1 {
        return None;
    }
    let local_keys: Vec<SubstateKey> = tx
        .routing()
        .provision_keys
        .iter()
        .filter_map(DeclaredKey::cell)
        .filter(|cell| trie.shard_for_prefix(cell.owner) == local_shard)
        .collect();
    let local_ranges: Vec<DeclaredRange> = tx
        .routing()
        .provision_keys
        .iter()
        .filter_map(DeclaredKey::range)
        .filter(|range| trie.shard_for_prefix(range.owner) == local_shard)
        .collect();
    let payer_shard = trie.shard_for_prefix(tx.fee_payer());
    // A shard that only takes delivery of the transaction never includes
    // it, so no part goes there.
    let classified = member.classified();
    let targets: Vec<ShardId> =
        if local_keys.is_empty() && local_ranges.is_empty() && payer_shard != local_shard {
            // The engagement echo: a counterpart with nothing to serve still
            // owes the payer its commitment of the transaction — the evidence
            // the payer's vote waits for — and owes nobody else anything.
            vec![payer_shard]
        } else {
            participants
                .iter()
                .copied()
                .filter(|&s| s != local_shard && classified.commits_at(s))
                .collect()
        };
    let request = ProvisionsRequest {
        tx_hash: tx.hash(),
        clock,
        targets,
        local_keys,
        local_ranges,
    };
    Some((request, member))
}

/// The keys a member declaring `declared` is served on `local`: the
/// cells and the ranges of its `Read` and `Write` entries `local` owns,
/// each ascending, one copy each. Ownership is read off the key's owner
/// alone, as its pins read it.
#[must_use]
pub fn served_request_keys(
    declared: &[(DeclaredKey, Mode)],
    local: ShardId,
) -> (Vec<SubstateKey>, Vec<DeclaredRange>) {
    let served: BTreeSet<DeclaredKey> = declared
        .iter()
        .filter(|(_, mode)| matches!(mode, Mode::Read | Mode::Write { .. }))
        .map(|(key, _)| *key)
        .filter(|key| ShardTrie::shard_owns_prefix(local, key.owner()))
        .collect();
    (
        served.iter().filter_map(DeclaredKey::cell).collect(),
        served.iter().filter_map(DeclaredKey::range).collect(),
    )
}

/// The request of `row`, a member the block serving it made head on
/// `local`: its served keys toward the targets it shares its verdict
/// with, which are the shards it awaits, at the clock of the block that
/// committed it. `None` where it awaits nobody.
#[must_use]
pub fn row_request(row: &MemberRow, local: ShardId) -> Option<ProvisionsRequest> {
    if row.awaits.is_empty() {
        return None;
    }
    let (local_keys, local_ranges) = served_request_keys(pinned_holds(row), local);
    Some(ProvisionsRequest {
        tx_hash: row.tx,
        clock: row.committed,
        targets: row.awaits.to_vec(),
        local_keys,
        local_ranges,
    })
}

/// Every request a block serves: [`provision_request`] for each
/// transaction in block order, then [`row_request`] for each member it
/// makes head, in rank order.
///
/// The block stands at `height` on `local`, its transactions routed
/// under `trie` and committed at `clock`; `state` is the state it leaves.
/// The head half reads rows alone, never a body, so it holds whatever
/// this node has derived. A transaction it has not routed is skipped.
#[must_use]
pub fn block_requests(
    state: &(impl Substates + ?Sized),
    trie: &ShardTrie,
    local: ShardId,
    height: BlockHeight,
    clock: WeightedTimestamp,
    transactions: &[Verifiable<Transaction>],
) -> Vec<ProvisionsRequest> {
    transactions
        .iter()
        .filter_map(|tx| provision_request(trie, tx, local, clock))
        .chain(
            served_rows(state, local, height)
                .iter()
                .filter_map(|row| row_request(row, local)),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use hyperscale_engine::tick_select::awaited_core;
    use hyperscale_types::test_utils::{
        TestCommittee, install_stub_protocol_statics, leg_shape, stub_transaction, test_prefix,
        test_principal,
    };
    use hyperscale_types::{Address, LegRole, PrincipalAddr, TimestampRange, WeightedTimestamp};
    use hyperscale_vm_types::Moves;
    use proptest::prelude::*;

    use super::*;
    use crate::test_fixtures::{CREDIT, Entries, WRITE, cell, shaped};

    fn validity() -> TimestampRange {
        TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(60_000),
        )
    }

    /// A routed transaction paid by `payer` and writing under `prefixes`.
    fn routed(payer: PrincipalAddr, prefixes: &[Address]) -> Verifiable<Transaction> {
        install_stub_protocol_statics();
        Verifiable::from(stub_transaction(payer, prefixes, 1_000, validity()))
    }

    fn unrouted() -> Verifiable<Transaction> {
        let payer = PrincipalAddr::new([0x42; 31]);
        let signed = stub_transaction(payer, &[payer.address()], 1, validity());
        let unrouted = Verifiable::from(Transaction::new(signed.body().clone()));
        assert!(!unrouted.as_unverified().is_routed());
        unrouted
    }

    /// A transaction this node never routed names no provisions: its
    /// read set is a derivation it does not hold.
    #[test]
    fn an_unrouted_transaction_names_no_provisions() {
        let topology = TestCommittee::new(4, 1).topology_snapshot(1);
        assert!(
            provision_request(
                topology.shard_trie(),
                &unrouted(),
                ShardId::ROOT,
                WeightedTimestamp::ZERO
            )
            .is_none()
        );
    }

    /// A transaction placed wholly on one shard owes nothing, even to a
    /// payer elsewhere than the shard asking: nobody else commits it.
    #[test]
    fn a_transaction_on_one_shard_owes_nothing() {
        let topology = TestCommittee::new(4, 42).topology_snapshot(2);
        let payer = test_principal(0x81);
        let tx = routed(payer, &[payer.address(), test_prefix(0x82)]);
        for local in [ShardId::leaf(1, 0), ShardId::leaf(1, 1)] {
            assert!(
                provision_request(topology.shard_trie(), &tx, local, WeightedTimestamp::ZERO)
                    .is_none()
            );
        }
    }

    /// A counterpart owning none of the read set owes the payer its
    /// engagement echo and nothing else; the payer owes every committing
    /// participant its part.
    #[test]
    fn a_pure_counterpart_fans_out_to_the_payer_alone() {
        // The counterpart only credits a cell it owns, so it owns nothing
        // to attest; the payer debits its own.
        let trie = ShardTrie::uniform(1);
        let (payer_shard, counterpart) = (ShardId::leaf(1, 1), ShardId::leaf(1, 0));
        let payer = test_principal(0x81);
        let tx = shaped(payer, &[(cell(test_prefix(0x01), 1), CREDIT)], Vec::new());
        let targets = |local| {
            provision_request(&trie, &tx, local, WeightedTimestamp::ZERO)
                .map(|request| request.targets)
        };
        assert_eq!(targets(counterpart), Some(vec![payer_shard]));
        assert_eq!(targets(payer_shard), Some(vec![counterpart]));
    }

    /// A whole member keyed here shares its verdict with every
    /// participant, so its commit serves none of them: each is served
    /// from its head. Unkeyed, its commit serves them.
    #[test]
    fn a_keyed_shared_commit_serves_no_sharing_target() {
        let trie = ShardTrie::uniform(1);
        let (local, remote) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let payer = test_principal(0x81);
        let keyed = shaped(payer, &[(cell(test_prefix(0x01), 1), WRITE)], Vec::new());
        assert!(provision_request(&trie, &keyed, local, WeightedTimestamp::ZERO).is_none());
        let unkeyed = shaped(payer, &[(cell(test_prefix(0x01), 1), CREDIT)], Vec::new());
        assert_eq!(
            provision_request(&trie, &unkeyed, local, WeightedTimestamp::ZERO)
                .map(|request| request.targets),
            Some(vec![remote]),
        );
    }

    /// A committed block holding a transaction this node never routed
    /// owes no part for it, rather than reading the routing it lacks.
    #[test]
    fn a_block_of_an_unrouted_transaction_owes_no_part() {
        assert!(
            block_requests(
                &Entries::empty(),
                &ShardTrie::uniform(0),
                ShardId::ROOT,
                BlockHeight::new(1),
                WeightedTimestamp::ZERO,
                &[unrouted()],
            )
            .is_empty()
        );
    }

    /// A mode of each kind a declaration can name, by index.
    fn mode_of(kind: u8) -> Mode {
        match kind {
            0 => Mode::Read,
            1 => WRITE,
            2 => Mode::Delta { moves: Moves::Both },
            _ => Mode::Reserve { amount: 1 },
        }
    }

    proptest! {
        /// Every shard a keyed member shares its verdict with is one its
        /// commit names as a target, so the serve from its head reaches
        /// exactly the targets its commit leaves out: a whole member's
        /// every participant, and a core member's core siblings.
        #[test]
        fn a_keyed_shared_members_awaits_are_its_sharing_targets(
            depth in 1u32..=2,
            payer in any::<u8>(),
            entries in prop::collection::vec((any::<u8>(), 0u8..4), 1..5),
            cores in prop::collection::vec(any::<u8>(), 0..3),
            outbound in any::<bool>(),
        ) {
            let trie = ShardTrie::uniform(depth);
            let payer = test_principal(payer);
            let mut declared: Vec<(DeclaredKey, Mode)> = entries
                .iter()
                .map(|&(seed, kind)| (cell(test_prefix(seed), seed), mode_of(kind)))
                .collect();
            declared.extend(cores.iter().map(|&seed| (cell(test_prefix(seed), 0xC0), WRITE)));
            let legs = if cores.is_empty() {
                Vec::new()
            } else {
                let mut legs = vec![leg_shape(payer.address(), LegRole::Inbound, &[])];
                legs.extend(
                    cores
                        .iter()
                        .enumerate()
                        .map(|(at, &seed)| {
                            let output = u32::try_from(at).expect("a few cores");
                            leg_shape(test_prefix(seed), LegRole::Core, &[(0, output)])
                        }),
                );
                if outbound {
                    legs.push(leg_shape(payer.address(), LegRole::Outbound, &[(1, 0)]));
                }
                legs
            };
            let tx = shaped(payer, &declared, legs);
            for local in trie.leaves() {
                let Some((request, member)) =
                    committed_request(&trie, &tx, local, WeightedTimestamp::ZERO)
                else {
                    continue;
                };
                let pins = pins_of(&tx.routing().declared_modes, local);
                if !served_from_head(settlement_of(&member), &pins) {
                    continue;
                }
                for shard in awaited_core(&member).iter() {
                    prop_assert!(
                        request.targets.contains(shard),
                        "{shard:?} is awaited from {local:?} but not a target of its commit",
                    );
                }
            }
        }
    }
}
