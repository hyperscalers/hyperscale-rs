//! What a source block owes each target: one request per transaction,
//! derived from the envelope and the shard trie.
//!
//! The one targeting rule. The commit-time builder, the fetch serve and
//! the provision roots a header commits all read it, so a part is built
//! exactly where a root counts a leaf.

use std::collections::{BTreeSet, HashMap};

use hyperscale_core::ProvisionsRequest;
use hyperscale_engine::legs::Classified;
use hyperscale_types::{
    DeclaredKey, DeclaredRange, ShardId, ShardTrie, SubstateKey, TopologySnapshot, Transaction,
    ValidatorId, Verifiable, WeightedTimestamp,
};

/// Per-shard recipient lists for provision broadcasting.
pub type ShardRecipients = HashMap<ShardId, Vec<ValidatorId>>;

/// One transaction's provision request: the locally owned read-set keys
/// (fresh reads and read-modify-write priors) toward every remote
/// participant.
///
/// The payer shard's part flows even with nothing to serve — it is the
/// engagement evidence a counterpart demands before proposing the
/// transaction — and a counterpart with nothing to serve emits an empty
/// part to the payer alone: the engagement echo the payer's vote waits
/// for. A transaction placed on one shard owes nobody anything.
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
    if !tx.as_unverified().is_routed() {
        return None;
    }
    let participants: BTreeSet<ShardId> = tx
        .routing()
        .all_prefixes()
        .into_iter()
        .map(|prefix| trie.shard_for_prefix(prefix))
        .collect();
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
    let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), trie);
    let targets: Vec<ShardId> =
        if local_keys.is_empty() && local_ranges.is_empty() && payer_shard != local_shard {
            // The engagement echo: a counterpart with nothing to serve still
            // owes the payer its commitment of the transaction — the evidence
            // the payer's vote waits for — and owes nobody else anything.
            vec![payer_shard]
        } else {
            participants
                .into_iter()
                .filter(|&s| s != local_shard && classified.commits_at(s))
                .collect()
        };
    if targets.is_empty() {
        return None;
    }
    Some(ProvisionsRequest {
        tx_hash: tx.hash(),
        clock,
        targets,
        local_keys,
        local_ranges,
    })
}

/// Build provision requests and shard recipients for the block's
/// cross-shard transactions, which the block commits at `clock`: read
/// sets only.
///
/// A transaction this node never routed is skipped: whether it crosses
/// at all is a derivation only the nodes holding its records reach, and
/// a proposer replaying its own block after a restart may hold none.
///
/// Returns `None` if nothing in the block owes anyone a part.
#[must_use]
pub fn build_provision_requests(
    topology_snapshot: &TopologySnapshot,
    transactions: &[Verifiable<Transaction>],
    signers: &BTreeSet<ValidatorId>,
    local_shard: ShardId,
    clock: WeightedTimestamp,
) -> Option<(Vec<ProvisionsRequest>, ShardRecipients)> {
    let provision_requests: Vec<ProvisionsRequest> = transactions
        .iter()
        .filter_map(|tx| provision_request(topology_snapshot.shard_trie(), tx, local_shard, clock))
        .collect();
    if provision_requests.is_empty() {
        return None;
    }

    let mut shard_recipients = HashMap::new();
    for req in &provision_requests {
        for &target_shard in &req.targets {
            shard_recipients.entry(target_shard).or_insert_with(|| {
                topology_snapshot
                    .committee_for_shard(target_shard)
                    .iter()
                    .copied()
                    .filter(|v| !signers.contains(v))
                    .collect()
            });
        }
    }

    Some((provision_requests, shard_recipients))
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::{
        TestCommittee, install_stub_protocol_statics, stub_transaction, test_prefix, test_principal,
    };
    use hyperscale_types::{Address, PrincipalAddr, TimestampRange, WeightedTimestamp};

    use super::*;

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
        // The stub derivation carries no provision keys, so the non-payer
        // shard owns nothing to attest.
        let topology = TestCommittee::new(4, 42).topology_snapshot(2);
        let (payer_shard, counterpart) = (ShardId::leaf(1, 1), ShardId::leaf(1, 0));
        let payer = test_principal(0x81);
        let tx = routed(payer, &[test_prefix(0x01), test_prefix(0x81)]);
        let targets = |local| {
            provision_request(topology.shard_trie(), &tx, local, WeightedTimestamp::ZERO)
                .map(|request| request.targets)
        };
        assert_eq!(targets(counterpart), Some(vec![payer_shard]));
        assert_eq!(targets(payer_shard), Some(vec![counterpart]));
    }

    /// A committed block holding a transaction this node never routed
    /// owes no part for it, rather than reading the routing it lacks.
    #[test]
    fn a_block_of_an_unrouted_transaction_owes_no_part() {
        let committee = TestCommittee::new(4, 1);
        let topology = committee.topology_snapshot(1);
        assert!(
            build_provision_requests(
                &topology,
                &[unrouted()],
                &BTreeSet::from([committee.validator_id(0)]),
                ShardId::ROOT,
                WeightedTimestamp::ZERO,
            )
            .is_none()
        );
    }
}
