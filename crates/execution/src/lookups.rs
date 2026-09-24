//! Pure topology-derived helpers used by the execution coordinator.
//!
//! Everything here is a free function over `TopologySnapshot` — no mutable
//! state, no async, no dependency on coordinator internals. Moved out of
//! the coordinator so the topology-only parts are unit-testable without a
//! full driver fixture.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_types::{
    BlockHeight, ConsensusPublicKey, ConsensusReceipt, DeclaredKey, DeclaredRange,
    ExecutionCertificate, Finalization, ShardId, ShardTrie, SubstateKey, TopologySchedule,
    TopologySnapshot, Transaction, TxHash, TxOutcome, ValidatorId, Verifiable, VoteCount,
    WeightedTimestamp,
};
use hyperscale_vm_effects::{CrossingCell, CrossingLeaf};
use hyperscale_vm_types::ProtocolHasher;

/// Per-shard recipient lists for provision broadcasting.
pub type ShardRecipients = HashMap<ShardId, Vec<ValidatorId>>;

/// The committee that attests a tick of `shard` anchored at `anchor_wt`
/// at `height` — the one its votes address, its certificate's bitfield
/// indexes, and every verifier resolves from the certificate alone.
///
/// `None` when this replica cannot resolve it yet, or when the anchor
/// falls in a window the shard had already left: nobody was seated
/// there to attest, so a tick anchored past its shard's terminal gets no
/// leader, no tracker and no vote, and a certificate claiming one is
/// refused.
pub fn attesting_committee(
    schedule: &TopologySchedule,
    shard: ShardId,
    anchor_wt: WeightedTimestamp,
    height: BlockHeight,
) -> Option<&Arc<TopologySnapshot>> {
    schedule
        .at_for_shard_anchored(shard, anchor_wt, height)
        .filter(|(_, past_terminal)| !past_terminal)
        .map(|(snapshot, _)| snapshot)
}

/// Committee members of `shard` with the local validator filtered out.
///
/// Used for broadcast-style actions (e.g. `BroadcastExecutionCertificate`,
/// provision fetch) that fan out to every other member of a committee. Works
/// for both the local shard (self is always a member, filter removes exactly
/// one entry) and remote shards (filter is a no-op when self isn't a member).
pub fn peers_excluding_self(
    topology_snapshot: &TopologySnapshot,
    me: ValidatorId,
    shard: ShardId,
) -> Vec<ValidatorId> {
    topology_snapshot
        .committee_for_shard(shard)
        .iter()
        .copied()
        .filter(|&v| v != me)
        .collect()
}

/// The fetch keys a dropped certificate releases: its own shard paired with
/// every transaction it claimed an outcome for.
///
/// A certificate the admission path refuses answers for none of those
/// transactions, so each goes back to being expected and re-fetchable.
#[must_use]
pub fn fetch_keys_covered(ec: &ExecutionCertificate) -> Vec<(ShardId, TxHash)> {
    let shard = ec.shard_id();
    ec.tx_outcomes()
        .iter()
        .map(|outcome| (shard, outcome.tx_hash()))
        .collect()
}

/// True if `ec.signers()` represents at least 2f+1 of the voting power on
/// `ec.shard_id()`. Mirrors `qc_has_local_quorum_power` (in the shard consensus
/// crate) but resolves committee + voting power for the EC's own shard,
/// since cross-shard ECs are signed by remote committees.
#[must_use]
pub fn ec_has_shard_quorum_power(
    topology_snapshot: &TopologySnapshot,
    ec: &ExecutionCertificate,
) -> bool {
    let shard = ec.shard_id();
    let committee = topology_snapshot.consensus_committee_for_shard(shard);
    let signers_power: VoteCount = ec
        .signers()
        .set_indices()
        .filter_map(|i| committee.get(i))
        .map(|&vid| {
            topology_snapshot
                .vote_of(vid)
                .expect("committee member has voting power (TopologySnapshot invariant)")
        })
        .sum();
    VoteCount::has_quorum(signers_power, topology_snapshot.committee_votes(shard))
}

/// Public keys for a shard's consensus committee, in canonical order —
/// the positions EC signer bitfields index into.
///
/// Returns `None` if any committee member's public key is missing from the
/// topology — a signal the snapshot is corrupt and verification should not
/// proceed with a partial key set.
pub fn committee_public_keys_for_shard(
    topology_snapshot: &TopologySnapshot,
    shard: ShardId,
) -> Option<Vec<ConsensusPublicKey>> {
    let committee = topology_snapshot.consensus_committee_for_shard(shard);
    let mut pubkeys = Vec::with_capacity(committee.len());
    for &vid in committee {
        pubkeys.push(topology_snapshot.public_key(vid)?);
    }
    Some(pubkeys)
}

/// Pair each of a block's transactions with the shards party to it —
/// the ones whose certificates its settlement needs, this one included.
///
/// Derived from committed content and the block's own committee, so every
/// replica pairs them identically. In block order.
pub fn assign_participants(
    topology_snapshot: &TopologySnapshot,
    transactions: &[Arc<Verifiable<Transaction>>],
) -> Vec<(Arc<Verifiable<Transaction>>, BTreeSet<ShardId>)> {
    transactions
        .iter()
        .map(|tx| {
            let all_shards: BTreeSet<ShardId> = topology_snapshot
                .all_shards_for_transaction(tx)
                .into_iter()
                .collect();
            (Arc::clone(tx), all_shards)
        })
        .collect()
}

/// One transaction's provision request: the locally owned read-set keys
/// (fresh reads and read-modify-write priors) toward every remote
/// participant.
///
/// The payer shard's bundle flows even with nothing to serve — it is
/// the engagement evidence a counterpart demands before proposing the
/// transaction — and a counterpart with nothing to serve emits an empty
/// bundle to the payer alone: the engagement echo the payer's vote
/// waits for. The gossip emit path broadcasts to every target; the
/// fetch serve path narrows the same derivation to the requester.
pub fn provision_request(
    trie: &ShardTrie,
    tx: &Verifiable<Transaction>,
    local_shard: ShardId,
) -> Option<ProvisionsRequest> {
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
    let targets: Vec<ShardId> =
        if local_keys.is_empty() && local_ranges.is_empty() && payer_shard != local_shard {
            // The engagement echo: a counterpart with nothing to serve still
            // owes the payer its commitment of the transaction — the evidence
            // the payer's vote waits for — and owes nobody else anything.
            vec![payer_shard]
        } else {
            tx.routing()
                .all_prefixes()
                .into_iter()
                .map(|prefix| trie.shard_for_prefix(prefix))
                .filter(|&s| s != local_shard)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
    if targets.is_empty() {
        return None;
    }
    Some(ProvisionsRequest {
        tx_hash: tx.hash(),
        targets,
        local_keys,
        local_ranges,
    })
}

/// The crossing records a finalization issued: every live record an
/// executing member's settling receipt wrote under its own transaction,
/// with that transaction, in certificate order.
///
/// The one derivation of what a block issued. It walks
/// [`Finalization::settling_receipts`], never the raw receipt list or
/// the node's execution cache, and keeps a cell write only when the
/// value is present, `CrossingLeaf::read` reads it as a record naming
/// the receipt's own transaction, and the local certificate's outcome
/// for that transaction is the transaction's own execution. A retired
/// rewrite reads as a tombstone, and a deletion, a settling member's
/// write and a write under another transaction's name are not record
/// writes of an executing member, so none of them is named. Read off
/// inline block content only, so a replica holding a sealed block and
/// no transaction bodies derives the same list.
#[must_use]
pub fn records_written(finalization: &Finalization) -> Vec<(TxHash, SubstateKey, CrossingCell)> {
    let Some(local) = finalization
        .execution_certificates()
        .iter()
        .find(|ec| ec.tick_id() == finalization.tick_id())
    else {
        return Vec::new();
    };
    let executing: BTreeSet<TxHash> = local
        .tx_outcomes()
        .iter()
        .filter(|outcome| outcome.executes())
        .map(TxOutcome::tx_hash)
        .collect();
    let mut written = Vec::new();
    for receipt in finalization.settling_receipts() {
        if !executing.contains(&receipt.tx_hash) {
            continue;
        }
        let ConsensusReceipt::Succeeded { writes, .. } = receipt.consensus.as_ref() else {
            continue;
        };
        for (key, change) in &writes.cells {
            let Some(value) = change else {
                continue;
            };
            if let Some(CrossingLeaf::Record { cell, .. }) =
                CrossingLeaf::read(&ProtocolHasher, *key, value)
                && cell.tx == receipt.tx_hash
            {
                written.push((receipt.tx_hash, *key, cell));
            }
        }
    }
    written
}

/// Where each record a block's finalizations issued goes: the records
/// grouped by the shard owning each one's consumer under `trie`, in
/// certificate order, leaving out `local`.
///
/// The recipients are not a target set. A consumer inside a multi-shard
/// core has one owner among its shards; the other core shards are not
/// pushed to and read the record through their own asks. Sound only
/// because nothing waits on a push: a missed core shard costs one read,
/// never a promise, and no consensus-visible set is derived from the
/// consumer and the trie.
#[must_use]
pub fn record_pushes(
    finalizations: &[Arc<Verifiable<Finalization>>],
    trie: &ShardTrie,
    local: ShardId,
) -> BTreeMap<ShardId, Vec<SubstateKey>> {
    let mut pushes: BTreeMap<ShardId, Vec<SubstateKey>> = BTreeMap::new();
    for finalization in finalizations {
        for (_, key, cell) in records_written(finalization.as_unverified()) {
            let owner = trie.shard_for_prefix(cell.consumer);
            if owner != local {
                pushes.entry(owner).or_default().push(key);
            }
        }
    }
    pushes
}

/// Build provision requests and shard recipients for the block's
/// cross-shard transactions: read sets only.
///
/// Returns `None` if nothing in the block owes anyone a bundle.
pub fn build_provision_requests(
    topology_snapshot: &TopologySnapshot,
    transactions: &[Arc<Verifiable<Transaction>>],
    me: ValidatorId,
    local_shard: ShardId,
) -> Option<(Vec<ProvisionsRequest>, ShardRecipients)> {
    let local_vid = me;

    let mut provision_requests = Vec::new();
    for tx in transactions {
        if topology_snapshot.is_single_shard_transaction(tx) {
            continue;
        }
        if let Some(request) = provision_request(topology_snapshot.shard_trie(), tx, local_shard) {
            provision_requests.push(request);
        }
    }
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
                    .filter(|&v| v != local_vid)
                    .collect()
            });
        }
    }

    Some((provision_requests, shard_recipients))
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Capped;
    use hyperscale_types::test_utils::TestCommittee;
    use hyperscale_types::{NetworkDefinition, ValidatorInfo, ValidatorSet};

    use super::*;

    fn single_shard_topology(committee: &TestCommittee) -> TopologySnapshot {
        let validators: Vec<ValidatorInfo> = (0..committee.size())
            .map(|i| ValidatorInfo {
                validator_id: committee.validator_id(i),
                public_key: *committee.public_key(i),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        TopologySnapshot::new(NetworkDefinition::simulator(), 1, validator_set)
    }

    // ─── records_written ───────────────────────────────────────────────

    use std::sync::Arc as StdArc;

    use hyperscale_types::{
        AggregateSignature, BlockHeight, ConsensusReceipt, ExecutionOutcome, GlobalReceiptHash,
        GlobalReceiptRoot, Role, SignerBitfield, StateWrites, StoredReceipt, TickHalf, TickId,
        TxOutcome, WeightedTimestamp,
    };
    use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash, Terms};
    use hyperscale_vm_types::{Address, AddressClass, ProtocolHasher as Hasher, ResourceAddr};

    /// A crossing produced under `producer`'s target and consumed under
    /// `consumer`'s, and its record key.
    fn crossing(seed: u8, producer: u8, consumer: u8) -> (CrossingId, SubstateKey) {
        let id = CrossingId {
            producer: Address::new([producer; 31], AddressClass::Component),
            consumer: Address::new([consumer; 31], AddressClass::Component),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        };
        let key = id.record_key(&Hasher);
        (id, key)
    }

    fn tx(seed: u8) -> TxHash {
        TxHash(Hash32([seed; 32]))
    }

    /// A succeeded receipt of `tx` writing `cells`.
    fn receipt(tx: TxHash, cells: Vec<(SubstateKey, Option<Vec<u8>>)>) -> StoredReceipt {
        StoredReceipt {
            tx_hash: tx,
            consensus: StdArc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                writes: StateWrites {
                    cells: cells.into_iter().collect(),
                    ..StateWrites::default()
                },
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
            metadata: None,
        }
    }

    /// A certificate of `tick` carrying `outcomes`.
    fn certificate(tick: TickId, outcomes: Vec<TxOutcome>) -> StdArc<ExecutionCertificate> {
        StdArc::new(ExecutionCertificate::new(
            tick,
            WeightedTimestamp::from_millis(3),
            GlobalReceiptRoot::ZERO,
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        ))
    }

    /// A finalization of `local`'s tick at height 3 carrying `certificates`
    /// and `receipts`.
    fn finalization(
        local: ShardId,
        certificates: Vec<StdArc<ExecutionCertificate>>,
        receipts: Vec<StoredReceipt>,
    ) -> Finalization {
        Finalization::new(
            TickId::new(local, BlockHeight::new(3)),
            TickHalf::Legs,
            &Capped::new(certificates).expect("a list written out in a test"),
            Capped::from_array([]),
        )
        .with_receipts(Capped::new(receipts).expect("a list written out in a test"))
    }

    const SUCCEEDED: ExecutionOutcome = ExecutionOutcome::Succeeded {
        receipt_hash: GlobalReceiptHash::ZERO,
    };

    /// A settling receipt writing a live record under its own
    /// transaction yields that key; a deletion, a settling member's
    /// receipt and a record-shaped write naming another transaction in
    /// the same finalization yield nothing.
    #[test]
    fn records_written_names_what_the_block_issued() {
        let local = ShardId::leaf(1, 0);
        let tick = TickId::new(local, BlockHeight::new(3));
        let (issued, issued_key) = crossing(1, 0x11, 0x21);
        let (deleted, deleted_key) = crossing(2, 0x12, 0x22);
        let (others, others_key) = crossing(4, 0x14, 0x24);
        let (settled, settled_key) = crossing(5, 0x15, 0x25);
        let resource = ResourceAddr::new([0xE1; 31]);
        let live = |id: CrossingId, tx: TxHash| id.cell(tx, resource, 7, 9_000, Terms::Owed);

        let finalization = finalization(
            local,
            vec![certificate(
                tick,
                vec![
                    TxOutcome::new(tx(0xA1), SUCCEEDED.clone()),
                    TxOutcome::new(tx(0xA5), SUCCEEDED.clone()).as_role(Role::Settling),
                ],
            )],
            vec![
                receipt(
                    tx(0xA1),
                    vec![
                        (issued_key, Some(live(issued, tx(0xA1)).to_bytes())),
                        (deleted_key, None),
                        (others_key, Some(live(others, tx(0xB0)).to_bytes())),
                    ],
                ),
                receipt(
                    tx(0xA5),
                    vec![(settled_key, Some(live(settled, tx(0xA5)).to_bytes()))],
                ),
            ],
        );
        let written = records_written(&finalization);
        assert_eq!(written.len(), 1, "{written:?}");
        assert_eq!(written[0].0, tx(0xA1));
        assert_eq!(written[0].1, issued_key);
        assert_eq!(written[0].2, live(issued, tx(0xA1)));
        let _ = deleted;
    }

    /// A member refused by a counterpart certificate and one left
    /// uncovered both carry succeeded writes with a record, and neither
    /// is named.
    #[test]
    fn records_written_skips_what_the_certificates_do_not_settle() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let tick = TickId::new(local, BlockHeight::new(3));
        let (refused, refused_key) = crossing(6, 0x16, 0x26);
        let (uncovered, uncovered_key) = crossing(7, 0x17, 0x27);
        let resource = ResourceAddr::new([0xE1; 31]);
        let live = |id: CrossingId, tx: TxHash| id.cell(tx, resource, 7, 9_000, Terms::Owed);

        let finalization = finalization(
            local,
            vec![
                certificate(
                    tick,
                    vec![
                        TxOutcome::new(tx(0xC1), SUCCEEDED.clone()).awaiting([remote]),
                        TxOutcome::new(tx(0xC2), SUCCEEDED.clone()).awaiting([remote]),
                    ],
                ),
                certificate(
                    TickId::new(remote, BlockHeight::new(5)),
                    vec![TxOutcome::new(tx(0xC1), ExecutionOutcome::Failed)],
                ),
            ],
            vec![
                receipt(
                    tx(0xC1),
                    vec![(refused_key, Some(live(refused, tx(0xC1)).to_bytes()))],
                ),
                receipt(
                    tx(0xC2),
                    vec![(uncovered_key, Some(live(uncovered, tx(0xC2)).to_bytes()))],
                ),
            ],
        );
        assert!(
            records_written(&finalization).is_empty(),
            "the refused member and the uncovered one issue nothing"
        );
    }

    /// Each record goes to the shard owning its consumer in the given
    /// trie, in certificate order, and never to the local shard.
    #[test]
    fn a_record_is_pushed_to_its_consumers_owner() {
        let local = ShardId::leaf(1, 0);
        let other = ShardId::leaf(1, 1);
        let trie = ShardTrie::from_leaves([local, other]);
        let resource = ResourceAddr::new([0xE1; 31]);
        // Consumers under prefixes the trie routes to `other` and to
        // `local`: the high bit of the owner decides under a one-bit
        // trie.
        let (away, away_key) = crossing(8, 0x18, 0xC8);
        let (home, home_key) = crossing(9, 0x19, 0x19);
        assert_eq!(trie.shard_for_prefix(away.consumer), other);
        assert_eq!(trie.shard_for_prefix(home.consumer), local);
        let cell = |id: CrossingId, tx: TxHash| id.cell(tx, resource, 7, 9_000, Terms::Owed);
        let finalization = |seed: u8, id: CrossingId, key: SubstateKey| {
            StdArc::new(Verifiable::from(finalization(
                local,
                vec![certificate(
                    TickId::new(local, BlockHeight::new(3)),
                    vec![TxOutcome::new(tx(seed), SUCCEEDED.clone())],
                )],
                vec![receipt(
                    tx(seed),
                    vec![(key, Some(cell(id, tx(seed)).to_bytes()))],
                )],
            )))
        };
        let pushes = record_pushes(
            &[
                finalization(0xD1, home, home_key),
                finalization(0xD2, away, away_key),
            ],
            &trie,
            local,
        );
        assert_eq!(pushes, BTreeMap::from([(other, vec![away_key])]));
    }

    // ─── peers_excluding_self ───────────────────────────────────────────

    #[test]
    fn peers_excluding_self_drops_local_validator() {
        let committee = TestCommittee::new(4, 42);
        let topology_snapshot = single_shard_topology(&committee);

        let peers = peers_excluding_self(&topology_snapshot, ValidatorId::new(0), ShardId::ROOT);
        assert_eq!(peers.len(), 3);
        assert!(!peers.contains(&ValidatorId::new(0)));
        assert!(peers.contains(&ValidatorId::new(1)));
        assert!(peers.contains(&ValidatorId::new(2)));
        assert!(peers.contains(&ValidatorId::new(3)));
    }

    #[test]
    fn peers_excluding_self_empty_for_unknown_shard() {
        let committee = TestCommittee::new(4, 42);
        let topology_snapshot = single_shard_topology(&committee);

        // Shard 99 has no committee — filter returns an empty vec regardless
        // of who the local validator is.
        let peers = peers_excluding_self(
            &topology_snapshot,
            ValidatorId::new(0),
            ShardId::leaf(8, 99),
        );
        assert!(peers.is_empty());
    }

    #[test]
    fn peers_excluding_self_empty_when_solo_validator() {
        let committee = TestCommittee::new(1, 42);
        let topology_snapshot = single_shard_topology(&committee);

        let peers = peers_excluding_self(&topology_snapshot, ValidatorId::new(0), ShardId::ROOT);
        assert!(peers.is_empty());
    }

    // ─── committee_public_keys_for_shard ────────────────────────────────

    #[test]
    fn committee_public_keys_for_shard_returns_keys_in_order() {
        let committee = TestCommittee::new(4, 42);
        let topology_snapshot = single_shard_topology(&committee);

        let keys = committee_public_keys_for_shard(&topology_snapshot, ShardId::ROOT)
            .expect("well-formed topology resolves every key");
        assert_eq!(keys.len(), 4);

        for (i, key) in keys.iter().enumerate() {
            assert_eq!(key, committee.public_key(i));
        }
    }

    #[test]
    fn committee_public_keys_for_shard_empty_for_unknown_shard() {
        let committee = TestCommittee::new(4, 42);
        let topology_snapshot = single_shard_topology(&committee);

        // An unknown shard has an empty committee, so the result is
        // `Some(vec![])` — not `None` (which is reserved for corruption).
        let keys = committee_public_keys_for_shard(&topology_snapshot, ShardId::leaf(8, 99))
            .expect("empty committee is not corruption");
        assert!(keys.is_empty());
    }
}
