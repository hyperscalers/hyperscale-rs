//! Pure topology-derived helpers used by the execution coordinator.
//!
//! Everything here is a free function over `TopologySnapshot` — no mutable
//! state, no async, no dependency on coordinator internals. Moved out of
//! the coordinator so the topology-only parts are unit-testable without a
//! full driver fixture.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_types::{
    ConsensusPublicKey, DeclaredKey, DeclaredRange, ExecutionCertificate, Finalization, ShardId,
    ShardTrie, SubstateKey, TopologySnapshot, Transaction, TxHash, ValidatorId, Verifiable,
    VoteCount, committed_crossings,
};

/// Per-shard recipient lists for provision broadcasting.
pub type ShardRecipients = HashMap<ShardId, Vec<ValidatorId>>;

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

/// The crossing bundles a block's committed certificates promise: one
/// request per accepted outcome that escrowed something, naming the
/// record cells its execution wrote and the shards that claim them.
///
/// Read off the certificate alone — every record cell rides its
/// escrowed entry — so a validator holding the block and not the
/// transactions builds the same requests, and in the same order the
/// block's provision roots bucket them.
#[must_use]
pub fn crossing_requests(
    certificates: &[Arc<Verifiable<Finalization>>],
    local_shard: ShardId,
) -> Vec<ProvisionsRequest> {
    let mut requests: Vec<ProvisionsRequest> = Vec::new();
    for finalization in certificates {
        let finalization = finalization.as_unverified();
        let promised: BTreeSet<TxHash> = committed_crossings(finalization, local_shard)
            .map(|(_, tx_hash)| tx_hash)
            .collect();
        let Some(ec) = finalization
            .execution_certificates()
            .iter()
            .find(|ec| ec.tick_id() == finalization.tick_id())
        else {
            continue;
        };
        for outcome in ec.tx_outcomes() {
            if !promised.contains(&outcome.tx_hash()) {
                continue;
            }
            requests.push(ProvisionsRequest {
                tx_hash: outcome.tx_hash(),
                targets: outcome
                    .crossing_targets()
                    .iter()
                    .copied()
                    .filter(|&target| target != local_shard)
                    .collect(),
                local_keys: outcome.escrowed().to_vec(),
                local_ranges: Vec::new(),
            });
        }
    }
    requests
}

/// Build provision requests and shard recipients for cross-shard
/// transactions and for the crossings the block's certificates commit.
///
/// Returns `None` if nothing in the block owes anyone a bundle.
pub fn build_provision_requests(
    topology_snapshot: &TopologySnapshot,
    transactions: &[Arc<Verifiable<Transaction>>],
    certificates: &[Arc<Verifiable<Finalization>>],
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
    // After the transactions, as the block's roots bucket them.
    provision_requests.extend(crossing_requests(certificates, local_shard));

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

    /// A crossing request names exactly what a committed outcome
    /// escrowed — the record cells, toward the shards that claim them —
    /// and a refused outcome yields none.
    #[test]
    fn crossing_requests_name_the_record_cells_the_outcome_escrowed() {
        use hyperscale_types::{
            AggregateSignature, BlockHeight, ExecutionCertificate, ExecutionOutcome, Finalization,
            GlobalReceiptHash, GlobalReceiptRoot, Hash, SignerBitfield, TickHalf, TickId,
            TxOutcome, WeightedTimestamp,
        };
        use hyperscale_vm_types::{Address, AddressClass, LocalKey};

        let local = ShardId::leaf(1, 0);
        let target = ShardId::leaf(1, 1);
        let record = SubstateKey {
            owner: Address::new([0xC1; 31], AddressClass::Component),
            local: LocalKey([1; 16]),
        };
        let accepted = TxHash::from(Hash::from_bytes(&[1; 32]));
        let refused = TxHash::from(Hash::from_bytes(&[2; 32]));
        let tick = TickId::new(local, BlockHeight::new(3));
        let ec = ExecutionCertificate::new(
            tick,
            WeightedTimestamp::from_millis(3),
            GlobalReceiptRoot::ZERO,
            vec![
                TxOutcome::new(
                    accepted,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
                .escrowing([record])
                .crossing_to([target]),
                TxOutcome::new(refused, ExecutionOutcome::Failed)
                    .escrowing([record])
                    .crossing_to([target]),
            ],
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        let finalization = Arc::new(Verifiable::from(Finalization::new(
            tick,
            TickHalf::Legs,
            vec![Arc::new(ec)],
            vec![],
        )));

        let requests = crossing_requests(std::slice::from_ref(&finalization), local);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].tx_hash, accepted);
        assert_eq!(requests[0].targets, vec![target]);
        assert_eq!(requests[0].local_keys, vec![record]);
        assert!(requests[0].local_ranges.is_empty());
    }
}
