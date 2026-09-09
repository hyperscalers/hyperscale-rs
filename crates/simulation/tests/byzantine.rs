//! A host that answers, and answers wrongly.
//!
//! Every evidence seam in the protocol is a payload checked against
//! something the checker already holds, and a drop rule cannot reach any
//! of them: a suppressed answer exercises the fetch fallback, not the
//! check. So these run against a host whose responses are rewritten in
//! flight — the smallest thing that puts a forgery in front of a checker.
//!
//! Sim-only. The rewrite hooks the in-memory transport's response leg,
//! which the libp2p gate has no counterpart for, so the portable
//! `FaultableCluster` surface does not carry it.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};
use hyperscale_scenarios::query::{declared_price, vault_balance};
use hyperscale_scenarios::tx::{
    build_transfer_tx, cross_shard_cast, cross_shard_genesis_accounts, validity_around,
};
use hyperscale_scenarios::wait::await_tx_terminal;
use hyperscale_scenarios::{Cluster, FaultHandle, FaultableCluster, ScenarioConfig, epochs};
use hyperscale_types::network::response::{GetProvisionResponse, GetStateProofResponse};
use hyperscale_types::{
    Deadline, MerkleInclusionProof, Provisions, ShardId, TransactionDecision, TransactionStatus,
    WeightedTimestamp, Window,
};
use support::SimCluster;

/// Two shards, four validators each, resharding disarmed — the topology
/// the delivery-lapse scenarios use, so the reclaim under test is the one
/// they already pin honestly.
const fn cross_shard_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 2,
        split_bytes: u64::MAX,
        latency: std::time::Duration::from_millis(150),
    }
}

/// A forged state proof convinces nobody, and the reclaim it was meant to
/// forge lands anyway from an honest peer.
///
/// The lapse arm rests on a proof: the payer's shard reads the delivery's
/// claim cell absent from the recipient's committed state past `L`, and
/// that absence is what licenses taking the crossing back. Every part of
/// that is checked at the fetch — the anchor's root, the keys asked, the
/// proof's own reconstruction — and this is the scenario that makes one
/// responder attack it rather than assuming the checks hold.
///
/// One host of the recipient's committee answers every state-proof
/// request with a payload that reconstructs nothing. The requester must
/// refuse it and rotate: the proof it eventually carries into a block is
/// an honest peer's, the reclaim commits, and the payment comes back. A
/// checker that took the forgery would reclaim on a proof of nothing —
/// which, for a delivery that had claimed, is the crossing disposed
/// twice.
#[test]
fn a_forged_state_proof_convinces_nobody() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &cross_shard_genesis_accounts());
    let (payer_key, from, to) = cross_shard_cast();
    let payer_shard = ShardId::leaf(1, 0);
    let recipient_shard = ShardId::leaf(1, 1);

    cluster.run_faultable(|c| {
        let before = vault_balance(c, payer_shard, from);
        let recipient_before = vault_balance(c, recipient_shard, to);
        let refused_before = c.metric(
            "fetch_responses_refused",
            Some("state_proof:unusable_proof"),
        );

        // Every host but one of the shard the proof is asked of answers
        // with a well-formed response carrying a proof that reconstructs
        // nothing. Well-formed is the whole point: rubbish bytes are
        // refused at the decode as an unusable *answer*, which says
        // nothing about the proof check, so the forgery is built as the
        // response type and the rubbish put where the multiproof goes.
        // One peer answers honestly, which is what makes this a rotation
        // rather than an outage — and all but one lie so the rotation is
        // exercised whichever probe's fetch lands first.
        let hosts = c.committee_hosts(recipient_shard);
        let (_honest, liars) = hosts
            .split_last()
            .expect("the recipient's shard has a seated committee");
        let unreconstructable = hbor_to_vec(&GetStateProofResponse::found(
            MerkleInclusionProof::new(vec![0xFF; 64]),
        ))
        .expect("a state-proof response encodes");
        let forged: Vec<_> = liars
            .iter()
            .map(|&liar| {
                let unreconstructable = unreconstructable.clone();
                c.rewrite_responses(
                    liar,
                    "state_proof.request",
                    Arc::new(move |_asked: &[u8], _honest: &[u8]| unreconstructable.clone()),
                )
            })
            .collect();

        // The bundle never reaches the recipient, so the delivery lapses
        // and the payer asks the recipient's chain about the claim cell.
        let broadcast_dropped = c.drop_type("provisions.broadcast");
        let fetch_dropped = c.drop_type("provision.request");

        let validity = validity_around(c.now());
        let tx = build_transfer_tx(&payer_key, from, to, 100, validity);
        let price = declared_price(c, &tx);
        let hash = tx.hash();
        c.submit(Arc::new(tx));

        let verdict = await_tx_terminal(c, hash, epochs(8));
        assert!(
            matches!(
                verdict,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "the payer's leg settles alone and accepts; verdict = {verdict:?}",
        );
        assert!(
            c.run_until(epochs(4), |c| vault_balance(c, payer_shard, from)
                == before - 100 - price),
            "the leg pays the payment and the price",
        );

        let lapse = Window::Lapse
            .of(Deadline::of(validity.end_timestamp_exclusive))
            .start;
        assert!(
            c.run_until(epochs(12), |c| WeightedTimestamp::ZERO.plus(c.now())
                >= lapse),
            "the cut must stand past the lapse",
        );
        assert!(
            broadcast_dropped.fired() > 0 && fetch_dropped.fired() > 0,
            "both bundle channels must actually have been exercised and cut",
        );

        // The reclaim lands on an honest peer's proof.
        assert!(
            c.run_until(epochs(10), |c| vault_balance(c, payer_shard, from)
                == before - price),
            "the payment must come back on a proof the checks accept; holds {}",
            vault_balance(c, payer_shard, from),
        );
        assert!(
            forged.iter().any(|handle| handle.fired() > 0),
            "the forgery has to have been served, or nothing was attacked",
        );
        // What the reclaim landing shows is a value arriving, which an
        // unattacked run shows too. The refusal is the defence itself,
        // and the reason is what says which check did the refusing.
        assert!(
            c.metric(
                "fetch_responses_refused",
                Some("state_proof:unusable_proof")
            ) > refused_before,
            "no state-proof answer was refused on its proof, so the reconstruction never ran",
        );
        assert_eq!(
            vault_balance(c, recipient_shard, to),
            recipient_before,
            "the recipient was never credited",
        );
    });
}

/// A host that answers provision fetches with rubbish is rotated past,
/// and the crossing it was carrying still lands.
///
/// The delivery side's evidence seam, and the second thing a drop rule
/// cannot reach: `cross_shard_provisions_drop_fetch_fallback` makes a
/// responder silent, which the fetch already has a rotation for. A
/// responder that answers is the case where a check has to do the work —
/// a bundle is admitted only against the source header it names and the
/// root that header carries, so one that decodes to nothing must be
/// refused at the fetch rather than carried into a block.
#[test]
fn a_host_answering_provision_fetches_with_rubbish_is_rotated_past() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &cross_shard_genesis_accounts());
    let (payer_key, from, to) = cross_shard_cast();
    let payer_shard = ShardId::leaf(1, 0);
    let recipient_shard = ShardId::leaf(1, 1);

    cluster.run_faultable(|c| {
        let recipient_before = vault_balance(c, recipient_shard, to);
        let refused_before = c.metric("fetch_responses_refused", Some("provision"));

        // The push is cut, so the recipient has to fetch — and one host
        // of the shard it fetches from answers wrongly.
        let broadcast_dropped = c.drop_type("provisions.broadcast");
        // Every host of the shard the bundle is fetched from lies once
        // and then answers honestly. Picking one host to lie always is
        // the shape that reads better and measures nothing: the fetch
        // chooses its peer, a committee this size offers two, and a run
        // where it never chose the liar passes without an attack. Lying
        // on the first answer, whoever gives it, puts the rubbish in
        // front of the check every time.
        let lies = Arc::new(AtomicUsize::new(0));
        let forged: Vec<FaultHandle> = c
            .committee_hosts(payer_shard)
            .into_iter()
            .map(|host| {
                let lies = Arc::clone(&lies);
                c.rewrite_responses(
                    host,
                    "provision.request",
                    Arc::new(move |_asked: &[u8], honest: &[u8]| {
                        if lies.fetch_add(1, Ordering::Relaxed) == 0 {
                            vec![0x5A; 96]
                        } else {
                            honest.to_vec()
                        }
                    }),
                )
            })
            .collect();

        let tx = build_transfer_tx(&payer_key, from, to, 100, validity_around(c.now()));
        let hash = tx.hash();
        c.submit(Arc::new(tx));

        let verdict = await_tx_terminal(c, hash, epochs(8));
        assert!(
            matches!(
                verdict,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "the payer's leg settles alone and accepts; verdict = {verdict:?}",
        );
        assert!(
            c.run_until(epochs(10), |c| vault_balance(c, recipient_shard, to)
                == recipient_before + 100),
            "the delivery must claim from an honest peer's bundle; holds {}",
            vault_balance(c, recipient_shard, to),
        );
        assert!(
            broadcast_dropped.fired() > 0,
            "the push has to be cut, or nothing fetched",
        );
        assert!(
            forged.iter().any(|handle| handle.fired() > 0) && lies.load(Ordering::Relaxed) > 0,
            "the rubbish has to have been served, or nothing was attacked",
        );
        assert!(
            c.metric("fetch_responses_refused", Some("provision:unusable_answer")) > refused_before,
            "the rubbish was never refused, so the delivery landing says nothing",
        );
    });
}

/// The first honest exchange, kept so it can be served again: the bytes
/// asked for, and the bytes answered.
type Kept = Arc<Mutex<Option<(Vec<u8>, Vec<u8>)>>>;

/// A bundle answered with a bundle for another transaction is refused,
/// and the delivery it was carrying still lands.
///
/// The forgery worth checking at a fetch is a well-formed answer to a
/// different question, and a delivery bundle is the one payload where
/// that is free to build: the attacker needs no keys and no forging at
/// all, only an earlier honest answer kept and served again. What refuses
/// it is that a bundle is admitted against the source header it names and
/// the transaction the requester asked about, so an answer that proves
/// somebody else's crossing proves nothing here.
///
/// Two payments, and the second one's fetch is answered with the first
/// one's bundle. Both must arrive: the recipient is credited twice, once
/// for each, and never once or three times.
#[test]
fn a_bundle_replayed_from_another_transaction_is_refused() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &cross_shard_genesis_accounts());
    let (payer_key, from, to) = cross_shard_cast();
    let payer_shard = ShardId::leaf(1, 0);
    let recipient_shard = ShardId::leaf(1, 1);

    cluster.run_faultable(|c| {
        let recipient_before = vault_balance(c, recipient_shard, to);
        let refused_before = c.metric("fetch_responses_refused", Some("provision:scope_mismatch"));
        let broadcast_dropped = c.drop_type("provisions.broadcast");

        // The first honest answer is kept with the question it answered,
        // and served once to whoever asks a different one. Lying on the
        // first mismatched ask rather than always is what makes this a
        // rotation: the fetch picks its peer from a committee of two, and
        // a liar that never stops leaves the second payment unclaimable
        // for reasons that are not the check's.
        let kept: Kept = Arc::new(Mutex::new(None));
        let lies = Arc::new(AtomicUsize::new(0));
        let replayed: Vec<FaultHandle> = c
            .committee_hosts(payer_shard)
            .into_iter()
            .map(|host| {
                let kept = Arc::clone(&kept);
                let lies = Arc::clone(&lies);
                c.rewrite_responses(
                    host,
                    "provision.request",
                    Arc::new(move |asked: &[u8], honest: &[u8]| {
                        let mut held = kept.lock().unwrap_or_else(PoisonError::into_inner);
                        let reply = match held.as_ref() {
                            Some((earlier, reply))
                                if earlier != asked
                                    && lies.fetch_add(1, Ordering::Relaxed) == 0 =>
                            {
                                reply.clone()
                            }
                            Some(_) => honest.to_vec(),
                            None => {
                                *held = Some((asked.to_vec(), honest.to_vec()));
                                honest.to_vec()
                            }
                        };
                        drop(held);
                        reply
                    }),
                )
            })
            .collect();

        let mut hashes = Vec::new();
        for amount in [100u128, 101] {
            let tx = build_transfer_tx(&payer_key, from, to, amount, validity_around(c.now()));
            hashes.push(tx.hash());
            c.submit(Arc::new(tx));
            assert!(
                matches!(
                    await_tx_terminal(c, *hashes.last().expect("just pushed"), epochs(8)),
                    Some(TransactionStatus::Completed(TransactionDecision::Accept))
                ),
                "the payer's leg settles alone and accepts",
            );
        }

        assert!(
            c.run_until(epochs(12), |c| vault_balance(c, recipient_shard, to)
                == recipient_before + 201),
            "both deliveries must claim, each from a bundle that proves its own \
             crossing; holds {}",
            vault_balance(c, recipient_shard, to),
        );
        assert!(
            broadcast_dropped.fired() > 0,
            "the push has to be cut, or nothing fetched",
        );
        assert!(
            replayed.iter().any(|handle| handle.fired() > 0) && lies.load(Ordering::Relaxed) > 0,
            "the stale bundle has to have been served, or nothing was attacked",
        );
        // Both deliveries landing is what an unattacked run shows too.
        // The bundle admitted against the transaction the requester asked
        // about is the rule under test, and refusing the replay is where
        // it runs.
        assert!(
            c.metric("fetch_responses_refused", Some("provision:scope_mismatch")) > refused_before,
            "the replayed bundle was never refused on its scope",
        );
    });
}

/// A bundle whose entries its own proof does not cover is refused, and
/// the delivery it was carrying still lands.
///
/// The third shape a responder can take, and the one the other cases
/// cannot reach: a well-formed answer to the right question, carrying
/// values the source chain never held. The tx-root the source header
/// commits is over the transaction hashes, so tampering with an entry's
/// bytes leaves it intact and every check short of the merkle proof
/// passes. What refuses it is that a bundle's entries are held to the
/// state root of the block that issued them, which runs off
/// `Action::VerifyProvisions` rather than at the fetch.
///
/// One byte of one entry, rather than a decoded and inflated
/// `EscrowedValue`: the proof covers the whole value either way, so both
/// reach the same check, and the cheaper forgery needs nothing of the
/// engine's encoding.
#[test]
fn a_bundle_whose_entries_its_proof_does_not_cover_is_refused() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &cross_shard_genesis_accounts());
    let (payer_key, from, to) = cross_shard_cast();
    let payer_shard = ShardId::leaf(1, 0);
    let recipient_shard = ShardId::leaf(1, 1);

    cluster.run_faultable(|c| {
        let recipient_before = vault_balance(c, recipient_shard, to);
        let refused_before = c.metric(
            "fetch_responses_refused",
            Some("provision:unproven_entries"),
        );
        let broadcast_dropped = c.drop_type("provisions.broadcast");

        // Every host tampers with the first bundle it is asked for and
        // answers honestly after, so the check runs whichever peer the
        // fetch picked and the retry still has somewhere to land.
        let tampered = Arc::new(AtomicUsize::new(0));
        let forged: Vec<FaultHandle> = c
            .committee_hosts(payer_shard)
            .into_iter()
            .map(|host| {
                let tampered = Arc::clone(&tampered);
                c.rewrite_responses(
                    host,
                    "provision.request",
                    Arc::new(move |_asked: &[u8], honest: &[u8]| {
                        let Ok(response) = hbor_from_slice::<GetProvisionResponse>(honest) else {
                            return honest.to_vec();
                        };
                        let Some(bundle) = response.provisions.as_deref() else {
                            return honest.to_vec();
                        };
                        let mut entries = bundle.transactions().clone();
                        let Some(value) = entries
                            .iter_mut()
                            .flat_map(|entry| entry.entries.iter_mut())
                            .find_map(|entry| entry.value.as_mut())
                            .and_then(|bytes| bytes.first_mut())
                        else {
                            return honest.to_vec();
                        };
                        if tampered.fetch_add(1, Ordering::Relaxed) > 0 {
                            return honest.to_vec();
                        }
                        *value = value.wrapping_add(1);
                        let forged = Provisions::new(
                            bundle.source_shard(),
                            bundle.target_shard(),
                            bundle.block_height(),
                            bundle.source_block_ts(),
                            bundle.proof().clone(),
                            entries,
                        );
                        hbor_to_vec(&GetProvisionResponse {
                            provisions: Some(Arc::new(forged)),
                        })
                        .unwrap_or_else(|_| honest.to_vec())
                    }),
                )
            })
            .collect();

        let tx = build_transfer_tx(&payer_key, from, to, 100, validity_around(c.now()));
        let hash = tx.hash();
        c.submit(Arc::new(tx));

        let verdict = await_tx_terminal(c, hash, epochs(8));
        assert!(
            matches!(
                verdict,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "the payer's leg settles alone and accepts; verdict = {verdict:?}",
        );
        assert!(
            c.run_until(epochs(10), |c| vault_balance(c, recipient_shard, to)
                == recipient_before + 100),
            "the delivery must claim from a bundle whose proof covers it; holds {}",
            vault_balance(c, recipient_shard, to),
        );
        assert!(
            broadcast_dropped.fired() > 0,
            "the push has to be cut, or nothing fetched",
        );
        assert!(
            forged.iter().any(|handle| handle.fired() > 0) && tampered.load(Ordering::Relaxed) > 0,
            "the tampered bundle has to have been served, or nothing was attacked",
        );
        assert!(
            c.metric(
                "fetch_responses_refused",
                Some("provision:unproven_entries")
            ) > refused_before,
            "the tampered bundle was never refused on its proof",
        );
    });
}
