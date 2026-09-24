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

use hyperscale_hbor::{Bytes, Capped, from_slice as hbor_from_slice, to_vec as hbor_to_vec};
use hyperscale_scenarios::query::{declared_price, vault_balance};
use hyperscale_scenarios::tx::{
    build_transfer_tx, cross_shard_cast, cross_shard_genesis_accounts, validity_around,
};
use hyperscale_scenarios::wait::await_tx_terminal;
use hyperscale_scenarios::{Cluster, FaultHandle, FaultableCluster, ScenarioConfig, epochs};
use hyperscale_types::network::response::GetStateProofResponse;
use hyperscale_types::{
    Deadline, MAX_VALIDITY_RANGE, MerkleInclusionProof, ShardId, TransactionDecision,
    TransactionStatus, WeightedTimestamp,
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
/// proof's own reconstruction — and this is the scenario that makes a
/// responder attack it rather than assuming the checks hold.
///
/// The first state-proof answer the recipient's committee gives, whichever
/// host gives it, carries a payload that reconstructs nothing. The
/// requester must refuse it and rotate: the proof it eventually carries
/// into a block is an honest peer's, the reclaim commits, and the payment
/// comes back. A checker that took the forgery would reclaim on a proof of
/// nothing — which, for a delivery that had claimed, is the crossing
/// disposed twice.
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

        // Every host of the shard the proof is asked of answers its first
        // state-proof request with a well-formed response carrying a proof
        // that reconstructs nothing, and answers honestly after. Well-formed
        // is the whole point: rubbish bytes are refused at the decode as an
        // unusable *answer*, which says nothing about the proof check, so the
        // forgery is built as the response type and the rubbish put where the
        // multiproof goes.
        //
        // Lying on the first answer, whoever gives it, rather than picking one
        // host to lie always: the fetch chooses its peer, a committee this size
        // offers two, and a run where it never chose the liar passes without an
        // attack. An honest answer waiting behind the refusal is what makes
        // this a rotation rather than an outage.
        let unreconstructable = hbor_to_vec(&GetStateProofResponse::found(
            MerkleInclusionProof::new(vec![0xFF; 64]),
            Capped::empty(),
        ))
        .expect("a state-proof response encodes");
        let lies = Arc::new(AtomicUsize::new(0));
        let forged: Vec<FaultHandle> = c
            .committee_hosts(recipient_shard)
            .into_iter()
            .map(|host| {
                let unreconstructable = unreconstructable.clone();
                let lies = Arc::clone(&lies);
                c.rewrite_responses(
                    host,
                    "state_proof.request",
                    Arc::new(move |_asked: &[u8], honest: &[u8]| {
                        if lies.fetch_add(1, Ordering::Relaxed) == 0 {
                            unreconstructable.clone()
                        } else {
                            honest.to_vec()
                        }
                    }),
                )
            })
            .collect();

        // The bundle does not reach the recipient while the cut stands,
        // so the delivery has not claimed and the payer goes on asking
        // the recipient's chain about the claim cell — which is the
        // state-proof fetch this attacks.
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

        let asking = Deadline::of(validity.end_timestamp_exclusive)
            .at()
            .plus(MAX_VALIDITY_RANGE);
        assert!(
            c.run_until(epochs(12), |c| WeightedTimestamp::ZERO.plus(c.now())
                >= asking),
            "the cut must stand while the payer is asking about the claim",
        );
        assert!(
            broadcast_dropped.fired() > 0 && fetch_dropped.fired() > 0,
            "both bundle channels must actually have been exercised and cut",
        );
        assert!(
            forged.iter().any(|handle| handle.fired() > 0),
            "the forgery has to have been served, or nothing was attacked",
        );
        // The refusal is the defence itself, and the reason is what says
        // which check did the refusing.
        assert!(
            c.metric(
                "fetch_responses_refused",
                Some("state_proof:unusable_proof")
            ) > refused_before,
            "no state-proof answer was refused on its proof, so the reconstruction never ran",
        );

        // And the shard makes progress past the attack: with the bundle
        // flowing again the delivery lands and the recipient is paid,
        // which is where the crossing was owed all along.
        c.clear_drops();
        assert!(
            c.run_until(epochs(12), |c| vault_balance(c, recipient_shard, to)
                == recipient_before + 100),
            "the recipient must be paid once the bundle can reach it; holds {}",
            vault_balance(c, recipient_shard, to),
        );
        assert_eq!(
            vault_balance(c, payer_shard, from),
            before - 100 - price,
            "and nothing took the crossing back on the way",
        );
    });
}

/// A host that answers a record's read with rubbish is rotated past,
/// and the crossing it was carrying still lands.
///
/// The delivery side's evidence seam, and the second thing a drop rule
/// cannot reach: a silent responder the fetch already has a rotation
/// for. A responder that answers is the case where a check has to do
/// the work — a state proof is checked against the anchor the requester
/// commit-proved, so an answer that decodes to nothing must be refused
/// at the fetch rather than carried into a block.
#[test]
fn a_host_answering_a_records_read_with_rubbish_is_rotated_past() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &cross_shard_genesis_accounts());
    let (payer_key, from, to) = cross_shard_cast();
    let payer_shard = ShardId::leaf(1, 0);
    let recipient_shard = ShardId::leaf(1, 1);

    cluster.run_faultable(|c| {
        let recipient_before = vault_balance(c, recipient_shard, to);
        let refused_before = c.metric("fetch_responses_refused", Some("state_proof"));

        // Every host of the shard the record is read from lies once
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
                    "state_proof.request",
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
            "the delivery must run against an honest peer's reading; holds {}",
            vault_balance(c, recipient_shard, to),
        );
        assert!(
            forged.iter().any(|handle| handle.fired() > 0) && lies.load(Ordering::Relaxed) > 0,
            "the rubbish has to have been served, or nothing was attacked",
        );
        assert!(
            c.metric("fetch_responses_refused", Some("state_proof")) > refused_before,
            "the rubbish was never refused, so the delivery landing says nothing",
        );
    });
}

/// The first honest exchange, kept so it can be served again: the bytes
/// asked for, and the bytes answered.
type Kept = Arc<Mutex<Option<(Vec<u8>, Vec<u8>)>>>;

/// A record's read answered with the proof of another record is
/// refused, and the delivery it was carrying still lands.
///
/// The forgery worth checking at a fetch is a well-formed answer to a
/// different question, and a served proof is the one payload where that
/// is free to build: the attacker needs no keys and no forging at all,
/// only an earlier honest answer kept and served again. What refuses it
/// is that a proof is walked against the anchor the requester
/// commit-proved and over the keys it asked about, so an answer that
/// proves somebody else's crossing proves nothing here.
///
/// Two payments, and the second one's read is answered with the first
/// one's proof. Both must arrive: the recipient is credited twice, once
/// for each, and never once or three times.
#[test]
fn a_proof_replayed_from_another_records_read_is_refused() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &cross_shard_genesis_accounts());
    let (payer_key, from, to) = cross_shard_cast();
    let payer_shard = ShardId::leaf(1, 0);
    let recipient_shard = ShardId::leaf(1, 1);

    cluster.run_faultable(|c| {
        let recipient_before = vault_balance(c, recipient_shard, to);
        let refused_before = c.metric(
            "fetch_responses_refused",
            Some("state_proof:unusable_proof"),
        );

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
                    "state_proof.request",
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
            "both deliveries must run, each against a reading that proves its own \
             record; holds {}",
            vault_balance(c, recipient_shard, to),
        );
        assert!(
            replayed.iter().any(|handle| handle.fired() > 0) && lies.load(Ordering::Relaxed) > 0,
            "the stale proof has to have been served, or nothing was attacked",
        );
        // Both deliveries landing is what an unattacked run shows too.
        // The proof walked over the keys the requester asked about is the
        // rule under test, and refusing the replay is where it runs.
        assert!(
            c.metric(
                "fetch_responses_refused",
                Some("state_proof:unusable_proof")
            ) > refused_before,
            "the replayed proof was never refused on its keys",
        );
    });
}

/// A record value a served proof does not cover is refused, and the
/// delivery it was carrying still lands.
///
/// The third shape a responder can take, and the one the other cases
/// cannot reach: a well-formed answer to the right question, carrying a
/// value the source chain never held. The proof reconstructs the root
/// and claims the key, so every check short of hashing the value passes.
/// What refuses it is that a served value is held to the presence the
/// proof reconstructs for its key, at the fetch, so the peer rotates and
/// an honest answer lands.
///
/// One byte of the value, rather than a decoded and inflated record:
/// the hash covers the whole value either way, so both reach the same
/// check, and the cheaper forgery needs nothing of the kernel's
/// encoding.
#[test]
fn a_record_value_its_proof_does_not_cover_is_refused() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &cross_shard_genesis_accounts());
    let (payer_key, from, to) = cross_shard_cast();
    let payer_shard = ShardId::leaf(1, 0);
    let recipient_shard = ShardId::leaf(1, 1);

    cluster.run_faultable(|c| {
        let recipient_before = vault_balance(c, recipient_shard, to);
        let refused_before = c.metric(
            "fetch_responses_refused",
            Some("state_proof:value_off_its_proof"),
        );

        // Every host tampers with the first record value it is asked for
        // and answers honestly after, so the check runs whichever peer
        // the fetch picked and the retry still has somewhere to land.
        let tampered = Arc::new(AtomicUsize::new(0));
        let forged: Vec<FaultHandle> = c
            .committee_hosts(payer_shard)
            .into_iter()
            .map(|host| {
                let tampered = Arc::clone(&tampered);
                c.rewrite_responses(
                    host,
                    "state_proof.request",
                    Arc::new(move |_asked: &[u8], honest: &[u8]| {
                        let Ok(mut response) = hbor_from_slice::<GetStateProofResponse>(honest)
                        else {
                            return honest.to_vec();
                        };
                        if response.values.is_empty() {
                            return honest.to_vec();
                        }
                        if tampered.fetch_add(1, Ordering::Relaxed) > 0 {
                            return honest.to_vec();
                        }
                        let (key, bytes) = response.values[0].clone();
                        let mut bytes = bytes.to_vec();
                        bytes[0] = bytes[0].wrapping_add(1);
                        let forged = Bytes::new(bytes).expect("one byte changed fits");
                        response.values = Capped::from_array([(key, forged)]);
                        hbor_to_vec(&response).unwrap_or_else(|_| honest.to_vec())
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
            "the delivery must run against a value its proof covers; holds {}",
            vault_balance(c, recipient_shard, to),
        );
        assert!(
            forged.iter().any(|handle| handle.fired() > 0) && tampered.load(Ordering::Relaxed) > 0,
            "the tampered value has to have been served, or nothing was attacked",
        );
        assert!(
            c.metric(
                "fetch_responses_refused",
                Some("state_proof:value_off_its_proof")
            ) > refused_before,
            "the tampered value was never refused on its proof",
        );
    });
}
