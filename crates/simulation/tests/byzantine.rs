//! A host that answers, and answers wrongly.
//!
//! Every evidence seam in the protocol is a payload checked against
//! something the checker already holds, and a drop rule cannot reach any
//! of them: a suppressed answer exercises the fetch fallback, not the
//! check. So these run against a host whose responses are rewritten in
//! flight — the smallest thing that puts a forgery in front of a checker.
//!
//! Sim-only. The rewrite hooks the in-memory transport's response leg, and
//! the portable `FaultableCluster` surface does not carry response
//! rewrites.

mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_hbor::{Bytes, Capped, from_slice as hbor_from_slice, to_vec as hbor_to_vec};
use hyperscale_scenarios::query::{declared_price, vault_balance};
use hyperscale_scenarios::tx::{
    build_swap_tx, build_transfer_tx, cross_shard_cast, cross_shard_genesis_accounts,
    validity_around,
};
use hyperscale_scenarios::wait::await_tx_terminal;
use hyperscale_scenarios::{
    BOOK_SHARD, BOOK_VENUE_SHARD, BookRoute, Cluster, FaultHandle, FaultableCluster, SWAP_INPUT,
    SWAPPER_SHARD, ScenarioConfig, StockedVenue, VENUE_SHARD, book_route_genesis_accounts,
    committees_on_separate_hosts, departing_venue_split_bytes, epochs, grind_onto, stand_up_venue,
    venue_genesis_accounts,
};
use hyperscale_storage::entry_from_leaf;
use hyperscale_storage::tree::proofs::generate_proof;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::network::request::{GetProvisionsRequest, GetStateProofRequest};
use hyperscale_types::network::response::{GetProvisionResponse, GetStateProofResponse};
use hyperscale_types::{
    BlockHeight, Ed25519PrivateKey, LocalKey, MerkleInclusionProof, PrincipalAddr, Provision,
    ProvisionParts, ShardId, SubstateEntry, SubstateKey, TransactionDecision, TransactionStatus,
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

/// A venue on one shard and its callers on the other, over the fixture
/// packages: a swap's core reads the caller's escrowed record, which is
/// the record read these tests attack. Every committee sits on hosts of
/// its own, so that read crosses the wire the rewrite sits on.
fn venue_swap_cluster() -> SimCluster {
    SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &cross_shard_config(),
        42,
        &venue_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
}

/// Cut the pushes of the caller's shard to the venue's, so the core
/// reads the caller's record by asking for it — the fetch these tests
/// attack.
fn cut_record_pushes(c: &mut SimCluster) {
    let (callers, venues) = committees_on_separate_hosts(c, SWAPPER_SHARD, VENUE_SHARD);
    c.drop_type_between(&callers, &venues, "crossing.readings");
}

/// Submit a swap of `caller`'s through `venue` and wait for it to
/// accept: the core has read the caller's record and run.
fn swap_accepts(
    c: &mut SimCluster,
    venue: &StockedVenue,
    caller_key: &Ed25519PrivateKey,
    caller: PrincipalAddr,
) {
    let tx = build_swap_tx(
        caller_key,
        caller,
        &venue.meta,
        *PROTOCOL_RESOURCE,
        SWAP_INPUT,
        0,
        validity_around(c.now()),
    );
    let hash = tx.hash();
    c.submit(tx);
    let verdict = await_tx_terminal(c, hash, epochs(12));
    assert!(
        matches!(
            verdict,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the swap must accept, its core having read the caller's record; verdict = {verdict:?}",
    );
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
    let mut cluster = SimCluster::with_grown_accounts_on_dedicated_pool_hosts(
        &cross_shard_config(),
        42,
        &cross_shard_genesis_accounts(),
    );
    let (payer_key, from, to) = cross_shard_cast();
    let payer_shard = ShardId::leaf(1, 0);
    let recipient_shard = ShardId::leaf(1, 1);

    cluster.run_faultable(|c| {
        committees_on_separate_hosts(c, payer_shard, recipient_shard);
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

        // The record's push does not reach the recipient while the cut
        // stands, so nothing credits it and the payer goes on asking the
        // recipient's chain about the claim cell — which is the
        // state-proof fetch this attacks.
        let push_dropped = c.drop_type("crossing.readings");

        let validity = validity_around(c.now());
        let tx = build_transfer_tx(&payer_key, from, to, 100, validity);
        let price = declared_price(c, &tx);
        let hash = tx.hash();
        c.submit(tx);

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

        // The payer asks about the claim at a boundary of the recipient's
        // shard recorded past the validity end, so the cut stands until
        // that ask has been answered, which is a boundary hop after the
        // validity end rather than at it.
        assert!(
            c.run_until(epochs(12), |_| forged
                .iter()
                .any(|handle| handle.fired() > 0)),
            "the forgery has to have been served, or nothing was attacked",
        );
        assert!(
            push_dropped.fired() > 0,
            "the record's push must actually have been exercised and cut",
        );
        // The refusal is the defence itself, and the reason is what says
        // which check did the refusing. It is counted once the forged
        // answer reaches the asker, which can be after the serve is seen.
        assert!(
            c.run_until(epochs(1), |c| c.metric(
                "fetch_responses_refused",
                Some("state_proof:unusable_proof"),
            ) > refused_before),
            "no state-proof answer was refused on its proof, so the reconstruction never ran",
        );

        // And the shard makes progress past the attack: with the push
        // flowing again the recipient is credited, which is where the
        // crossing was owed all along.
        c.clear_drops();
        assert!(
            c.run_until(epochs(12), |c| vault_balance(c, recipient_shard, to)
                == recipient_before + 100),
            "the recipient must be paid once the record can reach it; holds {}",
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
/// The consuming core's evidence seam, and the second thing a drop rule
/// cannot reach: a silent responder the fetch already has a rotation
/// for. A responder that answers is the case where a check has to do
/// the work — a state proof is checked against the anchor the requester
/// commit-proved, so an answer that decodes to nothing must be refused
/// at the fetch rather than carried into a block.
#[test]
fn a_host_answering_a_records_read_with_rubbish_is_rotated_past() {
    let mut cluster = venue_swap_cluster();
    cluster.run_faultable(|c| {
        let mut taken = Vec::new();
        let venue = stand_up_venue(c, VENUE_SHARD, &mut taken);
        let (caller_key, caller) = grind_onto(SWAPPER_SHARD, &mut taken);
        cut_record_pushes(c);
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
            .committee_hosts(SWAPPER_SHARD)
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

        swap_accepts(c, &venue, &caller_key, caller);
        assert!(
            forged.iter().any(|handle| handle.fired() > 0) && lies.load(Ordering::Relaxed) > 0,
            "the rubbish has to have been served, or nothing was attacked",
        );
        assert!(
            c.metric("fetch_responses_refused", Some("state_proof")) > refused_before,
            "the rubbish was never refused, so the swap landing says nothing",
        );
    });
}

/// The first honest exchange, kept so it can be served again: the bytes
/// asked for, and the bytes answered.
type Kept = Arc<Mutex<Option<(Vec<u8>, Vec<u8>)>>>;

/// A record's read answered with the proof of another record is
/// refused, and the swap it was carrying still lands.
///
/// The forgery worth checking at a fetch is a well-formed answer to a
/// different question, and a served proof is the one payload where that
/// is free to build: the attacker needs no keys and no forging at all,
/// only an earlier honest answer kept and served again. What refuses it
/// is that a proof is walked against the anchor the requester
/// commit-proved and over the keys it asked about, so an answer that
/// proves somebody else's crossing proves nothing here.
///
/// Two swaps, and the second one's read is answered with the first
/// one's proof. Both must accept, each on a reading of its own record.
#[test]
fn a_proof_replayed_from_another_records_read_is_refused() {
    let mut cluster = venue_swap_cluster();
    cluster.run_faultable(|c| {
        let mut taken = Vec::new();
        let venue = stand_up_venue(c, VENUE_SHARD, &mut taken);
        let (caller_key, caller) = grind_onto(SWAPPER_SHARD, &mut taken);
        cut_record_pushes(c);
        let refused_before = c.metric("fetch_responses_refused", Some("state_proof"));

        // The first honest answer is kept with the question it answered,
        // and served once to whoever asks a different one. Lying on the
        // first mismatched ask rather than always is what makes this a
        // rotation: the fetch picks its peer from a committee of two, and
        // a liar that never stops leaves the second payment unclaimable
        // for reasons that are not the check's.
        let kept: Kept = Arc::new(Mutex::new(None));
        let lies = Arc::new(AtomicUsize::new(0));
        let replayed: Vec<FaultHandle> = c
            .committee_hosts(SWAPPER_SHARD)
            .into_iter()
            .map(|host| {
                let kept = Arc::clone(&kept);
                let lies = Arc::clone(&lies);
                c.rewrite_responses(
                    host,
                    "state_proof.request",
                    Arc::new(move |asked: &[u8], honest: &[u8]| {
                        let mut held = kept.lock().unwrap_or_else(PoisonError::into_inner);
                        // Another question is other keys: the same keys
                        // asked again at a later height over an unchanged
                        // root are the same question, and its answer
                        // honestly answers it.
                        let keys = |bytes: &[u8]| {
                            hbor_from_slice::<GetStateProofRequest>(bytes)
                                .map(|request| request.keys)
                                .ok()
                        };
                        let reply = match held.as_ref() {
                            Some((earlier, reply))
                                if keys(earlier) != keys(asked)
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

        // Two swaps, each through the core's read of its own record.
        swap_accepts(c, &venue, &caller_key, caller);
        swap_accepts(c, &venue, &caller_key, caller);
        assert!(
            replayed.iter().any(|handle| handle.fired() > 0) && lies.load(Ordering::Relaxed) > 0,
            "the stale proof has to have been served, or nothing was attacked",
        );
        // Both swaps accepting is what an unattacked run shows too. The
        // proof walked over the keys the requester asked about, and the
        // values held to what it proves for them, is the rule under
        // test, and refusing the replay is where it runs.
        assert!(
            c.metric("fetch_responses_refused", Some("state_proof")) > refused_before,
            "the replayed proof was never refused",
        );
    });
}

/// A record value a served proof does not cover is refused, and the
/// swap it was carrying still lands.
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
    let mut cluster = venue_swap_cluster();
    cluster.run_faultable(|c| {
        let mut taken = Vec::new();
        let venue = stand_up_venue(c, VENUE_SHARD, &mut taken);
        let (caller_key, caller) = grind_onto(SWAPPER_SHARD, &mut taken);
        cut_record_pushes(c);
        let refused_before = c.metric(
            "fetch_responses_refused",
            Some("state_proof:value_off_its_proof"),
        );

        // Every host tampers with the first record value it is asked for
        // and answers honestly after, so the check runs whichever peer
        // the fetch picked and the retry still has somewhere to land.
        let tampered = Arc::new(AtomicUsize::new(0));
        let forged: Vec<FaultHandle> = c
            .committee_hosts(SWAPPER_SHARD)
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

        swap_accepts(c, &venue, &caller_key, caller);
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

/// The book route's four quarters, grown on dedicated pool hosts, with
/// the reshape trigger armed above every quarter and never voted down:
/// the venue's shard stays whole.
fn book_route_cluster() -> SimCluster {
    SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &ScenarioConfig {
            shard_size: 4,
            vnodes_per_host: 1,
            pool_surplus: 18,
            num_shards: 4,
            split_bytes: departing_venue_split_bytes(),
            latency: std::time::Duration::from_millis(150),
        },
        42,
        &book_route_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
}

/// Rewrites one part's entries, or leaves the part alone with `None`.
type EntryForgery = fn(&Provision) -> Option<Vec<SubstateEntry>>;

/// `honest` with every part `forge` rewrites carrying the entries it
/// gives, re-proved over them under the state root of its source height
/// in `storage`, so the forged part's own proof checks. `None` where no
/// part could be forged.
fn reprove_parts(storage: &SimShardStorage, honest: &[u8], forge: EntryForgery) -> Option<Vec<u8>> {
    let response = hbor_from_slice::<GetProvisionResponse>(honest).ok()?;
    let mut forged = false;
    let parts = response
        .parts
        .into_inner()
        .into_iter()
        .map(|part| {
            let Some(entries) = forge(&part) else {
                return part;
            };
            let keys: Vec<SubstateKey> = entries.iter().map(|entry| entry.key).collect();
            let Some(proof) = generate_proof(storage, &keys, part.block_height()) else {
                return part;
            };
            let Ok(entries) = Capped::new(entries) else {
                return part;
            };
            forged = true;
            Provision::new(ProvisionParts {
                source_shard: part.source_shard(),
                target_shard: part.target_shard(),
                block_height: part.block_height(),
                source_block_ts: part.source_block_ts(),
                clock: part.clock(),
                tx_hash: part.tx_hash(),
                entries,
                proof,
                leaf: part.leaf().clone(),
            })
        })
        .collect();
    forged.then(|| {
        hbor_to_vec(&GetProvisionResponse {
            parts: Capped::new(parts).expect("no more parts than the honest answer"),
            count: response.count,
        })
        .expect("an answer encodes")
    })
}

/// One range entry left out of a part serving two or more.
fn drop_a_range_entry(part: &Provision) -> Option<Vec<SubstateEntry>> {
    let ranged: Vec<usize> = part
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            entry
                .value
                .as_ref()
                .is_some_and(|value| entry_from_leaf(entry.key, value).is_some())
        })
        .map(|(at, _)| at)
        .collect();
    if ranged.len() < 2 {
        return None;
    }
    let dropped = ranged[ranged.len() / 2];
    Some(
        part.entries()
            .iter()
            .enumerate()
            .filter(|(at, _)| *at != dropped)
            .map(|(_, entry)| entry.clone())
            .collect(),
    )
}

/// One made-up key added to a part, under the owner of its first entry
/// so it falls in the source's prefix, carried as absent at its sorted
/// position. The source never committed a value there, so the proof
/// re-built over the part's keys proves the absence.
fn add_an_uncommitted_key(part: &Provision) -> Option<Vec<SubstateEntry>> {
    let entries = part.entries();
    let added = SubstateKey {
        owner: entries.first()?.key.owner,
        local: LocalKey([0xEE; 16]),
    };
    let at = entries
        .iter()
        .position(|entry| entry.key.to_bytes() >= added.to_bytes())
        .unwrap_or(entries.len());
    if entries.get(at).is_some_and(|entry| entry.key == added) {
        return None;
    }
    let mut forged = entries.to_vec();
    forged.insert(at, SubstateEntry::new(added, None));
    Some(forged)
}

/// Run the book route with the book's provision gossip to the venue's
/// shard dropped, and the host first asked about each source block
/// answering every fetch for that block with its parts rewritten by
/// `forge`. The rewrite has to fire, the venue's shard has to refuse a
/// part at its leaf, and the route has to settle at the closed form and
/// conserve.
fn book_route_refuses(forge: EntryForgery, forgery: &str) {
    let mut cluster = book_route_cluster();
    cluster.run_faultable(|c| {
        let mut route = BookRoute::stand_up(c);
        let (books, venues) = committees_on_separate_hosts(c, BOOK_SHARD, BOOK_VENUE_SHARD);
        let gossip = c.drop_type_between(&books, &venues, "provisions.broadcast");

        let forged = Arc::new(AtomicUsize::new(0));
        let liars: Arc<Mutex<BTreeMap<BlockHeight, usize>>> = Arc::default();
        for host in c.committee_hosts(BOOK_SHARD) {
            let storage = c
                .runner()
                .shard_storage(
                    u32::try_from(host).expect("a host index fits a node index"),
                    BOOK_SHARD,
                )
                .expect("a committee host stores its shard");
            let forged = Arc::clone(&forged);
            let liars = Arc::clone(&liars);
            let _ = c.rewrite_responses(
                host,
                "provision.request",
                Arc::new(move |asked: &[u8], honest: &[u8]| {
                    let Ok(request) = hbor_from_slice::<GetProvisionsRequest>(asked) else {
                        return honest.to_vec();
                    };
                    let liar = *liars
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .entry(request.height)
                        .or_insert(host);
                    if liar != host {
                        return honest.to_vec();
                    }
                    reprove_parts(&storage, honest, forge).map_or_else(
                        || honest.to_vec(),
                        |lie| {
                            forged.fetch_add(1, Ordering::Relaxed);
                            lie
                        },
                    )
                }),
            );
        }
        let refused_before = c.metric(
            "fetch_responses_refused",
            Some("provision:content_mismatch"),
        );

        let fill = route.run(c, epochs(12), "byzantine");
        assert!(
            gossip.fired() > 0 && forged.load(Ordering::Relaxed) > 0,
            "a part {forgery} has to have been served, or nothing was attacked: {fill:?}",
        );
        assert!(
            c.metric(
                "fetch_responses_refused",
                Some("provision:content_mismatch"),
            ) > refused_before,
            "no part {forgery} was refused at its leaf, so the root check never ran",
        );
        route.assert_conserved(c, epochs(12));
    });
}

/// A part that drops one entry of its transaction's declared interval
/// is refused, and the route it provisions completes on an honest
/// peer's part.
///
/// The book's shard withholds its provision gossip, so the venue's shard
/// fetches the route's part. The host first asked about each source
/// block — the proposer, which the fetch prefers — answers every fetch
/// for that block with the route's part missing one of the interval's
/// entries, re-proved over what it keeps: its own proof checks, and the
/// entries it carries are the source's. Only the leaf binding the keys a
/// transaction is served to the header's root tells it apart. Taken,
/// the venue's shard would walk one ask fewer than the book's own shard
/// does, and the core would not agree; refused, the venue's shard asks
/// another peer, and the route settles at the closed form over the asks
/// the book's committing block left.
#[test]
fn a_served_part_dropping_a_range_entry_is_refused() {
    book_route_refuses(drop_a_range_entry, "missing a range entry");
}

/// A fetched part carrying a key its source header did not commit is
/// refused, and the route it provisions completes on an honest peer's
/// part.
///
/// The same attack as dropping a range entry, from the other side: the
/// lying host adds a key under the source's prefix to every part it
/// serves, carried as absent and re-proved, so the part's proof checks
/// and every value it carries is the source's. What the source's header
/// committed for the transaction is the keys its part serves, so the
/// leaf recomputed over one key more does not walk to the header's root,
/// and the venue's shard asks another peer.
#[test]
fn a_fetched_part_carrying_a_key_its_header_did_not_commit_is_refused() {
    book_route_refuses(add_an_uncommitted_key, "carrying an added key");
}
