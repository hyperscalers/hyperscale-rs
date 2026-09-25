//! The event stream is the only channel between the session and the page,
//! so the field names a `TraceKind` serializes to are the interface.
//!
//! The page switches on `type` and reads fields off the payload by name. A
//! rename that compiles here still breaks the viewer silently — it renders
//! `undefined` rather than failing — so the shape is pinned rather than
//! left to the derive.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_demo::{Session, SessionConfig, TraceKind};
use serde_json::{Value, to_value};

/// Every event kind, and the exact keys its payload carries.
fn expected() -> BTreeMap<&'static str, BTreeSet<&'static str>> {
    let kinds: [(&str, &[&str]); 13] = [
        (
            "blockCommitted",
            &[
                "shard",
                "height",
                "round",
                "fallback",
                "proposer",
                "crossShardTicks",
            ],
        ),
        ("beaconBlockCommitted", &["epoch"]),
        ("topologyChanged", &["shards", "appeared", "retired"]),
        (
            "provisionsVerified",
            &["from", "fromHeight", "to", "toHeight", "txs"],
        ),
        (
            "crossingCredited",
            &["from", "fromHeight", "to", "toHeight", "txs"],
        ),
        (
            "executionCertified",
            &["shard", "height", "tick", "into", "intoHeight", "outcomes"],
        ),
        (
            "tickFinalized",
            &["shard", "height", "openedAt", "tick", "participants", "txs"],
        ),
        ("shardTerminal", &["shard", "height", "handoffFrom"]),
        (
            "messageDelivered",
            &[
                "from",
                "to",
                "class",
                "messageType",
                "sentAt",
                "deliveredAt",
                "shard",
            ],
        ),
        ("trafficSampled", &["byClass", "sampled", "dropped"]),
        ("hostsChanged", &["hosts"]),
        ("txSubmitted", &["tx"]),
        ("txStatusChanged", &["tx", "status", "height"]),
    ];
    kinds
        .into_iter()
        .map(|(kind, fields)| (kind, fields.iter().copied().collect()))
        .collect()
}

/// Drive a two-shard session long enough to produce every kind: past the
/// split for the topology and terminal events, then under transfer load for
/// the cross-shard ones.
fn every_kind() -> Vec<Value> {
    let mut session = Session::new(
        SessionConfig {
            max_shards: 2,
            ..SessionConfig::default()
        },
        42,
    );
    let mut events = Vec::new();
    for _ in 0..440 {
        events.extend(session.step(500));
    }
    for i in 0..200 {
        if i % 20 == 0 {
            session.submit_transfer();
        }
        events.extend(session.step(500));
    }
    events
        .iter()
        .map(|event| to_value(event).expect("a trace event serializes"))
        .collect()
}

#[test]
fn every_event_kind_carries_exactly_the_fields_the_page_reads() {
    let expected = expected();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for event in every_kind() {
        let object = event.as_object().expect("an event is an object");
        assert!(
            object.contains_key("wt"),
            "every event is stamped: {event:?}",
        );
        let kind = object["kind"].as_object().expect("kind is an object");
        let tag = kind["type"].as_str().expect("kind is tagged").to_string();
        let fields: BTreeSet<&str> = kind
            .keys()
            .map(String::as_str)
            .filter(|k| *k != "type")
            .collect();
        let want = expected
            .get(tag.as_str())
            .unwrap_or_else(|| panic!("unknown event kind {tag}: {kind:?}"));
        assert_eq!(fields, *want, "fields of {tag} changed");
        seen.insert(tag);
    }

    // A transfer-only session provisions nothing: a crossing's record
    // travels as a state claim, and a transfer declares no read set.
    let unexercised = ["provisionsVerified"];
    let missing: Vec<_> = expected
        .keys()
        .filter(|k| !seen.contains(**k) && !unexercised.contains(k))
        .copied()
        .collect();
    assert!(
        missing.is_empty(),
        "the run must exercise every kind; never produced: {missing:?}",
    );
}

#[test]
fn an_arcs_payload_reads_as_the_page_expects() {
    // The page indexes outcomes as `[tx, outcome]` pairs and treats every
    // shard and transaction label as a bare string, so a newtype that
    // started serializing as an object would break it without a type error
    // anywhere.
    let events = every_kind();

    let certified = events
        .iter()
        .find(|e| e["kind"]["type"] == "executionCertified")
        .expect("a session under load certifies executions");
    let kind = &certified["kind"];
    assert!(kind["shard"].is_string(), "a shard path is a bare string");
    assert!(kind["tick"].is_string(), "a tick label is a bare string");
    let outcome = &kind["outcomes"][0];
    assert!(outcome[0].is_string(), "an outcome names its transaction");
    assert!(
        matches!(
            outcome[1].as_str(),
            Some("succeeded" | "failed" | "aborted")
        ),
        "an outcome uses the docs' vocabulary, saw {outcome:?}",
    );

    // A transfer-only session provisions nothing, so the shape of a
    // provisions arc is checked only where the run produced one.
    if let Some(provisions) = events
        .iter()
        .find(|e| e["kind"]["type"] == "provisionsVerified")
    {
        let kind = &provisions["kind"];
        assert!(kind["from"].is_string() && kind["to"].is_string());
        assert!(kind["fromHeight"].is_u64() && kind["toHeight"].is_u64());
        assert!(
            kind["txs"][0].is_string(),
            "a transaction label is a string"
        );
    }
}

#[test]
fn the_network_view_payloads_read_as_the_page_expects() {
    // The panel indexes per-class totals as `[class, deliveries, bytes]` and
    // reads each host's duties off named fields. Both are collections of
    // tuples or structs that a derive could reshape without a type error.
    let events = every_kind();

    let traffic = events
        .iter()
        .find(|e| e["kind"]["type"] == "trafficSampled")
        .expect("a running network carries traffic");
    let by_class = &traffic["kind"]["byClass"][0];
    assert!(
        by_class[0].is_string(),
        "a class is named by its metric label, saw {by_class:?}",
    );
    assert!(
        by_class[1].is_u64() && by_class[2].is_u64(),
        "a class carries a delivery count and a byte count, saw {by_class:?}",
    );

    let roster = events
        .iter()
        .find(|e| e["kind"]["type"] == "hostsChanged")
        .expect("a split moves the roster");
    let host = &roster["kind"]["hosts"][0];
    assert!(host["host"].is_u64(), "a host is named by index");
    assert!(host["shards"].is_array(), "a host lists what it serves");
    assert!(
        host["pooled"].is_u64(),
        "a host counts its shard-less followers",
    );

    let delivered = events
        .iter()
        .find(|e| e["kind"]["type"] == "messageDelivered")
        .expect("a running network delivers messages");
    let kind = &delivered["kind"];
    assert!(
        kind["from"].is_u64() && kind["to"].is_u64(),
        "a delivery names hosts by index, matching the roster",
    );
    assert!(
        kind["shard"].is_string() || kind["shard"].is_null(),
        "a delivery's shard is a bare path or absent, saw {:?}",
        kind["shard"],
    );
}

/// The one kind whose payload is not exercised by the shared run above: a
/// single-shard session never splits, so nothing terminates.
#[test]
fn a_shard_that_never_terminates_reports_no_terminal() {
    let mut session = Session::new(SessionConfig::default(), 42);
    let mut events = Vec::new();
    for _ in 0..60 {
        events.extend(session.step(500));
    }
    assert!(
        !events
            .iter()
            .any(|e| matches!(e.kind, TraceKind::ShardTerminal { .. })),
        "a lone root shard has no handoff to certify",
    );
}
