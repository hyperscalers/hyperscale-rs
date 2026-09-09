//! Portable network-fault scenarios.

use std::fmt::Write;

use hyperscale_engine::XRD;
use hyperscale_types::{
    BlockHeight, Deadline, Ed25519PrivateKey, Epoch, HALT_THRESHOLD_EPOCHS, MAX_VALIDITY_RANGE,
    PrincipalAddr, ShardId, StateRoot, SubstateKey, TransactionDecision, TransactionStatus, TxHash,
    WeightedTimestamp, Window,
};

use crate::reshape::split_lifecycle;
use crate::straddler::{STRADDLER_PAYMENT, chain_settled, submit_straddler_recording};
use crate::support::conservation::{Charges, World, probe_world};
use crate::support::faultable::FaultableCluster;
use crate::support::query::{beacon_epoch, vault_balance};
use crate::support::tx::{
    HALT_STRADDLER_BATCH, account_shard, build_probe_transfer_tx, build_transfer_tx,
    cross_shard_fault_cast, halt_straddler_setup, validity_around,
};
use crate::support::wait::{await_beacon_epoch, await_height, await_tx_terminal};
use crate::support::{Cluster, epochs};

/// Dropping `transaction.gossip` still delivers a submitted transfer — via the
/// fetch fallback — with the drop rule firing and the fetch engaging.
///
/// The feasibility check for the libp2p gate: on the sim the drop is total at
/// delivery; on production the inbound `Ignore` filter suppresses the gossip on
/// every host, so a submitted transaction reaches the committee only by the
/// fetch fallback.
///
/// # Panics
///
/// Panics if the transfer does not accept within budget, the drop rule never
/// fired, or the fetch fallback never engaged.
pub fn gossip_drop_engages_fetch_fallback(c: &mut impl FaultableCluster) {
    let fetch_before = c.metric("fetch_items_sent", Some("transaction"));
    let dropped = c.drop_type("transaction.gossip");
    let world = probe_world(c);
    let mut charges = Charges::default();

    let transfer = build_probe_transfer_tx(validity_around(c.now()));
    let hash = charges.submit(c, transfer);

    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must still accept via the fetch fallback; status = {status:?}"
    );
    world.assert_settles_within(c, &charges, epochs(4), "a probe under a gossip drop");
    assert!(
        dropped.fired() >= 1,
        "the transaction.gossip drop rule must fire",
    );
    assert!(
        c.metric("fetch_items_sent", Some("transaction")) > fetch_before,
        "the transaction fetch fallback must engage (before={fetch_before})",
    );
}

/// A 2-2 host partition starves quorum (3 of 4), so consensus halts; healing it
/// resumes commits as the lagging half catches up.
///
/// Requires a four-host single-shard cluster. The heal exercises the catch-up
/// sync path: the lagging half resynchronises via block fetch, not gossip
/// re-delivery, so the resume budget covers a few sync rounds.
///
/// # Panics
///
/// Panics if consensus does not commit before the partition, progress fails to
/// halt under it, or commits do not resume after the heal.
pub fn partition_halts_and_heals(c: &mut impl FaultableCluster) {
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(4)),
        "consensus must commit a block before the partition",
    );
    let before = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height before the partition")
        .inner();

    // Neither half of a 2-2 split has the 3-of-4 quorum, so progress halts.
    c.partition(&[0, 1], &[2, 3]);
    c.run_until(epochs(1), |_| false);
    let during = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height during the partition")
        .inner();
    assert!(
        during <= before + 2,
        "a 2-2 partition has no quorum, so progress must halt: before={before}, during={during}",
    );

    // Healing lets the pacemaker resynchronise the lagging half; commits resume.
    c.heal_all();
    assert!(
        await_height(c, ShardId::ROOT, during + 3, epochs(6)),
        "consensus must resume committing once the partition heals (stalled at {during})",
    );
}

/// A transaction settles while one validator is isolated: the remaining 3-of-4
/// quorum holds, and the vote-retry rotation recovers any tick the isolated node
/// was leading.
///
/// Requires a four-host single-shard cluster. Submission routes to host 0, so a
/// different host is isolated — one that still proposes some rounds, exercising
/// the leader-failure fallback.
///
/// # Panics
///
/// Panics if consensus does not commit before the isolation or the transfer does
/// not complete while a validator is isolated.
pub fn isolated_validator_still_settles(c: &mut impl FaultableCluster) {
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(4)),
        "consensus must commit a block before isolating a validator",
    );
    c.isolate(3);
    let world = probe_world(c);
    let mut charges = Charges::default();

    let transfer = build_probe_transfer_tx(validity_around(c.now()));
    let hash = charges.submit(c, transfer);

    let status = await_tx_terminal(c, hash, epochs(6));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must complete despite an isolated validator; status = {status:?}",
    );
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a probe beside an isolated validator",
    );
}

/// A shard halts when f+1 of its committee withhold their consensus
/// messages, and the beacon recovers it by re-drawing the whole committee
/// from the pool.
///
/// After the root grows, two members of the left child's four-member
/// committee go silent at the consensus layer only: their outbound
/// proposals, votes, and timeouts are dropped, and vote delivery to them
/// is cut (a silent member aggregates no QCs of its own), while every
/// other channel — beacon participation, pool ratification, block
/// serving — stays connected. The honest remainder is short of the 2f+1
/// quorum, so the shard freezes while its sibling and the beacon keep
/// committing. Once
/// the boundary watermark stalls past the halt threshold the beacon flags
/// the shard, seats a fresh committee from the pool spares, and retains
/// the replaced members in the routing view; the incomers sync the halted
/// tip from them, bridge the halt gap, and the shard resumes committing.
/// The first crossing under the fresh committee clears the recovery
/// record.
///
/// The reshape thresholds stay armed throughout — quiet (both children
/// hold in the stable band between the derived merge floor and the split
/// threshold), but forcing every proposal and vote through the reshape
/// predicate's substate walk. Across the recovery that walk crosses the
/// sync-admitted halted tip, whose byte total no fresh member can
/// resolve; the bridge blocks build and verify only because both sides
/// agree the assertion is out of play there, and that agreement is what
/// this scenario exercises.
///
/// Requires [`halt_straddler_setup`] at genesis, a dedicated
/// host per validator, and two committees' worth of pool surplus — one
/// grow cohort, one recovery committee.
///
/// [`halt_straddler_setup`]: crate::tx::halt_straddler_setup
///
/// # Panics
///
/// Panics if the shard fails to halt, the beacon or the sibling shard
/// stops committing through the halt, the recovery never fires, the shard
/// fails to resume under its fresh committee, or the recovery record
/// never clears.
pub fn halted_shard_recovers_by_committee_redraw(c: &mut impl FaultableCluster) {
    let (left, right) = ShardId::ROOT.children();
    split_lifecycle(c);
    let halt = freeze_shard(c, left, right, |_| {});
    await_halt_recovery(c, &halt);
}

/// Cross-shard ticks stay atomic across a shard halt and its
/// committee-redraw recovery.
///
/// The grown left child freezes exactly as in
/// [`halted_shard_recovers_by_committee_redraw`], but with cross-child
/// transfers in flight at every phase of the cut: a settling batch
/// finalized on both children before any fault installs, a racing batch
/// submitted at the freeze edge — the last instant with any chance to
/// commit on the halting shard — and a doomed batch submitted against the
/// frozen shard. The surviving sibling must drive every tick it engaged to
/// a terminal verdict on its own deadline clock during the halt, never
/// hanging on the dead counterparty; a probe whose payer is the dead shard
/// engages nowhere, because no counterpart can hold evidence of a commit
/// that never happened, and so has no lock or reservation to resolve.
/// After the recovery the two chains
/// must agree probe by probe: no tick applied on one side that the other
/// refused, with absence on the recovered chain counting as an abort (the
/// fresh committee resolves pre-halt ticks from certificates alone and
/// commits no abort finalization of its own). Once the recovery record
/// clears, a fresh transfer per direction must settle — the recovered
/// shard's cross-shard rail serves again.
///
/// Requires [`halt_straddler_setup`] at genesis, a dedicated host per
/// validator, and two committees' worth of pool surplus.
///
/// [`halt_straddler_setup`]: crate::tx::halt_straddler_setup
///
/// # Panics
///
/// Panics if the halt or recovery misses a lifecycle budget, an in-flight
/// tick hangs, the chains disagree on any probe's fate, or the
/// post-recovery transfers fail to settle.
pub fn halted_shard_straddler_atomic(c: &mut impl FaultableCluster) {
    let (halted, survivor) = ShardId::ROOT.children();
    let setup = halt_straddler_setup();
    split_lifecycle(c);

    // Every account a probe pays from or delivers to, in every batch and
    // after the recovery. The ballast holds the band and never spends.
    let world = World::open(
        c,
        *XRD,
        setup
            .straddlers
            .iter()
            .chain(&setup.post_recovery)
            .flat_map(|(_, from, to)| [from.address(), to.address()]),
        [],
    );
    let mut charges = Charges::default();
    let mut probes: Vec<Probe> = Vec::new();

    // Settling batch: finalized on both children before any fault
    // installs, so each chain records its half — the payer's verdict and
    // the recipient's delivery.
    for leg in &setup.straddlers[..HALT_STRADDLER_BATCH] {
        probes.push(submit_probe(c, &mut charges, leg));
    }
    assert!(
        c.run_until(epochs(12), |c| {
            probes
                .iter()
                .all(|p| chain_settled(c, halted, p.hash) && chain_settled(c, survivor, p.hash))
        }),
        "the settling batch must finalize on both children before the halt",
    );

    // Racing batch: submitted at the freeze edge, inside the staged cut —
    // the shard commits at most a couple more heights, so each probe
    // either squeezes through or is left in flight when it freezes. No
    // per-batch assertion; each lands in whichever bucket it raced into.
    let halt = freeze_shard(c, halted, survivor, |c| {
        for leg in &setup.straddlers[HALT_STRADDLER_BATCH..2 * HALT_STRADDLER_BATCH] {
            probes.push(submit_probe(c, &mut charges, leg));
        }
    });

    // Doomed batch: submitted against the frozen shard. A survivor-paid
    // probe still settles on the survivor — its payer's chain answers
    // alone — but its delivery has nowhere to land; a halted-paid probe
    // never commits anywhere.
    for leg in &setup.straddlers[2 * HALT_STRADDLER_BATCH..] {
        probes.push(submit_probe(c, &mut charges, leg));
    }

    // The survivor's verdict waits on no one: a probe it pays for accepts
    // during the halt, well inside the detection window, and its delivery
    // to the frozen shard does not land. A probe the *halted* shard pays
    // for is the opposite case and costs the survivor nothing: a
    // delivery rides evidence the payer's shard committed, and a frozen
    // shard commits nothing, so the survivor never engages it. There is
    // nothing to wait on, which is why these are not waited on — doing so
    // would spend the halt's own detection window on probes that were
    // never going to answer.
    let mut engaged = 0u32;
    for probe in &probes[HALT_STRADDLER_BATCH..] {
        if probe.payer_shard != survivor {
            assert!(
                c.chain_fate(survivor, probe.hash).0.is_none(),
                "the survivor engaged a probe whose payer shard is frozen",
            );
            continue;
        }
        engaged += 1;
        let status = await_tx_terminal(c, probe.hash, epochs(6));
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "a survivor-paid probe must accept on its payer's chain during the halt; \
             status = {status:?}",
        );
    }
    assert!(
        engaged > 0,
        "no in-flight probe was paid for by the survivor — the probe batches \
         no longer exercise its verdict clock",
    );
    for probe in &probes[2 * HALT_STRADDLER_BATCH..] {
        if probe.payer_shard == survivor {
            assert!(
                c.chain_fate(halted, probe.hash).0.is_none(),
                "a delivery landed on the frozen shard",
            );
        }
    }

    // The frozen chain's record is canonical for pre-halt heights: the
    // recovery bridges over the QC-attested tip, so nothing recorded here
    // is orphaned, while a fresh member's synced view may not reach below
    // its snap anchor.
    let at_freeze: Vec<_> = probes
        .iter()
        .map(|p| c.chain_fate(halted, p.hash))
        .collect();

    await_halt_recovery(c, &halt);

    let stranded = assert_deliveries_agree(c, halted, survivor, &probes, &at_freeze);

    // The recovered shard's cross-shard rail serves again: a fresh
    // transfer per direction settles on both chains and credits its
    // recipient once. The budget is generous — a ceiling, not the
    // expected latency: the fresh committee is establishing cross-shard
    // connectivity from a cold start (routing to the sibling, provision
    // serving) right after the recovery record cleared, which on a
    // real-network harness takes longer than a steady-state cross-shard
    // settlement round.
    let revived: Vec<Probe> = setup
        .post_recovery
        .iter()
        .map(|leg| submit_probe(c, &mut charges, leg))
        .collect();
    assert!(
        c.run_until(epochs(40), |c| {
            revived.iter().all(|p| {
                chain_settled(c, halted, p.hash)
                    && chain_settled(c, survivor, p.hash)
                    && credited_once(c, p)
            })
        }),
        "a post-recovery transfer per direction must settle on both chains \
         and credit its recipient once",
    );

    assert_conserved_less_the_strand(c, &world, &charges, stranded);
}

/// Two-sided conservation, less what the halt stranded: a survivor-paid
/// delivery whose window closed while the recipient was frozen debited
/// its payer and issued its record cell, and nothing claims it. Its
/// payer reclaims it on a proof that the claim never landed, taken
/// against the recipient's chain past the lapse — for as long as the
/// claim cell that proof reads is still standing. A halt that ends
/// inside that window gives everything back and the figure is zero; one
/// that outruns it reaches a swept cell, and what it was owed strands
/// with nobody able to dispose of it.
///
/// The conservation equality reads the figure the chains give, not a
/// bound. What is bounded is which probes may appear in it: the doomed
/// batch's two survivor-paid deliveries and the racing batch's two —
/// each landing in whichever bucket it raced into — and nothing from the
/// settling batch, which finalized on both children before any fault
/// installed.
fn assert_conserved_less_the_strand<C: Cluster>(
    c: &mut C,
    world: &World,
    charges: &Charges,
    stranded: u128,
) {
    assert!(
        stranded <= 4 * STRADDLER_PAYMENT,
        "only the doomed batch's two survivor-paid deliveries and the racing \
         batch's two can strand; nothing from the settling batch can, having \
         finalized on both children before any fault installed. stranded = {stranded}",
    );
    let balanced = c.run_until(epochs(8), |c| {
        world.held(c) + charges.burned(c) + stranded == world.before()
    });
    assert!(
        balanced,
        "a halt and its recovery: the world held {} before and {} after, with {} burned \
         and {stranded} stranded across the halt",
        world.before(),
        world.held(c),
        charges.burned(c),
    );
}

/// Assert one crossing's halves under the severance: the payer settles
/// it alone if its chain carried it at all, and no delivery lands.
///
/// Whether the payer committed it is the race the cut lands in the
/// middle of, so that is read first rather than assumed — a transaction
/// the partition beat into the block is nobody's to decide.
fn assert_severed_crossing<C: FaultableCluster>(
    c: &mut C,
    (left, right): (ShardId, ShardId),
    crossing: &Crossing,
    label: &str,
) {
    let payer_shard = payer_of(crossing, left, right);
    if c.chain_fate(payer_shard, crossing.hash).0.is_some() {
        let decided = c.run_until(epochs(4), |c| {
            matches!(
                c.chain_fate(payer_shard, crossing.hash).1,
                Some((_, TransactionDecision::Accept))
            )
        });
        let payer_fate = c.chain_fate(payer_shard, crossing.hash).1.map(|(_, d)| d);
        assert!(
            decided,
            "a payer that committed the {label} transfer settles it alone under the \
             severance — it awaits nobody: {payer_fate:?}",
        );
    } else {
        assert!(
            c.chain_fate(payer_shard, crossing.hash).1.is_none(),
            "the {label} transfer's payer reached a verdict on a transaction its \
             chain never carried",
        );
    }
    assert!(
        c.chain_fate(crossing.recipient_shard, crossing.hash)
            .0
            .is_none(),
        "the {label} delivery landed across the severance",
    );
}

/// A transaction's fate on one chain: the height that committed it and
/// the height and decision that finalized it.
type ChainFate = (
    Option<BlockHeight>,
    Option<(BlockHeight, TransactionDecision)>,
);

/// One straddler probe: where it pays, where it delivers, and when its
/// delivery window closes.
struct Probe {
    hash: TxHash,
    payer_shard: ShardId,
    recipient_shard: ShardId,
    recipient: PrincipalAddr,
    /// The record cells its crossings write, on the payer's shard —
    /// where the value it escrowed sits until something disposes of it.
    records: Vec<SubstateKey>,
    /// The last instant a delivery of it is admissible: the signed
    /// window's end plus the delivery allowance past it.
    delivery_closes: WeightedTimestamp,
    /// Where the claim cell the payer's reclaim is proved against is
    /// swept, and so where an unclaimed crossing stops being
    /// disposable at all: past it the claim reads absent because it was
    /// swept rather than because it was never written, and neither
    /// presence nor absence proves anything.
    claim_closes: WeightedTimestamp,
}

/// Submit one straddler leg, recording what the assertions read back.
fn submit_probe<C: Cluster>(
    c: &mut C,
    charges: &mut Charges,
    (key, from, to): &(Ed25519PrivateKey, PrincipalAddr, PrincipalAddr),
) -> Probe {
    // The same window the submission builds against the same clock, so
    // this is the transaction's own range rather than an estimate of it.
    let window = validity_around(c.now());
    let (hash, records) = submit_straddler_recording(c, charges, key, *from, *to);
    Probe {
        hash,
        payer_shard: account_shard(*from, 2),
        recipient_shard: account_shard(*to, 2),
        recipient: *to,
        records,
        delivery_closes: window.end_timestamp_exclusive.plus(MAX_VALIDITY_RANGE),
        claim_closes: Window::LegEntry
            .of(Deadline::of(window.end_timestamp_exclusive))
            .end,
    }
}

/// Whether `probe`'s recipient holds exactly its genesis dust plus one
/// payment — credited once, never twice.
fn credited_once<C: Cluster>(c: &C, probe: &Probe) -> bool {
    vault_balance(c, probe.recipient_shard, probe.recipient) == 10 + STRADDLER_PAYMENT
}

/// Assert the two chains agree probe by probe once the halted shard has
/// recovered: a recipient is credited exactly when its chain committed
/// the delivery, and once; nothing is delivered that no payer accepted;
/// every settling probe delivered; every doomed probe the frozen shard
/// paid for committed nowhere. A survivor-paid probe whose delivery
/// window is still open lands on the recovered shard.
///
/// Returns what the halt stranded: the payments of every survivor-paid
/// probe that accepted and whose delivery never landed.
///
/// `at_freeze` is the halted chain's own view taken before the recovery:
/// a commit or an accept in either that snapshot or the post-recovery
/// walk counts, since the snapshot covers heights a fresh member never
/// synced and the walk covers anything finalized after resume.
fn assert_deliveries_agree<C: Cluster>(
    c: &mut C,
    halted: ShardId,
    survivor: ShardId,
    probes: &[Probe],
    at_freeze: &[ChainFate],
) -> u128 {
    let fate_on = |c: &C, shard: ShardId, idx: usize, hash: TxHash| {
        fate_including_freeze(c, halted, at_freeze, shard, idx, hash)
    };
    let mut report = String::new();
    let mut settled = 0u32;
    let mut doomed_nowhere = 0u32;
    let batch = HALT_STRADDLER_BATCH;
    for (idx, probe) in probes.iter().enumerate() {
        let payer = fate_on(c, probe.payer_shard, idx, probe.hash);
        let recipient = fate_on(c, probe.recipient_shard, idx, probe.hash);
        let accepted = matches!(payer.1, Some((_, TransactionDecision::Accept)));
        let delivered = recipient.0.is_some();
        let held = vault_balance(c, probe.recipient_shard, probe.recipient);
        let _ = write!(
            report,
            "\n  #{idx}: payer={:?} {payer:?}; recipient={:?} {recipient:?}; holds {held}",
            probe.payer_shard, probe.recipient_shard,
        );
        assert_eq!(
            held,
            if delivered {
                10 + STRADDLER_PAYMENT
            } else {
                10
            },
            "a recipient is credited exactly when its chain delivered, and once:{report}",
        );
        assert!(
            accepted || !delivered,
            "a delivery landed that no payer accepted:{report}",
        );
        if idx < batch {
            assert!(
                accepted && delivered,
                "every settling probe must accept and deliver:{report}",
            );
            settled += 1;
        } else if idx >= 2 * batch && probe.payer_shard == halted {
            assert!(
                payer.0.is_none() && recipient.0.is_none(),
                "a probe the frozen shard paid for committed somewhere:{report}",
            );
            doomed_nowhere += 1;
        }
    }
    assert_eq!(
        settled,
        u32::try_from(batch).unwrap_or(u32::MAX),
        "the settling batch is the whole first batch",
    );
    assert!(
        doomed_nowhere > 0,
        "no doomed probe was paid for by the frozen shard — the batches no \
         longer exercise it",
    );

    // Whatever the survivor accepted and the recovered shard has not yet
    // delivered lands now, if its window is still open; a delivery whose
    // window closed while the shard was frozen is owed nothing here, and
    // its payer's reclaim reaches nothing either, the halt having
    // outlasted the record's grace.
    let now = WeightedTimestamp::ZERO.plus(c.now());
    let owed: Vec<&Probe> = undelivered_survivor_paid(c, halted, survivor, probes, at_freeze)
        .into_iter()
        .map(|idx| &probes[idx])
        .filter(|p| now < p.delivery_closes)
        .collect();
    let landed = c.run_until(epochs(10), |c| {
        owed.iter()
            .all(|p| c.chain_fate(halted, p.hash).0.is_some() && credited_once(c, p))
    });
    assert!(
        landed,
        "a delivery whose window is open must land on the recovered shard and \
         credit once; owed = {:?}",
        owed.iter().map(|p| p.hash).collect::<Vec<_>>(),
    );

    let undelivered = undelivered_survivor_paid(c, halted, survivor, probes, at_freeze);
    assert!(
        undelivered.iter().all(|&idx| idx >= HALT_STRADDLER_BATCH),
        "the settling batch finalized on both children before any fault installed, \
         so nothing of it can strand; undelivered probes = {undelivered:?}",
    );
    strand_left_by(c, probes, &undelivered)
}

/// What the halt stranded, of the deliveries it left unlanded: the
/// payments whose record cell is still standing when nothing can dispose
/// of it any more.
fn strand_left_by<C: Cluster>(c: &mut C, probes: &[Probe], undelivered: &[usize]) -> u128 {
    for &idx in undelivered {
        assert!(
            !probes[idx].records.is_empty(),
            "a probe the halt left undelivered crossed to say it: probe {idx}",
        );
    }

    // A record is value, and value is not swept on a clock — no arm of
    // the sweep reaches a record cell. What decides whether the payer
    // gets its crossing back is the life of the claim cell the reclaim
    // is proved against: inside it the absence is provable and the
    // reclaim is licensed, past it the cell is swept and absence proves
    // nothing, so the record stands with nobody able to dispose of it.
    // Both fates are correct, and which one a halt reaches is how long
    // it ran against that one window.
    let taken_back = c.run_until(epochs(10), |c| {
        let now = WeightedTimestamp::ZERO.plus(c.now());
        undelivered.iter().all(|&idx| {
            let probe = &probes[idx];
            now >= probe.claim_closes || !record_stands(c, probe)
        })
    });
    assert!(
        taken_back,
        "a reclaim still licensed by the claim cell it is proved against commits, \
         and the record it takes back goes",
    );

    // The strand is what is left: read off the cells rather than
    // inferred from the balances or from the halt's length.
    let stranded = undelivered
        .iter()
        .filter(|&&idx| record_stands(c, &probes[idx]))
        .count();
    for &idx in undelivered {
        let probe = &probes[idx];
        assert!(
            !record_stands(c, probe) || WeightedTimestamp::ZERO.plus(c.now()) >= probe.claim_closes,
            "a record still standing is one nothing could dispose of: probe {idx} on {:?}",
            probe.payer_shard,
        );
    }
    u128::try_from(stranded).expect("a handful of probes") * STRADDLER_PAYMENT
}

/// Whether any crossing `probe` issued is still sitting in its record
/// cell on the shard that wrote it.
fn record_stands<C: Cluster>(c: &C, probe: &Probe) -> bool {
    probe.records.iter().any(|record| {
        c.substate(probe.payer_shard, record.owner, record.local.0)
            .is_some()
    })
}

/// A probe's fate on `shard`, taking the halted shard's reading from
/// before the freeze where its chain has since said nothing.
///
/// A recovered shard's chain answers for what it committed before the
/// freeze, but a scenario that read it only after the recovery would
/// miss a probe the shard settled and then stopped answering for.
fn fate_including_freeze<C: Cluster>(
    c: &C,
    halted: ShardId,
    at_freeze: &[ChainFate],
    shard: ShardId,
    idx: usize,
    hash: TxHash,
) -> ChainFate {
    let now = c.chain_fate(shard, hash);
    if shard == halted {
        let frozen = at_freeze[idx];
        (now.0.or(frozen.0), now.1.or(frozen.1))
    } else {
        now
    }
}

/// The probes the survivor accepted and the halted shard has not
/// committed a delivery of, by index.
///
/// Read twice: once to drive whatever is still inside its window onto
/// the recovered shard, and once after, when what is left is what the
/// halt stranded.
fn undelivered_survivor_paid<C: Cluster>(
    c: &C,
    halted: ShardId,
    survivor: ShardId,
    probes: &[Probe],
    at_freeze: &[ChainFate],
) -> Vec<usize> {
    probes
        .iter()
        .enumerate()
        .filter(|(idx, p)| {
            p.payer_shard == survivor
                && matches!(
                    fate_including_freeze(c, halted, at_freeze, survivor, *idx, p.hash).1,
                    Some((_, TransactionDecision::Accept))
                )
                && fate_including_freeze(c, halted, at_freeze, halted, *idx, p.hash)
                    .0
                    .is_none()
        })
        .map(|(idx, _)| idx)
        .collect()
}

/// A staged shard freeze: the fault rules are installed and the shard has
/// verifiably stopped committing. Carries the observations
/// [`await_halt_recovery`] asserts against.
struct StagedHalt {
    /// The frozen shard.
    shard: ShardId,
    /// Its live sibling, asserted to keep committing through the halt.
    sibling: ShardId,
    /// The frozen shard's settled height once in-flight rounds drained.
    frozen_at: u64,
    /// The beacon epoch when the freeze settled.
    epoch_at_halt: u64,
    /// The sibling's committed height when the freeze settled.
    sibling_at_halt: u64,
}

/// Freeze `shard` with a staged consensus cut against two of its four
/// committee members.
///
/// f+1 of the committee withhold: their outbound consensus messages stop
/// reaching everyone else. The honest remainder is 2f, short of quorum,
/// so the shard halts; nothing else is cut. Vote delivery TO the
/// withholding pair is cut too — a silent member collects no votes —
/// else the pair keeps aggregating QCs only it holds and privately
/// commits a suffix the recovery must orphan, and the faulted hosts
/// (honest code under a network fault) would panic on the commit-linkage
/// break instead of modeling adversaries that simply stop.
///
/// The cut is staged. Cutting everything at one instant leaves the same
/// private-commit race in the in-flight window: a pair member due to
/// aggregate the next rounds' votes can hold a QC no one else ever sees
/// and commit one height past the beacon-attested frontier — a suffix the
/// recovery orphans, and the linkage break kills the host. So first
/// starve aggregation (votes toward the pair), then drain an epoch — any
/// QC a pair member already holds is broadcast and becomes common
/// knowledge in this window, while consensus keeps committing through the
/// pair's timed-out leader rounds — and only then silence the pair's
/// outbound channels.
///
/// `at_freeze_edge` runs between the drain and the silencing — the last
/// instant new work enters the shard's pipeline with any chance to
/// commit.
fn freeze_shard<C: FaultableCluster>(
    c: &mut C,
    shard: ShardId,
    sibling: ShardId,
    at_freeze_edge: impl FnOnce(&mut C),
) -> StagedHalt {
    let committee = c.committee_hosts(shard);
    assert_eq!(
        committee.len(),
        4,
        "the halting shard must be served by a four-member committee",
    );
    let withholding = &committee[..2];
    let others: Vec<usize> = (0..c.host_count())
        .filter(|host| !withholding.contains(host))
        .collect();

    c.drop_type_between(&others, withholding, "block.vote");
    c.run_until(epochs(1), |_| false);
    at_freeze_edge(c);
    let votes_withheld = c.drop_type_between(withholding, &others, "block.vote");
    c.drop_type_between(withholding, &others, "block.header");
    c.drop_type_between(withholding, &others, "shard.timeout");

    // In-flight rounds drain, then the shard freezes.
    c.run_until(epochs(1), |_| false);
    let frozen = c
        .committed_height(shard)
        .expect("the halting shard committed during the grow")
        .inner();
    let epoch_at_halt = beacon_epoch(c).expect("a committed beacon epoch").inner();
    let sibling_at_halt = c
        .committed_height(sibling)
        .expect("the sibling shard serves")
        .inner();
    c.run_until(epochs(2), |_| false);
    let during = c
        .committed_height(shard)
        .expect("a committed height during the halt")
        .inner();
    assert!(
        during <= frozen + 2,
        "two of four withholding leaves no quorum, so the shard must halt: \
         frozen={frozen}, during={during}",
    );
    assert!(
        votes_withheld.fired() >= 1,
        "the withheld votes must actually be dropped",
    );
    StagedHalt {
        shard,
        sibling,
        frozen_at: during,
        epoch_at_halt,
        sibling_at_halt,
    }
}

/// Drive a staged freeze through detection, committee redraw, resume, and
/// record clear, asserting the beacon and the sibling shard stay live
/// throughout.
fn await_halt_recovery(c: &mut impl FaultableCluster, halt: &StagedHalt) {
    let shard = halt.shard;

    // The boundary watermark stalls past the threshold; the beacon flags
    // the shard and re-draws its committee from the pool spares. The cut is
    // permanent, so detection is guaranteed — the budget is a generous
    // ceiling, not the expected latency: cross-shard traffic in flight at
    // the freeze lets the shard commit a few more blocks before it stalls,
    // and on a real-network harness the per-fold cadence varies, so the
    // `threshold` miss folds accrue later than on the quiet quick sim.
    let threshold = u32::try_from(HALT_THRESHOLD_EPOCHS).expect("threshold fits u32");
    let recovered = c.run_until(epochs(threshold + 25), |c| {
        c.beacon_state()
            .is_some_and(|state| state.pending_recoveries.contains_key(&shard))
    });
    assert!(
        recovered,
        "the beacon must flag the halted shard and seat a fresh committee",
    );
    // Only the shard halted: the beacon and the sibling kept committing.
    let epoch_now = beacon_epoch(c).expect("a committed beacon epoch").inner();
    assert!(
        epoch_now > halt.epoch_at_halt,
        "the beacon must keep producing epochs through the halt \
         ({} -> {epoch_now})",
        halt.epoch_at_halt,
    );
    assert!(
        c.committed_height(halt.sibling)
            .expect("the sibling shard serves")
            .inner()
            > halt.sibling_at_halt,
        "the sibling shard must keep committing through the halt",
    );

    // The fresh committee syncs the halted tip from the retained members,
    // bridges the halt gap, and resumes committing past the frozen height.
    // The pool the recovery draws from holds exactly `shard_size` spares,
    // so the fresh committee is whatever the tenure shuffle rotated into
    // the pool — here one of the withholding hosts, cycled off the halted
    // shard before the flag and redrawn (the recovery is only as clean as
    // a fresh draw at the pool's corrupt fraction). The fresh committee
    // keeps its honest majority and recovers, but a lone isolated member
    // dropping a quarter of the views stretches the resume, so the budget
    // is generous — a ceiling on the wait, not the expected latency.
    assert!(
        await_height(c, shard, halt.frozen_at + 3, epochs(40)),
        "the recovered shard must resume committing under its fresh committee \
         (frozen at {})",
        halt.frozen_at,
    );
    // The first crossing under the fresh committee completes the recovery.
    let cleared = c.run_until(epochs(20), |c| {
        c.beacon_state()
            .is_some_and(|state| !state.pending_recoveries.contains_key(&shard))
    });
    assert!(
        cleared,
        "the shard's next boundary crossing must clear the recovery record",
    );
}

/// The committed state root that every host serving `shard` agrees on, or `None`
/// if any two disagree or one has not yet reported. The stall-not-fork check:
/// after a heal, this becoming `Some` means the shard's whole committee — the
/// rejoined dark hosts included — converged on one chain. A host still catching
/// up reports a different (or no) root, so it holds this at `None` until every
/// committee member is back in step. Scoped to the shard's committee so it works
/// in a multi-shard cluster, where only some hosts serve any given shard.
fn agreed_state_root(c: &impl FaultableCluster, shard: ShardId) -> Option<StateRoot> {
    let hosts = c.committee_hosts(shard);
    let first = c.host_committed_state_root(*hosts.first()?, shard)?;
    for &host in &hosts[1..] {
        if c.host_committed_state_root(host, shard)? != first {
            return None;
        }
    }
    Some(first)
}

/// A connected minority fragment partitions off, stays dark across an epoch
/// boundary, then rejoins as a group.
///
/// The regression shape behind the rejoin-wedge class, where fragment members
/// share stale state with each other while partitioned.
///
/// Requires a seven-host single-shard committee: quorum is five (strict >2/3),
/// so cutting the two-host fragment `{0, 1}` off the majority `{2..6}` leaves
/// both the shard and the beacon majority live — the majority keeps committing
/// and crossing epoch boundaries while the fragment is frozen. A full
/// bipartition, so both harnesses agree on the cut.
///
/// # Panics
///
/// Panics if consensus does not commit before the partition, the majority fails
/// to progress while the fragment is dark, the fragment advances while
/// partitioned, or the rejoined fragment fails to catch up and agree on the
/// committed root after the heal.
pub fn minority_fragment_rejoins_after_partition(c: &mut impl FaultableCluster) {
    assert_eq!(
        c.host_count(),
        7,
        "this scenario needs a seven-host committee so a two-host fragment leaves quorum live",
    );

    // Every host — the future fragment included — must be seated and committing
    // before the cut, so the fragment goes dark from a real synced state (not a
    // never-seated genesis host) and rejoins by catching up a bounded gap.
    let seated = c.run_until(epochs(6), |c| {
        (0..7).all(|host| {
            c.host_committed_height(host, ShardId::ROOT)
                .is_some_and(|h| h.inner() >= 1)
        })
    });
    assert!(
        seated,
        "every host must commit a block before the partition"
    );
    let start_epoch = beacon_epoch(c).expect("a committed beacon epoch").inner();

    c.partition(&[0, 1], &[2, 3, 4, 5, 6]);
    let before = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height before the partition")
        .inner();
    let frag_before: Vec<u64> = [0, 1]
        .iter()
        .map(|&host| {
            c.host_committed_height(host, ShardId::ROOT)
                .map_or(0, BlockHeight::inner)
        })
        .collect();

    // Keep the fragment dark across exactly one epoch boundary — the majority
    // (five of seven) keeps both shard and beacon consensus live, and bounding
    // the dark window to a single epoch keeps the fragment's catch-up gap inside
    // the block-retention window.
    assert!(
        await_beacon_epoch(c, start_epoch + 1, epochs(6)),
        "the five-host majority must cross an epoch boundary while the fragment is dark",
    );
    // Partition onset can transiently stall the majority: a replica missing a
    // pending ancestor body breaks the zero-slack five-of-five quorum until
    // the spin detector's sync recovers it, and rotating fetches past the two
    // dark peers costs a timeout each. Progress is the requirement, not
    // instantaneous progress — so give the sample a recovery budget.
    assert!(
        c.run_until(epochs(3), |c| c
            .committed_height(ShardId::ROOT)
            .is_some_and(|h| h.inner() > before + 2)),
        "the five-host majority must keep committing while the fragment is dark: \
         before={before}",
    );
    let during = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height during the partition")
        .inner();

    // The dark fragment has no quorum of its own, so neither of its hosts commits.
    for (&host, &frozen) in [0, 1].iter().zip(&frag_before) {
        let now = c
            .host_committed_height(host, ShardId::ROOT)
            .map_or(0, BlockHeight::inner);
        assert!(
            now <= frozen + 1,
            "fragment host {host} committed while partitioned (frozen={frozen}, now={now})",
        );
    }

    // Heal: the fragment resynchronises via block fetch, catches up to a tip past
    // the dark window, and every host — fragment included — agrees on the root.
    c.heal_all();
    let target = during + 2;
    let caught_up = c.run_until(epochs(10), |c| {
        [0, 1].iter().all(|&host| {
            c.host_committed_height(host, ShardId::ROOT)
                .is_some_and(|h| h.inner() >= target)
        }) && agreed_state_root(c, ShardId::ROOT).is_some()
    });
    assert!(
        caught_up,
        "the rejoined fragment must catch up past the dark window ({target}) and \
         every host must agree on the committed state root",
    );
}

/// Liveness needs a quorum, not the whole committee.
///
/// After a partition drops the cluster below quorum, restoring exactly a quorum
/// — with the remaining member still dark — must resume progress; the final
/// member then catches up.
///
/// Requires a four-host single-shard committee (quorum three). Hosts 0 and 1 are
/// isolated rather than split `{0,1} | {2,3}`, so host 0 is genuinely edgeless:
/// a plain partition would leave the 0–1 edge open, and production gossip would
/// relay across it once the staged heal reconnects host 1. `{2, 3}` alone is two
/// of four, below quorum, so consensus halts; reconnecting host 1 to hosts 2 and
/// 3 forms an exact three-of-four quorum that resumes progress before host 0 is
/// healed back in.
///
/// # Panics
///
/// Panics if consensus does not commit before the partition, progress fails to
/// halt under it, the exact-quorum heal fails to resume progress, or host 0 fails
/// to catch up and agree on the committed root after the final heal.
pub fn partition_heals_at_exact_quorum(c: &mut impl FaultableCluster) {
    assert_eq!(
        c.host_count(),
        4,
        "this scenario needs a four-host committee so three connected hosts are exactly quorum",
    );
    // Every host — host 0 included — must be seated and committing before the
    // isolation, so the host that stays dark rejoins from a real synced state.
    let seated = c.run_until(epochs(6), |c| {
        (0..4).all(|host| {
            c.host_committed_height(host, ShardId::ROOT)
                .is_some_and(|h| h.inner() >= 1)
        })
    });
    assert!(
        seated,
        "every host must commit a block before the partition"
    );

    // Isolate both 0 and 1 so the 0–1 edge is cut too; `{2, 3}` is below quorum.
    c.isolate(0);
    c.isolate(1);
    let before = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height before the partition")
        .inner();
    c.run_until(epochs(1), |_| false);
    let during = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height during the partition")
        .inner();
    assert!(
        during <= before + 2,
        "with only two of four connected there is no quorum, so progress must halt: \
         before={before}, during={during}",
    );

    // Reconnect host 1 to hosts 2 and 3 — an exact three-of-four quorum, host 0
    // still dark. Progress must resume before the final heal.
    c.heal_between(1, 2);
    c.heal_between(1, 3);
    let resumed = during + 3;
    assert!(
        await_height(c, ShardId::ROOT, resumed, epochs(6)),
        "an exact three-of-four quorum (host 0 still dark) must resume progress",
    );
    let host0 = c
        .host_committed_height(0, ShardId::ROOT)
        .map_or(0, BlockHeight::inner);
    assert!(
        host0 < resumed,
        "the still-dark host 0 must not have kept pace (host0={host0}, tip={resumed})",
    );

    // Heal host 0 back in; it catches up and every host agrees on the root.
    c.heal_all();
    let target = resumed + 2;
    let caught_up = c.run_until(epochs(8), |c| {
        c.host_committed_height(0, ShardId::ROOT)
            .is_some_and(|h| h.inner() >= target)
            && agreed_state_root(c, ShardId::ROOT).is_some()
    });
    assert!(
        caught_up,
        "host 0 must catch up to the tip ({target}) and every host must agree on \
         the committed state root after the final heal",
    );
}

/// Severing every edge between two shards strands their in-flight cross-shard
/// ticks without ever splitting one, and healing resolves them.
///
/// A two-shard cluster (`split_lifecycle`) whose committees sit on disjoint host
/// sets, so `partition(committee_hosts(left), committee_hosts(right))` cuts every
/// inter-shard edge in both directions while leaving intra-shard edges intact —
/// unlike the drop scenarios, which always leave a fetch route the tick recovers
/// through.
///
/// No tick aborts while the cut holds, and that is the shape of the cut rather
/// than a slow deadline. The same partition splits the beacon quorum, so epoch
/// production halts, and both shards coast their `L = 1` lookahead runway and
/// then hold at the schedule head with their attested clocks frozen. Every
/// deadline in the system is read from that clock, so none of them can arrive:
/// the cut that strands a tick is the cut that stops the clock its abort would
/// be timed against. What must hold under it is the safety half — no stranded
/// tick settles Accept on either side, and the two shards never disagree — and
/// then, on the heal, that both reach a terminal verdict rather than wedging.
///
/// The deadline itself has its own scenario, which cuts the two message types a
/// payer's bundle travels and leaves both committees and the beacon healthy, so
/// the clock keeps running while the evidence does not arrive.
///
/// The two probes end up in different cases, deliberately. The one in flight as
/// the cut lands was already committed on its payer's shard, so it owes a
/// verdict and gets one on the heal. The one submitted into the frozen half was
/// never included at all, and its signed window closes before that half
/// resumes — so it expires in the pool with no chain owing it anything, which
/// is what a validity window is for.
///
/// Cross-shard transfers run in each direction over the funded pair; the
/// single-shard controls run on disjoint accounts, so they settle intra-shard
/// without colliding with the severed ticks' declared writes.
///
/// # Panics
///
/// Panics if a shard wedges under the severance, a single-shard control fails to
/// settle, a severed cross-shard transfer settles or the two shards disagree on
/// its fate, an in-flight transfer never resolves after the heal, or a fresh
/// cross-shard transfer fails to settle.
pub fn inter_shard_partition_strands_ticks_until_it_heals(c: &mut impl FaultableCluster) {
    let (left, right) = ShardId::ROOT.children();
    split_lifecycle(c);

    let left_hosts = c.committee_hosts(left);
    let right_hosts = c.committee_hosts(right);
    assert!(
        !left_hosts.is_empty() && !right_hosts.is_empty(),
        "both split children must be served before the severance",
    );
    assert!(
        left_hosts.iter().all(|h| !right_hosts.contains(h)),
        "the two committees must sit on disjoint host sets: left={left_hosts:?}, right={right_hosts:?}",
    );

    let cast = cross_shard_fault_cast();
    let world = fault_family_world(c);
    let mut charges = Charges::default();

    let left_before = c
        .committed_height(left)
        .expect("left serves before the severance")
        .inner();
    let right_before = c
        .committed_height(right)
        .expect("right serves before the severance")
        .inner();

    // A cross-shard transfer in flight as the cut lands.
    let before = submit_crossing(c, &mut charges);

    // Sever every inter-shard edge (both directions), intra-shard edges intact.
    c.partition(&left_hosts, &right_hosts);

    // A second cross-shard transfer submitted under the severance, sourced on
    // the far side so each shard pays for one stranded delivery.
    let during = submit_crossing_between(c, &mut charges, &cast.right, (left, cast.left.1));

    // A single-shard control per child, on accounts disjoint from the crossing
    // pair — these must settle purely intra-shard while the cross-shard
    // deliveries are stranded.
    for (index, (key, from, to)) in cast.controls.iter().enumerate() {
        let control = build_transfer_tx(key, *from, *to, 100, validity_around(c.now()));
        let hash = charges.submit(c, control);
        let status = await_tx_terminal(c, hash, epochs(2));
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "single-shard control {index} must settle under the severance; \
             status = {status:?}",
        );
    }

    // Both shards kept committing locally throughout — the severance froze the
    // cross-shard deliveries, not either side's consensus.
    let left_during = c
        .committed_height(left)
        .expect("left serves during the severance")
        .inner();
    let right_during = c
        .committed_height(right)
        .expect("right serves during the severance")
        .inner();
    assert!(
        left_during > left_before,
        "the left shard wedged under the severance (before={left_before}, during={left_during})",
    );
    assert!(
        right_during > right_before,
        "the right shard wedged under the severance (before={right_before}, during={right_during})",
    );

    // No delivery lands across the cut, and a payer that carried the
    // transaction reaches its verdict anyway. A divided transfer's payer
    // settles it alone, so the severance stalls the delivery and nothing
    // else — the case worth failing is a payer that committed the
    // transaction and then waits on a counterpart it does not await.
    // Whether it committed at all is the race the cut lands in the middle
    // of, so that is read first rather than assumed: a transaction the
    // partition beat into the block is nobody's to decide, and the
    // `resolved > 0` check below is what keeps the pair from being
    // vacuous. The delivery's absence is read off the chain rather than
    // waited for: with the beacon starved by the same partition, one that
    // has not landed is not going to.
    for (crossing, label) in [(&before, "left→right"), (&during, "right→left")] {
        assert_severed_crossing(c, (left, right), crossing, label);
    }

    // Heal every edge. Epoch production resumes and both clocks restart, so a
    // transfer a payer had committed accepts if it has not already, and its
    // delivery — stranded, not lost — lands on the recipient's chain.
    //
    // A transfer submitted *into* the frozen half is the other case: its shard
    // held at the schedule head without ever including it, and by the heal its
    // signed window has closed, so it can never be included and no chain owes
    // it a verdict. It expires, which is the pool's job and not consensus's.
    c.heal_all();
    let resolved = [(&before, "left→right"), (&during, "right→left")]
        .into_iter()
        .filter(|(crossing, label)| assert_delivered_after_heal(c, left, right, crossing, label))
        .count();
    assert!(
        resolved > 0,
        "no transfer was in flight across the cut — the severance landed before \
         either shard could commit one, so nothing was stranded",
    );

    // A fresh cross-shard transfer settles normally on the healed network.
    let fresh = submit_crossing(c, &mut charges);
    let fresh_status = await_tx_terminal(c, fresh.hash, epochs(10));
    assert!(
        matches!(
            fresh_status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "a fresh cross-shard transfer must settle once the severance heals; \
         status = {fresh_status:?}",
    );
    await_crossed(c, &fresh, "post-heal");

    // Stranded, not lost: every delivery the cut held back landed on the
    // heal, and the one transfer no shard ever included cost nobody
    // anything.
    world.assert_settles_within(c, &charges, epochs(8), "a severance and its heal");
}

/// The child that pays for `crossing`: the one it does not deliver to.
fn payer_of(crossing: &Crossing, left: ShardId, right: ShardId) -> ShardId {
    if crossing.recipient_shard == right {
        left
    } else {
        right
    }
}

/// Assert `crossing` resolved once the severance healed, and report whether
/// it was ever committed at all.
///
/// A transfer its payer had committed owes an accept there and a delivery
/// on the recipient's chain. One no shard ever included owes nothing: its
/// signed window closed while its half held at the schedule head, so it
/// expires in the pool.
fn assert_delivered_after_heal<C: FaultableCluster>(
    c: &mut C,
    left: ShardId,
    right: ShardId,
    crossing: &Crossing,
    label: &str,
) -> bool {
    let payer_shard = payer_of(crossing, left, right);
    if c.chain_fate(payer_shard, crossing.hash).0.is_none() {
        assert!(
            c.tx_status(crossing.hash).is_none(),
            "a transfer no shard ever committed reached a verdict anyway ({label})",
        );
        return false;
    }
    let verdict = await_tx_terminal(c, crossing.hash, epochs(10));
    assert!(
        matches!(
            verdict,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the {label} transfer must accept on its payer's chain once the severance \
         heals; status = {verdict:?}",
    );
    assert!(
        c.run_until(epochs(10), |c| matches!(
            c.chain_fate(crossing.recipient_shard, crossing.hash).1,
            Some((_, TransactionDecision::Accept))
        )),
        "the {label} delivery must land on the recipient's chain once the \
         severance heals; recipient = {:?}",
        c.chain_fate(crossing.recipient_shard, crossing.hash),
    );
    true
}

/// A ratification pool partitioned below quorum halts epoch production, and the
/// shards defer at the schedule head rather than fork.
///
/// A disjoint two-shard cluster (eight hosts, one validator each).
/// `partition(committee_hosts(left), committee_hosts(right))` splits the beacon
/// pool 4|4 — neither side reaches quorum, so no beacon block commits and epoch
/// production halts — while each shard keeps its own four hosts together, so
/// shard consensus stays live. The partition then holds *past* the `L = 1`
/// lookahead runway. The shards coast on the committees the last committed beacon
/// epoch resolved, so their heights climb for the runway and then plateau once
/// the weighted timestamp crosses past the last resolved committee window —
/// stall, not fork. Healing restores the pool quorum, epoch production resumes,
/// and both shards commit on past their frozen heights.
///
/// # Panics
///
/// Panics if the partitioned pool advances the epoch, a shard fails to coast then
/// freeze, either shard keeps committing past its runway (a fork or a wedge
/// rather than a clean defer), or the heal fails to resume epochs, shard
/// progress, or cross-host root agreement.
pub fn beacon_pool_partition_stalls_epoch_production(c: &mut impl FaultableCluster) {
    let (left, right) = ShardId::ROOT.children();
    split_lifecycle(c);

    let left_hosts = c.committee_hosts(left);
    let right_hosts = c.committee_hosts(right);
    assert!(
        !left_hosts.is_empty() && !right_hosts.is_empty(),
        "both split children must be served before the partition",
    );
    assert!(
        left_hosts.iter().all(|h| !right_hosts.contains(h)),
        "the two committees must sit on disjoint host sets: left={left_hosts:?}, right={right_hosts:?}",
    );

    let start_epoch = beacon_epoch(c)
        .expect("a committed beacon epoch before the partition")
        .inner();
    let left_before = c.committed_height(left).expect("left serves").inner();
    let right_before = c.committed_height(right).expect("right serves").inner();

    // Split the beacon pool below quorum. Each shard keeps its own hosts, so
    // shard consensus survives; the pool spanning both shards does not.
    c.partition(&left_hosts, &right_hosts);

    // Coast past the L = 1 runway, then the shards defer at the schedule head.
    c.run_until(epochs(3), |_| false);
    let left_frozen = c.committed_height(left).expect("left serves").inner();
    let right_frozen = c.committed_height(right).expect("right serves").inner();
    assert_eq!(
        beacon_epoch(c).map(Epoch::inner),
        Some(start_epoch),
        "the pool partitioned below quorum must halt epoch production",
    );
    assert!(
        left_frozen > left_before && right_frozen > right_before,
        "both shards must coast the lookahead runway before deferring \
         (left {left_before}->{left_frozen}, right {right_before}->{right_frozen})",
    );

    // Hold longer: the deferred shards make no further progress — a stall, not a
    // fork, and not an unbounded run past the runway.
    c.run_until(epochs(2), |_| false);
    assert_eq!(
        c.committed_height(left).map(BlockHeight::inner),
        Some(left_frozen),
        "the left shard must defer at the schedule head, not commit past its runway",
    );
    assert_eq!(
        c.committed_height(right).map(BlockHeight::inner),
        Some(right_frozen),
        "the right shard must defer at the schedule head, not commit past its runway",
    );
    assert_eq!(
        beacon_epoch(c).map(Epoch::inner),
        Some(start_epoch),
        "epoch production must stay halted while the pool is partitioned",
    );

    // Heal: the pool reaches quorum again, epochs resume, and both shards commit
    // past their frozen heights on the one chain every serving host agrees on.
    c.heal_all();
    assert!(
        await_beacon_epoch(c, start_epoch + 1, epochs(8)),
        "epoch production must resume once the pool heals (stalled at epoch {start_epoch})",
    );
    assert!(
        await_height(c, left, left_frozen + 1, epochs(8))
            && await_height(c, right, right_frozen + 1, epochs(8)),
        "both shards must resume committing past their frozen heights after the heal \
         (left {left_frozen}, right {right_frozen})",
    );
    let agreed = c.run_until(epochs(8), |c| {
        agreed_state_root(c, left).is_some() && agreed_state_root(c, right).is_some()
    });
    assert!(
        agreed,
        "every serving host must agree on each shard's committed root after the heal",
    );
}

/// The payment every cross-shard fault probe carries.
const CROSSING_PAYMENT: u128 = 500;

/// Submit a transfer from the left child's funded account into the right
/// child's, and return its hash.
///
/// The signed validity window discriminates repeat submissions: two probes
/// built at the same clock over the same pair would be one transaction under
/// hash dedup, which is the replay protection working rather than a builder
/// limitation.
/// A cross-shard transfer in flight, with what its recipient held when it
/// was submitted.
///
/// The credit is asserted as a delta off that reading: the vault is
/// cluster-wide state, and what it holds is whatever earlier crossings
/// left there.
struct Crossing {
    hash: TxHash,
    recipient_shard: ShardId,
    recipient: PrincipalAddr,
    held_before: u128,
}

/// Wait for `crossing` to land on the recipient's chain and credit its
/// vault.
///
/// A divided transfer accepts on its payer's chain alone; the recipient's
/// shard commits the delivery in a block of its own, a hop behind, and
/// credits the vault when it does. Read the moment the payer's status
/// flips, the recipient shows nothing yet — and a scenario in this family
/// that never read the recipient at all would pass on a payment that never
/// left one shard: the DA fetch engages for any dropped gossip, and the
/// remote-header channel runs as ordinary machinery in a grown cluster, so
/// neither counter alone distinguishes a crossing from a local payment.
fn await_crossed<C: Cluster>(c: &mut C, crossing: &Crossing, context: &str) {
    let (left, right) = ShardId::ROOT.children();
    let credited = crossing.held_before + CROSSING_PAYMENT;
    let landed = c.run_until(epochs(8), |c| {
        c.chain_fate(left, crossing.hash).0.is_some()
            && c.chain_fate(right, crossing.hash).0.is_some()
            && vault_balance(c, crossing.recipient_shard, crossing.recipient) == credited
    });
    assert!(
        landed,
        "the {context} transfer never crossed the split: left={:?}, right={:?}, \
         recipient holds {} against {credited} expected",
        c.chain_fate(left, crossing.hash).0,
        c.chain_fate(right, crossing.hash).0,
        vault_balance(c, crossing.recipient_shard, crossing.recipient),
    );
}

/// Everything the cross-shard fault family's transfers can reach: the
/// crossing pair and the controls' accounts, on both children.
fn fault_family_world<C: Cluster>(c: &C) -> World {
    let cast = cross_shard_fault_cast();
    let mut holders = vec![cast.left.1.address(), cast.right.1.address()];
    for (_, payer, recipient) in &cast.controls {
        holders.push(payer.address());
        holders.push(recipient.address());
    }
    World::open(c, *XRD, holders, [])
}

/// Submit the family's crossing: the left child's funded account pays the
/// right child's.
fn submit_crossing<C: Cluster>(c: &mut C, charges: &mut Charges) -> Crossing {
    let cast = cross_shard_fault_cast();
    let (_, right) = ShardId::ROOT.children();
    submit_crossing_between(c, charges, &cast.left, (right, cast.right.1))
}

/// Submit a crossing from `payer` into `recipient`'s account on its shard.
fn submit_crossing_between<C: Cluster>(
    c: &mut C,
    charges: &mut Charges,
    payer: &(Ed25519PrivateKey, PrincipalAddr),
    recipient: (ShardId, PrincipalAddr),
) -> Crossing {
    let (recipient_shard, recipient) = recipient;
    let held_before = vault_balance(c, recipient_shard, recipient);
    let tx = build_transfer_tx(
        &payer.0,
        payer.1,
        recipient,
        CROSSING_PAYMENT,
        validity_around(c.now()),
    );
    let hash = charges.submit(c, tx);
    Crossing {
        hash,
        recipient_shard,
        recipient,
        held_before,
    }
}

/// Grow to two shards, drop the `broadcast` message type, then run a cross-shard
/// transfer that must recover via the `fetch_kind` fetch fallback.
///
/// Works for any broadcast the cross-shard flow relies on — the unicast
/// bundle delivery (`provisions.broadcast`) suppressed at the sender's gate,
/// or a gossip broadcast (`transaction.gossip`, `block.committed`) suppressed
/// by the receiver's inbound filter. The transfer runs from the left child's
/// funded account into the right child's, both seeded at genesis. Faults
/// install after the split settles, so the grow rides its own broadcasts
/// cleanly. Asserts the transfer accepts and lands, the drop fired, the fetch
/// engaged, and nothing aborted.
///
/// The provisions leg is the sharpest of these on the engine: a payer's
/// bundle is the evidence its counterpart engages against, so suppressing the
/// broadcast withholds engagement itself until the fetch bridges it.
fn cross_shard_broadcast_drop(
    c: &mut impl FaultableCluster,
    broadcast: &'static str,
    fetch_kind: &'static str,
) {
    split_lifecycle(c);
    // Snapshot the fetch counter before the drop: the counter is cluster-wide
    // and monotonic, so measuring the increase isolates the fetches this outage
    // forces from any the split itself emitted (remote-header sync in particular
    // runs as normal machinery in a grown cluster, not only as a fallback).
    let fetch_before = c.metric("fetch_items_sent", Some(fetch_kind));
    let dropped = c.drop_type(broadcast);
    let world = fault_family_world(c);
    let mut charges = Charges::default();

    let crossing = submit_crossing(c, &mut charges);

    let status = await_tx_terminal(c, crossing.hash, epochs(10));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the cross-shard transfer must settle despite the dropped {broadcast}; status = {status:?}",
    );
    await_crossed(c, &crossing, broadcast);
    world.assert_settles_within(c, &charges, epochs(8), broadcast);
    assert!(dropped.fired() >= 1, "the {broadcast} drop must fire");
    assert!(
        c.metric("fetch_items_sent", Some(fetch_kind)) > fetch_before,
        "the {fetch_kind} fetch fallback must engage (before={fetch_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the cross-shard transfer must not abort",
    );
}

/// Dropping `provisions.broadcast` still settles a cross-shard transfer — the
/// destination shard fetches the provisions rather than receiving them.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the provision
/// fetch never engages, or anything aborts.
pub fn cross_shard_provisions_drop_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "provisions.broadcast", "provision");
}

/// Dropping `execution.cert.batch` changes nothing for a divided transfer.
///
/// Nothing waits on a certificate from across the split, so the exec-cert
/// fetch never engages and the transfer lands and credits as it would with
/// the channel open. The payer's chain settles the transfer on its own verdict, and the
/// recipient commits the delivery off the payer's committed bundle, never
/// off a certificate. A certificate is waited for only where a route sends
/// one shard's verdict to another — a leg with its core elsewhere — and a
/// transfer has no such edge.
///
/// # Panics
///
/// Panics if the transfer does not settle and land, the exec-cert fetch
/// engages, or anything aborts.
pub fn cross_shard_exec_cert_drop_is_inert(c: &mut impl FaultableCluster) {
    split_lifecycle(c);
    let fetch_before = c.metric("fetch_items_sent", Some("exec_cert"));
    let _dropped = c.drop_type("execution.cert.batch");
    let world = fault_family_world(c);
    let mut charges = Charges::default();

    let crossing = submit_crossing(c, &mut charges);

    let status = await_tx_terminal(c, crossing.hash, epochs(10));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle with execution.cert.batch dropped; status = {status:?}",
    );
    await_crossed(c, &crossing, "execution.cert.batch");
    world.assert_settles_within(c, &charges, epochs(8), "execution.cert.batch");
    assert_eq!(
        c.metric("fetch_items_sent", Some("exec_cert")),
        fetch_before,
        "no shard waits on a certificate for a divided transfer, so the \
         exec-cert fetch has nothing to bridge",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the cross-shard transfer must not abort",
    );
}

/// Dropping BOTH `provisions.broadcast` and `execution.cert.batch` at once
/// still settles a cross-shard transfer.
///
/// The provision fetch bridges the bundle, and the certificate channel has
/// nothing a divided transfer waits on.
///
/// # Panics
///
/// Panics if the transfer does not settle and land, the bundle drop never
/// fires, the provision fetch never engages, the exec-cert fetch engages,
/// or anything aborts.
pub fn cross_shard_compound_drop_fetch_fallback(c: &mut impl FaultableCluster) {
    split_lifecycle(c);
    let provision_before = c.metric("fetch_items_sent", Some("provision"));
    let exec_cert_before = c.metric("fetch_items_sent", Some("exec_cert"));
    let provisions_dropped = c.drop_type("provisions.broadcast");
    let _exec_cert_dropped = c.drop_type("execution.cert.batch");
    let world = fault_family_world(c);
    let mut charges = Charges::default();

    let crossing = submit_crossing(c, &mut charges);

    let status = await_tx_terminal(c, crossing.hash, epochs(12));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle despite both channels dropped; status = {status:?}",
    );
    await_crossed(c, &crossing, "compound-drop");
    world.assert_settles_within(c, &charges, epochs(8), "compound-drop");
    assert!(
        provisions_dropped.fired() >= 1,
        "the provisions.broadcast drop must fire",
    );
    assert!(
        c.metric("fetch_items_sent", Some("provision")) > provision_before,
        "the provision fetch fallback must engage (before={provision_before})",
    );
    assert_eq!(
        c.metric("fetch_items_sent", Some("exec_cert")),
        exec_cert_before,
        "the exec-cert fetch has nothing to bridge for a divided transfer",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the compound cross-shard transfer must not abort",
    );
}

/// Dropping `transaction.gossip` in a grown cluster still settles a cross-shard
/// transfer — the source committee fetches the transaction body (the DA
/// fallback) rather than receiving it by gossip.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the transaction
/// fetch never engages, or anything aborts.
pub fn cross_shard_transaction_da_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "transaction.gossip", "transaction");
}

/// Dropping `block.committed` still settles a cross-shard transfer — the shard
/// tracking its counterpart's committed headers fetches them via the
/// remote-header sync rather than receiving them by gossip.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the
/// remote-header fetch never engages, or anything aborts.
pub fn cross_shard_header_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "block.committed", "remote_header");
}

/// A cross-shard transfer settles under unreliable request RPC.
///
/// Provisions never broadcast — forcing the provision fetch fallback — AND half
/// of every `provision.request` leg is dropped, so each fetch attempt is a
/// coin-flip that must be retried until one gets through. Proves the
/// request-manager retry path recovers a fetch under probabilistic request
/// loss without aborting.
///
/// The 50% loss is exercised per attempt on both harnesses: the sim draws from
/// the engine's own seeded RNG at the request-drain site, and production
/// consults the same gate in the libp2p request pool per send, surfacing a
/// dropped leg as the timeout the retry loop rolls again.
///
/// Returns the cluster-wide `provision.request` drop count. Engagement is
/// deterministic on the sim — the wiring asserts it per seed — but not on
/// production, where the async retry path can settle the fetch on an undropped
/// first leg, so a caller there asserts only the liveness invariants this body
/// checks. All other invariants (settle, broadcast dropped, fetch engaged, zero
/// aborts) hold on both.
///
/// # Panics
///
/// Panics if the transfer fails to settle, the broadcast drop never fires, the
/// provision fetch never engages, or anything aborts.
pub fn cross_shard_provisions_fetch_with_request_loss(c: &mut impl FaultableCluster) -> u64 {
    split_lifecycle(c);
    let fetch_before = c.metric("fetch_items_sent", Some("provision"));
    let broadcast_dropped = c.drop_type("provisions.broadcast");
    let request_dropped = c.drop_type_with_probability("provision.request", 0.5);
    let world = fault_family_world(c);
    let mut charges = Charges::default();

    let crossing = submit_crossing(c, &mut charges);

    let status = await_tx_terminal(c, crossing.hash, epochs(12));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle despite 50% provision.request loss; status = {status:?}",
    );
    await_crossed(c, &crossing, "request-loss");
    world.assert_settles_within(c, &charges, epochs(8), "request-loss");
    assert!(
        broadcast_dropped.fired() >= 1,
        "the provisions.broadcast drop must fire",
    );
    assert!(
        c.metric("fetch_items_sent", Some("provision")) > fetch_before,
        "the provision fetch fallback must engage (before={fetch_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the transfer must not abort under request loss",
    );

    request_dropped.fired()
}

/// A transient `provisions.broadcast` outage recovers even when the fault lifts
/// mid-flight.
///
/// Drop the broadcast, submit a cross-shard transfer, and hold the outage
/// until it has bitten the bundle that matters: the payer's chain sends one
/// bundle when it commits the transfer and another, carrying the crossing
/// the recipient's delivery rides, when it commits the finalization. Only
/// the second withholds the delivery, so the fault holds until the payer's
/// chain has finalized. Then lift it and confirm the delivery still lands
/// via the provision fetch fallback with nothing aborting. A dropped
/// bundle is not re-emitted on lift, so the recipient recovers by fetch
/// either way; the point is that removing a live drop rule mid-recovery is
/// safe — the fetch bridge completes and no tick wedges.
///
/// One transfer, not two: both accounts of the crossing pair are declared
/// writes of every transfer between them, so a second overlapping cross-shard
/// transfer would race the first's conflict window rather than test recovery.
///
/// # Panics
///
/// Panics if the payer's chain fails to finalize the transfer, the outage
/// never fired, the transfer fails to land, the provision fetch never
/// engaged, or anything aborts.
pub fn cross_shard_provisions_recovers_after_transient_outage(c: &mut impl FaultableCluster) {
    split_lifecycle(c);
    let (payer_shard, _) = ShardId::ROOT.children();
    let fetch_before = c.metric("fetch_items_sent", Some("provision"));
    let dropped = c.drop_type("provisions.broadcast");
    let world = fault_family_world(c);
    let mut charges = Charges::default();

    let crossing = submit_crossing(c, &mut charges);

    // Let the outage bite the crossing bundle: the payer's chain finalizes
    // the transfer and the bundle its finalizing block sends is dropped
    // before we lift the fault, so the recovery genuinely spans a removal.
    let finalized = c.run_until(epochs(8), |c| {
        c.chain_fate(payer_shard, crossing.hash).1.is_some()
    });
    assert!(
        finalized,
        "the payer's chain must finalize the transfer before the outage lifts",
    );
    assert!(
        dropped.fired() >= 1,
        "the provisions.broadcast drop must fire before the outage lifts",
    );
    c.clear_drops();

    let status = await_tx_terminal(c, crossing.hash, epochs(10));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle via the provision fetch despite the transient \
         outage; status = {status:?}",
    );
    await_crossed(c, &crossing, "transient-outage");
    world.assert_settles_within(c, &charges, epochs(8), "transient-outage");
    assert!(
        c.metric("fetch_items_sent", Some("provision")) > fetch_before,
        "the provision fetch fallback must bridge the outage (before={fetch_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the transfer must not abort",
    );
}

/// Every channel a beacon commit needs. With all seven dropped the committee
/// never reaches its vote threshold, so each epoch commits as a skip block:
/// the topology schedule keeps advancing — shards stay live and keep crossing
/// epoch cuts — while no shard contribution seats.
const BEACON_COMMIT_CHANNELS: [&str; 7] = [
    "beacon.proposal",
    "beacon.spc.new_view",
    "beacon.spc.new_commit",
    "beacon.spc.empty_view",
    "beacon.pc.vote1",
    "beacon.pc.vote2",
    "beacon.pc.vote3",
];

/// Epochs the beacon spends committing skips.
const SUPPRESSED_EPOCHS: u32 = 3;

/// The anchor epoch of the reveal chain the fold last seeded from `shard`.
///
/// `record_boundaries` stamps `ShardBoundary::weighted_timestamp` from the
/// crossing header's parent QC on exactly the folds that seed, so the anchor
/// epoch a fold closed reads straight off the boundary record. The identity
/// holds while no crossing is fenced — a fenced crossing records without
/// seeding — which is the case whenever no halt recovery is pending.
fn folded_anchor_epoch<C: Cluster>(c: &C, shard: ShardId) -> Option<Epoch> {
    let state = c.beacon_state()?;
    let boundary = state.boundaries.get(&shard)?;
    Some(
        state
            .chain_config
            .epoch_windows()
            .epoch_for(boundary.weighted_timestamp),
    )
}

/// A beacon that lags across several epochs folds one crossing on resumption
/// and drops the reveal chains of every epoch it skipped.
///
/// The fold seeds `state.randomness` from one chain value per crossing, and a
/// chain is per-epoch: nothing carries an unfolded epoch's reveals forward, so
/// entropy the shard produced while the beacon was blind is gone rather than
/// deferred. This prices that loss. Suppressing the commit channels leaves
/// epoch production running on skip blocks, so the shard keeps producing and
/// crossing cuts throughout; on resumption the sourcing rule anchors the
/// newest crossing and the epochs between the last fold and that crossing
/// never contribute.
///
/// The loss tracks the outage one epoch for one: the fold cannot skip an
/// epoch it was awake for, and it always folds the crossing that ends the
/// outage. A healthy-beacon control runs first, pinning the awake fold at one
/// anchor epoch closed per step, so the gap the outage opens cannot be
/// mistaken for one the fold leaves anyway.
///
/// # Panics
///
/// Panics if no crossing folds before the outage, the awake fold leaves a gap
/// of its own, the beacon stops committing (freezing the shard rather than
/// lagging it), the suppression fails to stall the fold, the fold never
/// resumes, or the skipped span differs from the outage that produced it.
pub fn beacon_lag_drops_skipped_epochs_reveal_chains(c: &mut impl FaultableCluster) {
    let shard = ShardId::ROOT;

    // A seeded genesis record reads as anchor epoch 0, and so does the first
    // crossing (the one into epoch 1, anchored below the cut it crosses), so
    // only an anchor epoch past 0 proves a real crossing folded.
    assert!(
        c.run_until(epochs(8), |c| folded_anchor_epoch(c, shard)
            .is_some_and(|e| e.inner() >= 1)),
        "the fold must seed from a crossing before the outage",
    );
    let warmed = folded_anchor_epoch(c, shard)
        .expect("a folded crossing")
        .inner();

    // Control: an awake beacon closes every anchor epoch, so the next fold
    // steps by exactly one. Without this the outage measurement below could
    // be reading a gap the fold leaves anyway.
    assert!(
        c.run_until(epochs(3), |c| folded_anchor_epoch(c, shard)
            .is_some_and(|e| e.inner() > warmed)),
        "the fold must close an anchor epoch while the beacon is awake",
    );
    let before = folded_anchor_epoch(c, shard)
        .expect("a folded crossing")
        .inner();
    assert_eq!(
        before - warmed,
        1,
        "an awake beacon must leave no gap: folded {warmed} then {before}",
    );
    let epoch_before = beacon_epoch(c).expect("a committed beacon epoch").inner();

    for channel in BEACON_COMMIT_CHANNELS {
        c.drop_type(channel);
    }
    c.run_until(epochs(SUPPRESSED_EPOCHS), |_| false);
    let during = folded_anchor_epoch(c, shard)
        .expect("the boundary record survives the outage")
        .inner();
    assert!(
        beacon_epoch(c).expect("a committed beacon epoch").inner() > epoch_before,
        "the beacon must keep committing skip blocks through the outage, \
         or the shard freezes at the schedule head instead of lagging",
    );
    assert_eq!(
        during, before,
        "a beacon committing only skips must seat no contribution",
    );
    c.clear_drops();

    assert!(
        c.run_until(epochs(10), |c| folded_anchor_epoch(c, shard)
            .is_some_and(|e| e.inner() > before)),
        "the fold must resume once the commit channels reopen",
    );
    let after = folded_anchor_epoch(c, shard)
        .expect("a folded crossing")
        .inner();

    // Epochs strictly between the two folds contributed nothing. The loss
    // tracks the outage one for one: the fold cannot skip an epoch it was
    // awake for, and it always folds the crossing that ends the outage.
    let skipped = after - before - 1;
    assert_eq!(
        skipped,
        u64::from(SUPPRESSED_EPOCHS),
        "a {SUPPRESSED_EPOCHS}-epoch outage must cost exactly that many \
         epochs' reveal chains, but skipped {skipped} (folded {before} then \
         {after})",
    );
}
