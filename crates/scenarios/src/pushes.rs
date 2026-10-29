//! A crossing answer reaches its record's producer by push, as pacing,
//! and retires the record only once read at a boundary of the consumer's
//! shard; the answer itself goes on no push.
//!
//! A block that writes a crossing answer pushes it to the record's
//! producer, which stops nothing on it: a fresh `Taken` is one a
//! recovery of the consumer's shard can discard, so the producer
//! retires the record only on the `Taken` read at a boundary the beacon
//! recorded for that shard, which it asks for itself. Each scenario here
//! cuts one push direction of a cross-shard transfer, and the record
//! goes at the consumer's boundary whatever is cut. No block pushes a
//! record's removal either: the consumer reads the record absent at a
//! boundary the beacon recorded for the producer's shard, and deletes
//! its answer there whatever pushes are cut.

use hyperscale_effects_bridge::ProtocolHasher;
use hyperscale_effects_bridge::vm_statics::crossing_records;
use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_types::{
    Deadline, RETENTION_HORIZON, ShardId, SubstateKey, TransactionDecision, TransactionStatus,
    TxHash, WeightedTimestamp,
};
use hyperscale_vm_effects::{Answered, CrossingCell, CrossingId};

use crate::support::conservation::{Charges, World};
use crate::support::faultable::{FaultableCluster, report_claims_recarried};
use crate::support::query::{boundary_clock, clock, owning_shard, retirement_wait, vault_balance};
use crate::support::tx::{build_transfer_tx, cross_shard_cast, validity_around};
use crate::support::wait::await_tx_terminal;
use crate::support::{Budget, Cluster, epochs};

const PAYER_SHARD: ShardId = ShardId::leaf(1, 0);
const RECIPIENT_SHARD: ShardId = ShardId::leaf(1, 1);

/// The answer deletions the cluster's blocks carried as boundary
/// readings.
const BOUNDARY_DELETIONS: (&str, Option<&str>) = ("boundary_deletions_carried", None);

fn asks(c: &impl FaultableCluster, (name, label): (&'static str, Option<&str>)) -> u64 {
    c.metric(name, label)
}

/// Whether the beacon has recorded a boundary of the recipient's shard
/// whose clock is later than `taken`, a clock at or before the one its
/// `Taken` was written at: one that shows the answer.
fn shows_the_answer<C: Cluster>(c: &C, taken: WeightedTimestamp) -> bool {
    boundary_clock(c, RECIPIENT_SHARD).is_some_and(|at| at > taken)
}

/// Run until the beacon has recorded a boundary of the recipient's shard
/// later than `after`, and that boundary has aged past a retention
/// horizon, so a block can carry a reading at it; or until `done` holds.
fn await_a_readable_boundary<C: FaultableCluster>(
    c: &mut C,
    after: WeightedTimestamp,
    budget: Budget,
    done: impl Fn(&C) -> bool,
) -> bool {
    if !c.run_until(budget, |c| done(c) || shows_the_answer(c, after)) {
        return false;
    }
    let Some(at) = boundary_clock(c, RECIPIENT_SHARD).filter(|at| *at > after) else {
        return true;
    };
    c.run_until(budget, |c| done(c) || clock(c) > at.plus(RETENTION_HORIZON))
}

/// Run until `record` goes, asserting it stands while no boundary of the
/// recipient's shard the beacon recorded is later than `taken`: the
/// payer retires on the recipient's `Taken` read there and on nothing
/// fresher.
fn retired_at_a_later_boundary<C: FaultableCluster>(
    c: &mut C,
    record: SubstateKey,
    taken: WeightedTimestamp,
    budget: Budget,
) {
    assert!(
        c.run_until(budget, |c| !stands(c, record) || shows_the_answer(c, taken)),
        "the beacon records a boundary of the recipient's shard past its Taken",
    );
    assert!(
        stands(c, record),
        "nothing retires the record before a boundary of the recipient's shard shows its Taken",
    );
    assert!(
        c.run_until(budget, |c| !stands(c, record)),
        "the payer reads the Taken at that boundary and retires the record",
    );
}

/// Whether `key` holds a value on the shard its owner routes to.
fn stands<C: Cluster + ?Sized>(c: &C, key: SubstateKey) -> bool {
    c.substate(owning_shard(c, key.owner), key.owner, key.local.0)
        .is_some()
}

/// The payer's and the recipient's committee hosts, which must be
/// disjoint for a cut between them to be a cut of one direction.
fn sides(c: &impl FaultableCluster) -> (Vec<usize>, Vec<usize>) {
    let payer = c.committee_hosts(PAYER_SHARD);
    let recipient = c.committee_hosts(RECIPIENT_SHARD);
    assert!(
        payer.iter().all(|host| !recipient.contains(host)),
        "a directional cut needs the two committees on disjoint hosts: \
         payer {payer:?}, recipient {recipient:?}",
    );
    (payer, recipient)
}

/// A transfer submitted and accepted, with the world that tracks it.
struct Transfer {
    world: World,
    charges: Charges,
    hash: TxHash,
    deadline: Deadline,
    record: SubstateKey,
}

/// Submit a cross-shard transfer and wait for the payer's leg to accept.
fn transfer(c: &mut impl FaultableCluster) -> Transfer {
    let (payer_key, from, to) = cross_shard_cast();
    let mut world = World::open(c, *PROTOCOL_RESOURCE, [from.address(), to.address()], []);
    let mut charges = Charges::default();
    let validity = validity_around(c.now());
    let tx = build_transfer_tx(&payer_key, from, to, 100, validity);
    let records = crossing_records(
        &c.with_derivation(|derivation| tx.try_derived(derivation))
            .expect("a scenario transfer derives")
            .legs,
    );
    let [record] = records.as_slice() else {
        panic!("a transfer crosses once: {records:?}");
    };
    let record = *record;
    world.owing([record]);
    let hash = charges.submit(c, tx);
    let verdict = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            verdict,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the payer's leg accepts; verdict = {verdict:?}",
    );
    Transfer {
        world,
        charges,
        hash,
        deadline: Deadline::of(validity.end_timestamp_exclusive),
        record,
    }
}

/// The consumer's `Taken` answer to the crossing `record` names, read
/// off the record while it stands.
///
/// A transaction's status turns final when its finalization forms, and
/// the record is written when the block carrying it commits, so the
/// record is waited for and not read at the status alone.
fn taken_answer<C: Cluster>(c: &mut C, record: SubstateKey) -> SubstateKey {
    assert!(
        c.run_until(epochs(1), |c| stands(c, record)),
        "the record stands on the payer's chain once its leg's tick settles",
    );
    let bytes = c
        .substate(owning_shard(c, record.owner), record.owner, record.local.0)
        .expect("a record that stands is read");
    let cell = CrossingCell::from_bytes(&bytes).expect("a record cell");
    CrossingId::of_record(record.owner, &cell).answer_key(&ProtocolHasher, Answered::Taken)
}

/// A lost answer push costs nothing: the payer retires the record on
/// the recipient's `Taken` read at a boundary of the recipient's shard,
/// which the push never carried.
///
/// Every answer push from the recipient's shard to the payer's is cut.
/// The recipient delivers and writes its `Taken`; the payer's record
/// stands until the beacon records a boundary of the recipient's shard
/// later than the `Taken`, and goes on that boundary's reading.
///
/// # Panics
///
/// Panics if the transfer does not accept or deliver, if the record goes
/// before a boundary of the recipient's shard shows its `Taken`, if the
/// cut never fires, if the record is not retired after it, or if the
/// world does not conserve.
pub fn a_lost_answer_push_is_read_at_the_consumers_boundary<C: FaultableCluster>(c: &mut C) {
    lost_answer_push(c, 0);
}

/// The boundary read cannot be withheld: with f of the payer's
/// validators withholding their fetch, the others ask and carry the
/// reading.
///
/// [`a_lost_answer_push_is_read_at_the_consumers_boundary`] with one of
/// the payer's four validators unable to fetch from the recipient's
/// shard. The withholding validator's asks are dropped; every other
/// validator derives the same question and asks it at the same boundary
/// for itself, and whichever of them leads next carries the reading.
///
/// # Panics
///
/// As [`a_lost_answer_push_is_read_at_the_consumers_boundary`], and if
/// the withholding validator's asks never fire.
pub fn a_withheld_boundary_read_is_carried_by_an_honest_validator<C: FaultableCluster>(c: &mut C) {
    lost_answer_push(c, 1);
}

fn lost_answer_push<C: FaultableCluster>(c: &mut C, withholding: usize) {
    let (payer_hosts, recipient_hosts) = sides(c);
    let (_, _, to) = cross_shard_cast();
    let recipient_before = vault_balance(c, RECIPIENT_SHARD, to);
    let answers_cut = c.drop_type_between(&recipient_hosts, &payer_hosts, "crossing.readings");
    let withheld = c.drop_type_between(
        &payer_hosts[..withholding],
        &recipient_hosts,
        "state_proof.request",
    );

    // At or before the clock the recipient's `Taken` is written at.
    let taken = clock(c);
    let Transfer {
        world,
        charges,
        record,
        ..
    } = transfer(c);
    let answer = taken_answer(c, record);
    assert!(
        c.run_until(epochs(6), |c| vault_balance(c, RECIPIENT_SHARD, to)
            == recipient_before + 100
            && stands(c, answer)),
        "the recipient is paid and its answer stands",
    );
    retired_at_a_later_boundary(c, record, taken, epochs(8) + retirement_wait(c));
    assert!(
        answers_cut.fired() > 0,
        "the answer's push must have been cut"
    );
    if withholding > 0 {
        assert!(
            withheld.fired() > 0,
            "the withholding validator asked too, and its asks were dropped",
        );
    }
    assert!(
        c.run_until(epochs(8) + retirement_wait(c), |c| !stands(c, answer)),
        "and the recipient deletes its answer at a boundary of the payer's shard",
    );
    c.clear_drops();
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a transfer whose answer push was lost",
    );
}

/// An answer is deleted at a boundary of its producer's shard, on no
/// push.
///
/// The record reaches the recipient by its push and the recipient's fold
/// credits it, while the answer's push back is cut, so the payer's record
/// stands. Then the cut turns round: every push from the payer's shard to
/// the recipient's is cut, and the answer pushes flow again. The payer
/// reads the answer at a boundary of the recipient's shard and retires
/// the record. No push carries the removal,
/// so the cut loses nothing of it, and the answer stands past the
/// retirement. It goes once the recipient has read the record absent at
/// a boundary the beacon recorded for the payer's shard, which its own
/// ask brings.
///
/// # Panics
///
/// Panics if the transfer does not accept or the recipient is not
/// credited, if the record is not retired, if the answer goes within
/// half a retention horizon of the retirement, if the answer is not
/// deleted, if no block carried a boundary deletion, or if the world
/// does not conserve.
pub fn an_answer_goes_at_its_producers_boundary_with_every_push_cut<C: FaultableCluster>(
    c: &mut C,
) {
    let (payer_hosts, recipient_hosts) = sides(c);
    let (_, _, to) = cross_shard_cast();
    let recipient_before = vault_balance(c, RECIPIENT_SHARD, to);
    c.drop_type_between(&recipient_hosts, &payer_hosts, "crossing.readings");

    let Transfer {
        world,
        charges,
        record,
        ..
    } = transfer(c);
    let answer = taken_answer(c, record);
    assert!(
        c.run_until(epochs(6), |c| vault_balance(c, RECIPIENT_SHARD, to)
            == recipient_before + 100
            && stands(c, answer)),
        "the recipient is credited and its answer stands",
    );
    c.clear_drops();
    c.drop_type_between(&payer_hosts, &recipient_hosts, "crossing.readings");
    assert!(
        c.run_until(epochs(8), |c| !stands(c, record)),
        "the payer reads the answer and retires the record",
    );
    let fresh_until = clock(c).plus(RETENTION_HORIZON / 2);
    assert!(
        c.run_until(epochs(8), |c| clock(c) >= fresh_until || !stands(c, answer)),
        "the run must outlast a fresh reading of the retirement",
    );
    assert!(
        stands(c, answer),
        "the answer outlives its record's retirement: no fresh absence deletes it",
    );
    assert!(
        c.run_until(epochs(8), |c| !stands(c, answer)),
        "the recipient reads the record absent at a boundary of the payer's shard and \
         deletes its answer",
    );
    assert!(
        asks(c, BOUNDARY_DELETIONS) > 0,
        "and it was a boundary reading that deleted it",
    );
    c.clear_drops();
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a transfer whose answer went at a boundary with the payer's pushes cut",
    );
    report_claims_recarried(
        c,
        "an_answer_goes_at_its_producers_boundary_with_every_push_cut",
    );
}

/// An answer written past the deadline is read at a later boundary of
/// the recipient's shard, not missed by a reading taken before it was
/// written.
///
/// The recipient is cut off from the record, and the payer's pushes to
/// it and its answer pushes back are cut too, so past the deadline
/// nothing answers and the record stands, whatever boundaries the payer
/// reads. The record reaches the recipient once its reads flow again,
/// the delivery lands and writes its `Taken` with the answer push still
/// cut, and the payer retires the record on the `Taken` read at a
/// boundary of the recipient's shard later than it.
///
/// # Panics
///
/// Panics if the transfer does not accept, if the delivery lands while
/// the cut stands, if the recipient is not paid once its reads flow, if
/// the record goes before a boundary shows its `Taken` or is not retired
/// after one, or if the world does not conserve.
pub fn an_answer_written_past_the_deadline_is_read_at_a_later_boundary<C: FaultableCluster>(
    c: &mut C,
) {
    let (payer_hosts, recipient_hosts) = sides(c);
    let (_, _, to) = cross_shard_cast();
    let recipient_before = vault_balance(c, RECIPIENT_SHARD, to);
    let cut_answers =
        |c: &mut C| c.drop_type_between(&recipient_hosts, &payer_hosts, "crossing.readings");
    cut_answers(c);
    c.drop_type_between(&payer_hosts, &recipient_hosts, "crossing.readings");
    c.drop_type_between(&payer_hosts, &recipient_hosts, "provisions.broadcast");
    c.drop_type_between(&recipient_hosts, &payer_hosts, "provision.request");
    c.drop_type_between(&recipient_hosts, &payer_hosts, "state_proof.request");

    let Transfer {
        world,
        charges,
        hash,
        deadline,
        record,
    } = transfer(c);

    // Past the deadline nothing answers, and the record stands, whatever
    // boundaries of the recipient's shard the payer reads.
    assert!(
        c.run_until(epochs(12), |c| clock(c) >= deadline.at()),
        "the run reaches the deadline",
    );
    let read_from = clock(c);
    assert!(
        await_a_readable_boundary(c, read_from, epochs(4) + retirement_wait(c), |c| {
            !stands(c, record)
        }),
        "the run outlasts a boundary of the recipient's shard the payer can read",
    );
    assert!(
        c.chain_fate(RECIPIENT_SHARD, hash).0.is_none() && stands(c, record),
        "while the recipient is cut off nothing answers and the record stands",
    );

    // The recipient's reads flow again; its answer's push stays cut.
    // At or before the clock the recipient's `Taken` is written at.
    let taken = clock(c);
    c.clear_drops();
    let answers_still_cut = cut_answers(c);
    assert!(
        c.run_until(epochs(12), |c| vault_balance(c, RECIPIENT_SHARD, to)
            == recipient_before + 100),
        "the recipient is paid once the record can reach it",
    );
    retired_at_a_later_boundary(c, record, taken, epochs(12) + retirement_wait(c));
    assert!(
        answers_still_cut.fired() > 0,
        "the answer's push must have been cut",
    );
    c.clear_drops();
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a transfer whose answer landed past the deadline",
    );
}

/// A payer replica that rejoins past the deadline reads a lost answer
/// itself at a boundary of the recipient's shard, off the rows it holds,
/// carrying nothing across the rejoin.
///
/// Every answer push to the payer's shard is cut, and so is every
/// payer validator's read of the recipient's shard, so every payer
/// replica's boundary read goes nowhere and the record stands. One
/// replica then rejoins by `rejoin` (a restart on the store it kept, or
/// a snap-sync onto an empty one), and it alone can read again. Its
/// questions derive from committed state, so it asks the recipient's
/// boundary as soon as it holds the state it rejoined at, and the record
/// is retired within a few of the payer's blocks of that.
///
/// The bound counts from the first boundary after the catch-up: the one
/// the head stands at once the replica holds its rows, which it asks at
/// once, aged past a retention horizon so a block can carry its reading.
/// A snap-synced replica imports the beacon-attested boundary, which
/// trails the tip by one to two epochs, and replays the gap before it
/// holds the rows the question derives from; the payer's blocks
/// committed during that replay are the sync's, not the ask's. A
/// restarted replica holds its store at once.
///
/// # Panics
///
/// Panics if the transfer does not accept or deliver, if no boundary of
/// the recipient's shard shows the answer, if the record goes before the
/// rejoin, if the replica does not catch up to the height it rejoined
/// at, if the record is not retired within the bound once it has, or if
/// the world does not conserve.
pub fn a_rejoined_producer_reads_a_lost_answer_at_a_boundary<C: FaultableCluster>(
    c: &mut C,
    rejoin: impl FnOnce(&mut C, usize, ShardId),
) {
    /// The payer blocks a rejoined replica, once caught up, gets to read
    /// the answer at the boundary and see a block it leads carry it.
    const REJOINED_WITHIN: u64 = 24;

    let (payer_hosts, recipient_hosts) = sides(c);
    let (_, _, to) = cross_shard_cast();
    let recipient_before = vault_balance(c, RECIPIENT_SHARD, to);
    let cut = |c: &mut C, readers: &[usize]| {
        c.drop_type_between(&recipient_hosts, &payer_hosts, "crossing.readings");
        c.drop_type_between(readers, &recipient_hosts, "state_proof.request")
    };
    let reads_cut = cut(c, &payer_hosts);

    // At or before the clock the recipient's `Taken` is written at.
    let taken = clock(c);
    let Transfer {
        world,
        charges,
        deadline,
        record,
        ..
    } = transfer(c);
    let answer = taken_answer(c, record);
    assert!(
        c.run_until(epochs(6), |c| vault_balance(c, RECIPIENT_SHARD, to)
            == recipient_before + 100
            && stands(c, answer)),
        "the recipient is paid and its answer stands",
    );
    assert!(
        c.run_until(epochs(12), |c| clock(c) >= deadline.at()),
        "the run reaches the deadline",
    );
    assert!(
        await_a_readable_boundary(c, taken, epochs(4) + retirement_wait(c), |_| false),
        "a boundary of the recipient's shard shows the answer, old enough to ride",
    );
    assert!(reads_cut.fired() > 0, "and every read of it was cut");
    assert!(stands(c, record), "so the record stands");

    let rejoined = payer_hosts[0];
    rejoin(c, rejoined, PAYER_SHARD);
    c.clear_drops();
    cut(c, &payer_hosts[1..]);
    let rejoined_at = c
        .committed_height(PAYER_SHARD)
        .expect("the payer's shard runs");
    assert!(
        c.run_until(epochs(1), |c| c
            .host_committed_height(rejoined, PAYER_SHARD)
            .is_some_and(|height| height >= rejoined_at)),
        "the rejoined replica catches up to height {rejoined_at:?}",
    );
    // The replica asks the boundary the head stands at once caught up,
    // and a block carries that boundary's reading once it is older than
    // a retention horizon.
    let asked = boundary_clock(c, RECIPIENT_SHARD).expect("the beacon records the boundary");
    assert!(
        c.run_until(epochs(2) + retirement_wait(c), |c| !stands(c, record)
            || clock(c) > asked.plus(RETENTION_HORIZON)),
        "the boundary asked at the catch-up ages past a retention horizon",
    );
    let from = c
        .committed_height(PAYER_SHARD)
        .expect("the payer's shard runs")
        .inner();
    assert!(
        c.run_until(epochs(4), |c| !stands(c, record)),
        "the rejoined replica reads the answer at the boundary and retires the record",
    );
    let retired_at = c
        .committed_height(PAYER_SHARD)
        .expect("the payer's shard runs")
        .inner();
    assert!(
        retired_at <= from + REJOINED_WITHIN,
        "at once: caught up at height {from}, retired at {retired_at}",
    );
    c.clear_drops();
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a transfer whose answer a rejoined replica read",
    );
}

/// A recipient replica cut off while an owed crossing is credited, and
/// kept from the payer's hosts as it catches up, credits it from the
/// block alone.
///
/// One recipient host is isolated before the transfer, and the rest of
/// its committee credits the recipient. Healed toward every host but the
/// payer's, which alone serve the record, the host block-syncs the
/// blocks it missed and commits each on its QC, the credit computed from
/// the block's own claims; a root that disagrees halts the replica. It
/// reaches a peer's height with the peer's root. Healed whole, the payer
/// retires the record on the recipient's `Taken` read at a boundary.
///
/// The isolation is short. A member absent for an epoch's randomness
/// commitment, or for a run of its proposals, is jailed and unseated, so
/// a committee replica never lags a whole retention horizon.
///
/// # Panics
///
/// Panics if the transfer does not credit without the isolated replica,
/// if the replica does not catch up to its peer's height and root while
/// kept from the payer's hosts, or if the record is not retired.
pub fn a_replica_that_missed_the_credit_commits_it_from_the_block<C: FaultableCluster>(c: &mut C) {
    let (_, recipient_hosts) = sides(c);
    let [lagging, peer, ..] = recipient_hosts[..] else {
        panic!("a recipient committee of at least two: {recipient_hosts:?}");
    };
    let (_, _, to) = cross_shard_cast();
    let recipient_before = vault_balance(c, RECIPIENT_SHARD, to);

    c.isolate(lagging);
    let isolated_at = c
        .host_committed_height(lagging, RECIPIENT_SHARD)
        .expect("the isolated host carries the recipient's shard");
    let Transfer {
        world,
        charges,
        record,
        ..
    } = transfer(c);
    assert!(
        c.run_until(epochs(6), |c| vault_balance(c, RECIPIENT_SHARD, to)
            == recipient_before + 100),
        "the recipient is credited without the isolated replica",
    );
    let credited_by = c
        .host_committed_height(peer, RECIPIENT_SHARD)
        .expect("the peer runs");
    let lagged_at = c
        .host_committed_height(lagging, RECIPIENT_SHARD)
        .expect("the isolated host still carries the shard");
    assert!(
        lagged_at <= isolated_at.next() && lagged_at < credited_by,
        "the isolated replica commits at most the block in flight when it was cut off, \
         which precedes the transfer: isolated at {isolated_at:?}, at {lagged_at:?}, \
         credited by {credited_by:?}",
    );

    // Healed toward every host but the payer's, which alone hold the
    // record, so whatever the replica commits it computes from the
    // blocks it syncs.
    let (payer_hosts, _) = sides(c);
    c.heal_all();
    c.partition(&[lagging], &payer_hosts);
    assert!(
        c.run_until(epochs(4), |c| {
            let lagging_at = c.host_committed_height(lagging, RECIPIENT_SHARD);
            lagging_at.is_some_and(|height| height >= credited_by)
                && lagging_at == c.host_committed_height(peer, RECIPIENT_SHARD)
                && c.host_committed_state_root(lagging, RECIPIENT_SHARD)
                    == c.host_committed_state_root(peer, RECIPIENT_SHARD)
        }),
        "the healed replica reaches its peer's height and root, past the credit at \
         {credited_by:?}: at {:?}, peer at {:?}",
        c.host_committed_height(lagging, RECIPIENT_SHARD),
        c.host_committed_height(peer, RECIPIENT_SHARD),
    );
    assert!(
        stands(c, record),
        "the record still stands, served only by the hosts cut from the replica",
    );
    c.heal_all();
    assert!(
        c.run_until(epochs(4) + retirement_wait(c), |c| !stands(c, record)),
        "the payer retires the record",
    );
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a transfer a replica that missed the credit caught up on",
    );
}
