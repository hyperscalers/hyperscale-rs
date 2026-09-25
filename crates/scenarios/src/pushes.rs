//! Crossing changes a counterpart reads arrive by push; a lost push is
//! read by the fallback.
//!
//! A block that writes a crossing answer pushes it to the record's
//! producer, and a block that removes a record pushes the absence to the
//! answer's consumer. On the happy path neither side asks the other
//! anything. Each scenario here cuts one push direction of a
//! cross-shard transfer and holds that nothing asks before the
//! transaction's deadline, that the fallback asks past it, and that the
//! reading it brings settles the crossing all the same.

use hyperscale_effects_bridge::ProtocolHasher;
use hyperscale_effects_bridge::vm_statics::crossing_records;
use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_types::{
    Deadline, ShardId, SubstateKey, TransactionDecision, TransactionStatus, TxHash,
};
use hyperscale_vm_effects::{Answered, CrossingCell, CrossingId};

use crate::support::conservation::{Charges, World};
use crate::support::faultable::FaultableCluster;
use crate::support::query::{clock, owning_shard, vault_balance};
use crate::support::tx::{build_transfer_tx, cross_shard_cast, validity_around};
use crate::support::wait::await_tx_terminal;
use crate::support::{Cluster, epochs};

const PAYER_SHARD: ShardId = ShardId::leaf(1, 0);
const RECIPIENT_SHARD: ShardId = ShardId::leaf(1, 1);

/// The fallback asks each side counts: a producer asking what its
/// consumer answered, and a consumer asking whether the record behind
/// its answer still stands.
const PRODUCER_ASKS: (&str, Option<&str>) = ("crossing_fallback_asks", Some("producer"));
const CONSUMER_ASKS: (&str, Option<&str>) = ("crossing_fallback_asks", Some("consumer"));

fn asks(c: &impl FaultableCluster, (name, label): (&'static str, Option<&str>)) -> u64 {
    c.metric(name, label)
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
        &tx.try_derived(c.derivation().as_ref())
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
fn taken_answer<C: Cluster + ?Sized>(c: &C, record: SubstateKey) -> SubstateKey {
    let bytes = c
        .substate(owning_shard(c, record.owner), record.owner, record.local.0)
        .expect("the record stands on the payer's chain once its leg accepts");
    let cell = CrossingCell::from_bytes(&bytes).expect("a record cell");
    CrossingId::of_record(record.owner, &cell).answer_key(&ProtocolHasher, Answered::Taken)
}

/// Run until the deadline has passed or `early` says something moved
/// before it, then assert nothing did.
fn nothing_moves_before_the_deadline<C: FaultableCluster>(
    c: &mut C,
    deadline: Deadline,
    early: impl Fn(&C) -> bool,
    what: &str,
) {
    assert!(
        c.run_until(epochs(8), |c| clock(c) >= deadline.at() || early(c)),
        "the run must reach the deadline",
    );
    assert!(!early(c), "{what}");
}

/// A lost answer push is read by the producer's fallback, past the
/// deadline and not before.
///
/// Every answer push from the recipient's shard to the payer's is cut.
/// The recipient delivers and writes its `Taken`; the payer's record
/// stands, and nothing asks about it while the deadline has not passed,
/// since the push is the only carrier before it. Past the deadline the
/// payer asks the answer, reads it present, and its fold retires the
/// record.
///
/// # Panics
///
/// Panics if the transfer does not accept or deliver, if anything asks
/// or the record goes before the deadline, if the cut never fires, if
/// the record is not retired past the deadline, or if the world does not
/// conserve.
pub fn a_lost_answer_push_is_asked_past_the_deadline<C: FaultableCluster>(c: &mut C) {
    lost_answer_push(c, 0);
}

/// The fallback cannot be withheld: with f of the payer's validators
/// withholding their fetch, the others ask and carry the reading.
///
/// [`a_lost_answer_push_is_asked_past_the_deadline`] with one of the
/// payer's four validators unable to fetch from the recipient's shard.
/// The withholding validator's asks are dropped; every other validator
/// derives the same question and asks it for itself, and whichever of
/// them leads next carries the reading.
///
/// # Panics
///
/// As [`a_lost_answer_push_is_asked_past_the_deadline`], and if the
/// withholding validator's asks never fire.
pub fn a_withheld_fallback_is_asked_by_an_honest_validator<C: FaultableCluster>(c: &mut C) {
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

    nothing_moves_before_the_deadline(
        c,
        deadline,
        |c| asks(c, PRODUCER_ASKS) > 0 || !stands(c, record),
        "before the deadline nothing asks and the record stands: its answer's push is lost",
    );
    assert!(
        c.run_until(epochs(8), |c| !stands(c, record)),
        "past the deadline the payer asks the answer and retires the record",
    );
    assert!(
        answers_cut.fired() > 0,
        "the answer's push must have been cut"
    );
    assert!(
        asks(c, PRODUCER_ASKS) > 0,
        "and it was the fallback that read it"
    );
    if withholding > 0 {
        assert!(
            withheld.fired() > 0,
            "the withholding validator asked too, and its asks were dropped",
        );
    }
    assert!(
        c.run_until(epochs(8), |c| !stands(c, answer)),
        "and the removal's push deletes the recipient's answer",
    );
    c.clear_drops();
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a transfer whose answer push was lost",
    );
}

/// A lost removal push is read by the consumer's fallback, past the
/// deadline its answer carries.
///
/// The record reaches the recipient by its push and the recipient's fold
/// credits it, while the answer's push back is cut, so the payer's record
/// stands. Then the cut turns round: every push from the payer's shard to
/// the recipient's is cut, and the answer pushes flow again. The payer
/// reads the answer by its own fallback and retires the record, and the
/// removal's push is lost. The answer stands, unasked, until the deadline
/// it carries; then the recipient asks the record, reads it absent, and
/// its fold deletes the answer.
///
/// # Panics
///
/// Panics if the transfer does not accept or the recipient is not
/// credited, if the record is not retired, if anything asks or the answer
/// goes before the deadline, if the cut never fires, if the answer is not
/// deleted past the deadline, or if the world does not conserve.
pub fn a_lost_removal_push_is_asked_past_the_deadline<C: FaultableCluster>(c: &mut C) {
    let (payer_hosts, recipient_hosts) = sides(c);
    let (_, _, to) = cross_shard_cast();
    let recipient_before = vault_balance(c, RECIPIENT_SHARD, to);
    c.drop_type_between(&recipient_hosts, &payer_hosts, "crossing.readings");

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
        "the recipient is credited and its answer stands",
    );
    c.clear_drops();
    let removals_cut = c.drop_type_between(&payer_hosts, &recipient_hosts, "crossing.readings");
    nothing_moves_before_the_deadline(
        c,
        deadline,
        |c| asks(c, CONSUMER_ASKS) > 0 || !stands(c, answer),
        "before the deadline nothing asks and the answer stands",
    );
    assert!(
        c.run_until(epochs(8), |c| !stands(c, record)),
        "the payer reads the answer and retires the record",
    );
    assert!(
        c.run_until(epochs(8), |c| !stands(c, answer)),
        "past the deadline the recipient asks the record and deletes its answer",
    );
    assert!(
        removals_cut.fired() > 0,
        "the payer's pushes must have been cut"
    );
    assert!(
        asks(c, CONSUMER_ASKS) > 0,
        "and it was the fallback that read the absence",
    );
    c.clear_drops();
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a transfer whose removal push was lost",
    );
}

/// An answer written past the deadline is read on a later step of the
/// fallback, not missed by a one-shot read.
///
/// The recipient is cut off from the record, and the payer's pushes to
/// it and its answer pushes back are cut too, so past the deadline the
/// payer asks the answer and reads nothing there. The record reaches the
/// recipient once its reads flow again, the delivery lands and writes
/// its `Taken` with the answer push still cut, and the payer's next ask
/// reads it and retires the record.
///
/// # Panics
///
/// Panics if the transfer does not accept, if the delivery lands while
/// the cut stands, if the payer does not ask past the deadline, if the
/// recipient is not paid once its reads flow, if the record is not
/// retired, or if the world does not conserve.
pub fn an_answer_written_past_the_deadline_is_read_on_a_later_ask<C: FaultableCluster>(c: &mut C) {
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

    // Past the deadline the payer asks, and asks again on its backoff,
    // with no answer to read.
    let hosts = u64::try_from(payer_hosts.len()).expect("a committee size");
    assert!(
        c.run_until(epochs(12), |c| clock(c) >= deadline.at()
            && asks(c, PRODUCER_ASKS) >= 2 * hosts),
        "the payer asks the answer past the deadline, more than once: asked {} at {:?}, \
         deadline {:?}, recipient committed {:?}, record stands {}",
        asks(c, PRODUCER_ASKS),
        clock(c),
        deadline.at(),
        c.chain_fate(RECIPIENT_SHARD, hash),
        stands(c, record),
    );
    assert!(
        c.chain_fate(RECIPIENT_SHARD, hash).0.is_none() && stands(c, record),
        "while the recipient is cut off nothing answers and the record stands",
    );

    // The recipient's reads flow again; its answer's push stays cut.
    c.clear_drops();
    let answers_still_cut = cut_answers(c);
    let asked_before = asks(c, PRODUCER_ASKS);
    assert!(
        c.run_until(epochs(12), |c| vault_balance(c, RECIPIENT_SHARD, to)
            == recipient_before + 100),
        "the recipient is paid once the record can reach it",
    );
    assert!(
        c.run_until(epochs(12), |c| !stands(c, record)),
        "and a later ask reads its answer and retires the record",
    );
    assert!(
        answers_still_cut.fired() > 0,
        "the answer's push must have been cut",
    );
    assert!(
        asks(c, PRODUCER_ASKS) > asked_before,
        "and the reading came from an ask after the answer was written",
    );
    c.clear_drops();
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a transfer whose answer landed past the deadline",
    );
}

/// A payer replica that rejoins past the deadline asks a lost answer
/// itself, off the rows it holds, carrying nothing across the rejoin.
///
/// Every answer push to the payer's shard is cut, and so is every
/// payer validator's read of the recipient's shard, so past the
/// deadline every payer replica's ask goes nowhere. One replica then
/// rejoins by `rejoin` (a restart on the store it kept, or a snap-sync
/// onto an empty one), and it alone can read again. Its questions derive
/// from committed state, so it asks at once and the record is retired
/// within a few of the payer's blocks.
///
/// # Panics
///
/// Panics if the transfer does not accept or deliver, if the payer's
/// replicas do not ask past the deadline, if the record goes before the
/// rejoin, if it is not retired within the bound once the replica
/// rejoins, or if the world does not conserve.
pub fn a_rejoined_producer_asks_a_lost_answer<C: FaultableCluster>(
    c: &mut C,
    rejoin: impl FnOnce(&mut C, usize, ShardId),
) {
    /// The payer blocks a rejoined replica gets to read the answer and
    /// see a block it leads carry it.
    const REJOINED_WITHIN: u64 = 24;

    let (payer_hosts, recipient_hosts) = sides(c);
    let (_, _, to) = cross_shard_cast();
    let recipient_before = vault_balance(c, RECIPIENT_SHARD, to);
    let cut = |c: &mut C, readers: &[usize]| {
        c.drop_type_between(&recipient_hosts, &payer_hosts, "crossing.readings");
        c.drop_type_between(readers, &recipient_hosts, "state_proof.request")
    };
    let reads_cut = cut(c, &payer_hosts);

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

    let hosts = u64::try_from(payer_hosts.len()).expect("a committee size");
    assert!(
        c.run_until(epochs(12), |c| clock(c) >= deadline.at()
            && asks(c, PRODUCER_ASKS) >= hosts),
        "every payer replica asks past the deadline: asked {}",
        asks(c, PRODUCER_ASKS),
    );
    assert!(reads_cut.fired() > 0, "and every ask was cut");
    assert!(stands(c, record), "so the record stands");

    let rejoined = payer_hosts[0];
    rejoin(c, rejoined, PAYER_SHARD);
    c.clear_drops();
    cut(c, &payer_hosts[1..]);
    let from = c
        .committed_height(PAYER_SHARD)
        .expect("the payer's shard runs")
        .inner();
    assert!(
        c.run_until(epochs(4), |c| !stands(c, record)),
        "the rejoined replica asks the answer and retires the record",
    );
    let retired_at = c
        .committed_height(PAYER_SHARD)
        .expect("the payer's shard runs")
        .inner();
    assert!(
        retired_at <= from + REJOINED_WITHIN,
        "at once: rejoined at height {from}, retired at {retired_at}",
    );
    c.clear_drops();
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a transfer whose answer a rejoined replica read",
    );
}
