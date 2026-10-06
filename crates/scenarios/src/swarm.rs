//! Transfers under a seed-driven [`Nemesis`], judged after it heals.

use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_types::{TransactionStatus, TxHash};

use crate::epochs;
use crate::support::conservation::{Charges, World};
use crate::support::faultable::CrashableCluster;
use crate::support::nemesis::Nemesis;
use crate::support::query::{live_shards, served_shards, shard_decisions};
use crate::support::tx::{build_transfer_tx, recipient, sender, validity_around};

/// Funded senders the swarm draws payers from, and recipients it pays.
pub const SWARM_ACCOUNTS: u8 = 8;

/// Transfers under a nemesis stay live and conserved once it heals.
///
/// `rounds` epochs of transfers, a nemesis fault installed at the start of
/// each, then a heal: every transfer that committed reaches its terminal,
/// value is conserved across every account the run touched, and at least
/// one transfer settled, so the run said something.
///
/// A transfer the faults kept from committing before its validity window
/// closed is dropped by the mempool and never gets a status; that is the
/// faults' due, not a liveness failure.
///
/// # Panics
///
/// Panics if a committed transfer never reaches its terminal after the
/// heal, if two replicas of one shard report different decisions of a
/// transfer, if a shard live at the heal stops committing, if nothing settles
/// at all, or if value is not conserved.
pub fn transfers_survive_a_nemesis<C: CrashableCluster>(c: &mut C, seed: u64, rounds: u8) {
    let mut world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        (0..SWARM_ACCOUNTS)
            .map(|index| sender(index).1.address())
            .chain((0..SWARM_ACCOUNTS).map(|index| recipient(index).address())),
        [],
    );
    let mut charges = Charges::default();
    let mut nemesis = Nemesis::new(seed);
    let mut submitted: Vec<TxHash> = Vec::new();
    for round in 0..rounds {
        nemesis.step(c);
        for index in 0..SWARM_ACCOUNTS {
            let (payer, from) = sender(index);
            let to = recipient((index + round) % SWARM_ACCOUNTS);
            let tx = build_transfer_tx(
                &payer,
                from,
                to,
                1 + u128::from(round),
                validity_around(c.now()),
            );
            submitted.push(charges.submit(c, tx));
        }
        c.run_until(epochs(1), |_| false);
    }
    nemesis.heal(c);
    let healed_at: Vec<_> = served_shards(c)
        .into_iter()
        .map(|shard| (shard, c.committed_height(shard)))
        .collect();

    let committed = |c: &C, hash: &TxHash| {
        c.tx_status(*hash)
            .is_some_and(|status| !matches!(status, TransactionStatus::Pending))
    };
    let settled = c.run_until(epochs(8), |c| {
        submitted
            .iter()
            .filter(|hash| committed(c, hash))
            .all(|hash| c.tx_status(*hash).is_some_and(|status| status.is_final()))
    });
    let unsettled: Vec<(TxHash, Option<TransactionStatus>)> = submitted
        .iter()
        .filter(|hash| committed(c, hash) && !c.tx_status(**hash).is_some_and(|s| s.is_final()))
        .map(|hash| (*hash, c.tx_status(*hash)))
        .collect();
    assert!(
        settled,
        "committed transfers never reached their terminal after the heal: {unsettled:?}",
    );
    // Every replica of a shard reports the decision its chain reached,
    // whatever the nemesis kept it from hearing.
    for hash in &submitted {
        let _ = shard_decisions(c, *hash);
    }
    // A shard that halted for good settles none of the transfers its payers
    // send, and those never commit, so the settlement check above passes
    // over them; every shard live at the heal must still be moving.
    // A shard that split or merged since stops committing by design, and
    // its successors were not live at the heal to be measured.
    let advanced = |c: &C, shard, height| {
        !live_shards(c).contains(&shard) || c.committed_height(shard) > height
    };
    let moving = c.run_until(epochs(1), |c| {
        healed_at
            .iter()
            .all(|&(shard, height)| advanced(c, shard, height))
    });
    let stalled: Vec<_> = healed_at
        .into_iter()
        .filter(|&(shard, height)| !advanced(c, shard, height))
        .collect();
    assert!(
        moving,
        "shards made no progress after the heal: {stalled:?}",
    );
    assert!(
        submitted
            .iter()
            .any(|hash| c.tx_status(*hash).is_some_and(|status| status.is_final())),
        "no transfer settled across {rounds} rounds, so the run checked nothing",
    );
    // A cross-shard transfer's value sits in its crossing record between
    // the payer's leg and the payee's; count it while it stands.
    world.owing(charges.records(c));
    world.assert_settles_within(c, &charges, epochs(8), "transfers under a nemesis");
}
