//! A seed-driven fault schedule over any [`FaultableCluster`].
//!
//! Each [`Nemesis::step`] lifts the fault it last installed and draws the
//! next from its own seed: a minority bipartition, one that flaps open and
//! shut, one isolated host, a probabilistic drop of one message type, a few
//! withheld committee members, a crashed host, or a quiet step. A crash is
//! not lifted: the host restarts on its own once its downtime is over, and
//! a crash armed at a write that has not fired is disarmed. A fault is installed only while every consensus
//! committee, each shard's and the beacon's, keeps a quorum outside it, so a
//! run under the nemesis must stay safe and, once [`Nemesis::heal`] lifts the
//! last fault, live.
//!
//! The schedule is recorded as it runs and printed if the run panics, so a
//! failure names the faults that led to it.

use std::collections::BTreeSet;
use std::ops::Range;
use std::time::Duration;
use std::{iter, thread};

use hyperscale_types::test_utils::Withheld;
use hyperscale_types::{BlockHeight, ValidatorId, ValidatorStatus};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::support::epochs;
use crate::support::faultable::{Crash, CrashableCluster, FaultableCluster};

/// Message types a drop fault may target: every class the protocol
/// recovers from losing, by retransmission or a fetch fallback.
const DROPPABLE: [&str; 9] = [
    "block.header",
    "block.vote",
    "block.committed",
    "shard.timeout",
    "execution.vote",
    "execution.cert.batch",
    "provisions.broadcast",
    "crossing.readings",
    "transaction.gossip",
];

/// How many blocks a seated member may trail its shard's tip and still
/// count toward a quorum: in-flight commits, not a member left behind.
const LAG_ALLOWANCE: u64 = 64;

/// How far ahead a flapping partition's windows are laid out: past any
/// round, so the fault keeps flapping until the next step lifts it.
const FLAP_HORIZON: Duration = Duration::from_secs(600);

/// Draws before a fault that keeps every committee's quorum is given up on
/// for this step.
const MAX_DRAWS: usize = 16;

/// The furthest write ahead a crash may be armed at: a running host
/// writes a vote register every few blocks, so one this close fires
/// within the step.
const MAX_WRITES_BEFORE_CRASH: u64 = 32;

/// The fault a nemesis has installed.
enum Fault {
    /// A partition, flapping or not, or an isolated host: lifted by healing
    /// every cut.
    Cut,
    Drop,
    Withhold(Vec<ValidatorId>),
    /// A crash armed at one of a host's coming writes.
    ArmedCrash(usize),
}

/// A seed-driven fault schedule.
pub struct Nemesis {
    rng: ChaCha8Rng,
    active: Option<Fault>,
    log: Vec<String>,
}

impl Nemesis {
    /// A schedule drawn from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            rng: ChaCha8Rng::seed_from_u64(seed ^ 0x4E45_4D45_5349_5321),
            active: None,
            log: Vec::new(),
        }
    }

    /// Lift the active fault and install the next one.
    pub fn step(&mut self, c: &mut impl CrashableCluster) {
        self.heal(c);
        let at = c.now();
        let installed = match self.rng.random_range(0..7u8) {
            0 => self.partition(c),
            1 => self.flap(c),
            2 => self.isolate(c),
            3 => Some(self.lossy(c)),
            4 => self.withhold(c),
            5 => self.crash(c),
            _ => None,
        };
        let entry = installed.unwrap_or_else(|| "quiet".to_owned());
        self.log.push(format!("{at:?}: {entry}"));
    }

    /// Lift the active fault, restoring full delivery.
    pub fn heal(&mut self, c: &mut impl CrashableCluster) {
        match self.active.take() {
            Some(Fault::Cut) => c.heal_all(),
            Some(Fault::Drop) => c.clear_drops(),
            Some(Fault::Withhold(validators)) => {
                c.withhold(&validators, Withheld::Nothing);
            }
            Some(Fault::ArmedCrash(host)) => c.disarm_crash(host),
            None => {}
        }
    }

    /// The faults installed so far, one line per step.
    #[must_use]
    pub fn schedule(&self) -> &[String] {
        &self.log
    }

    fn partition(&mut self, c: &mut impl FaultableCluster) -> Option<String> {
        let hosts = c.host_count();
        for _ in 0..MAX_DRAWS {
            let count = self.rng.random_range(1..=hosts.div_ceil(3).max(1));
            let side = self.draw_hosts(hosts, count);
            let cut = validators_on(c, &side);
            if keeps_quorums(c, &cut) {
                let rest: Vec<usize> = (0..hosts).filter(|h| !side.contains(h)).collect();
                c.partition(&side, &rest);
                self.active = Some(Fault::Cut);
                return Some(format!("partition {side:?} from the rest"));
            }
        }
        None
    }

    /// A minority bipartition that cuts for part of every period and
    /// connects for the rest, so the protocol keeps recovering into a cut
    /// rather than once out of one.
    fn flap(&mut self, c: &mut impl FaultableCluster) -> Option<String> {
        let hosts = c.host_count();
        for _ in 0..MAX_DRAWS {
            let count = self.rng.random_range(1..=hosts.div_ceil(3).max(1));
            let side = self.draw_hosts(hosts, count);
            if !keeps_quorums(c, &validators_on(c, &side)) {
                continue;
            }
            let period = Duration::from_millis(self.rng.random_range(2_000..=10_000));
            let cut_for = period.mul_f64(self.rng.random_range(0.3..0.7));
            let windows: Vec<Range<Duration>> = iter::successors(Some(Duration::ZERO), |start| {
                Some(*start + period).filter(|next| *next < FLAP_HORIZON)
            })
            .map(|start| start..start + cut_for)
            .collect();
            let rest: Vec<usize> = (0..hosts).filter(|h| !side.contains(h)).collect();
            c.partition_during(&side, &rest, &windows);
            self.active = Some(Fault::Cut);
            return Some(format!(
                "flap {side:?} from the rest, cut {cut_for:?} of every {period:?}"
            ));
        }
        None
    }

    fn isolate(&mut self, c: &mut impl FaultableCluster) -> Option<String> {
        for _ in 0..MAX_DRAWS {
            let host = self.rng.random_range(0..c.host_count());
            if keeps_quorums(c, &validators_on(c, &[host])) {
                c.isolate(host);
                self.active = Some(Fault::Cut);
                return Some(format!("isolate host {host}"));
            }
        }
        None
    }

    fn lossy(&mut self, c: &mut impl FaultableCluster) -> String {
        let type_id = DROPPABLE[self.rng.random_range(0..DROPPABLE.len())];
        let probability = self.rng.random_range(0.1..0.5);
        c.drop_type_with_probability(type_id, probability);
        self.active = Some(Fault::Drop);
        format!("drop {type_id} at {probability:.2}")
    }

    fn withhold(&mut self, c: &mut impl FaultableCluster) -> Option<String> {
        let committees = committees(c);
        if committees.is_empty() {
            return None;
        }
        let committee = &committees[self.rng.random_range(0..committees.len())];
        let most = (committee.len().saturating_sub(1)) / 3;
        if most == 0 {
            return None;
        }
        let count = self.rng.random_range(1..=most);
        let mut members: Vec<ValidatorId> = committee.iter().copied().collect();
        let mut chosen = Vec::with_capacity(count);
        for _ in 0..count {
            chosen.push(members.swap_remove(self.rng.random_range(0..members.len())));
        }
        let cut: BTreeSet<ValidatorId> = chosen.iter().copied().collect();
        if !keeps_quorums(c, &cut) {
            return None;
        }
        let withheld = if self.rng.random_range(0..2u8) == 0 {
            Withheld::Votes
        } else {
            Withheld::Consensus
        };
        c.withhold(&chosen, withheld);
        let entry = format!("withhold {withheld:?} from {chosen:?}");
        self.active = Some(Fault::Withhold(chosen));
        Some(entry)
    }

    /// Crash one host whose members every committee can spare, by its
    /// process or its machine, now or at one of its coming writes, for no
    /// time or an epoch.
    fn crash(&mut self, c: &mut impl CrashableCluster) -> Option<String> {
        for _ in 0..MAX_DRAWS {
            let host = self.rng.random_range(0..c.host_count());
            if c.is_up(host) && keeps_quorums(c, &validators_on(c, &[host])) {
                let crash = if self.rng.random_range(0..2u8) == 0 {
                    Crash::Process
                } else {
                    Crash::Machine
                };
                let downtime = epochs(self.rng.random_range(0..=1u32));
                if self.rng.random_range(0..2u8) == 0 {
                    c.crash(host, crash, downtime);
                    return Some(format!("crash host {host} ({crash:?}) for {downtime:?}"));
                }
                let writes_before = self.rng.random_range(0..MAX_WRITES_BEFORE_CRASH);
                c.crash_at_write(host, writes_before, crash, downtime);
                self.active = Some(Fault::ArmedCrash(host));
                return Some(format!(
                    "crash host {host} ({crash:?}) at its write {writes_before}, for {downtime:?}"
                ));
            }
        }
        None
    }

    fn draw_hosts(&mut self, hosts: usize, count: usize) -> Vec<usize> {
        let mut pool: Vec<usize> = (0..hosts).collect();
        let mut drawn = Vec::with_capacity(count);
        for _ in 0..count.min(hosts) {
            drawn.push(pool.swap_remove(self.rng.random_range(0..pool.len())));
        }
        drawn.sort_unstable();
        drawn
    }
}

impl Drop for Nemesis {
    fn drop(&mut self) {
        if thread::panicking() {
            eprintln!("nemesis schedule:");
            for entry in &self.log {
                eprintln!("  {entry}");
            }
        }
    }
}

/// Every consensus committee the beacon names for this window and the
/// next: each shard's and its own. A fault installed now outlives the
/// window it was drawn in, so it must hold against the next one as well.
fn committees(c: &impl FaultableCluster) -> Vec<BTreeSet<ValidatorId>> {
    let Some(state) = c.beacon_state() else {
        return Vec::new();
    };
    let next = state.next_shard_committees.iter().map(|(shard, committee)| {
        committee
            .members
            .iter()
            .copied()
            .filter(|member| {
                state.validators.get(member).is_some_and(|record| {
                    matches!(record.status, ValidatorStatus::OnShard { shard: on, ready: true, .. } if on == *shard)
                })
            })
            .collect()
    });
    state
        .shard_consensus_members
        .values()
        .map(|members| members.iter().copied().collect())
        .chain(next)
        .chain(iter::once(state.committee.iter().copied().collect()))
        .collect()
}

/// Members the beacon no longer counts on: jailed, revoked or unstaked.
/// They sign nothing, so a committee already carries them as faults.
fn inactive(c: &impl FaultableCluster) -> BTreeSet<ValidatorId> {
    c.beacon_state().map_or_else(BTreeSet::new, |state| {
        state
            .validators
            .iter()
            .filter(|(_, record)| {
                !matches!(
                    record.status,
                    ValidatorStatus::OnShard { .. }
                        | ValidatorStatus::Observing { .. }
                        | ValidatorStatus::Pooled
                )
            })
            .map(|(id, _)| *id)
            .collect()
    })
}

/// The validators hosted on `hosts`.
fn validators_on(c: &impl FaultableCluster, hosts: &[usize]) -> BTreeSet<ValidatorId> {
    committees(c)
        .into_iter()
        .flatten()
        .filter(|validator| c.host_of(*validator).is_some_and(|h| hosts.contains(&h)))
        .collect()
}

/// Seated members whose copy of their shard trails its tip by more than
/// [`LAG_ALLOWANCE`], or who hold no copy at all. A member that has not
/// reached the block it is asked to vote on signs nothing, so until it
/// catches up its committee already carries it as a fault.
fn lagging(c: &impl FaultableCluster) -> BTreeSet<ValidatorId> {
    let Some(state) = c.beacon_state() else {
        return BTreeSet::new();
    };
    state
        .shard_consensus_members
        .iter()
        .flat_map(|(shard, members)| {
            let tip = c.committed_height(*shard).map_or(0, BlockHeight::inner);
            members.iter().copied().filter(move |member| {
                c.host_of(*member)
                    .and_then(|host| c.host_committed_height(host, *shard))
                    .is_none_or(|height| tip.saturating_sub(height.inner()) > LAG_ALLOWANCE)
            })
        })
        .collect()
}

/// Whether every committee keeps a quorum with `cut` taken out of it,
/// counting the members already inactive or lagging as cut too.
fn keeps_quorums(c: &impl FaultableCluster, cut: &BTreeSet<ValidatorId>) -> bool {
    let absent: BTreeSet<ValidatorId> = inactive(c).into_iter().chain(lagging(c)).collect();
    committees(c).iter().all(|committee| {
        let faulty = committee
            .iter()
            .filter(|member| cut.contains(member) || absent.contains(member))
            .count();
        faulty <= committee.len().saturating_sub(1) / 3
    })
}
