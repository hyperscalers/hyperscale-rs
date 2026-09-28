//! A seed-driven fault schedule over any [`FaultableCluster`].
//!
//! Each [`Nemesis::step`] lifts the fault it last installed and draws the
//! next from its own seed: a minority bipartition, one isolated host, a
//! probabilistic drop of one message type, a few withheld committee members,
//! or a quiet step. A fault is installed only while every consensus
//! committee, each shard's and the beacon's, keeps a quorum outside it, so a
//! run under the nemesis must stay safe and, once [`Nemesis::heal`] lifts the
//! last fault, live.
//!
//! The schedule is recorded as it runs and printed if the run panics, so a
//! failure names the faults that led to it.

use std::collections::BTreeSet;
use std::{iter, thread};

use hyperscale_types::ValidatorId;
use hyperscale_types::test_utils::Withheld;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::support::faultable::FaultableCluster;

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

/// Draws before a fault that keeps every committee's quorum is given up on
/// for this step.
const MAX_DRAWS: usize = 16;

/// The fault a nemesis has installed.
enum Fault {
    /// A partition or an isolated host: lifted by healing every cut.
    Cut,
    Drop,
    Withhold(Vec<ValidatorId>),
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
    pub fn step(&mut self, c: &mut impl FaultableCluster) {
        self.heal(c);
        let at = c.now();
        let installed = match self.rng.random_range(0..5u8) {
            0 => self.partition(c),
            1 => self.isolate(c),
            2 => Some(self.lossy(c)),
            3 => self.withhold(c),
            _ => None,
        };
        let entry = installed.unwrap_or_else(|| "quiet".to_owned());
        self.log.push(format!("{at:?}: {entry}"));
    }

    /// Lift the active fault, restoring full delivery.
    pub fn heal(&mut self, c: &mut impl FaultableCluster) {
        match self.active.take() {
            Some(Fault::Cut) => c.heal_all(),
            Some(Fault::Drop) => c.clear_drops(),
            Some(Fault::Withhold(validators)) => {
                c.withhold(&validators, Withheld::Nothing);
            }
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

/// Every consensus committee the beacon currently names: each shard's and
/// its own.
fn committees(c: &impl FaultableCluster) -> Vec<BTreeSet<ValidatorId>> {
    let Some(state) = c.beacon_state() else {
        return Vec::new();
    };
    state
        .shard_consensus_members
        .values()
        .map(|members| members.iter().copied().collect())
        .chain(iter::once(state.committee.iter().copied().collect()))
        .collect()
}

/// The validators hosted on `hosts`.
fn validators_on(c: &impl FaultableCluster, hosts: &[usize]) -> BTreeSet<ValidatorId> {
    committees(c)
        .into_iter()
        .flatten()
        .filter(|validator| c.host_of(*validator).is_some_and(|h| hosts.contains(&h)))
        .collect()
}

/// Whether every committee keeps a quorum with `cut` taken out of it.
fn keeps_quorums(c: &impl FaultableCluster, cut: &BTreeSet<ValidatorId>) -> bool {
    committees(c).iter().all(|committee| {
        let faulty = committee.intersection(cut).count();
        faulty <= committee.len().saturating_sub(1) / 3
    })
}
