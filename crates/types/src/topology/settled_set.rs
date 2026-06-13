//! The split-boundary settled-set predicate.
//!
//! When a shard `P` splits, its chain terminates at a terminal block `B`.
//! A cross-shard transaction whose `P`-half settles only if `P` committed
//! the wave's certificate by `B` — otherwise one side of the transaction
//! would apply without the other. `S_P` is the set of wave-ids `P` settled
//! by `B`; a surviving counterpart reconstructs it from `P`'s tail chain.
//!
//! This module holds the shared predicate both sides apply: the shard
//! coordinator's pre-vote fence (a block carrying such a wave votes only
//! if every past-terminal EC is settled) and the execution coordinator's
//! finalize-hygiene gate (don't even produce a wave the fence would
//! reject). Keeping one predicate keeps the two verdicts from drifting —
//! a disagreement would let a gate produce what the fence rejects.

use std::collections::{BTreeSet, HashMap};
use std::hash::BuildHasher;

use crate::{RETENTION_HORIZON, ShardId, TopologySchedule, WaveId, WeightedTimestamp};

/// A terminated shard's settled-wave set.
///
/// `waves` are the wave-ids whose certificate committed in its chain at or
/// before its terminal block. `terminal_wt` is the weighted timestamp at
/// which the shard terminated, bounding how long the set stays relevant —
/// [`RETENTION_HORIZON`] past it, any wave naming the shard is
/// categorically unreachable everywhere.
#[derive(Clone, Debug)]
pub struct SettledWaveSet {
    /// Wave-ids the terminated shard settled by its terminal block.
    pub waves: BTreeSet<WaveId>,
    /// The terminal block's weighted timestamp.
    pub terminal_wt: WeightedTimestamp,
}

/// The verdict on a set of cross-shard execution certificates against the
/// known settled sets, at an anchored weighted timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettledSetVerdict {
    /// No certificate names a past-terminal shard, or every such
    /// certificate's wave is in that shard's settled set.
    Pass,
    /// A certificate names a wave a past-terminal shard did not settle,
    /// names a shard evicted from every retained window, or sits past the
    /// terminated shard's retention horizon — categorically unreachable.
    Reject,
    /// A certificate names a past-terminal shard whose settled set isn't
    /// known yet — hold until it is reconstructed.
    Defer,
}

/// Resolve cross-shard execution certificates against the known settled
/// sets at `anchored_wt`.
///
/// `ecs` yields `(shard, wave_id)` for each constituent execution
/// certificate. Past-terminal-ness is read off the **anchored** snapshot
/// at `anchored_wt`, so callers that must agree across replicas (the
/// vote fence) pass the voted block's `parent_qc` weighted timestamp;
/// node-local callers (the finalize gate) pass their committed timestamp.
pub fn settled_set_verdict<'a, S, I>(
    settled_sets: &HashMap<ShardId, SettledWaveSet, S>,
    topology: &TopologySchedule,
    local_shard: ShardId,
    anchored_wt: WeightedTimestamp,
    ecs: I,
) -> SettledSetVerdict
where
    S: BuildHasher,
    I: IntoIterator<Item = (ShardId, &'a WaveId)>,
{
    let mut defer = false;
    for (shard, wave_id) in ecs {
        if shard == local_shard {
            continue;
        }
        // Evicted from every retained window — terminated so long ago its
        // waves can never resolve.
        let Some((_, past_terminal)) = topology.at_for_shard(shard, anchored_wt) else {
            return SettledSetVerdict::Reject;
        };
        if !past_terminal {
            continue;
        }
        match settled_sets.get(&shard) {
            Some(settled) if anchored_wt > settled.terminal_wt.plus(RETENTION_HORIZON) => {
                return SettledSetVerdict::Reject;
            }
            Some(settled) if !settled.waves.contains(wave_id) => {
                return SettledSetVerdict::Reject;
            }
            Some(_) => {}
            None => defer = true,
        }
    }
    if defer {
        SettledSetVerdict::Defer
    } else {
        SettledSetVerdict::Pass
    }
}
