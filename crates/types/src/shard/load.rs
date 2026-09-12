//! The shard's attested load, as a block header states it.

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::DeclaredWork;

/// What a block attests about its shard's load: what the chain has
/// consumed, what its blocks reserved, and the state it holds.
///
/// Every figure is header content, so a consumer reads them off a header
/// it already holds — the beacon off the boundary header it sources each
/// epoch, a joining node off the block it joined at — and every replica
/// recomputes them before voting. The pair is deliberately two shapes:
///
/// - [`cumulative_work`](Self::cumulative_work) is a **flow**, carried as a
///   running total over the chain's whole history. A consumer wanting one
///   epoch's consumption differences it against the total it last
///   recorded, which makes the quantity monotone and its application
///   idempotent: a missed boundary crossing is absorbed by the next one
///   instead of lost. Carrying the total rather than the increment is
///   also what lets a node that joined mid-chain continue the count —
///   the block it synced to states the running total, so nothing has to
///   reconstruct it from history the joiner does not have.
/// - [`used`](Self::used) is a flow on the same terms, kept per
///   dimension because its consumer moves each price row by its own
///   dimension's use — a scalar would hide a network saturating disk
///   while compute idles, which is the thing the vector exists to show.
/// - [`substate_bytes`](Self::substate_bytes) is a **level**, the byte
///   total behind the block's parent state. A consumer records it as-is,
///   and a missed crossing simply leaves the value unrefreshed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct ShardLoad {
    /// Work this chain has attested over its whole history, through the
    /// certificates the block itself carries.
    ///
    /// Priced by the engine's schedule, which combines the compute an
    /// execution consumed with the footprint its declaration claimed —
    /// so a participant that applied almost nothing still reports the
    /// exclusivity it held. Consensus carries the one scalar and never
    /// the ratio behind it.
    ///
    /// Accumulation saturates rather than wrapping. Wrapping would break
    /// the monotonicity a differencing consumer relies on, and it has no
    /// honest reading: the epoch it straddles would come out as zero
    /// consumption or as the whole counter's width.
    pub cumulative_work: u64,
    /// What this chain's blocks have reserved against their per-block
    /// caps over its whole history, dimension by dimension.
    ///
    /// A flow like [`cumulative_work`](Self::cumulative_work) and for
    /// the same reasons, but a vector rather than a scalar: the beacon
    /// moves each row of the price table by its own dimension's use, so
    /// a network saturating disk while compute idles has to be readable
    /// as exactly that. Differenced across an epoch against the block
    /// count, it is the utilization the controller steps on.
    ///
    /// Declared, never measured: the figure is the sum of what the
    /// block's transactions reserved on this shard, which is what
    /// `BLOCK_CAPS` capped and what every replica recomputes before
    /// voting.
    pub used: DeclaredWork,
    /// Committed substate byte total behind the block's parent state —
    /// the same quantity the reshape predicate evaluates.
    ///
    /// `None` under exactly the condition that takes that predicate out
    /// of play: the block's ancestry crosses a halt recovery's
    /// sync-admitted suffix, where the total is unknowable until the
    /// suffix commits. Every replica that can vote on the block resolves
    /// the same absence, so the claim stays agreed.
    pub substate_bytes: Option<u64>,
}

impl ShardLoad {
    /// Nothing consumed and no resolved byte total.
    ///
    /// Every structural genesis header's load: a chain starts its own
    /// count at zero — including a split child or a merged parent, which
    /// inherit state but not their predecessor's attested work — and a
    /// genesis block has no parent state to have a total behind.
    pub const ZERO: Self = Self {
        cumulative_work: 0,
        used: DeclaredWork::ZERO,
        substate_bytes: None,
    };

    /// This load advanced by `work` and `used`, and re-anchored on
    /// `substate_bytes`.
    ///
    /// The successor relation the proposer applies and every verifier
    /// recomputes, so neither side can drift on the arithmetic.
    #[must_use]
    pub const fn advance(self, work: u64, used: DeclaredWork, substate_bytes: Option<u64>) -> Self {
        Self {
            cumulative_work: self.cumulative_work.saturating_add(work),
            used: self.used.saturating_add(used),
            substate_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    /// A vector with `compute` set and nothing else, so a test can move
    /// one dimension and read that the others held.
    const fn compute(compute: u64) -> DeclaredWork {
        DeclaredWork {
            compute,
            ..DeclaredWork::ZERO
        }
    }

    #[test]
    fn advance_accumulates_the_flows_and_replaces_the_byte_level() {
        let start = ShardLoad::ZERO;
        let next = start.advance(70, compute(7), Some(4_096));
        assert_eq!(next.cumulative_work, 70);
        assert_eq!(next.used.compute, 7);
        assert_eq!(next.substate_bytes, Some(4_096));

        // Both flows accumulate; the byte total is a level, so it
        // replaces.
        let later = next.advance(30, compute(3), Some(8_192));
        assert_eq!(later.cumulative_work, 100);
        assert_eq!(later.used.compute, 10);
        assert_eq!(later.substate_bytes, Some(8_192));

        // An unresolved byte total does not disturb either flow.
        let unresolved = later.advance(5, compute(1), None);
        assert_eq!(unresolved.cumulative_work, 105);
        assert_eq!(unresolved.used.compute, 11);
        assert_eq!(unresolved.substate_bytes, None);

        // Each dimension accumulates on its own: a block declaring only
        // reads leaves the compute total where it was.
        let reads = unresolved.advance(
            0,
            DeclaredWork {
                read_bytes: 4_096,
                ..DeclaredWork::ZERO
            },
            None,
        );
        assert_eq!(reads.used.compute, 11);
        assert_eq!(reads.used.read_bytes, 4_096);
    }

    #[test]
    fn saturating_accumulation_does_not_wrap() {
        let brim = ShardLoad::ZERO.advance(u64::MAX, compute(u64::MAX), None);
        let past = brim.advance(1_000, compute(1_000), None);
        assert_eq!(past.cumulative_work, u64::MAX);
        assert_eq!(past.used.compute, u64::MAX);
    }

    #[test]
    fn hbor_round_trip_covers_both_byte_total_arms() {
        for load in [
            ShardLoad::ZERO,
            ShardLoad::ZERO.advance(1, compute(1), Some(0)),
            ShardLoad::ZERO.advance(u64::MAX, compute(u64::MAX), Some(u64::MAX)),
        ] {
            let bytes = hbor_to_vec(&load).unwrap();
            assert_eq!(hbor_from_slice::<ShardLoad>(&bytes).unwrap(), load);
        }
    }
}
