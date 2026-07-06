//! The HotStuff-2 safe-vote registers.

use crate::Round;

/// Snapshot of a validator's two monotone safe-vote registers.
///
/// `locked_round` is the highest QC round the validator has voted to
/// extend; `last_voted_round` is the highest round it has voted or
/// timed out in. HotStuff-2's one-vote-per-round and lock-monotonicity
/// rules are guards over these values, so both only ever ratchet upward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SafeVoteRegisters {
    /// Highest QC round the validator has voted to extend.
    pub locked_round: Round,
    /// Highest round the validator has voted or timed out in.
    pub last_voted_round: Round,
}

impl SafeVoteRegisters {
    /// Field-wise maximum — the merge rule for register snapshots.
    /// Registers only ratchet, so the max of two snapshots is the most
    /// restrictive position either represents.
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        Self {
            locked_round: self.locked_round.max(other.locked_round),
            last_voted_round: self.last_voted_round.max(other.last_voted_round),
        }
    }
}
