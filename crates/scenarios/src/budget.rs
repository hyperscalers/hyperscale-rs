//! Scenario wait budgets, denominated in epochs.

/// A wait budget, measured in beacon epochs.
///
/// A scenario never spells a wall-clock `Duration`: a wait is "N epochs for the
/// split to admit". Each adaptor multiplies a `Budget` by its own epoch length
/// (the sim's logical `EPOCH_MS`, production's wall-clock `EPOCH_MS` under the
/// `ci` feature), so one budget is faithful on both clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Budget(pub u32);

/// A [`Budget`] of `n` epochs.
#[must_use]
pub const fn epochs(n: u32) -> Budget {
    Budget(n)
}
