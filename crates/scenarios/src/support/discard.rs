//! Discarding a run whose seed did not produce the setup a scenario needs.
//!
//! A scenario tuned against one seed often needs that seed to draw a
//! particular shape — a committee landing on a retained host, a fault rule
//! actually firing. Under a sweep of other seeds, a draw without that shape
//! says nothing about the protocol, so the run is discarded rather than
//! failed. A sweep classifies a panic carrying [`DISCARD`] as a discard.

/// Prefix of the panic [`assume`] and [`discard`] raise.
pub const DISCARD: &str = "SIM-DISCARD:";

/// Discard the run, rather than fail it, when the seed did not produce what
/// the scenario needs.
///
/// For a setup precondition, or evidence that the path under test was
/// reached; never for the property under test itself.
///
/// # Panics
///
/// Panics with [`DISCARD`] when `condition` does not hold.
pub fn assume(condition: bool, what: &str) {
    assert!(condition, "{DISCARD} {what}");
}

/// Discard the run unconditionally: [`assume`] for a value the seed did not
/// produce.
///
/// # Panics
///
/// Always, with [`DISCARD`].
pub fn discard(what: &str) -> ! {
    panic!("{DISCARD} {what}");
}
