//! Reservations that legs no tick has resolved still hold.
//!
//! A cross-shard leg's reservation is engaged the moment its block
//! commits and released only when its tick's fate does, and in between it
//! is invisible: the settled state a later tick reads still shows the
//! whole balance, because nothing a tick has not resolved may be read.
//! Judging a second withdrawal against that balance is what lets one
//! vault fund two.
//!
//! The amount is the declared one. A reservation says statically how much
//! feasibility is judged against — that is the whole reason the mode
//! carries a number — so the hold needs nothing from the leg's execution
//! and is known from the moment it is dispatched.
//!
//! These are debits a leg was granted. The ceiling a committed
//! transaction holds for its fee is another kind of promise, kept as
//! committed state and read beside these: a reservation settles or
//! releases and the cell must cover it, where a fee hold is a floor under
//! everything else the cell is asked for.
//!
//! A third kind is a credit rather than a debit: what a tick's member
//! credited a cell while nothing committed holds a later tick's
//! settlement behind its own. A later tick reads the credit and may not
//! spend it.

use std::collections::BTreeMap;

use crate::{SubstateKey, TxHash};

/// What each unresolved leg holds against each amount cell.
///
/// Shaped as the kernel's `Base::holds` reads it, keyed by transaction so
/// a leg judging its own reservation finds the one it took rather than
/// counting it twice.
pub type ProvisionalHolds = BTreeMap<SubstateKey, BTreeMap<TxHash, u128>>;

/// What each amount cell carries of credits no committed order settles
/// ahead of a later tick, summed.
///
/// A reclaim is seated by no line of its block, so its tick's half is
/// owed only where it was composed and a later tick's half can settle
/// first. Every later tick is judged as if the credit were not there
/// until the base carries it.
pub type UnsettledCredits = BTreeMap<SubstateKey, u128>;
