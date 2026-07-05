//! Sans-io reshape sequencers: the split/merge-specific building blocks.
//!
//! These sit above the general state-sync substrate in [`crate::bootstrap`]
//! (`ShardBootstrap`, `SnapSync`) and turn a beacon-attested reshape boundary
//! into a seated child or reformed parent:
//!
//! - [`observer`] — an observer syncs its child span ([`ObserverBootstrap`](observer::ObserverBootstrap))
//!   then follows the parent to its terminal crossing ([`ObserverTail`](observer::ObserverTail));
//! - [`split_flip`] — derive a split child's genesis from the parent's terminal
//!   contribution ([`split_genesis_from_terminal`](split_flip::split_genesis_from_terminal));
//! - [`merge_flip`] — derive a merged parent's genesis from both children's
//!   terminals ([`merge_genesis_from_terminals`](merge_flip::merge_genesis_from_terminals)).
//!
//! Sans-io like the substrate they compose: drivers own transport, pacing, and
//! the store writes. The production supervisor pumps them with async requests;
//! the simulation steps them deterministically — both run this exact sequencing.

pub mod adopt;
pub mod merge_flip;
pub mod observer;
pub mod orchestrator;
pub mod split_flip;
pub mod view;

use hyperscale_storage::RecoveredState;
use hyperscale_types::Block;

/// A reshape duty's in-flight store, held by the driver between the
/// orchestrator's `OpenStore` and `Seat` requests.
///
/// Bundles the open store the duty imports and adopts into, the recovered
/// state its seated vnodes boot from (rebuilt at the adopt), and the derived
/// genesis the seat installs.
pub struct PreparedStore<S> {
    /// The opened store the duty imports and adopts into.
    pub storage: S,
    /// The recovered state the seat boots from, rebuilt at the adopt.
    pub recovered: RecoveredState,
    /// The derived genesis, set at the adopt, installed at the seat.
    pub genesis: Option<Block>,
}
