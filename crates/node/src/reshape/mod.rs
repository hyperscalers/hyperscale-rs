//! Sans-io reshape sequencers: the split/merge-specific building blocks.
//!
//! These sit above the general state-sync substrate in [`crate::bootstrap`]
//! (`ShardBootstrap`, `SnapSync`) and turn a beacon-attested reshape boundary
//! into a seated child or reformed parent:
//!
//! - `orchestrator` — the per-host [`ReshapeOrchestrator`] that discovers and
//!   sequences every duty, and the io it exchanges with its adapter;
//! - `observer` — an observer syncs its child span (`ObserverBootstrap`)
//!   then follows the parent to its terminal crossing (`ObserverTail`);
//! - `split_flip` — derive a split child's genesis from the parent's terminal
//!   contribution;
//! - `merge_flip` — derive a merged parent's genesis from both children's
//!   terminals;
//! - `screen` — the peer verdict on a reshape fetch's answer, judged against
//!   the request alone, which both drivers hand the transport
//!   ([`block_verdict`], [`headers_verdict`]);
//! - `adopt` — the one adoption gate both drivers call
//!   ([`adopt_prepared_store`]);
//! - `prepared` — the stores duties prepare, and the one place their
//!   lifecycle from open to seat is written ([`PreparedStores`]).
//!
//! Sans-io like the substrate they compose: drivers own transport, pacing, and
//! the store writes. The production supervisor pumps them with async requests;
//! the simulation steps them deterministically — both run this exact sequencing.

mod adopt;
mod genesis;
mod merge_flip;
mod observer;
mod orchestrator;
mod prepared;
mod screen;
mod split_flip;
mod view;

pub use adopt::adopt_prepared_store;
pub use genesis::DerivedGenesis;
pub use observer::ready_notification;
pub use orchestrator::{
    AdoptKind, FetchKind, FetchedKind, OverRunning, ReshapeEvent, ReshapeOrchestrator,
    ReshapeRequest, Ticket, seed_gate,
};
pub use prepared::{PreparedStores, ReshapeCompletion, Seating};
pub use screen::{block_verdict, headers_verdict};
pub use view::ReshapeView;
