//! Beacon-side storage abstractions: process-level chain reader/writer
//! for the global beacon chain.
//!
//! Sibling [`crate::shard`](crate::shard) hosts the per-shard tier;
//! beacon traits live alongside but are independent — backends impl
//! both (or just one) as needed. The process holds one
//! `Arc<impl BeaconStorage>` shared across every vnode's
//! `BeaconCoordinator`.

pub mod chain_reader;
pub mod chain_writer;
pub mod ratify_registers;
pub mod storage;
