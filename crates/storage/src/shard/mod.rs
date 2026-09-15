//! Shard-side storage abstractions: per-shard chain reader/writer,
//! pending-chain overlay, substate plumbing.
//!
//! Sibling [`crate::beacon`] hosts the parallel
//! beacon-chain storage tier — independent traits, independent
//! backend impls, independent lifetime. Cross-cutting modules
//! ([`crate::tree`], [`crate::lock_recover`])
//! live at crate root.

pub mod boundary;
pub mod chain_reader;
pub mod chain_writer;
pub mod committed_provisions;
pub mod dedup_window;
pub mod derived;
pub mod genesis;
pub mod packages;
pub mod pending_chain;
pub mod recovered_state;
pub mod retention;
pub mod store;
pub mod sweep;
pub mod tick_certs;
pub mod tick_chain;
pub mod unresolved;
pub mod vote_registers;
pub mod writes;
