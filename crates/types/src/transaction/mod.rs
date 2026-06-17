//! Transaction types for consensus.
//!
//! - [`routable`]: [`RoutableTransaction`] (the network-routing wrapper around a Radix `NotarizedTransactionV1`/`V2`).
//! - [`status`]: [`TransactionDecision`], [`TransactionStatus`], [`TransactionError`],
//!   and the RPC-string parser.
//! - [`constructors`]: `routable_from_*` constructors that derive read/write sets
//!   from notarized Radix transactions.
//! - [`manifest_analysis`]: read/write set extraction from Radix manifest instructions
//!   (private helpers used by [`constructors`]).
//! - [`notarize`]: helpers for signing and notarizing a `TransactionManifestV1`.
//! - [`limits`]: per-transaction wire-limit constants.
//! - [`system_action`]: beacon actions carried in a transaction's plaintext message.

pub mod constructors;
pub mod limits;
mod manifest_analysis;
pub mod notarize;
pub mod routable;
pub mod status;
pub mod system_action;
