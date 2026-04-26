//! Transaction types for consensus.
//!
//! - [`routable`]: [`RoutableTransaction`] (the wrapper + manual SBOR).
//! - [`status`]: [`TransactionDecision`], [`TransactionStatus`], [`TransactionError`],
//!   and the RPC-string parser.
//! - [`constructors`]: `routable_from_*` constructors that derive read/write sets
//!   from notarized Radix transactions.
//! - [`manifest_analysis`]: read/write set extraction from Radix manifest instructions
//!   (private helpers used by [`constructors`]).
//! - [`notarize`]: helpers for signing and notarizing a `TransactionManifestV1`.

pub mod constructors;
mod manifest_analysis;
pub mod notarize;
pub mod routable;
pub mod status;
