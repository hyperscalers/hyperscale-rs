//! Cross-shard state provisioning types.
//!
//! - [`limits`]: per-provision wire-limit constants.
//! - [`proof`]: opaque merkle multiproof bytes.
//! - [`provision`]: one transaction's part ([`Provision`]) with its own proof.
//! - [`substate`]: pre-computed-key substate entries and per-tx provision wrappers.

pub mod limits;
pub mod proof;
pub mod provision;
pub mod substate;
