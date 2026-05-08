//! Cross-shard state provisioning types.
//!
//! - [`entry`]: per-transaction state entries within a provision.
//! - [`limits`]: per-provision wire-limit constants.
//! - [`proof`]: opaque merkle multiproof bytes.
//! - [`provisions`]: per-block bundle ([`Provisions`]) joining the proof with all tx entries.
//! - [`substate`]: pre-computed-key substate entries and per-tx provision wrappers.

pub mod entry;
pub mod limits;
pub mod proof;
pub mod provisions;
pub mod substate;
