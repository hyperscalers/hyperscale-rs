//! Cross-shard state provisioning types.
//!
//! - [`substate`]: pre-computed-key substate entries and per-tx provision wrappers.
//! - [`tx_entries`]: per-transaction state entries within a provision.
//! - [`proof`]: opaque merkle multiproof bytes.
//! - [`batch`]: per-block bundle ([`Provisions`]) joining the proof with all tx entries.
//! - [`limits`]: per-provision wire-limit constants.

pub mod batch;
pub mod limits;
pub mod proof;
pub mod substate;
pub mod tx_entries;
