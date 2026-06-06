//! Topology and validator set.
//!
//! - [`awaiting`]: [`AwaitingTopologyBuffer`] parking artifacts whose committee
//!   epoch the beacon hasn't reached.
//! - [`schedule`]: per-epoch [`TopologySchedule`] resolving committees by
//!   weighted timestamp.
//! - [`snapshot`]: read-only [`TopologySnapshot`] view used by subsystems.
//! - [`validator`]: [`ValidatorInfo`] / [`ValidatorSet`].

pub mod awaiting;
pub mod schedule;
pub mod snapshot;
pub mod trie;
pub mod validator;
