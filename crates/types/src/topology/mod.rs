//! Topology and validator set.
//!
//! - [`awaiting`]: [`AwaitingTopologyBuffer`] parking artifacts whose committee
//!   epoch the beacon hasn't reached.
//! - [`schedule`]: per-epoch [`TopologySchedule`] resolving committees by
//!   weighted timestamp.
//! - [`shard_prefix`]: the JMT root path a shard's state tree is rooted at.
//! - [`snapshot`]: read-only [`TopologySnapshot`] view used by subsystems.
//! - [`trie`]: the active shard partition as a binary [`trie::ShardTrie`].
//! - [`validator`]: [`ValidatorInfo`] / [`ValidatorSet`].

pub mod awaiting;
pub mod schedule;
pub mod shard_prefix;
pub mod snapshot;
pub mod trie;
pub mod validator;
