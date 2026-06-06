//! Topology and validator set.
//!
//! - [`awaiting`]: [`AwaitingTopologyBuffer`] parking artifacts whose committee
//!   epoch the beacon hasn't reached.
//! - [`network_root`]: combine per-shard subtree roots into the network state root.
//! - [`schedule`]: per-epoch [`TopologySchedule`] resolving committees by
//!   weighted timestamp.
//! - [`snapshot`]: read-only [`TopologySnapshot`] view used by subsystems.
//! - [`trie`]: the active shard partition as a binary [`trie::ShardTrie`].
//! - [`validator`]: [`ValidatorInfo`] / [`ValidatorSet`].

pub mod awaiting;
pub mod network_root;
pub mod schedule;
pub mod snapshot;
pub mod trie;
pub mod validator;
