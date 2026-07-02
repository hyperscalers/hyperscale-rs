//! Portable node-behavioral scenarios.
//!
//! A *scenario* is a plain synchronous function over an abstract [`Cluster`]:
//! it drives the cluster from a precondition to a postcondition and asserts the
//! postcondition. The same function body runs on both harnesses — the
//! simulation's logical clock and production's wall-clock QUIC + `RocksDB`
//! cluster — via two thin adaptors that each implement [`Cluster`]. A scenario
//! that passes on one harness and fails on the other is then a real divergence,
//! not a test-authoring artefact.
//!
//! Each module at the crate root is one such scenario (or a small family of
//! them). The harness-agnostic vocabulary they are written against — the
//! [`Cluster`] trait, [`ScenarioConfig`], [`Budget`], and the [`query`],
//! [`wait`], [`tx`], and [`grow_to`] helpers — lives in [`support`]. The two
//! adaptors (`SimCluster`, `ProdCluster`) are supplied by the test crates that
//! depend on this one.

mod support;

mod faults;
mod liveness;
mod multi_vnode;
mod reshape;
mod straddler;
mod transactions;
mod witnesses;

pub use faults::{
    cross_shard_compound_drop_fetch_fallback, cross_shard_exec_cert_drop_fetch_fallback,
    cross_shard_header_fetch_fallback, cross_shard_provisions_drop_fetch_fallback,
    cross_shard_provisions_fetch_with_request_loss,
    cross_shard_provisions_recovers_after_transient_outage,
    cross_shard_transaction_da_fetch_fallback, gossip_drop_engages_fetch_fallback,
    isolated_validator_still_settles, partition_halts_and_heals,
};
pub use liveness::liveness_baseline;
pub use multi_vnode::multi_vnode_progress;
pub use reshape::{
    grow_reaches_four_shard_topology, grow_reaches_two_shard_topology, merge_lifecycle,
    merge_seats_full_keeper_committee, split_lifecycle,
};
pub use straddler::{
    isolate_ec_intake, merge_straddler_atomic, split_straddler_atomic,
    split_straddler_ec_partition_atomic, split_straddler_run, straddler_one_sided_count,
    surviving_sibling_split_seats_full_committees,
};
pub use support::{
    Budget, Cluster, FaultHandle, FaultableCluster, ScenarioConfig, epochs, grow_to, query, tx,
    vote_reshape_threshold, wait,
};
pub use transactions::{cross_shard_tx, livelock_resolves_promptly, single_shard_tx};
pub use witnesses::{
    pool_capacity_caps_registrations, re_registration_of_a_live_validator_is_a_no_op,
    register_validator_pools_a_node, register_without_capacity_is_rejected,
    registered_validator_activates_onto_a_shard, stake_deposit_folds_into_beacon_state,
    stake_withdraw_drops_effective_stake, withdrawal_ejects_a_validator_that_a_deposit_reactivates,
};
