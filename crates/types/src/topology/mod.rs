//! Topology, validator set, epoch, and consensus configuration.
//!
//! - [`validator`]: [`ValidatorInfo`] / [`ValidatorSet`].
//! - [`epoch`]: [`EpochId`], [`EpochConfig`], [`ValidatorShardState`].
//! - [`consensus_config`]: [`GlobalConsensusConfig`], [`ShardCommitteeConfig`],
//!   [`ValidatorRating`], [`GlobalValidatorInfo`].
//! - [`snapshot`]: read-only [`TopologySnapshot`] view used by subsystems.

pub mod consensus_config;
pub mod epoch;
pub mod snapshot;
pub mod validator;
