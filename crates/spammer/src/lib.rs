//! Hyperscale Transaction Spammer
//!
//! A library and CLI tool for generating and submitting transactions to a Hyperscale network.
//!
//! # Modules
//!
//! - [`accounts`]: Account management (FundedAccount, AccountPool)
//! - [`workloads`]: Transaction workload generation (WorkloadGenerator trait)
//! - [`client`]: RPC client for transaction submission
//! - [`runner`]: Spammer orchestrator
//! - [`genesis`]: Genesis balance generation for cluster setup
//! - [`config`]: Configuration types

pub mod accounts;
pub mod client;
pub mod config;
pub mod genesis;
mod latency;
pub mod runner;
pub mod workloads;

pub use accounts::{
    AccountPool, AccountPoolError, AccountUsageStats, FundedAccount, SelectionMode,
};
pub use client::RpcClient;
pub use config::SpammerConfig;
pub use runner::Spammer;
pub use workloads::{TransferWorkload, WorkloadGenerator};
