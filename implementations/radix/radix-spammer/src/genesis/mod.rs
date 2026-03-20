//! Genesis balance generation for cluster setup.
//!
//! Generates TOML configuration for funding spammer accounts at genesis.

use crate::accounts::AccountPool;
use hyperscale_types::ShardGroupId;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::prelude::AddressBech32Encoder;
use radix_common::types::ComponentAddress;
use std::fmt::Write;

/// Generate TOML-formatted genesis balances for all accounts in the pool.
///
/// Output format:
/// ```toml
/// [[genesis.xrd_balances]]
/// address = "account_sim1..."
/// balance = "1000000"
/// ```
pub fn generate_genesis_toml(
    num_shards: u64,
    accounts_per_shard: usize,
    balance: Decimal,
) -> Result<String, GenesisError> {
    let pool = AccountPool::generate(num_shards, accounts_per_shard)?;
    let balances = pool.all_genesis_balances(balance);

    Ok(format_balances_toml(&balances, None))
}

/// Generate TOML-formatted genesis balances for accounts on a specific shard only.
///
/// This is useful for large clusters where including all accounts in every
/// validator's config would cause memory issues during genesis.
pub fn generate_genesis_toml_for_shard(
    num_shards: u64,
    accounts_per_shard: usize,
    balance: Decimal,
    shard: u64,
) -> Result<String, GenesisError> {
    let pool = AccountPool::generate(num_shards, accounts_per_shard)?;
    let shard_id = ShardGroupId(shard);
    let balances = pool.genesis_balances_for_shard(shard_id, balance);

    Ok(format_balances_toml(&balances, Some(shard)))
}

/// Format a list of (address, balance) pairs as TOML.
///
/// If `shard` is provided, adds a comment indicating which shard these accounts belong to.
pub fn format_balances_toml(
    balances: &[(ComponentAddress, Decimal)],
    shard: Option<u64>,
) -> String {
    let mut output = String::new();
    let encoder = AddressBech32Encoder::new(&NetworkDefinition::simulator());

    writeln!(output, "# Generated genesis balances for spammer accounts").unwrap();
    if let Some(shard_id) = shard {
        writeln!(
            output,
            "# Shard {} only: {} accounts",
            shard_id,
            balances.len()
        )
        .unwrap();
    } else {
        writeln!(output, "# {} accounts total (all shards)", balances.len()).unwrap();
    }
    writeln!(output).unwrap();

    for (address, balance) in balances {
        let address_str = encoder.encode(address.as_node_id().as_bytes()).unwrap();
        writeln!(output, "[[genesis.xrd_balances]]").unwrap();
        writeln!(output, "address = \"{}\"", address_str).unwrap();
        writeln!(output, "balance = \"{}\"", balance).unwrap();
        writeln!(output).unwrap();
    }

    output
}

/// Errors during genesis generation.
#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    #[error("Account generation failed: {0}")]
    AccountGeneration(#[from] crate::accounts::AccountPoolError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_genesis_toml() {
        let toml = generate_genesis_toml(2, 2, Decimal::from(1000u32)).unwrap();

        assert!(toml.contains("[[genesis.xrd_balances]]"));
        assert!(toml.contains("address = \"account_"));
        assert!(toml.contains("balance = \"1000\""));
        assert!(toml.contains("all shards"));
        // Should have 4 accounts (2 shards * 2 accounts)
        assert_eq!(toml.matches("[[genesis.xrd_balances]]").count(), 4);
    }

    #[test]
    fn test_generate_genesis_toml_for_shard() {
        let toml = generate_genesis_toml_for_shard(2, 5, Decimal::from(1000u32), 0).unwrap();

        assert!(toml.contains("[[genesis.xrd_balances]]"));
        assert!(toml.contains("address = \"account_"));
        assert!(toml.contains("balance = \"1000\""));
        assert!(toml.contains("Shard 0 only"));
        // Should have 5 accounts (only shard 0)
        assert_eq!(toml.matches("[[genesis.xrd_balances]]").count(), 5);

        // Generate for shard 1 and verify it's also 5 accounts
        let toml1 = generate_genesis_toml_for_shard(2, 5, Decimal::from(1000u32), 1).unwrap();
        assert!(toml1.contains("Shard 1 only"));
        assert_eq!(toml1.matches("[[genesis.xrd_balances]]").count(), 5);
    }
}
