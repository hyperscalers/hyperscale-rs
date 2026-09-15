//! Genesis balance generation for cluster setup.
//!
//! Generates TOML configuration for funding spammer accounts at genesis.

use std::fmt::Write;

use hex::encode as hex_encode;
use hyperscale_types::PrincipalAddr;

use crate::accounts::{AccountPool, AccountPoolError};

/// Generate TOML-formatted genesis balances for every account in the pool.
///
/// Genesis is single-shard: every account is funded on the ROOT shard and the
/// network partitions them by prefix as it grows. `num_shards` only spreads
/// the generated accounts across the prefixes they will route to post-grow.
///
/// Output format:
/// ```toml
/// [[genesis.accounts]]
/// address = "0f1e2d..."
/// balance = "1000000"
/// ```
///
/// # Errors
///
/// Returns [`GenesisError::AccountGeneration`] if the underlying account pool
/// can't be constructed for the requested shard/account counts.
pub fn generate_genesis_toml(
    num_shards: u64,
    accounts_per_shard: usize,
    balance: u128,
) -> Result<String, GenesisError> {
    let pool = AccountPool::generate(num_shards, accounts_per_shard)?;
    Ok(format_balances_toml(&pool.all_genesis_balances(balance)))
}

/// Format a list of `(address, balance)` pairs as genesis TOML. Every account
/// is funded on the ROOT shard.
///
/// # Panics
///
/// Panics if `writeln!` to a `String` fails, which it cannot.
#[must_use]
pub(crate) fn format_balances_toml(balances: &[(PrincipalAddr, u128)]) -> String {
    let mut output = String::new();

    writeln!(output, "# Generated genesis balances for spammer accounts").unwrap();
    writeln!(
        output,
        "# {} accounts total, all funded on ROOT",
        balances.len()
    )
    .unwrap();
    writeln!(output).unwrap();

    for (address, balance) in balances {
        writeln!(output, "[[genesis.accounts]]").unwrap();
        writeln!(output, "address = \"{}\"", hex_encode(address.to_bytes())).unwrap();
        writeln!(output, "balance = \"{balance}\"").unwrap();
        writeln!(output).unwrap();
    }

    output
}

/// Errors during genesis generation.
#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    /// The underlying account pool could not be generated.
    #[error("Account generation failed: {0}")]
    AccountGeneration(#[from] AccountPoolError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_genesis_toml() {
        let toml = generate_genesis_toml(2, 2, 1_000).unwrap();

        assert!(toml.contains("[[genesis.accounts]]"));
        assert!(toml.contains("balance = \"1000\""));
        assert!(toml.contains("all funded on ROOT"));
        // Every account is funded regardless of which prefix it routes to: 4
        // accounts (2 shards * 2 accounts).
        assert_eq!(toml.matches("[[genesis.accounts]]").count(), 4);
    }
}
