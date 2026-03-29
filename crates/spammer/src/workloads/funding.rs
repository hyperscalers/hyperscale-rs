//! Funding workload for creating accounts beyond the genesis limit.
//!
//! Generates transfer transactions from genesis-funded accounts to new accounts
//! that couldn't be included in genesis due to engine limits.

use crate::accounts::{AccountPool, FundingOp};
use hyperscale_types::{sign_and_notarize, RoutableTransaction, ShardGroupId};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_transactions::builder::ManifestBuilder;
use std::collections::HashMap;
use tracing::{info, warn};

/// Generates funding transactions from a runtime funding plan.
pub struct FundingWorkload {
    network: NetworkDefinition,
    fee: Decimal,
}

impl FundingWorkload {
    /// Create a new funding workload.
    pub fn new(network: NetworkDefinition) -> Self {
        Self {
            network,
            fee: Decimal::from(10u32),
        }
    }

    /// The per-transaction fee used by funding transactions.
    ///
    /// Callers need this to compute the extra genesis balance for funder accounts.
    pub fn fee(&self) -> Decimal {
        self.fee
    }

    /// Generate all funding transactions from the plan.
    ///
    /// Returns transactions grouped by target shard (for submission routing).
    /// Each transaction withdraws from a genesis account and deposits to an
    /// unfunded account. Nonces are consumed on the source accounts via
    /// `next_nonce()`, so the main workload will naturally pick up where
    /// funding left off.
    pub fn generate_funding_transactions(
        &self,
        accounts: &AccountPool,
        plan: &[FundingOp],
    ) -> HashMap<ShardGroupId, Vec<RoutableTransaction>> {
        let mut by_shard: HashMap<ShardGroupId, Vec<RoutableTransaction>> = HashMap::new();
        let mut generated = 0u64;
        let mut failed = 0u64;

        for op in plan {
            let shard_accounts = match accounts.accounts_for_shard(op.source_shard) {
                Some(a) => a,
                None => {
                    failed += 1;
                    continue;
                }
            };

            let source = &shard_accounts[op.source_idx];

            let manifest = ManifestBuilder::new()
                .lock_fee(source.address, self.fee)
                .withdraw_from_account(source.address, XRD, op.amount)
                .try_deposit_entire_worktop_or_abort(op.dest_address, None)
                .build();

            let nonce = source.next_nonce();

            let notarized =
                match sign_and_notarize(manifest, &self.network, nonce as u32, &source.keypair) {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(error = ?e, "Failed to sign funding transaction");
                        failed += 1;
                        continue;
                    }
                };

            let tx: RoutableTransaction = match notarized.try_into() {
                Ok(t) => t,
                Err(e) => {
                    warn!(error = ?e, "Failed to convert funding transaction");
                    failed += 1;
                    continue;
                }
            };

            by_shard.entry(op.source_shard).or_default().push(tx);
            generated += 1;
        }

        info!(generated, failed, "Generated funding transactions");
        by_shard
    }
}
