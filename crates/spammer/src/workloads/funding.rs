//! Funding workload for creating accounts beyond the genesis limit.
//!
//! Generates transfer transactions from genesis-funded accounts to new accounts
//! that couldn't be included in genesis due to engine limits.

use crate::accounts::{AccountPool, FundingOp};
use crate::validity::{ValidityClock, wall_clock};
use hyperscale_types::{
    RoutableTransaction, ShardGroupId, routable_from_notarized_v1, sign_and_notarize,
};
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
    validity_clock: ValidityClock,
}

impl FundingWorkload {
    /// Create a new funding workload.
    #[must_use]
    pub fn new(network: NetworkDefinition) -> Self {
        Self {
            network,
            fee: Decimal::from(10u32),
            validity_clock: wall_clock(),
        }
    }

    /// Override the source of validity ranges. The simulator uses this to
    /// anchor windows on its simulated clock instead of the wall clock.
    #[must_use]
    pub fn with_validity_clock(mut self, clock: ValidityClock) -> Self {
        self.validity_clock = clock;
        self
    }

    /// The per-transaction fee used by funding transactions.
    ///
    /// Callers need this to compute the extra genesis balance for funder accounts.
    #[must_use]
    pub const fn fee(&self) -> Decimal {
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
            let Some(shard_accounts) = accounts.accounts_for_shard(op.source_shard) else {
                failed += 1;
                continue;
            };

            let source = &shard_accounts[op.source_idx];

            let manifest = ManifestBuilder::new()
                .lock_fee(source.address, self.fee)
                .withdraw_from_account(source.address, XRD, op.amount)
                .try_deposit_entire_worktop_or_abort(op.dest_address, None)
                .build();

            let nonce = source.next_nonce();

            let notarized = match sign_and_notarize(
                manifest,
                &self.network,
                u32::try_from(nonce).unwrap_or(u32::MAX),
                &source.keypair,
            ) {
                Ok(n) => n,
                Err(e) => {
                    warn!(error = ?e, "Failed to sign funding transaction");
                    failed += 1;
                    continue;
                }
            };

            let tx: RoutableTransaction =
                match routable_from_notarized_v1(notarized, (self.validity_clock)()) {
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
