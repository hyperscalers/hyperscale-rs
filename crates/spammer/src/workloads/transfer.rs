//! XRD transfer workload generator.

use crate::accounts::{AccountPool, FundedAccount, SelectionMode};
use crate::workloads::WorkloadGenerator;
use hyperscale_types::{sign_and_notarize, RoutableTransaction, ShardGroupId};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_transactions::builder::ManifestBuilder;
use rand::{Rng, RngCore};
use tracing::warn;

/// Generates XRD transfer transactions.
pub struct TransferWorkload {
    /// Ratio of cross-shard transactions (0.0 to 1.0).
    cross_shard_ratio: f64,

    /// Account selection mode.
    selection_mode: SelectionMode,

    /// Transfer amount per transaction.
    amount: Decimal,

    /// Network definition for transaction signing.
    network: NetworkDefinition,
}

impl TransferWorkload {
    /// Create a new transfer workload generator.
    pub fn new(network: NetworkDefinition) -> Self {
        Self {
            cross_shard_ratio: 0.3,
            selection_mode: SelectionMode::default(),
            amount: Decimal::from(100u32),
            network,
        }
    }

    /// Set the cross-shard transaction ratio (0.0 to 1.0).
    pub fn with_cross_shard_ratio(mut self, ratio: f64) -> Self {
        self.cross_shard_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Set the account selection mode.
    pub fn with_selection_mode(mut self, mode: SelectionMode) -> Self {
        self.selection_mode = mode;
        self
    }

    /// Set the transfer amount.
    pub fn with_amount(mut self, amount: Decimal) -> Self {
        self.amount = amount;
        self
    }

    /// Generate a same-shard transfer.
    fn generate_same_shard_inner<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        rng: &mut R,
    ) -> Option<RoutableTransaction> {
        let shard = ShardGroupId(rng.gen_range(0..accounts.num_shards()));
        let (from, to) = accounts.pair_for_shard(shard, rng, self.selection_mode)?;
        self.build_transfer(from, to)
    }

    /// Generate a cross-shard transfer.
    fn generate_cross_shard_inner<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        rng: &mut R,
    ) -> Option<RoutableTransaction> {
        let (from, to) = accounts.cross_shard_pair(rng, self.selection_mode)?;
        self.build_transfer(from, to)
    }

    /// Build a transfer transaction from one account to another.
    fn build_transfer(
        &self,
        from: &FundedAccount,
        to: &FundedAccount,
    ) -> Option<RoutableTransaction> {
        // Build manifest: withdraw from sender, deposit to receiver
        let manifest = ManifestBuilder::new()
            .lock_fee(from.address, Decimal::from(10u32))
            .withdraw_from_account(from.address, XRD, self.amount)
            .try_deposit_entire_worktop_or_abort(to.address, None)
            .build();

        // Get and increment nonce atomically
        let nonce = from.next_nonce();

        // Sign and notarize
        let notarized =
            match sign_and_notarize(manifest, &self.network, nonce as u32, &from.keypair) {
                Ok(n) => n,
                Err(e) => {
                    warn!(error = ?e, "Failed to sign transaction");
                    return None;
                }
            };

        // Convert to RoutableTransaction
        let tx: RoutableTransaction = match notarized.try_into() {
            Ok(t) => t,
            Err(e) => {
                warn!(error = ?e, "Failed to convert to RoutableTransaction");
                return None;
            }
        };

        Some(tx)
    }

    /// Generate one transaction (internal helper for trait impl).
    fn generate_one_inner<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        rng: &mut R,
    ) -> Option<RoutableTransaction> {
        let is_cross_shard =
            accounts.num_shards() >= 2 && rng.gen::<f64>() < self.cross_shard_ratio;

        if is_cross_shard {
            self.generate_cross_shard_inner(accounts, rng)
        } else {
            self.generate_same_shard_inner(accounts, rng)
        }
    }

    /// Generate a same-shard transfer for a specific shard.
    fn generate_same_shard_for<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        target_shard: ShardGroupId,
        rng: &mut R,
    ) -> Option<RoutableTransaction> {
        let shard_accounts = accounts.accounts_for_shard(target_shard)?;

        if shard_accounts.len() < 2 {
            return None;
        }

        // Use AccountPool's selection for stateful modes (NoContention, RoundRobin)
        // which use atomic counters to ensure proper distribution/no conflicts.
        let (from, to) = accounts.pair_for_shard(target_shard, rng, self.selection_mode)?;

        self.build_transfer(from, to)
    }

    /// Generate a cross-shard transfer that involves a specific shard.
    ///
    /// The transaction will have the target shard as one of the involved shards.
    fn generate_cross_shard_for<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        target_shard: ShardGroupId,
        rng: &mut R,
    ) -> Option<RoutableTransaction> {
        if accounts.num_shards() < 2 {
            return None;
        }

        // Pick another shard randomly (different from target)
        let mut other_shard = ShardGroupId(rng.gen_range(0..accounts.num_shards()));
        while other_shard == target_shard {
            other_shard = ShardGroupId(rng.gen_range(0..accounts.num_shards()));
        }

        // Randomly decide if target shard is sender or receiver
        let target_is_sender = rng.gen_bool(0.5);

        // Use AccountPool's selection for stateful modes (NoContention, RoundRobin)
        let (from, to) = if target_is_sender {
            accounts.cross_shard_pair_for(target_shard, other_shard, rng, self.selection_mode)?
        } else {
            accounts.cross_shard_pair_for(other_shard, target_shard, rng, self.selection_mode)?
        };

        self.build_transfer(from, to)
    }

    /// Generate a transaction that involves a specific shard.
    ///
    /// This generates either a same-shard transaction within the target shard,
    /// or a cross-shard transaction where the target shard is one of the involved shards.
    pub fn generate_for_shard<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        target_shard: ShardGroupId,
        rng: &mut R,
    ) -> Option<RoutableTransaction> {
        let is_cross_shard =
            accounts.num_shards() >= 2 && rng.gen::<f64>() < self.cross_shard_ratio;

        if is_cross_shard {
            self.generate_cross_shard_for(accounts, target_shard, rng)
        } else {
            self.generate_same_shard_for(accounts, target_shard, rng)
        }
    }

    /// Generate a batch of transactions for a specific shard.
    ///
    /// All transactions will involve the target shard (either as the only shard
    /// for same-shard transactions, or as one of the involved shards for cross-shard).
    pub fn generate_batch_for_shard<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        target_shard: ShardGroupId,
        count: usize,
        rng: &mut R,
    ) -> Vec<RoutableTransaction> {
        (0..count)
            .filter_map(|_| self.generate_for_shard(accounts, target_shard, rng))
            .collect()
    }
}

impl WorkloadGenerator for TransferWorkload {
    fn generate_one(
        &self,
        accounts: &AccountPool,
        rng: &mut dyn RngCore,
    ) -> Option<RoutableTransaction> {
        // Wrap the dyn RngCore to get Rng trait
        self.generate_one_inner(accounts, rng)
    }

    fn generate_batch(
        &self,
        accounts: &AccountPool,
        count: usize,
        rng: &mut dyn RngCore,
    ) -> Vec<RoutableTransaction> {
        (0..count)
            .filter_map(|_| self.generate_one_inner(accounts, rng))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::shard_for_node;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_generate_same_shard_transfer() {
        let accounts = AccountPool::generate(2, 10).unwrap();
        let workload =
            TransferWorkload::new(NetworkDefinition::simulator()).with_cross_shard_ratio(0.0); // All same-shard
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let tx = workload.generate_one(&accounts, &mut rng);
        assert!(tx.is_some(), "Should generate a transaction");

        let tx = tx.unwrap();
        assert!(
            !tx.declared_writes.is_empty(),
            "Transaction should have declared writes"
        );
    }

    #[test]
    fn test_generate_cross_shard_transfer() {
        let accounts = AccountPool::generate(2, 10).unwrap();
        let workload =
            TransferWorkload::new(NetworkDefinition::simulator()).with_cross_shard_ratio(1.0); // All cross-shard
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let tx = workload.generate_one(&accounts, &mut rng);
        assert!(tx.is_some(), "Should generate a transaction");

        let tx = tx.unwrap();
        assert!(
            tx.is_cross_shard(2),
            "Transaction should be cross-shard for 2 shards"
        );
    }

    #[test]
    fn test_generate_for_shard_same_shard() {
        let num_shards = 4u64;
        let accounts = AccountPool::generate(num_shards, 10).unwrap();
        let workload =
            TransferWorkload::new(NetworkDefinition::simulator()).with_cross_shard_ratio(0.0); // All same-shard
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Generate transactions targeting shard 2
        let target_shard = ShardGroupId(2);
        for _ in 0..20 {
            let tx = workload
                .generate_for_shard(&accounts, target_shard, &mut rng)
                .expect("Should generate a transaction");

            // All writes should be on the target shard
            for write in &tx.declared_writes {
                let write_shard = shard_for_node(write, num_shards);
                assert_eq!(
                    write_shard, target_shard,
                    "Same-shard transaction should only write to target shard"
                );
            }
        }
    }

    #[test]
    fn test_generate_for_shard_cross_shard() {
        let num_shards = 4u64;
        let accounts = AccountPool::generate(num_shards, 10).unwrap();
        let workload =
            TransferWorkload::new(NetworkDefinition::simulator()).with_cross_shard_ratio(1.0); // All cross-shard
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Generate transactions targeting shard 1
        let target_shard = ShardGroupId(1);
        for _ in 0..20 {
            let tx = workload
                .generate_for_shard(&accounts, target_shard, &mut rng)
                .expect("Should generate a transaction");

            // Transaction should be cross-shard
            assert!(
                tx.is_cross_shard(num_shards),
                "Should be a cross-shard transaction"
            );

            // At least one write should be on the target shard
            let shards_written: std::collections::HashSet<_> = tx
                .declared_writes
                .iter()
                .map(|w| shard_for_node(w, num_shards))
                .collect();
            assert!(
                shards_written.contains(&target_shard),
                "Cross-shard transaction should involve target shard"
            );
        }
    }

    #[test]
    fn test_generate_batch_for_shard() {
        let num_shards = 3u64;
        let accounts = AccountPool::generate(num_shards, 10).unwrap();
        let workload =
            TransferWorkload::new(NetworkDefinition::simulator()).with_cross_shard_ratio(0.5);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Generate a batch targeting shard 0
        let target_shard = ShardGroupId(0);
        let batch = workload.generate_batch_for_shard(&accounts, target_shard, 50, &mut rng);

        assert!(!batch.is_empty(), "Should generate transactions");

        // All transactions should involve the target shard
        for tx in &batch {
            let shards_involved: std::collections::HashSet<_> = tx
                .declared_writes
                .iter()
                .chain(tx.declared_reads.iter())
                .map(|n| shard_for_node(n, num_shards))
                .collect();

            assert!(
                shards_involved.contains(&target_shard),
                "All transactions should involve the target shard"
            );
        }
    }
}
