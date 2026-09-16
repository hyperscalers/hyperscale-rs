//! Native-resource transfer workload generator.

use std::sync::atomic::{AtomicU64, Ordering};

use hyperscale_transactions::{Ceilings, Client, Terms};
use hyperscale_types::{NetworkDefinition, NetworkId, ShardId, Transaction};
use rand::{Rng, RngExt};

use crate::accounts::{AccountPool, FundedAccount, SelectionMode};
use crate::validity::{ValidityClock, wall_clock};
use crate::workloads::WorkloadGenerator;

/// What a transfer moves when the caller sets no amount.
pub const DEFAULT_TRANSFER_AMOUNT: u128 = 100;

/// The fee ceiling every generated transfer signs. Placeholder pricing,
/// well above what a transfer draws.
pub const TRANSFER_MAX_FEE: u128 = 1_000;

/// Generates transfer transactions.
pub struct TransferWorkload {
    /// Ratio of cross-shard transactions (0.0 to 1.0).
    cross_shard_ratio: f64,

    /// Account selection mode.
    selection_mode: SelectionMode,

    /// Transfer amount per transaction.
    amount: u128,

    /// Round-robin counter for shard selection in `NoContention` mode.
    /// Ensures even distribution across shards to prevent one shard's
    /// account counter from advancing faster than others.
    shard_counter: AtomicU64,

    /// Source of validity ranges. Defaults to wall clock; the simulator
    /// substitutes a simulated-clock anchor.
    validity_clock: ValidityClock,

    /// The world every built transfer resolves its accounts in.
    client: Client,
}

impl Default for TransferWorkload {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferWorkload {
    /// Create a new transfer workload generator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cross_shard_ratio: 0.3,
            selection_mode: SelectionMode::default(),
            amount: DEFAULT_TRANSFER_AMOUNT,
            shard_counter: AtomicU64::new(0),
            validity_clock: wall_clock(),
            client: Client::genesis(NetworkId::from(&NetworkDefinition::simulator())),
        }
    }

    /// Override the source of validity ranges. The simulator uses this to
    /// anchor windows on its simulated clock instead of the wall clock.
    #[must_use]
    pub fn with_validity_clock(mut self, clock: ValidityClock) -> Self {
        self.validity_clock = clock;
        self
    }

    /// Set the cross-shard transaction ratio (0.0 to 1.0).
    #[must_use]
    pub const fn with_cross_shard_ratio(mut self, ratio: f64) -> Self {
        self.cross_shard_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Set the account selection mode.
    #[must_use]
    pub const fn with_selection_mode(mut self, mode: SelectionMode) -> Self {
        self.selection_mode = mode;
        self
    }

    /// Set the transfer amount.
    #[must_use]
    pub const fn with_amount(mut self, amount: u128) -> Self {
        self.amount = amount;
        self
    }

    /// Generate a same-shard transfer.
    fn generate_same_shard_inner<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        rng: &mut R,
    ) -> Option<Transaction> {
        // For NoContention mode, use round-robin shard selection to ensure even
        // distribution. Random selection can cause one shard's account counter
        // to advance much faster than others, leading to account reuse before
        // transactions complete.
        let depth = accounts.num_shards().trailing_zeros();
        let shard = if self.selection_mode == SelectionMode::NoContention {
            let counter = self.shard_counter.fetch_add(1, Ordering::Relaxed);
            ShardId::leaf(depth, counter % accounts.num_shards())
        } else {
            ShardId::leaf(depth, rng.random_range(0..accounts.num_shards()))
        };
        let (from, to) = accounts.pair_for_shard(shard, rng, self.selection_mode)?;
        Some(self.build_transfer(from, to))
    }

    /// Generate a cross-shard transfer.
    fn generate_cross_shard_inner<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        rng: &mut R,
    ) -> Option<Transaction> {
        let (from, to) = accounts.cross_shard_pair(rng, self.selection_mode)?;
        Some(self.build_transfer(from, to))
    }

    /// Build a transfer transaction from one account to another.
    ///
    /// The sender's nonce rides the envelope message: the transaction
    /// hash covers the whole signed envelope, so without it two transfers
    /// of the same amount inside one validity window would be the same
    /// transaction and the second would dedup away.
    fn build_transfer(&self, from: &FundedAccount, to: &FundedAccount) -> Transaction {
        let nonce = from.next_nonce();
        self.client
            .transfer(
                &from.keypair,
                to.address,
                self.amount,
                (self.validity_clock)(),
                Terms {
                    max_fee: TRANSFER_MAX_FEE,
                    ceilings: Ceilings::Guessed,
                    priority_bp: 0,
                    message: nonce.to_le_bytes().to_vec(),
                },
            )
            .expect("the stdlib account answers a transfer")
    }

    /// Generate one transaction (internal helper for trait impl).
    fn generate_one_inner<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        rng: &mut R,
    ) -> Option<Transaction> {
        let is_cross_shard =
            accounts.num_shards() >= 2 && rng.random::<f64>() < self.cross_shard_ratio;

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
        target_shard: ShardId,
        rng: &mut R,
    ) -> Option<Transaction> {
        let shard_accounts = accounts.accounts_for_shard(target_shard)?;

        if shard_accounts.len() < 2 {
            return None;
        }

        // Use AccountPool's selection for stateful modes (NoContention, RoundRobin)
        // which use atomic counters to ensure proper distribution/no conflicts.
        let (from, to) = accounts.pair_for_shard(target_shard, rng, self.selection_mode)?;

        Some(self.build_transfer(from, to))
    }

    /// Generate a cross-shard transfer that involves a specific shard.
    ///
    /// The transaction will have the target shard as one of the involved shards.
    fn generate_cross_shard_for<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        target_shard: ShardId,
        rng: &mut R,
    ) -> Option<Transaction> {
        if accounts.num_shards() < 2 {
            return None;
        }

        // Pick another shard randomly (different from target)
        let depth = accounts.num_shards().trailing_zeros();
        let mut other_shard = ShardId::leaf(depth, rng.random_range(0..accounts.num_shards()));
        while other_shard == target_shard {
            other_shard = ShardId::leaf(depth, rng.random_range(0..accounts.num_shards()));
        }

        // Randomly decide if target shard is sender or receiver
        let target_is_sender = rng.random_bool(0.5);

        // Use AccountPool's selection for stateful modes (NoContention, RoundRobin)
        let (from, to) = if target_is_sender {
            accounts.cross_shard_pair_for(target_shard, other_shard, rng, self.selection_mode)?
        } else {
            accounts.cross_shard_pair_for(other_shard, target_shard, rng, self.selection_mode)?
        };

        Some(self.build_transfer(from, to))
    }

    /// Generate a transaction that involves a specific shard.
    ///
    /// This generates either a same-shard transaction within the target shard,
    /// or a cross-shard transaction where the target shard is one of the involved shards.
    pub fn generate_for_shard<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        target_shard: ShardId,
        rng: &mut R,
    ) -> Option<Transaction> {
        let is_cross_shard =
            accounts.num_shards() >= 2 && rng.random::<f64>() < self.cross_shard_ratio;

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
    pub(crate) fn generate_batch_for_shard<R: Rng + ?Sized>(
        &self,
        accounts: &AccountPool,
        target_shard: ShardId,
        count: usize,
        rng: &mut R,
    ) -> Vec<Transaction> {
        (0..count)
            .filter_map(|_| self.generate_for_shard(accounts, target_shard, rng))
            .collect()
    }
}

impl WorkloadGenerator for TransferWorkload {
    fn generate_one(&self, accounts: &AccountPool, rng: &mut dyn Rng) -> Option<Transaction> {
        self.generate_one_inner(accounts, rng)
    }

    fn generate_batch(
        &self,
        accounts: &AccountPool,
        count: usize,
        rng: &mut dyn Rng,
    ) -> Vec<Transaction> {
        (0..count)
            .filter_map(|_| self.generate_one_inner(accounts, rng))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use hyperscale_effects_bridge::decode_tree;
    use hyperscale_types::ShardTrie;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;

    /// The shards a generated transfer touches, read off the envelope's
    /// own graph. The client never derives effect sets — it routes by the
    /// account addresses it picked — so the assertion reads the same
    /// thing the workload chose.
    fn shards_touched(tx: &Transaction, num_shards: u64) -> HashSet<ShardId> {
        let partition = ShardTrie::uniform_from_count(num_shards);
        let tree = decode_tree(&tx.body().tree).unwrap();
        tree.root
            .graph
            .nodes
            .iter()
            .map(|node| partition.shard_for_prefix(node.target))
            .collect()
    }

    #[test]
    fn test_generate_same_shard_transfer() {
        let accounts = AccountPool::generate(2, 10).unwrap();
        let workload = TransferWorkload::new().with_cross_shard_ratio(0.0);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let tx = workload
            .generate_one(&accounts, &mut rng)
            .expect("Should generate a transaction");
        assert_eq!(
            shards_touched(&tx, 2).len(),
            1,
            "a same-shard transfer touches exactly one shard"
        );
    }

    #[test]
    fn test_generate_cross_shard_transfer() {
        let accounts = AccountPool::generate(2, 10).unwrap();
        let workload = TransferWorkload::new().with_cross_shard_ratio(1.0);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let tx = workload
            .generate_one(&accounts, &mut rng)
            .expect("Should generate a transaction");
        assert_eq!(
            shards_touched(&tx, 2).len(),
            2,
            "a cross-shard transfer touches both shards"
        );
    }

    #[test]
    fn test_generate_for_shard_same_shard() {
        let num_shards = 4u64;
        let accounts = AccountPool::generate(num_shards, 10).unwrap();
        let workload = TransferWorkload::new().with_cross_shard_ratio(0.0);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let target_shard = ShardId::leaf(2, 2);
        for _ in 0..20 {
            let tx = workload
                .generate_for_shard(&accounts, target_shard, &mut rng)
                .expect("Should generate a transaction");
            assert_eq!(
                shards_touched(&tx, num_shards),
                HashSet::from([target_shard]),
                "Same-shard transaction should only touch the target shard"
            );
        }
    }

    #[test]
    fn test_generate_for_shard_cross_shard() {
        let num_shards = 4u64;
        let accounts = AccountPool::generate(num_shards, 10).unwrap();
        let workload = TransferWorkload::new().with_cross_shard_ratio(1.0);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let target_shard = ShardId::leaf(2, 1);
        for _ in 0..20 {
            let tx = workload
                .generate_for_shard(&accounts, target_shard, &mut rng)
                .expect("Should generate a transaction");
            let touched = shards_touched(&tx, num_shards);
            assert!(touched.len() > 1, "Should be a cross-shard transaction");
            assert!(
                touched.contains(&target_shard),
                "Cross-shard transaction should involve target shard"
            );
        }
    }

    #[test]
    fn test_generate_batch_for_shard() {
        let num_shards = 4u64;
        let accounts = AccountPool::generate(num_shards, 10).unwrap();
        let workload = TransferWorkload::new().with_cross_shard_ratio(0.5);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let target_shard = ShardId::leaf(2, 0);
        let batch = workload.generate_batch_for_shard(&accounts, target_shard, 50, &mut rng);
        assert!(!batch.is_empty(), "Should generate transactions");

        for tx in &batch {
            assert!(
                shards_touched(tx, num_shards).contains(&target_shard),
                "All transactions should involve the target shard"
            );
        }
    }
}
