//! Account management for transaction generation.
//!
//! Provides a `FundedAccount` type and `AccountPool` for managing accounts
//! distributed across shards. The first [`MAX_GENESIS_ACCOUNTS_PER_SHARD`]
//! accounts per shard are funded at genesis time; any beyond that limit are
//! funded via runtime transactions before the main workload starts.

use hyperscale_types::{
    ed25519_keypair_from_seed, shard_for_node, Ed25519PrivateKey, NodeId, ShardGroupId,
};

/// Maximum number of accounts that can be created per shard at genesis.
///
/// The Radix Engine panics when a single node's genesis includes more than
/// approximately 16,000 accounts. Since each node only processes its own
/// shard's accounts at genesis, this is the per-shard limit. Accounts beyond
/// this limit must be funded via runtime transactions after genesis.
pub const MAX_GENESIS_ACCOUNTS_PER_SHARD: usize = 16_000;
use radix_common::math::Decimal;
use radix_common::types::ComponentAddress;
use rand::RngExt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

/// A funded account that can sign transactions.
///
/// Uses atomic nonce for thread-safe concurrent transaction generation.
/// The nonce is wrapped in Arc so it can be shared across partitions.
pub struct FundedAccount {
    /// The Ed25519 keypair for signing transactions.
    pub keypair: Ed25519PrivateKey,

    /// The Radix component address for this account.
    pub address: ComponentAddress,

    /// The shard this account belongs to.
    pub shard: ShardGroupId,

    /// Nonce counter for transaction signing (thread-safe, shared across partitions).
    nonce: std::sync::Arc<AtomicU64>,
}

impl Clone for FundedAccount {
    fn clone(&self) -> Self {
        // Ed25519PrivateKey doesn't implement Clone, so we need to reconstruct from bytes
        // This is safe because we're just copying the key material
        let key_bytes = self.keypair.to_bytes();
        let keypair = Ed25519PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");

        Self {
            keypair,
            address: self.address,
            shard: self.shard,
            // Share the same nonce across clones (important for partitioning)
            nonce: std::sync::Arc::clone(&self.nonce),
        }
    }
}

impl FundedAccount {
    /// Create a new funded account from a seed.
    ///
    /// The seed is deterministically expanded to create a keypair,
    /// and the account's shard is determined by hashing the address.
    #[must_use]
    pub fn from_seed(seed: u64, num_shards: u64) -> Self {
        // Create varied seed bytes from the u64 seed
        let mut seed_bytes = [0u8; 32];
        let seed_le = seed.to_le_bytes();
        for (i, chunk) in seed_bytes.chunks_mut(8).enumerate() {
            // XOR with index to ensure different chunks even for small seeds
            let varied = seed.wrapping_add(i as u64);
            chunk.copy_from_slice(&varied.to_le_bytes());
        }
        // Also incorporate the original seed directly for uniqueness
        seed_bytes[0..8].copy_from_slice(&seed_le);
        let keypair = ed25519_keypair_from_seed(&seed_bytes);
        let address = Self::address_from_keypair(&keypair);
        let shard = Self::shard_for_address(&address, num_shards);

        Self {
            keypair,
            address,
            shard,
            nonce: std::sync::Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get the next nonce and increment atomically.
    ///
    /// Thread-safe for concurrent transaction generation.
    #[must_use]
    pub fn next_nonce(&self) -> u64 {
        self.nonce.fetch_add(1, Ordering::SeqCst)
    }

    /// Get current nonce without incrementing.
    #[must_use]
    pub fn current_nonce(&self) -> u64 {
        self.nonce.load(Ordering::SeqCst)
    }

    /// Set the nonce value (useful for restoring state).
    pub fn set_nonce(&self, value: u64) {
        self.nonce.store(value, Ordering::SeqCst);
    }

    /// Derive account address from keypair.
    fn address_from_keypair(keypair: &Ed25519PrivateKey) -> ComponentAddress {
        let radix_pk = keypair.public_key();
        ComponentAddress::preallocated_account_from_public_key(&radix_pk)
    }

    /// Determine which shard an address belongs to.
    fn shard_for_address(address: &ComponentAddress, num_shards: u64) -> ShardGroupId {
        let node_id = address.into_node_id();
        let det_node_id = NodeId(node_id.0[..30].try_into().unwrap());
        shard_for_node(&det_node_id, num_shards)
    }
}

/// Account selection mode for picking accounts from the pool.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum SelectionMode {
    /// Pure random selection - can cause contention under high load.
    Random,

    /// Round-robin selection - cycles through accounts sequentially.
    RoundRobin,

    /// Zipf distribution - realistic "popular accounts" pattern.
    /// Higher exponent = more skewed toward lower indices (hotspots).
    Zipf {
        /// Skew exponent — higher values concentrate selections on lower indices.
        exponent: f64,
    },

    /// No contention - each call gets a disjoint pair of accounts.
    /// Uses a global counter to ensure no conflicts between transactions.
    /// With N accounts per shard, supports N/2 concurrent non-conflicting transactions.
    #[default]
    NoContention,
}

/// Pool of funded accounts distributed across shards.
pub struct AccountPool {
    /// Accounts grouped by shard.
    pub(crate) by_shard: HashMap<ShardGroupId, Vec<FundedAccount>>,

    /// Number of shards.
    num_shards: u64,

    /// Per-shard account allocation counters.
    /// Used by `RoundRobin` and `NoContention` selection modes. In `NoContention` mode,
    /// both same-shard and cross-shard selections draw from the same per-shard
    /// counter, ensuring no two transactions ever get the same account.
    round_robin_counters: HashMap<ShardGroupId, std::sync::atomic::AtomicUsize>,

    /// Usage tracking: total selections per account index per shard.
    usage_counts: HashMap<ShardGroupId, Vec<std::sync::atomic::AtomicU64>>,
}

/// A partition of accounts for a single worker thread.
///
/// Each partition contains a disjoint subset of accounts from the main pool.
/// This allows lock-free access during spamming since each worker exclusively
/// owns its accounts.
pub struct AccountPartition {
    /// Accounts grouped by shard (owned, not shared).
    by_shard: HashMap<ShardGroupId, Vec<FundedAccount>>,

    /// Number of shards.
    num_shards: u64,

    /// Per-shard account allocation counters.
    /// Both same-shard and cross-shard draw from these, preventing contention.
    shard_counters: HashMap<ShardGroupId, usize>,
}

impl AccountPool {
    /// Create an empty account pool.
    #[must_use]
    pub fn new(num_shards: u64) -> Self {
        use std::sync::atomic::AtomicUsize;

        let mut by_shard = HashMap::new();
        let mut round_robin_counters = HashMap::new();
        let mut usage_counts = HashMap::new();

        for shard in 0..num_shards {
            let shard_id = ShardGroupId(shard);
            by_shard.insert(shard_id, Vec::new());
            round_robin_counters.insert(shard_id, AtomicUsize::new(0));
            usage_counts.insert(shard_id, Vec::new());
        }

        Self {
            by_shard,
            num_shards,
            round_robin_counters,
            usage_counts,
        }
    }

    /// Generate accounts targeting specific shards.
    ///
    /// This searches for keypair seeds whose derived accounts land on each shard.
    /// Seeds start at 100 (after reserved seeds) for compatibility with simulator.
    ///
    /// # Errors
    ///
    /// Returns [`AccountPoolError::GenerationFailed`] if no seed is found for
    /// every requested shard within the iteration budget.
    ///
    /// # Panics
    ///
    /// Panics if `num_shards * accounts_per_shard` overflows `usize` on a 32-bit
    /// target — unreachable for any realistic configuration.
    pub fn generate(num_shards: u64, accounts_per_shard: usize) -> Result<Self, AccountPoolError> {
        use std::sync::atomic::AtomicU64;

        info!(num_shards, accounts_per_shard, "Generating account pool");

        let mut pool = Self::new(num_shards);

        // Find accounts for each shard - start at seed 100 for compatibility
        let mut seed = 100u64;
        let num_shards_usize = usize::try_from(num_shards).unwrap_or(usize::MAX);
        let mut found_per_shard = vec![0usize; num_shards_usize];
        let max_iterations = accounts_per_shard * num_shards_usize * 10;
        let mut iterations = 0;

        while found_per_shard
            .iter()
            .any(|&count| count < accounts_per_shard)
        {
            let account = FundedAccount::from_seed(seed, num_shards);
            let shard_idx = usize::try_from(account.shard.0).unwrap_or(usize::MAX);

            if found_per_shard[shard_idx] < accounts_per_shard {
                pool.by_shard.get_mut(&account.shard).unwrap().push(account);
                found_per_shard[shard_idx] += 1;
            }

            seed = seed.wrapping_add(1);
            iterations += 1;
            if iterations > max_iterations {
                return Err(AccountPoolError::GenerationFailed {
                    shards: num_shards,
                    accounts_per_shard,
                });
            }
        }

        // Initialize usage counts for each shard
        for shard in 0..num_shards {
            let shard_id = ShardGroupId(shard);
            let count = pool.by_shard.get(&shard_id).map_or(0, std::vec::Vec::len);
            let counters: Vec<AtomicU64> = (0..count).map(|_| AtomicU64::new(0)).collect();
            pool.usage_counts.insert(shard_id, counters);
        }

        info!(
            total_accounts = pool.total_accounts(),
            "Generated accounts for all shards"
        );

        Ok(pool)
    }

    /// Get the XRD balances for a specific shard to configure in genesis.
    #[must_use]
    pub fn genesis_balances_for_shard(
        &self,
        shard: ShardGroupId,
        balance: Decimal,
    ) -> Vec<(ComponentAddress, Decimal)> {
        self.by_shard
            .get(&shard)
            .map(|accounts| {
                accounts
                    .iter()
                    .map(|account| (account.address, balance))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all genesis balances across all shards.
    #[must_use]
    pub fn all_genesis_balances(&self, balance: Decimal) -> Vec<(ComponentAddress, Decimal)> {
        self.by_shard
            .values()
            .flat_map(|accounts| accounts.iter().map(|a| (a.address, balance)))
            .collect()
    }

    /// Whether any shard has more accounts than the genesis limit.
    ///
    /// When true, the caller must run a funding phase after genesis to create
    /// the remaining accounts via runtime transactions.
    #[must_use]
    pub fn needs_runtime_funding(&self) -> bool {
        self.by_shard
            .values()
            .any(|accounts| accounts.len() > MAX_GENESIS_ACCOUNTS_PER_SHARD)
    }

    /// Get capped genesis balances for a shard, respecting the engine limit.
    ///
    /// Returns balances for at most [`MAX_GENESIS_ACCOUNTS_PER_SHARD`] accounts.
    /// Accounts that will serve as funding sources for runtime-funded accounts
    /// receive extra balance to cover those transfers (amount + fee per funded account).
    #[must_use]
    pub fn genesis_balances_capped(
        &self,
        shard: ShardGroupId,
        balance: Decimal,
        fee_per_funding_tx: Decimal,
    ) -> Vec<(ComponentAddress, Decimal)> {
        let Some(accounts) = self.by_shard.get(&shard) else {
            return Vec::new();
        };

        let genesis_count = accounts.len().min(MAX_GENESIS_ACCOUNTS_PER_SHARD);
        let unfunded_count = accounts
            .len()
            .saturating_sub(MAX_GENESIS_ACCOUNTS_PER_SHARD);

        if unfunded_count == 0 {
            // All accounts fit in genesis — no extra balance needed.
            return accounts.iter().map(|a| (a.address, balance)).collect();
        }

        // Distribute unfunded accounts round-robin across genesis accounts.
        // Compute how many extra accounts each genesis account will fund.
        let base_extra = unfunded_count / genesis_count;
        let remainder = unfunded_count % genesis_count;
        let cost_per_funded = balance + fee_per_funding_tx;

        accounts[..genesis_count]
            .iter()
            .enumerate()
            .map(|(i, account)| {
                let num_to_fund = base_extra + usize::from(i < remainder);
                let extra =
                    cost_per_funded * Decimal::from(u32::try_from(num_to_fund).unwrap_or(u32::MAX));
                (account.address, balance + extra)
            })
            .collect()
    }

    /// Build a plan of funding operations for accounts beyond the genesis limit.
    ///
    /// Each operation pairs a genesis account (source) with an unfunded account
    /// (destination) on the same shard. Sources are assigned round-robin.
    #[must_use]
    pub fn runtime_funding_plan(&self, funding_amount: Decimal) -> Vec<FundingOp> {
        let mut plan = Vec::new();

        for (&shard, accounts) in &self.by_shard {
            let genesis_count = accounts.len().min(MAX_GENESIS_ACCOUNTS_PER_SHARD);
            if accounts.len() <= genesis_count {
                continue;
            }

            for (i, dest) in accounts[genesis_count..].iter().enumerate() {
                let source_idx = i % genesis_count;
                plan.push(FundingOp {
                    source_shard: shard,
                    source_idx,
                    dest_address: dest.address,
                    amount: funding_amount,
                });
            }
        }

        plan
    }

    /// Get a pair of accounts on the same shard.
    pub fn same_shard_pair(
        &self,
        rng: &mut impl rand::Rng,
        mode: SelectionMode,
    ) -> Option<(&FundedAccount, &FundedAccount)> {
        let shard = ShardGroupId(rng.random_range(0..self.num_shards));
        let num_accounts = self.by_shard.get(&shard)?.len();

        if num_accounts < 2 {
            return None;
        }

        let (idx1, idx2) = self.select_pair_indices(shard, num_accounts, rng, mode);

        let accounts = self.by_shard.get(&shard)?;
        Some((&accounts[idx1], &accounts[idx2]))
    }

    /// Get a pair of accounts on different shards (for cross-shard transactions).
    pub fn cross_shard_pair(
        &self,
        rng: &mut (impl rand::Rng + ?Sized),
        mode: SelectionMode,
    ) -> Option<(&FundedAccount, &FundedAccount)> {
        if self.num_shards < 2 {
            return None;
        }

        let shard1 = ShardGroupId(rng.random_range(0..self.num_shards));
        let mut shard2 = ShardGroupId(rng.random_range(0..self.num_shards));
        while shard2 == shard1 {
            shard2 = ShardGroupId(rng.random_range(0..self.num_shards));
        }

        self.cross_shard_pair_for(shard1, shard2, rng, mode)
    }

    /// Get a pair of accounts from two specific shards (for cross-shard transactions).
    ///
    /// Returns (`from_account`, `to_account`) where from is on `from_shard` and to is on `to_shard`.
    ///
    /// For `NoContention` mode, uses the per-shard counters to ensure no conflicts with
    /// same-shard transactions. Each cross-shard pair consumes one account from each shard's
    /// counter sequence, ensuring coordination between same-shard and cross-shard workloads.
    ///
    /// # Panics
    ///
    /// Panics if `from_shard`'s round-robin counter is missing — unreachable
    /// for any shard registered via [`Self::new`] / [`Self::generate`].
    pub fn cross_shard_pair_for(
        &self,
        from_shard: ShardGroupId,
        to_shard: ShardGroupId,
        rng: &mut (impl rand::Rng + ?Sized),
        mode: SelectionMode,
    ) -> Option<(&FundedAccount, &FundedAccount)> {
        use std::sync::atomic::Ordering;

        let num_accounts1 = self.by_shard.get(&from_shard)?.len();
        let num_accounts2 = self.by_shard.get(&to_shard)?.len();

        if num_accounts1 == 0 || num_accounts2 == 0 {
            return None;
        }

        let (idx1, idx2) = if mode == SelectionMode::NoContention {
            // Allocate 1 slot from each shard's unified counter.
            // Same-shard and cross-shard both draw from the same per-shard
            // counters, so no two transactions ever get the same account.
            let counter1 = self.round_robin_counters.get(&from_shard).unwrap();
            let counter2 = self.round_robin_counters.get(&to_shard).unwrap();
            let c1 = counter1.fetch_add(1, Ordering::Relaxed);
            let c2 = counter2.fetch_add(1, Ordering::Relaxed);
            (c1 % num_accounts1, c2 % num_accounts2)
        } else {
            // For other modes, use per-shard selection
            let idx1 = self.select_single_index(from_shard, num_accounts1, rng, mode);
            let idx2 = self.select_single_index(to_shard, num_accounts2, rng, mode);
            (idx1, idx2)
        };

        // Track usage
        self.record_usage(from_shard, idx1);
        self.record_usage(to_shard, idx2);

        let accounts1 = self.by_shard.get(&from_shard)?;
        let accounts2 = self.by_shard.get(&to_shard)?;

        Some((&accounts1[idx1], &accounts2[idx2]))
    }

    /// Get a pair of accounts on a specific shard.
    ///
    /// This properly uses the selection mode's atomic counters for NoContention/RoundRobin.
    pub fn pair_for_shard(
        &self,
        shard: ShardGroupId,
        rng: &mut (impl rand::Rng + ?Sized),
        mode: SelectionMode,
    ) -> Option<(&FundedAccount, &FundedAccount)> {
        let num_accounts = self.by_shard.get(&shard)?.len();

        if num_accounts < 2 {
            return None;
        }

        let (idx1, idx2) = self.select_pair_indices(shard, num_accounts, rng, mode);

        let accounts = self.by_shard.get(&shard)?;
        Some((&accounts[idx1], &accounts[idx2]))
    }

    /// Select a pair of distinct account indices based on selection mode.
    fn select_pair_indices(
        &self,
        shard: ShardGroupId,
        num_accounts: usize,
        rng: &mut (impl rand::Rng + ?Sized),
        mode: SelectionMode,
    ) -> (usize, usize) {
        use std::sync::atomic::Ordering;

        let (idx1, idx2) = match mode {
            SelectionMode::Random => {
                let idx1 = rng.random_range(0..num_accounts);
                let mut idx2 = rng.random_range(0..num_accounts);
                while idx2 == idx1 {
                    idx2 = rng.random_range(0..num_accounts);
                }
                (idx1, idx2)
            }
            SelectionMode::RoundRobin => {
                let counter = self.round_robin_counters.get(&shard).unwrap();
                // Relaxed ordering is sufficient - we just need unique values, not ordering guarantees
                let c = counter.fetch_add(1, Ordering::Relaxed);
                let idx1 = (c * 2) % num_accounts;
                let idx2 = (c * 2 + 1) % num_accounts;
                (idx1, idx2)
            }
            SelectionMode::Zipf { exponent } => {
                let idx1 = Self::zipf_index(num_accounts, exponent, rng);
                let mut idx2 = Self::zipf_index(num_accounts, exponent, rng);
                while idx2 == idx1 {
                    idx2 = Self::zipf_index(num_accounts, exponent, rng);
                }
                (idx1, idx2)
            }
            SelectionMode::NoContention => {
                // Allocate 2 slots from the unified per-shard counter.
                // Same-shard and cross-shard both draw from this counter,
                // so they never pick the same account concurrently.
                let counter = self.round_robin_counters.get(&shard).unwrap();
                let c = counter.fetch_add(2, Ordering::Relaxed);
                let idx1 = c % num_accounts;
                let idx2 = (c + 1) % num_accounts;
                (idx1, idx2)
            }
        };

        // Track usage
        self.record_usage(shard, idx1);
        self.record_usage(shard, idx2);

        (idx1, idx2)
    }

    /// Select a single account index based on selection mode.
    fn select_single_index(
        &self,
        shard: ShardGroupId,
        num_accounts: usize,
        rng: &mut (impl rand::Rng + ?Sized),
        mode: SelectionMode,
    ) -> usize {
        use std::sync::atomic::Ordering;

        let idx = match mode {
            SelectionMode::Random => rng.random_range(0..num_accounts),
            SelectionMode::RoundRobin => {
                let counter = self.round_robin_counters.get(&shard).unwrap();
                counter.fetch_add(1, Ordering::Relaxed) % num_accounts
            }
            SelectionMode::Zipf { exponent } => Self::zipf_index(num_accounts, exponent, rng),
            SelectionMode::NoContention => {
                // Use per-shard counter for even distribution within each shard.
                let counter = self.round_robin_counters.get(&shard).unwrap();
                counter.fetch_add(1, Ordering::Relaxed) % num_accounts
            }
        };

        // Track usage
        self.record_usage(shard, idx);

        idx
    }

    /// Record that an account was selected.
    fn record_usage(&self, shard: ShardGroupId, idx: usize) {
        use std::sync::atomic::Ordering;

        if let Some(counts) = self.usage_counts.get(&shard) {
            if let Some(counter) = counts.get(idx) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Generate a Zipf-distributed index.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    // Skewed sampling for benchmarks; precision/sign correctness aren't material.
    fn zipf_index(n: usize, exponent: f64, rng: &mut (impl rand::Rng + ?Sized)) -> usize {
        let exp = exponent.max(1.0);
        let u: f64 = rng.random();
        let idx = ((n as f64).powf(1.0 - u)).powf(1.0 / exp) as usize;
        idx.min(n - 1)
    }

    /// Total number of accounts across all shards.
    #[must_use]
    pub fn total_accounts(&self) -> usize {
        self.by_shard.values().map(std::vec::Vec::len).sum()
    }

    /// Number of accounts on a specific shard.
    #[must_use]
    pub fn accounts_on_shard(&self, shard: ShardGroupId) -> usize {
        self.by_shard.get(&shard).map_or(0, std::vec::Vec::len)
    }

    /// Get all shards with accounts.
    pub fn shards(&self) -> impl Iterator<Item = ShardGroupId> + '_ {
        self.by_shard.keys().copied()
    }

    /// Get the number of shards.
    #[must_use]
    pub fn num_shards(&self) -> u64 {
        self.num_shards
    }

    /// Get accounts for a specific shard.
    #[must_use]
    pub fn accounts_for_shard(&self, shard: ShardGroupId) -> Option<&[FundedAccount]> {
        self.by_shard.get(&shard).map(std::vec::Vec::as_slice)
    }

    /// Partition the account pool into multiple disjoint partitions.
    ///
    /// Each partition gets an exclusive subset of accounts, enabling lock-free
    /// parallel spamming. Accounts are distributed round-robin across partitions
    /// to ensure even distribution.
    ///
    /// # Arguments
    /// * `num_partitions` - Number of partitions to create (typically = num workers)
    ///
    /// # Returns
    /// A vector of `AccountPartition`, each containing a disjoint subset of accounts.
    /// If there are fewer accounts than partitions, some partitions may be empty.
    #[must_use]
    pub fn partition(&self, num_partitions: usize) -> Vec<AccountPartition> {
        let num_partitions = num_partitions.max(1);

        // Initialize empty partitions
        let mut partitions: Vec<AccountPartition> = (0..num_partitions)
            .map(|_| AccountPartition::new(self.num_shards))
            .collect();

        // Distribute accounts round-robin across partitions
        for (&shard, accounts) in &self.by_shard {
            for (i, account) in accounts.iter().enumerate() {
                let partition_idx = i % num_partitions;
                partitions[partition_idx]
                    .by_shard
                    .entry(shard)
                    .or_default()
                    .push(account.clone());
            }
        }

        partitions
    }

    /// Get usage statistics for analysis.
    #[must_use]
    pub fn usage_stats(&self) -> AccountUsageStats {
        use std::sync::atomic::Ordering;

        let mut total_selections = 0u64;
        let mut max_selections = 0u64;
        let mut min_selections = u64::MAX;
        let mut account_count = 0usize;

        for counts in self.usage_counts.values() {
            for counter in counts {
                let count = counter.load(Ordering::Relaxed);
                total_selections += count;
                max_selections = max_selections.max(count);
                if count > 0 {
                    min_selections = min_selections.min(count);
                }
                account_count += 1;
            }
        }

        if min_selections == u64::MAX {
            min_selections = 0;
        }

        #[allow(clippy::cast_precision_loss)] // headline ratio for human-readable stats
        let avg_selections = if account_count > 0 {
            total_selections as f64 / account_count as f64
        } else {
            0.0
        };

        AccountUsageStats {
            total_selections,
            avg_selections,
            max_selections,
            min_selections,
            account_count,
        }
    }
}

/// A single runtime-funding operation: transfer from a genesis account to an
/// unfunded account on the same shard.
#[derive(Clone, Debug)]
pub struct FundingOp {
    /// Shard of the source (genesis) account.
    pub source_shard: ShardGroupId,
    /// Index of the source account within its shard's account vec.
    pub source_idx: usize,
    /// Address of the destination (unfunded) account.
    pub dest_address: ComponentAddress,
    /// Amount of XRD to transfer.
    pub amount: Decimal,
}

/// Statistics about account usage distribution.
#[derive(Clone, Debug)]
pub struct AccountUsageStats {
    /// Total number of account selections.
    pub total_selections: u64,
    /// Average selections per account.
    pub avg_selections: f64,
    /// Maximum selections for any account.
    pub max_selections: u64,
    /// Minimum selections for any account (excluding unused).
    pub min_selections: u64,
    /// Total number of accounts.
    pub account_count: usize,
}

impl AccountUsageStats {
    /// Calculate the skew ratio (max / avg). Higher = more uneven.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // headline ratio for human-readable stats
    pub fn skew_ratio(&self) -> f64 {
        if self.avg_selections > 0.0 {
            self.max_selections as f64 / self.avg_selections
        } else {
            0.0
        }
    }
}

/// Errors that can occur during account pool operations.
#[derive(Debug, thiserror::Error)]
pub enum AccountPoolError {
    /// Couldn't find seeds for every requested shard within the iteration budget.
    #[error("Could not generate enough accounts for {shards} shards with {accounts_per_shard} accounts each")]
    GenerationFailed {
        /// Number of shards requested.
        shards: u64,
        /// Accounts requested per shard.
        accounts_per_shard: usize,
    },
    /// I/O or parse error while reading the nonce-state file.
    #[error("Failed to load nonces: {0}")]
    NonceLoadError(String),
    /// I/O or serialization error while writing the nonce-state file.
    #[error("Failed to save nonces: {0}")]
    NonceSaveError(String),
}

/// Default path for nonce state file.
pub const DEFAULT_NONCE_FILE: &str = ".hyperscale-nonces.json";

impl AccountPool {
    /// Load nonces from a JSON file.
    ///
    /// File format: `{"<address_hex>": <nonce>, ...}`
    /// Accounts not in the file keep their current nonce (0 for fresh pools).
    ///
    /// # Errors
    ///
    /// Returns [`AccountPoolError::NonceLoadError`] if the file exists but
    /// can't be read or parsed as JSON.
    pub fn load_nonces(&self, path: &std::path::Path) -> Result<usize, AccountPoolError> {
        use std::sync::atomic::Ordering;

        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(AccountPoolError::NonceLoadError(e.to_string())),
        };

        let nonces: HashMap<String, u64> = serde_json::from_str(&contents)
            .map_err(|e| AccountPoolError::NonceLoadError(e.to_string()))?;

        let mut loaded = 0;
        for accounts in self.by_shard.values() {
            for account in accounts {
                let addr_hex = hex::encode(account.address.as_bytes());
                if let Some(&nonce) = nonces.get(&addr_hex) {
                    account.nonce.store(nonce, Ordering::SeqCst);
                    loaded += 1;
                }
            }
        }

        Ok(loaded)
    }

    /// Save current nonces to a JSON file.
    ///
    /// Only saves accounts with nonce > 0 to keep the file small.
    ///
    /// # Errors
    ///
    /// Returns [`AccountPoolError::NonceSaveError`] if serialization or the
    /// underlying file write fails.
    pub fn save_nonces(&self, path: &std::path::Path) -> Result<usize, AccountPoolError> {
        use std::sync::atomic::Ordering;

        let mut nonces: HashMap<String, u64> = HashMap::new();

        for accounts in self.by_shard.values() {
            for account in accounts {
                let nonce = account.nonce.load(Ordering::SeqCst);
                if nonce > 0 {
                    let addr_hex = hex::encode(account.address.as_bytes());
                    nonces.insert(addr_hex, nonce);
                }
            }
        }

        let contents = serde_json::to_string_pretty(&nonces)
            .map_err(|e| AccountPoolError::NonceSaveError(e.to_string()))?;

        std::fs::write(path, contents)
            .map_err(|e| AccountPoolError::NonceSaveError(e.to_string()))?;

        Ok(nonces.len())
    }

    /// Load nonces from the default file path.
    ///
    /// # Errors
    ///
    /// Returns [`AccountPoolError::NonceLoadError`] if the file exists but
    /// can't be read or parsed as JSON.
    pub fn load_nonces_default(&self) -> Result<usize, AccountPoolError> {
        self.load_nonces(std::path::Path::new(DEFAULT_NONCE_FILE))
    }

    /// Save nonces to the default file path.
    ///
    /// # Errors
    ///
    /// Returns [`AccountPoolError::NonceSaveError`] if serialization or the
    /// underlying file write fails.
    pub fn save_nonces_default(&self) -> Result<usize, AccountPoolError> {
        self.save_nonces(std::path::Path::new(DEFAULT_NONCE_FILE))
    }
}

impl AccountPartition {
    /// Create an empty partition.
    fn new(num_shards: u64) -> Self {
        let mut shard_counters = HashMap::new();
        for shard in 0..num_shards {
            shard_counters.insert(ShardGroupId(shard), 0usize);
        }
        Self {
            by_shard: HashMap::new(),
            num_shards,
            shard_counters,
        }
    }

    /// Get the number of shards.
    #[must_use]
    pub fn num_shards(&self) -> u64 {
        self.num_shards
    }

    /// Get total number of accounts in this partition.
    #[must_use]
    pub fn total_accounts(&self) -> usize {
        self.by_shard.values().map(std::vec::Vec::len).sum()
    }

    /// Get number of accounts on a specific shard.
    #[must_use]
    pub fn accounts_on_shard(&self, shard: ShardGroupId) -> usize {
        self.by_shard.get(&shard).map_or(0, std::vec::Vec::len)
    }

    /// Get accounts for a specific shard.
    #[must_use]
    pub fn accounts_for_shard(&self, shard: ShardGroupId) -> Option<&[FundedAccount]> {
        self.by_shard.get(&shard).map(std::vec::Vec::as_slice)
    }

    /// Get a pair of accounts on the same shard (mutable for counter updates).
    ///
    /// Uses round-robin selection for `NoContention` mode to ensure no account reuse.
    ///
    /// # Panics
    ///
    /// Panics if `shard` has no counter — unreachable for any shard registered
    /// via [`AccountPool::new`] / [`AccountPool::generate`].
    pub fn pair_for_shard(
        &mut self,
        shard: ShardGroupId,
        rng: &mut impl rand::Rng,
        mode: SelectionMode,
    ) -> Option<(&FundedAccount, &FundedAccount)> {
        let accounts = self.by_shard.get(&shard)?;
        let num_accounts = accounts.len();

        if num_accounts < 2 {
            return None;
        }

        let (idx1, idx2) = match mode {
            SelectionMode::NoContention | SelectionMode::RoundRobin => {
                // Allocate 2 slots from the per-shard counter.
                // No atomics needed since we own this partition.
                let c = self.shard_counters.get_mut(&shard).unwrap();
                let val = *c;
                *c = val.wrapping_add(2);
                (val % num_accounts, (val + 1) % num_accounts)
            }
            SelectionMode::Random => {
                let idx1 = rng.random_range(0..num_accounts);
                let mut idx2 = rng.random_range(0..num_accounts);
                while idx2 == idx1 {
                    idx2 = rng.random_range(0..num_accounts);
                }
                (idx1, idx2)
            }
            SelectionMode::Zipf { exponent } => {
                let idx1 = Self::zipf_index(num_accounts, exponent, rng);
                let mut idx2 = Self::zipf_index(num_accounts, exponent, rng);
                while idx2 == idx1 {
                    idx2 = Self::zipf_index(num_accounts, exponent, rng);
                }
                (idx1, idx2)
            }
        };

        Some((&accounts[idx1], &accounts[idx2]))
    }

    /// Get a cross-shard pair of accounts.
    pub fn cross_shard_pair(
        &mut self,
        rng: &mut impl rand::Rng,
        mode: SelectionMode,
    ) -> Option<(&FundedAccount, &FundedAccount)> {
        if self.num_shards < 2 {
            return None;
        }

        let shard1 = ShardGroupId(rng.random_range(0..self.num_shards));
        let mut shard2 = ShardGroupId(rng.random_range(0..self.num_shards));
        while shard2 == shard1 {
            shard2 = ShardGroupId(rng.random_range(0..self.num_shards));
        }

        self.cross_shard_pair_for(shard1, shard2, rng, mode)
    }

    /// Get a cross-shard pair for specific shards.
    ///
    /// # Panics
    ///
    /// Panics if either shard's counter is missing — unreachable for any
    /// shard registered via [`AccountPool::new`] / [`AccountPool::generate`].
    pub fn cross_shard_pair_for(
        &mut self,
        from_shard: ShardGroupId,
        to_shard: ShardGroupId,
        rng: &mut impl rand::Rng,
        mode: SelectionMode,
    ) -> Option<(&FundedAccount, &FundedAccount)> {
        let accounts1 = self.by_shard.get(&from_shard)?;
        let accounts2 = self.by_shard.get(&to_shard)?;

        let num_accounts1 = accounts1.len();
        let num_accounts2 = accounts2.len();

        if num_accounts1 == 0 || num_accounts2 == 0 {
            return None;
        }

        let (idx1, idx2) = match mode {
            SelectionMode::NoContention | SelectionMode::RoundRobin => {
                // Allocate 1 slot from each shard's counter.
                // Same counter space as same-shard, preventing contention.
                let c1 = self.shard_counters.get_mut(&from_shard).unwrap();
                let v1 = *c1;
                *c1 = v1.wrapping_add(1);
                let c2 = self.shard_counters.get_mut(&to_shard).unwrap();
                let v2 = *c2;
                *c2 = v2.wrapping_add(1);
                (v1 % num_accounts1, v2 % num_accounts2)
            }
            SelectionMode::Random => (
                rng.random_range(0..num_accounts1),
                rng.random_range(0..num_accounts2),
            ),
            SelectionMode::Zipf { exponent } => (
                Self::zipf_index(num_accounts1, exponent, rng),
                Self::zipf_index(num_accounts2, exponent, rng),
            ),
        };

        // Need to re-borrow because we need both slices
        let accounts1 = self.by_shard.get(&from_shard)?;
        let accounts2 = self.by_shard.get(&to_shard)?;

        Some((&accounts1[idx1], &accounts2[idx2]))
    }

    /// Generate a Zipf-distributed index.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    // Skewed sampling for benchmarks; precision/sign correctness aren't material.
    fn zipf_index(n: usize, exponent: f64, rng: &mut impl rand::Rng) -> usize {
        let exp = exponent.max(1.0);
        let u: f64 = rng.random();
        let idx = ((n as f64).powf(1.0 - u)).powf(1.0 / exp) as usize;
        idx.min(n - 1)
    }

    /// Get all shards that have accounts in this partition.
    pub fn shards(&self) -> impl Iterator<Item = ShardGroupId> + '_ {
        self.by_shard.keys().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_account_generation() {
        let pool = AccountPool::generate(2, 10).unwrap();
        assert_eq!(pool.total_accounts(), 20);
        assert_eq!(pool.accounts_on_shard(ShardGroupId(0)), 10);
        assert_eq!(pool.accounts_on_shard(ShardGroupId(1)), 10);
    }

    #[test]
    fn test_account_deterministic() {
        let acc1 = FundedAccount::from_seed(42, 2);
        let acc2 = FundedAccount::from_seed(42, 2);
        assert_eq!(acc1.address, acc2.address);
    }

    #[test]
    fn test_atomic_nonce() {
        let account = FundedAccount::from_seed(100, 2);
        assert_eq!(account.next_nonce(), 0);
        assert_eq!(account.next_nonce(), 1);
        assert_eq!(account.next_nonce(), 2);
        assert_eq!(account.current_nonce(), 3);
    }

    #[test]
    fn test_same_shard_pair() {
        let pool = AccountPool::generate(2, 10).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let pair = pool.same_shard_pair(&mut rng, SelectionMode::Random);
        assert!(pair.is_some());

        let (from, to) = pair.unwrap();
        assert_eq!(from.shard, to.shard);
        assert_ne!(from.address, to.address);
    }

    #[test]
    fn test_cross_shard_pair() {
        let pool = AccountPool::generate(2, 10).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let pair = pool.cross_shard_pair(&mut rng, SelectionMode::Random);
        assert!(pair.is_some());

        let (from, to) = pair.unwrap();
        assert_ne!(from.shard, to.shard);
    }

    #[test]
    fn test_no_contention_mode() {
        let pool = AccountPool::generate(2, 20).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut used_indices: std::collections::HashSet<(u64, usize)> =
            std::collections::HashSet::new();

        // Generate 10 same-shard pairs - should all be disjoint
        for _ in 0..10 {
            let (from, to) = pool
                .same_shard_pair(&mut rng, SelectionMode::NoContention)
                .unwrap();

            let shard = from.shard;
            let from_addr = from.address;
            let to_addr = to.address;

            let from_idx = pool.by_shard[&shard]
                .iter()
                .position(|a| a.address == from_addr)
                .unwrap();
            let to_idx = pool.by_shard[&shard]
                .iter()
                .position(|a| a.address == to_addr)
                .unwrap();

            assert!(
                used_indices.insert((shard.0, from_idx)),
                "Account index ({}, {}) was reused!",
                shard.0,
                from_idx
            );
            assert!(
                used_indices.insert((shard.0, to_idx)),
                "Account index ({}, {}) was reused!",
                shard.0,
                to_idx
            );
        }
    }

    #[test]
    fn test_genesis_balances() {
        let pool = AccountPool::generate(2, 5).unwrap();
        let balance = Decimal::from(1000u32);

        let all_balances = pool.all_genesis_balances(balance);
        assert_eq!(all_balances.len(), 10);

        for (_, bal) in &all_balances {
            assert_eq!(*bal, balance);
        }
    }

    #[test]
    fn test_no_contention_same_shard_only() {
        // Test that same-shard transactions don't conflict with each other
        let pool = AccountPool::generate(2, 40).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut used_indices: std::collections::HashSet<(u64, usize)> =
            std::collections::HashSet::new();

        // Generate 20 same-shard transactions - should all be disjoint
        for i in 0..20 {
            let (from, to) = pool
                .same_shard_pair(&mut rng, SelectionMode::NoContention)
                .unwrap();

            let from_idx = pool.by_shard[&from.shard]
                .iter()
                .position(|a| a.address == from.address)
                .unwrap();
            let to_idx = pool.by_shard[&to.shard]
                .iter()
                .position(|a| a.address == to.address)
                .unwrap();

            assert!(
                used_indices.insert((from.shard.0, from_idx)),
                "Same-shard tx {}: from account ({}, {}) was reused!",
                i,
                from.shard.0,
                from_idx
            );
            assert!(
                used_indices.insert((to.shard.0, to_idx)),
                "Same-shard tx {}: to account ({}, {}) was reused!",
                i,
                to.shard.0,
                to_idx
            );
        }
    }

    #[test]
    fn test_no_contention_cross_shard_only() {
        // Test that cross-shard transactions don't conflict with each other
        let pool = AccountPool::generate(2, 40).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut used_indices: std::collections::HashSet<(u64, usize)> =
            std::collections::HashSet::new();

        // Generate 40 cross-shard transactions - should all be disjoint
        for i in 0..40 {
            let (from, to) = pool
                .cross_shard_pair(&mut rng, SelectionMode::NoContention)
                .unwrap();

            let from_idx = pool.by_shard[&from.shard]
                .iter()
                .position(|a| a.address == from.address)
                .unwrap();
            let to_idx = pool.by_shard[&to.shard]
                .iter()
                .position(|a| a.address == to.address)
                .unwrap();

            assert!(
                used_indices.insert((from.shard.0, from_idx)),
                "Cross-shard tx {}: from account ({}, {}) was reused!",
                i,
                from.shard.0,
                from_idx
            );
            assert!(
                used_indices.insert((to.shard.0, to_idx)),
                "Cross-shard tx {}: to account ({}, {}) was reused!",
                i,
                to.shard.0,
                to_idx
            );
        }
    }

    #[test]
    fn test_partition_distribution() {
        // Test that partitioning distributes accounts evenly
        let pool = AccountPool::generate(2, 100).unwrap();
        let partitions = pool.partition(4);

        assert_eq!(partitions.len(), 4);

        // Each partition should have ~25 accounts per shard (100/4)
        for partition in &partitions {
            // Should have both shards
            assert!(partition.accounts_on_shard(ShardGroupId(0)) > 0);
            assert!(partition.accounts_on_shard(ShardGroupId(1)) > 0);

            // Should have roughly equal distribution (within 1 due to rounding)
            let shard0_count = partition.accounts_on_shard(ShardGroupId(0));
            let shard1_count = partition.accounts_on_shard(ShardGroupId(1));
            assert!(
                (24..=26).contains(&shard0_count),
                "Expected ~25 accounts, got {shard0_count} for shard 0"
            );
            assert!(
                (24..=26).contains(&shard1_count),
                "Expected ~25 accounts, got {shard1_count} for shard 1"
            );
        }

        // Total accounts across all partitions should equal original
        let total: usize = partitions
            .iter()
            .map(super::AccountPartition::total_accounts)
            .sum();
        assert_eq!(total, pool.total_accounts());
    }

    #[test]
    fn test_partition_disjoint() {
        // Test that partitions have disjoint account sets
        let pool = AccountPool::generate(2, 20).unwrap();
        let partitions = pool.partition(4);

        let mut all_addresses: std::collections::HashSet<_> = std::collections::HashSet::new();

        for partition in &partitions {
            for shard_id in 0..2 {
                if let Some(accounts) = partition.accounts_for_shard(ShardGroupId(shard_id)) {
                    for account in accounts {
                        assert!(
                            all_addresses.insert(account.address),
                            "Account {:?} appears in multiple partitions!",
                            account.address
                        );
                    }
                }
            }
        }

        assert_eq!(all_addresses.len(), pool.total_accounts());
    }

    #[test]
    fn test_partition_pair_selection() {
        // Test that partition pair selection works correctly
        let pool = AccountPool::generate(2, 20).unwrap();
        let mut partitions = pool.partition(2);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Each partition should be able to generate pairs
        for partition in &mut partitions {
            let pair =
                partition.pair_for_shard(ShardGroupId(0), &mut rng, SelectionMode::NoContention);
            assert!(
                pair.is_some(),
                "Should be able to get a pair from partition"
            );

            let (from, to) = pair.unwrap();
            assert_eq!(from.shard, to.shard);
            assert_ne!(from.address, to.address);
        }
    }

    #[test]
    fn test_partition_shares_nonces() {
        // Test that partitions share nonces with the original pool
        // This is critical for saving nonces after multi-threaded spamming
        let pool = AccountPool::generate(1, 10).unwrap();
        let partitions = pool.partition(2);

        // Get an account from partition 0 and increment its nonce
        let partition0_accounts = partitions[0].accounts_for_shard(ShardGroupId(0)).unwrap();
        let account_in_partition = &partition0_accounts[0];
        let address = account_in_partition.address;

        // Increment nonce via the partition's account
        let nonce1 = account_in_partition.next_nonce();
        assert_eq!(nonce1, 0);
        let nonce2 = account_in_partition.next_nonce();
        assert_eq!(nonce2, 1);

        // The original pool should see the updated nonce
        let pool_accounts = pool.accounts_for_shard(ShardGroupId(0)).unwrap();
        let original_account = pool_accounts.iter().find(|a| a.address == address).unwrap();
        assert_eq!(
            original_account.current_nonce(),
            2,
            "Original pool should see nonce updates from partition"
        );
    }
}
