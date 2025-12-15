//! Account management for transaction generation.
//!
//! Provides a `FundedAccount` type and `AccountPool` for managing accounts
//! distributed across shards. Accounts are funded at genesis time.

use hyperscale_types::{shard_for_node, KeyPair, KeyType, NodeId, ShardGroupId};
use radix_common::crypto::Ed25519PublicKey;
use radix_common::math::Decimal;
use radix_common::types::ComponentAddress;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

/// A funded account that can sign transactions.
///
/// Uses atomic nonce for thread-safe concurrent transaction generation.
pub struct FundedAccount {
    /// The keypair for signing transactions.
    pub keypair: KeyPair,

    /// The Radix component address for this account.
    pub address: ComponentAddress,

    /// The shard this account belongs to.
    pub shard: ShardGroupId,

    /// Nonce counter for transaction signing (thread-safe).
    nonce: AtomicU64,
}

impl Clone for FundedAccount {
    fn clone(&self) -> Self {
        Self {
            keypair: self.keypair.clone(),
            address: self.address,
            shard: self.shard,
            nonce: AtomicU64::new(self.nonce.load(Ordering::SeqCst)),
        }
    }
}

impl FundedAccount {
    /// Create a new funded account from a seed.
    ///
    /// The seed is deterministically expanded to create a keypair,
    /// and the account's shard is determined by hashing the address.
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
        let keypair = KeyPair::from_seed(KeyType::Ed25519, &seed_bytes);
        let address = Self::address_from_keypair(&keypair);
        let shard = Self::shard_for_address(&address, num_shards);

        Self {
            keypair,
            address,
            shard,
            nonce: AtomicU64::new(0),
        }
    }

    /// Get the next nonce and increment atomically.
    ///
    /// Thread-safe for concurrent transaction generation.
    pub fn next_nonce(&self) -> u64 {
        self.nonce.fetch_add(1, Ordering::SeqCst)
    }

    /// Get current nonce without incrementing.
    pub fn current_nonce(&self) -> u64 {
        self.nonce.load(Ordering::SeqCst)
    }

    /// Set the nonce value (useful for restoring state).
    pub fn set_nonce(&self, value: u64) {
        self.nonce.store(value, Ordering::SeqCst);
    }

    /// Derive account address from keypair.
    fn address_from_keypair(keypair: &KeyPair) -> ComponentAddress {
        match keypair.public_key() {
            hyperscale_types::PublicKey::Ed25519(bytes) => {
                let radix_pk = Ed25519PublicKey(bytes);
                ComponentAddress::preallocated_account_from_public_key(&radix_pk)
            }
            _ => panic!("Only Ed25519 keypairs are supported for accounts"),
        }
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
    Zipf { exponent: f64 },

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

    /// Round-robin counters per shard.
    /// Used by both RoundRobin and NoContention selection modes.
    round_robin_counters: HashMap<ShardGroupId, std::sync::atomic::AtomicUsize>,

    /// Usage tracking: total selections per account index per shard.
    usage_counts: HashMap<ShardGroupId, Vec<std::sync::atomic::AtomicU64>>,
}

impl AccountPool {
    /// Create an empty account pool.
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
    pub fn generate(num_shards: u64, accounts_per_shard: usize) -> Result<Self, AccountPoolError> {
        use std::sync::atomic::AtomicU64;

        info!(num_shards, accounts_per_shard, "Generating account pool");

        let mut pool = Self::new(num_shards);

        // Find accounts for each shard - start at seed 100 for compatibility
        let mut seed = 100u64;
        let mut found_per_shard = vec![0usize; num_shards as usize];
        let max_iterations = accounts_per_shard * num_shards as usize * 10;
        let mut iterations = 0;

        while found_per_shard
            .iter()
            .any(|&count| count < accounts_per_shard)
        {
            let account = FundedAccount::from_seed(seed, num_shards);
            let shard_idx = account.shard.0 as usize;

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
            let count = pool.by_shard.get(&shard_id).map(|v| v.len()).unwrap_or(0);
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
    pub fn all_genesis_balances(&self, balance: Decimal) -> Vec<(ComponentAddress, Decimal)> {
        self.by_shard
            .values()
            .flat_map(|accounts| accounts.iter().map(|a| (a.address, balance)))
            .collect()
    }

    /// Get a pair of accounts on the same shard.
    pub fn same_shard_pair(
        &self,
        rng: &mut impl rand::Rng,
        mode: SelectionMode,
    ) -> Option<(&FundedAccount, &FundedAccount)> {
        let shard = ShardGroupId(rng.gen_range(0..self.num_shards));
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

        let shard1 = ShardGroupId(rng.gen_range(0..self.num_shards));
        let mut shard2 = ShardGroupId(rng.gen_range(0..self.num_shards));
        while shard2 == shard1 {
            shard2 = ShardGroupId(rng.gen_range(0..self.num_shards));
        }

        self.cross_shard_pair_for(shard1, shard2, rng, mode)
    }

    /// Get a pair of accounts from two specific shards (for cross-shard transactions).
    ///
    /// Returns (from_account, to_account) where from is on `from_shard` and to is on `to_shard`.
    pub fn cross_shard_pair_for(
        &self,
        from_shard: ShardGroupId,
        to_shard: ShardGroupId,
        rng: &mut (impl rand::Rng + ?Sized),
        mode: SelectionMode,
    ) -> Option<(&FundedAccount, &FundedAccount)> {
        let num_accounts1 = self.by_shard.get(&from_shard)?.len();
        let num_accounts2 = self.by_shard.get(&to_shard)?.len();

        if num_accounts1 == 0 || num_accounts2 == 0 {
            return None;
        }

        let idx1 = self.select_single_index(from_shard, num_accounts1, rng, mode);
        let idx2 = self.select_single_index(to_shard, num_accounts2, rng, mode);

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
                let idx1 = rng.gen_range(0..num_accounts);
                let mut idx2 = rng.gen_range(0..num_accounts);
                while idx2 == idx1 {
                    idx2 = rng.gen_range(0..num_accounts);
                }
                (idx1, idx2)
            }
            SelectionMode::RoundRobin => {
                let counter = self.round_robin_counters.get(&shard).unwrap();
                let c = counter.fetch_add(1, Ordering::SeqCst);
                let idx1 = (c * 2) % num_accounts;
                let idx2 = (c * 2 + 1) % num_accounts;
                (idx1, idx2)
            }
            SelectionMode::Zipf { exponent } => {
                let idx1 = self.zipf_index(num_accounts, exponent, rng);
                let mut idx2 = self.zipf_index(num_accounts, exponent, rng);
                while idx2 == idx1 {
                    idx2 = self.zipf_index(num_accounts, exponent, rng);
                }
                (idx1, idx2)
            }
            SelectionMode::NoContention => {
                // Use per-shard counter to ensure each shard cycles through its own
                // accounts independently. This provides even distribution across shards
                // while still avoiding contention within each shard.
                let counter = self.round_robin_counters.get(&shard).unwrap();
                let c = counter.fetch_add(1, Ordering::SeqCst);
                let pair_base = (c * 2) % num_accounts;
                let idx1 = pair_base;
                let idx2 = (pair_base + 1) % num_accounts;
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
            SelectionMode::Random => rng.gen_range(0..num_accounts),
            SelectionMode::RoundRobin => {
                let counter = self.round_robin_counters.get(&shard).unwrap();
                counter.fetch_add(1, Ordering::SeqCst) % num_accounts
            }
            SelectionMode::Zipf { exponent } => self.zipf_index(num_accounts, exponent, rng),
            SelectionMode::NoContention => {
                // Use per-shard counter for even distribution within each shard.
                let counter = self.round_robin_counters.get(&shard).unwrap();
                counter.fetch_add(1, Ordering::SeqCst) % num_accounts
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
    fn zipf_index(&self, n: usize, exponent: f64, rng: &mut (impl rand::Rng + ?Sized)) -> usize {
        let exp = exponent.max(1.0);
        let u: f64 = rng.gen();
        let idx = ((n as f64).powf(1.0 - u)).powf(1.0 / exp) as usize;
        idx.min(n - 1)
    }

    /// Total number of accounts across all shards.
    pub fn total_accounts(&self) -> usize {
        self.by_shard.values().map(|v| v.len()).sum()
    }

    /// Number of accounts on a specific shard.
    pub fn accounts_on_shard(&self, shard: ShardGroupId) -> usize {
        self.by_shard.get(&shard).map(|v| v.len()).unwrap_or(0)
    }

    /// Get all shards with accounts.
    pub fn shards(&self) -> impl Iterator<Item = ShardGroupId> + '_ {
        self.by_shard.keys().copied()
    }

    /// Get the number of shards.
    pub fn num_shards(&self) -> u64 {
        self.num_shards
    }

    /// Get accounts for a specific shard.
    pub fn accounts_for_shard(&self, shard: ShardGroupId) -> Option<&[FundedAccount]> {
        self.by_shard.get(&shard).map(|v| v.as_slice())
    }

    /// Get usage statistics for analysis.
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
    #[error("Could not generate enough accounts for {shards} shards with {accounts_per_shard} accounts each")]
    GenerationFailed {
        shards: u64,
        accounts_per_shard: usize,
    },
    #[error("Failed to load nonces: {0}")]
    NonceLoadError(String),
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
    pub fn load_nonces_default(&self) -> Result<usize, AccountPoolError> {
        self.load_nonces(std::path::Path::new(DEFAULT_NONCE_FILE))
    }

    /// Save nonces to the default file path.
    pub fn save_nonces_default(&self) -> Result<usize, AccountPoolError> {
        self.save_nonces(std::path::Path::new(DEFAULT_NONCE_FILE))
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
}
