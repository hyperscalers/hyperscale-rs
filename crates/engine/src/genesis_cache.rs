//! Process-wide cache of prepared genesis snapshots.
//!
//! Radix Engine genesis bootstrap is the dominant fixed cost in simulation
//! tests (~2.5s per node). The output is deterministic given the network and
//! [`GenesisConfig`], so we run it once per unique key on a throwaway
//! in-memory store and reuse the merged [`DatabaseUpdates`] across every
//! node and every test in the same process.

use crate::genesis::{GenesisConfig, bootstrap};
use hyperscale_storage::{
    CommittableSubstateDatabase, DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey,
    DbSubstateValue, PartitionDatabaseUpdates, PartitionEntry, SubstateDatabase, merge_into,
};
use radix_common::network::NetworkDefinition;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};

static CACHE: OnceLock<Mutex<HashMap<u64, Arc<DatabaseUpdates>>>> = OnceLock::new();

/// Return the merged [`DatabaseUpdates`] for a genesis bootstrap with the
/// given network and config, building (and caching) on first request.
///
/// # Panics
///
/// Panics if the cache mutex is poisoned (i.e. another thread panicked
/// while holding it).
pub fn prepared_genesis(
    network: &NetworkDefinition,
    config: &GenesisConfig,
) -> Arc<DatabaseUpdates> {
    let key = key_for(network, config);
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(existing) = cache.lock().unwrap().get(&key) {
        return existing.clone();
    }

    let mut scratch = ScratchDb::default();
    bootstrap(network, config, &mut scratch);
    let merged = Arc::new(scratch.merged);

    cache.lock().unwrap().insert(key, merged.clone());
    merged
}

fn key_for(network: &NetworkDefinition, config: &GenesisConfig) -> u64 {
    let mut hasher = DefaultHasher::new();
    network.id.hash(&mut hasher);
    config.cache_hash(&mut hasher);
    hasher.finish()
}

/// In-memory substate database used only by the genesis cache.
///
/// Holds two parallel structures:
/// - `state` — partition → sorted (`sort_key` → value) map; serves reads
///   issued by the Radix Engine while bootstrap is in progress.
/// - `merged` — the accumulator handed back to callers, preserving the
///   `DatabaseUpdates` shape (Delta vs Reset) that downstream backends
///   rely on for `commit_substates_only` and JMT computation.
#[derive(Default)]
struct ScratchDb {
    state: HashMap<DbPartitionKey, BTreeMap<DbSortKey, DbSubstateValue>>,
    merged: DatabaseUpdates,
}

impl SubstateDatabase for ScratchDb {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        self.state.get(partition_key)?.get(sort_key).cloned()
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        let Some(map) = self.state.get(partition_key) else {
            return Box::new(std::iter::empty());
        };
        let collected: Vec<PartitionEntry> = from_sort_key.map_or_else(
            || map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            |from| {
                map.range(from.clone()..)
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            },
        );
        Box::new(collected.into_iter())
    }
}

impl CommittableSubstateDatabase for ScratchDb {
    fn commit(&mut self, updates: &DatabaseUpdates) {
        for (entity_key, node_updates) in &updates.node_updates {
            for (partition_num, part_updates) in &node_updates.partition_updates {
                let partition_key = DbPartitionKey {
                    node_key: entity_key.clone(),
                    partition_num: *partition_num,
                };
                match part_updates {
                    PartitionDatabaseUpdates::Delta { substate_updates } => {
                        let map = self.state.entry(partition_key).or_default();
                        for (sk, upd) in substate_updates {
                            match upd {
                                DatabaseUpdate::Set(v) => {
                                    map.insert(sk.clone(), v.clone());
                                }
                                DatabaseUpdate::Delete => {
                                    map.remove(sk);
                                }
                            }
                        }
                    }
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values,
                    } => {
                        let map: BTreeMap<_, _> = new_substate_values
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect();
                        self.state.insert(partition_key, map);
                    }
                }
            }
        }
        merge_into(&mut self.merged, updates);
    }
}
