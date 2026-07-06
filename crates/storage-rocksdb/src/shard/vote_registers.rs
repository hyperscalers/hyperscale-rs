//! Durable safe-vote registers — `SafeVoteRegisterStore` for
//! [`RocksDbShardStorage`].

use hyperscale_storage::SafeVoteRegisterStore;
use hyperscale_types::{SafeVoteRegisters, ValidatorId};
use rocksdb::{WriteBatch, WriteOptions};

use super::column_families::SafeVoteRegistersCf;
use super::core::RocksDbShardStorage;
use super::metadata::read_chain_origin;
use crate::typed_cf::{TypedCf, batch_put};

impl SafeVoteRegisterStore for RocksDbShardStorage {
    fn persist_safe_vote_registers(&self, validator: ValidatorId, registers: SafeVoteRegisters) {
        // One guard spans the read-merge-write so concurrent signers'
        // writes stay monotone regardless of scheduling; register
        // writes are rare enough (one per vote or timeout) that
        // serializing the fsync under it costs nothing.
        let mut cache = self
            .vote_registers
            .lock()
            .expect("vote register cache lock poisoned");

        let origin = read_chain_origin(&*self.db);
        let stored = cache
            .get(&validator)
            .copied()
            .or_else(|| self.cf_get::<SafeVoteRegistersCf>(&validator));
        let merged = match stored {
            // A record from a different chain incarnation is dead
            // weight — overwrite it rather than merging round numbers
            // that belong to an unrelated chain.
            Some((stored_origin, stored_registers)) if stored_origin == origin => {
                registers.max(stored_registers)
            }
            _ => registers,
        };
        if stored == Some((origin, merged)) {
            return; // nothing raised (e.g. a timeout retransmit) — skip the fsync
        }

        let mut batch = WriteBatch::default();
        batch_put::<SafeVoteRegistersCf>(
            &mut batch,
            SafeVoteRegistersCf::handle(&self.cf()),
            &validator,
            &(origin, merged),
        );
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .write_opt(batch, &write_opts)
            .expect("BFT CRITICAL: safe-vote register write failed");

        cache.insert(validator, (origin, merged));
    }

    fn safe_vote_registers(&self, validator: ValidatorId) -> Option<SafeVoteRegisters> {
        let (origin, registers) = self.cf_get::<SafeVoteRegistersCf>(&validator)?;
        (origin == read_chain_origin(&*self.db)).then_some(registers)
    }
}
