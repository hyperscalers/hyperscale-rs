//! Durable safe-vote registers — `SafeVoteRegisterStore` for
//! [`RocksDbShardStorage`].

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_storage::SafeVoteRegisterStore;
use hyperscale_types::{
    Block, BlockHash, BlockHeight, SafeVoteRegisters, ValidatorId, VotePosition,
};
use rocksdb::{WriteBatch, WriteOptions};

use super::column_families::{SafeVoteRegistersCf, VotedBlocksCf};
use super::core::RocksDbShardStorage;
use super::metadata::read_chain_origin;
use crate::typed_cf::{TypedCf, batch_put, iter_all, iter_from};

impl SafeVoteRegisterStore for RocksDbShardStorage {
    fn persist_vote_position(&self, validator: ValidatorId, position: &VotePosition) {
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
            .cloned()
            .or_else(|| self.cf_get::<SafeVoteRegistersCf>(&validator));
        let merged = match &stored {
            // A record from a different chain incarnation is dead
            // weight — overwrite it rather than merging round numbers
            // that belong to an unrelated chain.
            Some((stored_origin, stored_registers)) if *stored_origin == origin => {
                position.registers.clone().max(stored_registers.clone())
            }
            _ => position.registers.clone(),
        };
        if stored.as_ref() == Some(&(origin, merged.clone())) && position.justification.is_empty() {
            return; // nothing raised (e.g. a timeout retransmit) — skip the fsync
        }

        let cf = self.cf();
        let mut batch = WriteBatch::default();
        batch_put::<SafeVoteRegistersCf>(
            &mut batch,
            SafeVoteRegistersCf::handle(&cf),
            &validator,
            &(origin, merged.clone()),
        );
        // Same batch as the record: a lock whose justification did not
        // survive the crash is one its holder can never satisfy again.
        let voted_blocks_cf = VotedBlocksCf::handle(&cf);
        for block in &position.justification {
            batch_put::<VotedBlocksCf>(
                &mut batch,
                voted_blocks_cf,
                &(block.height(), block.hash()),
                &(origin, (**block).clone()),
            );
        }
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .write_opt(batch, &write_opts)
            .expect("BFT CRITICAL: safe-vote register write failed");

        cache.insert(validator, (origin, merged));
    }

    fn voted_blocks_above(&self, committed_height: BlockHeight) -> Vec<Arc<Block>> {
        let origin = read_chain_origin(&*self.db);
        let cf = self.cf();
        iter_from::<VotedBlocksCf>(
            &self.db,
            VotedBlocksCf::handle(&cf),
            &(committed_height.next(), BlockHash::ZERO),
        )
        .filter(|(_, (tag, _))| *tag == origin)
        .map(|(_, (_, block))| Arc::new(block))
        .collect()
    }

    fn safe_vote_registers(&self, validator: ValidatorId) -> Option<SafeVoteRegisters> {
        let (origin, registers) = self.cf_get::<SafeVoteRegistersCf>(&validator)?;
        (origin == read_chain_origin(&*self.db)).then_some(registers)
    }

    fn all_safe_vote_registers(&self) -> BTreeMap<ValidatorId, SafeVoteRegisters> {
        let origin = read_chain_origin(&*self.db);
        let cf = self.cf();
        iter_all::<SafeVoteRegistersCf>(&self.db, SafeVoteRegistersCf::handle(&cf))
            .filter_map(|(validator, (record_origin, registers))| {
                (record_origin == origin).then_some((validator, registers))
            })
            .collect()
    }
}
