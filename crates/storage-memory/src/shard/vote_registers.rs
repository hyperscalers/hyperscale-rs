//! Durable safe-vote registers — `SafeVoteRegisterStore` for
//! [`SimShardStorage`].
//!
//! Records live exactly as long as the store handle, which is what a
//! simulated restart preserves: dropping a coordinator and rebuilding
//! it over the same `SimShardStorage` models a crash that loses process
//! memory but keeps disk.

use std::sync::Arc;

use hyperscale_storage::SafeVoteRegisterStore;
use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_types::{
    Block, BlockHash, BlockHeight, SafeVoteRegisters, ValidatorId, VotePosition,
};

use super::core::SimShardStorage;
use crate::crash_point;

impl SafeVoteRegisterStore for SimShardStorage {
    fn persist_vote_position(&self, validator: ValidatorId, position: &VotePosition) {
        crash_point::write();
        let mut c = write_or_recover(&self.consensus);
        let origin = c.chain_origin;
        let merged = match c.safe_vote_registers.get(&validator) {
            Some((stored_origin, stored_registers)) if *stored_origin == origin => {
                position.registers.clone().max((**stored_registers).clone())
            }
            _ => position.registers.clone(),
        };
        c.safe_vote_registers
            .insert(validator, (origin, Arc::new(merged)));
        for block in &position.justification {
            c.voted_blocks
                .insert((block.height(), block.hash()), (origin, Arc::clone(block)));
        }
    }

    fn voted_blocks_above(&self, committed_height: BlockHeight) -> Vec<Arc<Block>> {
        let c = read_or_recover(&self.consensus);
        c.voted_blocks
            .range((committed_height.next(), BlockHash::ZERO)..)
            .filter(|(_, (origin, _))| *origin == c.chain_origin)
            .map(|(_, (_, block))| Arc::clone(block))
            .collect()
    }

    fn safe_vote_registers(&self, validator: ValidatorId) -> Option<SafeVoteRegisters> {
        let c = read_or_recover(&self.consensus);
        let (origin, registers) = c.safe_vote_registers.get(&validator)?;
        (*origin == c.chain_origin).then(|| (**registers).clone())
    }
}
