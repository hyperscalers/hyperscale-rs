//! Durable safe-vote registers — `SafeVoteRegisterStore` for
//! [`SimShardStorage`].
//!
//! Records live exactly as long as the store handle, which is what a
//! simulated restart preserves: dropping a coordinator and rebuilding
//! it over the same `SimShardStorage` models a crash that loses process
//! memory but keeps disk.

use hyperscale_storage::SafeVoteRegisterStore;
use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_types::{SafeVoteRegisters, ValidatorId};

use super::core::SimShardStorage;

impl SafeVoteRegisterStore for SimShardStorage {
    fn persist_safe_vote_registers(&self, validator: ValidatorId, registers: SafeVoteRegisters) {
        let mut c = write_or_recover(&self.consensus);
        let origin = c.chain_origin;
        let merged = match c.safe_vote_registers.get(&validator) {
            Some((stored_origin, stored_registers)) if *stored_origin == origin => {
                registers.max(*stored_registers)
            }
            _ => registers,
        };
        c.safe_vote_registers.insert(validator, (origin, merged));
    }

    fn safe_vote_registers(&self, validator: ValidatorId) -> Option<SafeVoteRegisters> {
        let c = read_or_recover(&self.consensus);
        let (origin, registers) = c.safe_vote_registers.get(&validator)?;
        (*origin == c.chain_origin).then_some(*registers)
    }
}
