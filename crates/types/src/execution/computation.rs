//! Tick-leader selection.

use hyperscale_hbor::to_vec as hbor_to_vec;

use crate::{Attempt, Hash, TickId, ValidatorId};

/// Deterministically select the tick leader for a tick.
///
/// The tick leader collects the committee's first execution votes,
/// aggregates the EC, and broadcasts it to local peers and remote shards.
/// A vote that has not certified is retried to the whole attesting
/// committee instead, so the leader is drawn once per tick.
///
/// Uses `Hash(encode(tick_id) ++ Attempt::INITIAL.to_le_bytes()) %
/// committee_size` for deterministic selection. All validators compute the
/// same result.
///
/// # Panics
///
/// Panics if `committee` is empty.
#[must_use]
pub fn tick_leader(tick_id: &TickId, committee: &[ValidatorId]) -> ValidatorId {
    assert!(!committee.is_empty(), "committee must not be empty");
    let mut buf = hbor_to_vec(tick_id).expect("TickId serialization should never fail");
    buf.extend_from_slice(&Attempt::INITIAL.to_le_bytes());
    let selection_hash = Hash::from_bytes(&buf);
    let bytes = selection_hash.as_bytes();
    let index_val = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let index = usize::try_from(index_val % committee.len() as u64)
        .expect("modulo of usize len fits in usize");
    committee[index]
}
