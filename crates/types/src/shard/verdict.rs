//! What a member row has heard of its siblings' verdicts.
//!
//! A shard learns a sibling's verdict on a member they share only from
//! the sibling's committed state, through a state claim a block carries.
//! Each reading is kept on the member's row beside the mark of the
//! anchor it was taken at, one entry per sibling, and the newest reading
//! stands: an entry is replaced only by a reading at a strictly higher
//! mark, whatever either says.

use hyperscale_hbor::{Capped, Hbor};

use crate::{MAX_PREFIXES_PER_TX, ReadMark, ShardId};

/// What a sibling's committed state says of a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum Said {
    /// Its certificate succeeded for the member, among the shards the
    /// reader's own row shares the verdict with.
    Yes,
    /// It applied the member's effects, among those same shards.
    Accepted,
    /// Its verdict cell holds anything else, or it holds no row for the
    /// member and can commit none.
    Left,
}

/// One sibling's newest reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct Heard {
    /// The sibling read.
    pub shard: ShardId,
    /// The anchor the reading was taken at.
    pub mark: ReadMark,
    /// What it said there; `None` where it had stated nothing and could
    /// still commit the member.
    pub said: Option<Said>,
}

/// What a row has heard, at most one entry per sibling its settlement
/// awaits, ascending by shard.
pub type Hearing = Capped<Vec<Heard>, MAX_PREFIXES_PER_TX>;
