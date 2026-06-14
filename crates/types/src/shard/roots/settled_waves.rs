//! [`SettledWavesRoot`] computation.
//!
//! The root commits the set of wave-ids a shard settled within its
//! retention window up to a terminal block. A terminating shard carries it
//! on its boundary header; a surviving counterpart fetches the same set and
//! accepts it only when its recomputed root equals the attested one, so the
//! complete set — and therefore the absence of any wave from it — is
//! authenticated.
//!
//! [`SettledWavesRoot`]: crate::SettledWavesRoot

use std::collections::BTreeSet;
use std::sync::Arc;

use sbor::prelude::*;

use crate::{
    FinalizedWave, Hash, SettledWavesRoot, ShardId, Verifiable, WaveId, compute_merkle_root,
};

/// The wave-ids `shard` settled in `certificates`.
///
/// The local execution certificate of each committed wave is the entry
/// keyed on this shard. A block's own shard is `block.header().shard_id()`,
/// so a caller filtering a block's certificates passes that.
#[must_use]
pub fn local_settled_wave_ids<'a>(
    certificates: impl IntoIterator<Item = &'a Arc<Verifiable<FinalizedWave>>>,
    shard: ShardId,
) -> Vec<WaveId> {
    certificates
        .into_iter()
        .flat_map(|fw| fw.certificate().ec_wave_ids())
        .filter(|wave_id| wave_id.shard_id() == shard)
        .collect()
}

/// Domain tag separating a settled-wave merkle leaf from every other
/// leaf preimage the codebase hashes.
const SETTLED_WAVE_LEAF_TAG: &[u8] = b"hyperscale.settled_wave_leaf.v1";

/// The merkle leaf for one settled wave-id.
fn settled_wave_leaf(wave_id: &WaveId) -> Hash {
    let mut preimage = SETTLED_WAVE_LEAF_TAG.to_vec();
    preimage.extend_from_slice(&basic_encode(wave_id).expect("WaveId SBOR encoding never fails"));
    Hash::from_bytes(&preimage)
}

/// Merkle root over a shard's settled wave-ids.
///
/// The ids are taken as a set — sorted by [`WaveId`] order and
/// deduplicated — so the root is a pure function of the membership,
/// independent of the order they were discovered in. Empty →
/// [`SettledWavesRoot::ZERO`].
#[must_use]
pub fn settled_waves_root_from_ids<'a>(
    wave_ids: impl IntoIterator<Item = &'a WaveId>,
) -> SettledWavesRoot {
    let sorted: BTreeSet<&WaveId> = wave_ids.into_iter().collect();
    if sorted.is_empty() {
        return SettledWavesRoot::ZERO;
    }
    let leaves: Vec<Hash> = sorted.into_iter().map(settled_wave_leaf).collect();
    SettledWavesRoot::from_raw(compute_merkle_root(&leaves))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{BlockHeight, ShardId};

    fn wave(shard: u64, height: u64) -> WaveId {
        WaveId::new(
            ShardId::from_heap_index(shard + 1),
            BlockHeight::new(height),
            BTreeSet::new(),
        )
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(
            settled_waves_root_from_ids(std::iter::empty()),
            SettledWavesRoot::ZERO
        );
    }

    #[test]
    fn order_independent_and_deduplicated() {
        let a = wave(0, 1);
        let b = wave(0, 2);
        let c = wave(1, 1);
        let forward = settled_waves_root_from_ids([&a, &b, &c]);
        let shuffled = settled_waves_root_from_ids([&c, &a, &b]);
        let with_dup = settled_waves_root_from_ids([&c, &a, &b, &a, &c]);
        assert_eq!(forward, shuffled);
        assert_eq!(forward, with_dup);
    }

    #[test]
    fn membership_changes_the_root() {
        let a = wave(0, 1);
        let b = wave(0, 2);
        let just_a = settled_waves_root_from_ids([&a]);
        let a_and_b = settled_waves_root_from_ids([&a, &b]);
        assert_ne!(just_a, a_and_b);
        assert_ne!(just_a, SettledWavesRoot::ZERO);
    }
}
