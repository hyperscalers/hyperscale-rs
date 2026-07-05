//! The shared reshape-adoption gate.
//!
//! Every reshape duty — a split parent half, a split observer, a merge keeper —
//! installs its derived genesis into a prepared store, then checks the adopted
//! root against the beacon-attested anchor before trusting it: a match means the
//! local derivation and the beacon agree; a mismatch means they have diverged
//! and the duty must fail closed. [`adopt_prepared_store`] runs the whole
//! sequence — the per-duty [`BoundaryStore`] adopt call, the expected-root
//! selection, and the acceptance check — so both harnesses call one gate
//! rather than re-deriving any part of it.

use hyperscale_storage::{BoundaryStore, RecoveredState};
use hyperscale_types::{Block, ChainOrigin, StateRoot};

use super::orchestrator::AdoptKind;

/// Install a reshape duty's derived `genesis` into its prepared store and
/// gate the adopted root against the beacon anchor.
///
/// Returns the [`RecoveredState`] the seat boots from.
/// The store-level adopt differs per duty — [`AdoptKind::Split`] adopts the
/// observer's followed store, [`AdoptKind::ParentHalf`] the
/// checkpoint-cloned child subtree, [`AdoptKind::Merge`] the composed parent
/// union — as does the expected root: a followed store verifies against the
/// genesis block's own root (itself reproduced from the parent terminal and
/// the child anchor), while a parent half and a merge verify against the
/// beacon-attested `anchor_root`.
///
/// # Errors
///
/// Returns a description when the store-level adopt fails, when
/// `anchor_root` is `None` for a kind that requires it (the anchor no longer
/// projects), or when the adopted root does not match the expected one — the
/// local derivation and the beacon disagree, so the duty must not seat.
pub fn adopt_prepared_store<S: BoundaryStore>(
    storage: &S,
    kind: AdoptKind,
    origin: ChainOrigin,
    genesis: &Block,
    anchor_root: Option<StateRoot>,
) -> Result<RecoveredState, String> {
    let (adopted, expected) = match kind {
        AdoptKind::Split => (
            storage
                .adopt_followed_child(origin, genesis)
                .map_err(|e| format!("followed adoption: {e}"))?,
            genesis.header().state_root(),
        ),
        AdoptKind::ParentHalf => (
            storage
                .adopt_split_child(origin, genesis)
                .map_err(|e| format!("split child adoption: {e}"))?,
            anchor_root.ok_or("split child anchor no longer projects")?,
        ),
        AdoptKind::Merge => (
            storage
                .adopt_merge_parent(origin, genesis)
                .map_err(|e| format!("merge adoption: {e}"))?,
            anchor_root.ok_or("merge parent anchor no longer projects")?,
        ),
    };
    let substate_bytes = storage
        .substate_bytes_at_version(origin.genesis_height.inner())
        .unwrap_or(0);
    verified_recovered_state(adopted, expected, origin, substate_bytes)
}

/// Accept a reshape adoption, gating it against the beacon anchor.
///
/// Checks the store's `adopted` root against the beacon-attested `expected`
/// anchor root and builds the [`RecoveredState`] the seat boots from over
/// `origin` and the adopted `substate_bytes`.
fn verified_recovered_state(
    adopted: StateRoot,
    expected: StateRoot,
    origin: ChainOrigin,
    substate_bytes: u64,
) -> Result<RecoveredState, String> {
    if adopted != expected {
        return Err(format!(
            "adopted reshape root {adopted:?} does not match the anchor {expected:?}"
        ));
    }
    Ok(RecoveredState {
        substate_bytes,
        chain_origin: origin,
        ..RecoveredState::default()
    })
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BlockHeight, ChainOrigin, Hash, StateRoot, WeightedTimestamp};

    use super::verified_recovered_state;

    fn origin() -> ChainOrigin {
        ChainOrigin {
            genesis_height: BlockHeight::new(10),
            anchor_wt: WeightedTimestamp::ZERO,
        }
    }

    #[test]
    fn matching_root_yields_the_seat_state() {
        let root = StateRoot::from_raw(Hash::from_bytes(b"adopted"));
        let recovered = verified_recovered_state(root, root, origin(), 4_096).expect("matches");
        assert_eq!(recovered.substate_bytes, 4_096);
        assert_eq!(recovered.chain_origin, origin());
    }

    #[test]
    fn diverged_root_fails_closed() {
        let adopted = StateRoot::from_raw(Hash::from_bytes(b"adopted"));
        let expected = StateRoot::from_raw(Hash::from_bytes(b"beacon"));
        assert!(verified_recovered_state(adopted, expected, origin(), 0).is_err());
    }
}
