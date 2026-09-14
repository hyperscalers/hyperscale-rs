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

use hyperscale_storage::{AdoptSource, BoundaryStore, RecoveredState};
use hyperscale_types::{Block, ChainOrigin, PredecessorTerminal, ShardId, StateRoot, SubstateKey};

use super::orchestrator::AdoptKind;

/// Install a reshape duty's derived `genesis` into its prepared store and
/// gate the adopted root against the one the genesis names.
///
/// Returns the [`RecoveredState`] the seat boots from.
/// The store-level adopt differs per duty — [`AdoptKind::Split`] adopts the
/// observer's followed store, [`AdoptKind::ParentHalf`] the
/// checkpoint-cloned child subtree, [`AdoptKind::Merge`] the composed parent
/// union — but every kind verifies against the genesis block's own root.
/// Each genesis composes from terminal blocks its duty commit-proved: a
/// split reads the terminal's `split_child_roots`, checked to compose to
/// that block's own committed state root; a merge composes the two
/// children's terminal roots, each attested by its own chain. Neither pair
/// can name a subtree no terminal committed, so the store either holds what
/// the genesis names or the duty must not seat.
///
/// # Errors
///
/// Returns a description when the store-level adopt fails, or when the
/// adopted root does not match the genesis's — the store does not hold the
/// subtree the genesis names.
pub fn adopt_prepared_store<S: BoundaryStore>(
    storage: &S,
    shard: ShardId,
    kind: AdoptKind,
    origin: ChainOrigin,
    genesis: &Block,
    predecessors: Vec<PredecessorTerminal>,
) -> Result<RecoveredState, String> {
    let source = match kind {
        AdoptKind::Split => AdoptSource::FollowedTip,
        AdoptKind::ParentHalf => AdoptSource::ParentSubtree,
        AdoptKind::Merge => AdoptSource::InPlace,
    };
    let adopted = storage
        .adopt_genesis(origin, genesis, source)
        .map_err(|e| format!("reshape adoption: {e}"))?;
    let substate_bytes = storage
        .substate_bytes_at_version(origin.genesis_height.inner())
        .unwrap_or(0);
    // A seat's obligations come from the leaves it imported and from
    // nothing else, whichever way it was seated. The value a predecessor
    // escrowed arrives with the prefix and no chain here names it: a
    // merged parent's chain begins at the import, a memory clone holds
    // no blocks at all, and the predecessor drops its ledger at the cut.
    // So the state is the authority for every kind, and it is what every
    // keeper imported.
    //
    // A cloned store carrying the predecessor's blocks composes nothing
    // twice on top of this: the replay walk stops at this chain's own
    // origin, so it never reaches a block the predecessor committed.
    let escrow_records = storage.escrow_records(shard);
    verified_recovered_state(
        adopted,
        genesis.header().state_root(),
        origin,
        substate_bytes,
        predecessors,
        escrow_records,
    )
}

/// Accept a reshape adoption, gating it against the root its genesis names.
///
/// Checks the store's `adopted` root against `expected` and builds the
/// [`RecoveredState`] the seat boots from over `origin` and the adopted
/// `substate_bytes`.
fn verified_recovered_state(
    adopted: StateRoot,
    expected: StateRoot,
    origin: ChainOrigin,
    substate_bytes: u64,
    predecessors: Vec<PredecessorTerminal>,
    escrow_records: Vec<(SubstateKey, Vec<u8>)>,
) -> Result<RecoveredState, String> {
    if adopted != expected {
        return Err(format!(
            "adopted reshape root {adopted:?} does not match the genesis's {expected:?}"
        ));
    }
    Ok(RecoveredState {
        substate_bytes,
        chain_origin: origin,
        predecessors,
        escrow_records,
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
        let recovered =
            verified_recovered_state(root, root, origin(), 4_096, Vec::new(), Vec::new())
                .expect("matches");
        assert_eq!(recovered.substate_bytes, 4_096);
        assert_eq!(recovered.chain_origin, origin());
    }

    #[test]
    fn diverged_root_fails_closed() {
        let adopted = StateRoot::from_raw(Hash::from_bytes(b"adopted"));
        let expected = StateRoot::from_raw(Hash::from_bytes(b"beacon"));
        assert!(
            verified_recovered_state(adopted, expected, origin(), 0, Vec::new(), Vec::new())
                .is_err()
        );
    }
}
