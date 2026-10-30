//! The shared reshape-adoption gate.
//!
//! Every reshape duty — a split parent half, a split observer, a merge keeper —
//! installs its derived genesis into a prepared store, then checks the adopted
//! root against the state root the genesis names before trusting it: a match
//! means the store holds the subtree the genesis commits to; a mismatch means
//! the store has diverged from it and the duty must fail closed.
//! [`adopt_prepared_store`] runs the whole sequence — the per-duty
//! [`BoundaryStore`] adopt call, the expected-root selection, and the
//! acceptance check — so both harnesses call one gate rather than
//! re-deriving any part of it.

use hyperscale_storage::{AdoptSource, BoundaryStore, MemberIndex, RecoveredState};
use hyperscale_types::{Anchor, ChainOrigin, ReadFrontier, ShardId, StateRoot};

use super::genesis::DerivedGenesis;
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
/// Returns a description when the store-level adopt fails, when the
/// adopted root does not match the genesis's — the store does not hold the
/// subtree the genesis names — or when the store records no substate byte
/// total at the genesis height.
pub fn adopt_prepared_store<S: BoundaryStore>(
    storage: &S,
    shard: ShardId,
    kind: AdoptKind,
    genesis: &DerivedGenesis,
) -> Result<RecoveredState, String> {
    let DerivedGenesis {
        block: genesis,
        origin,
        predecessors,
    } = genesis;
    let origin = *origin;
    let source = match kind {
        AdoptKind::Split => AdoptSource::FollowedTip,
        AdoptKind::ParentHalf => AdoptSource::ParentSubtree,
        AdoptKind::Merge => AdoptSource::InPlace,
    };
    let adopted = storage
        .adopt_genesis(origin, genesis, source)
        .map_err(|e| format!("reshape adoption: {e}"))?;
    let substate_bytes = storage.substate_bytes_at_version(origin.genesis_height.inner());
    let read_frontier = storage.read_frontier(shard);
    let members = storage.member_index(shard);
    verified_recovered_state(
        adopted,
        genesis.header().state_root(),
        origin,
        substate_bytes,
        predecessors.clone(),
        read_frontier,
        members,
    )
}

/// Accept a reshape adoption, gating it against the root its genesis names.
///
/// Checks the store's `adopted` root against `expected` and builds the
/// [`RecoveredState`] the seat boots from over `origin` and the adopted
/// `substate_bytes`. The byte total seeds the frontier the seat's
/// `substate_bytes` header claims build on, so a store that recorded none
/// at the genesis version fails the adoption rather than claiming zero.
fn verified_recovered_state(
    adopted: StateRoot,
    expected: StateRoot,
    origin: ChainOrigin,
    substate_bytes: Option<u64>,
    predecessors: Vec<Anchor>,
    read_frontier: ReadFrontier,
    members: MemberIndex,
) -> Result<RecoveredState, String> {
    if adopted != expected {
        return Err(format!(
            "adopted reshape root {adopted:?} does not match the genesis's {expected:?}"
        ));
    }
    let substate_bytes = substate_bytes.ok_or_else(|| {
        format!(
            "adopted reshape store records no substate byte total at its genesis height {}",
            origin.genesis_height,
        )
    })?;
    Ok(RecoveredState {
        substate_bytes,
        chain_origin: Some(origin),
        predecessors,
        read_frontier,
        members: Some(members),
        ..RecoveredState::default()
    })
}

#[cfg(test)]
mod tests {
    use hyperscale_storage::MemberIndex;
    use hyperscale_types::{
        BlockHeight, ChainOrigin, Epoch, Hash, ReadFrontier, ReadMark, ShardId, StateRoot,
        WeightedTimestamp,
    };

    use super::verified_recovered_state;

    fn origin() -> ChainOrigin {
        ChainOrigin {
            genesis_height: BlockHeight::new(10),
            anchor_wt: WeightedTimestamp::ZERO,
        }
    }

    /// A seat boots from the root it adopted, and carries the read
    /// frontier the adopted state holds into the coordinator's copy.
    #[test]
    fn matching_root_yields_the_seat_state() {
        let root = StateRoot::from_raw(Hash::from_bytes(b"adopted"));
        let read_frontier = ReadFrontier::from_entries([(
            ShardId::leaf(1, 1),
            ReadMark {
                epoch: Epoch::new(2),
                height: BlockHeight::new(40),
            },
        )]);
        let recovered = verified_recovered_state(
            root,
            root,
            origin(),
            Some(4_096),
            Vec::new(),
            read_frontier.clone(),
            MemberIndex::empty(ShardId::ROOT),
        )
        .expect("matches");
        assert_eq!(recovered.substate_bytes, 4_096);
        assert_eq!(recovered.chain_origin, Some(origin()));
        assert_eq!(recovered.read_frontier, read_frontier);
    }

    #[test]
    fn diverged_root_fails_closed() {
        let adopted = StateRoot::from_raw(Hash::from_bytes(b"adopted"));
        let expected = StateRoot::from_raw(Hash::from_bytes(b"beacon"));
        assert!(
            verified_recovered_state(
                adopted,
                expected,
                origin(),
                Some(0),
                Vec::new(),
                ReadFrontier::default(),
                MemberIndex::empty(ShardId::ROOT),
            )
            .is_err()
        );
    }

    /// The byte total seeds the seat's `substate_bytes` frontier, so a
    /// store with none at the genesis version fails closed rather than
    /// claiming an empty state.
    #[test]
    fn a_missing_byte_total_fails_closed() {
        let root = StateRoot::from_raw(Hash::from_bytes(b"adopted"));
        assert!(
            verified_recovered_state(
                root,
                root,
                origin(),
                None,
                Vec::new(),
                ReadFrontier::default(),
                MemberIndex::empty(ShardId::ROOT),
            )
            .is_err()
        );
    }
}
