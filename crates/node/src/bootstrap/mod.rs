//! Sans-io shard bootstrap sequencer.
//!
//! Composes the two snap-sync assemblers into the full bootstrap a
//! joining vnode runs against its beacon-attested boundary anchor:
//!
//! 1. **Witness history** — [`WitnessHistorySync`] assembles the anchor
//!    window's leaf payloads, bound to the anchor through the boundary
//!    header;
//! 2. **State** — [`SnapSync`] reconstructs the shard's committed state
//!    from verified range chunks;
//! 3. **Import** — the assembled leaves and the witness window surface
//!    as data ([`ShardBootstrap::take_import`]); the driver writes both
//!    through `BoundaryStore::import_boundary_state` in one atomic
//!    import and feeds the resulting root back, which the sequencer
//!    checks against the anchor;
//! 4. **Complete** — the verified pieces assemble into the
//!    [`RecoveredState`] the shard's state machines boot from.
//!
//! Sans-io: drivers own transport, pacing, and the import write. The
//! production runner pumps it with async requests; the simulation steps
//! it deterministically — both run this exact sequencing.

pub mod snap_sync;
pub mod state_range_serve;
pub mod witness_history;
pub mod witness_history_serve;

use hyperscale_engine::{GenesisConfig, prepared_genesis};
use hyperscale_storage::{
    GenesisCommit, ImportLeaf, RecoveredState, ShardChainReader, WitnessSeed,
};
use hyperscale_types::network::request::{GetStateRangeRequest, GetWitnessHistoryRequest};
use hyperscale_types::network::response::{
    GetStateRangeResponse, GetWitnessHistoryResponse, MAX_LEAVES_PER_STATE_RANGE,
};
use hyperscale_types::{
    BlockHeader, BlockHeight, Hash, MAX_WITNESSES_PER_FETCH, NetworkDefinition, ShardAnchor,
    ShardId, ShardWitnessPayload, StateRoot, shard_prefix_path,
};

use self::snap_sync::SnapSync;
use self::witness_history::WitnessHistorySync;

/// Replicate the network's engine bootstrap into a store created after
/// network genesis — a mobility joiner or a split observer — before its
/// authenticated span imports.
///
/// Every genesis-born store carries the full bootstrap on its substate
/// side for read availability (`install_engine_genesis` writes it
/// unfiltered while the JMT takes only the shard's prefix subtree), and
/// transaction execution assumes it on every store: the engine's
/// implicit reads — system packages, the intent-hash tracker — resolve
/// locally, never through provisions. Balances are stripped: account
/// state is authenticated and arrives through the span import, which
/// overwrites the replicated values for keys inside the store's prefix.
///
/// # Panics
///
/// Panics if `storage` already has committed blocks — the replication
/// would regress an evolved substate side to its birth values.
pub fn replicate_engine_bootstrap<S>(
    storage: &S,
    network: &NetworkDefinition,
    genesis_config: &GenesisConfig,
) where
    S: GenesisCommit + ShardChainReader,
{
    assert_eq!(
        storage.committed_height(),
        BlockHeight::GENESIS,
        "engine bootstrap replication requires a store with no committed blocks"
    );
    let mut config = genesis_config.clone();
    config.xrd_balances.clear();
    let bootstrap = prepared_genesis(network, &config);
    storage.replicate_genesis_substates(&bootstrap);
}

/// The identity of the network's engine bootstrap.
///
/// What [`replicate_engine_bootstrap`] needs to rebuild it for a fresh
/// store. Drivers that open stores long after startup (the production
/// shard supervisor) carry one of these instead of the raw pair.
#[derive(Clone)]
pub struct EngineBootstrap {
    /// Network the engine was bootstrapped for.
    pub network: NetworkDefinition,
    /// The network-birth genesis config. Balances are stripped at
    /// replication; only the shared system state matters.
    pub config: GenesisConfig,
}

impl EngineBootstrap {
    /// [`replicate_engine_bootstrap`] with this identity.
    pub fn replicate_into<S>(&self, storage: &S)
    where
        S: GenesisCommit + ShardChainReader,
    {
        replicate_engine_bootstrap(storage, &self.network, &self.config);
    }
}

/// State sub-range fan-out: `2^4 = 16` concurrent range fetches.
pub(crate) const SPLIT_BITS: u8 = 4;

#[allow(clippy::cast_possible_truncation)] // compile-time cap, far below u32::MAX
pub(crate) const STATE_CHUNK_LIMIT: u32 = MAX_LEAVES_PER_STATE_RANGE as u32;

#[allow(clippy::cast_possible_truncation)] // compile-time cap, far below u32::MAX
const WITNESS_PAGE_LIMIT: u32 = MAX_WITNESSES_PER_FETCH as u32;

/// One outbound request the bootstrap wants in flight. The driver
/// routes it to the target shard's committee and feeds the response
/// back through the matching `on_*` method.
#[derive(Debug)]
pub enum BootstrapRequest {
    /// A state range fetch for the sub-range identified by the id the
    /// driver must echo into [`ShardBootstrap::on_state_range`].
    StateRange(usize, GetStateRangeRequest),
    /// A witness-history page fetch.
    WitnessHistory(GetWitnessHistoryRequest),
}

/// Outcome of feeding one response into the sequencer or one of its
/// inner assemblers.
#[derive(Debug, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// Response verified and absorbed.
    Accepted,
    /// Response rejected; the driver should penalize the peer and
    /// rotate. The affected work is re-armed and re-emitted by the
    /// next [`ShardBootstrap::next_requests`].
    Rejected(&'static str),
}

enum Phase {
    /// Assembling the beacon-witness history.
    Witness(Box<WitnessHistorySync>),
    /// Assembling the shard's committed state.
    State(SnapSync),
    /// Leaves assembled and chunk-verified, waiting for the driver to
    /// take them (with the witness window) for the store import.
    ImportReady(Vec<ImportLeaf>),
    /// Driver took the import; waiting for the imported root.
    Importing,
    /// Everything verified against the anchor.
    Complete,
}

/// The witness phase's verified output: the anchor-bound boundary
/// header, the derived leaf hashes that seed the accumulator, and the
/// payloads the store import seeds — taken by [`ShardBootstrap::take_import`].
struct VerifiedWitnessWindow {
    header: Box<BlockHeader>,
    hashes: Vec<Hash>,
    payloads: Vec<ShardWitnessPayload>,
}

/// Sequencing state for one shard bootstrap.
pub struct ShardBootstrap {
    shard: ShardId,
    anchor: ShardAnchor,
    phase: Phase,
    /// The verified witness window; set when the witness phase
    /// completes, its payloads move into the import.
    witness: Option<VerifiedWitnessWindow>,
    /// Total value bytes across the leaves handed to the driver for the
    /// store import — the imported substate byte total, identical to the
    /// total the store seeds at the anchor height. Seeds the recovered
    /// state's byte frontier.
    imported_substate_bytes: u64,
}

impl ShardBootstrap {
    /// Start a bootstrap against `anchor` for `shard`. The witness
    /// history assembles first — it serves from the live chain and its
    /// payloads ride the state import — then the state fan-out.
    #[must_use]
    pub fn new(shard: ShardId, anchor: ShardAnchor) -> Self {
        Self {
            shard,
            anchor,
            phase: Phase::Witness(Box::new(WitnessHistorySync::new(
                anchor,
                WITNESS_PAGE_LIMIT,
            ))),
            witness: None,
            imported_substate_bytes: 0,
        }
    }

    /// Start a state-only assembly against `anchor` — no witness
    /// history. A merge keeper collects a terminating child's span this
    /// way: the reformed parent's witness domain starts fresh, so the
    /// import seeds no window and [`Self::take_import`]'s seed is empty.
    #[must_use]
    pub fn state_only(shard: ShardId, anchor: ShardAnchor) -> Self {
        Self {
            shard,
            anchor,
            phase: Phase::State(SnapSync::new(
                anchor,
                shard_prefix_path(shard),
                SPLIT_BITS,
                STATE_CHUNK_LIMIT,
            )),
            witness: None,
            imported_substate_bytes: 0,
        }
    }

    /// The anchor this bootstrap verifies against.
    #[must_use]
    pub const fn anchor(&self) -> ShardAnchor {
        self.anchor
    }

    /// Every request the current phase wants in flight. Empty while
    /// requests are outstanding, an import is pending, or the bootstrap
    /// is complete.
    pub fn next_requests(&mut self) -> Vec<BootstrapRequest> {
        match &mut self.phase {
            Phase::Witness(witness) => witness
                .next_request()
                .map(BootstrapRequest::WitnessHistory)
                .into_iter()
                .collect(),
            Phase::State(snap) => snap
                .next_requests()
                .into_iter()
                .map(|(id, request)| BootstrapRequest::StateRange(id, request))
                .collect(),
            Phase::ImportReady(_) | Phase::Importing | Phase::Complete => Vec::new(),
        }
    }

    /// Feed one state range response for `sub_range`. After the final
    /// chunk the assembled leaves become available via
    /// [`Self::take_import`].
    pub fn on_state_range(
        &mut self,
        sub_range: usize,
        response: &GetStateRangeResponse,
    ) -> BootstrapOutcome {
        let Phase::State(snap) = &mut self.phase else {
            return BootstrapOutcome::Rejected("state response outside the state phase");
        };
        let outcome = snap.on_response(sub_range, response);
        if snap.is_complete() {
            self.phase = Phase::ImportReady(snap.take_leaves());
        }
        outcome
    }

    /// Re-arm a state sub-range after a transport-level failure.
    pub fn on_state_range_failure(&mut self, sub_range: usize) {
        if let Phase::State(snap) = &mut self.phase {
            snap.on_failure(sub_range);
        }
    }

    /// The fully assembled, chunk-verified leaves plus the verified
    /// witness window, ready for `BoundaryStore::import_boundary_state`
    /// at the anchor height. `Some` exactly once; the driver answers
    /// with the imported root via [`Self::on_imported`].
    pub fn take_import(&mut self) -> Option<(BlockHeight, Vec<ImportLeaf>, WitnessSeed)> {
        let Phase::ImportReady(leaves) = &mut self.phase else {
            return None;
        };
        let leaves = std::mem::take(leaves);
        self.phase = Phase::Importing;
        self.imported_substate_bytes = leaves.iter().map(|l| l.value.len() as u64).sum();
        // A full bootstrap seeds the verified window; a state-only one
        // ([`Self::state_only`]) has none and seeds nothing.
        let seed = self
            .witness
            .as_mut()
            .map_or_else(WitnessSeed::default, |window| WitnessSeed {
                base: window.header.beacon_witness_base(),
                payloads: std::mem::take(&mut window.payloads),
            });
        Some((self.anchor.height, leaves, seed))
    }

    /// Verify the imported root against the attested anchor and
    /// complete the bootstrap.
    ///
    /// # Errors
    ///
    /// Returns a description when `root` diverges from the anchor — the
    /// store now holds an import that can never verify; the bootstrap
    /// is unrecoverable on this store.
    ///
    /// # Panics
    ///
    /// Panics unless the import was taken via [`Self::take_import`].
    pub fn on_imported(&mut self, root: StateRoot) -> Result<(), String> {
        assert!(
            matches!(self.phase, Phase::Importing),
            "on_imported outside the import phase",
        );
        if root != self.anchor.state_root {
            return Err(format!(
                "imported root {root:?} does not match attested anchor {:?}",
                self.anchor.state_root,
            ));
        }
        self.phase = Phase::Complete;
        Ok(())
    }

    /// Feed one witness-history response. After the final page the
    /// verified window is held for the import and the state fan-out
    /// opens.
    pub fn on_witness_history(&mut self, response: &GetWitnessHistoryResponse) -> BootstrapOutcome {
        let Phase::Witness(witness) = &mut self.phase else {
            return BootstrapOutcome::Rejected("witness response outside the witness phase");
        };
        let outcome = witness.on_response(response);
        if witness.is_complete() {
            let (header, payloads) = witness.take_parts();
            self.witness = Some(VerifiedWitnessWindow {
                hashes: payloads
                    .iter()
                    .map(ShardWitnessPayload::leaf_hash)
                    .collect(),
                header: Box::new(header),
                payloads,
            });
            self.phase = Phase::State(SnapSync::new(
                self.anchor,
                shard_prefix_path(self.shard),
                SPLIT_BITS,
                STATE_CHUNK_LIMIT,
            ));
        }
        outcome
    }

    /// Re-arm the witness fetch after a transport-level failure.
    pub fn on_witness_history_failure(&mut self) {
        if let Phase::Witness(witness) = &mut self.phase {
            witness.on_failure();
        }
    }

    /// Whether nothing has been imported into the store yet — the
    /// witness and state assemblies — the phases at which restarting
    /// against a newer anchor is sound.
    #[must_use]
    pub const fn pre_import(&self) -> bool {
        matches!(self.phase, Phase::Witness(_) | Phase::State(_))
    }

    /// Whether every phase has completed and verified.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.phase, Phase::Complete)
    }

    /// The [`RecoveredState`] a snap-synced joiner boots from: tip at
    /// the anchor, committee anchor from the boundary header, witness
    /// accumulator seeded with the verified history.
    ///
    /// # Panics
    ///
    /// Panics unless [`Self::is_complete`].
    #[must_use]
    pub fn into_recovered_state(self) -> RecoveredState {
        assert!(
            matches!(self.phase, Phase::Complete),
            "bootstrap recovery taken before completion",
        );
        let window = self
            .witness
            .expect("a complete bootstrap holds its verified witness window");
        RecoveredState::from_snap_synced_boundary(
            &self.anchor,
            &window.header,
            window.hashes,
            self.imported_substate_bytes,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::{pin_snap_sync_replica, stake_deposit};
    use hyperscale_storage::{BoundaryStore, PendingChain, SubstateStore};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::ShardWitnessPayload;

    use super::*;
    use crate::bootstrap::state_range_serve::serve_state_range_request;
    use crate::bootstrap::witness_history_serve::serve_witness_history_request;

    const ENTRIES: u8 = 12;

    /// A committed replica: `ENTRIES` substate blocks, then a boundary
    /// block whose header carries the witness commitment over `leaves`,
    /// pinned for serving.
    fn replica(leaves: &[ShardWitnessPayload]) -> (Arc<SimShardStorage>, ShardAnchor) {
        let storage = SimShardStorage::default();
        let anchor = pin_snap_sync_replica(&storage, ENTRIES, leaves);
        (Arc::new(storage), anchor)
    }

    /// Drive the sequencer to completion against `serving`, importing
    /// into `fresh` when the import surfaces.
    fn drive(
        bootstrap: &mut ShardBootstrap,
        serving: &Arc<SimShardStorage>,
        pending_chain: &PendingChain<SimShardStorage>,
        fresh: &SimShardStorage,
    ) {
        for _ in 0..1_000 {
            if bootstrap.is_complete() {
                return;
            }
            for request in bootstrap.next_requests() {
                match request {
                    BootstrapRequest::StateRange(id, request) => {
                        let response = serve_state_range_request(serving, &request);
                        assert_eq!(
                            bootstrap.on_state_range(id, &response),
                            BootstrapOutcome::Accepted,
                        );
                    }
                    BootstrapRequest::WitnessHistory(request) => {
                        let response = serve_witness_history_request(pending_chain, &request);
                        assert_eq!(
                            bootstrap.on_witness_history(&response),
                            BootstrapOutcome::Accepted,
                        );
                    }
                }
            }
            if let Some((height, leaves, witnesses)) = bootstrap.take_import() {
                let root = fresh
                    .import_boundary_state(height, leaves, witnesses)
                    .unwrap();
                bootstrap.on_imported(root).unwrap();
            }
        }
        panic!("bootstrap did not complete");
    }

    fn witness_leaves() -> Vec<ShardWitnessPayload> {
        (1u64..=5).map(stake_deposit).collect()
    }

    /// The full sequencing: state fan-out, import + root check against
    /// the anchor, witness history, and the seeded recovery.
    #[test]
    fn sequences_state_import_and_witness_history() {
        let leaves = witness_leaves();
        let (serving, anchor) = replica(&leaves);
        let pending_chain = PendingChain::new(Arc::clone(&serving));
        let fresh = Arc::new(SimShardStorage::default());

        let mut bootstrap = ShardBootstrap::new(ShardId::ROOT, anchor);
        drive(&mut bootstrap, &serving, &pending_chain, &fresh);

        let recovered = bootstrap.into_recovered_state();
        assert_eq!(recovered.committed_height, anchor.height);
        assert_eq!(recovered.committed_hash, Some(anchor.block_hash));
        assert_eq!(recovered.jmt_root, Some(anchor.state_root));
        let expected_hashes: Vec<Hash> =
            leaves.iter().map(ShardWitnessPayload::leaf_hash).collect();
        assert_eq!(recovered.beacon_witness_leaf_hashes, expected_hashes);
        assert_eq!(fresh.state_root(), anchor.state_root);

        // The import seeded the anchor window's payloads: the store
        // rebuilds its accumulator across a restart and answers the
        // beacon fold's witness fetches, without ever having executed
        // the pre-anchor chain.
        assert_eq!(
            PendingChain::new(Arc::clone(&fresh))
                .get_beacon_witness_payload_range(0, leaves.len() as u64),
            leaves,
        );
        assert_eq!(
            fresh.load_recovered_state().beacon_witness_leaf_hashes,
            expected_hashes,
        );
    }

    /// A diverging import root is terminal: the store holds an import
    /// that can never verify.
    #[test]
    fn import_root_mismatch_is_an_error() {
        let (serving, anchor) = replica(&[]);
        let pending_chain = PendingChain::new(Arc::clone(&serving));
        let mut bootstrap = ShardBootstrap::new(ShardId::ROOT, anchor);
        let mut imported = false;
        for _ in 0..1_000 {
            for request in bootstrap.next_requests() {
                match request {
                    BootstrapRequest::StateRange(id, request) => {
                        let response = serve_state_range_request(&serving, &request);
                        bootstrap.on_state_range(id, &response);
                    }
                    BootstrapRequest::WitnessHistory(request) => {
                        let response = serve_witness_history_request(&pending_chain, &request);
                        bootstrap.on_witness_history(&response);
                    }
                }
            }
            if bootstrap.take_import().is_some() {
                imported = true;
                break;
            }
        }
        assert!(imported, "state assembly never reached the import");
        assert!(
            bootstrap
                .on_imported(StateRoot::from_raw(Hash::from_bytes(
                    b"not_the_anchor_root"
                )))
                .is_err()
        );
    }

    /// Phase gating: responses outside their phase are rejected without
    /// disturbing the sequencing.
    #[test]
    fn out_of_phase_responses_are_rejected() {
        let (serving, anchor) = replica(&[]);
        let pending_chain = PendingChain::new(Arc::clone(&serving));

        let mut bootstrap = ShardBootstrap::new(ShardId::ROOT, anchor);
        // Still in the witness phase: a state response is unsolicited.
        let state_request = GetStateRangeRequest {
            height: anchor.height,
            start: Hash::ZERO,
            end: Hash::ZERO,
            limit: 16,
        };
        let response = serve_state_range_request(&serving, &state_request);
        assert!(matches!(
            bootstrap.on_state_range(0, &response),
            BootstrapOutcome::Rejected(_),
        ));
        let _ = pending_chain;
        assert!(!bootstrap.next_requests().is_empty());
    }
}
