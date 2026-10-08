//! Protocol-event passthrough step handlers.
//!
//! `ShardScopedInput::Protocol(_)` is the channel for state-machine events that
//! re-enter `ShardLoop` via `dispatch_event` (continuation-style). Most are pure
//! passthrough — feed the variant straight into the state machine. The
//! one exception is `BlockPersisted`, which carries `ShardLoop`-side commit
//! pipeline state (`block_commit`, `pending_chain`) that needs updating
//! before the state machine sees the event.

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::{BodyHold, FloorInputs, ShardStorage, chain_floor};
use hyperscale_types::BlockHeight;

use crate::shard::ShardLoop;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Update the commit pipeline before forwarding `BlockPersisted` to the
    /// state machine: the persisted height advances `block_commit`'s gate
    /// and `pending_chain`'s pruning watermark, and the event picks up
    /// the authoritative substate byte total from storage so the state
    /// machine's count frontier reconciles even across sync commits.
    pub(in crate::shard) fn handle_block_persisted(&mut self, height: BlockHeight) {
        self.io.block_commit.mark_persisted(height);
        // Drop pending state for blocks now persisted to RocksDB.
        self.io.pending_chain.prune(height);
        self.io.consensus.proposals.prune(height);
        // Evict ticks whose folds the persisted base now fully covers.
        self.hold_execution_baselines(height);
        self.advance_chain_floor();
        // The byte total is written in the same crash-consistent batch as
        // the block's JMT, and `height` is the tip we just persisted, so it
        // is always present. A zero fallback here would silently corrupt the
        // reshape count frontier the state machine reconciles from, so fail
        // loud instead.
        let substate_bytes = self
            .io
            .storage
            .substate_bytes_at(height)
            .expect("the just-persisted height must carry its committed byte total");
        self.dispatch_event(ProtocolEvent::BlockPersisted {
            height,
            substate_bytes,
        });
    }

    /// Hold the tick chain and the store's history at the lowest baseline
    /// any seated vnode's execution still reads, with the base known to
    /// carry `persisted`.
    ///
    /// Every vnode runs each tick itself, so one seated behind its
    /// siblings — a seat admitted mid-chain replaying from where its
    /// restore resumes — needs history they no longer do, and a hold that
    /// followed the furthest of them would retire it.
    pub(in crate::shard) fn hold_execution_baselines(&self, persisted: BlockHeight) {
        let executed = self
            .vnodes
            .iter()
            .map(|vnode| vnode.state.execution_coordinator().baseline_floor())
            .min()
            .unwrap_or(persisted);
        self.io.tick_chain.prune_persisted(persisted, executed);
    }

    /// Move the store's chain floor to what its readers still reach,
    /// once the oldest pin or the attested anchor has moved since it last
    /// did — the binding term moves with them, once an epoch.
    ///
    /// The rows a live ledger entry reads beneath the floor are held
    /// first, as the union over the seated vnodes: each runs its own
    /// ledger, and one seated behind its siblings may still owe an entry
    /// they have let go of.
    pub(in crate::shard) fn advance_chain_floor(&mut self) {
        let topology = self.process.topology_snapshot().load();
        let attested = topology.boundary(self.shard).map(|anchor| anchor.height);
        let oldest_pin = [self.io.storage.oldest_pin(), attested]
            .into_iter()
            .flatten()
            .min();
        let pins = (oldest_pin, attested);
        if self.io.floor_pins == Some(pins) {
            return;
        }
        self.io.floor_pins = Some(pins);
        let held: BodyHold = self
            .vnodes
            .iter()
            .flat_map(|vnode| vnode.state.execution_coordinator().held_commits())
            .collect();
        self.io.storage.hold_bodies(&held);
        let Some(vnode) = self.vnodes.first() else {
            return;
        };
        let floor = chain_floor(
            &*self.io.storage,
            FloorInputs {
                origin: vnode.state.shard_coordinator().chain_origin(),
                oldest_pin: attested.and(oldest_pin),
                settled_window_floor: topology.settled_window_floor(self.shard),
            },
        );
        self.io.storage.advance_chain_floor(floor);
    }

    /// Default `Protocol(_)` passthrough — fan the event across fetch-binding
    /// drain hooks (so e.g. `TransactionsReceived` clears in-flight tracking)
    /// and feed the variant into the state machine.
    pub(in crate::shard) fn handle_protocol_passthrough(&mut self, event: ProtocolEvent) {
        self.drive_fetch_admission(&event);
        self.dispatch_event(event);
    }
}
