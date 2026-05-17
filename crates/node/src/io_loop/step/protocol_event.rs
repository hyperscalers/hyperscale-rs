//! Protocol-event passthrough step handlers.
//!
//! `NodeInput::Protocol(_)` is the channel for state-machine events that
//! re-enter `IoLoop` via `feed_event` (continuation-style). Most are pure
//! passthrough — feed the variant straight into the state machine. The
//! one exception is `BlockPersisted`, which carries IoLoop-side commit
//! pipeline state (`block_commit`, `pending_chain`) that needs updating
//! before the state machine sees the event.

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::BlockHeight;

use crate::io_loop::IoLoop;

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Update `IoLoop`'s commit pipeline before forwarding `BlockPersisted`
    /// to the state machine: the persisted height advances `block_commit`'s
    /// gate and `pending_chain`'s pruning watermark.
    pub(in crate::io_loop) fn handle_block_persisted(&mut self, height: BlockHeight) {
        self.shard_block_commit_mut().mark_persisted(height);
        // Drop pending state for blocks now persisted to RocksDB.
        self.shard_pending_chain().prune(height);
        self.feed_event(0, ProtocolEvent::BlockPersisted { height });
    }

    /// Default `Protocol(_)` passthrough — fan the event across fetch-binding
    /// drain hooks (so e.g. `TransactionsReceived` clears in-flight tracking)
    /// and feed the variant into the state machine.
    pub(in crate::io_loop) fn handle_protocol_passthrough(&mut self, event: ProtocolEvent) {
        self.drive_fetch_admission(&event);
        self.feed_event(0, event);
    }
}
