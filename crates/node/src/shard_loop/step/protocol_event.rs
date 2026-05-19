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
use hyperscale_storage::Storage;
use hyperscale_types::BlockHeight;

use crate::shard_loop::ShardLoop;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: Storage,
    N: Network,
    D: Dispatch,
{
    /// Update the commit pipeline before forwarding `BlockPersisted` to the
    /// state machine: the persisted height advances `block_commit`'s gate
    /// and `pending_chain`'s pruning watermark.
    pub(in crate::shard_loop) fn handle_block_persisted(&mut self, height: BlockHeight) {
        self.io.block_commit.mark_persisted(height);
        // Drop pending state for blocks now persisted to RocksDB.
        self.io.pending_chain.prune(height);
        self.dispatch_event(ProtocolEvent::BlockPersisted { height });
    }

    /// Default `Protocol(_)` passthrough — fan the event across fetch-binding
    /// drain hooks (so e.g. `TransactionsReceived` clears in-flight tracking)
    /// and feed the variant into the state machine.
    pub(in crate::shard_loop) fn handle_protocol_passthrough(&mut self, event: ProtocolEvent) {
        self.drive_fetch_admission(&event);
        self.dispatch_event(event);
    }
}
