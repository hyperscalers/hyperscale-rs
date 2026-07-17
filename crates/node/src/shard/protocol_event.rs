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
use hyperscale_storage::ShardStorage;
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

    /// Default `Protocol(_)` passthrough — fan the event across fetch-binding
    /// drain hooks (so e.g. `TransactionsReceived` clears in-flight tracking)
    /// and feed the variant into the state machine.
    pub(in crate::shard) fn handle_protocol_passthrough(&mut self, event: ProtocolEvent) {
        self.drive_fetch_admission(&event);
        self.dispatch_event(event);
    }
}
