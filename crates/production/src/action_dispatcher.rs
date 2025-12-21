//! Dedicated action dispatcher task for fire-and-forget network I/O.
//!
//! This module provides an `ActionDispatcher` that handles network broadcasts
//! independently from the main event loop. This prevents network latency from
//! blocking consensus processing.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    ACTION DISPATCHER ARCHITECTURE                       │
//! └─────────────────────────────────────────────────────────────────────────┘
//!
//!     ┌─────────────────────────────────┐
//!     │   MAIN EVENT LOOP               │
//!     │  (Owns State Machine)           │
//!     │                                 │
//!     │  state.handle(event) → actions  │
//!     │                                 │
//!     │  Network broadcasts:            │
//!     │    dispatch_tx.send(action)     │───────────┐
//!     │                                 │           │
//!     │  All other actions:             │           │
//!     │    process_action(action).await │           │
//!     └─────────────────────────────────┘           │
//!                                                   │
//!                                                   ▼
//!     ┌─────────────────────────────────────────────────────────────────┐
//!     │                    ACTION DISPATCHER TASK                       │
//!     │  (Fire-and-Forget Network I/O)                                  │
//!     │                                                                 │
//!     │  Handles network broadcasts:                                    │
//!     │  - BroadcastToShard (block proposals, votes)                    │
//!     │  - BroadcastGlobal (cross-shard messages)                       │
//!     │  - Batched execution messages (votes, certs, provisions)        │
//!     └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance Benefits
//!
//! 1. **No Event Loop Blocking**: Network broadcasts don't block consensus processing
//! 2. **Decoupled Latency**: Network delays don't affect state machine transitions
//! 3. **Higher Throughput**: Event loop can process more events while broadcasts complete

use crate::message_batcher::MessageBatcherHandle;
use crate::network::Libp2pAdapter;
use hyperscale_core::OutboundMessage;
use hyperscale_types::ShardGroupId;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, trace, warn};

/// Actions that can be dispatched to the action dispatcher task.
///
/// These are fire-and-forget network actions that don't require a response
/// or synchronous completion.
#[derive(Debug)]
pub enum DispatchableAction {
    /// Broadcast a message to a specific shard.
    BroadcastToShard {
        shard: ShardGroupId,
        message: OutboundMessage,
    },

    /// Broadcast a message globally.
    BroadcastGlobal { message: OutboundMessage },

    /// Queue a state vote for batched broadcast.
    QueueStateVote {
        shard: ShardGroupId,
        vote: hyperscale_types::StateVoteBlock,
    },

    /// Queue a state certificate for batched broadcast.
    QueueStateCertificate {
        shard: ShardGroupId,
        certificate: hyperscale_types::StateCertificate,
    },

    /// Queue a state provision for batched broadcast.
    QueueStateProvision {
        shard: ShardGroupId,
        provision: hyperscale_types::StateProvision,
    },
}

/// Configuration for the action dispatcher.
#[derive(Debug, Clone)]
pub struct ActionDispatcherConfig {
    /// Channel capacity for dispatched actions.
    /// Higher capacity allows more buffering but uses more memory.
    pub channel_capacity: usize,
}

impl Default for ActionDispatcherConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 1024,
        }
    }
}

/// Handle for the action dispatcher task.
#[allow(dead_code)]
pub struct ActionDispatcherHandle {
    /// Sender for dispatching actions.
    pub tx: mpsc::Sender<DispatchableAction>,
    /// Join handle for the spawned task.
    join_handle: tokio::task::JoinHandle<()>,
}

impl ActionDispatcherHandle {
    /// Check if the dispatcher task is still running.
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        !self.join_handle.is_finished()
    }
}

/// Context for the action dispatcher task.
pub struct ActionDispatcherContext {
    pub network: Arc<Libp2pAdapter>,
    pub message_batcher: MessageBatcherHandle,
}

/// Spawn the action dispatcher task.
///
/// This task handles fire-and-forget network I/O independently from
/// the main event loop, preventing network latency from blocking
/// consensus processing.
pub fn spawn_action_dispatcher(
    config: ActionDispatcherConfig,
    context: ActionDispatcherContext,
) -> ActionDispatcherHandle {
    let (tx, rx) = mpsc::channel(config.channel_capacity);

    let join_handle = tokio::spawn(async move {
        run_action_dispatcher(rx, context).await;
    });

    ActionDispatcherHandle { tx, join_handle }
}

/// Run the action dispatcher event loop.
async fn run_action_dispatcher(
    mut rx: mpsc::Receiver<DispatchableAction>,
    context: ActionDispatcherContext,
) {
    info!("Action dispatcher task started");

    while let Some(action) = rx.recv().await {
        // Process the action without blocking
        if let Err(e) = process_dispatched_action(&action, &context).await {
            warn!(
                error = ?e,
                action = ?std::mem::discriminant(&action),
                "Failed to process dispatched action"
            );
        }
    }

    info!("Action dispatcher task shutting down (channel closed)");
}

/// Process a single dispatched action.
async fn process_dispatched_action(
    action: &DispatchableAction,
    context: &ActionDispatcherContext,
) -> Result<(), ActionDispatchError> {
    match action {
        DispatchableAction::BroadcastToShard { shard, message } => {
            trace!(
                ?shard,
                msg_type = message.type_name(),
                "Dispatching broadcast to shard"
            );
            context
                .network
                .broadcast_shard(*shard, message)
                .await
                .map_err(|e| ActionDispatchError::Network(e.to_string()))?;
        }

        DispatchableAction::BroadcastGlobal { message } => {
            trace!(
                msg_type = message.type_name(),
                "Dispatching global broadcast"
            );
            context
                .network
                .broadcast_global(message)
                .await
                .map_err(|e| ActionDispatchError::Network(e.to_string()))?;
        }

        DispatchableAction::QueueStateVote { shard, vote } => {
            context.message_batcher.queue_vote(*shard, vote.clone());
        }

        DispatchableAction::QueueStateCertificate { shard, certificate } => {
            context
                .message_batcher
                .queue_certificate(*shard, certificate.clone());
        }

        DispatchableAction::QueueStateProvision { shard, provision } => {
            context
                .message_batcher
                .queue_provision(*shard, provision.clone());
        }
    }

    Ok(())
}

/// Errors that can occur during action dispatch.
#[derive(Debug)]
pub enum ActionDispatchError {
    Network(String),
}

impl std::fmt::Display for ActionDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionDispatchError::Network(e) => write!(f, "Network error: {}", e),
        }
    }
}

impl std::error::Error for ActionDispatchError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = ActionDispatcherConfig::default();
        assert_eq!(config.channel_capacity, 1024);
    }
}
