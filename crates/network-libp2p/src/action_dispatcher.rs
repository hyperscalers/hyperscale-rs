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
//!     │  - BroadcastBlockHeader, BroadcastBlockVote                     │
//!     │  - BroadcastTransaction, BroadcastTransactionCertificate        │
//!     │  - Batched execution messages (votes, certs, provisions)        │
//!     └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance Benefits
//!
//! 1. **No Event Loop Blocking**: Network broadcasts don't block consensus processing
//! 2. **Decoupled Latency**: Network delays don't affect state machine transitions
//! 3. **Higher Throughput**: Event loop can process more events while broadcasts complete

use crate::adapter::Libp2pAdapter;
use crate::message_batcher::MessageBatcherHandle;
use hyperscale_types::{NetworkMessage, ShardGroupId};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, trace, warn};

/// Actions that can be dispatched to the action dispatcher task.
///
/// These are fire-and-forget network actions that don't require a response
/// or synchronous completion.
#[derive(Debug)]
pub enum DispatchableAction {
    /// Broadcast a block header to a specific shard.
    BroadcastBlockHeader {
        shard: ShardGroupId,
        header: Box<hyperscale_messages::BlockHeaderGossip>,
    },

    /// Broadcast a block vote to a specific shard.
    BroadcastBlockVote {
        shard: ShardGroupId,
        vote: hyperscale_messages::BlockVoteGossip,
    },

    /// Broadcast a transaction to a specific shard.
    BroadcastTransaction {
        shard: ShardGroupId,
        gossip: Box<hyperscale_messages::TransactionGossip>,
    },

    /// Broadcast a transaction certificate to a specific shard.
    BroadcastTransactionCertificate {
        shard: ShardGroupId,
        gossip: hyperscale_messages::TransactionCertificateGossip,
    },

    /// Queue a state vote for batched broadcast.
    QueueStateVote {
        shard: ShardGroupId,
        vote: hyperscale_types::StateVoteBlock,
    },

    /// Queue a state certificate for batched broadcast.
    QueueStateCertificate {
        shard: ShardGroupId,
        certificate: std::sync::Arc<hyperscale_types::StateCertificate>,
    },

    /// Queue a state provision for batched broadcast.
    QueueStateProvision {
        shard: ShardGroupId,
        provision: hyperscale_types::StateProvision,
    },
}

/// Handle for the action dispatcher task.
#[allow(dead_code)]
pub struct ActionDispatcherHandle {
    /// Sender for dispatching actions.
    /// Unbounded to prevent dropping critical consensus messages under load.
    pub tx: mpsc::UnboundedSender<DispatchableAction>,
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
///
/// Uses an unbounded channel to ensure critical consensus messages
/// (state votes, certificates, provisions) are never dropped under load.
/// The dispatcher task is fast (just forwards to network/batcher), so
/// the queue naturally drains. Memory usage is bounded by production rate.
pub fn spawn_action_dispatcher(context: ActionDispatcherContext) -> ActionDispatcherHandle {
    let (tx, rx) = mpsc::unbounded_channel();

    let join_handle = tokio::spawn(async move {
        run_action_dispatcher(rx, context).await;
    });

    ActionDispatcherHandle { tx, join_handle }
}

/// Run the action dispatcher event loop.
async fn run_action_dispatcher(
    mut rx: mpsc::UnboundedReceiver<DispatchableAction>,
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

/// Encode a message and publish it to the network.
fn encode_and_publish<T: sbor::BasicEncode + NetworkMessage>(
    context: &ActionDispatcherContext,
    topic: &hyperscale_network::Topic,
    value: &T,
) -> Result<(), ActionDispatchError> {
    let data = hyperscale_network::encode_to_wire(value)
        .map_err(|e| ActionDispatchError::Network(e.to_string()))?;
    let priority = T::priority();
    context
        .network
        .publish(topic, data, priority)
        .map_err(|e| ActionDispatchError::Network(e.to_string()))?;
    Ok(())
}

/// Process a single dispatched action.
async fn process_dispatched_action(
    action: &DispatchableAction,
    context: &ActionDispatcherContext,
) -> Result<(), ActionDispatchError> {
    match action {
        DispatchableAction::BroadcastBlockHeader { shard, header } => {
            trace!(?shard, "Dispatching block header broadcast to shard");
            let topic = hyperscale_network::Topic::block_header(*shard);
            encode_and_publish(context, &topic, header.as_ref())?;
        }

        DispatchableAction::BroadcastBlockVote { shard, vote } => {
            trace!(?shard, "Dispatching block vote broadcast to shard");
            let topic = hyperscale_network::Topic::block_vote(*shard);
            encode_and_publish(context, &topic, vote)?;
        }

        DispatchableAction::BroadcastTransaction { shard, gossip } => {
            trace!(?shard, "Dispatching transaction broadcast to shard");
            let topic = hyperscale_network::Topic::transaction_gossip(*shard);
            encode_and_publish(context, &topic, gossip.as_ref())?;
        }

        DispatchableAction::BroadcastTransactionCertificate { shard, gossip } => {
            trace!(
                ?shard,
                "Dispatching transaction certificate broadcast to shard"
            );
            let topic = hyperscale_network::Topic::transaction_certificate(*shard);
            encode_and_publish(context, &topic, gossip)?;
        }

        DispatchableAction::QueueStateVote { shard, vote } => {
            context.message_batcher.queue_vote(*shard, vote.clone());
        }

        DispatchableAction::QueueStateCertificate { shard, certificate } => {
            context
                .message_batcher
                .queue_certificate(*shard, std::sync::Arc::unwrap_or_clone(certificate.clone()));
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
