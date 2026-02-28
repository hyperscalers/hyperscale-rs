//! Command types and priority-based command channels.

use hyperscale_types::MessagePriority;
use libp2p::{Multiaddr, PeerId as Libp2pPeerId};
use tokio::sync::mpsc;

/// Maximum number of commands to drain per event loop iteration.
/// Prevents tight loops from monopolizing the event loop when channels are flooded.
/// High-priority response commands and normal commands each have this limit.
pub(super) const MAX_COMMANDS_PER_DRAIN: usize = 100;

/// Commands sent to the swarm task.
///
/// Commands are processed in priority order when using priority channels.
/// Non-broadcast commands (Subscribe, Dial, etc.) are always processed
/// with high priority since they're control operations.
#[derive(Debug)]
pub(super) enum SwarmCommand {
    /// Subscribe to a gossipsub topic.
    Subscribe { topic: String },

    /// Broadcast a message to a topic with priority.
    ///
    /// Priority determines processing order in the event loop.
    /// Higher priority messages are processed before lower priority ones.
    Broadcast {
        topic: String,
        data: Vec<u8>,
        priority: MessagePriority,
    },

    /// Dial a peer.
    Dial { address: Multiaddr },

    /// Query listen addresses.
    GetListenAddresses {
        response_tx: tokio::sync::oneshot::Sender<Vec<Multiaddr>>,
    },

    /// Query connected peers.
    GetConnectedPeers {
        response_tx: tokio::sync::oneshot::Sender<Vec<Libp2pPeerId>>,
    },
}

/// Receiver type for priority command channels.
pub(super) type PriorityReceivers = (
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
);

/// Priority-based command channels for the swarm task.
///
/// Commands are sent to the appropriate channel based on message priority.
/// The event loop processes channels in priority order (Critical first, Background last).
#[derive(Clone, Debug)]
pub(super) struct PriorityCommandChannels {
    /// Critical priority - BFT consensus messages, pending block requests.
    /// Never dropped, processed immediately.
    critical: mpsc::UnboundedSender<SwarmCommand>,

    /// Coordination priority - Cross-shard 2PC messages.
    /// High priority, may be batched.
    coordination: mpsc::UnboundedSender<SwarmCommand>,

    /// Finalization priority - Transaction certificate gossip.
    /// Important but not liveness-critical.
    finalization: mpsc::UnboundedSender<SwarmCommand>,

    /// Propagation priority - Transaction gossip (mempool).
    /// Best-effort, can be shed under load.
    propagation: mpsc::UnboundedSender<SwarmCommand>,

    /// Background priority - Sync operations.
    /// Lowest priority, fully deferrable.
    background: mpsc::UnboundedSender<SwarmCommand>,
}

impl PriorityCommandChannels {
    /// Create new priority channels, returning (senders, receivers).
    pub(super) fn new() -> (Self, PriorityReceivers) {
        let (critical_tx, critical_rx) = mpsc::unbounded_channel();
        let (coordination_tx, coordination_rx) = mpsc::unbounded_channel();
        let (finalization_tx, finalization_rx) = mpsc::unbounded_channel();
        let (propagation_tx, propagation_rx) = mpsc::unbounded_channel();
        let (background_tx, background_rx) = mpsc::unbounded_channel();

        (
            Self {
                critical: critical_tx,
                coordination: coordination_tx,
                finalization: finalization_tx,
                propagation: propagation_tx,
                background: background_tx,
            },
            (
                critical_rx,
                coordination_rx,
                finalization_rx,
                propagation_rx,
                background_rx,
            ),
        )
    }

    /// Send a command to the appropriate priority channel.
    ///
    /// For Broadcast commands, uses the embedded priority.
    /// For control commands (Subscribe, Dial, etc.), uses Critical priority.
    #[allow(clippy::result_large_err)]
    pub(super) fn send(
        &self,
        cmd: SwarmCommand,
    ) -> Result<(), mpsc::error::SendError<SwarmCommand>> {
        let priority = match &cmd {
            SwarmCommand::Broadcast { priority, .. } => *priority,
            // Control commands always get critical priority
            SwarmCommand::Subscribe { .. }
            | SwarmCommand::Dial { .. }
            | SwarmCommand::GetListenAddresses { .. }
            | SwarmCommand::GetConnectedPeers { .. } => MessagePriority::Critical,
        };

        match priority {
            MessagePriority::Critical => self.critical.send(cmd),
            MessagePriority::Coordination => self.coordination.send(cmd),
            MessagePriority::Finalization => self.finalization.send(cmd),
            MessagePriority::Propagation => self.propagation.send(cmd),
            MessagePriority::Background => self.background.send(cmd),
        }
    }
}
