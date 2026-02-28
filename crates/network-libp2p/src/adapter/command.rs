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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_channels_creation() {
        let (_channels, (mut crit, mut coord, mut final_, mut prop, mut bg)) =
            PriorityCommandChannels::new();

        // All receivers should be empty initially
        assert!(crit.try_recv().is_err());
        assert!(coord.try_recv().is_err());
        assert!(final_.try_recv().is_err());
        assert!(prop.try_recv().is_err());
        assert!(bg.try_recv().is_err());
    }

    #[test]
    fn test_broadcast_routes_by_priority() {
        let (channels, (mut crit, mut coord, mut final_, mut prop, mut bg)) =
            PriorityCommandChannels::new();

        channels
            .send(SwarmCommand::Broadcast {
                topic: "t".into(),
                data: vec![1],
                priority: MessagePriority::Critical,
            })
            .unwrap();
        channels
            .send(SwarmCommand::Broadcast {
                topic: "t".into(),
                data: vec![2],
                priority: MessagePriority::Coordination,
            })
            .unwrap();
        channels
            .send(SwarmCommand::Broadcast {
                topic: "t".into(),
                data: vec![3],
                priority: MessagePriority::Finalization,
            })
            .unwrap();
        channels
            .send(SwarmCommand::Broadcast {
                topic: "t".into(),
                data: vec![4],
                priority: MessagePriority::Propagation,
            })
            .unwrap();
        channels
            .send(SwarmCommand::Broadcast {
                topic: "t".into(),
                data: vec![5],
                priority: MessagePriority::Background,
            })
            .unwrap();

        assert!(
            matches!(crit.try_recv().unwrap(), SwarmCommand::Broadcast { data, .. } if data == vec![1])
        );
        assert!(
            matches!(coord.try_recv().unwrap(), SwarmCommand::Broadcast { data, .. } if data == vec![2])
        );
        assert!(
            matches!(final_.try_recv().unwrap(), SwarmCommand::Broadcast { data, .. } if data == vec![3])
        );
        assert!(
            matches!(prop.try_recv().unwrap(), SwarmCommand::Broadcast { data, .. } if data == vec![4])
        );
        assert!(
            matches!(bg.try_recv().unwrap(), SwarmCommand::Broadcast { data, .. } if data == vec![5])
        );
    }

    #[test]
    fn test_control_commands_use_critical_channel() {
        let (channels, (mut crit, _, _, _, _)) = PriorityCommandChannels::new();

        channels
            .send(SwarmCommand::Subscribe {
                topic: "test".into(),
            })
            .unwrap();
        assert!(matches!(
            crit.try_recv().unwrap(),
            SwarmCommand::Subscribe { .. }
        ));

        channels
            .send(SwarmCommand::Dial {
                address: "/ip4/127.0.0.1/tcp/1234".parse().unwrap(),
            })
            .unwrap();
        assert!(matches!(
            crit.try_recv().unwrap(),
            SwarmCommand::Dial { .. }
        ));
    }

    #[test]
    fn test_send_fails_on_closed_channel() {
        let (channels, receivers) = PriorityCommandChannels::new();
        drop(receivers);

        let result = channels.send(SwarmCommand::Subscribe {
            topic: "test".into(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_messages_preserve_order() {
        let (channels, (mut crit, _, _, _, _)) = PriorityCommandChannels::new();

        for i in 0..5u8 {
            channels
                .send(SwarmCommand::Broadcast {
                    topic: format!("topic-{}", i),
                    data: vec![i],
                    priority: MessagePriority::Critical,
                })
                .unwrap();
        }

        for i in 0..5u8 {
            let msg = crit.try_recv().unwrap();
            assert!(matches!(msg, SwarmCommand::Broadcast { data, .. } if data == vec![i]));
        }
        assert!(crit.try_recv().is_err());
    }
}
