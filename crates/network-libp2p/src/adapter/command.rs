//! Command types and class-based command channels.

use hyperscale_types::MessageClass;
use libp2p::{Multiaddr, PeerId as Libp2pPeerId};
use tokio::sync::mpsc;

/// Maximum number of commands to drain per event loop iteration.
/// Prevents tight loops from monopolizing the event loop when channels are flooded.
pub(super) const MAX_COMMANDS_PER_DRAIN: usize = 100;

/// Commands sent to the swarm task.
///
/// Commands are processed in class order when using class channels.
/// Non-broadcast commands (Subscribe, Dial, etc.) are always processed
/// at the most-urgent class since they're control operations.
#[derive(Debug)]
pub(super) enum SwarmCommand {
    /// Subscribe to a gossipsub topic.
    Subscribe { topic: String },

    /// Broadcast a message to a topic with the given class.
    ///
    /// Class determines processing order in the event loop. More-urgent
    /// classes are processed before less-urgent ones.
    Broadcast {
        topic: String,
        data: Vec<u8>,
        class: MessageClass,
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

/// Receiver type for class-tiered command channels.
pub(super) type ClassReceivers = (
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
);

/// Class-tiered command channels for the swarm task.
///
/// Commands are sent to the appropriate channel based on message class.
/// The event loop processes channels in class order (Consensus first, Bulk last).
#[derive(Clone, Debug)]
pub(super) struct ClassCommandChannels {
    /// Consensus class — BFT round-blocking traffic.
    /// Never dropped, processed immediately.
    consensus: mpsc::UnboundedSender<SwarmCommand>,

    /// `BlockCompletion` class — DA gap-closure for the current proposal.
    block_completion: mpsc::UnboundedSender<SwarmCommand>,

    /// `CrossShardProgress` class — execution and finalization coordination.
    cross_shard_progress: mpsc::UnboundedSender<SwarmCommand>,

    /// Recovery class — catch-up traffic. Sheddable.
    recovery: mpsc::UnboundedSender<SwarmCommand>,

    /// Bulk class — high-volume best-effort with fetch fallback.
    bulk: mpsc::UnboundedSender<SwarmCommand>,
}

impl ClassCommandChannels {
    /// Create new class channels, returning (senders, receivers).
    pub(super) fn new() -> (Self, ClassReceivers) {
        let (consensus_tx, consensus_rx) = mpsc::unbounded_channel();
        let (block_completion_tx, block_completion_rx) = mpsc::unbounded_channel();
        let (cross_shard_progress_tx, cross_shard_progress_rx) = mpsc::unbounded_channel();
        let (recovery_tx, recovery_rx) = mpsc::unbounded_channel();
        let (bulk_tx, bulk_rx) = mpsc::unbounded_channel();

        (
            Self {
                consensus: consensus_tx,
                block_completion: block_completion_tx,
                cross_shard_progress: cross_shard_progress_tx,
                recovery: recovery_tx,
                bulk: bulk_tx,
            },
            (
                consensus_rx,
                block_completion_rx,
                cross_shard_progress_rx,
                recovery_rx,
                bulk_rx,
            ),
        )
    }

    /// Send a command to the appropriate class channel.
    ///
    /// For Broadcast commands, uses the embedded class.
    /// For control commands (Subscribe, Dial, etc.), uses Consensus class.
    #[allow(clippy::result_large_err)]
    pub(super) fn send(
        &self,
        cmd: SwarmCommand,
    ) -> Result<(), mpsc::error::SendError<SwarmCommand>> {
        let class = match &cmd {
            SwarmCommand::Broadcast { class, .. } => *class,
            // Control commands always get Consensus class.
            SwarmCommand::Subscribe { .. }
            | SwarmCommand::Dial { .. }
            | SwarmCommand::GetListenAddresses { .. }
            | SwarmCommand::GetConnectedPeers { .. } => MessageClass::Consensus,
        };

        match class {
            MessageClass::Consensus => self.consensus.send(cmd),
            MessageClass::BlockCompletion => self.block_completion.send(cmd),
            MessageClass::CrossShardProgress => self.cross_shard_progress.send(cmd),
            MessageClass::Recovery => self.recovery.send(cmd),
            MessageClass::Bulk => self.bulk.send(cmd),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_class_channels_creation() {
        let (_channels, (mut con, mut bc, mut csp, mut rec, mut bulk)) =
            ClassCommandChannels::new();

        assert!(con.try_recv().is_err());
        assert!(bc.try_recv().is_err());
        assert!(csp.try_recv().is_err());
        assert!(rec.try_recv().is_err());
        assert!(bulk.try_recv().is_err());
    }

    #[test]
    fn test_broadcast_routes_by_class() {
        let (channels, (mut con, mut bc, mut csp, mut rec, mut bulk)) = ClassCommandChannels::new();

        channels
            .send(SwarmCommand::Broadcast {
                topic: "t".into(),
                data: vec![1],
                class: MessageClass::Consensus,
            })
            .unwrap();
        channels
            .send(SwarmCommand::Broadcast {
                topic: "t".into(),
                data: vec![2],
                class: MessageClass::BlockCompletion,
            })
            .unwrap();
        channels
            .send(SwarmCommand::Broadcast {
                topic: "t".into(),
                data: vec![3],
                class: MessageClass::CrossShardProgress,
            })
            .unwrap();
        channels
            .send(SwarmCommand::Broadcast {
                topic: "t".into(),
                data: vec![4],
                class: MessageClass::Recovery,
            })
            .unwrap();
        channels
            .send(SwarmCommand::Broadcast {
                topic: "t".into(),
                data: vec![5],
                class: MessageClass::Bulk,
            })
            .unwrap();

        assert!(
            matches!(con.try_recv().unwrap(), SwarmCommand::Broadcast { data, .. } if data == vec![1])
        );
        assert!(
            matches!(bc.try_recv().unwrap(), SwarmCommand::Broadcast { data, .. } if data == vec![2])
        );
        assert!(
            matches!(csp.try_recv().unwrap(), SwarmCommand::Broadcast { data, .. } if data == vec![3])
        );
        assert!(
            matches!(rec.try_recv().unwrap(), SwarmCommand::Broadcast { data, .. } if data == vec![4])
        );
        assert!(
            matches!(bulk.try_recv().unwrap(), SwarmCommand::Broadcast { data, .. } if data == vec![5])
        );
    }

    #[test]
    fn test_control_commands_use_consensus_channel() {
        let (channels, (mut con, _, _, _, _)) = ClassCommandChannels::new();

        channels
            .send(SwarmCommand::Subscribe {
                topic: "test".into(),
            })
            .unwrap();
        assert!(matches!(
            con.try_recv().unwrap(),
            SwarmCommand::Subscribe { .. }
        ));

        channels
            .send(SwarmCommand::Dial {
                address: "/ip4/127.0.0.1/tcp/1234".parse().unwrap(),
            })
            .unwrap();
        assert!(matches!(con.try_recv().unwrap(), SwarmCommand::Dial { .. }));
    }

    #[test]
    fn test_send_fails_on_closed_channel() {
        let (channels, receivers) = ClassCommandChannels::new();
        drop(receivers);

        let result = channels.send(SwarmCommand::Subscribe {
            topic: "test".into(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_messages_preserve_order() {
        let (channels, (mut con, _, _, _, _)) = ClassCommandChannels::new();

        for i in 0..5u8 {
            channels
                .send(SwarmCommand::Broadcast {
                    topic: format!("topic-{i}"),
                    data: vec![i],
                    class: MessageClass::Consensus,
                })
                .unwrap();
        }

        for i in 0..5u8 {
            let msg = con.try_recv().unwrap();
            assert!(matches!(msg, SwarmCommand::Broadcast { data, .. } if data == vec![i]));
        }
        assert!(con.try_recv().is_err());
    }
}
