//! Command types and class-based command channels.

use hyperscale_metrics as metrics;
use hyperscale_types::MessageClass;
use libp2p::{Multiaddr, PeerId as Libp2pPeerId};
use tokio::sync::mpsc;
use tracing::warn;

/// Maximum number of commands to drain per event loop iteration.
/// Prevents tight loops from monopolizing the event loop when channels are flooded.
pub(super) const MAX_COMMANDS_PER_DRAIN: usize = 100;

/// Bounded capacity for the `Recovery` class channel.
///
/// Catchup traffic (block / remote-header sync) is sheddable: a flood here
/// must not consume unbounded memory and must not delay urgent classes via
/// the event loop's drain budget. Sized to absorb a sync session's typical
/// burst (one batch every ~200ms × tens of in-flight peers) without
/// blocking the steady-state.
pub(super) const RECOVERY_CHANNEL_CAPACITY: usize = 4096;

/// Bounded capacity for the `Bulk` class channel.
///
/// `TransactionGossip` is the highest-volume class; under congestion the
/// fetch-fallback path recovers any drops. Larger than `Recovery` because
/// per-tx volume is the workload's natural scaling axis.
pub(super) const BULK_CHANNEL_CAPACITY: usize = 8192;

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
///
/// The first three lanes are unbounded — `Consensus`, `BlockCompletion`,
/// and `CrossShardProgress` are low-cardinality by construction and
/// dropping them is a liveness hazard. The last two are bounded — see
/// [`RECOVERY_CHANNEL_CAPACITY`] and [`BULK_CHANNEL_CAPACITY`].
pub(super) type ClassReceivers = (
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::Receiver<SwarmCommand>,
    mpsc::Receiver<SwarmCommand>,
);

/// Class-tiered command channels for the swarm task.
///
/// Commands are sent to the appropriate channel based on message class.
/// The event loop processes channels in class order (Consensus first, Bulk last).
///
/// Sheddable lanes (`Recovery`, `Bulk`) are bounded; if their channel is
/// full at send time, the command is dropped and a backpressure event is
/// recorded so the operator can see when the cap is biting. Hot lanes
/// (`Consensus`, `BlockCompletion`, `CrossShardProgress`) are unbounded —
/// their volume is bounded by protocol cardinality.
#[derive(Clone, Debug)]
pub(super) struct ClassCommandChannels {
    /// Consensus class — BFT round-blocking traffic.
    /// Never dropped, processed immediately.
    consensus: mpsc::UnboundedSender<SwarmCommand>,

    /// `BlockCompletion` class — DA gap-closure for the current proposal.
    block_completion: mpsc::UnboundedSender<SwarmCommand>,

    /// `CrossShardProgress` class — execution and finalization coordination.
    cross_shard_progress: mpsc::UnboundedSender<SwarmCommand>,

    /// Recovery class — catch-up traffic. Sheddable; bounded at
    /// [`RECOVERY_CHANNEL_CAPACITY`]. Drops on overflow.
    recovery: mpsc::Sender<SwarmCommand>,

    /// Bulk class — high-volume best-effort with fetch fallback. Bounded
    /// at [`BULK_CHANNEL_CAPACITY`]. Drops on overflow.
    bulk: mpsc::Sender<SwarmCommand>,
}

impl ClassCommandChannels {
    /// Create new class channels, returning (senders, receivers).
    pub(super) fn new() -> (Self, ClassReceivers) {
        let (consensus_tx, consensus_rx) = mpsc::unbounded_channel();
        let (block_completion_tx, block_completion_rx) = mpsc::unbounded_channel();
        let (cross_shard_progress_tx, cross_shard_progress_rx) = mpsc::unbounded_channel();
        let (recovery_tx, recovery_rx) = mpsc::channel(RECOVERY_CHANNEL_CAPACITY);
        let (bulk_tx, bulk_rx) = mpsc::channel(BULK_CHANNEL_CAPACITY);

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
    ///
    /// Returns `Err` only when the receiver is gone (swarm task shut down).
    /// A full sheddable channel is *not* an error: the command is dropped
    /// with a `network_command_dropped` backpressure event recorded.
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
            MessageClass::Recovery => try_send_or_drop(&self.recovery, cmd, "recovery_channel"),
            MessageClass::Bulk => try_send_or_drop(&self.bulk, cmd, "bulk_channel"),
        }
    }
}

/// Non-blocking send into a bounded sheddable lane. On `Full`, drop the
/// command and record a backpressure event tagged `source` so the operator
/// can see the lane biting; the function still returns `Ok(())` because a
/// full sheddable lane is not a fatal error. On `Closed`, return the same
/// `SendError` shape as the unbounded lanes so callers don't need to
/// handle a separate variant.
#[allow(clippy::result_large_err)]
fn try_send_or_drop(
    sender: &mpsc::Sender<SwarmCommand>,
    cmd: SwarmCommand,
    source: &'static str,
) -> Result<(), mpsc::error::SendError<SwarmCommand>> {
    match sender.try_send(cmd) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(dropped)) => {
            metrics::record_backpressure_event(source);
            warn!(source, "Sheddable class channel full; dropping command");
            // Drop is intentional. Return Ok so callers don't treat
            // backpressure as a hard error.
            drop(dropped);
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(cmd)) => Err(mpsc::error::SendError(cmd)),
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
