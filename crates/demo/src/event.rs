//! The event stream the viewer renders.
//!
//! These are presentation types, not wire types: they are `serde`-encoded to
//! JavaScript values and never hashed, signed, or gossiped, so the ordered
//! collection discipline the wire types carry does not apply here.

use std::time::Duration;

use hyperscale_simulation::{DeliveryDrain, DeliveryRecord};
use hyperscale_types::{
    BlockHeight, ExecutionOutcome, Finalization, MessageClass, Provisions, Round, ShardId, TickId,
    TxHash, TxOutcome,
};
use serde::Serialize;

/// Milliseconds on the harness clock, the unit every instant in the stream
/// is reported in.
fn as_millis(at: Duration) -> u64 {
    u64::try_from(at.as_millis()).unwrap_or(u64::MAX)
}

/// One observation, stamped with the BFT-attested time it happened at.
///
/// `wt` is the canonical weighted timestamp — the value carried in the
/// committing child's parent QC (INV-SHARD-6), never a served QC's stamp —
/// so it is monotone along a chain and identical on every replica. It is the
/// timeline's x-axis.
///
/// An observation with no attested time of its own — a transaction's status,
/// a partition change, anything the transport did — is stamped at the
/// attested frontier it was observed from, so one sort orders the whole
/// stream. [`TraceKind::MessageDelivered`] additionally carries the two
/// instants the delivery spanned; those are the harness clock the session
/// steps, not attested time, and the two never mix in one field.
#[derive(Debug, Clone, Serialize)]
#[allow(missing_docs)] // `wt` is described above; `kind` is the payload
pub struct TraceEvent {
    pub wt: u64,
    pub kind: TraceKind,
}

/// A shard's trie path as a bit string, most significant bit first — `""`
/// for the root, `"1"` for its right child, `"10"` and `"11"` for that
/// child's own children.
///
/// The viewer derives the whole topology from these: one path is another's
/// parent exactly when it is a prefix of it, which is the same relation the
/// keyspace partition uses. `ShardId`'s own `Display` is a debug rendering
/// and carries no such structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShardPath(pub String);

impl From<ShardId> for ShardPath {
    fn from(shard: ShardId) -> Self {
        let depth = shard.depth();
        let path = shard.path();
        let bits = (0..depth)
            .rev()
            .map(|bit| if path >> bit & 1 == 1 { '1' } else { '0' })
            .collect();
        Self(bits)
    }
}

/// What was observed. Serialized tagged, so the viewer switches on `type`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[allow(missing_docs)] // payload fields; their names are the documentation
pub enum TraceKind {
    #[serde(rename_all = "camelCase")]
    BlockCommitted {
        shard: ShardPath,
        height: u64,
        round: u64,
        /// A fallback block is an empty view-change recovery block: it
        /// carries no payload and reuses its parent's timestamp, which is
        /// why the timeline draws it differently from a normal block.
        fallback: bool,
        proposer: u64,
        /// The block's transactions that touch more than one shard, and so
        /// open cross-shard execution. Stays zero until the topology has
        /// more than one shard.
        cross_shard_ticks: u32,
    },
    /// The beacon committed an epoch. One block per epoch, wall-clock paced,
    /// carrying no transactions: it decides validator set and topology, and
    /// every shard resolves its committee from the schedule this produces.
    #[serde(rename_all = "camelCase")]
    BeaconBlockCommitted { epoch: u64 },
    /// The keyspace partition changed — a split seated its children, or a
    /// merge composed its parent. Carries the whole new partition rather
    /// than a delta so a viewer that joined late still renders correctly.
    #[serde(rename_all = "camelCase")]
    TopologyChanged {
        shards: Vec<ShardPath>,
        /// Leaves that were not in the previous partition.
        appeared: Vec<ShardPath>,
        /// Leaves that were in it and are not now — a split parent, or the
        /// children a merge composed away.
        retired: Vec<ShardPath>,
    },
    /// State committed on `from` that `to` took delivery of.
    ///
    /// Drawn as an arc from `(from, fromHeight)` — the block whose state was
    /// provisioned — to `(to, toHeight)`, the block where `to` committed the
    /// bundle. Derived at the destination: a bundle reaches a block only
    /// once the committee has checked its proof against `from`'s
    /// QC-attested state root, so the arc stands for a proof that checked
    /// out rather than a message that was sent.
    ///
    /// One arc per bundle, in the direction the state travelled. A transfer
    /// draws one: the payer's shard settles it alone and the recipient's
    /// commits the delivery, so the arc runs from payer to recipient and
    /// nothing runs back.
    #[serde(rename_all = "camelCase")]
    ProvisionsVerified {
        from: ShardPath,
        from_height: u64,
        to: ShardPath,
        to_height: u64,
        txs: Vec<TxLabel>,
    },
    /// One shard's execution certificate, as accepted by the shard that
    /// committed it.
    ///
    /// `shard` and `height` locate the tick on the committee that signed
    /// the certificate; `into` and `intoHeight` locate the block that
    /// carried it. They differ exactly when the certificate crossed a shard
    /// boundary, which is when the viewer draws an arc.
    #[serde(rename_all = "camelCase")]
    ExecutionCertified {
        shard: ShardPath,
        height: u64,
        tick: TickLabel,
        into: ShardPath,
        into_height: u64,
        /// Per-transaction `succeeded`, `failed`, or `aborted`, in the
        /// tick's canonical order.
        outcomes: Vec<(TxLabel, &'static str)>,
    },
    /// Every participating shard reported and the finalization is
    /// committed — the point where the arcs on both sides converge.
    #[serde(rename_all = "camelCase")]
    TickFinalized {
        shard: ShardPath,
        /// The block that committed the certificate.
        height: u64,
        /// The block whose transactions opened the tick. The gap between
        /// the two is the settlement round's latency.
        opened_at: u64,
        tick: TickLabel,
        /// Every shard that signed a certificate in this tick, `shard`
        /// included. A single entry means the tick never left the shard.
        participants: Vec<ShardPath>,
        txs: Vec<TxLabel>,
    },
    /// A shard reached its last block.
    ///
    /// `height` is the chain's final height. `handoffFrom` is the first
    /// height whose header carried a settled-transaction root: from there to the
    /// end the shard is certifying its own handoff rather than merely
    /// running, which is the difference between a chain that stopped and one
    /// that finished.
    #[serde(rename_all = "camelCase")]
    ShardTerminal {
        shard: ShardPath,
        height: u64,
        handoff_from: Option<u64>,
    },
    /// One message the transport carried between two hosts.
    ///
    /// This is what the network *attempted*, not what consensus attested: a
    /// delivery is a message that arrived, and nothing more. The arcs on the
    /// timeline stand for verified artifacts and these do not, which is why
    /// they are drawn in a panel of their own rather than between the lanes.
    ///
    /// `sentAt` and `deliveredAt` are milliseconds on the harness clock the
    /// session steps — their difference is the latency the transport drew.
    /// Attested time necessarily trails that clock, so they are never
    /// comparable with the `wt` this event is stamped at.
    #[serde(rename_all = "camelCase")]
    MessageDelivered {
        from: u32,
        to: u32,
        /// Priority class of the sending type: `consensus`,
        /// `block_completion`, `cross_shard_progress`, `recovery`, or `bulk`.
        /// Only the last two are sheddable under backpressure.
        class: &'static str,
        message_type: &'static str,
        sent_at: u64,
        delivered_at: u64,
        /// Shard the delivery was scoped to; absent for global traffic and
        /// for request round trips, whose shard is the committee's rather
        /// than the message's.
        shard: Option<ShardPath>,
    },
    /// What the transport carried over one step, in full.
    ///
    /// `byClass` is exact and covers every delivery, including those the
    /// sample dropped: a viewer animating a thinned sample still reports
    /// true volume, and `dropped` is how much it is not showing.
    #[serde(rename_all = "camelCase")]
    TrafficSampled {
        /// `(class, deliveries, bytes)` for each class that carried
        /// anything this step.
        by_class: Vec<(&'static str, u64, u64)>,
        /// Deliveries reported individually as [`Self::MessageDelivered`].
        sampled: u32,
        /// Deliveries the sample budget left out.
        dropped: u64,
    },
    /// The hosts and what each one serves.
    ///
    /// Emitted whenever the roster moves, which is what makes a split legible
    /// as staffing: hosts leave the free pool and appear in a child's
    /// committee, and a reshape stops being a line on a timeline.
    #[serde(rename_all = "camelCase")]
    HostsChanged { hosts: Vec<HostRole> },
    #[serde(rename_all = "camelCase")]
    TxSubmitted { tx: TxLabel },
    #[serde(rename_all = "camelCase")]
    TxStatusChanged {
        tx: TxLabel,
        /// `pending`, `committed`, or a terminal `succeeded` / `aborted` /
        /// `rejected` — the outcome every participating shard agrees on
        /// (INV-EXEC-1).
        status: &'static str,
        /// Set once the transaction is ordered: the height that committed it.
        height: Option<u64>,
    },
}

/// What one host is doing: the shards it serves and how many shard-less
/// vnodes it keeps following the beacon.
///
/// A host with no shards and a non-zero `pooled` is free pool — stock a
/// reshape draws on to staff a new committee. Hosts are identified by index
/// alone: the demo runs one vnode per host, so the host *is* the validator
/// and a second identifier would name the same thing twice.
///
/// `shards` is what the host carries, which outlives the live partition: a
/// split parent's store is retained past its terminal block (INV-BEACON-8),
/// so a grown host lists the retired parent alongside its live child. The
/// viewer already knows the live leaves from
/// [`TraceKind::TopologyChanged`] and intersects.
///
/// `seated` is the subset of those the host holds a consensus seat on — the
/// set quorum counts. Carrying a shard is not the same as voting on it: a
/// rotation entrant bootstraps the shard's state for the better part of a
/// minute before it signals Ready, and a committee that showed every host
/// carrying the shard would report more members than the protocol seats.
/// `observing` names the pending splits it has been drawn into and the child
/// each sends it to, which the beacon settles an epoch before the cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(missing_docs)] // flat readouts; their names are the documentation
pub struct HostRole {
    pub host: u32,
    pub shards: Vec<ShardPath>,
    pub(crate) seated: Vec<ShardPath>,
    pub(crate) observing: Vec<ObserverSeat>,
    pub pooled: u32,
}

/// A seat binding a host to one half of `shard`'s pending split.
///
/// Covers both populations a split draws on, which never overlap: a cohort
/// observer syncing `child`'s sub-prefix from the free pool, and a member of
/// the splitting committee that will re-root onto `child` at the cut. The
/// first holds no seat on `shard`; the second votes on it until the cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(missing_docs)] // flat readouts; their names are the documentation
pub(crate) struct ObserverSeat {
    pub shard: ShardPath,
    pub(crate) child: ShardPath,
    /// Whether the beacon has folded the seat's `ReshapeReady` witness — the
    /// observer has the child's state, not merely the assignment.
    pub(crate) ready: bool,
}

/// A transaction hash, shortened to the prefix a reader can match by eye.
#[derive(Debug, Clone, Serialize)]
pub struct TxLabel(pub String);

impl From<TxHash> for TxLabel {
    fn from(hash: TxHash) -> Self {
        let rendered = format!("{hash}");
        let short: String = rendered
            .trim_start_matches("TxHash(")
            .chars()
            .take(8)
            .collect();
        Self(short)
    }
}

/// A tick's identity on the shard that opened it, `<shard>@<height>` —
/// the same pair a [`TickId`] binds.
///
/// Not comparable across shards: one logical settlement round gives every
/// participant its own tick id, so the viewer relates the two sides by the
/// shard-and-height endpoints each event carries, never by this string.
#[derive(Debug, Clone, Serialize)]
pub struct TickLabel(pub String);

impl TickLabel {
    fn new(shard: ShardId, height: BlockHeight) -> Self {
        let path = ShardPath::from(shard).0;
        let name = if path.is_empty() { "ROOT" } else { &path };
        Self(format!("{name}@{}", height.inner()))
    }
}

/// The outcome vocabulary the docs use, per transaction.
const fn outcome_label(outcome: &ExecutionOutcome) -> &'static str {
    match outcome {
        ExecutionOutcome::Succeeded { .. } => "succeeded",
        ExecutionOutcome::Failed => "failed",
        ExecutionOutcome::Aborted => "aborted",
    }
}

fn labelled_outcomes(outcomes: &[TxOutcome]) -> Vec<(TxLabel, &'static str)> {
    outcomes
        .iter()
        .map(|o| (o.tx_hash().into(), outcome_label(o.outcome())))
        .collect()
}

fn tx_labels(outcomes: &[TxOutcome]) -> Vec<TxLabel> {
    outcomes.iter().map(|o| o.tx_hash().into()).collect()
}

impl TraceEvent {
    pub(crate) fn block_committed(
        wt: u64,
        shard: ShardId,
        height: BlockHeight,
        round: Round,
        fallback: bool,
        proposer: u64,
        cross_shard_ticks: u32,
    ) -> Self {
        Self {
            wt,
            kind: TraceKind::BlockCommitted {
                shard: shard.into(),
                height: height.inner(),
                round: round.inner(),
                fallback,
                proposer,
                cross_shard_ticks,
            },
        }
    }

    pub(crate) const fn beacon_block(wt: u64, epoch: u64) -> Self {
        Self {
            wt,
            kind: TraceKind::BeaconBlockCommitted { epoch },
        }
    }

    pub(crate) fn topology_changed(
        wt: u64,
        shards: &[ShardId],
        appeared: Vec<ShardId>,
        retired: Vec<ShardId>,
    ) -> Self {
        let paths = |ids: Vec<ShardId>| ids.into_iter().map(ShardPath::from).collect();
        Self {
            wt,
            kind: TraceKind::TopologyChanged {
                shards: shards.iter().copied().map(ShardPath::from).collect(),
                appeared: paths(appeared),
                retired: paths(retired),
            },
        }
    }

    pub(crate) fn provisions_verified(
        wt: u64,
        bundle: &Provisions,
        to: ShardId,
        to_height: BlockHeight,
        delivered: Vec<TxHash>,
    ) -> Self {
        Self {
            wt,
            kind: TraceKind::ProvisionsVerified {
                from: bundle.source_shard().into(),
                from_height: bundle.block_height().inner(),
                to: to.into(),
                to_height: to_height.inner(),
                txs: delivered.into_iter().map(TxLabel::from).collect(),
            },
        }
    }

    pub(crate) fn execution_certified(
        wt: u64,
        tick: &TickId,
        into: ShardId,
        into_height: BlockHeight,
        outcomes: &[TxOutcome],
    ) -> Self {
        Self {
            wt,
            kind: TraceKind::ExecutionCertified {
                shard: tick.shard_id().into(),
                height: tick.block_height().inner(),
                tick: TickLabel::new(tick.shard_id(), tick.block_height()),
                into: into.into(),
                into_height: into_height.inner(),
                outcomes: labelled_outcomes(outcomes),
            },
        }
    }

    /// The convergence point: `tick`'s certificate, committed on `shard` at
    /// `height`.
    ///
    /// The transaction list is read off the tick's own certificate — the one
    /// whose id matches the tick — rather than through
    /// [`Finalization::local_ec`], which panics on a malformed certificate.
    /// A viewer must not be able to take the tab down by rendering one.
    pub(crate) fn tick_finalized(
        wt: u64,
        shard: ShardId,
        height: BlockHeight,
        tick: &Finalization,
    ) -> Self {
        let id = tick.tick_id();
        let certificates = tick.execution_certificates();
        let txs = certificates
            .iter()
            .find(|ec| ec.tick_id() == id)
            .map_or_else(Vec::new, |ec| tx_labels(ec.tx_outcomes()));
        Self {
            wt,
            kind: TraceKind::TickFinalized {
                shard: shard.into(),
                height: height.inner(),
                opened_at: id.block_height().inner(),
                tick: TickLabel::new(id.shard_id(), id.block_height()),
                participants: certificates
                    .iter()
                    .map(|ec| ec.tick_id().shard_id().into())
                    .collect(),
                txs,
            },
        }
    }

    pub(crate) fn shard_terminal(
        wt: u64,
        shard: ShardId,
        height: BlockHeight,
        handoff_from: Option<BlockHeight>,
    ) -> Self {
        Self {
            wt,
            kind: TraceKind::ShardTerminal {
                shard: shard.into(),
                height: height.inner(),
                handoff_from: handoff_from.map(BlockHeight::inner),
            },
        }
    }

    pub(crate) fn message_delivered(wt: u64, record: &DeliveryRecord) -> Self {
        Self {
            wt,
            kind: TraceKind::MessageDelivered {
                from: record.from,
                to: record.to,
                class: record.class.as_str(),
                message_type: record.message_type,
                sent_at: as_millis(record.sent_at),
                delivered_at: as_millis(record.delivered_at),
                shard: record.shard.map(ShardPath::from),
            },
        }
    }

    pub(crate) fn traffic_sampled(wt: u64, sampled: u32, drain: &DeliveryDrain) -> Self {
        Self {
            wt,
            kind: TraceKind::TrafficSampled {
                by_class: MessageClass::ALL
                    .iter()
                    .map(|class| (*class, drain.by_class[*class as usize]))
                    .filter(|(_, tally)| tally.deliveries > 0)
                    .map(|(class, tally)| (class.as_str(), tally.deliveries, tally.bytes))
                    .collect(),
                sampled,
                dropped: drain.dropped,
            },
        }
    }

    pub(crate) const fn hosts_changed(wt: u64, hosts: Vec<HostRole>) -> Self {
        Self {
            wt,
            kind: TraceKind::HostsChanged { hosts },
        }
    }

    pub(crate) fn tx_submitted(wt: u64, tx: TxHash) -> Self {
        Self {
            wt,
            kind: TraceKind::TxSubmitted { tx: tx.into() },
        }
    }

    pub(crate) fn tx_status(
        wt: u64,
        tx: TxHash,
        status: &'static str,
        height: Option<u64>,
    ) -> Self {
        Self {
            wt,
            kind: TraceKind::TxStatusChanged {
                tx: tx.into(),
                status,
                height,
            },
        }
    }
}
