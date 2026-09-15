//! What the coordinator holds until evidence lets it through, and the
//! one release that re-drives it.
//!
//! Every artifact here was refused nothing: it arrived before what it
//! needs — a beacon epoch, a source block's commit proof, a departed
//! partner's settled set — and goes back through the handler it came
//! in by once that lands. Holding is bounded per reason and shard,
//! oldest dropped: a node this far behind re-fetches through ordinary
//! sync regardless, and the expected-certificate tracker re-fetches a
//! certificate on timeout.
//!
//! A finalization built here and held on its settlement is the
//! locally-produced class of [`hyperscale_types::verifiable`]: content-
//! addressed, held once, and never dropped on a clock — a deadline
//! verdict could contradict a settlement the partner already committed.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use hyperscale_types::{ExecutionCertificate, Finalization, ShardId, Verifiable};

/// Per-reason, per-shard cap on held artifacts. Node-local, not
/// consensus-critical.
const MAX_PARKED_PER_SHARD: usize = 256;

/// What an artifact waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Waiting {
    /// This node's beacon has not reached the artifact's committee
    /// epoch, so its signing committee cannot be resolved. Pure
    /// catch-up: under lookahead the committee is already globally
    /// fixed.
    Beacon,
    /// The source block of a certificate from this shard is not
    /// commit-proven. A bare QC certifies availability, and an f+1..2f
    /// corrupt committee can certify a sibling that never commits and
    /// export certificates computed from it.
    Proof(ShardId),
    /// The finalize gate deferred: a contained certificate names a
    /// shard scheduled to terminate, or past-terminal with its settled
    /// set not yet known. Re-asked on every commit and when a set is
    /// recorded; leaves only on evidence.
    Settlement,
}

/// What arrived.
pub enum Parked {
    /// A certificate received by broadcast or fetch.
    Certificate(Box<Verifiable<ExecutionCertificate>>),
    /// A finalization fetched from a peer.
    Fetched(Arc<Verifiable<Finalization>>),
    /// A finalization this validator built.
    Built(Arc<Verifiable<Finalization>>),
}

impl Parked {
    fn shard(&self) -> ShardId {
        match self {
            Self::Certificate(cert) => cert.shard_id(),
            Self::Fetched(tick) | Self::Built(tick) => tick.tick_id().shard_id(),
        }
    }
}

/// What landed, and so what may be released.
#[derive(Clone, Copy, Debug)]
pub enum Wake {
    /// The beacon advanced.
    Beacon,
    /// A block of this shard was commit-proven.
    Proof(ShardId),
    /// A block committed here.
    Commit,
    /// This departed shard's settled set was recorded: it stands in for
    /// the commit proof of everything it names, and answers the
    /// settlement question.
    SettledSet(ShardId),
}

impl Wake {
    fn releases(self, waiting: Waiting) -> bool {
        match (self, waiting) {
            (Self::Beacon, Waiting::Beacon)
            | (Self::Commit | Self::SettledSet(_), Waiting::Settlement) => true,
            (Self::Proof(shard) | Self::SettledSet(shard), Waiting::Proof(held)) => shard == held,
            _ => false,
        }
    }
}

/// Everything held, by reason and shard, each queue in arrival order.
#[derive(Default)]
pub struct ParkedArtifacts {
    held: BTreeMap<(Waiting, ShardId), VecDeque<Parked>>,
}

impl ParkedArtifacts {
    /// Hold `item` until `waiting` is answered.
    pub fn park(&mut self, waiting: Waiting, item: Parked) {
        let queue = self.held.entry((waiting, item.shard())).or_default();
        if let Parked::Built(tick) = &item {
            let id = tick.receipt_hash();
            queue.retain(|held| !matches!(held, Parked::Built(held) if held.receipt_hash() == id));
            queue.push_back(item);
            return;
        }
        queue.push_back(item);
        while queue.len() > MAX_PARKED_PER_SHARD {
            queue.pop_front();
        }
    }

    /// Take everything `wake` answers for, in reason then shard then
    /// arrival order. What still waits after re-driving is parked
    /// again by the handler that finds it so.
    pub fn release(&mut self, wake: Wake) -> Vec<Parked> {
        let (released, kept): (BTreeMap<_, _>, BTreeMap<_, _>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|((waiting, _), _)| wake.releases(*waiting));
        self.held = kept;
        released.into_values().flatten().collect()
    }

    /// How many artifacts wait on `waiting`.
    #[must_use]
    pub fn waiting_on(&self, waiting: impl Fn(Waiting) -> bool) -> usize {
        self.held
            .iter()
            .filter(|((held, _), _)| waiting(*held))
            .map(|(_, queue)| queue.len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        AggregateSignature, BlockHeight, ExecutionOutcome, GlobalReceiptRoot, Hash, SignerBitfield,
        TickId, TxHash, TxOutcome, WeightedTimestamp,
    };

    use super::*;

    fn cert(shard: ShardId, seed: u8) -> Parked {
        Parked::Certificate(Box::new(
            ExecutionCertificate::new(
                TickId::new(shard, BlockHeight::new(u64::from(seed))),
                WeightedTimestamp::ZERO,
                GlobalReceiptRoot::ZERO,
                vec![TxOutcome::new(
                    TxHash::from(Hash::from_bytes(&[seed])),
                    ExecutionOutcome::Aborted,
                )],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            )
            .into(),
        ))
    }

    #[test]
    fn a_wake_releases_its_own_reason_and_shard_only() {
        let a = ShardId::leaf(1, 0);
        let b = ShardId::leaf(1, 1);
        let mut parked = ParkedArtifacts::default();
        parked.park(Waiting::Proof(a), cert(a, 1));
        parked.park(Waiting::Proof(b), cert(b, 2));
        parked.park(Waiting::Beacon, cert(a, 3));

        assert_eq!(parked.release(Wake::Proof(a)).len(), 1);
        assert_eq!(parked.release(Wake::Commit).len(), 0);
        assert_eq!(parked.waiting_on(|w| matches!(w, Waiting::Proof(_))), 1);
        assert_eq!(parked.release(Wake::SettledSet(b)).len(), 1);
        assert_eq!(parked.release(Wake::Beacon).len(), 1);
        assert_eq!(parked.waiting_on(|_| true), 0);
    }

    #[test]
    fn holding_is_bounded_per_reason_and_shard_oldest_first() {
        let shard = ShardId::leaf(1, 0);
        let mut parked = ParkedArtifacts::default();
        for i in 0..=MAX_PARKED_PER_SHARD {
            parked.park(Waiting::Beacon, cert(shard, u8::try_from(i % 200).unwrap()));
        }
        let released = parked.release(Wake::Beacon);
        assert_eq!(released.len(), MAX_PARKED_PER_SHARD);
        let Parked::Certificate(first) = &released[0] else {
            panic!("a certificate was parked");
        };
        assert_eq!(
            first.block_height(),
            BlockHeight::new(1),
            "the oldest was dropped"
        );
    }
}
