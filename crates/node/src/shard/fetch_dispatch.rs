//! Generic fetch dispatch + tick-timer plumbing.

use std::collections::BTreeSet;
use std::time::Duration;

use hyperscale_core::{FetchIds, ProtocolEvent, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{LocalTimestamp, MessageClass, ShardId, ValidatorId};

use super::{ShardLoop, TimerOp};
use crate::beacon::{self, BeaconCandidateBinding, BeaconProposalBinding, ShardWitnessBinding};
use crate::fetch::{FetchBinding, FetchInput, FetchOutput, Intent, Release};
use crate::shard::consensus::ProposalBinding;
use crate::shard::cross_shard::{
    ExecCertBinding, FinalizationBinding, LocalProvisionBinding, ProvisionBinding,
    SettledTxsBinding, StateProofBinding,
};
use crate::shard::instances::InstanceRecordBinding;
use crate::shard::mempool::TransactionBinding;
use crate::shard::packages::PackageArtifactBinding;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Dispatch outputs from a [`FetchBinding`]'s state machine on this
    /// shard: emit one network request per chunk (or per id, for `PER_ID`
    /// bindings) and route the response through the binding's callback.
    ///
    /// The shard's id is threaded through to per-binding callbacks so the
    /// response can be routed back to this shard.
    pub(in crate::shard) fn process_fetch_outputs<B: FetchBinding>(
        &self,
        outputs: Vec<FetchOutput<B::Id>>,
    ) {
        let local_shard = self.shard;
        for FetchOutput::Send {
            ids,
            shard,
            preferred,
            class,
        } in outputs
        {
            if B::PER_ID {
                for id in ids {
                    B::dispatch_chunk(
                        vec![id],
                        local_shard,
                        shard,
                        preferred,
                        class,
                        &*self.process.network,
                        self.event_sender(),
                    );
                }
            } else {
                B::dispatch_chunk(
                    ids,
                    local_shard,
                    shard,
                    preferred,
                    class,
                    &*self.process.network,
                    self.event_sender(),
                );
            }
        }
    }

    /// Drive a single fetch binding on this shard: feed an input and
    /// dispatch the outputs the handler returns. Each handler ends with
    /// `spawn_pending_fetches` so freed slots are filled in the same
    /// event-loop turn — this wrapper just routes the FSM-emitted Sends
    /// to the network.
    pub(crate) fn drive_fetch<B: FetchBinding>(&mut self, input: FetchInput<B::Id>) {
        if let FetchInput::Request {
            ids,
            shard,
            preferred,
            class,
        } = &input
        {
            tracing::trace!(
                binding = B::NAME,
                local_shard = ?self.shard,
                ids = ids.len(),
                shard = ?shard,
                preferred = ?preferred,
                class = ?class,
                "Dispatching fetch request"
            );
        }
        let outputs = B::fetch_mut(&mut self.io).handle(input);
        self.process_fetch_outputs::<B>(outputs);
    }

    /// Release a batch of ids from the binding that fetches them: a
    /// response boundary's failure or fulfilment and a coordinator's
    /// `Action::AbandonFetch` all arrive here.
    pub(in crate::shard) fn release_fetch(&mut self, ids: FetchIds, how: Release) {
        self.drive_fetch_ids(ids, how.into());
    }

    /// Ask `shard`'s committee for a batch of ids.
    pub(in crate::shard) fn request_fetch(
        &mut self,
        ids: FetchIds,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
    ) {
        self.drive_fetch_ids(
            ids,
            Intent::Ask {
                shard,
                preferred,
                class,
            },
        );
    }

    /// The one place a [`FetchIds`] arm is matched back to its binding.
    /// Asking and releasing differ only in the [`FetchInput`] the
    /// [`Intent`] builds, so they share this walk rather than each
    /// keeping their own copy of it.
    fn drive_fetch_ids(&mut self, ids: FetchIds, intent: Intent) {
        match ids {
            FetchIds::Transactions(ids) => {
                self.drive_fetch::<TransactionBinding>(intent.input(ids));
            }
            FetchIds::LocalProvisions(ids) => {
                self.drive_fetch::<LocalProvisionBinding>(intent.input(ids));
            }
            FetchIds::Finalizations(ids) => {
                self.drive_fetch::<FinalizationBinding>(intent.input(ids));
            }
            FetchIds::RemoteProvisions(ids) => {
                self.drive_fetch::<ProvisionBinding>(intent.input(ids));
            }
            FetchIds::ExecutionCerts(ids) => self.drive_fetch::<ExecCertBinding>(intent.input(ids)),
            FetchIds::StateProofs(ids) => self.drive_fetch::<StateProofBinding>(intent.input(ids)),
            FetchIds::SettledTxs(ids) => self.drive_fetch::<SettledTxsBinding>(intent.input(ids)),
            FetchIds::Proposals(ids) => self.drive_fetch::<ProposalBinding>(intent.input(ids)),
            FetchIds::BeaconProposals(ids) => {
                self.drive_fetch::<BeaconProposalBinding>(intent.input(ids));
            }
            FetchIds::BeaconCandidates(ids) => {
                self.drive_fetch::<BeaconCandidateBinding>(intent.input(ids));
            }
            FetchIds::ShardWitnesses(ids) => {
                self.drive_fetch::<ShardWitnessBinding>(intent.input(ids));
            }
            FetchIds::PackageArtifacts(ids) => {
                self.drive_fetch::<PackageArtifactBinding>(intent.input(ids));
            }
            FetchIds::InstanceRecords(ids) => {
                self.drive_fetch::<InstanceRecordBinding>(intent.input(ids));
            }
        }
    }

    /// Release what `B`'s fetch still holds `within` a scope that
    /// `wanted` no longer names. For a fetch whose consumer re-derives
    /// its whole wanted set each pass, this is the only retirement:
    /// nothing answers for an id the consumer stopped asking about.
    pub(in crate::shard) fn abandon_unwanted<B: FetchBinding>(
        &mut self,
        wanted: &BTreeSet<B::Id>,
        within: impl Fn(&B::Id) -> bool,
    ) {
        let stale: Vec<B::Id> = B::fetch_mut(&mut self.io)
            .pending_ids()
            .filter(|id| within(id) && !wanted.contains(id))
            .cloned()
            .collect();
        if !stale.is_empty() {
            self.drive_fetch::<B>(FetchInput::Abandoned { ids: stale });
        }
    }

    /// Route an admission `ProtocolEvent` to whichever fetch bindings
    /// drain in-flight tracking on it, scoped to this shard. Goes
    /// through `drive_fetch` so the freed slots' `spawn_pending_fetches`
    /// outputs reach the network in the same event-loop turn instead
    /// of being silently dropped.
    pub(in crate::shard) fn drive_fetch_admission(&mut self, event: &ProtocolEvent) {
        match event {
            ProtocolEvent::TransactionsAdmitted { txs } => {
                let ids: Vec<_> = txs.iter().map(|tx| tx.hash()).collect();
                if !ids.is_empty() {
                    self.drive_fetch::<TransactionBinding>(FetchInput::Admitted { ids });
                }
            }
            ProtocolEvent::ProvisionsAdmitted { provisions, .. } => {
                self.drive_fetch::<LocalProvisionBinding>(FetchInput::Admitted {
                    ids: vec![provisions.hash()],
                });
                self.drive_fetch::<ProvisionBinding>(FetchInput::Admitted {
                    ids: vec![(
                        provisions.source_shard(),
                        provisions.target_shard(),
                        provisions.block_height(),
                    )],
                });
            }
            ProtocolEvent::FinalizationsAdmitted { finalizations } => {
                let ids: Vec<_> = finalizations.iter().map(|w| w.receipt_hash()).collect();
                self.drive_fetch::<FinalizationBinding>(FetchInput::Admitted { ids });
            }
            ProtocolEvent::ExecutionCertificateAdmitted { certificate } => {
                // The certificate answers for every transaction it covers,
                // so admitting it closes each of those fetches.
                let shard = certificate.shard_id();
                let ids: Vec<_> = certificate
                    .tx_outcomes()
                    .iter()
                    .map(|outcome| (shard, outcome.tx_hash()))
                    .collect();
                self.drive_fetch::<ExecCertBinding>(FetchInput::Admitted { ids });
            }
            _ => {}
        }
    }
}

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Refresh this shard's `FetchTick` timer based on whether any of its
    /// subsystems (beacon fetches, mempool, consensus block-sync, beacon-block
    /// sync, cross-shard) has pending work. Each shard manages its own ticker
    /// — a shard with idle fetches stops paying for the 200ms wake-up while
    /// busier shards keep ticking.
    pub(crate) fn update_fetch_tick_timer(&mut self) {
        let any_pending = self.io.beacon_fetch.has_pending()
            || self.io.packages.has_pending()
            || self.io.instances.has_pending()
            || self.io.mempool.has_pending()
            || self.io.consensus.has_pending()
            || beacon::has_pending(&self.beacon_block)
            || self.io.cross_shard.has_pending();
        if let Some(op) = self.fetch_tick.refresh(self.shard, self.now, any_pending) {
            self.pending_timer_ops.push(op);
        }
    }
}

/// A shard's `FetchTick`, armed once and left to fire.
///
/// Setting a timer replaces the one pending, so a tick set again on every
/// step would fire only after a step-free interval, and a shard stepping
/// more often than that would never tick. The tick is set when nothing is
/// armed, or when the armed one is overdue, so a fire lost on its way
/// cannot leave the shard unticked.
#[derive(Debug, Default)]
pub struct FetchTicker {
    /// When the armed tick is due, or `None` while none is armed.
    due: Option<LocalTimestamp>,
}

impl FetchTicker {
    /// Interval for the periodic fetch tick timer.
    const INTERVAL: Duration = Duration::from_millis(200);

    /// The timer op `shard`'s tick needs at `now`, given whether any of its
    /// fetches has pending work: a set when it is due one, a cancel when
    /// it is armed with nothing left to do.
    fn refresh(&mut self, shard: ShardId, now: LocalTimestamp, pending: bool) -> Option<TimerOp> {
        if !pending {
            return self.due.take().map(|_| TimerOp::Cancel {
                shard: Some(shard),
                id: TimerId::FetchTick,
            });
        }
        if self.due.is_some_and(|due| now < due) {
            return None;
        }
        self.due = Some(now.plus(Self::INTERVAL));
        Some(TimerOp::Set {
            shard: Some(shard),
            id: TimerId::FetchTick,
            duration: Self::INTERVAL,
        })
    }

    /// The armed tick fired.
    pub(super) const fn fired(&mut self) {
        self.due = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARD: ShardId = ShardId::leaf(1, 0);

    fn is_set(op: Option<&TimerOp>) -> bool {
        matches!(
            op,
            Some(TimerOp::Set {
                id: TimerId::FetchTick,
                ..
            })
        )
    }

    /// Steps arriving faster than the interval leave the armed tick to
    /// fire: none of them sets it again until it is due.
    #[test]
    fn a_busy_shard_leaves_its_armed_tick_to_fire() {
        let mut ticker = FetchTicker::default();
        let t0 = LocalTimestamp::from_millis(1_000);
        assert!(is_set(ticker.refresh(SHARD, t0, true).as_ref()));
        for step in 1..FetchTicker::INTERVAL.as_millis() {
            let now = t0.plus(Duration::from_millis(u64::try_from(step).unwrap()));
            assert!(
                ticker.refresh(SHARD, now, true).is_none(),
                "a step {step}ms after arming pushed the tick back",
            );
        }
        ticker.fired();
        let fired_at = t0.plus(FetchTicker::INTERVAL);
        assert!(is_set(ticker.refresh(SHARD, fired_at, true).as_ref()));
    }

    /// An armed tick whose fire never arrived is set again once overdue,
    /// and a shard with nothing pending cancels the one armed, once.
    #[test]
    fn an_overdue_tick_is_set_again_and_an_idle_one_cancelled() {
        let mut ticker = FetchTicker::default();
        let t0 = LocalTimestamp::from_millis(1_000);
        assert!(is_set(ticker.refresh(SHARD, t0, true).as_ref()));
        let overdue = t0.plus(FetchTicker::INTERVAL);
        assert!(is_set(ticker.refresh(SHARD, overdue, true).as_ref()));
        assert!(matches!(
            ticker.refresh(SHARD, overdue, false),
            Some(TimerOp::Cancel {
                id: TimerId::FetchTick,
                ..
            })
        ));
        assert!(ticker.refresh(SHARD, overdue, false).is_none());
    }
}
