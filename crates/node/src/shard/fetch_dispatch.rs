//! Generic fetch dispatch + tick-timer plumbing.

use std::collections::BTreeSet;
use std::time::Duration;

use hyperscale_core::{FetchIds, ProtocolEvent, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{LocalTimestamp, MessageClass, ShardId, ValidatorId};
use tracing::warn;

use super::{ShardIo, ShardLoop, TimerOp, TimerOwner};
use crate::fetch::{FetchInput, FetchOutput, FetchedBy, Intent, Release, ShardReply};
use crate::shard::consensus::ProposalBinding;
use crate::shard::cross_shard::{
    FinalizationBinding, LocalProvisionBinding, ProvisionBinding, SettledTxsBinding,
    StateProofBinding, VerdictProofBinding,
};
use crate::shard::instances::InstanceRecordBinding;
use crate::shard::mempool::TransactionBinding;
use crate::shard::packages::PackageArtifactBinding;

/// Every fetch binding a shard loop drives, by the [`FetchIds`] arm that
/// carries its ids, handed to `$apply` as `Arm => Binding,` pairs. The
/// router's match over [`FetchIds`] is exhaustive, so a new arm cannot
/// leave this list, and everything that fans out over the bindings
/// expands it rather than keeping its own copy.
macro_rules! every_fetch_binding {
    ($apply:ident) => {
        $apply! {
            Transactions => TransactionBinding,
            LocalProvisions => LocalProvisionBinding,
            Finalizations => FinalizationBinding,
            RemoteProvisions => ProvisionBinding,
            StateProofs => StateProofBinding,
            VerdictProofs => VerdictProofBinding,
            SettledTxs => SettledTxsBinding,
            Proposals => ProposalBinding,
            PackageArtifacts => PackageArtifactBinding,
            InstanceRecords => InstanceRecordBinding,
        }
    };
}

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Dispatch outputs from a [`FetchBinding`]'s state machine on this
    /// shard: emit one network request per chunk (or per id, for `PER_ID`
    /// bindings) and route the response back to this shard's loop.
    pub(in crate::shard) fn process_fetch_outputs<B: FetchedBy<ShardIo<S>>>(
        &self,
        outputs: Vec<FetchOutput<B::Id>>,
    ) {
        let reply = ShardReply {
            shard: self.shard,
            sender: self.event_sender().clone(),
        };
        let network = &*self.process.network;
        for FetchOutput::Send { ids, route } in outputs {
            if B::PER_ID {
                for id in ids {
                    B::dispatch_chunk(vec![id], route, network, &reply);
                }
            } else {
                B::dispatch_chunk(ids, route, network, &reply);
            }
        }
    }

    /// Drive a single fetch binding on this shard: feed an input and
    /// dispatch the outputs the handler returns. Each handler ends with
    /// `spawn_pending_fetches` so freed slots are filled in the same
    /// event-loop turn — this wrapper just routes the FSM-emitted Sends
    /// to the network.
    pub(crate) fn drive_fetch<B: FetchedBy<ShardIo<S>>>(&mut self, input: FetchInput<B::Id>) {
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
        macro_rules! route {
            ($($arm:ident => $binding:ty,)*) => {
                match ids {
                    $(FetchIds::$arm(ids) => self.drive_fetch::<$binding>(intent.input(ids)),)*
                    // No replica emits a beacon fetch: the host's beacon
                    // loop drives them for its fold and participants.
                    FetchIds::Beacon(ids) => {
                        warn!(?ids, "a beacon fetch reached a shard loop — dropping");
                    }
                }
            };
        }
        every_fetch_binding!(route);
    }

    /// Tick every fetch binding on this shard. The list is the one
    /// [`Self::drive_fetch_ids`] matches over, so a binding its ids can
    /// reach is a binding the tick reaches.
    pub(in crate::shard) fn tick_every_fetch(&mut self) {
        macro_rules! tick {
            ($($arm:ident => $binding:ty,)*) => {
                $(self.drive_fetch::<$binding>(FetchInput::Tick);)*
            };
        }
        every_fetch_binding!(tick);
    }

    /// Release what `B`'s fetch still holds `within` a scope that
    /// `wanted` no longer names. For a fetch whose consumer re-derives
    /// its whole wanted set each pass, this is the only retirement:
    /// nothing answers for an id the consumer stopped asking about.
    pub(in crate::shard) fn abandon_unwanted<B: FetchedBy<ShardIo<S>>>(
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
    /// subsystems (packages, instances, mempool, consensus block-sync,
    /// cross-shard) has pending work. Each shard manages its own ticker
    /// — a shard with idle fetches stops paying for the 200ms wake-up while
    /// busier shards keep ticking.
    pub(crate) fn update_fetch_tick_timer(&mut self) {
        let any_pending = self.io.packages.has_pending()
            || self.io.instances.has_pending()
            || self.io.mempool.has_pending()
            || self.io.consensus.has_pending()
            || self.io.cross_shard.has_pending();
        if let Some(op) =
            self.fetch_tick
                .refresh(TimerOwner::Loop(self.shard), self.now, any_pending)
        {
            self.pending_timer_ops.push(op);
        }
    }
}

/// A loop's `FetchTick`, armed once and left to fire.
///
/// Setting a timer replaces the one pending, so a tick set again on every
/// step would fire only after a step-free interval, and a loop stepping
/// more often than that would never tick. The tick is set when nothing is
/// armed, or when the armed one is overdue, so a fire lost on its way
/// cannot leave the loop unticked.
#[derive(Debug, Default)]
pub struct FetchTicker {
    /// When the armed tick is due, or `None` while none is armed.
    due: Option<LocalTimestamp>,
}

impl FetchTicker {
    /// Interval for the periodic fetch tick timer.
    const INTERVAL: Duration = Duration::from_millis(200);

    /// The timer op `owner`'s tick needs at `now`, given whether any of
    /// its fetches has pending work: a set when it is due one, a cancel
    /// when it is armed with nothing left to do.
    pub(crate) fn refresh(
        &mut self,
        owner: TimerOwner,
        now: LocalTimestamp,
        pending: bool,
    ) -> Option<TimerOp> {
        if !pending {
            return self.due.take().map(|_| TimerOp::Cancel {
                owner,
                id: TimerId::FetchTick,
            });
        }
        if self.due.is_some_and(|due| now < due) {
            return None;
        }
        self.due = Some(now.plus(Self::INTERVAL));
        Some(TimerOp::Set {
            owner,
            id: TimerId::FetchTick,
            duration: Self::INTERVAL,
        })
    }

    /// The armed tick fired.
    pub(crate) const fn fired(&mut self) {
        self.due = None;
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_core::BeaconFetchIds;
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{BeaconBlockHash, BlockHash, BlockHeight, Epoch, Hash};

    use super::*;
    use crate::shard::test_host::{Fixture, Loop, loop_of};

    const SHARD: ShardId = ShardId::leaf(1, 0);

    /// Fail `id` on `B`'s fetch twice before a tick, so it is held, and
    /// return whether the loop's fetch tick sent it again.
    fn tick_resends_a_held<B: FetchedBy<ShardIo<SimShardStorage>>>(
        shard_loop: &mut Loop,
        id: &B::Id,
    ) -> bool {
        let ids = || B::ids(vec![id.clone()]);
        shard_loop.request_fetch(ids(), SHARD, None, None);
        shard_loop.release_fetch(ids(), Release::Failed);
        shard_loop.release_fetch(ids(), Release::Failed);
        assert_eq!(
            B::fetch_mut(&mut shard_loop.io).in_flight_count(),
            0,
            "{}: a second failure before the tick holds the id",
            B::NAME,
        );
        shard_loop.handle_fetch_tick();
        B::fetch_mut(&mut shard_loop.io).in_flight_count() == 1
    }

    /// The loop's fetch tick reaches the vote-named proposal fetch, so an
    /// id it holds after a second failure goes out again on the tick.
    #[test]
    fn the_fetch_tick_resends_a_held_proposal() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        let shard_loop = loop_of(&mut host);
        assert!(tick_resends_a_held::<ProposalBinding>(
            shard_loop,
            &BlockHash::from_raw(Hash::from_bytes(b"proposal")),
        ));
    }

    /// A beacon fetch that reaches a shard loop is dropped: nothing is
    /// asked, nothing is left pending, and the loop's tick drives none.
    #[test]
    fn the_shard_fetch_tick_drives_no_beacon_fetch() {
        let fix = Fixture::new();
        let mut host = fix.host(BlockHeight::GENESIS);
        let _ = host.network().drain_pending_requests();
        let shard_loop = loop_of(&mut host);
        let candidate = (
            Epoch::new(1),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"candidate")),
        );
        shard_loop.request_fetch(
            FetchIds::Beacon(BeaconFetchIds::Candidates(vec![candidate])),
            SHARD,
            None,
            None,
        );
        shard_loop.handle_fetch_tick();
        shard_loop.pending_timer_ops.clear();
        shard_loop.update_fetch_tick_timer();
        assert!(
            !shard_loop
                .pending_timer_ops
                .iter()
                .any(|op| is_set(Some(op))),
            "nothing is left pending for the shard's tick to drive",
        );
        assert!(
            host.network().drain_pending_requests().is_empty(),
            "no beacon ask leaves a shard loop",
        );
    }

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
        assert!(is_set(
            ticker.refresh(TimerOwner::Loop(SHARD), t0, true).as_ref()
        ));
        for step in 1..FetchTicker::INTERVAL.as_millis() {
            let now = t0.plus(Duration::from_millis(u64::try_from(step).unwrap()));
            assert!(
                ticker.refresh(TimerOwner::Loop(SHARD), now, true).is_none(),
                "a step {step}ms after arming pushed the tick back",
            );
        }
        ticker.fired();
        let fired_at = t0.plus(FetchTicker::INTERVAL);
        assert!(is_set(
            ticker
                .refresh(TimerOwner::Loop(SHARD), fired_at, true)
                .as_ref()
        ));
    }

    /// An armed tick whose fire never arrived is set again once overdue,
    /// and a shard with nothing pending cancels the one armed, once.
    #[test]
    fn an_overdue_tick_is_set_again_and_an_idle_one_cancelled() {
        let mut ticker = FetchTicker::default();
        let t0 = LocalTimestamp::from_millis(1_000);
        assert!(is_set(
            ticker.refresh(TimerOwner::Loop(SHARD), t0, true).as_ref()
        ));
        let overdue = t0.plus(FetchTicker::INTERVAL);
        assert!(is_set(
            ticker
                .refresh(TimerOwner::Loop(SHARD), overdue, true)
                .as_ref()
        ));
        assert!(matches!(
            ticker.refresh(TimerOwner::Loop(SHARD), overdue, false),
            Some(TimerOp::Cancel {
                id: TimerId::FetchTick,
                ..
            })
        ));
        assert!(
            ticker
                .refresh(TimerOwner::Loop(SHARD), overdue, false)
                .is_none()
        );
    }
}
