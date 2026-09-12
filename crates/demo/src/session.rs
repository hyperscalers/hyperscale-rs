//! The simulation session and its event derivation.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_effects_bridge::account_address;
use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_simulation::{CryptoScheme, SimConfig, SimulationRunner};
use hyperscale_storage::ShardChainReader;
use hyperscale_transactions::{Client, Terms};
use hyperscale_types::{
    BeaconChainConfig, BlockHeight, Ed25519PrivateKey, MAX_VALIDITY_RANGE, NetworkDefinition,
    NetworkId, PrincipalAddr, Provisions, ReshapeThresholds, ShardId, SharedCertificates,
    TimestampRange, Transaction, TransactionDecision, TransactionStatus, TxHash, ValidatorId,
    Verifiable, WeightedTimestamp,
};

use crate::event::{HostRole, ObserverSeat, ShardPath, TraceEvent};

/// The signer for demo account `seed`, and the preallocated account it
/// controls. Deterministic so a seeded session funds and spends the same
/// accounts every run.
fn signer_from_seed(seed: u8) -> Ed25519PrivateKey {
    Ed25519PrivateKey::from_bytes(&[seed; 32]).expect("32 bytes is a valid Ed25519 key")
}

fn account_from_seed(seed: u8) -> PrincipalAddr {
    account_address(&signer_from_seed(seed).public_key().0)
}

/// How far back of `now` a validity window opens, absorbing the chain's
/// anchor trailing the session clock.
const VALIDITY_BACK: Duration = Duration::from_secs(5);

/// Slack held under [`MAX_VALIDITY_RANGE`] so a window built against the
/// session clock is still well formed at an anchor trailing it.
const VALIDITY_SLACK: Duration = Duration::from_secs(15);

/// How far past `now` a validity window runs — the rest of the budget
/// once the backward opening and the anchor slack are taken.
const VALIDITY_FORWARD: Duration =
    MAX_VALIDITY_RANGE.saturating_sub(VALIDITY_BACK.saturating_add(VALIDITY_SLACK));

/// A validity window bracketing `now`, wide enough that a transaction stays
/// valid while it waits out ordering and settlement.
fn validity_around(now: Duration) -> TimestampRange {
    TimestampRange::new(
        WeightedTimestamp::ZERO.plus(now.saturating_sub(VALIDITY_BACK)),
        WeightedTimestamp::ZERO.plus(now + VALIDITY_FORWARD),
    )
}

/// Deliveries reported individually per step.
///
/// More than a viewer can animate in one frame, and far fewer than a busy
/// step carries — the point of a budget is that the two need not match. What
/// the budget leaves out is still counted, so a thinned sample costs detail
/// and never accuracy.
const DELIVERY_SAMPLE: usize = 64;

/// Beacon epoch length a session runs at.
///
/// A reshape is paced in epochs — trigger, admission, cohort draw, snap-sync,
/// readiness gate, flip — so the epoch sets how long a viewer waits before the
/// page shows a split. The production five-minute epoch makes that span
/// thousands of blocks, which is minutes of boot before anything moves. Thirty
/// seconds is the shortest value the recovery timeouts (`SPC_VIEW_TIMEOUT`,
/// `SKIP_TIMEOUT`) are still sized against.
///
/// A constant of the demo, not of the simulation: the sims raise their epoch
/// to production parity under their `ci` feature, and a session that followed
/// them there would take half an hour of simulated time to split.
const EPOCH_MS: u64 = 30_000;

/// Simulated time between reshape-orchestrator polls.
///
/// Polls land on a fixed grid of simulated time, so a caller asking for one
/// long span and a caller asking for the short spans covering it drive the
/// same run. Pacing on the span instead would make the run a function of how
/// often the caller happens to paint.
///
/// The value has to be well inside `VIEW_CHANGE_TIMEOUT`. A duty gated on
/// chain progress — recognising a terminal, proving its commit, seeding a
/// half from its parent — retries once per poll, so the poll interval is
/// what a child's committee seats staggered across. Seat it slower than the
/// fresh committee's first round and the members already seated spend that
/// round timing out on the ones that are not.
const RESHAPE_TICK_MS: u64 = 100;

/// Genesis-funded accounts the load generator draws from. Small enough that
/// every transfer pair is visually distinguishable, large enough that a
/// session spreads its traffic rather than piling every transfer onto one
/// account.
const ACCOUNTS: u8 = 8;

/// What each demo account holds at genesis — far above anything a session
/// spends, so the load generator never runs one dry.
///
/// What it has to clear is the fee *ceiling*, not the fee: admission holds
/// [`TRANSFER_MAX_FEE`] against the payer until the transfer settles, so a
/// rotation of [`ACCOUNTS`] payers can only ever have
/// `funding / TRANSFER_MAX_FEE` transfers apiece in flight or spent, and
/// past that the session stops moving with nothing on screen to say why.
const ACCOUNT_FUNDING: u128 = 100_000_000;

/// What one demo transfer moves, and the fee ceiling it signs. Placeholder
/// pricing; the demo is about movement, not economics.
const TRANSFER_AMOUNT: u128 = 1;
const TRANSFER_MAX_FEE: u128 = 1_000;

/// How far a status has progressed, for picking the best of several hosts'
/// answers. A terminal decision beats an ordering, which beats admission.
const fn status_rank(status: &TransactionStatus) -> u8 {
    match status {
        TransactionStatus::Pending => 0,
        TransactionStatus::Committed(_) => 1,
        TransactionStatus::LegFinalized => 2,
        TransactionStatus::Completed(_) => 3,
    }
}

/// The terminal outcome, in the vocabulary the docs use.
const fn decision_label(decision: TransactionDecision) -> &'static str {
    match decision {
        TransactionDecision::Accept => "succeeded",
        TransactionDecision::Reject => "rejected",
        TransactionDecision::Aborted => "aborted",
    }
}

/// Precedence when several hosts have decided: the same order the protocol
/// itself aggregates outcomes in across a tick's certificates, so the demo
/// reduces a transaction the way its own participants would.
const fn decision_precedence(decision: TransactionDecision) -> u8 {
    match decision {
        TransactionDecision::Accept => 0,
        TransactionDecision::Reject => 1,
        TransactionDecision::Aborted => 2,
    }
}

/// A status to display, and the height that ordered the transaction where
/// there is one.
type Reported = (&'static str, Option<u64>);

/// Reduce every host's answer to the one status to report.
///
/// Status is per host, and a host only tracks the shards it serves, so a
/// transaction's answer has to be pieced together from all of them: after a
/// split, whichever child a host does not carry reports nothing at all, and
/// polling one host would leave those transactions pending forever.
///
/// Every host that has decided is supposed to have decided the same way
/// (INV-EXEC-1), so the precedence below is not expected to discriminate
/// between them. It is here because *something* has to be well defined:
/// reducing by "furthest progressed" alone leaves every terminal decision
/// tied, and a settled transaction then changes on screen as each further
/// host finishes and the poll order resolves the tie differently.
fn resolve_status(answers: &[TransactionStatus]) -> Option<Reported> {
    let decided = answers
        .iter()
        .filter_map(|status| match status {
            TransactionStatus::Completed(decision) => Some(*decision),
            _ => None,
        })
        .max_by_key(|decision| decision_precedence(*decision));
    if let Some(decision) = decided {
        return Some((decision_label(decision), None));
    }
    // Nothing terminal yet: the furthest along any host has got.
    answers
        .iter()
        .max_by_key(|status| status_rank(status))
        .map(|status| match status {
            TransactionStatus::Committed(height) => ("committed", Some(height.inner())),
            TransactionStatus::LegFinalized => ("leg finalized", None),
            _ => ("pending", None),
        })
}

/// Derive the settlement events a block attests to: the state it took
/// delivery of and the finalizations it committed.
///
/// A bundle reaches a block only once this committee has checked its
/// merkle multiproof against the source's QC-attested state root, and a
/// finalization only once every certificate it carries is in hand and
/// verified — 2f+1 aggregated signatures each. That is what makes an arc
/// drawn from one of these a claim about proofs rather than about
/// messages.
///
/// An empty bundle — a shard's commitment of a transaction it has nothing
/// to serve for — moves no state and draws nothing. Single-shard ticks
/// land here too and produce no arcs of their own: they carry one
/// certificate, from the committing shard itself.
fn settlement_events(
    events: &mut Vec<TraceEvent>,
    wt: u64,
    shard: ShardId,
    height: BlockHeight,
    provisions: &[Arc<Verifiable<Provisions>>],
    certificates: &SharedCertificates,
) {
    for bundle in provisions {
        let bundle = bundle.as_unverified();
        let delivered: Vec<TxHash> = bundle
            .transactions()
            .iter()
            .filter(|entry| !entry.entries.is_empty())
            .map(|entry| entry.tx_hash)
            .collect();
        if !delivered.is_empty() {
            events.push(TraceEvent::provisions_verified(
                wt, bundle, shard, height, delivered,
            ));
        }
    }
    for tick in certificates.iter() {
        let tick = tick.as_unverified();
        for certificate in tick.execution_certificates() {
            events.push(TraceEvent::execution_certified(
                wt,
                certificate.tick_id(),
                shard,
                height,
                certificate.tx_outcomes(),
            ));
        }
        events.push(TraceEvent::tick_finalized(wt, shard, height, tick));
    }
}

/// What each host serves, in host order.
///
/// Read from what hosts actually carry rather than from the trie, because
/// that is the question the roster answers: which committee a host is in, and
/// whether it is sitting in the free pool waiting to staff one.
///
/// Which of those it holds a seat on comes from the topology instead. The two
/// disagree for as long as a rotation entrant takes to bootstrap: it carries
/// the shard from the moment it starts syncing, and joins
/// `consensus_committee_for_shard` only once it signals Ready.
fn roster(runner: &SimulationRunner) -> Vec<HostRole> {
    let topology = (0..runner.num_hosts()).find_map(|host| runner.host_topology(host));
    (0..runner.num_hosts())
        .map(|host| {
            let shards = runner.hosted_shards_of(host);
            // One vnode per host, so the host index is the validator it signs
            // as — the same identity the committee lists.
            let me = ValidatorId::new(u64::from(host));
            let seated = shards
                .iter()
                .copied()
                .filter(|&shard| {
                    topology
                        .as_ref()
                        .is_some_and(|t| t.consensus_committee_for_shard(shard).contains(&me))
                })
                .map(ShardPath::from)
                .collect();
            // A pending split binds two populations to a child ahead of the
            // cut, and a host is only ever in one of them. Observer cohorts
            // are drawn from the free pool, keyed by the shard splitting;
            // parent halves are the splitting committee's own members, keyed
            // by the child each will seat on.
            let observing = topology
                .as_ref()
                .map(|t| {
                    let observers =
                        t.reshape_observer_cohorts()
                            .iter()
                            .filter_map(|(&shard, cohort)| {
                                let seat = cohort.get(&me)?;
                                Some(ObserverSeat {
                                    shard: ShardPath::from(shard),
                                    child: ShardPath::from(seat.shard),
                                    ready: seat.ready,
                                })
                            });
                    let halves =
                        t.reshape_parent_half_cohorts()
                            .iter()
                            .filter_map(|(&child, cohort)| {
                                Some(ObserverSeat {
                                    shard: ShardPath::from(*cohort.get(&me)?),
                                    child: ShardPath::from(child),
                                    // A member already holds the state its
                                    // half re-roots from; nothing to sync.
                                    ready: true,
                                })
                            });
                    observers.chain(halves).collect()
                })
                .unwrap_or_default();
            HostRole {
                host,
                shards: shards.iter().copied().map(ShardPath::from).collect(),
                seated,
                observing,
                pooled: u32::try_from(runner.pooled_len(host)).unwrap_or(u32::MAX),
            }
        })
        .collect()
}

/// How the cluster a session opens is shaped.
#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    /// Validators per shard committee.
    pub shard_size: u32,
    /// Leaves the topology may grow to. Must be a power of two.
    ///
    /// The session always *starts* at a single ROOT shard, because that is
    /// where every network starts. Above one, the split trigger is armed and
    /// the pool is staffed for the splits it allows, so the topology grows
    /// while the session runs and a viewer sees the reshape happen rather
    /// than arriving after it. Growth stops on its own once the pool can no
    /// longer staff a child committee: admission is gated on a deep enough
    /// free pool, so the surplus is the ceiling.
    pub max_shards: u32,
    /// Validators pooled beyond what the splits consume.
    ///
    /// Every split draws a full cohort, so a session staffed only for its
    /// splits ends with an empty pool — and committee rotation refuses to
    /// run without one, because removing a member it cannot backfill would
    /// shrink the committee below `shard_size`. Spares are what let a
    /// validator rotate.
    pub pool_spares: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            shard_size: 4,
            max_shards: 1,
            pool_spares: 0,
        }
    }
}

/// A running simulation plus the watermarks of what has been reported.
pub struct Session {
    runner: SimulationRunner,
    now: Duration,
    /// Highest height already emitted per shard. A shard absent from the map
    /// has had nothing emitted yet.
    reported_through: BTreeMap<ShardId, BlockHeight>,
    /// The partition as last reported, so a step emits only changes.
    reported_shards: Vec<ShardId>,
    /// First height seen carrying a settled-transaction root, per shard — the
    /// start of the handoff window a terminating shard closes with its last
    /// block. Absent for every shard that is not on its way out.
    handoff_from: BTreeMap<ShardId, BlockHeight>,
    /// Highest beacon epoch already reported.
    reported_epoch: Option<u64>,
    /// Highest canonical weighted timestamp any shard has reported.
    ///
    /// Derived events — a transaction's status, a partition change — are
    /// observations *of* committed chain content, so they are stamped here
    /// rather than on the session's own clock. Mixing the two would put a
    /// derived event ahead of the blocks it was derived from, because
    /// attested time necessarily trails the clock the harness is stepping.
    attested_wt: u64,
    /// Submitted transactions and the last status reported for each, so a
    /// step emits only transitions.
    tracked: BTreeMap<TxHash, Option<Reported>>,
    /// The host roster as last reported, so a step emits only moves.
    reported_hosts: Vec<HostRole>,
    /// Events raised between steps — submissions happen on the caller's
    /// clock, not the simulation's, so they wait here for the next drain.
    pending: Vec<TraceEvent>,
    nonce: u32,
    /// The world every built transfer resolves its accounts in.
    client: Client,
}

impl Session {
    /// Build a single-shard cluster at `seed`, fund [`ACCOUNTS`] accounts, and
    /// run genesis.
    ///
    /// The topology grows from here as the session steps, up to
    /// [`SessionConfig::max_shards`].
    #[must_use]
    pub fn new(config: SessionConfig, seed: u64) -> Self {
        let splits = config.max_shards.saturating_sub(1);
        let sim_config = SimConfig {
            shard_size: config.shard_size,
            // Each split staffs its children from the free pool, so the grow
            // needs one spare cohort per split or the readiness gate never
            // passes (INV-RESHAPE-1).
            pool_surplus: splits * config.shard_size + config.pool_spares,
            // One validator per host, pool included. Co-hosting is a real
            // deployment shape, but it means a split's observers snap-sync on
            // the same hosts that are running the parent's consensus — which
            // is not what a network of distinct operators looks like, and
            // muddies anything the demo shows about reshape cost.
            dedicated_pool_hosts: true,
            beacon_chain_config: Some(BeaconChainConfig {
                shard_size: config.shard_size,
                epoch_duration_ms: EPOCH_MS,
                // Arm the split trigger unconditionally: the demo grows on
                // demand rather than waiting for a shard to outgrow a byte
                // threshold in real time.
                reshape_thresholds: ReshapeThresholds {
                    split_bytes: 0,
                    split_fullness: u32::MAX,
                },
                ..BeaconChainConfig::default()
            }),
            // Constant-cost signing, in the browser and in the tests alike: a
            // session paints frames, so per-signature cost is frame budget.
            // The sims default to real BLS under their `ci` feature and a
            // session that followed them would run several times slower for a
            // signature path it never draws.
            crypto_scheme: CryptoScheme::Mock,
            accounts: (1..=ACCOUNTS)
                .map(|s| (account_from_seed(s), ACCOUNT_FUNDING))
                .collect(),
            ..SimConfig::default()
        };
        let mut runner = SimulationRunner::new(&sim_config, seed);
        runner.enable_delivery_log(DELIVERY_SAMPLE);
        runner.initialize_genesis();
        // Seed the partition watermark with the genesis topology, so the
        // first change reported is a real one rather than the session
        // announcing the shard it opened on.
        let opening = (0..runner.num_hosts())
            .find_map(|host| runner.host_topology(host))
            .map(|topology| topology.shard_trie().leaves().collect())
            .unwrap_or_default();
        let opening_hosts = roster(&runner);
        Self {
            runner,
            now: Duration::ZERO,
            reported_shards: opening,
            handoff_from: BTreeMap::new(),
            reported_epoch: None,
            attested_wt: 0,
            reported_through: BTreeMap::new(),
            tracked: BTreeMap::new(),
            // Seeded with the roster the session opens on, read back through
            // `hosts()`, so the first change reported is a real move rather
            // than the session announcing the cluster it booted.
            reported_hosts: opening_hosts,
            pending: Vec::new(),
            nonce: 0,
            client: Client::genesis(NetworkId::from(&NetworkDefinition::simulator())),
        }
    }

    /// What each host serves right now, in host order.
    ///
    /// The roster a viewer opens on; every later move arrives as a
    /// [`TraceKind::HostsChanged`](crate::event::TraceKind::HostsChanged).
    #[must_use]
    pub fn hosts(&self) -> Vec<HostRole> {
        roster(&self.runner)
    }

    /// Build a transfer between two funded accounts.
    ///
    /// The rotation nonce rides the envelope message: the transaction hash
    /// covers the whole signed envelope, so two presses of the button
    /// inside one validity window would otherwise be the same transaction
    /// and the second would dedup away.
    fn build_transfer(&self, from: u8, to: u8) -> Transaction {
        self.client
            .transfer(
                &signer_from_seed(from),
                account_from_seed(from),
                account_from_seed(to),
                TRANSFER_AMOUNT,
                Terms {
                    max_fee: TRANSFER_MAX_FEE,
                    validity: validity_around(self.now),
                    message: self.nonce.to_le_bytes().to_vec(),
                },
            )
            .expect("the stdlib account answers a transfer")
    }

    /// Submit a protocol resource transfer between two funded accounts, returning its hash.
    ///
    /// The payer rotates with the nonce, so a caller driving a steady rate
    /// spreads load across accounts instead of serializing on one. The payee
    /// is the first account in rotation that the trie routes to a different
    /// shard: roughly half of all pairs land on the same shard once the root
    /// has split, and a same-shard transfer settles with no counterparty, so
    /// picking by rotation alone would leave every other press of the button
    /// with nothing crossing to show. Falls back to the plain rotation on a
    /// topology where nothing crosses at all.
    pub fn submit_transfer(&mut self) -> TxHash {
        let from = u8::try_from(self.nonce % u32::from(ACCOUNTS)).unwrap_or(0) + 1;
        let topology =
            (0..self.runner.num_hosts()).find_map(|host| self.runner.host_topology(host));
        // Built outside any node, so nothing has derived it: routing is
        // the deriving node's answer, and the question below is about a
        // routed fact.
        let derivation = self.runner.host_derivation(0);
        let crosses = |tx: &Transaction| {
            let Some(derivation) = derivation.as_ref() else {
                return false;
            };
            tx.try_derived(derivation.as_ref()).is_ok()
                && topology
                    .as_ref()
                    .is_some_and(|t| t.is_cross_shard_transaction(tx))
        };
        // The next account in rotation is the fallback, so a topology where
        // nothing crosses still submits the pair it would have picked anyway.
        let mut tx = self.build_transfer(from, (from % ACCOUNTS) + 1);
        if !crosses(&tx) {
            for step in 2..ACCOUNTS {
                let candidate = self.build_transfer(from, ((from + step - 1) % ACCOUNTS) + 1);
                if crosses(&candidate) {
                    tx = candidate;
                    break;
                }
            }
        }
        let hash = tx.hash();
        let tx = Arc::new(tx);
        self.runner.schedule_initial_event(
            0,
            Duration::from_millis(1),
            HostEvent::process(ProcessScopedInput::SubmitTransaction { tx }),
        );
        self.nonce += 1;
        self.tracked.insert(hash, None);
        self.pending
            .push(TraceEvent::tx_submitted(self.attested_wt, hash));
        hash
    }

    /// Advance simulated time by `ms` and return everything observed.
    ///
    /// The span runs as the [`RESHAPE_TICK_MS`] intervals it spans, so one
    /// long call and the short calls covering the same time produce the same
    /// run. How much a caller asks for at once is a matter of how often it
    /// wants to paint, and nothing else.
    pub fn step(&mut self, ms: u64) -> Vec<TraceEvent> {
        let target = self.now + Duration::from_millis(ms);
        let mut events = Vec::new();
        while self.now < target {
            // Seating is driven by the harness, not by the event queue: an
            // orchestrator only advances when it is polled, and placement
            // only reconciles when it is scanned. Driving both here is what
            // lets a split unfold across the session instead of being
            // completed before the first frame, and what staffs the seat a
            // shuffle rotates.
            let now_ms = u64::try_from(self.now.as_millis()).unwrap_or(u64::MAX);
            if now_ms % RESHAPE_TICK_MS == 0 {
                self.runner.topology_step();
            }
            let next_poll = Duration::from_millis((now_ms / RESHAPE_TICK_MS + 1) * RESHAPE_TICK_MS);
            self.now = next_poll.min(target);
            self.runner.run_until(self.now);
            // Blocks first: they carry attested time, and everything else is
            // stamped against the frontier they establish.
            events.extend(self.drain_committed());
            events.extend(std::mem::take(&mut self.pending));
            events.extend(self.drain_beacon());
            events.extend(self.drain_topology());
            events.extend(self.drain_hosts());
            events.extend(self.drain_tx_status());
        }
        // Once for the whole span, unlike the derivations above: the delivery
        // budget bounds what a viewer animates between paints, so it belongs
        // to the call rather than to the intervals inside it.
        events.extend(self.drain_traffic());
        // One batch, one timeline: the viewer renders in weighted-time order
        // regardless of which derivation produced an event.
        events.sort_by_key(|event| event.wt);
        events
    }

    /// Report each beacon epoch committed since the last step.
    fn drain_beacon(&mut self) -> Vec<TraceEvent> {
        let Some(latest) = (0..self.runner.num_hosts())
            .find_map(|host| self.runner.beacon_storage(host))
            .and_then(|storage| storage.latest_committed_epoch())
        else {
            return Vec::new();
        };
        let latest = latest.inner();
        let from = self.reported_epoch.map_or(0, |e| e + 1);
        self.reported_epoch = Some(latest);
        // An epoch's own time is its wall-clock pacing: the beacon refuses to
        // start an epoch before `epoch × epoch_duration_ms`, so that product
        // is the instant it belongs at on the timeline.
        (from..=latest)
            .map(|epoch| TraceEvent::beacon_block(epoch * EPOCH_MS, epoch))
            .collect()
    }

    /// Report a partition change, if the trie's leaves moved this step.
    fn drain_topology(&mut self) -> Vec<TraceEvent> {
        let current = self.live_shards();
        if current == self.reported_shards {
            return Vec::new();
        }
        let appeared = current
            .iter()
            .filter(|s| !self.reported_shards.contains(s))
            .copied()
            .collect();
        let retired: Vec<ShardId> = self
            .reported_shards
            .iter()
            .filter(|s| !current.contains(s))
            .copied()
            .collect();
        // A retired shard has proposed its last block, so its chain's final
        // height is settled now and its store is retained past the cut
        // (INV-BEACON-8) for exactly this kind of read. The walk itself
        // never reaches that height: it reports a block only once a
        // committing child carries its timestamp, and the last block has no
        // child.
        let mut events: Vec<TraceEvent> = retired
            .iter()
            .filter_map(|shard| {
                let height = (0..self.runner.num_hosts())
                    .find_map(|host| self.runner.hosts_shard(host, *shard))?
                    .committed_height();
                Some(TraceEvent::shard_terminal(
                    self.attested_wt,
                    *shard,
                    height,
                    self.handoff_from.get(shard).copied(),
                ))
            })
            .collect();
        events.push(TraceEvent::topology_changed(
            self.attested_wt,
            &current,
            appeared,
            retired,
        ));
        self.reported_shards = current;
        events
    }

    /// Report the host roster, if any host's duties moved this step.
    fn drain_hosts(&mut self) -> Vec<TraceEvent> {
        let current = roster(&self.runner);
        if current == self.reported_hosts {
            return Vec::new();
        }
        self.reported_hosts.clone_from(&current);
        vec![TraceEvent::hosts_changed(self.attested_wt, current)]
    }

    /// Report what the transport carried this step: a bounded sample of
    /// individual deliveries, and the exact totals behind them.
    ///
    /// Both are stamped at the attested frontier, because a delivery has no
    /// attested time of its own — the instants it spanned ride the event's
    /// payload on the harness clock instead.
    fn drain_traffic(&mut self) -> Vec<TraceEvent> {
        let wt = self.attested_wt;
        let drain = self.runner.drain_deliveries();
        if drain.records.is_empty() && drain.dropped == 0 {
            return Vec::new();
        }
        let mut events: Vec<TraceEvent> = drain
            .records
            .iter()
            .map(|record| TraceEvent::message_delivered(wt, record))
            .collect();
        let sampled = u32::try_from(drain.records.len()).unwrap_or(u32::MAX);
        events.push(TraceEvent::traffic_sampled(wt, sampled, &drain));
        events
    }

    /// Report every tracked transaction whose status moved this step.
    ///
    /// Polled rather than pushed: status is a projection of committed chain
    /// content, so reading it back is an observation, not a hook into the
    /// path that produces it.
    fn drain_tx_status(&mut self) -> Vec<TraceEvent> {
        let wt = self.attested_wt;
        let mut events = Vec::new();
        // Ask every host and keep the furthest-progressed answer. Status is
        // per host, and a host only tracks transactions on the shards it
        // serves — so after a split, whichever child this host does not carry
        // would report nothing at all and its transactions would appear to
        // hang in pending forever.
        let latest: Vec<(TxHash, Option<Reported>)> = self
            .tracked
            .keys()
            .map(|hash| {
                let answers: Vec<TransactionStatus> = (0..self.runner.num_hosts())
                    .filter_map(|host| self.runner.tx_status(host, hash))
                    .collect();
                (*hash, resolve_status(&answers))
            })
            .collect();

        for (hash, current) in latest {
            let last = self.tracked.get_mut(&hash).expect("hash came from tracked");
            if current == *last {
                continue;
            }
            if let Some((label, height)) = current {
                events.push(TraceEvent::tx_status(wt, hash, label, height));
            }
            *last = current;
        }
        events
    }

    /// The shards the topology currently partitions the keyspace into, in
    /// trie order.
    ///
    /// Read from the beacon-derived topology rather than from what hosts
    /// happen to store: a split parent's store is retained past its terminal
    /// block so late joiners and counterparties can still resolve it
    /// (INV-BEACON-8), so host storage lists shards that no longer exist.
    /// The trie's leaves are the live partition by definition.
    #[must_use]
    pub fn live_shards(&self) -> Vec<ShardId> {
        (0..self.runner.num_hosts())
            .find_map(|host| self.runner.host_topology(host))
            .map(|topology| topology.shard_trie().leaves().collect())
            .unwrap_or_default()
    }

    /// Walk each shard's newly committed blocks and emit one event apiece.
    ///
    /// A block is reported only once its committing child's header is
    /// readable, because that child's parent QC carries the block's canonical
    /// weighted timestamp (INV-SHARD-6). Reading the block's own QC instead
    /// would pick up whatever round it was last certified in — a gossip
    /// artifact, not consensus content — and the timeline would jitter under
    /// re-certification. The cost is that the chain tip is reported one block
    /// late, which is invisible at any watchable playback rate.
    fn drain_committed(&mut self) -> Vec<TraceEvent> {
        let mut events = Vec::new();
        let mut watermarks: Vec<(ShardId, BlockHeight)> = Vec::new();
        let mut handoffs: BTreeMap<ShardId, BlockHeight> = BTreeMap::new();
        let mut frontier = self.attested_wt;
        let topology =
            (0..self.runner.num_hosts()).find_map(|host| self.runner.host_topology(host));

        for shard in self.live_shards() {
            // Hosts of one shard agree on committed content, so the furthest
            // along answers for all of them.
            let Some(storage) = (0..self.runner.num_hosts())
                .filter_map(|host| self.runner.hosts_shard(host, shard))
                .max_by_key(|storage| storage.committed_height())
            else {
                continue;
            };
            let committed = storage.committed_height().inner();

            // On first sight, start at the tip rather than replaying the
            // chain: a split child seeds at its parent's terminal height, so
            // its first height is wherever the parent stopped and heights
            // below that were never its own. Recorded straight away so the
            // next step resumes from here instead of treating the shard as
            // new again and skipping ahead.
            let reported = self.reported_through.get(&shard).map_or_else(
                || {
                    let start = committed.saturating_sub(1);
                    watermarks.push((shard, BlockHeight::new(start)));
                    start
                },
                |height| height.inner(),
            );

            // The tip has no committing child yet, so stop one short of it.
            for height in (reported + 1)..committed {
                let Some(block) = storage.get_block(BlockHeight::new(height)) else {
                    break;
                };
                let Some(child) = storage.get_certified_header(BlockHeight::new(height + 1)) else {
                    break;
                };
                let block = block.as_ref().block();
                let header = block.header();
                let crossing = topology.as_ref().map_or(0, |topology| {
                    block
                        .transactions()
                        .iter()
                        .filter(|tx| topology.is_cross_shard_transaction(tx))
                        .count()
                });
                let wt = child
                    .as_ref()
                    .header()
                    .parent_qc()
                    .weighted_timestamp()
                    .as_millis();
                frontier = frontier.max(wt);
                events.push(TraceEvent::block_committed(
                    wt,
                    shard,
                    header.height(),
                    header.round(),
                    header.is_fallback(),
                    header.proposer().inner(),
                    u32::try_from(crossing).unwrap_or(u32::MAX),
                ));
                // A settled-transaction root rides every header of a terminating
                // shard's final epoch, so the first one seen opens the
                // handoff window that the shard's last block closes.
                if header.settled_txs_root().is_some() {
                    handoffs.entry(shard).or_insert_with(|| header.height());
                }
                // A stored block keeps only its bundles' hashes; the bodies
                // are read back beside it.
                settlement_events(
                    &mut events,
                    wt,
                    shard,
                    header.height(),
                    &storage.provisions_at(header.height()),
                    block.certificates(),
                );
                watermarks.push((shard, BlockHeight::new(height)));
            }
        }

        for (shard, height) in watermarks {
            self.reported_through.insert(shard, height);
        }
        for (shard, height) in handoffs {
            self.handoff_from.entry(shard).or_insert(height);
        }
        self.attested_wt = self.attested_wt.max(frontier);
        events.sort_by_key(|event| event.wt);
        events
    }
}
