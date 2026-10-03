//! The request retry policy every transport runs: which peer to ask, how long
//! to wait on it, when to rotate away, and when to give up.
//!
//! Sans-IO. The transport sends the attempt, waits, and reports what came
//! back; [`Attempts`] decides what happens next. Time is a `Duration` on the
//! transport's own clock and randomness is passed in, so the production
//! transport drives it with tokio and a thread RNG while the simulator drives
//! it with scheduled events and a seeded stream.
//!
//! Retry is request-centric: under packet loss a timeout says little about
//! the peer, so the same peer is retried before rotating, and selection is
//! weighted by observed health rather than gated on it, so an unhealthy peer
//! keeps an occasional chance.
//!
//! A peer that answers without holding what was asked has not answered the
//! request. The request moves on to a peer it has not heard that from, and
//! comes back empty only once every candidate has said so or its attempt
//! budget is spent.

use std::collections::BTreeMap;
use std::time::Duration;

use hyperscale_hbor::from_slice as hbor_from_slice;
use hyperscale_types::MessageClass;
use hyperscale_types::network::Request;
use rand::{Rng, RngExt};

/// Longest a single attempt waits on a peer.
const MAX_STREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// Shortest attempt timeout once a peer's RTT is known. Absorbs jitter and
/// short transport stalls that the RTT multiplier alone would not cover on a
/// fast link.
const MIN_STREAM_TIMEOUT_WARM: Duration = Duration::from_millis(300);

/// Attempt timeout for a peer with no successful round trip yet. The RTT
/// estimate only moves on success, so a cold timeout tighter than a real WAN
/// round trip would time out every attempt and never seed it.
const MIN_STREAM_TIMEOUT_COLD: Duration = Duration::from_secs(2);

/// Attempt timeout as a multiple of the peer's RTT estimate.
const STREAM_TIMEOUT_RTT_MULTIPLIER: f64 = 5.0;

/// Smoothing for the health averages: a new observation carries this weight.
const EMA_ALPHA: f64 = 0.2;

/// Selection weight of a peer never asked.
const NEUTRAL_WEIGHT: f64 = 0.5;

/// Whether `class` runs the relaxed retry regime.
///
/// `Recovery` and `Bulk` are the sheddable classes; every other class retries
/// tightly so the consensus and cross-shard paths absorb packet loss without
/// falling behind.
#[must_use]
pub const fn uses_relaxed_retry(class: MessageClass) -> bool {
    matches!(class, MessageClass::Recovery | MessageClass::Bulk)
}

/// How long an attempt waits on a peer whose RTT estimate is `rtt_ema_secs`
/// (`None` for a peer that has never answered).
#[must_use]
pub fn stream_timeout(rtt_ema_secs: Option<f64>) -> Duration {
    rtt_ema_secs.map_or(MIN_STREAM_TIMEOUT_COLD, |rtt| {
        Duration::from_secs_f64(rtt * STREAM_TIMEOUT_RTT_MULTIPLIER)
            .clamp(MIN_STREAM_TIMEOUT_WARM, MAX_STREAM_TIMEOUT)
    })
}

/// The first backoff of a request: half the peer's RTT clamped to
/// `[50ms, 1s]`, or `default_backoff` for a cold peer, then shortened for the
/// tight regime and lengthened for the relaxed one.
#[must_use]
pub fn initial_backoff(
    rtt_ema_secs: Option<f64>,
    default_backoff: Duration,
    class: MessageClass,
) -> Duration {
    let base_backoff = rtt_ema_secs.map_or(default_backoff, |rtt| {
        Duration::from_secs_f64(rtt * 0.5).clamp(Duration::from_millis(50), Duration::from_secs(1))
    });
    if uses_relaxed_retry(class) {
        base_backoff.mul_f32(1.5)
    } else {
        base_backoff.mul_f32(0.7)
    }
}

/// Whether an encoded answer to an `R` is [`Outcome::Empty`].
///
/// Empty in [`Request::is_empty_response`]'s terms. An answer that does
/// not decode is not empty: it is the requester's to reject.
#[must_use]
pub fn is_empty_answer<R: Request>(bytes: &[u8]) -> bool {
    hbor_from_slice::<R::Response>(bytes).is_ok_and(|response| R::is_empty_response(&response))
}

/// Why an attempt failed. A timeout is common under packet loss and costs a
/// peer half the health of any other failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The peer did not answer within the attempt's timeout.
    Timeout,
    /// The peer answered with an error, or its answer was unusable.
    Other,
}

/// What one peer's past attempts say about it.
#[derive(Debug, Clone)]
struct PeerHealth {
    /// Moving average of the success rate, starting neutral at 0.5.
    success_rate_ema: f64,
    /// Moving average of the round trip, seeded at 100ms; meaningful only
    /// once `round_trips > 0`.
    rtt_ema_secs: f64,
    in_flight: u32,
    last_success: Option<Duration>,
    /// Attempts the peer answered, whether or not it held what was asked.
    round_trips: u64,
}

impl Default for PeerHealth {
    fn default() -> Self {
        Self {
            success_rate_ema: 0.5,
            rtt_ema_secs: 0.1,
            in_flight: 0,
            last_success: None,
            round_trips: 0,
        }
    }
}

impl PeerHealth {
    fn record_success(&mut self, rtt: Duration, now: Duration) {
        self.record_round_trip(rtt);
        self.last_success = Some(now);
        self.success_rate_ema = self.success_rate_ema.mul_add(1.0 - EMA_ALPHA, EMA_ALPHA);
    }

    /// The peer answered after `rtt`. Says how far away it is and nothing
    /// about whether it serves: an answer without what was asked moves
    /// neither the success rate nor the recency.
    fn record_round_trip(&mut self, rtt: Duration) {
        self.round_trips += 1;
        self.in_flight = self.in_flight.saturating_sub(1);
        self.rtt_ema_secs = rtt
            .as_secs_f64()
            .mul_add(EMA_ALPHA, self.rtt_ema_secs * (1.0 - EMA_ALPHA));
    }

    fn record_failure(&mut self, kind: FailureKind) {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.penalise(kind);
    }

    fn penalise(&mut self, kind: FailureKind) {
        let penalty = match kind {
            FailureKind::Timeout => EMA_ALPHA * 0.5,
            FailureKind::Other => EMA_ALPHA,
        };
        self.success_rate_ema *= 1.0 - penalty;
    }

    /// Higher is likelier to be picked: success rate (floored so no peer is
    /// shut out), lower RTT, fewer requests in flight, and a recent success.
    fn selection_weight(&self, now: Duration) -> f64 {
        let success_factor = self.success_rate_ema.max(0.05);
        let rtt_factor = 1.0 / (1.0 + self.rtt_ema_secs);
        let load_factor = 1.0 / f64::from(self.in_flight).mul_add(0.2, 1.0);
        let recency_factor = match self.last_success.map(|t| now.saturating_sub(t)) {
            Some(since) if since < Duration::from_secs(10) => 1.1,
            Some(since) if since < Duration::from_mins(1) => 1.0,
            _ => 0.9,
        };
        success_factor * rtt_factor * load_factor * recency_factor
    }
}

/// One requester's view of the health of every peer it has asked.
#[derive(Debug, Clone)]
pub struct PeerHealthBook<P> {
    peers: BTreeMap<P, PeerHealth>,
}

impl<P> Default for PeerHealthBook<P> {
    fn default() -> Self {
        Self {
            peers: BTreeMap::new(),
        }
    }
}

impl<P: Ord + Copy> PeerHealthBook<P> {
    /// Record an attempt dispatched to `peer`.
    pub fn record_started(&mut self, peer: P) {
        self.peers.entry(peer).or_default().in_flight += 1;
    }

    /// Record `peer` answering after `rtt`.
    pub fn record_success(&mut self, peer: P, rtt: Duration, now: Duration) {
        self.peers.entry(peer).or_default().record_success(rtt, now);
    }

    /// Record `peer` answering after `rtt` without holding what was asked.
    pub fn record_empty(&mut self, peer: P, rtt: Duration) {
        self.peers.entry(peer).or_default().record_round_trip(rtt);
    }

    /// Record an attempt to `peer` failing.
    pub fn record_failure(&mut self, peer: P, kind: FailureKind) {
        self.peers.entry(peer).or_default().record_failure(kind);
    }

    /// Record that the requester rejected an answer `peer` gave. The attempt
    /// already resolved as a success, so nothing of it is still in flight.
    pub fn record_rejected(&mut self, peer: P) {
        self.peers
            .entry(peer)
            .or_default()
            .penalise(FailureKind::Other);
    }

    /// Record an attempt to `peer` abandoned without an outcome.
    pub fn record_cancelled(&mut self, peer: P) {
        if let Some(health) = self.peers.get_mut(&peer) {
            health.in_flight = health.in_flight.saturating_sub(1);
        }
    }

    /// `peer`'s RTT estimate, or `None` while it has never answered: the
    /// seeded estimate is not an observation.
    #[must_use]
    pub fn rtt_ema_secs(&self, peer: P) -> Option<f64> {
        self.peers
            .get(&peer)
            .filter(|health| health.round_trips > 0)
            .map(|health| health.rtt_ema_secs)
    }

    /// A health-weighted random pick from `candidates`; `None` only when
    /// there are none.
    pub fn select<R: Rng + ?Sized>(
        &self,
        candidates: &[P],
        now: Duration,
        rng: &mut R,
    ) -> Option<P> {
        let first = *candidates.first()?;
        let weights: Vec<f64> = candidates
            .iter()
            .map(|peer| {
                self.peers
                    .get(peer)
                    .map_or(NEUTRAL_WEIGHT, |health| health.selection_weight(now))
            })
            .collect();
        let total: f64 = weights.iter().sum();
        if total <= 0.0 {
            return Some(first);
        }
        let mut target = rng.random_range(0.0..total);
        for (&peer, weight) in candidates.iter().zip(weights) {
            target -= weight;
            if target <= 0.0 {
                return Some(peer);
            }
        }
        candidates.last().copied()
    }

    /// A pick from `candidates` other than `exclude`, or `exclude` itself
    /// when it is the only candidate.
    pub fn select_excluding<R: Rng + ?Sized>(
        &self,
        candidates: &[P],
        exclude: P,
        now: Duration,
        rng: &mut R,
    ) -> Option<P> {
        let others: Vec<P> = candidates
            .iter()
            .copied()
            .filter(|peer| *peer != exclude)
            .collect();
        if others.is_empty() {
            return candidates.contains(&exclude).then_some(exclude);
        }
        self.select(&others, now, rng)
    }
}

/// The retry budget and backoff shape of a request.
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    /// Timed-out attempts against one peer before rotating. Sized so one
    /// request's `max_total_attempts` reaches every peer of a committee:
    /// rotating every 2 of 15 attempts covers 7 peers.
    pub retries_before_rotation: u32,
    /// Failed attempts before the request gives up.
    pub max_total_attempts: u32,
    /// First backoff for a cold peer, before the class adjustment.
    pub initial_backoff: Duration,
    /// Ceiling the backoff grows toward.
    pub max_backoff: Duration,
    /// Growth factor between successive backoffs.
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            retries_before_rotation: 2,
            max_total_attempts: 15,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(500),
            backoff_multiplier: 1.5,
        }
    }
}

/// How an attempt ended, as the transport saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The peer answered after `rtt`.
    Answered {
        /// Dispatch to answer.
        rtt: Duration,
    },
    /// The peer answered after `rtt` that it holds nothing of what was
    /// asked.
    Empty {
        /// Dispatch to answer.
        rtt: Duration,
    },
    /// No answer within the attempt's timeout.
    TimedOut,
    /// The peer answered with an error, or the transport failed otherwise.
    Failed,
}

/// What the transport does after an attempt ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// The request succeeded against [`Attempts::peer`], or ended on an
    /// empty answer with no candidate or budget left to ask another.
    Done,
    /// Dispatch the next attempt after waiting `after`.
    Retry {
        /// Backoff before the next attempt.
        after: Duration,
    },
    /// The request gives up after waiting `after`, having failed `attempts`
    /// times.
    Exhausted {
        /// Failed attempts.
        attempts: u32,
        /// Backoff the transport waits before reporting the failure.
        after: Duration,
    },
}

/// One request's progress through its retry budget.
#[derive(Debug, Clone)]
pub struct Attempts<P> {
    config: RetryConfig,
    candidates: Vec<P>,
    /// Candidates that answered empty; never asked again by this request.
    emptied: Vec<P>,
    current: P,
    failures: u32,
    current_peer_failures: u32,
    backoff: Duration,
}

impl<P: Ord + Copy> Attempts<P> {
    /// Open a request over `candidates`, starting from `preferred` when it is
    /// one of them. `None` when there are no candidates.
    pub fn start<R: Rng + ?Sized>(
        config: RetryConfig,
        candidates: Vec<P>,
        preferred: Option<P>,
        class: MessageClass,
        book: &PeerHealthBook<P>,
        now: Duration,
        rng: &mut R,
    ) -> Option<Self> {
        let current = match preferred {
            Some(peer) if candidates.contains(&peer) => peer,
            _ => book.select(&candidates, now, rng)?,
        };
        let backoff = initial_backoff(book.rtt_ema_secs(current), config.initial_backoff, class);
        Some(Self {
            config,
            candidates,
            emptied: Vec::new(),
            current,
            failures: 0,
            current_peer_failures: 0,
            backoff,
        })
    }

    /// The peer the current attempt goes, or went, to.
    #[must_use]
    pub const fn peer(&self) -> P {
        self.current
    }

    /// Dispatch the next attempt: the peer to send it to and how long to wait
    /// on it. A current peer `live` refuses is swapped for a pick among the
    /// live candidates; `None` when no candidate is live.
    pub fn dispatch<R: Rng + ?Sized>(
        &mut self,
        live: impl Fn(P) -> bool,
        book: &mut PeerHealthBook<P>,
        now: Duration,
        rng: &mut R,
    ) -> Option<(P, Duration)> {
        if !live(self.current) {
            let live_peers: Vec<P> = self.unemptied().filter(|peer| live(*peer)).collect();
            self.current = book.select(&live_peers, now, rng)?;
        }
        book.record_started(self.current);
        Some((
            self.current,
            stream_timeout(book.rtt_ema_secs(self.current)),
        ))
    }

    /// Candidates that have not answered this request empty.
    fn unemptied(&self) -> impl Iterator<Item = P> + '_ {
        self.candidates
            .iter()
            .copied()
            .filter(|peer| !self.emptied.contains(peer))
    }

    /// Fold the dispatched attempt's `outcome` into the peer's health and
    /// decide what follows. A timeout retries the same peer until
    /// `retries_before_rotation`; any other failure rotates at once. An
    /// empty answer rotates at once and without backoff to a peer that has
    /// not answered empty, and is not a failure: the peer answered, and
    /// what it lacked another may hold. Once every candidate has answered
    /// empty, or the empty answers and failures together spend
    /// `max_total_attempts`, the request is done with the empty answer.
    pub fn resolve<R: Rng + ?Sized>(
        &mut self,
        outcome: Outcome,
        book: &mut PeerHealthBook<P>,
        now: Duration,
        rng: &mut R,
    ) -> Resolution {
        let peer = self.current;
        let rotate = match outcome {
            Outcome::Answered { rtt } => {
                book.record_success(peer, rtt, now);
                return Resolution::Done;
            }
            Outcome::Empty { rtt } => {
                book.record_empty(peer, rtt);
                if !self.emptied.contains(&peer) {
                    self.emptied.push(peer);
                }
                let asked = self
                    .failures
                    .saturating_add(u32::try_from(self.emptied.len()).unwrap_or(u32::MAX));
                if asked >= self.config.max_total_attempts {
                    return Resolution::Done;
                }
                let remaining: Vec<P> = self.unemptied().collect();
                let Some(next) = book.select(&remaining, now, rng) else {
                    return Resolution::Done;
                };
                self.current = next;
                self.current_peer_failures = 0;
                return Resolution::Retry {
                    after: Duration::ZERO,
                };
            }
            Outcome::TimedOut => {
                book.record_failure(peer, FailureKind::Timeout);
                self.current_peer_failures += 1;
                self.current_peer_failures >= self.config.retries_before_rotation
            }
            Outcome::Failed => {
                book.record_failure(peer, FailureKind::Other);
                true
            }
        };
        self.failures += 1;
        if rotate {
            let remaining: Vec<P> = self.unemptied().collect();
            if let Some(next) = book.select_excluding(&remaining, peer, now, rng) {
                self.current = next;
            }
            self.current_peer_failures = 0;
        }
        let after = self.backoff;
        self.backoff = Duration::from_secs_f64(
            (after.as_secs_f64() * self.config.backoff_multiplier)
                .min(self.config.max_backoff.as_secs_f64()),
        );
        if self.failures >= self.config.max_total_attempts {
            Resolution::Exhausted {
                attempts: self.failures,
                after,
            }
        } else {
            Resolution::Retry { after }
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;

    const NOW: Duration = Duration::from_secs(100);

    fn rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(7)
    }

    fn assert_near_ms(actual: Duration, expected_ms: f64) {
        let actual_ms = actual.as_secs_f64() * 1000.0;
        assert!(
            (actual_ms - expected_ms).abs() < 1.0,
            "expected ≈{expected_ms}ms, got {actual_ms}ms"
        );
    }

    #[test]
    fn the_stream_timeout_follows_rtt_between_its_floors() {
        assert_eq!(stream_timeout(Some(0.005)), MIN_STREAM_TIMEOUT_WARM);
        assert_eq!(stream_timeout(Some(0.2)), Duration::from_secs(1));
        assert_eq!(stream_timeout(Some(5.0)), MAX_STREAM_TIMEOUT);
        assert_eq!(stream_timeout(None), MIN_STREAM_TIMEOUT_COLD);
    }

    #[test]
    fn the_initial_backoff_scales_by_regime() {
        let default = Duration::from_millis(100);
        assert_near_ms(
            initial_backoff(Some(0.2), default, MessageClass::CrossShardProgress),
            70.0,
        );
        assert_near_ms(
            initial_backoff(Some(0.2), default, MessageClass::Recovery),
            150.0,
        );
        assert_near_ms(
            initial_backoff(None, default, MessageClass::Consensus),
            70.0,
        );
        assert_near_ms(
            initial_backoff(Some(0.01), default, MessageClass::Bulk),
            75.0,
        );
        assert_near_ms(
            initial_backoff(Some(10.0), default, MessageClass::Recovery),
            1500.0,
        );
    }

    #[test]
    fn a_timeout_costs_half_what_an_error_does() {
        let mut timed_out = PeerHealth::default();
        let mut errored = PeerHealth::default();
        timed_out.record_failure(FailureKind::Timeout);
        errored.record_failure(FailureKind::Other);
        assert!(timed_out.success_rate_ema > errored.success_rate_ema);
    }

    #[test]
    fn the_rtt_estimate_is_unknown_until_a_peer_answers() {
        let mut book = PeerHealthBook::default();
        book.record_started(1u32);
        book.record_failure(1, FailureKind::Timeout);
        assert_eq!(book.rtt_ema_secs(1), None);
        book.record_success(1, Duration::from_millis(100), NOW);
        assert!(book.rtt_ema_secs(1).is_some());
    }

    #[test]
    fn a_rejected_answer_keeps_other_attempts_in_flight() {
        let mut book = PeerHealthBook::default();
        book.record_started(1u32);
        book.record_started(1);
        book.record_success(1, Duration::from_millis(50), NOW);
        let before = book.peers[&1].success_rate_ema;
        book.record_rejected(1);
        assert_eq!(book.peers[&1].in_flight, 1);
        assert!(book.peers[&1].success_rate_ema < before);
    }

    #[test]
    fn selection_prefers_a_healthy_peer_and_never_shuts_one_out() {
        let mut book = PeerHealthBook::default();
        for _ in 0..10 {
            book.record_success(1u32, Duration::from_millis(50), NOW);
            book.record_failure(2, FailureKind::Other);
        }
        let mut rng = rng();
        let mut picks = [0u32; 3];
        for _ in 0..1000 {
            picks[book.select(&[1, 2], NOW, &mut rng).unwrap() as usize] += 1;
        }
        assert!(picks[1] > picks[2] * 3, "healthy peer picked {picks:?}");
        assert!(picks[2] > 0, "an unhealthy peer keeps a chance");
    }

    #[test]
    fn selection_excluding_falls_back_to_the_only_candidate() {
        let book = PeerHealthBook::default();
        let mut rng = rng();
        assert_eq!(book.select_excluding(&[1u32, 2], 1, NOW, &mut rng), Some(2));
        assert_eq!(book.select_excluding(&[1u32], 1, NOW, &mut rng), Some(1));
        assert_eq!(book.select_excluding(&[2u32], 1, NOW, &mut rng), Some(2));
        assert_eq!(book.select(&[] as &[u32], NOW, &mut rng), None);
    }

    fn config() -> RetryConfig {
        RetryConfig {
            max_total_attempts: 5,
            ..RetryConfig::default()
        }
    }

    fn open(candidates: Vec<u32>, preferred: Option<u32>) -> (Attempts<u32>, PeerHealthBook<u32>) {
        let book = PeerHealthBook::default();
        let attempts = Attempts::start(
            config(),
            candidates,
            preferred,
            MessageClass::Recovery,
            &book,
            NOW,
            &mut rng(),
        )
        .expect("candidates");
        (attempts, book)
    }

    fn dispatch(attempts: &mut Attempts<u32>, book: &mut PeerHealthBook<u32>) -> u32 {
        attempts
            .dispatch(|_| true, book, NOW, &mut rng())
            .expect("a live peer")
            .0
    }

    #[test]
    fn a_timeout_retries_the_same_peer_before_rotating() {
        let (mut attempts, mut book) = open(vec![1, 2], Some(1));
        let mut asked = Vec::new();
        for _ in 0..3 {
            asked.push(dispatch(&mut attempts, &mut book));
            attempts.resolve(Outcome::TimedOut, &mut book, NOW, &mut rng());
        }
        assert_eq!(asked, vec![1, 1, 2]);
    }

    #[test]
    fn an_error_rotates_at_once() {
        let (mut attempts, mut book) = open(vec![1, 2], Some(1));
        assert_eq!(dispatch(&mut attempts, &mut book), 1);
        attempts.resolve(Outcome::Failed, &mut book, NOW, &mut rng());
        assert_eq!(dispatch(&mut attempts, &mut book), 2);
    }

    #[test]
    fn an_answer_ends_the_request() {
        let (mut attempts, mut book) = open(vec![1, 2], Some(2));
        assert_eq!(dispatch(&mut attempts, &mut book), 2);
        let rtt = Duration::from_millis(80);
        assert_eq!(
            attempts.resolve(Outcome::Answered { rtt }, &mut book, NOW, &mut rng()),
            Resolution::Done
        );
        assert_eq!(attempts.peer(), 2);
        assert!(book.rtt_ema_secs(2).is_some());
    }

    #[test]
    fn the_budget_exhausts_with_backoff_growing_to_its_ceiling() {
        let (mut attempts, mut book) = open(vec![1, 2], Some(1));
        let mut backoffs = Vec::new();
        let exhausted = loop {
            dispatch(&mut attempts, &mut book);
            match attempts.resolve(Outcome::TimedOut, &mut book, NOW, &mut rng()) {
                Resolution::Retry { after } => backoffs.push(after),
                Resolution::Exhausted { attempts, after } => {
                    backoffs.push(after);
                    break attempts;
                }
                Resolution::Done => unreachable!(),
            }
        };
        assert_eq!(exhausted, 5);
        assert_eq!(backoffs.len(), 5);
        assert!(backoffs.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(*backoffs.last().unwrap(), config().max_backoff);
    }

    #[test]
    fn an_empty_answer_rotates_without_backoff_and_never_asks_that_peer_again() {
        let (mut attempts, mut book) = open(vec![1, 2, 3], Some(1));
        let rtt = Duration::from_millis(20);
        assert_eq!(dispatch(&mut attempts, &mut book), 1);
        assert_eq!(
            attempts.resolve(Outcome::Empty { rtt }, &mut book, NOW, &mut rng()),
            Resolution::Retry {
                after: Duration::ZERO
            }
        );
        let second = dispatch(&mut attempts, &mut book);
        assert_ne!(second, 1);
        // A timeout rotates among the peers that have not answered empty.
        attempts.resolve(Outcome::TimedOut, &mut book, NOW, &mut rng());
        attempts.resolve(Outcome::TimedOut, &mut book, NOW, &mut rng());
        let third = dispatch(&mut attempts, &mut book);
        assert!(third != 1 && third != second, "asked {third}");
        attempts.resolve(Outcome::Empty { rtt }, &mut book, NOW, &mut rng());
        assert_eq!(dispatch(&mut attempts, &mut book), second);
        assert_eq!(
            attempts.resolve(Outcome::Empty { rtt }, &mut book, NOW, &mut rng()),
            Resolution::Done,
            "every candidate answered empty"
        );
    }

    #[test]
    fn an_empty_answer_measures_the_peer_without_crediting_it() {
        let mut book = PeerHealthBook::default();
        book.record_started(1u32);
        book.record_empty(1, Duration::from_millis(20));
        assert!(book.rtt_ema_secs(1).is_some());
        assert_eq!(book.peers[&1].in_flight, 0);
        assert!((book.peers[&1].success_rate_ema - 0.5).abs() < f64::EPSILON);
        assert_eq!(book.peers[&1].last_success, None);
    }

    #[test]
    fn a_preferred_peer_outside_the_candidates_is_ignored() {
        let (attempts, _) = open(vec![1], Some(9));
        assert_eq!(attempts.peer(), 1);
    }

    #[test]
    fn a_dead_peer_is_swapped_for_a_live_one() {
        let (mut attempts, mut book) = open(vec![1, 2], Some(1));
        let dispatched = attempts.dispatch(|peer| peer != 1, &mut book, NOW, &mut rng());
        assert_eq!(dispatched.map(|(peer, _)| peer), Some(2));
        assert_eq!(
            attempts.dispatch(|_| false, &mut book, NOW, &mut rng()),
            None
        );
    }
}
