//! Per-peer budget for the work a peer's refused traffic costs this host.
//!
//! Each refusal is charged at an estimate of the work it took: little for an
//! item that failed to decode or that this host could not place, a lot for
//! one whose signature it checked and found wanting. A peer may run up
//! [`ALLOWANCE`] of such work at once, and time pays it down at one part in
//! [`WORK_SHARE`] of the time that passes. A peer past its allowance cools
//! down: its traffic of that kind is dropped unread for a period that
//! doubles each time it happens again, until a long enough stretch without
//! one starts it over.
//!
//! Nothing a peer sends that is accepted pays its debt down. A peer can
//! always send something acceptable, such as a record of its own signed
//! afresh, so credit for good traffic would let it buy back refused work
//! item for item. What keeps an honest peer clear is that the refusals it
//! causes cost little: a host that is behind ignores items it cannot place
//! yet, and is charged only the work of reading them, while the heavy
//! charge is kept for items no honest peer sends.
//!
//! A cooldown, once begun, runs its course. Work charged while it lasts is
//! for traffic read before it began, so it adds to the debt without
//! starting another.

use std::time::Duration;

use dashmap::DashMap;
use hyperscale_types::ValidatorId;
use tokio::time::Instant;

/// Refused work a peer may run up at once before it cools down.
const ALLOWANCE: Duration = Duration::from_millis(50);

/// Time pays a peer's debt down at one part in this many of the time that
/// passes, so a peer may keep this host refusing its traffic for at most
/// that share of one core.
const WORK_SHARE: u32 = 100;

/// Length of a peer's first cooldown.
const INITIAL_COOLDOWN: Duration = Duration::from_secs(1);

/// Longest cooldown; each one after the first doubles up to this.
const MAX_COOLDOWN: Duration = Duration::from_secs(30);

/// A peer whose last cooldown ended this long ago starts over at
/// [`INITIAL_COOLDOWN`].
const FORGIVEN_AFTER: Duration = Duration::from_secs(120);

/// Debt and cooldown state of one peer.
struct PeerState {
    /// Refused work not yet paid down by time.
    owed: Duration,
    /// When `owed` was last brought up to date.
    updated: Instant,
    /// When the peer's latest cooldown ends or ended, if it has had one.
    cooldown_until: Option<Instant>,
    /// Length of the next cooldown.
    backoff: Duration,
}

impl PeerState {
    const fn new(now: Instant) -> Self {
        Self {
            owed: Duration::ZERO,
            updated: now,
            cooldown_until: None,
            backoff: INITIAL_COOLDOWN,
        }
    }

    /// Add `work` to what the peer owes at `now`, starting a cooldown when
    /// that takes it past its allowance.
    fn charge(&mut self, work: Duration, now: Instant) -> Option<Duration> {
        let forgiven = now.saturating_duration_since(self.updated) / WORK_SHARE;
        self.owed = self.owed.saturating_sub(forgiven) + work;
        self.updated = now;

        if self.owed <= ALLOWANCE || self.cooldown_until.is_some_and(|until| now < until) {
            return None;
        }
        if self
            .cooldown_until
            .is_some_and(|until| now.saturating_duration_since(until) >= FORGIVEN_AFTER)
        {
            self.backoff = INITIAL_COOLDOWN;
        }
        let cooldown = self.backoff;
        self.cooldown_until = Some(now + cooldown);
        self.backoff = (cooldown * 2).min(MAX_COOLDOWN);
        Some(cooldown)
    }
}

/// Charges each peer for the work its refused traffic costs and says which
/// peers are cooling down. A peer is kept by its principal (see
/// [`crate::peer::Peer`]), so the map holds at most one entry per validator.
#[derive(Default)]
pub struct Cooldown {
    peers: DashMap<ValidatorId, PeerState>,
}

impl Cooldown {
    /// Charge `peer` for `work` spent on traffic this host refused. Returns
    /// the cooldown the peer has just entered when the charge took it past
    /// its allowance.
    pub fn charge(&self, peer: ValidatorId, work: Duration) -> Option<Duration> {
        let now = Instant::now();
        self.peers
            .entry(peer)
            .or_insert_with(|| PeerState::new(now))
            .charge(work, now)
    }

    /// Whether `peer` is cooling down.
    pub fn cooling_down(&self, peer: ValidatorId) -> bool {
        self.peers.get(&peer).is_some_and(|state| {
            state
                .cooldown_until
                .is_some_and(|until| Instant::now() < until)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::time::advance;

    use super::*;

    fn random_peer() -> ValidatorId {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        ValidatorId::new(NEXT.fetch_add(1, Ordering::Relaxed))
    }

    /// About what checking one signature costs.
    const SIGNATURE: Duration = Duration::from_millis(2);

    /// About what refusing a small item before any signature check costs.
    const CHEAP: Duration = Duration::from_micros(14);

    #[tokio::test(start_paused = true)]
    async fn work_within_the_allowance_does_not_cool_a_peer_down() {
        let cooldown = Cooldown::default();
        let peer = random_peer();
        assert_eq!(cooldown.charge(peer, ALLOWANCE), None);
        assert!(!cooldown.cooling_down(peer));

        assert_eq!(
            cooldown.charge(peer, Duration::from_nanos(1)),
            Some(INITIAL_COOLDOWN)
        );
        assert!(cooldown.cooling_down(peer));
        assert!(!cooldown.cooling_down(random_peer()), "peers are isolated");
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_interleaving_accepted_items_with_forgeries_is_still_cooled_down() {
        let cooldown = Cooldown::default();
        let peer = random_peer();
        // Seven forged records to each signed one, as fast as a link
        // carries them: the signed ones charge nothing and forgive nothing.
        let mut forged = 0u32;
        let triggered = loop {
            forged += 1;
            if let Some(cooling) = cooldown.charge(peer, SIGNATURE) {
                break cooling;
            }
            if forged.is_multiple_of(7) {
                advance(Duration::from_micros(500)).await;
            }
        };
        assert_eq!(triggered, INITIAL_COOLDOWN);
        let allowed = ALLOWANCE.as_nanos() / SIGNATURE.as_nanos();
        assert_eq!(
            u128::from(forged),
            allowed + 1,
            "the first past the allowance"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn time_pays_work_down_at_the_peers_share() {
        let cooldown = Cooldown::default();
        let peer = random_peer();
        // Just under one part in WORK_SHARE of every second, for minutes.
        let per_second = Duration::from_secs(1) / WORK_SHARE * 99 / 100;
        for _ in 0..600 {
            assert_eq!(cooldown.charge(peer, per_second), None);
            advance(Duration::from_secs(1)).await;
        }

        // Twice the share fills the allowance and cools the peer down.
        let mut seconds = 0;
        while cooldown.charge(peer, per_second * 2).is_none() {
            advance(Duration::from_secs(1)).await;
            seconds += 1;
        }
        assert_eq!(seconds, 4, "the allowance holds four seconds of the excess");
    }

    #[tokio::test(start_paused = true)]
    async fn a_host_that_is_behind_refusing_a_peer_freely_does_not_cool_it_down() {
        let cooldown = Cooldown::default();
        let peer = random_peer();
        // Every item a busy peer delivers is refused for a minute because
        // the receiver cannot place it: five hundred a second.
        for _ in 0..60 * 500 {
            assert_eq!(cooldown.charge(peer, CHEAP), None);
            advance(Duration::from_millis(2)).await;
        }
        assert!(!cooldown.cooling_down(peer));
    }

    #[tokio::test(start_paused = true)]
    async fn a_cooldown_runs_its_course_and_a_peer_still_in_debt_goes_straight_back() {
        let cooldown = Cooldown::default();
        let peer = random_peer();
        assert_eq!(cooldown.charge(peer, ALLOWANCE * 2), Some(INITIAL_COOLDOWN));

        // Verdicts on traffic read before the cooldown began add to the
        // debt without starting another.
        assert_eq!(cooldown.charge(peer, SIGNATURE), None);
        advance(INITIAL_COOLDOWN / 2).await;
        assert!(cooldown.cooling_down(peer));

        advance(INITIAL_COOLDOWN / 2).await;
        assert!(!cooldown.cooling_down(peer), "the cooldown lapsed");
        assert_eq!(
            cooldown.charge(peer, CHEAP),
            Some(INITIAL_COOLDOWN * 2),
            "a peer still past its allowance cools down again, for longer"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cooldowns_double_up_to_the_cap() {
        let cooldown = Cooldown::default();
        let peer = random_peer();
        let mut lengths = Vec::new();
        for _ in 0..8 {
            let length = cooldown
                .charge(peer, ALLOWANCE * 4)
                .expect("past the allowance");
            lengths.push(length.as_secs());
            advance(length).await;
        }
        assert_eq!(lengths, [1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_long_clean_stretch_starts_the_cooldowns_over() {
        let cooldown = Cooldown::default();
        let peer = random_peer();
        for expected in [1, 2, 4] {
            let length = cooldown
                .charge(peer, ALLOWANCE * 4)
                .expect("past the allowance");
            assert_eq!(length.as_secs(), expected);
            advance(length).await;
        }

        advance(FORGIVEN_AFTER.saturating_sub(Duration::from_secs(1))).await;
        assert_eq!(
            cooldown.charge(peer, ALLOWANCE * 4),
            Some(Duration::from_secs(8)),
            "not yet forgiven"
        );
        advance(Duration::from_secs(8) + FORGIVEN_AFTER).await;
        assert_eq!(cooldown.charge(peer, ALLOWANCE * 4), Some(INITIAL_COOLDOWN));
    }
}
