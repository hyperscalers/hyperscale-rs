//! Who may make this host sign before proving anything.
//!
//! The side that accepts a connection signs the dialer's nonce once for
//! every validator it hosts before the dialer has proved it carries any
//! validator at all. The QUIC handshake proves only that the dialer holds
//! its endpoint key, and anyone may make one. So before it signs, the host
//! asks two things of the dialer's endpoint:
//!
//! - **Vouched for.** A validator's signed address record in this host's
//!   book names the endpoint, so the validator stands behind it. Such a
//!   dialer binds at once, [`VOUCHED_BURST`] times and then once every
//!   [`VOUCHED_REFILL`]: enough for every reconnect an honest host makes.
//! - **Anyone else** shares one budget of [`UNVOUCHED_BURST`] binds and then
//!   one every [`UNVOUCHED_REFILL`]. A host joining for the first time, whose
//!   record has not reached this host yet, binds from it; so does a host
//!   that knows only its bootstrap peers.
//!
//! A dialer with no turn has its connection closed before anything is
//! signed, and dials again on its own backoff. The handshake keeps its
//! three messages and gains no round trip: the decision is a lookup made
//! between the transport handshake and the first signature.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use iroh::EndpointId;
use tokio::time::Instant;

/// Binds a vouched endpoint may make at once.
const VOUCHED_BURST: u32 = 4;

/// Time in which a vouched endpoint earns another bind.
const VOUCHED_REFILL: Duration = Duration::from_secs(2);

/// Binds unvouched endpoints may make at once, together.
const UNVOUCHED_BURST: u32 = 32;

/// Time in which unvouched endpoints together earn another bind.
const UNVOUCHED_REFILL: Duration = Duration::from_millis(125);

/// Vouched endpoints whose budgets are remembered before the full ones,
/// which a fresh budget would equal, are let go.
const VOUCHED_REMEMBERED: usize = 4096;

/// Turns at something, earned back over time up to a burst.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Turns held as of `at`, in units of one turn.
    turns: f64,
    at: Instant,
}

impl Bucket {
    fn full(burst: u32, now: Instant) -> Self {
        Self {
            turns: f64::from(burst),
            at: now,
        }
    }

    /// The bucket's turns at `now`.
    fn refilled(&self, burst: u32, refill: Duration, now: Instant) -> f64 {
        let earned = now.saturating_duration_since(self.at).as_secs_f64() / refill.as_secs_f64();
        (self.turns + earned).min(f64::from(burst))
    }

    /// Take a turn at `now`, if one is there.
    fn take(&mut self, burst: u32, refill: Duration, now: Instant) -> bool {
        let turns = self.refilled(burst, refill, now);
        self.at = now;
        if turns >= 1.0 {
            self.turns = turns - 1.0;
            true
        } else {
            self.turns = turns;
            false
        }
    }
}

/// Decides which dialers this host signs for.
pub struct BindGate {
    unvouched: Mutex<Bucket>,
    vouched: Mutex<HashMap<EndpointId, Bucket>>,
}

impl Default for BindGate {
    fn default() -> Self {
        Self {
            unvouched: Mutex::new(Bucket::full(UNVOUCHED_BURST, Instant::now())),
            vouched: Mutex::new(HashMap::new()),
        }
    }
}

impl BindGate {
    /// Whether `peer`, which the book vouches for or not, may have this host
    /// sign for it now.
    pub fn admit(&self, peer: EndpointId, vouched: bool) -> bool {
        let now = Instant::now();
        if !vouched {
            return self.unvouched.lock().expect("bind gate lock").take(
                UNVOUCHED_BURST,
                UNVOUCHED_REFILL,
                now,
            );
        }
        let mut vouched = self.vouched.lock().expect("bind gate lock");
        if vouched.len() >= VOUCHED_REMEMBERED && !vouched.contains_key(&peer) {
            vouched.retain(|_, bucket| {
                bucket.refilled(VOUCHED_BURST, VOUCHED_REFILL, now) < f64::from(VOUCHED_BURST)
            });
        }
        vouched
            .entry(peer)
            .or_insert_with(|| Bucket::full(VOUCHED_BURST, now))
            .take(VOUCHED_BURST, VOUCHED_REFILL, now)
    }
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;
    use tokio::time::advance;

    use super::*;

    fn random_peer() -> EndpointId {
        SecretKey::generate().public()
    }

    /// How many of `attempts` binds, one every `spacing`, `gate` admits.
    async fn admitted(
        gate: &BindGate,
        peer: impl Fn() -> EndpointId,
        vouched: bool,
        attempts: u32,
        spacing: Duration,
    ) -> u32 {
        let mut admitted = 0;
        for _ in 0..attempts {
            admitted += u32::from(gate.admit(peer(), vouched));
            advance(spacing).await;
        }
        admitted
    }

    #[tokio::test(start_paused = true)]
    async fn strangers_together_get_a_burst_then_a_steady_trickle() {
        let gate = BindGate::default();
        // A thousand strangers a second, for ten seconds.
        let got = admitted(&gate, random_peer, false, 10_000, Duration::from_millis(1)).await;
        let earned = 10_000 / u32::try_from(UNVOUCHED_REFILL.as_millis()).unwrap();
        assert!(
            got >= UNVOUCHED_BURST + earned - 1 && got <= UNVOUCHED_BURST + earned + 1,
            "{got} admitted"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_vouched_endpoint_is_not_held_up_by_strangers() {
        let gate = BindGate::default();
        let _ = admitted(&gate, random_peer, false, 1_000, Duration::ZERO).await;
        assert!(
            !gate.admit(random_peer(), false),
            "the strangers' budget is spent"
        );
        assert!(gate.admit(random_peer(), true), "a vouched endpoint binds");
    }

    #[tokio::test(start_paused = true)]
    async fn a_vouched_endpoint_rebinding_without_pause_gets_its_own_trickle() {
        let gate = BindGate::default();
        let peer = random_peer();
        let got = admitted(&gate, || peer, true, 1_000, Duration::from_millis(10)).await;
        let earned = 10_000 / u32::try_from(VOUCHED_REFILL.as_millis()).unwrap();
        assert!(
            got >= VOUCHED_BURST + earned - 1 && got <= VOUCHED_BURST + earned + 1,
            "{got} admitted"
        );
        assert!(
            gate.admit(random_peer(), true),
            "another vouched endpoint is not held up"
        );
    }
}
