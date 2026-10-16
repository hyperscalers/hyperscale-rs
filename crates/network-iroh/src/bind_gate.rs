//! Who may make this host work before proving anything.
//!
//! The side that accepts a connection runs a QUIC handshake with the dialer
//! and then signs the dialer's nonce once for every validator it hosts, all
//! before the dialer has proved it carries any validator at all. The
//! handshake proves only that the dialer holds its endpoint key, and anyone
//! may make one. So before any of that work the host asks what it can see
//! of the dialer:
//!
//! - **Vouched for.** A validator's signed address record in this host's
//!   book names where the connection comes from: the endpoint a relay says
//!   it is, or the socket address it arrives from directly. Such a dialer
//!   goes on to its handshake. Its endpoint, once the handshake shows it,
//!   binds [`VOUCHED_BURST`] times and then once every [`VOUCHED_REFILL`]:
//!   enough for every reconnect an honest host makes.
//! - **Anyone else** shares one budget of [`UNVOUCHED_BURST`] handshakes and
//!   then one every [`UNVOUCHED_REFILL`], taken before the handshake. A host
//!   joining for the first time, whose record has not reached this host
//!   yet, binds from it; so does a host that knows only its bootstrap peers.
//!
//! A dialer with no turn is refused before its handshake, for one packet
//! each way, and dials again on its own backoff. A dialer whose address
//! vouched for it but whose handshake shows an endpoint no record names
//! takes a stranger's turn then, before anything is signed. The bind keeps
//! its three messages and gains no round trip: each decision is a lookup.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use iroh::EndpointId;
use tokio::time::Instant;

/// Binds a vouched endpoint may make at once.
const VOUCHED_BURST: u32 = 4;

/// Time in which a vouched endpoint earns another bind.
const VOUCHED_REFILL: Duration = Duration::from_secs(2);

/// Handshakes unvouched dialers may start at once, together.
const UNVOUCHED_BURST: u32 = 32;

/// Time in which unvouched dialers together earn another handshake.
const UNVOUCHED_REFILL: Duration = Duration::from_millis(125);

/// Vouched endpoints whose budgets are remembered before the full ones,
/// which a fresh budget would equal, are let go.
const VOUCHED_REMEMBERED: usize = 4096;

/// What an inbound connection shows of its dialer before its handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// It came through a relay, which names the dialer's endpoint.
    Relayed(EndpointId),
    /// It came straight from this socket address.
    Direct(SocketAddr),
}

/// How an inbound connection was let on to its handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ticket {
    /// A record names where it comes from. `paid` is the endpoint whose
    /// own turn at binding was taken already, when the relay named it.
    Vouched { paid: Option<EndpointId> },
    /// Nothing names it, and it took a turn from the strangers' budget.
    Stranger,
}

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

/// Decides which dialers this host works for.
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
    /// Before its handshake: whether a connection from `origin`, which a
    /// record in the book names or not, may go on to it, and on what
    /// ticket.
    pub fn admit_incoming(&self, origin: Origin, named: bool) -> Option<Ticket> {
        match (origin, named) {
            (Origin::Relayed(peer), true) => self
                .take_vouched(peer)
                .then_some(Ticket::Vouched { paid: Some(peer) }),
            (Origin::Direct(_), true) => Some(Ticket::Vouched { paid: None }),
            (_, false) => self.take_unvouched().then_some(Ticket::Stranger),
        }
    }

    /// After its handshake: whether this host signs for `peer`, which the
    /// book vouches for or not, let on to its handshake with `ticket`.
    pub fn admit_bind(&self, peer: EndpointId, vouched: bool, ticket: Ticket) -> bool {
        match ticket {
            Ticket::Stranger => true,
            Ticket::Vouched { paid } if vouched => paid == Some(peer) || self.take_vouched(peer),
            Ticket::Vouched { .. } => self.take_unvouched(),
        }
    }

    fn take_unvouched(&self) -> bool {
        self.unvouched.lock().expect("bind gate lock").take(
            UNVOUCHED_BURST,
            UNVOUCHED_REFILL,
            Instant::now(),
        )
    }

    fn take_vouched(&self, peer: EndpointId) -> bool {
        let now = Instant::now();
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

    fn address() -> SocketAddr {
        "192.0.2.1:4000".parse().unwrap()
    }

    /// Whether a dialer at `origin` is let on and, once its handshake shows
    /// `peer`, signed for.
    fn admit(gate: &BindGate, origin: Origin, peer: EndpointId, vouched: bool) -> bool {
        gate.admit_incoming(origin, vouched)
            .is_some_and(|ticket| gate.admit_bind(peer, vouched, ticket))
    }

    /// How many of `attempts` dialers relayed from `peer`, one every
    /// `spacing`, `gate` signs for.
    async fn admitted(
        gate: &BindGate,
        peer: impl Fn() -> EndpointId,
        vouched: bool,
        attempts: u32,
        spacing: Duration,
    ) -> u32 {
        let mut admitted = 0;
        for _ in 0..attempts {
            let peer = peer();
            admitted += u32::from(admit(gate, Origin::Relayed(peer), peer, vouched));
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
            gate.admit_incoming(Origin::Direct(address()), false)
                .is_none(),
            "the strangers' budget is spent"
        );
        let peer = random_peer();
        assert!(
            admit(&gate, Origin::Relayed(peer), peer, true),
            "a vouched endpoint binds"
        );
        assert!(
            admit(&gate, Origin::Direct(address()), random_peer(), true),
            "so does one from a vouched address"
        );
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
        let other = random_peer();
        assert!(
            admit(&gate, Origin::Relayed(other), other, true),
            "another vouched endpoint is not held up"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_vouched_endpoint_pays_its_turn_once() {
        let gate = BindGate::default();
        let peer = random_peer();
        for _ in 0..VOUCHED_BURST {
            assert!(admit(&gate, Origin::Relayed(peer), peer, true));
        }
        assert!(
            gate.admit_incoming(Origin::Relayed(peer), true).is_none(),
            "its turns are spent before the handshake"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_vouched_address_hiding_a_stranger_pays_a_strangers_turn() {
        let gate = BindGate::default();
        let ticket = gate
            .admit_incoming(Origin::Direct(address()), true)
            .expect("a vouched address goes on to its handshake");
        let _ = admitted(&gate, random_peer, false, 1_000, Duration::ZERO).await;
        assert!(
            !gate.admit_bind(random_peer(), false, ticket),
            "an endpoint no record names waits for a stranger's turn"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stranger_let_on_is_signed_for_without_paying_again() {
        let gate = BindGate::default();
        let ticket = gate
            .admit_incoming(Origin::Direct(address()), false)
            .expect("a stranger's turn");
        let _ = admitted(&gate, random_peer, false, 1_000, Duration::ZERO).await;
        assert!(gate.admit_bind(random_peer(), false, ticket));
    }
}
