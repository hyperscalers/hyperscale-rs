//! The fault-injection engine — drop rules, the partition block-set, and the
//! seeded probability RNG. Gated behind `test-utils`; only the test harnesses
//! install faults.
//!
//! Tests install [`FaultRule`]s that drop messages by type, host, transport
//! tier, and clock, and [`Engine::block`] host pairs to model partitions. Used
//! to exercise fallback paths (fetch protocols, retries, catch-up sync) by
//! suppressing the primary delivery channel for a payload or cutting a set of
//! hosts off. Probability draws come from the engine's own [`ChaCha8Rng`],
//! seeded off a caller-supplied seed mixed with a fixed salt — an isolated
//! stream that never perturbs the sim's master RNG.
//!
//! # Example
//!
//! ```ignore
//! let dropped = network.fault()
//!     .drop_type("provisions.notification")
//!     .from(proposer)
//!     .install();
//!
//! runner.run_until(Duration::from_secs(2));
//! assert!(dropped.fired() >= 1);
//! ```

use std::collections::HashSet;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{Decision, HostId, MessageContext, Tier};

/// Salt mixed into the engine's seed so its probability stream is disjoint from
/// the harness's master RNG.
const FAULT_SALT: u64 = 0xFA17_5A17_FA17_5A17;

/// Filter on a host dimension (sender or recipient).
#[derive(Debug, Clone, Default)]
enum HostFilter {
    #[default]
    Any,
    Is(HostId),
}

impl HostFilter {
    fn matches(&self, host: HostId) -> bool {
        match self {
            Self::Any => true,
            Self::Is(h) => *h == host,
        }
    }
}

/// Filter on transport tier.
#[derive(Debug, Clone, Default)]
enum TierFilter {
    #[default]
    Any,
    OneOf(Vec<Tier>),
}

impl TierFilter {
    fn matches(&self, tier: Tier) -> bool {
        match self {
            Self::Any => true,
            Self::OneOf(ts) => ts.contains(&tier),
        }
    }
}

/// Filter on message type id.
#[derive(Debug, Clone, Default)]
enum TypeFilter {
    #[default]
    Any,
    OneOf(Vec<&'static str>),
}

impl TypeFilter {
    fn matches(&self, type_id: &str) -> bool {
        match self {
            Self::Any => true,
            Self::OneOf(types) => types.contains(&type_id),
        }
    }
}

/// Time window during which a rule is active. `None` ends mean unbounded.
#[derive(Debug, Clone, Copy, Default)]
struct TimeWindow {
    start: Option<Duration>,
    end: Option<Duration>,
}

impl TimeWindow {
    fn contains(&self, now: Duration) -> bool {
        self.start.is_none_or(|s| now >= s) && self.end.is_none_or(|e| now < e)
    }
}

/// What to do when a rule matches.
#[derive(Debug, Clone, Copy)]
enum FaultAction {
    /// Drop the message unconditionally.
    Drop,
    /// Drop with the given probability `[0.0, 1.0]`.
    DropWithProbability(f64),
}

/// Portable descriptor for a drop rule — the value form of the fluent builder.
///
/// Installs rules from a shared `&self` control surface — the adapter's fault
/// gate and the test harness — where the borrow-based [`FaultBuilder`] can't
/// reach. Every field is optional; an unset field matches anything.
#[derive(Debug, Clone, Default)]
pub struct DropSpec {
    /// Match this message type id.
    pub type_id: Option<&'static str>,
    /// Match this sending host.
    pub from: Option<HostId>,
    /// Match this receiving host.
    pub to: Option<HostId>,
    /// Match this transport tier.
    pub tier: Option<Tier>,
    /// Drop with this probability `[0.0, 1.0]`; unset means always drop when matched.
    pub probability: Option<f64>,
    /// Active window (start inclusive, end exclusive); unset means unbounded.
    ///
    /// Not portable across harnesses: the clock origin differs — the sim
    /// measures from its genesis-relative logical clock, the libp2p gate from
    /// wall-clock at gate construction. A windowed rule means different things
    /// on each, so the portable scenario surface never exposes one.
    pub window: Option<Range<Duration>>,
}

#[derive(Debug, Clone, Default)]
struct Matcher {
    types: TypeFilter,
    sender: HostFilter,
    recipient: HostFilter,
    tier: TierFilter,
}

impl Matcher {
    fn matches(&self, ctx: &MessageContext<'_>) -> bool {
        self.types.matches(ctx.type_id)
            && self.sender.matches(ctx.sender)
            && self.recipient.matches(ctx.recipient)
            && self.tier.matches(ctx.tier)
    }
}

#[derive(Debug, Clone)]
struct FaultRule {
    id: u64,
    matcher: Matcher,
    action: FaultAction,
    window: TimeWindow,
    fired: Arc<AtomicU64>,
}

/// Handle returned by [`RuleBuilder::install`]. Cheaply cloneable.
///
/// Holds the fire counter shared with the live rule; reads always reflect the
/// current fire count. Use the handle to inspect or remove the rule.
#[derive(Debug, Clone)]
pub struct RuleHandle {
    id: u64,
    fired: Arc<AtomicU64>,
}

impl RuleHandle {
    /// Number of times the rule fired (matched and applied a non-Pass action).
    /// For a deterministic [`FaultAction::Drop`] this equals the number of
    /// matching dispatches; for [`FaultAction::DropWithProbability`] it counts
    /// only the draws that actually dropped.
    #[must_use]
    pub fn fired(&self) -> u64 {
        self.fired.load(Ordering::Relaxed)
    }
}

/// Per-host fault-injection state: drop rules plus a partition block-set.
///
/// One object owns both — a matching drop rule suppresses a single message
/// class, a blocked `(from, to)` pair suppresses every delivery between two
/// hosts (a partition). Owns its own probability RNG, so probability draws never
/// touch a harness's master stream.
#[derive(Debug)]
pub struct Engine {
    rules: Vec<FaultRule>,
    next_id: u64,
    blocked: HashSet<(HostId, HostId)>,
    rng: Mutex<ChaCha8Rng>,
}

impl Engine {
    /// Build an empty engine whose probability stream is derived from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            rules: Vec::new(),
            next_id: 0,
            blocked: HashSet::new(),
            rng: Mutex::new(ChaCha8Rng::seed_from_u64(seed ^ FAULT_SALT)),
        }
    }

    // ── Drop rules ───────────────────────────────────────────────────────

    /// Decide what to do with a single message dispatch against the drop rules.
    ///
    /// Iterates rules in install order; the first rule whose matcher matches
    /// AND whose time window contains `now` decides. Probability draws use the
    /// engine's own seeded RNG, disjoint from any master stream. Partitions are
    /// checked separately via [`Self::is_blocked`].
    #[must_use]
    pub fn decide(&self, ctx: &MessageContext<'_>, now: Duration) -> Decision {
        for rule in &self.rules {
            if !rule.window.contains(now) || !rule.matcher.matches(ctx) {
                continue;
            }
            match rule.action {
                FaultAction::Drop => {}
                FaultAction::DropWithProbability(p) => {
                    if self.rng.lock().random::<f64>() >= p {
                        continue;
                    }
                }
            }
            rule.fired.fetch_add(1, Ordering::Relaxed);
            return Decision::Drop;
        }
        Decision::Pass
    }

    /// Remove a rule by handle. Returns true if a rule was removed.
    pub fn remove(&mut self, handle: &RuleHandle) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != handle.id);
        self.rules.len() < before
    }

    /// Remove every installed drop rule (leaves the block-set intact).
    pub fn clear(&mut self) {
        self.rules.clear();
    }

    fn install(&mut self, matcher: Matcher, action: FaultAction, window: TimeWindow) -> RuleHandle {
        let id = self.next_id;
        self.next_id += 1;
        let fire_counter = Arc::new(AtomicU64::new(0));
        self.rules.push(FaultRule {
            id,
            matcher,
            action,
            window,
            fired: Arc::clone(&fire_counter),
        });
        RuleHandle {
            id,
            fired: fire_counter,
        }
    }

    /// Install a drop rule from a [`DropSpec`] — the value-form entry point the
    /// shared-`&self` control surfaces install through. Equivalent to the fluent
    /// builder.
    pub fn install_spec(&mut self, spec: DropSpec) -> RuleHandle {
        let action = spec.probability.map_or(FaultAction::Drop, |p| {
            FaultAction::DropWithProbability(p.clamp(0.0, 1.0))
        });
        let mut matcher = Matcher::default();
        if let Some(type_id) = spec.type_id {
            matcher.types = TypeFilter::OneOf(vec![type_id]);
        }
        if let Some(from) = spec.from {
            matcher.sender = HostFilter::Is(from);
        }
        if let Some(to) = spec.to {
            matcher.recipient = HostFilter::Is(to);
        }
        if let Some(tier) = spec.tier {
            matcher.tier = TierFilter::OneOf(vec![tier]);
        }
        let window = spec
            .window
            .map_or_else(TimeWindow::default, |r| TimeWindow {
                start: Some(r.start),
                end: Some(r.end),
            });
        self.install(matcher, action, window)
    }

    // ── Partition (block-set) ────────────────────────────────────────────

    /// Block the directed edge `a → b`: deliveries from `a` to `b` are dropped.
    pub fn block(&mut self, a: HostId, b: HostId) {
        self.blocked.insert((a, b));
    }

    /// Unblock the directed edge `a → b`.
    pub fn unblock(&mut self, a: HostId, b: HostId) {
        self.blocked.remove(&(a, b));
    }

    /// Whether a delivery from `a` to `b` is blocked by a partition.
    #[must_use]
    pub fn is_blocked(&self, a: HostId, b: HostId) -> bool {
        self.blocked.contains(&(a, b))
    }

    /// Clear every blocked edge — heal all partitions (leaves drop rules intact).
    pub fn unblock_all(&mut self) {
        self.blocked.clear();
    }

    /// Number of blocked directed edges.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocked.len()
    }
}

/// Builder for installing or removing [`FaultRule`]s on an [`Engine`].
///
/// Terminal methods like [`Self::drop_type`] return a [`RuleBuilder`] for
/// further refinement and a final [`RuleBuilder::install`].
pub struct FaultBuilder<'a> {
    engine: &'a mut Engine,
}

impl<'a> FaultBuilder<'a> {
    /// Wrap an engine for fluent rule construction.
    pub const fn new(engine: &'a mut Engine) -> Self {
        Self { engine }
    }

    /// Drop messages whose `type_id` equals the given string.
    #[must_use]
    pub fn drop_type(self, type_id: &'static str) -> RuleBuilder<'a> {
        RuleBuilder::new(self.engine, FaultAction::Drop).type_id(type_id)
    }

    /// Drop with the given probability `[0.0, 1.0]`.
    #[must_use]
    pub fn drop_type_with_probability(
        self,
        type_id: &'static str,
        probability: f64,
    ) -> RuleBuilder<'a> {
        RuleBuilder::new(
            self.engine,
            FaultAction::DropWithProbability(probability.clamp(0.0, 1.0)),
        )
        .type_id(type_id)
    }

    /// Remove a previously installed rule.
    #[must_use]
    pub fn remove(self, handle: &RuleHandle) -> bool {
        self.engine.remove(handle)
    }

    /// Remove all installed drop rules.
    pub fn clear(self) {
        self.engine.clear();
    }
}

/// Refines a rule's matcher and time window before installation.
pub struct RuleBuilder<'a> {
    engine: &'a mut Engine,
    action: FaultAction,
    matcher: Matcher,
    window: TimeWindow,
}

impl<'a> RuleBuilder<'a> {
    fn new(engine: &'a mut Engine, action: FaultAction) -> Self {
        Self {
            engine,
            action,
            matcher: Matcher::default(),
            window: TimeWindow::default(),
        }
    }

    fn type_id(mut self, type_id: &'static str) -> Self {
        self.matcher.types = TypeFilter::OneOf(vec![type_id]);
        self
    }

    /// Match only when sent by this host.
    #[must_use]
    pub const fn from(mut self, sender: HostId) -> Self {
        self.matcher.sender = HostFilter::Is(sender);
        self
    }

    /// Match only when received by this host.
    #[must_use]
    pub const fn to(mut self, recipient: HostId) -> Self {
        self.matcher.recipient = HostFilter::Is(recipient);
        self
    }

    /// Match only on the given transport tier.
    #[must_use]
    pub fn tier(mut self, tier: Tier) -> Self {
        self.matcher.tier = TierFilter::OneOf(vec![tier]);
        self
    }

    /// Active only while the clock is in `range` (start inclusive, end exclusive).
    ///
    /// The clock origin is harness-specific, so a windowed rule is not portable;
    /// it is authored per harness, never through the scenario surface (see
    /// [`DropSpec::window`]).
    #[must_use]
    pub const fn during(mut self, range: Range<Duration>) -> Self {
        self.window.start = Some(range.start);
        self.window.end = Some(range.end);
        self
    }

    /// Install the rule. Returns a handle to inspect or remove it later.
    #[must_use]
    pub fn install(self) -> RuleHandle {
        self.engine.install(self.matcher, self.action, self.window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        Engine::new(42)
    }

    fn h(id: u32) -> HostId {
        HostId(id)
    }

    fn ctx(sender: u32, recipient: u32, type_id: &str, tier: Tier) -> MessageContext<'_> {
        MessageContext {
            sender: HostId(sender),
            recipient: HostId(recipient),
            type_id,
            tier,
        }
    }

    #[test]
    fn empty_engine_passes_everything() {
        let engine = engine();
        assert_eq!(
            engine.decide(&ctx(0, 1, "x", Tier::Gossip), Duration::ZERO),
            Decision::Pass
        );
    }

    #[test]
    fn drop_type_only_matches_named_type() {
        let mut engine = engine();
        let handle = FaultBuilder::new(&mut engine)
            .drop_type("foo.gossip")
            .install();
        assert_eq!(
            engine.decide(&ctx(0, 1, "foo.gossip", Tier::Gossip), Duration::ZERO),
            Decision::Drop
        );
        assert_eq!(
            engine.decide(&ctx(0, 1, "bar.gossip", Tier::Gossip), Duration::ZERO),
            Decision::Pass
        );
        assert_eq!(handle.fired(), 1);
    }

    #[test]
    fn from_filter_restricts_sender() {
        let mut engine = engine();
        let handle = FaultBuilder::new(&mut engine)
            .drop_type("foo")
            .from(h(3))
            .install();
        assert_eq!(
            engine.decide(&ctx(3, 1, "foo", Tier::Gossip), Duration::ZERO),
            Decision::Drop
        );
        assert_eq!(
            engine.decide(&ctx(2, 1, "foo", Tier::Gossip), Duration::ZERO),
            Decision::Pass
        );
        assert_eq!(handle.fired(), 1);
    }

    #[test]
    fn time_window_gates_rule() {
        let mut engine = engine();
        let handle = FaultBuilder::new(&mut engine)
            .drop_type("foo")
            .during(Duration::from_secs(1)..Duration::from_secs(3))
            .install();
        assert_eq!(
            engine.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO),
            Decision::Pass
        );
        assert_eq!(
            engine.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::from_secs(2)),
            Decision::Drop
        );
        assert_eq!(
            engine.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::from_secs(3)),
            Decision::Pass
        );
        assert_eq!(handle.fired(), 1);
    }

    #[test]
    fn first_match_wins() {
        let mut engine = engine();
        // Specific rule first, broad rule second — the first matching rule that
        // fires decides and returns, so later rules never see that dispatch.
        let specific = FaultBuilder::new(&mut engine)
            .drop_type("foo")
            .from(h(0))
            .install();
        let broad = FaultBuilder::new(&mut engine).drop_type("foo").install();
        // Sender 0: the specific rule drops and returns; the broad never fires.
        assert_eq!(
            engine.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO),
            Decision::Drop
        );
        // Sender 2: the specific rule's `from(0)` misses, the broad rule drops.
        assert_eq!(
            engine.decide(&ctx(2, 1, "foo", Tier::Gossip), Duration::ZERO),
            Decision::Drop
        );
        assert_eq!(specific.fired(), 1);
        assert_eq!(broad.fired(), 1);
    }

    #[test]
    fn tier_filter_separates_request_and_response() {
        let mut engine = engine();
        let handle = FaultBuilder::new(&mut engine)
            .drop_type("foo")
            .tier(Tier::Response)
            .install();
        assert_eq!(
            engine.decide(&ctx(0, 1, "foo", Tier::Request), Duration::ZERO),
            Decision::Pass
        );
        assert_eq!(
            engine.decide(&ctx(1, 0, "foo", Tier::Response), Duration::ZERO),
            Decision::Drop
        );
        assert_eq!(handle.fired(), 1);
    }

    #[test]
    fn remove_takes_a_rule_out() {
        let mut engine = engine();
        let handle = FaultBuilder::new(&mut engine).drop_type("foo").install();
        assert_eq!(
            engine.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO),
            Decision::Drop
        );
        assert!(engine.remove(&handle));
        assert_eq!(
            engine.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO),
            Decision::Pass
        );
    }

    #[test]
    fn probability_drop_uses_seeded_rng_deterministically() {
        let mut e1 = Engine::new(7);
        let mut e2 = Engine::new(7);
        let h1 = FaultBuilder::new(&mut e1)
            .drop_type_with_probability("foo", 0.5)
            .install();
        let _h2 = FaultBuilder::new(&mut e2)
            .drop_type_with_probability("foo", 0.5)
            .install();
        for _ in 0..100 {
            let d1 = e1.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO);
            let d2 = e2.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO);
            assert_eq!(d1, d2);
        }
        assert!(h1.fired() > 0);
        assert!(h1.fired() < 200);
    }

    #[test]
    fn block_suppresses_a_directed_edge() {
        let mut engine = engine();
        assert!(!engine.is_blocked(h(0), h(1)));
        engine.block(h(0), h(1));
        assert!(engine.is_blocked(h(0), h(1)));
        // Directed — the reverse edge is unaffected.
        assert!(!engine.is_blocked(h(1), h(0)));
        assert_eq!(engine.block_count(), 1);

        engine.unblock(h(0), h(1));
        assert!(!engine.is_blocked(h(0), h(1)));
        assert_eq!(engine.block_count(), 0);
    }

    #[test]
    fn unblock_all_heals_partitions_but_keeps_rules() {
        let mut engine = engine();
        let handle = FaultBuilder::new(&mut engine).drop_type("foo").install();
        engine.block(h(0), h(1));
        engine.block(h(2), h(3));
        assert_eq!(engine.block_count(), 2);

        engine.unblock_all();
        assert_eq!(engine.block_count(), 0);
        // Drop rules survive a heal.
        assert_eq!(
            engine.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO),
            Decision::Drop
        );
        assert_eq!(handle.fired(), 1);
    }

    #[test]
    fn install_spec_matches_like_the_builder() {
        let mut engine = engine();
        let handle = engine.install_spec(DropSpec {
            type_id: Some("foo"),
            to: Some(h(1)),
            ..Default::default()
        });
        // Type "foo" to host 1 drops.
        assert_eq!(
            engine.decide(&ctx(0, 1, "foo", Tier::Notification), Duration::ZERO),
            Decision::Drop
        );
        // A different recipient does not match.
        assert_eq!(
            engine.decide(&ctx(0, 2, "foo", Tier::Notification), Duration::ZERO),
            Decision::Pass
        );
        assert_eq!(handle.fired(), 1);
    }
}
