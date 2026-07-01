//! Per-message-type fault injection for [`crate::SimulatedNetwork`].
//!
//! Tests install [`FaultRule`]s that selectively drop or delay messages based
//! on their type, sender, recipient, transport tier, and the current sim
//! time. Used to exercise fallback paths (fetch protocols, retries) by
//! suppressing the primary delivery channel for a payload.
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

use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rand::RngExt;
use rand_chacha::ChaCha8Rng;

use crate::NodeIndex;

/// Transport tier on which a message is dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Broadcast gossip to all peers in a shard or globally.
    Gossip,
    /// Unicast notification with no response.
    Notification,
    /// Outbound request leg of a request/response RPC.
    Request,
    /// Inbound response leg of a request/response RPC.
    Response,
}

/// Context passed to fault rules at each dispatch site.
#[derive(Debug, Clone, Copy)]
pub struct MessageContext<'a> {
    /// Node sending the message.
    pub sender: NodeIndex,
    /// Node receiving the message.
    pub recipient: NodeIndex,
    /// Message type id (e.g. `"transaction.gossip"`).
    pub type_id: &'a str,
    /// Transport tier.
    pub tier: Tier,
}

/// Decision returned by the fault injector for a single dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Deliver normally with the network's sampled latency.
    Pass,
    /// Drop the message; bumps the rule's fired counter.
    Drop,
    /// Add `extra` on top of the network's sampled latency.
    DelayExtra(Duration),
}

/// Filter on a single matching dimension.
#[derive(Debug, Clone, Default)]
enum NodeFilter {
    #[default]
    Any,
    Is(NodeIndex),
    Among(Vec<NodeIndex>),
}

impl NodeFilter {
    fn matches(&self, node: NodeIndex) -> bool {
        match self {
            Self::Any => true,
            Self::Is(n) => *n == node,
            Self::Among(ns) => ns.contains(&node),
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
pub enum FaultAction {
    /// Drop the message unconditionally.
    Drop,
    /// Drop with the given probability `[0.0, 1.0]`.
    DropWithProbability(f64),
    /// Add a fixed extra delay on top of the sampled latency.
    DelayExtra(Duration),
}

#[derive(Debug, Clone, Default)]
struct Matcher {
    types: TypeFilter,
    sender: NodeFilter,
    recipient: NodeFilter,
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
    matched: Arc<AtomicU64>,
    fired: Arc<AtomicU64>,
}

/// Handle returned by [`RuleBuilder::install`]. Cheaply cloneable.
///
/// Holds counters shared with the live rule; reads always reflect the
/// current match/fire counts. Use the handle to inspect or remove the rule.
#[derive(Debug, Clone)]
pub struct RuleHandle {
    id: u64,
    matched: Arc<AtomicU64>,
    fired: Arc<AtomicU64>,
}

impl RuleHandle {
    /// Number of dispatches the rule's matcher matched, regardless of the
    /// decision applied. For a probabilistic rule this counts every matching
    /// message, including those a coin-flip chose to pass — so it's the right
    /// signal for "did this rule intercept any traffic at all", independent of
    /// whether the probabilistic action happened to drop.
    #[must_use]
    pub fn matched(&self) -> u64 {
        self.matched.load(Ordering::Relaxed)
    }

    /// Number of times the rule fired (matched and applied a non-Pass action).
    /// For a deterministic [`FaultAction::Drop`] this equals [`Self::matched`];
    /// for [`FaultAction::DropWithProbability`] it counts only the draws that
    /// actually dropped.
    #[must_use]
    pub fn fired(&self) -> u64 {
        self.fired.load(Ordering::Relaxed)
    }

    /// Internal id, used by [`FaultInjector::remove`].
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }
}

/// Per-message-type fault injection state attached to a [`crate::SimulatedNetwork`].
#[derive(Debug, Default)]
pub struct FaultInjector {
    rules: Vec<FaultRule>,
    next_id: u64,
}

impl FaultInjector {
    /// Decide what to do with a single message dispatch.
    ///
    /// Iterates rules in install order; the first rule whose matcher matches
    /// AND whose time window contains `now` decides. Probability draws use
    /// the network's seeded RNG.
    #[must_use]
    pub fn decide(
        &self,
        ctx: &MessageContext<'_>,
        now: Duration,
        rng: &mut ChaCha8Rng,
    ) -> Decision {
        for rule in &self.rules {
            if !rule.window.contains(now) || !rule.matcher.matches(ctx) {
                continue;
            }
            // The matcher matched this dispatch — record it before the action
            // resolves, so a probabilistic rule that draws "pass" still counts
            // as having intercepted the message.
            rule.matched.fetch_add(1, Ordering::Relaxed);
            let decision = match rule.action {
                FaultAction::Drop => Decision::Drop,
                FaultAction::DropWithProbability(p) => {
                    if rng.random::<f64>() < p {
                        Decision::Drop
                    } else {
                        continue;
                    }
                }
                FaultAction::DelayExtra(d) => Decision::DelayExtra(d),
            };
            rule.fired.fetch_add(1, Ordering::Relaxed);
            return decision;
        }
        Decision::Pass
    }

    /// Remove a rule by handle. Returns true if a rule was removed.
    pub fn remove(&mut self, handle: &RuleHandle) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != handle.id);
        self.rules.len() < before
    }

    /// Remove every installed rule.
    pub fn clear(&mut self) {
        self.rules.clear();
    }

    /// Number of installed rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn install(&mut self, matcher: Matcher, action: FaultAction, window: TimeWindow) -> RuleHandle {
        let id = self.next_id;
        self.next_id += 1;
        let match_counter = Arc::new(AtomicU64::new(0));
        let fire_counter = Arc::new(AtomicU64::new(0));
        self.rules.push(FaultRule {
            id,
            matcher,
            action,
            window,
            matched: Arc::clone(&match_counter),
            fired: Arc::clone(&fire_counter),
        });
        RuleHandle {
            id,
            matched: match_counter,
            fired: fire_counter,
        }
    }
}

/// Builder for installing or removing [`FaultRule`]s on a [`FaultInjector`].
///
/// Returned by `SimulatedNetwork::fault()`. Terminal methods like
/// [`Self::drop_type`] / [`Self::delay_type`] return a [`RuleBuilder`] for
/// further refinement and a final [`RuleBuilder::install`].
pub struct FaultBuilder<'a> {
    injector: &'a mut FaultInjector,
}

impl<'a> FaultBuilder<'a> {
    pub(crate) const fn new(injector: &'a mut FaultInjector) -> Self {
        Self { injector }
    }

    /// Drop messages of any type that match the rest of the filters.
    #[must_use]
    pub fn drop_all(self) -> RuleBuilder<'a> {
        RuleBuilder::new(self.injector, FaultAction::Drop)
    }

    /// Drop messages whose `type_id` equals the given string.
    #[must_use]
    pub fn drop_type(self, type_id: &'static str) -> RuleBuilder<'a> {
        RuleBuilder::new(self.injector, FaultAction::Drop).type_id(type_id)
    }

    /// Drop messages whose `type_id` is one of the given strings.
    #[must_use]
    pub fn drop_types(self, type_ids: &[&'static str]) -> RuleBuilder<'a> {
        RuleBuilder::new(self.injector, FaultAction::Drop).type_ids(type_ids)
    }

    /// Drop with the given probability `[0.0, 1.0]`.
    #[must_use]
    pub fn drop_type_with_probability(
        self,
        type_id: &'static str,
        probability: f64,
    ) -> RuleBuilder<'a> {
        RuleBuilder::new(
            self.injector,
            FaultAction::DropWithProbability(probability.clamp(0.0, 1.0)),
        )
        .type_id(type_id)
    }

    /// Add `extra` to the sampled latency for matching messages.
    #[must_use]
    pub fn delay_type(self, type_id: &'static str, extra: Duration) -> RuleBuilder<'a> {
        RuleBuilder::new(self.injector, FaultAction::DelayExtra(extra)).type_id(type_id)
    }

    /// Remove a previously installed rule.
    #[must_use]
    pub fn remove(self, handle: &RuleHandle) -> bool {
        self.injector.remove(handle)
    }

    /// Remove all installed rules.
    pub fn clear(self) {
        self.injector.clear();
    }
}

/// Refines a rule's matcher and time window before installation.
pub struct RuleBuilder<'a> {
    injector: &'a mut FaultInjector,
    action: FaultAction,
    matcher: Matcher,
    window: TimeWindow,
}

impl<'a> RuleBuilder<'a> {
    fn new(injector: &'a mut FaultInjector, action: FaultAction) -> Self {
        Self {
            injector,
            action,
            matcher: Matcher::default(),
            window: TimeWindow::default(),
        }
    }

    fn type_id(mut self, type_id: &'static str) -> Self {
        self.matcher.types = TypeFilter::OneOf(vec![type_id]);
        self
    }

    fn type_ids(mut self, type_ids: &[&'static str]) -> Self {
        self.matcher.types = TypeFilter::OneOf(type_ids.to_vec());
        self
    }

    /// Match only when sent by this node.
    #[must_use]
    pub fn from(mut self, sender: NodeIndex) -> Self {
        self.matcher.sender = NodeFilter::Is(sender);
        self
    }

    /// Match only when sent by any of these nodes.
    #[must_use]
    pub fn from_any(mut self, senders: &[NodeIndex]) -> Self {
        self.matcher.sender = NodeFilter::Among(senders.to_vec());
        self
    }

    /// Match only when received by this node.
    #[must_use]
    pub fn to(mut self, recipient: NodeIndex) -> Self {
        self.matcher.recipient = NodeFilter::Is(recipient);
        self
    }

    /// Match only when received by any of these nodes.
    #[must_use]
    pub fn to_any(mut self, recipients: &[NodeIndex]) -> Self {
        self.matcher.recipient = NodeFilter::Among(recipients.to_vec());
        self
    }

    /// Match in either direction between `a` and `b`.
    #[must_use]
    pub fn between_nodes(mut self, a: NodeIndex, b: NodeIndex) -> Self {
        self.matcher.sender = NodeFilter::Among(vec![a, b]);
        self.matcher.recipient = NodeFilter::Among(vec![a, b]);
        self
    }

    /// Match only on the given transport tier.
    #[must_use]
    pub fn tier(mut self, tier: Tier) -> Self {
        self.matcher.tier = TierFilter::OneOf(vec![tier]);
        self
    }

    /// Match only on the given set of tiers.
    #[must_use]
    pub fn tiers(mut self, tiers: &[Tier]) -> Self {
        self.matcher.tier = TierFilter::OneOf(tiers.to_vec());
        self
    }

    /// Active only while sim time is in `range` (start inclusive, end exclusive).
    #[must_use]
    pub const fn during(mut self, range: Range<Duration>) -> Self {
        self.window.start = Some(range.start);
        self.window.end = Some(range.end);
        self
    }

    /// Active starting at this sim time.
    #[must_use]
    pub const fn after(mut self, t: Duration) -> Self {
        self.window.start = Some(t);
        self
    }

    /// Active until this sim time (exclusive).
    #[must_use]
    pub const fn until(mut self, t: Duration) -> Self {
        self.window.end = Some(t);
        self
    }

    /// Install the rule. Returns a handle to inspect or remove it later.
    #[must_use]
    pub fn install(self) -> RuleHandle {
        self.injector
            .install(self.matcher, self.action, self.window)
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    fn rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(42)
    }

    fn ctx(
        sender: NodeIndex,
        recipient: NodeIndex,
        type_id: &str,
        tier: Tier,
    ) -> MessageContext<'_> {
        MessageContext {
            sender,
            recipient,
            type_id,
            tier,
        }
    }

    #[test]
    fn empty_injector_passes_everything() {
        let injector = FaultInjector::default();
        let mut r = rng();
        let d = injector.decide(&ctx(0, 1, "x", Tier::Gossip), Duration::ZERO, &mut r);
        assert_eq!(d, Decision::Pass);
    }

    #[test]
    fn drop_type_only_matches_named_type() {
        let mut injector = FaultInjector::default();
        let h = FaultBuilder::new(&mut injector)
            .drop_type("foo.gossip")
            .install();
        let mut r = rng();
        assert_eq!(
            injector.decide(
                &ctx(0, 1, "foo.gossip", Tier::Gossip),
                Duration::ZERO,
                &mut r
            ),
            Decision::Drop
        );
        assert_eq!(
            injector.decide(
                &ctx(0, 1, "bar.gossip", Tier::Gossip),
                Duration::ZERO,
                &mut r
            ),
            Decision::Pass
        );
        assert_eq!(h.fired(), 1);
    }

    #[test]
    fn from_filter_restricts_sender() {
        let mut injector = FaultInjector::default();
        let h = FaultBuilder::new(&mut injector)
            .drop_type("foo")
            .from(3)
            .install();
        let mut r = rng();
        assert_eq!(
            injector.decide(&ctx(3, 1, "foo", Tier::Gossip), Duration::ZERO, &mut r),
            Decision::Drop
        );
        assert_eq!(
            injector.decide(&ctx(2, 1, "foo", Tier::Gossip), Duration::ZERO, &mut r),
            Decision::Pass
        );
        assert_eq!(h.fired(), 1);
    }

    #[test]
    fn time_window_gates_rule() {
        let mut injector = FaultInjector::default();
        let h = FaultBuilder::new(&mut injector)
            .drop_type("foo")
            .during(Duration::from_secs(1)..Duration::from_secs(3))
            .install();
        let mut r = rng();
        assert_eq!(
            injector.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO, &mut r),
            Decision::Pass
        );
        assert_eq!(
            injector.decide(
                &ctx(0, 1, "foo", Tier::Gossip),
                Duration::from_secs(2),
                &mut r
            ),
            Decision::Drop
        );
        assert_eq!(
            injector.decide(
                &ctx(0, 1, "foo", Tier::Gossip),
                Duration::from_secs(3),
                &mut r
            ),
            Decision::Pass
        );
        assert_eq!(h.fired(), 1);
    }

    #[test]
    fn first_match_wins() {
        let mut injector = FaultInjector::default();
        // Specific exception first, broad rule second.
        let exception = FaultBuilder::new(&mut injector)
            .delay_type("foo", Duration::from_millis(50))
            .from(0)
            .install();
        let broad = FaultBuilder::new(&mut injector).drop_type("foo").install();
        let mut r = rng();
        assert_eq!(
            injector.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO, &mut r),
            Decision::DelayExtra(Duration::from_millis(50))
        );
        assert_eq!(
            injector.decide(&ctx(2, 1, "foo", Tier::Gossip), Duration::ZERO, &mut r),
            Decision::Drop
        );
        assert_eq!(exception.fired(), 1);
        assert_eq!(broad.fired(), 1);
    }

    #[test]
    fn tier_filter_separates_request_and_response() {
        let mut injector = FaultInjector::default();
        let h = FaultBuilder::new(&mut injector)
            .drop_type("foo")
            .tier(Tier::Response)
            .install();
        let mut r = rng();
        assert_eq!(
            injector.decide(&ctx(0, 1, "foo", Tier::Request), Duration::ZERO, &mut r),
            Decision::Pass
        );
        assert_eq!(
            injector.decide(&ctx(1, 0, "foo", Tier::Response), Duration::ZERO, &mut r),
            Decision::Drop
        );
        assert_eq!(h.fired(), 1);
    }

    #[test]
    fn remove_takes_a_rule_out() {
        let mut injector = FaultInjector::default();
        let h = FaultBuilder::new(&mut injector).drop_type("foo").install();
        let mut r = rng();
        assert_eq!(
            injector.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO, &mut r),
            Decision::Drop
        );
        assert!(injector.remove(&h));
        assert_eq!(
            injector.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO, &mut r),
            Decision::Pass
        );
    }

    #[test]
    fn probability_drop_uses_seeded_rng_deterministically() {
        let mut injector = FaultInjector::default();
        let h = FaultBuilder::new(&mut injector)
            .drop_type_with_probability("foo", 0.5)
            .install();
        let mut r1 = rng();
        let mut r2 = rng();
        for _ in 0..100 {
            let d1 = injector.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO, &mut r1);
            let d2 = injector.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO, &mut r2);
            assert_eq!(d1, d2);
        }
        assert!(h.fired() > 0);
        assert!(h.fired() < 200);
    }

    #[test]
    fn matched_counts_passes_a_probabilistic_rule_doesnt_drop() {
        // A zero-probability rule never drops, but every matching dispatch
        // must still register as a match: `matched()` is how the fault-tests
        // assert a probabilistic rule's matcher is wired without coupling the
        // premise check to the coin-flip outcome.
        let mut injector = FaultInjector::default();
        let h = FaultBuilder::new(&mut injector)
            .drop_type_with_probability("foo", 0.0)
            .install();
        let mut r = rng();
        for _ in 0..8 {
            assert_eq!(
                injector.decide(&ctx(0, 1, "foo", Tier::Request), Duration::ZERO, &mut r),
                Decision::Pass
            );
        }
        assert_eq!(h.matched(), 8);
        assert_eq!(h.fired(), 0);
    }

    #[test]
    fn matched_equals_fired_for_deterministic_drop() {
        let mut injector = FaultInjector::default();
        let h = FaultBuilder::new(&mut injector).drop_type("foo").install();
        let mut r = rng();
        for _ in 0..3 {
            assert_eq!(
                injector.decide(&ctx(0, 1, "foo", Tier::Gossip), Duration::ZERO, &mut r),
                Decision::Drop
            );
        }
        assert_eq!(h.matched(), 3);
        assert_eq!(h.fired(), 3);
    }
}
