//! Typed dispatch into the unified fetch protocols.
//!
//! Coordinators emit [`crate::Action::Fetch`] wrapping one of these variants
//! when they need the runner to issue a network fetch. `io_loop`'s dispatcher
//! has a single `Action::Fetch(req)` arm that matches on the inner enum and
//! calls into the corresponding `instances/*.rs` module.
//!
//! Peer selection is the network layer's job: the runner derives the
//! `ShardId` from the variant (local shard for intra-shard variants;
//! `source_shard` or `tick_id.shard_id()` for cross-shard variants)
//! and hands it to `Network::request` along with `preferred`. Coordinators
//! never reach into the topology for committee membership when emitting
//! fetches.
//!
//! Per-payload variants are keyless (just `ids + preferred`); admission
//! events drive cancellation rather than scope-keyed eviction. Cross-shard
//! variants retain `(source_shard, block_height)` because that scope IS
//! the fetch key (no id-set to enumerate).

use hyperscale_types::{Anchor, MessageClass, ShardId, SubstateKey, TerminalEvidence, ValidatorId};

use crate::FetchIds;

/// Fetch family — one variant per payload type.
///
/// Common field semantics across variants:
///
/// - `shard` — committee whose members will serve the request. Local for
///   intra-shard fetches; source shard for cross-shard DA fetches.
/// - `preferred` — canonical-source hint passed straight to
///   `Network::request`. `Some(proposer)` on shard-path fetches where one
///   peer is authoritative; `None` on catch-up / DA paths that fan out.
/// - `class` — overrides the wire type's static `NetworkMessage::class()`.
///   `None` keeps the default; `Some` demotes to a less-urgent class
///   (typically `Recovery`) for catch-up / best-effort traffic.
#[derive(Debug, Clone)]
pub enum FetchRequest {
    /// Ask `shard`'s committee for `ids`.
    ///
    /// The id vocabulary is [`FetchIds`], which is also what retires a
    /// batch on [`Action::AbandonFetch`](crate::Action::AbandonFetch) —
    /// one spelling per payload, asked and released alike, rather than a
    /// request shape per binding that a dispatcher reassembles into the
    /// ids its emitter already writes on the abandon path.
    ///
    /// Routing rules the ids do not carry themselves: transactions,
    /// local provisions and finalizations are intra-shard, so `shard` is
    /// local; remote provisions, execution certificates and shard
    /// witnesses route to the source shard, which has to be carried
    /// because the requester knows only that the payload is that
    /// shard's business; a state proof routes to its anchor's shard,
    /// whose committee holds the JMT version the anchor's height names.
    Ask {
        /// What to fetch.
        ids: FetchIds,
        /// Committee whose members will serve the request.
        shard: ShardId,
        /// Canonical-source hint, when one exists.
        preferred: Option<ValidatorId>,
        /// Optional class override; see enum-level doc.
        class: Option<MessageClass>,
    },
    /// A split's right child asking its parent's terminal state which
    /// committed markers it holds. Routing shard is `terminal.shard`,
    /// whose committee still answers while any retained window carries
    /// it. `preferred` is `None`: every member of the terminal committee
    /// holds the same state, so health-weighted rotation is what moves
    /// off a peer that serves `not_found` or an unusable proof.
    ///
    /// Carries the whole wanted set, re-derived on every scan. The node
    /// diffs it against what the state-proof fetch holds under this
    /// terminal, so a key that drops out of the set here — its
    /// transaction gone from the pool, or the rule retiring as the chain
    /// outlives its origin — is what releases its slot. An empty set is
    /// how the last one retires.
    PrecutProofs {
        /// The parent's terminal, whose state root every proof is
        /// checked against.
        terminal: Anchor,
        /// The marker keys still owed an answer.
        keys: Vec<SubstateKey>,
        /// Always `None` for this variant; see variant-level doc.
        preferred: Option<ValidatorId>,
        /// Optional class override; see enum-level doc.
        class: Option<MessageClass>,
    },
    /// A departed shard's settled-transaction set, checked against the
    /// root this node's own beacon fold attests. Routing shard is
    /// `evidence.shard`, whose terminal committee keeps serving while
    /// any retained window carries it. `preferred` is `None`: every
    /// member holds the same window.
    ///
    /// Carries the whole wanted set, re-derived on every beacon fold.
    /// The node diffs it against what the fetch already holds, so a
    /// terminal that drops out of the set here — the set acquired, the
    /// evidence window closed, the shard evicted from every retained
    /// window — is what releases its slot. An empty set is how the last
    /// one retires.
    SettledTxs {
        /// Every terminal whose settled set is still wanted.
        wanted: Vec<TerminalEvidence>,
        /// Always `None` for this variant; see variant-level doc.
        preferred: Option<ValidatorId>,
        /// Optional class override; see enum-level doc.
        class: Option<MessageClass>,
    },
}
