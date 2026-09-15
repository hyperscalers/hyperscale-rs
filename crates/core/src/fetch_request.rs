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

use hyperscale_types::{
    Anchor, MessageClass, PredecessorTerminal, ShardId, SubstateKey, TerminalEvidence, TxHash,
    ValidatorId,
};

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
    /// Committed-transaction membership query against a chain this one
    /// succeeds. Routing shard is `predecessor.shard`, whose committee
    /// still answers while any retained window carries it. `preferred`
    /// is `None`: every member of the terminal committee holds the same
    /// answer, so health-weighted rotation is what moves off a peer that
    /// serves `not_found` or an unusable proof.
    ///
    /// The predecessor rides whole rather than as a shard id. Its
    /// terminal names the window the server reconstructs, and its
    /// `committed_txs_root` is what an absence proof is checked against
    /// before any answer reaches the coordinator.
    CommittedTxs {
        /// The chain being queried and the terminal to resolve against.
        predecessor: PredecessorTerminal,
        /// Transactions whose membership in that chain's committed set
        /// is outstanding.
        tx_hashes: Vec<TxHash>,
        /// Always `None` for this variant; see variant-level doc.
        preferred: Option<ValidatorId>,
        /// Optional class override; see enum-level doc.
        class: Option<MessageClass>,
    },
    /// A state proof this shard's own committee relays, for a cell a
    /// block claims that this validator has not proven for itself.
    ///
    /// Routing shard is the local one: what is wanted is not a
    /// counterpart's state but a peer's copy of a proof of it. Every
    /// member probes, so most hold the bytes already, and the proposer
    /// of the block making the claim certainly does. `preferred` is
    /// `None` for that reason — any member that probed the anchor
    /// answers, and health-weighted rotation is what moves off one that
    /// did not.
    ///
    /// Distinct from [`Self::StateProof`] rather than a routing flag on
    /// it, because a fetch is keyed by its ids: the two ask different
    /// committees the same `(anchor, key)`, and one slot would hold
    /// whichever asked first and never rotate to the other.
    RelayedStateProof {
        /// The commit-proven state the proof reconstructs.
        anchor: Anchor,
        /// The keys whose presence or absence under it is wanted.
        keys: Vec<SubstateKey>,
        /// Always the local shard for this variant.
        shard: ShardId,
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
