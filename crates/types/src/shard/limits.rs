//! Block content limits.
//!
//! Hard caps on per-block payload sizes. Wire decoders enforce them at
//! decode time, admission paths enforce them at header ingress, and
//! proposers respect them when building blocks.
//!
//! These are protocol invariants, not operator-tunable config: every
//! validator must be able to handle a peak-sized block, so dialing
//! limits down on a single node only degrades that node's responsiveness
//! without reducing the protocol-wide load it has to keep up with.

use hyperscale_jmt::MAX_PROOF_CLAIMS;
use hyperscale_vm_types::{
    AMOUNT_CELL_BYTES, DeclaredWork, MAX_CALL_BYTES, MAX_ENVELOPE_BYTES, MAX_EVENT_BYTES_PER_TX,
    MAX_GAS_LIMIT, MAX_KEY_BYTES, MAX_SIG_BYTES, MAX_TX_ATTESTATIONS, VERIFY_WEIGHT,
};

use crate::provisioning::limits::MAX_MERKLE_PROOF_LEN;
use crate::{Address, LocalKey, RoutePrefix, TxsInFlight};

/// The largest message any transport carries, compressed.
///
/// One figure for both paths a block travels: the framed request streams
/// and the gossip topics. A message past it is not truncated, it is
/// dropped — the sender warns and the round it carried is lost — so a
/// section a proposer fills has to be budgeted against this rather than
/// discovered at it.
///
/// Stated here rather than in the transport because the caps that have
/// to fit inside it are stated here, and a bound nothing can be checked
/// against is not a bound.
pub const MAX_WIRE_MESSAGE_BYTES: usize = 10 * 1024 * 1024;

/// The bytes one transaction fetch response, or one outbound gossip
/// batch, carries between its transactions.
///
/// A response answers by hash, so the requester cannot know what it
/// asked for weighs; the responder stops filling at this budget and the
/// rest is asked for again. Sized so a batch ending on a maximal
/// envelope still encodes under the frame that carries it, which would
/// otherwise drop the whole message.
pub const MAX_FETCH_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

const _: () = assert!(
    MAX_FETCH_RESPONSE_BYTES + MAX_ENVELOPE_BYTES < MAX_WIRE_MESSAGE_BYTES,
    "a response filled to its budget plus the envelope that overran it fits the frame"
);

/// Hard cap on the number of live transactions any single block can carry.
///
/// Bounds the `tx_hashes` array in [`BlockManifest`](crate::BlockManifest),
/// the `transactions` array inside [`Block`](crate::Block), the
/// `tx_outcomes` array inside any one
/// [`ExecutionCertificate`](crate::ExecutionCertificate) for a tick from
/// this block, and the `transactions` (per-tx state-entry sets) inside
/// any one [`Provisions`](crate::Provisions) batch sourced from this
/// block.
pub const MAX_TXS_PER_BLOCK: usize = 4_096;

/// Hard cap on the sweepable cells one block's transactions may create
/// between them.
///
/// A sweepable cell is state the chain must carry until a sweep retires
/// it, so what bounds the resident population is the pair of rates: how
/// fast cells are created and how fast they are removed. Removal is
/// capped by [`MAX_SWEEP_PER_BLOCK`], and a creation rate above that cap
/// is a backlog that grows for as long as the load lasts. Capping only
/// the removal side would leave a sweep that bounds ordinary operation
/// and not the peak, which is not a bound.
///
/// The rates bound the backlog; what sets the resident *level* is how
/// long each family's cells live, and the two are independent. A cell
/// created here is retired one grace past the window it was derived
/// from, so the population a family contributes is this cap times its
/// grace measured in transaction windows — about one for the nullifier
/// and the committed cell, which take the default artifact grace, and
/// about twelve for the crossing family, whose claim cell has to stay
/// readable for the whole terminal evidence span or an inherited record
/// becomes one nobody can dispose of. So the crossing family dominates
/// the resident set by roughly an order of magnitude over the other two,
/// even though the committed cell is the one every transaction writes,
/// by choice, and none of that reaches the rates: the cap rationed here
/// is family-blind and per block, so a longer grace moves the level and
/// leaves what a block may create and remove exactly where it was.
///
/// Three families are sweepable and share that capacity — the nullifier,
/// the escrow claim (a reclaim's included) and the committed-transaction
/// cell a shard writes for every transaction it commits — because the
/// removal capacity they draw on is one capacity. A budget per family would cost throughput as well as
/// counters: a block could be invalid on one family's peak while the
/// shared walk had room.
///
/// The count has a fourth term that is not one of them. An escrow record
/// is a balance, retired by whoever consumes it and reachable by no
/// clock, so no sweep removes it and it draws on none of the capacity
/// this cap rations. It is counted anyway, and counting it only tightens
/// the ceiling on the three: the alternative is a figure whose slack
/// depends on how many of a block's edges cross.
///
/// Counted per shard, since that is where a cell lands and where the
/// sweep that retires it runs: a transaction's kernel cells whose owner
/// the shard holds, plus its committed cell, which every shard writes
/// for every transaction it commits. Sized at five times
/// [`MAX_TXS_PER_BLOCK`] so a full block of any shape the corpus
/// produces stays admissible on its busiest shard — every transaction
/// carries its committed cell and its own intent's nullifier, so a
/// transfer's payer writes those and the record, three; a swap's caller
/// adds the claim of what the venue issued, four; a liquidity provider
/// paying two resources writes two records and one claim beside them,
/// five. A bound subintent adds its own nullifier on its signer's shard,
/// so a subintent-heavy block packs fewer transactions, which is the
/// trade the figure made when nullifiers were the only family. Nothing
/// else in the block budget reaches this: a nullifier costs its
/// transaction a footprint unit and a signature, so the work budget
/// admits thirty-two of them per transaction and the creation ceiling
/// would otherwise sit two orders of magnitude above any removal count a
/// block can carry.
pub const MAX_SWEEPABLE_CREATED_PER_BLOCK: usize = 5 * MAX_TXS_PER_BLOCK;

/// Hard cap on the cells one block's sweep may remove.
///
/// A count and not a priced term: removals earn no fee because they are
/// not optional, and nothing is in flight for them — they resolve inside
/// the block that states them, so they never enter
/// [`MAX_UNSETTLED_TXS`]. That is the same trade the frontier's mandatory
/// advance makes, and it is why a proposer cannot decline to sweep in
/// order to keep block space for what does pay.
///
/// One walk over the three sweepable families, in key order: the bucket
/// leads every sweepable cell's local key, so a block's removals are one
/// contiguous range whatever families they mix, and the cap is on the
/// range rather than on any family's share of it.
///
/// Twice the creation cap, so a backlog drains rather than holding
/// station: a shard that fell behind under peak load catches up in
/// bounded time once the load stops, and one running at the creation cap
/// still removes what it creates with room to spare. The margin is also
/// what carries the one family member no block budgets at creation — a
/// reclaim's claim is written where the reclaim runs, one per record and
/// never beside the record's own claim, so it adds at most the record's
/// own rate to what the sweep must retire.
pub const MAX_SWEEP_PER_BLOCK: usize = 2 * MAX_SWEEPABLE_CREATED_PER_BLOCK;

/// The removal cap must outrun the creation cap, or the resident
/// population is bounded by nothing.
const _: () = assert!(
    MAX_SWEEP_PER_BLOCK >= 2 * MAX_SWEEPABLE_CREATED_PER_BLOCK,
    "a sweep must drain a backlog faster than a block can form one",
);

/// Whether a block whose transactions create `sweepable` cells between
/// them is one a validator may vote for.
///
/// On the block's own content, like every other content limit here, so a
/// validator reaches the verdict with no history behind it.
#[must_use]
pub const fn sweep_admits_block(sweepable: usize) -> bool {
    sweepable <= MAX_SWEEPABLE_CREATED_PER_BLOCK
}

/// Hard cap on the transactions a block's
/// [`AbandonmentRecord`](crate::AbandonmentRecord) records may name between
/// them.
///
/// A record answers for the transactions this chain still owes an outcome
/// for that a counterpart can never settle, and how many that can be is
/// what [`MAX_UNSETTLED_TXS`] already bounds — a transaction is only owed
/// while its place in the drain stands. So the ceiling is the drain's own
/// bound rather than a figure of its own, and a counterpart with more
/// outstanding than one block will carry is answered over several, each
/// record standing alone.
///
/// The bound is on the block rather than on any one record, because the
/// drain is one budget shared across every counterpart the block answers
/// for. It doubles as each record's own decode cap, since a single
/// counterpart can hold the whole of it — but that cap alone would let a
/// block carry the budget once per record, which is why the sum is
/// checked as well.
pub const MAX_UNSETTLED_PER_BLOCK: usize = 3 * MAX_TXS_PER_BLOCK;

/// Hard cap on the owner prefixes one transaction's routing names.
///
/// A wire bound on the reach a record restates, and the only structural
/// one there is: a prefix enters a transaction's routing through a
/// declared key, and a declared key costs its owner and its local half
/// inside the call body, so the body's own cap divides. Every real
/// transaction sits orders below it — a transfer names two, a route
/// half a dozen — and what the bound is for is that a decoder allocates
/// against an envelope a sender actually paid for rather than against a
/// length it claims.
pub const MAX_PREFIXES_PER_TX: usize =
    MAX_CALL_BYTES / (size_of::<Address>() + size_of::<LocalKey>());

/// Cap on the number of shards a block can name as provision targets, at
/// decode time.
///
/// A block can export provisions to at most `num_shards - 1` others. Real
/// deployments run far below this cap; it exists so a peer can't claim a
/// huge target map and force the decoder to build millions of entries
/// before the first frame check fires.
pub const MAX_PROVISION_TARGET_SHARDS: usize = 1_024;

/// Cap on the number of finalized transactions a proposer includes in a
/// single block, summed across all finalizations.
///
/// Truncation is a suffix of the order the proposer offers, which is the
/// order the ticks executed in — a tick settling ahead of one it shares a
/// cell with reverts a committed write, so nothing here may reorder to
/// fit. Also serves as the outer-`Vec<Finalization>` decode bound: every
/// tick's local EC carries at least one outcome in practice, so the count
/// of finalizations a block can carry is implicitly bounded by this
/// same cap.
pub const MAX_FINALIZED_TX_PER_BLOCK: usize = 8_192;

/// Cap on the things one query asks a counterpart to prove.
///
/// Bounds the response, whose per-entry cost is a merkle path rather
/// than a hash. Two questions share it, because a proof costs the same
/// whichever of them asked: the transactions a successor asks a
/// predecessor about, and the substate keys a leg's probe asks a
/// counterpart to prove present or absent — one probe asks about one
/// transaction's cell, so the two are the same size of question.
///
/// Each population is small by construction. A successor asks only about
/// transactions whose validity window opened before its origin, and only
/// until the chain outlives that origin by `MAX_VALIDITY_RANGE`; a leg
/// asks only about the crossings it issued. Anything with more than this
/// outstanding asks across several requests.
pub const MAX_PROOFS_PER_QUERY: usize = 256;

/// Hard cap on the number of provision batches any single block can carry.
///
/// A [`Provisions`](crate::Provisions) batch is keyed on `(source_shard,
/// target_shard, source_block_height)`. The count per local block scales
/// with the number of remote shards we depend on for cross-shard work
/// and the recent source-block-heights we still need state from. Sized
/// for small-to-mid-shard topologies; widening the topology may require
/// revisiting.
pub const MAX_PROVISIONS_PER_BLOCK: usize = 256;
/// The most leaves one cells query may be answered over, keys and
/// range entries together.
///
/// Every other bound on a declaration's reads is the transaction's, and
/// this request carries no transaction: it is asked on a preview's
/// behalf, before anything is signed, so a `CellRange`'s `cap` is
/// whatever the asker wrote and a server trusting it would walk whole
/// collections and build a multiproof over every leaf in them.
///
/// Two ceilings meet here and the lower binds. What a declaration could
/// legitimately reach is one transaction's whole read budget spent on
/// the narrowest leaf there is. What an *answer* can carry is
/// [`MAX_PROOF_CLAIMS`]: a multiproof over more leaves than that is
/// refused by the asker's own decoder, so a query above it buys a walk
/// whose proof can never be read, and refusing it early is the only
/// arm that spends nothing.
///
/// A query past the bound is refused rather than truncated. A short
/// answer would read back as a collection holding less than it does,
/// and a preview is the one thing that must not be quietly wrong.
/// The leaves alone: the siblings a proof of them needs are roughly this
/// times the tree's depth, which moves with the tree and so cannot be
/// bounded here. `generate_proof` holds the built proof to
/// `MAX_PROOF_SIBLINGS` instead, and a query whose proof would run past
/// it is answered as unprovable rather than with bytes the asker's own
/// decoder refuses.
pub const MAX_CELLS_PER_QUERY: u64 = {
    let by_declaration = MAX_TX_READ_BYTES / AMOUNT_CELL_BYTES as u64;
    let by_proof = MAX_PROOF_CLAIMS as u64;
    if by_proof < by_declaration {
        by_proof
    } else {
        by_declaration
    }
};

/// The most bytes of cell and entry values one cells answer may carry.
///
/// [`MAX_CELLS_PER_QUERY`] bounds the leaves and says nothing about what
/// they hold: a leaf runs to `MAX_SLOT_WIDTH`, so the leaf cap alone
/// admits an answer two orders of magnitude past the frame that would
/// have to carry it. The transports drop an oversize message rather
/// than truncating it, so a server that could build one would do the
/// whole walk and the proof for an answer nobody receives.
///
/// Spent across the whole answer and refused past, for the reason the
/// leaf cap is.
pub const MAX_CELLS_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Bytes a cells answer costs before its values: the multiproof over
/// its leaves, and the certified header, framing and keys around it.
const CELLS_ANSWER_FIXED_BYTES: usize = MAX_MERKLE_PROOF_LEN + 64 * 1024;

/// INV-WIRE-2: a cells answer with its values at their budget and its
/// proof at the decoder's cap still fits the frame that carries it.
const _: () = assert!(MAX_CELLS_RESPONSE_BYTES + CELLS_ANSWER_FIXED_BYTES < MAX_WIRE_MESSAGE_BYTES);

/// Hard cap on the state claims a block can carry.
///
/// One claim answers one fetch against one counterpart height; the
/// proposer offers what its own fetches read and the rest waits a
/// block. This bounds the section's bytes, and nothing else: the vote
/// fence withholds the vote on the whole block, so a single claim no
/// voter can check already couples every transaction beside it to a
/// counterpart's silence, and no cap above one changes that. What
/// bounds the coupling is the round timer, which prices a block held
/// at the fence at the ordinary timeout rather than the progress
/// window — see `has_own_work_at_round` in `hyperscale-shard`.
pub const MAX_STATE_CLAIMS_PER_BLOCK: usize = 256;

/// Byte budget the abandonment records of one block share.
///
/// The one section a block carries verbatim whose per-item cost varies:
/// a name is 128 bytes plus its reach, and a record's reach runs from a
/// transfer's two routes to a route's dozens. So a count cannot bound
/// it — [`MAX_UNSETTLED_PER_BLOCK`] names at their widest run past the
/// whole frame — and a proposer spends this instead, leaving the
/// remainder to the next block. Nothing is lost by stopping: a name a
/// record does not carry stays uncovered and is offered again.
///
/// Sized as the share of [`MAX_WIRE_MESSAGE_BYTES`] the assertion below
/// leaves for it. At the narrowest reach it still carries some eight
/// thousand names a block, several times the rate any drain can open
/// them at.
pub const MAX_PROPOSAL_EVIDENCE_BYTES: usize = 1024 * 1024;

/// Whether a block may still carry records weighing `weight` between
/// them.
///
/// The one reading of the budget, so the composer that fills the section
/// and the admission that checks it stop at the same place.
#[must_use]
pub const fn evidence_admits_block(weight: usize) -> bool {
    weight <= MAX_PROPOSAL_EVIDENCE_BYTES
}

/// Bytes one [`AbandonmentRecord`](crate::AbandonmentRecord) costs
/// before the names it carries.
pub const ABANDONMENT_RECORD_BYTES: usize = 32;

/// Bytes one [`UnsettledTx`](crate::UnsettledTx) costs before its reach.
pub const UNSETTLED_TX_BYTES: usize = 160;

/// Bytes one [`RoutePrefix`](crate::RoutePrefix) of a name's reach
/// costs.
pub const ROUTE_PREFIX_BYTES: usize = size_of::<RoutePrefix>();

/// Bytes one [`StateClaim`](crate::StateClaim) costs before its cells.
const STATE_CLAIM_BYTES: usize = 64;

/// Bytes one cell of a claim costs: the key and the reading of it.
const STATE_CLAIM_CELL_BYTES: usize = 82;

/// Bytes a hash-only entry of a manifest costs.
const HASH_BYTES: usize = 32;

/// Bytes the parts of a proposal that carry no capped list cost between
/// them: the header, the QC, the witness sources and the framing.
const PROPOSAL_FIXED_BYTES: usize = 64 * 1024;

/// The widest a proposal can encode: every section at its own cap, and
/// the record section at its byte budget.
///
/// The per-item figures above are upper bounds on the real encoding,
/// which `wire_budget.rs` holds them to by encoding a maximal value of
/// each and measuring it. Without that this assertion would only be
/// arithmetic over guesses.
const MAX_PROPOSAL_BYTES: usize = PROPOSAL_FIXED_BYTES
    + MAX_TXS_PER_BLOCK * HASH_BYTES
    + MAX_FINALIZED_TX_PER_BLOCK * HASH_BYTES
    + MAX_PROVISIONS_PER_BLOCK * HASH_BYTES
    + MAX_PROPOSAL_EVIDENCE_BYTES
    + MAX_STATE_CLAIMS_PER_BLOCK
        * (STATE_CLAIM_BYTES + MAX_PROOFS_PER_QUERY * STATE_CLAIM_CELL_BYTES);

/// INV-WIRE-1: a proposal every section of which is at its cap still
/// fits the frame that carries it. The transports drop an oversize
/// message rather than truncating it, so a proposer that could build one
/// would lose the round and lose it again on every block of that shape.
const _: () = assert!(MAX_PROPOSAL_BYTES < MAX_WIRE_MESSAGE_BYTES);

/// How many transactions a shard's chain may hold committed and
/// unsettled at once: a full pipeline of blocks — commit, execute,
/// certify — each at the wire cap.
///
/// The packing bound: a proposer adds transactions only while the count
/// the parent header carries stays under this, so a shard that is not
/// settling admits less until it does. A count and not a weight, because
/// every block is already capped per dimension on its own content, so
/// what a full pipeline can owe in any dimension is at most three block
/// caps by construction — and no arithmetic a price change could move.
///
/// A block carrying transactions is valid only if the total it leaves is
/// under this, so a chain of valid blocks never owes more than the
/// budget. A block carrying none is exempt whatever the total reads:
/// those are the blocks that carry the certificates the drain retreats
/// on, and refusing them would leave a chain that somehow sat above the
/// budget no way back down.
///
/// The total advances on commit and retreats when a certificate resolves
/// the transaction, whichever verdict it carries. One still unresolved at
/// its own deadline is certified aborted at the price its block took —
/// unless a certificate of the shard's own already covers it, in which
/// case a counterpart could have settled against that certificate, and
/// only that counterpart's departure makes the abort admissible. A
/// straddler waiting on a counterpart that never leaves holds its place
/// for as long as it waits.
pub const MAX_UNSETTLED_TXS: u64 = MAX_UNSETTLED_PER_BLOCK as u64;

/// Whether a block carrying `tx_count` transactions, and leaving the
/// drain holding `in_flight`, is one a validator may vote for.
///
/// `in_flight` is what the block leaves owing, not what it inherited, so
/// the bound is on the level a block produces: one that would carry the
/// drain past the budget is refused, and a chain whose blocks all pass
/// this never exceeds it.
///
/// A block that adds nothing is exempt from the level entirely. Those are
/// the blocks that carry the certificates the drain retreats on, so
/// refusing them would be refusing the only way back under.
#[must_use]
pub const fn drain_admits_block(in_flight: TxsInFlight, tx_count: usize) -> bool {
    tx_count == 0 || in_flight.inner() <= MAX_UNSETTLED_TXS
}

/// The fuel one block's transactions may declare between them: an
/// execution window of 125 ms on four cores at 2 G fuel/s.
pub const MAX_BLOCK_COMPUTE: u64 = 1_000_000_000;

/// The bytes one block's transactions may declare read off the store
/// between them: the window's share of a warm solid-state store under range reads,
/// taken at a third of nominal.
pub const MAX_BLOCK_READ_BYTES: u64 = 16 * 1024 * 1024;

/// The bytes one block's transactions may declare written between them.
///
/// Counted in the units `write_bytes` is denominated in, which carry a
/// per-leaf floor: a written leaf costs its path reads before any of its
/// own bytes, so the quantity a block spends is leaves far more than it
/// is bytes. At the floor, this window's share is about eight thousand
/// leaves, and a block of tiny cells reaches the cap at roughly that
/// many rather than at the hundreds of thousands a raw byte count would
/// have admitted.
///
/// Raised fourfold when the floor landed, and not a loosening: the old
/// figure counted a quantity nothing spends, so a block at it was
/// seconds of write work against a 125 ms window.
pub const MAX_BLOCK_WRITE_BYTES: u64 = 16 * 1024 * 1024;

/// The footprint one block's transactions may declare between them.
///
/// Footprint prices exclusion, which no physical rate bounds, so this
/// is sized against the corpus rather than derived: a transfer declares
/// a few dozen units and a book sweep some hundreds, and a full block of
/// either fits.
pub const MAX_BLOCK_FOOTPRINT: u64 = 256 * MAX_TXS_PER_BLOCK as u64;

/// The bytes one block's transactions may ask every validator to retain
/// between them: a validator's unique link share after gossip fanout,
/// over the blocks a second holds.
pub const MAX_BLOCK_RETENTION_BYTES: u64 = 4 * 1024 * 1024;

/// Every block cap as one vector, judged the way the sweep cap is: on
/// the block's own content, over each transaction's local share, so a
/// validator reaches the verdict with no history behind it.
pub const BLOCK_CAPS: DeclaredWork = DeclaredWork {
    compute: MAX_BLOCK_COMPUTE,
    read_bytes: MAX_BLOCK_READ_BYTES,
    write_bytes: MAX_BLOCK_WRITE_BYTES,
    footprint: MAX_BLOCK_FOOTPRINT,
    retention: MAX_BLOCK_RETENTION_BYTES,
};

/// Whether a block whose transactions declare `work` between them, over
/// their shares on the judging shard, is one a validator may vote for.
///
/// The one reading of the caps, so the proposer that fills a block and
/// the admission that checks it stop at the same place.
#[must_use]
pub const fn budget_admits_block(work: &DeclaredWork) -> bool {
    work.fits(&BLOCK_CAPS)
}

/// The bytes one transaction may declare read off the store: a
/// sixteenth of the block, so one envelope cannot own it.
pub const MAX_TX_READ_BYTES: u64 = MAX_BLOCK_READ_BYTES / 16;

/// The bytes one transaction may declare written: an eighth of the
/// block, on [`MAX_TX_READ_BYTES`]'s terms.
pub const MAX_TX_WRITE_BYTES: u64 = MAX_BLOCK_WRITE_BYTES / 8;

/// The footprint one transaction may declare: a sixteenth of the block,
/// on [`MAX_TX_READ_BYTES`]'s terms.
pub const MAX_TX_FOOTPRINT: u64 = MAX_BLOCK_FOOTPRINT / 16;

/// The most one transaction may declare in any dimension.
///
/// Compute and retention are sums of their own parts rather than
/// figures of their own, because the derivation builds them from those
/// same parts: a cap written independently would drift the first time a
/// term was added to one side and not the other, and the drift would
/// read as a transaction the protocol refuses for declaring exactly
/// what it is allowed to.
pub const TX_CAPS: DeclaredWork = DeclaredWork {
    compute: MAX_GAS_LIMIT + MAX_TX_SIGNATURE_COMPUTE,
    read_bytes: MAX_TX_READ_BYTES,
    write_bytes: MAX_TX_WRITE_BYTES,
    footprint: MAX_TX_FOOTPRINT,
    retention: MAX_ENVELOPE_BYTES as u64
        + MAX_TX_WRITE_BYTES
        + MAX_TX_SIGNATURE_BYTES
        + MAX_EVENT_BYTES_PER_TX as u64,
};

/// The most verifying one envelope's attestations can cost: every one
/// the transaction may carry, at the slowest registered scheme.
const MAX_TX_SIGNATURE_COMPUTE: u64 = MAX_TX_ATTESTATIONS as u64 * 3 * VERIFY_WEIGHT;

/// The auth material those same attestations carry, which retention
/// holds beside the envelope that carries them.
const MAX_TX_SIGNATURE_BYTES: u64 =
    MAX_TX_ATTESTATIONS as u64 * (MAX_KEY_BYTES as u64 + MAX_SIG_BYTES as u64);

/// Whether a transaction declaring `work` is one a block may carry at
/// all, whatever else it carries.
#[must_use]
pub const fn caps_admit_transaction(work: &DeclaredWork) -> bool {
    work.fits(&TX_CAPS)
}

/// A full block of transactions each at its own ceiling would not fit
/// the block in every dimension — that is what the per-block caps are
/// for — but one transaction at its ceiling always fits an empty block,
/// or the ceiling would be a figure nothing could ever carry.
const _: () = assert!(TX_CAPS.fits(&BLOCK_CAPS));

/// Hard cap on `header.round() - header.parent_qc().round()` — how many
/// skipped consensus rounds a single block may span.
///
/// Via the shard pacemaker's ceiling (`high_qc.round + MAX_ROUND_GAP`), it
/// also caps how far the view can ever run past certified progress.
///
/// Every validator re-derives one `MissedProposal` beacon-witness leaf per
/// skipped round when verifying and committing a block (see
/// [`missed_proposals_since_prev_commit`](crate::missed_proposals_since_prev_commit)),
/// so an unbounded round gap is an unbounded per-block allocation. The
/// proposer for `(height, round)` rotates with `round`, so a Byzantine
/// validator is the deterministic proposer for arbitrarily large rounds:
/// without this cap, one self-named header at `round ≈ u64::MAX` forces
/// every honest validator to materialize a `Vec` of that length.
///
/// The value is the shard's stall runway. Round gaps accrue only through
/// 2f+1 timeout quorums (Byzantine nodes alone can't advance the pacemaker),
/// each costing one view-change timeout — 30s at the backoff cap — so the
/// cap is reached after roughly `100_000` × 30s ≈ 35 days of continuous
/// certification stall, at which point the view parks at the ceiling and the
/// shard needs operator recovery. The wire cap and the pacemaker ceiling
/// must be the same constant: the view must never enter a round where no
/// proposal extending an adoptable QC would be wire-valid.
pub const MAX_ROUND_GAP: u64 = 100_000;

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::DeclaredWork;

    use super::{
        BLOCK_CAPS, MAX_SWEEPABLE_CREATED_PER_BLOCK, MAX_UNSETTLED_TXS, TX_CAPS, TxsInFlight,
        budget_admits_block, caps_admit_transaction, drain_admits_block, sweep_admits_block,
    };

    /// The bound bites on the level a block leaves: one carrying
    /// transactions is refused the moment its own total clears the
    /// budget, and admitted right up to it.
    #[test]
    fn a_block_is_refused_for_the_total_it_leaves() {
        let over = TxsInFlight::new(MAX_UNSETTLED_TXS + 1);
        assert!(!drain_admits_block(over, 1));
        assert!(drain_admits_block(TxsInFlight::new(MAX_UNSETTLED_TXS), 1));
    }

    /// Each cap bites in its own dimension: a block at every cap is
    /// admitted, one byte over any one of them is refused, and a
    /// transaction at its own ceilings fits an empty block.
    #[test]
    fn every_dimension_is_capped_on_its_own() {
        assert!(budget_admits_block(&BLOCK_CAPS));
        assert!(budget_admits_block(&DeclaredWork::ZERO));
        let over = [
            DeclaredWork {
                compute: BLOCK_CAPS.compute + 1,
                ..DeclaredWork::ZERO
            },
            DeclaredWork {
                read_bytes: BLOCK_CAPS.read_bytes + 1,
                ..DeclaredWork::ZERO
            },
            DeclaredWork {
                write_bytes: BLOCK_CAPS.write_bytes + 1,
                ..DeclaredWork::ZERO
            },
            DeclaredWork {
                footprint: BLOCK_CAPS.footprint + 1,
                ..DeclaredWork::ZERO
            },
            DeclaredWork {
                retention: BLOCK_CAPS.retention + 1,
                ..DeclaredWork::ZERO
            },
        ];
        for work in over {
            assert!(!budget_admits_block(&work), "{work:?}");
        }
        assert!(caps_admit_transaction(&TX_CAPS));
        assert!(!caps_admit_transaction(&DeclaredWork {
            read_bytes: TX_CAPS.read_bytes + 1,
            ..DeclaredWork::ZERO
        }));
    }

    /// And it never bites on a block that adds nothing. Those carry the
    /// certificates that release the drain, so refusing them would leave a
    /// chain that touched the ceiling unable to come back under it.
    #[test]
    fn a_block_adding_nothing_is_admitted_at_any_total() {
        assert!(drain_admits_block(TxsInFlight::new(u64::MAX), 0));
    }

    /// The creation cap bites at the cell. That it is outrun by the
    /// removal cap — the pair being what bounds the resident population,
    /// where either alone bounds one side of it — is the const assert's
    /// business rather than this one's.
    #[test]
    fn a_block_may_create_up_to_the_cap_and_no_more() {
        assert!(sweep_admits_block(MAX_SWEEPABLE_CREATED_PER_BLOCK));
        assert!(!sweep_admits_block(MAX_SWEEPABLE_CREATED_PER_BLOCK + 1));
        assert!(sweep_admits_block(0));
    }
}
