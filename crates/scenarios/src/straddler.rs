//! Straddler atomicity scenarios.
//!
//! A *straddler* is a cross-shard tick whose source side commits on a shard that
//! terminates at a reshape boundary. The surviving counterpart must read the
//! terminating shard's beacon-attested settled set and settle the straddler only
//! when the terminating shard settled it by its terminal block — never one-sided,
//! and never holding a permanent lock on the ones it didn't.

use std::fmt::Write;
use std::sync::Arc;

use hyperscale_effects_bridge::vm_statics::crossing_records;
use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_types::{
    BlockHeight, Deadline, Ed25519PrivateKey, Epoch, PrincipalAddr, ShardId, SubstateKey,
    TransactionDecision, TransactionStatus, TxHash, WeightedTimestamp, Window,
};

use crate::reshape::split_lifecycle;
use crate::support::conservation::{Charges, World};
use crate::support::query::{
    anchored_genesis_height, beacon_epoch, committee_size, declared_price, held, split_admitted,
    vault_balance,
};
use crate::support::tx::{
    MERGE_STRADDLER_LEFT, MERGE_STRADDLER_RIGHT, MERGE_STRADDLER_SURVIVOR, STRADDLER_SPLITTER,
    STRADDLER_SURVIVOR, build_reshape_threshold_vote_tx, build_transfer_tx, merge_straddler_setup,
    pool_operator, split_issuer_straddler_setup, split_straddler_setup, stdlib_flash_bytes,
    validity_around,
};
use crate::support::wait::{
    await_anchor_seeded, await_beacon_epoch, await_merge_keeper_count, await_root_matches_anchor,
    await_serves, await_split_admitted, await_tx_terminal,
};
use crate::support::{Cluster, FaultHandle, FaultableCluster, epochs};

/// Cut every path by which `shard`'s committee obtains `peer_shard`'s execution
/// certificate, so a cross-shard tick the two share cannot finalize on `shard`'s
/// side.
///
/// Fault rules gate pushes (gossip) and request legs, never response legs, so EC
/// intake is cut on the push and on the pulls, with the correct direction per
/// leg: `peer_shard` pushes its EC by gossip (`execution.cert.batch`), and
/// `shard` pulls the EC and the finalization that bundles it
/// (`execution_cert.request`, `finalization.request`). Provisions and headers
/// still flow, so `shard` still executes the tick and produces its own EC; it
/// just never receives `peer_shard`'s.
///
/// Faithful only with disjoint committees — if the two shards share a host, its
/// co-hosted vnodes hand the EC across in-process, which no network rule
/// intercepts.
#[must_use]
pub fn isolate_ec_intake(
    c: &mut impl FaultableCluster,
    shard: ShardId,
    peer_shard: ShardId,
) -> FaultHandle {
    let shard_hosts = c.committee_hosts(shard);
    let peer_hosts = c.committee_hosts(peer_shard);
    let handles = [
        c.drop_type_between(&peer_hosts, &shard_hosts, "execution.cert.batch"),
        c.drop_type_between(&shard_hosts, &peer_hosts, "execution_cert.request"),
        c.drop_type_between(&shard_hosts, &peer_hosts, "finalization.request"),
    ];
    FaultHandle::new(move || handles.iter().map(FaultHandle::fired).sum())
}

/// Epochs of lead the threshold vote carries beyond the fold budget, covering
/// the tally read at `activate_at - 1` plus scheduling slack.
const VOTE_ACTIVATE_LEAD_BASE: u64 = 3;

/// Epochs of lead before the threshold vote activates: the harness's vote
/// fold budget expressed in epochs, plus the base. Unlike
/// `vote_reshape_threshold`'s retry loop, this vote is cast once — the
/// activation epoch anchors the straddler boundary choreography — so the lead
/// must cover the harness's cast-to-fold latency up front.
const fn vote_activate_lead(fold_budget_ms: u64, epoch_ms: u64) -> u64 {
    VOTE_ACTIVATE_LEAD_BASE + fold_budget_ms.div_ceil(epoch_ms)
}

/// Reshape `split_bytes` the vote installs after the grow: between the
/// survivor's byte total and the splitter's, so only the heavier splitter
/// crosses and terminates while the survivor stays a live leaf.
///
/// Offset by the genesis package flash, which the survivor's half holds
/// beside its own ballast, while the splitter's ballast carries a fixed
/// lead over the flash — so the threshold sits between the two with
/// margins that hold as the stdlib grows, and the derived merge floor (an
/// eighth of it) stays below every live leaf, including the splitter's
/// own children once it splits.
pub fn straddler_split_bytes() -> u64 {
    split_bytes_over(stdlib_flash_bytes())
}

/// The voted-down threshold for a pair whose survivor holds a genesis
/// flash of `flash` bytes beside its ballast, and whose splitter's
/// ballast leads the flash by a fixed margin.
pub const fn split_bytes_over(flash: u64) -> u64 {
    flash + 12_000
}

/// Verify a split straddler settles atomically across the reshape boundary.
///
/// Grows the root into two shards (the heavier `leaf(1,0)` splitter and the
/// lighter `leaf(1,1)` survivor), votes `split_bytes` down so only the splitter
/// crosses, then submits cross-shard transfers from the survivor into the
/// splitter spread across the splitter's grow — the earliest settle before its
/// terminal block, the latest name a splitter that has already terminated. After
/// the split the survivor must reach a terminal verdict on every straddler,
/// consistent with what the splitter settled: never applying one the splitter
/// never settled, never contradicting one it did, and aborting (not hanging) the
/// rest. Requires the [`split_straddler_setup`] genesis funding.
///
/// # Panics
///
/// Panics if the grow or split misses its budget, or the settled-transaction fence is
/// breached (a one-sided application, a mismatch, or a hung straddler).
pub fn split_straddler_atomic(c: &mut impl Cluster) {
    let run = split_straddler_run(c, |_| {});
    assert_fence_held(c, run.splitter, run.terminal_b, &run.probes);
    run.assert_conserved(c);
}

/// Verify a split straddler settles atomically when the terminating splitter is
/// isolated from the survivor's execution certificate.
///
/// The same choreography as [`split_straddler_atomic`], but with the splitter's
/// EC intake cut ([`isolate_ec_intake`]) once committees stabilize: provisions
/// still flow, so the splitter executes each straddler and produces its own EC,
/// but never receives the survivor's and so settles none. The pre-boundary
/// settlement fence must hold atomicity anyway — the survivor cannot finalize a
/// straddler naming the splitter while the splitter has an admitted terminating
/// reshape, so no straddler resolves one-sided.
///
/// Requires disjoint splitter/survivor committees (no shared host), or a
/// co-hosted vnode bridges the EC across in-process, which no network rule
/// intercepts. The simulation seats these via dedicated pool hosts.
///
/// # Panics
///
/// Panics if the choreography misses its budget or any straddler resolves
/// one-sided (the survivor applies one the splitter never settled).
pub fn split_straddler_ec_partition_atomic(c: &mut impl FaultableCluster) {
    let mut cut = None;
    let run = split_straddler_run(c, |c| {
        cut = Some(isolate_ec_intake(c, STRADDLER_SPLITTER, STRADDLER_SURVIVOR));
    });
    let cut = cut.expect("the fault seam runs before any straddler is submitted");
    let one_sided = straddler_one_sided_count(c, run.splitter, run.terminal_b, &run.probes);
    assert!(
        cut.fired() > 0,
        "the splitter's certificate intake must actually have been exercised and cut, or no \
         straddler was ever held one-sided to begin with",
    );
    assert_eq!(
        one_sided, 0,
        "the survivor applied {one_sided} straddler(s) one-sided the splitter never settled",
    );
    run.assert_conserved(c);
}

/// Grow the root into the splitter/survivor pair and vote the reshape
/// threshold down so only the heavier splitter crosses it and terminates.
///
/// The shared front half of every split-straddler choreography: on return the
/// splitter has an admitted split, the survivor has none, and both committees
/// are stable — the seam a fault probe keys a rule on.
///
/// # Panics
///
/// Panics if the grow misses its budget, the splitter fails to admit a split,
/// or the survivor admits one.
pub fn arm_splitter_termination<C: Cluster>(c: &mut C) {
    split_lifecycle(c);
    vote_splitter_down(c);
}

/// Vote the reshape threshold down on an already grown pair so only the
/// heavier splitter crosses it, and await its admission.
///
/// The second half of [`arm_splitter_termination`], for a cluster that
/// reached the pair some other way — a grow the harness drove itself, as
/// one born running a package does.
///
/// # Panics
///
/// Panics if either shard is unserved, the splitter fails to admit a
/// split, or the survivor admits one.
pub fn vote_splitter_down<C: Cluster>(c: &mut C) {
    vote_splitter_down_to(c, straddler_split_bytes());
}

/// [`vote_splitter_down`] to an explicit threshold, for a pair whose byte
/// bands a scenario sized itself.
///
/// # Panics
///
/// As [`vote_splitter_down`].
pub fn vote_splitter_down_to<C: Cluster>(c: &mut C, split_bytes: u64) {
    let splitter = STRADDLER_SPLITTER;
    let survivor = STRADDLER_SURVIVOR;
    cast_splitter_vote(c, split_bytes);
    assert!(
        await_split_admitted(c, splitter, epochs(20)),
        "only the over-threshold splitter must admit a split",
    );
    assert!(
        !split_admitted(c, survivor),
        "the under-threshold survivor must not split",
    );
}

/// Cast the vote that takes the threshold to `split_bytes`, below the
/// splitter's bytes, without waiting for the admission it leads to.
///
/// # Panics
///
/// Panics if either shard of the pair is unserved.
pub fn cast_splitter_vote<C: Cluster>(c: &mut C, split_bytes: u64) {
    assert!(
        c.serves_shard(STRADDLER_SPLITTER) && c.serves_shard(STRADDLER_SURVIVOR),
        "the grow must seat both the splitter and the survivor",
    );
    cast_threshold_vote(c, split_bytes);
}

/// Cast the vote that takes the threshold to `split_bytes`, on whatever
/// partition the world has, without waiting for the admission it leads
/// to.
///
/// # Panics
///
/// Panics if the beacon serves no epoch yet.
pub fn cast_threshold_vote<C: Cluster>(c: &mut C, split_bytes: u64) {
    let current = beacon_epoch(c).expect("post-grow beacon epoch");
    let state = c.beacon_state().expect("post-grow beacon state");
    let epoch_ms = state.chain_config.epoch_duration_ms;
    let vote = build_reshape_threshold_vote_tx(
        &pool_operator().0,
        &state.params,
        split_bytes,
        Epoch::new(current.inner() + vote_activate_lead(c.vote_fold_budget_ms(), epoch_ms)),
        validity_around(c.now()),
    );
    c.submit(Arc::new(vote));
}

/// What a straddler choreography leaves for its caller to judge: the
/// probes, the shard that terminated and its terminal block, and the
/// conservation ledger the run was opened over.
pub struct StraddlerRun {
    /// The probe hashes, in submission order.
    pub probes: Vec<TxHash>,
    /// The shard that terminated.
    pub splitter: ShardId,
    /// Its terminal block height.
    pub terminal_b: BlockHeight,
    world: World,
    charges: Charges,
}

impl StraddlerRun {
    /// Assert every straddler's payer and recipient hold between them what
    /// they started with, less the prices: a straddler the fence abandoned
    /// moved nothing and still paid, and one it settled moved its payment
    /// exactly once.
    pub fn assert_conserved<C: Cluster>(&self, c: &mut C) {
        self.world.assert_settles_within(
            c,
            &self.charges,
            epochs(8),
            "straddlers across a terminal",
        );
    }
}

/// Everything a setup's straddlers can reach: each leg's payer and
/// recipient. The ballast holds the byte skew and never spends.
fn straddler_world<C: Cluster>(
    c: &C,
    straddlers: &[(Ed25519PrivateKey, PrincipalAddr, PrincipalAddr)],
) -> World {
    World::open(
        c,
        *PROTOCOL_RESOURCE,
        straddlers
            .iter()
            .flat_map(|(_, from, to)| [from.address(), to.address()]),
        [],
    )
}

/// The split-straddler choreography, minus the terminal assertion.
///
/// Grows, votes the threshold down, submits settling then straddling ticks,
/// drives the split, and waits for every straddler to reach a terminal verdict.
/// Returns the probe hashes, the splitter shard, and its terminal block height
/// for the caller to judge. `before_settling` runs once after the split is
/// admitted (committees stable, splitter still live) and before the settling
/// ticks are submitted — the seam a fault probe uses to install a rule keyed on
/// the live committees.
///
/// # Panics
///
/// Panics if the grow or split misses its budget, or a straddler never reaches
/// a terminal verdict.
pub fn split_straddler_run<C: Cluster>(
    c: &mut C,
    mut before_settling: impl FnMut(&mut C),
) -> StraddlerRun {
    let splitter = STRADDLER_SPLITTER;
    let (child_left, child_right) = splitter.children();
    let setup = split_straddler_setup();

    arm_splitter_termination(c);

    let world = straddler_world(c, &setup.straddlers);
    let mut charges = Charges::default();
    let mut probes: Vec<TxHash> = Vec::new();

    // Fault-injection seam: committees are stable and the splitter is still
    // live, so a probe can key a rule on the live splitter/survivor committees
    // before any straddler EC crosses.
    before_settling(c);

    // Settling ticks: submitted while the splitter still commits real blocks, so
    // it finalizes them before its terminal cut — they settle atomically.
    let half = setup.straddlers.len() / 2;
    for (key, from, to) in setup.straddlers.iter().take(half) {
        probes.push(submit_straddler(c, &mut charges, key, *from, *to));
    }

    // Advance until the gate drains the splitter from `pending_reshapes`: the
    // settling ticks finalize on it in this window, and it then coasts to its
    // terminal crossing committing only empty blocks.
    assert!(
        c.run_until(epochs(14), |c| !split_admitted(c, splitter)),
        "the splitter's split must gate within budget",
    );

    // Straddling ticks: submitted all at once during the coast — the splitter is
    // still the active leaf, so the survivor provisions to it, but its empty
    // coast blocks settle nothing, leaving them in flight when it terminates.
    for (key, from, to) in setup.straddlers.iter().skip(half) {
        probes.push(submit_straddler(c, &mut charges, key, *from, *to));
    }

    // The split executes: both children seat and commit past genesis.
    assert!(
        await_serves(c, child_left, epochs(28)) && await_serves(c, child_right, epochs(28)),
        "both splitter children must be served within budget",
    );

    // The splitter's terminal block sits one below the children's genesis. The
    // children serve from the cut, ahead of the fold that publishes their
    // anchor, so the height only reads off the boundary once that fold lands.
    assert!(
        await_anchor_seeded(c, child_left, epochs(6)),
        "the beacon must compose the split children's anchor",
    );
    let terminal_b = anchored_genesis_height(c, child_left)
        .and_then(BlockHeight::prev)
        .expect("the children's seeded genesis pins the splitter's terminal block");

    // Every straddler must reach a terminal verdict on the survivor.
    for hash in &probes {
        let status = await_tx_terminal(c, *hash, epochs(10));
        assert!(
            matches!(status, Some(TransactionStatus::Completed(_))),
            "a straddler hung on the settled-transaction fence; status = {status:?}",
        );
    }

    StraddlerRun {
        probes,
        splitter,
        terminal_b,
        world,
        charges,
    }
}

/// A leg issued under a cut crossing bundle, with what the scenario
/// reading its fate needs.
struct CutLeg {
    hash: TxHash,
    price: u128,
    lapse: WeightedTimestamp,
    broadcast_dropped: FaultHandle,
    fetch_dropped: FaultHandle,
}

/// Cast the splitter's vote, wait out its activation epoch, cut both
/// channels a crossing bundle travels, and submit the transfer.
///
/// The vote goes first because it activates epochs later and the split
/// is admitted only after that; the leg goes in at the activation epoch,
/// while the splitter still owns its half of the transfer, so what the
/// cut carries is the splitter's own — a leg committed after the cut
/// names the successor from the start and asks nothing of an
/// inheritance. As late as that so the lapse falls past the cut, which
/// is what puts the proof on the successor.
fn issue_a_leg_under_a_cut_bundle<C: FaultableCluster>(
    c: &mut C,
    charges: &mut Charges,
    payer_key: &Ed25519PrivateKey,
    payer: PrincipalAddr,
    recipient: PrincipalAddr,
) -> CutLeg {
    let cast_at = beacon_epoch(c).expect("post-grow beacon epoch");
    let epoch_ms = c
        .beacon_state()
        .expect("post-grow beacon state")
        .chain_config
        .epoch_duration_ms;
    cast_splitter_vote(c, straddler_split_bytes());
    let activation = cast_at.inner() + vote_activate_lead(c.vote_fold_budget_ms(), epoch_ms);
    assert!(
        await_beacon_epoch(c, activation, epochs(8)),
        "the vote's activation epoch must open within budget",
    );
    let broadcast_dropped = c.drop_type("provisions.broadcast");
    let fetch_dropped = c.drop_type("provision.request");
    let validity = validity_around(c.now());
    let tx = build_transfer_tx(payer_key, payer, recipient, STRADDLER_PAYMENT, validity);
    let price = declared_price(c, &tx);
    let lapse = Window::Lapse.of(Deadline::of_transaction(&tx)).start;
    let hash = charges.submit(c, tx);
    CutLeg {
        hash,
        price,
        lapse,
        broadcast_dropped,
        fetch_dropped,
    }
}

/// A delivery cut off across its deliverer's split is reclaimed on the
/// successor's proof.
///
/// The cut-off delivery's shape with the delivering shard leaving part
/// way: the survivor's payer pays and issues the crossing while the
/// splitter is live, both channels the bundle travels are cut so no
/// chain ever claims it, and the splitter is voted down and terminates.
/// A departed chain supplies no header past the lapse, so the claim
/// cell is proved absent where its prefix sits by then — on the child
/// that inherited the recipient — and the payment comes back on that
/// proof. On a clock whose epochs outlast the lapse the splitter's own
/// header past it answers first; the reclaim lands either way.
///
/// # Panics
///
/// Panics if the survivor does not commit the leg before the vote, if
/// the leg does not accept alone, if the bundle channels are never
/// exercised, if the delivery lands on any chain, if the children are
/// not served within budget, if the payment is not back within the
/// reclaim's room, or if the world does not conserve.
pub fn a_delivery_is_reclaimed_when_its_deliverer_splits<C: FaultableCluster>(c: &mut C) {
    let splitter = STRADDLER_SPLITTER;
    let survivor = STRADDLER_SURVIVOR;
    let setup = split_straddler_setup();
    let (payer_key, payer, recipient) = &setup.straddlers[0];

    split_lifecycle(c);
    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        [payer.address(), recipient.address()],
        [],
    );
    let mut charges = Charges::default();
    let before = vault_balance(c, survivor, *payer);
    let recipient_before = held(c, recipient.address(), *PROTOCOL_RESOURCE);

    let CutLeg {
        hash,
        price,
        lapse,
        broadcast_dropped,
        fetch_dropped,
    } = issue_a_leg_under_a_cut_bundle(c, &mut charges, payer_key, *payer, *recipient);
    assert!(
        c.run_until(epochs(2), |c| c.chain_fate(survivor, hash).0.is_some()),
        "the survivor must commit the leg while the splitter is live",
    );
    assert!(
        !split_admitted(c, splitter),
        "the leg has to be committed while the splitter still owns the recipient's \
         prefix, and the split's admission is the conservative marker of that: \
         past the cut the delivery is the successor's from the start",
    );
    // Read before the admission is awaited: on a clock whose epochs
    // outlast the lapse the reclaim lands inside that wait, and the
    // payment would be back before it was seen to leave.
    let verdict = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            verdict,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the payer's leg settles alone and accepts; verdict = {verdict:?}",
    );
    assert!(
        c.run_until(epochs(4), |c| vault_balance(c, survivor, *payer)
            == before - STRADDLER_PAYMENT - price),
        "the leg pays the payment and the price",
    );
    assert!(
        await_split_admitted(c, splitter, epochs(20)),
        "only the over-threshold splitter must admit a split",
    );
    assert!(
        !split_admitted(c, survivor),
        "the under-threshold survivor must not split",
    );

    // The splitter terminates and its children seat with its cells, the
    // recipient's among them.
    let (child_left, child_right) = splitter.children();
    assert!(
        await_serves(c, child_left, epochs(28)) && await_serves(c, child_right, epochs(28)),
        "both splitter children must be served within budget",
    );

    // Past the lapse, with the cut standing the whole way: no chain that
    // ever held the recipient had a bundle to claim from.
    let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
    assert!(
        c.run_until(epochs(12), |c| clock(c) >= lapse),
        "the cut must stand past the lapse",
    );
    assert!(
        broadcast_dropped.fired() > 0 && fetch_dropped.fired() > 0,
        "both bundle channels must actually have been exercised and cut"
    );
    for shard in [splitter, child_left, child_right] {
        let fate = c.chain_fate(shard, hash).1.map(|(_, decision)| decision);
        assert!(
            fate != Some(TransactionDecision::Accept),
            "the delivery must never have landed while its bundle was cut off; {shard} reached \
             {fate:?}",
        );
    }

    // The reclaim: the successor's chain passes the lapse, the survivor
    // proves the claim cell absent there, and the payment comes back.
    // The price stays paid — the leg ran and burned it.
    assert!(
        c.run_until(epochs(10), |c| vault_balance(c, survivor, *payer)
            == before - price),
        "the payer must get its payment back once the lapse is proved on the successor; \
         holds {}",
        vault_balance(c, survivor, *payer),
    );
    assert_eq!(
        held(c, recipient.address(), *PROTOCOL_RESOURCE),
        recipient_before,
        "the recipient was never credited",
    );
    c.clear_drops();
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a delivery cut off across its deliverer's split",
    );
}

/// A record inherited across its issuer's split is decided by the
/// successor that holds it.
///
/// The mirror of [`a_delivery_is_reclaimed_when_its_deliverer_splits`]:
/// what the cut carries here is the crossing's *record*, not its
/// delivery. The splitter's payer pays and issues the crossing, both
/// channels the bundle travels are cut so the survivor never claims it,
/// and the splitter is then voted down and terminates. The record
/// passes to the child that inherits the payer's prefix, and that child
/// — holding a leaf and no body — decides it against the claim key the
/// leaf names, credits the payment back and deletes the record.
///
/// This is the case the terminal evidence span buys and the inherited
/// seat spends: the claim cell has to outlive the cut for the successor
/// to have anything to ask about, and the record has to carry its
/// consumer's claim for the successor to know what to ask.
///
/// # Panics
///
/// Panics if the splitter does not commit the leg before the vote, if
/// the leg does not accept alone, if the bundle channels are never
/// exercised, if the delivery lands on any chain, if the children are
/// not served within budget, if the payment is not back on the
/// inheriting child within the reclaim's room, or if the world does not
/// conserve.
pub fn a_record_is_decided_by_the_successor_when_its_issuer_splits<C: FaultableCluster>(c: &mut C) {
    let splitter = STRADDLER_SPLITTER;
    let survivor = STRADDLER_SURVIVOR;
    let setup = split_issuer_straddler_setup();
    let (payer_key, payer, recipient) = &setup.straddlers[0];

    split_lifecycle(c);
    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        [payer.address(), recipient.address()],
        [],
    );
    let mut charges = Charges::default();
    let before = vault_balance(c, splitter, *payer);
    let recipient_before = held(c, recipient.address(), *PROTOCOL_RESOURCE);

    let CutLeg {
        hash,
        price,
        lapse,
        broadcast_dropped,
        fetch_dropped,
    } = issue_a_leg_under_a_cut_bundle(c, &mut charges, payer_key, *payer, *recipient);
    assert!(
        c.run_until(epochs(2), |c| c.chain_fate(splitter, hash).0.is_some()),
        "the splitter must commit the leg while it still owns the payer's prefix",
    );
    assert!(
        !split_admitted(c, splitter),
        "the leg has to be committed before the cut, so the record it leaves is one \
         a successor inherits rather than one the splitter's own chain decides",
    );
    let verdict = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            verdict,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the payer's leg settles alone and accepts; verdict = {verdict:?}",
    );
    assert!(
        c.run_until(epochs(4), |c| vault_balance(c, splitter, *payer)
            == before - STRADDLER_PAYMENT - price),
        "the leg pays the payment and the price",
    );

    // The splitter terminates and its children seat with its cells — the
    // payer's among them, and the record beside it.
    assert!(
        await_split_admitted(c, splitter, epochs(20)),
        "only the over-threshold splitter must admit a split",
    );
    assert!(
        !split_admitted(c, survivor),
        "the under-threshold survivor must not split",
    );
    let (child_left, child_right) = splitter.children();
    assert!(
        await_serves(c, child_left, epochs(28)) && await_serves(c, child_right, epochs(28)),
        "both splitter children must be served within budget",
    );

    // Past the lapse with the cut standing: the survivor never had a
    // bundle to claim from, so its claim cell is absent and stays so.
    let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
    assert!(
        c.run_until(epochs(12), |c| clock(c) >= lapse),
        "the cut must stand past the lapse",
    );
    assert!(
        broadcast_dropped.fired() > 0 && fetch_dropped.fired() > 0,
        "both bundle channels must actually have been exercised and cut"
    );
    let fate = c.chain_fate(survivor, hash).1.map(|(_, decision)| decision);
    assert!(
        fate != Some(TransactionDecision::Accept),
        "the delivery must never have landed while its bundle was cut off; {survivor} reached \
         {fate:?}",
    );

    // The successor decides what it inherited: the payment comes back on
    // whichever child took the payer's prefix. The price stays paid —
    // the leg ran and burned it.
    let inheritor = |c: &C| {
        [child_left, child_right]
            .into_iter()
            .map(|child| vault_balance(c, child, *payer))
            .max()
            .expect("two children")
    };
    assert!(
        c.run_until(epochs(10), |c| inheritor(c) == before - price),
        "the successor must credit the payment back once the claim is proved absent; \
         children hold {}",
        inheritor(c),
    );
    assert_eq!(
        held(c, recipient.address(), *PROTOCOL_RESOURCE),
        recipient_before,
        "the recipient was never credited",
    );
    c.clear_drops();
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a record inherited across its issuer's split",
    );
}

/// Verify a surviving sibling's second-generation split seats correctly.
///
/// Composes [`split_straddler_atomic`] (grow → vote the threshold down so only
/// the splitter crosses → settled-transaction fence), then layers the seating outcome:
/// the splitter retires into two full-strength child committees while the survivor
/// keeps its own, each child's committed root reproduces the beacon-composed
/// anchor, and both children commit a real block past their seeded genesis.
/// Requires the [`split_straddler_setup`] genesis funding on a config grown from a
/// single root.
///
/// # Panics
///
/// Panics if the lifecycle misses its budget, a committee is under strength, the
/// splitter fails to retire, a child root diverges from the anchor, or a child
/// stalls at its seeded genesis.
pub fn surviving_sibling_split_seats_full_committees(c: &mut impl Cluster) {
    assert!(
        await_beacon_epoch(c, 1, epochs(6)),
        "the beacon must fold before the grow so the genesis committee strength is known",
    );
    let strength = committee_size(c, ShardId::ROOT).expect("genesis seats the root committee");

    split_straddler_atomic(c);

    let splitter = STRADDLER_SPLITTER;
    let survivor = STRADDLER_SURVIVOR;
    let (child_left, child_right) = splitter.children();
    assert!(
        c.run_until(epochs(6), |c| committee_size(c, survivor) == Some(strength)
            && committee_size(c, child_left) == Some(strength)
            && committee_size(c, child_right) == Some(strength)
            && committee_size(c, splitter).is_none()),
        "the survivor and both splitter children must seat full committees of {strength}, and the splitter must retire",
    );

    assert!(
        await_root_matches_anchor(c, child_left, epochs(8))
            && await_root_matches_anchor(c, child_right, epochs(8)),
        "both splitter children's roots must reproduce the beacon anchor",
    );

    // A committed-height probe can transiently read `None` while a vnode's
    // serving surface hands over (the anchor probe above may have sampled a
    // host that has since rotated), so wait the heights back into view
    // before taking the bases.
    assert!(
        c.run_until(epochs(2), |c| c.committed_height(child_left).is_some()
            && c.committed_height(child_right).is_some()),
        "both splitter children must report a committed height",
    );
    let left_base = c
        .committed_height(child_left)
        .expect("the left child commits");
    let right_base = c
        .committed_height(child_right)
        .expect("the right child commits");
    assert!(
        c.run_until(epochs(6), |c| c
            .committed_height(child_left)
            .is_some_and(|h| h > left_base)
            && c.committed_height(child_right)
                .is_some_and(|h| h > right_base)),
        "both splitter children must keep committing past their seeded genesis",
    );
}

/// Verify a merge straddler settles atomically across the reshape boundary.
///
/// The cluster grows into four shards (the caller's `with_grown_balances`), then
/// the lighter `leaf(2, 2)`/`leaf(2, 3)` pair — funded below the derived merge
/// threshold — collapses into `leaf(1, 1)`, while the bulk-funded survivors
/// `leaf(2, 0)`/`leaf(2, 1)` stay above it and keep the left half alive: once the
/// topology is grown, the merge fires from the byte skew alone. Cross-shard
/// transfers run from the survivor `leaf(2, 0)` into the merging `leaf(2, 2)`, so
/// each tick names a shard that terminates at the merge. The first tick settles
/// before `leaf(2, 2)`'s terminal block; the second straddles it, in flight when
/// it terminates. After the merge the survivor must reach a terminal verdict on
/// every straddler, consistent with what `leaf(2, 2)` settled by its terminal
/// block — never one-sided, never contradicting a settlement, never hanging.
/// Exercises the merge-child terminal's settled-transaction attestation, the path a
/// split child's terminal cannot cover. Requires the [`merge_straddler_setup`]
/// funding on a config grown to four shards.
///
/// # Panics
///
/// Panics if the merge misses its budget, the merged parent never seats, or the
/// settled-transaction fence is breached (a one-sided application, a mismatch, or a
/// hung straddler).
pub fn merge_straddler_atomic(c: &mut impl Cluster) {
    let survivor = MERGE_STRADDLER_SURVIVOR;
    let merge_left = MERGE_STRADDLER_LEFT;
    let merge_right = MERGE_STRADDLER_RIGHT;
    let merge_parent = merge_left.parent().expect("a depth-2 leaf has a parent");
    let setup = merge_straddler_setup();

    // The cluster reaches this body grown to four shards; confirm every quarter
    // is seated and serving before driving the merge.
    assert!(
        await_serves(c, survivor, epochs(4))
            && await_serves(c, merge_left, epochs(4))
            && await_serves(c, merge_right, epochs(4))
            && await_serves(c, ShardId::leaf(2, 3), epochs(4)),
        "the grown four-shard topology must seat every quarter",
    );

    let world = straddler_world(c, &setup.straddlers);
    let mut charges = Charges::default();
    let mut probes: Vec<TxHash> = Vec::new();
    let half = setup.straddlers.len() / 2;

    // Settling ticks: submitted while `leaf(2, 0)` still commits real blocks, so
    // their cross-shard settlement can finalize at or below its terminal block
    // and land in the attested settled set. Submitted before the keeper
    // pairing arms the gate, then awaited to finalize on `leaf(2, 0)` so
    // settlement can't lose the race to the cut — a settler only needs to
    // finalize before the terminal.
    let settling: Vec<TxHash> = setup
        .straddlers
        .iter()
        .take(half)
        .map(|(key, from, to)| submit_straddler(c, &mut charges, key, *from, *to))
        .collect();
    probes.extend_from_slice(&settling);
    assert!(
        c.run_until(epochs(12), |c| settling
            .iter()
            .all(|hash| chain_settled(c, merge_left, *hash))),
        "the settling ticks must finalize on the merging child before its terminal",
    );

    // The light merging pair asserts the merge from its genesis byte skew; the
    // beacon pairs it and draws a keeper quorum (2f+1 of the four-validator
    // reformed committee). The heavy survivor pair never pairs.
    assert!(
        await_merge_keeper_count(c, merge_parent, 3, epochs(24)),
        "the light merging pair must pair a keeper quorum within budget",
    );

    // Straddling ticks: submitted once the merge has paired and `leaf(2, 0)` is
    // coasting to its terminal — the survivor still provisions to it, but its
    // coast blocks settle nothing, leaving them in flight when it terminates.
    for (key, from, to) in setup.straddlers.iter().skip(half) {
        probes.push(submit_straddler(c, &mut charges, key, *from, *to));
    }

    // Drive the merge to fire: the keepers' ready signals collapse the children
    // into `leaf(1, 1)`, seating it in the lookahead. Gate on the reformed parent
    // appearing in the lookahead — not merely on the pending record clearing — so
    // a pairing that lapses and re-pairs under the seeded schedule isn't read as
    // the gate.
    assert!(
        c.run_until(epochs(16), |c| merge_executed(c, merge_parent)),
        "the merge must gate within budget",
    );

    // The merge executes: the reformed parent seats and commits past genesis.
    assert!(
        await_serves(c, merge_parent, epochs(28)),
        "the merged parent must be served within budget",
    );

    // The merged parent's composed boundary records its seeded genesis height,
    // folded from both children's terminals after the gate seats the placeholder
    // at `GENESIS`. Wait for the composed height (a real genesis above `GENESIS`,
    // so its predecessor — the merging child's terminal — exists).
    assert!(
        c.run_until(epochs(12), |c| merged_genesis_height(c, merge_parent)
            .and_then(BlockHeight::prev)
            .is_some()),
        "the merged parent's composed boundary must fold within budget",
    );

    // The merging child's terminal block sits one below the merged genesis.
    let terminal_b = merged_genesis_height(c, merge_parent)
        .and_then(BlockHeight::prev)
        .expect("the merged seeded genesis pins the merging child's terminal block");

    // Every straddler must reach a terminal verdict on the survivor.
    for hash in &probes {
        let status = await_tx_terminal(c, *hash, epochs(12));
        assert!(
            matches!(status, Some(TransactionStatus::Completed(_))),
            "a straddler hung on the settled-transaction fence; status = {status:?}",
        );
    }

    assert_fence_held(c, merge_left, terminal_b, &probes);
    world.assert_settles_within(c, &charges, epochs(8), "straddlers across a merge");
}

/// Whether the merge into `parent` has executed: the reformed parent is seated
/// in the lookahead committee set and no longer pending.
fn merge_executed<C: Cluster>(c: &C, parent: ShardId) -> bool {
    c.beacon_state().is_some_and(|state| {
        !state.pending_reshapes.contains_key(&parent)
            && state.next_shard_committees.contains_key(&parent)
    })
}

/// The merged parent's seeded genesis height, from its composed boundary.
fn merged_genesis_height<C: Cluster>(c: &C, parent: ShardId) -> Option<BlockHeight> {
    c.beacon_state()
        .and_then(|state| state.boundaries.get(&parent).map(|b| b.height))
}

/// Whether `hash` finalized a non-abort decision on `shard`'s committed chain —
/// the source side of a cross-shard tick settling before a reshape terminal.
pub fn chain_settled<C: Cluster>(c: &C, shard: ShardId, hash: TxHash) -> bool {
    matches!(
        c.chain_fate(shard, hash).1,
        Some((_, decision)) if decision != TransactionDecision::Aborted
    )
}

/// The payment every straddler leg carries.
pub const STRADDLER_PAYMENT: u128 = 100;

/// Build a straddler transfer (payer → counterpart-shard recipient) bracketing
/// the current clock, submit it, and return its hash.
///
/// Each leg draws its own payer and recipient, so no two straddlers share
/// signed content — hash dedup would otherwise read them as one transaction.
pub fn submit_straddler<C: Cluster>(
    c: &mut C,
    charges: &mut Charges,
    key: &Ed25519PrivateKey,
    from: PrincipalAddr,
    to: PrincipalAddr,
) -> TxHash {
    submit_straddler_deriving(c, charges, key, from, to).0
}

/// [`submit_straddler`], also reporting the record cells its crossings
/// write — where the value it escrows sits until something disposes of
/// it.
///
/// A record cell is value rather than derived state, so nothing sweeps
/// it on a clock; a scenario that outlasts every window and reads the
/// cell is reading whether that holds.
pub fn submit_straddler_recording<C: Cluster>(
    c: &mut C,
    charges: &mut Charges,
    key: &Ed25519PrivateKey,
    from: PrincipalAddr,
    to: PrincipalAddr,
) -> (TxHash, Vec<SubstateKey>) {
    let (hash, records) = submit_straddler_deriving(c, charges, key, from, to);
    (hash, records)
}

/// [`submit_straddler`], also reporting what the transaction reserves
/// against its shards' drains.
///
fn submit_straddler_deriving<C: Cluster>(
    c: &mut C,
    charges: &mut Charges,
    key: &Ed25519PrivateKey,
    from: PrincipalAddr,
    to: PrincipalAddr,
) -> (TxHash, Vec<SubstateKey>) {
    let tx = build_transfer_tx(key, from, to, STRADDLER_PAYMENT, validity_around(c.now()));
    let records = crossing_records(
        &tx.try_derived(c.derivation().as_ref())
            .expect("a scenario transfer derives")
            .legs,
    );
    let hash = charges.submit(c, tx);
    (hash, records)
}

/// Assert the settled-transaction fence held for `probes`: every straddler the
/// survivor reached agrees with what the splitter settled by `terminal_b`, none
/// applied one-sided or contradicted a settlement, and at least one settled
/// atomically.
fn assert_fence_held<C: Cluster>(
    c: &C,
    splitter: ShardId,
    terminal_b: BlockHeight,
    probes: &[TxHash],
) {
    let tally = straddler_tally(c, splitter, terminal_b, probes);

    assert_eq!(
        tally.one_sided, 0,
        "the survivor applied a straddler the splitter never settled — one-sided:{}",
        tally.report,
    );
    assert_eq!(
        tally.mismatch, 0,
        "the survivor's verdict contradicted the splitter's settlement:{}",
        tally.report,
    );
    assert!(
        tally.consistent > 0,
        "no straddler settled atomically — submission timing needs retuning:{}",
        tally.report,
    );
}

/// How each straddler resolved on the survivor versus what the splitter settled
/// by its terminal block.
struct StraddlerTally {
    /// Survivor verdict matched the splitter's settlement.
    consistent: u32,
    /// Splitter never settled it; survivor correctly aborted.
    doomed: u32,
    /// Survivor applied a decision the splitter never settled — a broken fence.
    one_sided: u32,
    /// Survivor's verdict contradicted the splitter's settlement.
    mismatch: u32,
    /// Per-probe detail for assertion messages.
    report: String,
}

fn straddler_tally<C: Cluster>(
    c: &C,
    splitter: ShardId,
    terminal_b: BlockHeight,
    probes: &[TxHash],
) -> StraddlerTally {
    let mut tally = StraddlerTally {
        consistent: 0,
        doomed: 0,
        one_sided: 0,
        mismatch: 0,
        report: String::new(),
    };

    for (idx, hash) in probes.iter().enumerate() {
        let (_, splitter_final) = c.chain_fate(splitter, *hash);
        // The splitter settled it iff it finalized a non-abort decision at or
        // before its terminal block.
        let settled = splitter_final
            .and_then(|(h, d)| (h <= terminal_b && d != TransactionDecision::Aborted).then_some(d));
        let verdict = match c.tx_status(*hash) {
            Some(TransactionStatus::Completed(d)) => Some(d),
            _ => None,
        };
        let _ = write!(
            tally.report,
            "\n  #{idx}: splitter settled={settled:?}; survivor verdict={verdict:?}",
        );
        match (settled, verdict) {
            (Some(t), Some(v)) if t == v => tally.consistent += 1,
            (Some(_), Some(_)) => tally.mismatch += 1,
            (None, Some(TransactionDecision::Aborted)) => tally.doomed += 1, // correctly aborted
            (None, Some(_)) => tally.one_sided += 1,
            (_, None) => {} // unresolved — the abandonment gate caught it
        }
    }
    let _ = write!(
        tally.report,
        "\n  consistent={} doomed={}",
        tally.consistent, tally.doomed,
    );
    tally
}

/// The number of straddlers the survivor applied one-sided.
///
/// A one-sided straddler is one the survivor finalized on a decision the
/// splitter never settled by its terminal block. Zero when the fence holds; a
/// probe that cuts the survivor→splitter EC channel across the boundary watches
/// whether it goes positive.
#[must_use]
pub fn straddler_one_sided_count<C: Cluster>(
    c: &C,
    splitter: ShardId,
    terminal_b: BlockHeight,
    probes: &[TxHash],
) -> u32 {
    straddler_tally(c, splitter, terminal_b, probes).one_sided
}
