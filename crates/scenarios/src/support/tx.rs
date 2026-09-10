//! Portable transaction builders.
//!
//! These construct a [`Transaction`] from explicit inputs and so are
//! harness-agnostic; account discovery and the submit routing live in the
//! adaptors. A scenario submits the result via [`Cluster::submit`].
//!
//! [`Cluster::submit`]: crate::Cluster::submit

use std::sync::LazyLock;
use std::time::Duration;

use hyperscale_effects_bridge::genesis::{GenesisPackages, genesis_world_with_pools};
use hyperscale_effects_bridge::vm_statics::principal_for;
use hyperscale_effects_bridge::{ProtocolHasher, attach_metadata};
use hyperscale_engine::genesis::{
    OWNER_BADGE_ID, pool_address, pool_owner_badge, stake_unit, staking_artifact,
};
use hyperscale_engine::{XRD, account_address};
use hyperscale_hbor::TypeShape;
use hyperscale_transactions::{Client, DEFAULT_GAS_LIMIT, Terms};
use hyperscale_types::{
    AccountSigner, ComponentAddr, ConsensusPublicKey, ConsensusSignature, Ed25519PrivateKey,
    EnvelopeExt, Epoch, MAX_SUBINTENT_VALIDITY_RANGE, MAX_VALIDITY_RANGE, MIN_STAKE_FLOOR,
    MlDsa65PrivateKey, NetworkId, NetworkParams, PrincipalAddr, ResourceAddr, SchemeId, ShardId,
    ShardTrie, StakePoolId, StakePoolSeat, SubstateKey, TimestampRange, Transaction,
    TransactionBody, TransactionEnvelope, ValidatorId, WeightedTimestamp,
    ed25519_keypair_from_seed,
};
use hyperscale_vm_effects::{
    Composed, Constraint, EnvelopeTree, Hash32, InstanceMeta, IntentDecl, IntentHeader,
    ManifestGraph, ResourceKind, SlotId, Totality, Value, child_key, issued_resource, package_hash,
};
use hyperscale_vm_fixtures::{amm, amm_package_hash, lottery, lottery_package_hash};
use hyperscale_vm_manifest_builder::signing::{self, sign_subintent};
use hyperscale_vm_manifest_builder::{
    EnvelopeBuilder, GraphBuilder, IntentBuilder, TypedBuilder, TypedError,
};
use hyperscale_vm_sdk::client::VaultField;
use hyperscale_vm_stdlib::{STAKING_MODULE, account, account_artifact, instantiate, staking};
use hyperscale_vm_types::Address;

/// A deterministic Ed25519 signer from a one-byte seed. A faucet transaction's
/// fee comes from the faucet, so any key notarizes it.
#[must_use]
pub fn signer_from_seed(seed: u8) -> Ed25519PrivateKey {
    ed25519_keypair_from_seed(&[seed; 32])
}

/// A deterministic ML-DSA-65 signer from a one-byte seed.
///
/// # Panics
///
/// Cannot panic: every 32-byte string is a valid ML-DSA seed.
#[must_use]
pub fn ml_dsa_signer_from_seed(seed: u8) -> MlDsa65PrivateKey {
    MlDsa65PrivateKey::from_bytes(&[seed; 32]).expect("any 32 bytes seed ML-DSA")
}

/// The splitting shard of the grown surviving-sibling shape — `leaf(1, 0)`, the
/// heavier child the engine bootstrap concentrates substates into, which crosses
/// the voted-down threshold and terminates.
pub const STRADDLER_SPLITTER: ShardId = ShardId::leaf(1, 0);

/// The surviving sibling — `leaf(1, 1)`, the lighter child that stays under the
/// threshold. Straddler payers live here; their cross-shard ticks name the
/// terminating splitter.
pub const STRADDLER_SURVIVOR: ShardId = ShardId::leaf(1, 1);

/// The genesis package flash's byte total: every stdlib artifact, written
/// whole under the publisher's single prefix.
///
/// The flash lands on whichever shard that prefix routes to — nothing a
/// scenario controls — so every byte band calibrated around a shard that
/// may hold it offsets by this total. Expressed as an offset, a band's
/// margin holds as the stdlib grows; expressed as a literal, it silently
/// erodes with every regenerated guest blob.
#[must_use]
pub fn stdlib_flash_bytes() -> u64 {
    (account_artifact().len() + staking_artifact().len()) as u64
}

/// What one ballast account's vault cell stores: its `u128` balance.
/// Substate byte totals count value bytes, so this converts a byte band
/// into a ballast account count.
const BALLAST_CELL_BYTES: u64 = 16;

/// Bytes of ballast lead the splitter carries over the flash total, so a
/// vote threshold fits between the flash-holding survivor and the
/// splitter with fixed margins on both sides.
const SPLITTER_BALLAST_LEAD: u64 = 24_000;

/// Ballast accounts funded into the survivor: enough to clear the derived
/// merge floor with margin, and short of the splitter's by enough that
/// only the splitter crosses the voted-down split threshold even when the
/// package lump is on this side.
const STRADDLER_SURVIVOR_BULK: usize = 300;

/// Straddler pairs submitted across the splitter's grow — enough to span its
/// terminal cut: the earliest settle on it before it crosses, the latest name a
/// splitter that has already terminated.
pub const STRADDLER_COUNT: usize = 8;

/// The surviving shard of the depth-2 merge-straddler topology —
/// `leaf(2, 2)`.
///
/// The heaviest engine-bootstrap quarter, bulk-funded over `merge_bytes` so its
/// sibling pair never merges. Straddler payers live here; their cross-shard
/// ticks name the terminating merge-left child.
///
/// The surviving pair is the half the genesis package flash lands under,
/// so the flash only reinforces the ordering this scenario needs: a shard
/// the merge floor must sit *below* is the one that carries
/// [`stdlib_flash_bytes`] it does not control.
pub const MERGE_STRADDLER_SURVIVOR: ShardId = ShardId::leaf(2, 2);

/// The merge-left child — `leaf(2, 0)`.
///
/// Light enough to fall under `merge_bytes` and collapse into `leaf(1, 0)` with
/// its sibling. Straddler recipients live here, so the survivor's tick names the
/// shard that terminates at the merge.
pub const MERGE_STRADDLER_LEFT: ShardId = ShardId::leaf(2, 0);

/// The merge-right child — `leaf(2, 1)`, the lightest quarter, which merges with
/// [`MERGE_STRADDLER_LEFT`] into their parent `leaf(1, 0)`.
pub const MERGE_STRADDLER_RIGHT: ShardId = ShardId::leaf(2, 1);

/// Ballast accounts funded into each surviving quarter (`leaf(2, 2)` and
/// `leaf(2, 3)`), lifting the pair above `merge_bytes` so neither emits an
/// unpairable merge against the other while the lighter merging pair stays
/// under it.
const MERGE_SURVIVOR_BULK: usize = 500;

/// Merge-straddler pairs submitted across the merge.
///
/// Each payer in the survivor `leaf(2, 0)`, each recipient in the merging
/// `leaf(2, 2)`. Submitted in two ticks — the first settles before the
/// merge-left terminal, the second straddles it.
pub const MERGE_STRADDLER_COUNT: usize = 4;

/// Seed of the merge-straddler vote payer.
///
/// The simulation adaptor reaches the four-shard topology by growing the root
/// (the harness genesis is always single-shard) and then voting `split_bytes` up
/// so only the light pair merges. That vote is a fee-paying system action; this
/// account is funded at genesis so the adaptor's pre-grow vote can lock its fee.
/// On production the genesis seats four shards directly, so the account is just
/// an unused funded balance.
const MERGE_VOTE_PAYER_SEED: u8 = 200;

/// The merge-straddler vote payer's signing key — funded by
/// [`merge_straddler_setup`] for the simulation adaptor's pre-grow vote.
#[must_use]
pub fn merge_vote_payer() -> Ed25519PrivateKey {
    signer_from_seed(MERGE_VOTE_PAYER_SEED)
}

/// Seed of the witness scenarios' fee payer.
///
/// The beacon-witness scenarios (staking, validator registration, governance
/// votes) pay every system action from one genesis-funded account. Both adaptors
/// install [`witness_genesis_balances`] at genesis so the payer can lock fees on
/// either harness.
const WITNESS_PAYER_SEED: u8 = 42;

/// The witness scenarios' fee-paying signing key.
#[must_use]
pub fn witness_payer() -> Ed25519PrivateKey {
    signer_from_seed(WITNESS_PAYER_SEED)
}

/// Probe pairs per submission batch of the halted-shard straddler scenario.
///
/// Two transfers sourced on the surviving sibling into the halting shard,
/// one sourced on the halting shard itself, so both tick directions cross
/// each phase of the freeze.
pub const HALT_STRADDLER_BATCH: usize = 3;

/// The genesis funding and probe transfers for the halted-shard straddler
/// scenario.
///
/// The stable-band ballast plus three probe batches (submitted before
/// the fault installs, at the freeze edge, and against the frozen shard)
/// and a post-recovery transfer per direction. One definition the
/// adaptors and the scenario body share, so the funded accounts cannot
/// drift from the transfers spent against them.
pub struct HaltStraddlerSetup {
    /// Genesis accounts: the stable-band ballast plus every probe leg's
    /// payer and recipient.
    pub accounts: Vec<(PrincipalAddr, u128)>,
    /// Probe transfers in submission order, [`HALT_STRADDLER_BATCH`] per
    /// batch: `(payer key, payer account, recipient account)`.
    pub straddlers: Vec<(Ed25519PrivateKey, PrincipalAddr, PrincipalAddr)>,
    /// Transfers submitted after the recovery record clears, one per
    /// direction — the recovered shard's cross-shard rail must serve both.
    pub post_recovery: Vec<(Ed25519PrivateKey, PrincipalAddr, PrincipalAddr)>,
}

/// Ballast accounts per child of the root split, for the halt-recovery
/// stable band: above the derived merge floor, below the split threshold,
/// summing over it, so the root splits exactly once and the grown pair
/// holds while the halt and its recovery play out.
///
/// The child that receives the genesis package flash starts
/// [`stdlib_flash_bytes`] ahead, so the armed band offsets by the flash —
/// see [`straddler_bulk`] for why the flash sets the scale.
const HALT_RECOVERY_BULK: usize = 900;

/// Build the halted-shard straddler genesis funding and probe transfers.
///
/// Both children of the root are ballasted into the stable band — above
/// the derived merge floor, below the split threshold, summing over it —
/// so the root splits exactly once and the grown pair holds: neither
/// child re-splits or asserts a merge half while the halt and its
/// recovery play out (a pending reshape would exempt the halted shard
/// from detection). The probe accounts ride on top, small enough to leave
/// both children inside the band.
#[must_use]
pub fn halt_straddler_setup() -> HaltStraddlerSetup {
    let halting = ShardId::leaf(1, 0);
    let surviving = ShardId::leaf(1, 1);

    let mut accounts = Vec::new();
    ballast(halting, 2, HALT_RECOVERY_BULK, &mut accounts);
    ballast(surviving, 2, HALT_RECOVERY_BULK, &mut accounts);

    let mut taken = Vec::new();
    let mut leg = |from, to| transfer_leg(from, to, 2, &mut taken, &mut accounts);

    let mut straddlers = Vec::new();
    for _ in 0..3 {
        straddlers.push(leg(surviving, halting));
        straddlers.push(leg(surviving, halting));
        straddlers.push(leg(halting, surviving));
    }
    let post_recovery = vec![leg(surviving, halting), leg(halting, surviving)];
    HaltStraddlerSetup {
        accounts,
        straddlers,
        post_recovery,
    }
}

/// The genesis funding and straddler transfers for the merge-straddler scenario.
///
/// Mirrors [`SplitStraddlerSetup`] but for a four-shard topology: the surviving
/// quarter pair (`leaf(2, 2)`/`leaf(2, 3)`) is bulk-funded over `merge_bytes`,
/// the merging pair (`leaf(2, 0)`/`leaf(2, 1)`) is left under it, and the
/// straddlers run from the survivor into the merging left child. The funding is
/// installed at the single-shard genesis and partitions across the quarters as
/// the cluster grows.
pub struct MergeStraddlerSetup {
    /// Genesis accounts: the survivor pair ballasted over `merge_bytes`
    /// and the merging pair left under it, plus the straddler payers in
    /// the survivor and their recipients in the merging left child.
    pub accounts: Vec<(PrincipalAddr, u128)>,
    /// Straddler transfers: `(payer key, payer account in the survivor,
    /// recipient in the merging left child)`.
    pub straddlers: Vec<(Ed25519PrivateKey, PrincipalAddr, PrincipalAddr)>,
}

/// The genesis funding and straddler transfers for the split-straddler scenario.
///
/// One definition both adaptors and the scenario body derive from, so the funded
/// accounts can't drift from the transfers spent against them.
pub struct SplitStraddlerSetup {
    /// Genesis accounts: ballast skewed toward the splitter so only it
    /// crosses the voted-down threshold, plus the straddler payers in the
    /// survivor and their recipients in the splitter.
    pub accounts: Vec<(PrincipalAddr, u128)>,
    /// Straddler transfers: `(payer key, payer account in survivor, recipient in
    /// splitter)`.
    pub straddlers: Vec<(Ed25519PrivateKey, PrincipalAddr, PrincipalAddr)>,
}

/// Push `count` ballast accounts routing to `shard` under a
/// `num_shards`-wide trie onto `accounts`.
///
/// Ballast is funded for its committed bytes and nothing else: nothing
/// spends it, and the reshape thresholds a straddler scenario votes in are
/// bracketed against the totals it produces. Grinds the wide `u64` seed
/// space rather than the `u8` one the transacting accounts draw from, so a
/// ballast account can never collide with one a transfer names.
fn ballast(
    shard: ShardId,
    num_shards: u64,
    count: usize,
    accounts: &mut Vec<(PrincipalAddr, u128)>,
) {
    let trie = ShardTrie::uniform_from_count(num_shards);
    let mut found = 0;
    let mut seed: u64 = 1;
    while found < count {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let address = account_address(&ed25519_keypair_from_seed(&bytes).public_key().0);
        if trie.shard_for_prefix(address) == shard {
            accounts.push((address, BALLAST_FUNDING));
            found += 1;
        }
        seed += 1;
    }
}

/// What one ballast account holds. Never spent — the balance exists only
/// to give the cell a value to store.
const BALLAST_FUNDING: u128 = 10_000;

/// Ballast accounts per leaf in [`reshape_lifecycle_accounts`].
///
/// Only has to put every leaf on the board, not to shape a skew, so it
/// is a fraction of a straddler's bulk — each account costs a grind at
/// genesis and every cluster in a binary pays for the whole world.
const RESHAPE_LIFECYCLE_BULK: usize = 100;

/// Genesis funding spread over every leaf of a four-shard partition.
///
/// Genesis writes the stdlib package as one cell under a single prefix,
/// so an unfunded network is one shard holding a ~14 KiB lump beside
/// siblings holding nothing at all. Under an armed trigger that skew
/// decides the order splits are admitted in: the populated side splits
/// generation after generation while the empty sibling waits, and the
/// pool is drained by the deeper generations before the intended
/// partition can seat. A spread population keeps the generations in
/// step, and populating every leaf of the deepest partition these
/// scenarios reach populates every shard on the way down.
#[must_use]
pub fn reshape_lifecycle_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut accounts = Vec::new();
    for path in 0..4 {
        ballast(
            ShardId::leaf(2, path),
            4,
            RESHAPE_LIFECYCLE_BULK,
            &mut accounts,
        );
    }
    accounts
}

/// Seed base for the contention scenarios' payers; each sender occupies
/// one seed so no two payments share a payer account.
const CONTENTION_SENDER_BASE: u8 = 120;

/// Seed base for the contention scenarios' payees, disjoint from every
/// sender seed.
const CONTENTION_RECIPIENT_BASE: u8 = 200;

/// The byte skew alone: the splitter ballasted over the voted-down
/// threshold and the survivor under it, for a scenario that brings its
/// own cast to the pair.
#[must_use]
pub fn split_ballast_accounts() -> Vec<(PrincipalAddr, u128)> {
    split_ballast_accounts_over(stdlib_flash_bytes())
}

/// Ballast on one quarter of a four-shard partition, leading a genesis
/// flash of `flash` bytes by the splitter's margin: what puts that
/// quarter alone over a threshold voted to [`split_bytes_over`].
///
/// # Panics
///
/// Panics if the ballast count does not fit `usize`.
///
/// [`split_bytes_over`]: crate::straddler::split_bytes_over
#[must_use]
pub fn quarter_ballast_over(shard: ShardId, flash: u64) -> Vec<(PrincipalAddr, u128)> {
    let mut accounts = Vec::new();
    let bulk = usize::try_from((flash + SPLITTER_BALLAST_LEAD) / BALLAST_CELL_BYTES)
        .expect("ballast count fits usize");
    ballast(shard, 4, bulk, &mut accounts);
    accounts
}

/// [`split_ballast_accounts`] for a network whose genesis flash is
/// `flash` bytes — the fixture packages beside the protocol's, on a
/// network born running them.
///
/// # Panics
///
/// Panics if the ballast count does not fit `usize`.
#[must_use]
pub fn split_ballast_accounts_over(flash: u64) -> Vec<(PrincipalAddr, u128)> {
    let mut accounts = Vec::new();
    let bulk = usize::try_from((flash + SPLITTER_BALLAST_LEAD) / BALLAST_CELL_BYTES)
        .expect("ballast count fits usize");
    ballast(STRADDLER_SPLITTER, 2, bulk, &mut accounts);
    ballast(
        STRADDLER_SURVIVOR,
        2,
        STRADDLER_SURVIVOR_BULK,
        &mut accounts,
    );
    accounts
}

/// The genesis flash of a network born running the fixture packages
/// beside the protocol's: every artifact, written whole under the
/// publisher's single prefix.
#[must_use]
pub fn fixture_flash_bytes() -> u64 {
    GenesisPackages::with_fixtures()
        .artifacts()
        .iter()
        .map(|artifact| artifact.len() as u64)
        .sum()
}

/// The genesis funding and transfers for a train into a shard across its
/// reshape.
pub struct TrainSetup {
    /// Genesis accounts: the byte skew plus every leg's payer and recipient.
    pub accounts: Vec<(PrincipalAddr, u128)>,
    /// One transfer per leg, a surviving shard's payer into the
    /// terminating shard's recipient, each from its own payer so the
    /// train never waits on a reservation.
    pub legs: Vec<(Ed25519PrivateKey, PrincipalAddr, PrincipalAddr)>,
}

/// Build the split-train genesis funding and its `count` legs: survivor
/// payers into splitter recipients over the split-straddler byte skew.
#[must_use]
pub fn split_train_setup(count: usize) -> TrainSetup {
    let mut accounts = split_ballast_accounts();
    let mut taken = Vec::new();
    let legs = (0..count)
        .map(|_| {
            transfer_leg(
                STRADDLER_SURVIVOR,
                STRADDLER_SPLITTER,
                2,
                &mut taken,
                &mut accounts,
            )
        })
        .collect();
    TrainSetup { accounts, legs }
}

/// Build the merge-train genesis funding and its `count` legs: survivor
/// payers into merge-left recipients over the merge-straddler byte skew.
#[must_use]
pub fn merge_train_setup(count: usize) -> TrainSetup {
    let mut accounts = Vec::new();
    merge_survivor_ballast(&mut accounts);
    let mut taken = Vec::new();
    let legs = (0..count)
        .map(|_| {
            transfer_leg(
                MERGE_STRADDLER_SURVIVOR,
                MERGE_STRADDLER_LEFT,
                4,
                &mut taken,
                &mut accounts,
            )
        })
        .collect();
    TrainSetup { accounts, legs }
}

/// Build the split-straddler genesis funding and straddler transfers.
///
/// The splitter (`leaf(1, 0)`) is ballasted over the voted-down threshold,
/// the survivor (`leaf(1, 1)`) under it, so only the splitter crosses and
/// terminates. The skew comes from the [`ballast`] — accounts funded for
/// their committed bytes and nothing else — while the straddlers
/// themselves are transfers from a survivor payer into a splitter
/// recipient.
#[must_use]
pub fn split_straddler_setup() -> SplitStraddlerSetup {
    let mut accounts = split_ballast_accounts();
    let mut taken = Vec::new();
    let straddlers = (0..STRADDLER_COUNT)
        .map(|_| {
            transfer_leg(
                STRADDLER_SURVIVOR,
                STRADDLER_SPLITTER,
                2,
                &mut taken,
                &mut accounts,
            )
        })
        .collect();

    SplitStraddlerSetup {
        accounts,
        straddlers,
    }
}

/// [`split_straddler_setup`] with the leg reversed: the payer in the
/// splitting shard and the recipient in the survivor.
///
/// What the cut then carries is the crossing's *record* rather than its
/// delivery — the issuer is what splits, so a successor inherits the
/// record and has to decide it against the claim cell its leaf names.
#[must_use]
pub fn split_issuer_straddler_setup() -> SplitStraddlerSetup {
    let mut accounts = split_ballast_accounts();
    let mut taken = Vec::new();
    let straddlers = (0..STRADDLER_COUNT)
        .map(|_| {
            transfer_leg(
                STRADDLER_SPLITTER,
                STRADDLER_SURVIVOR,
                2,
                &mut taken,
                &mut accounts,
            )
        })
        .collect();

    SplitStraddlerSetup {
        accounts,
        straddlers,
    }
}

/// [`merge_survivor_ballast`] on its own, for a scenario composing the
/// merge topology's byte skew with funding of its own.
#[must_use]
pub fn merge_survivor_ballast_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut accounts = Vec::new();
    merge_survivor_ballast(&mut accounts);
    accounts
}

/// Lift the surviving quarters (`leaf(2, 2)` and `leaf(2, 3)`) above
/// `merge_bytes`, so neither emits an unpairable merge against the other
/// and churns the schedule, while the lighter pair stays under it.
fn merge_survivor_ballast(accounts: &mut Vec<(PrincipalAddr, u128)>) {
    let num_shards = 4;
    ballast(
        MERGE_STRADDLER_SURVIVOR,
        num_shards,
        MERGE_SURVIVOR_BULK,
        accounts,
    );
    ballast(
        ShardId::leaf(2, 3),
        num_shards,
        MERGE_SURVIVOR_BULK,
        accounts,
    );
}

/// Build the merge-straddler genesis funding and straddler transfers.
///
/// Across the four-shard topology the surviving quarters (`leaf(2, 2)`/`leaf(2,
/// 3)`) are bulk-funded over the derived `merge_bytes` so neither auto-merges,
/// while the lighter merging pair (`leaf(2, 0)`/`leaf(2, 1)`) stays under it and
/// collapses into `leaf(1, 0)`. Straddler payers sit in the survivor
/// `leaf(2, 2)` and recipients in the merging `leaf(2, 0)`, so each cross-shard
/// tick names the shard that terminates at the merge.
#[must_use]
pub fn merge_straddler_setup() -> MergeStraddlerSetup {
    let num_shards = 4;
    let mut accounts = Vec::new();
    merge_survivor_ballast(&mut accounts);

    let mut taken = Vec::new();
    let straddlers = (0..MERGE_STRADDLER_COUNT)
        .map(|_| {
            transfer_leg(
                MERGE_STRADDLER_SURVIVOR,
                MERGE_STRADDLER_LEFT,
                num_shards,
                &mut taken,
                &mut accounts,
            )
        })
        .collect();
    MergeStraddlerSetup {
        accounts,
        straddlers,
    }
}

/// A validity window bracketing `now`.
///
/// The terms an intent is sealed under: the scenario network, and the
/// same window the envelope carrying it is signed for. An intent's
/// window narrows the transaction, so mirroring the envelope's is what
/// leaves the transaction exactly as wide as its composer asked.
#[must_use]
pub const fn scenario_header(validity: TimestampRange) -> IntentHeader {
    IntentHeader {
        network: SCENARIO_NETWORK,
        validity_start_ms: validity.start_timestamp_inclusive.as_millis(),
        validity_end_ms: validity.end_timestamp_exclusive.as_millis(),
        discriminator: 0,
    }
}

/// The terms a standing offer is signed under.
///
/// The scenario network, and a window far wider than any transaction's —
/// which is the point of an offer: its signer is not composing it now
/// and does not know when a composer will. The composition's own window
/// is what narrows it.
#[must_use]
pub const fn offer_header() -> IntentHeader {
    IntentHeader {
        network: SCENARIO_NETWORK,
        validity_start_ms: 0,
        // The cap in milliseconds, which a `u64` holds with room: the
        // constant is days and the type counts to half a billion years.
        validity_end_ms: MAX_SUBINTENT_VALIDITY_RANGE.as_secs() * 1_000,
        discriminator: 0,
    }
}

/// Opens [`VALIDITY_BACK`] before `now` to absorb the chain's anchor
/// trailing the cluster clock, and runs [`VALIDITY_FORWARD`] past it.
#[must_use]
pub fn validity_around(now: Duration) -> TimestampRange {
    TimestampRange::new(
        WeightedTimestamp::ZERO.plus(now.saturating_sub(VALIDITY_BACK)),
        WeightedTimestamp::ZERO.plus(now + VALIDITY_FORWARD),
    )
}

/// How far back of `now` [`validity_around`] opens a window.
const VALIDITY_BACK: Duration = Duration::from_secs(5);

/// Slack held under [`MAX_VALIDITY_RANGE`] so a window built against the
/// cluster clock is still well formed at an anchor trailing it.
const VALIDITY_SLACK: Duration = Duration::from_secs(15);

/// How far forward [`validity_around`] opens a window — the rest of the
/// budget once the backward opening and the anchor slack are taken.
///
/// Wall-clock rather than epoch-shaped, and both a transaction's
/// inclusion deadline and — for a cross-shard VM payer — the point past
/// which it gives up waiting for engagement echoes.
const VALIDITY_FORWARD: Duration =
    MAX_VALIDITY_RANGE.saturating_sub(VALIDITY_BACK.saturating_add(VALIDITY_SLACK));

/// The account owned by [`signer_from_seed`]'s key for `seed`.
#[must_use]
pub fn account_from_seed(seed: u8) -> PrincipalAddr {
    account_address(&signer_from_seed(seed).public_key().0)
}

/// The account owned by [`ml_dsa_signer_from_seed`]'s key for `seed`.
///
/// A scheme is part of what a principal address derives from, so this
/// and [`account_from_seed`] never collide on one seed.
///
/// # Panics
///
/// Cannot panic: the registry admits ML-DSA-65 keys at the width this
/// signer produces them, which its own crate pins.
#[must_use]
pub fn ml_dsa_account_from_seed(seed: u8) -> PrincipalAddr {
    let key = ml_dsa_signer_from_seed(seed);
    principal_for(SchemeId::ML_DSA_65, &key.public_key())
        .expect("ML-DSA-65 is registered at the width its keys have")
}

/// Contention sender `index`: its signing key and account, drawn from a
/// seed lane disjoint from every other fixture's, so senders never
/// collide with recipients or with the ballast.
#[must_use]
pub fn sender(index: u8) -> (Ed25519PrivateKey, PrincipalAddr) {
    let seed = CONTENTION_SENDER_BASE + index;
    (signer_from_seed(seed), account_from_seed(seed))
}

/// contention recipient `index`.
#[must_use]
pub fn recipient(index: u8) -> PrincipalAddr {
    account_from_seed(CONTENTION_RECIPIENT_BASE + index)
}

/// Genesis accounts for the scenarios: `senders` funded payers plus
/// `recipients` payees.
///
/// Recipients are listed for their opening balance, not to make them
/// reachable: a deposit lands on any principal address, funded here or
/// not.
#[must_use]
pub fn genesis_accounts(senders: u8, recipients: u8) -> Vec<(PrincipalAddr, u128)> {
    (0..senders)
        .map(|index| (sender(index).1, 10_000u128))
        .chain((0..recipients).map(|index| (recipient(index), 10)))
        .collect()
}

/// Genesis funding for a burst of withdrawals off one vault.
///
/// Admission refuses an envelope whose payer cannot cover the fee it
/// declares on top of what its in-flight siblings already declared, so a
/// burst of `count` withdrawals needs `count * MAX_FEE` in the vault
/// before contention is what is being measured rather than solvency.
#[must_use]
pub fn withdrawal_burst_genesis_accounts(count: u8) -> Vec<(PrincipalAddr, u128)> {
    let funded = u128::from(count) * MAX_FEE * 2;
    vec![(sender(0).1, funded), (recipient(0), 10)]
}

/// One payment to each of `recipients`, all from `from` in a single
/// transaction.
///
/// A withdrawal per recipient rather than one split between them: each
/// leg is an independent reservation on the payer's own vault, which is
/// what a fan-out actually contends on, and the payer's shard is the one
/// cell every leg shares.
///
/// # Panics
///
/// Panics on a recipient list long enough to overflow a node index,
/// which is orders past the manifest node cap admission enforces.
#[must_use]
pub fn build_fan_out_tx(
    payer: &Ed25519PrivateKey,
    from: PrincipalAddr,
    recipients: &[PrincipalAddr],
    amount: u128,
    validity: TimestampRange,
) -> Transaction {
    let graph = graph(account_address(&payer.public_key().0), |b| {
        for (index, to) in recipients.iter().enumerate() {
            let leg = amount + index as u128;
            let funds = account::withdraw(b, from, *XRD, leg)?;
            account::deposit(b, *to, funds)?;
        }
        Ok(())
    });
    Transaction::new(envelope(graph, payer, validity))
}

/// The accounts the participant sweep fans out across: one payer on the
/// first leaf and one payee on each leaf, under a `num_shards`-wide trie.
///
/// The sweep walks the same grind, so what it names is what genesis
/// funded.
#[must_use]
pub fn participant_sweep_accounts(num_shards: u64) -> Vec<(Ed25519PrivateKey, PrincipalAddr)> {
    let depth = num_shards.trailing_zeros();
    let mut taken = Vec::new();
    let mut accounts = accounts_routing_to(ShardId::leaf(depth, 0), num_shards, 1, &mut taken);
    for leaf in 0..num_shards {
        accounts.extend(accounts_routing_to(
            ShardId::leaf(depth, leaf),
            num_shards,
            1,
            &mut taken,
        ));
    }
    accounts
}

/// Genesis funding for [`participant_sweep_accounts`].
#[must_use]
pub fn participant_sweep_genesis_accounts(num_shards: u64) -> Vec<(PrincipalAddr, u128)> {
    participant_sweep_accounts(num_shards)
        .into_iter()
        .map(|(_, account)| (account, 10_000u128))
        .collect()
}

/// The conflicting pair the livelock probe submits: one account on each
/// child of the root split.
///
/// Ground onto opposite children so the two transfers are genuinely
/// cross-shard and share their whole account set — each is the other's
/// mirror, which is the shape that would livelock if conflicting ticks
/// could starve each other.
#[must_use]
pub fn livelock_pair() -> Vec<(Ed25519PrivateKey, PrincipalAddr)> {
    let mut taken = Vec::new();
    vec![
        account_routing_to(ShardId::leaf(1, 0), &mut taken),
        account_routing_to(ShardId::leaf(1, 1), &mut taken),
    ]
}

/// Genesis funding for [`livelock_pair`]: both sides pay and receive,
/// so both need a payer's balance.
#[must_use]
pub fn livelock_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    livelock_pair()
        .into_iter()
        .map(|(_, account)| (account, 10_000u128))
        .collect()
}

/// The transaction a scenario submits when it needs real traffic and does
/// not care what the traffic does.
///
/// A transfer between the first genesis-funded sender and recipient, so
/// any cluster funding [`genesis_accounts`] can carry it. Scenarios
/// use it to keep a committee busy, to give a drop rule something to
/// drop, or to have one settlement to watch — none of which depends on
/// the payment itself.
#[must_use]
pub fn build_probe_transfer_tx(validity: TimestampRange) -> Transaction {
    let (payer, from) = sender(0);
    build_transfer_tx(&payer, from, recipient(0), PROBE_PAYMENT, validity)
}

/// What [`build_probe_transfer_tx`] moves: enough to be a real credit,
/// far under the sender's genesis funding so a scenario can submit
/// several.
pub const PROBE_PAYMENT: u128 = 100;

/// Genesis funding for a scenario that submits a train of
/// [`build_probe_transfer_tx`] probes rather than one.
///
/// Admission refuses an envelope whose payer cannot cover the fee it
/// declares on top of its in-flight siblings', so a train of `count`
/// probes needs the whole train's declared cost in the vault before
/// solvency is what the scenario measures. Doubled for headroom, the way
/// [`withdrawal_burst_genesis_accounts`] sizes its own burst.
#[must_use]
pub fn probe_train_genesis_accounts(count: u32) -> Vec<(PrincipalAddr, u128)> {
    let funded = u128::from(count) * (MAX_FEE + PROBE_PAYMENT) * 2;
    vec![(sender(0).1, funded), (recipient(0), 10)]
}

/// `count` accounts routing to `shard` under a `num_shards`-wide trie,
/// each drawing a fresh seed.
#[must_use]
pub fn accounts_routing_to(
    shard: ShardId,
    num_shards: u64,
    count: usize,
    taken: &mut Vec<u8>,
) -> Vec<(Ed25519PrivateKey, PrincipalAddr)> {
    (0..count)
        .map(|_| account_routing_to_n(shard, num_shards, taken))
        .collect()
}

/// How many senders the cross-shard fraction sweep runs with. Named so
/// the world's registration and the scenario's own funding cannot drift.
pub const CROSS_FRACTION_SENDERS: usize = 16;

/// Genesis VM funding for the cross-shard fraction sweep: `senders`
/// payers on the left child, and a payee for each on whichever child the
/// sweep sends it to.
///
/// Every account a transfer names has to exist at genesis — an instance
/// the registry does not know cannot be a deposit target — so the walk
/// here is the sweep's own, in the same order.
#[must_use]
pub fn cross_fraction_genesis_accounts(senders: usize) -> Vec<(PrincipalAddr, u128)> {
    let (left, right) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
    let mut taken = Vec::new();
    let mut accounts: Vec<(PrincipalAddr, u128)> =
        accounts_routing_to(left, 2, senders, &mut taken)
            .into_iter()
            .map(|(_, account)| (account, 10_000u128))
            .collect();
    // Both recipient walks in full, so any cross fraction the sweep is
    // run at finds its payees funded.
    for shard in [left, right] {
        accounts.extend(
            accounts_routing_to(shard, 2, senders, &mut taken)
                .into_iter()
                .map(|(_, account)| (account, 10u128)),
        );
    }
    accounts
}

/// Grind a signing key whose account routes to `shard` under the
/// depth-1 partition. Seeds in `taken` are skipped, so successive calls
/// yield distinct accounts.
///
/// # Panics
///
/// Panics on a shard that is not a depth-1 leaf.
#[must_use]
pub fn account_routing_to(
    shard: ShardId,
    taken: &mut Vec<u8>,
) -> (Ed25519PrivateKey, PrincipalAddr) {
    assert!(
        shard == ShardId::leaf(1, 0) || shard == ShardId::leaf(1, 1),
        "depth-1 grinding only"
    );
    account_routing_to_n(shard, 2, taken)
}

/// Grind a signing key whose account routes to `shard` under the
/// `num_shards`-wide uniform partition, skipping seeds already `taken`.
///
/// A account's 16-byte address *is* its placement — the trie walks the
/// prefix bits directly rather than hashing — so grinding is a scan for a
/// seed whose address lands in the wanted leaf.
///
/// # Panics
///
/// Panics if no seed in the `u8` space routes to `shard`.
#[must_use]
pub fn account_routing_to_n(
    shard: ShardId,
    num_shards: u64,
    taken: &mut Vec<u8>,
) -> (Ed25519PrivateKey, PrincipalAddr) {
    let trie = ShardTrie::uniform_from_count(num_shards);
    for seed in 1..=u8::MAX {
        if taken.contains(&seed) {
            continue;
        }
        let address = account_from_seed(seed);
        if trie.shard_for_prefix(address) == shard {
            taken.push(seed);
            return (signer_from_seed(seed), address);
        }
    }
    panic!("no VM account seed routes to {shard:?}");
}

/// Grind an ML-DSA-65 signing key whose account routes to `shard` under
/// the depth-1 uniform partition, skipping seeds already `taken`.
///
/// [`account_routing_to`]'s post-quantum twin, and a separate seed lane:
/// the scheme rides in the address preimage, so one seed grinds to a
/// different account under each scheme and the two never collide.
///
/// # Panics
///
/// Panics if no seed in the `u8` space routes to `shard`.
#[must_use]
pub fn ml_dsa_account_routing_to(
    shard: ShardId,
    taken: &mut Vec<u8>,
) -> (MlDsa65PrivateKey, PrincipalAddr) {
    assert!(
        shard == ShardId::leaf(1, 0) || shard == ShardId::leaf(1, 1),
        "depth-1 grinding only"
    );
    let trie = ShardTrie::uniform_from_count(2);
    for seed in 1..=u8::MAX {
        if taken.contains(&seed) {
            continue;
        }
        let address = ml_dsa_account_from_seed(seed);
        if trie.shard_for_prefix(address) == shard {
            taken.push(seed);
            return (ml_dsa_signer_from_seed(seed), address);
        }
    }
    panic!("no ML-DSA account seed routes to {shard:?}");
}

/// The shard owning `address` under the `num_shards`-wide uniform
/// partition. A account's address *is* its placement, so this is the
/// trie walk over the address bits and nothing else.
///
/// # Panics
///
/// Panics if `num_shards` is not a power of two.
#[must_use]
pub fn account_shard(address: impl Into<Address>, num_shards: u64) -> ShardId {
    ShardTrie::uniform_from_count(num_shards).shard_for_prefix(address)
}

/// Grind a straddler leg: a payer in `from_shard` and a recipient in
/// `to_shard`, both funded — the payer to cover the payment and its fee
/// ceiling, the recipient with dust so the deposit has a live instance to
/// land in.
fn transfer_leg(
    from_shard: ShardId,
    to_shard: ShardId,
    num_shards: u64,
    taken: &mut Vec<u8>,
    accounts: &mut Vec<(PrincipalAddr, u128)>,
) -> (Ed25519PrivateKey, PrincipalAddr, PrincipalAddr) {
    let (payer_key, payer) = account_routing_to_n(from_shard, num_shards, taken);
    let (_, recipient) = account_routing_to_n(to_shard, num_shards, taken);
    accounts.push((payer, 10_000));
    accounts.push((recipient, 10));
    (payer_key, payer, recipient)
}

/// The cross-shard VM cast: the payer's key and account on `leaf(1, 0)`
/// and the recipient's account on `leaf(1, 1)`.
#[must_use]
pub fn cross_shard_cast() -> (Ed25519PrivateKey, PrincipalAddr, PrincipalAddr) {
    let (payer, from, key, _) = cross_shard_keys();
    (payer, from, account_address(&key.public_key().0))
}

/// [`cross_shard_cast`] with the recipient's key as well: what a
/// scenario needs when the far side has to authorise something of its
/// own rather than only be paid.
#[must_use]
pub fn cross_shard_keys() -> (
    Ed25519PrivateKey,
    PrincipalAddr,
    Ed25519PrivateKey,
    PrincipalAddr,
) {
    let mut taken = Vec::new();
    let (payer, from) = account_routing_to(ShardId::leaf(1, 0), &mut taken);
    let (recipient, to) = account_routing_to(ShardId::leaf(1, 1), &mut taken);
    (payer, from, recipient, to)
}

/// Genesis funding for the cross-shard VM cast: the payer funded, the
/// recipient seeded with dust so its vault cell exists before the
/// transfer rather than being created by it.
#[must_use]
pub fn cross_shard_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let (_payer, from, to) = cross_shard_cast();
    vec![(from, 10_000), (to, 10)]
}

/// What one payer's vault is funded with when two withdrawals off it are
/// meant to be individually covered and jointly uncoverable.
pub const OVERDRAW_FUNDING: u128 = 10_000;

/// One withdrawal of an [`OVERDRAW_CAST`](overdraw_cast) pair: covered
/// on its own, uncoverable beside its sibling.
pub const OVERDRAW_AMOUNT: u128 = 6_000;

/// The cast of two withdrawals off one vault into separate remote
/// vaults: the payer on `leaf(1, 0)`, two distinct recipients on
/// `leaf(1, 1)`.
///
/// Distinct recipients so the two credits land on different cells —
/// what the pair measures is the payer's reservation, not the
/// recipients' deposits.
#[must_use]
pub fn overdraw_cast() -> (
    Ed25519PrivateKey,
    PrincipalAddr,
    PrincipalAddr,
    PrincipalAddr,
) {
    let mut taken = Vec::new();
    let (payer, from) = account_routing_to(ShardId::leaf(1, 0), &mut taken);
    let (_, first) = account_routing_to(ShardId::leaf(1, 1), &mut taken);
    let (_, second) = account_routing_to(ShardId::leaf(1, 1), &mut taken);
    (payer, from, first, second)
}

/// Genesis funding for [`overdraw_cast`]: the payer holding less than the
/// two withdrawals together, each recipient holding dust.
#[must_use]
pub fn overdraw_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let (_, from, first, second) = overdraw_cast();
    vec![(from, OVERDRAW_FUNDING), (first, 10), (second, 10)]
}

/// The cast of a cross-shard leg followed by a local one over the same
/// cell: the remote payer on `leaf(1, 0)`, a payer on `leaf(1, 1)`, and
/// the recipient they both credit, also on `leaf(1, 1)`.
#[must_use]
pub fn shared_recipient_cast() -> (
    Ed25519PrivateKey,
    PrincipalAddr,
    Ed25519PrivateKey,
    PrincipalAddr,
    PrincipalAddr,
) {
    let mut taken = Vec::new();
    let (remote_payer, remote_from) = account_routing_to(ShardId::leaf(1, 0), &mut taken);
    let (local_payer, local_from) = account_routing_to(ShardId::leaf(1, 1), &mut taken);
    let (_, to) = account_routing_to(ShardId::leaf(1, 1), &mut taken);
    (remote_payer, remote_from, local_payer, local_from, to)
}

/// Genesis funding for [`shared_recipient_cast`]: both payers covered for
/// their payment and its fee ceiling, the shared recipient holding dust.
#[must_use]
pub fn shared_recipient_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let (_, remote_from, _, local_from, to) = shared_recipient_cast();
    vec![(remote_from, 10_000), (local_from, 10_000), (to, 10)]
}

/// The nullifier race's cast: two composers who each fund a request, and
/// the account that signed it.
///
/// Distinct seeds from every other VM scenario's, so the shared statics
/// registry admits them all without collision.
#[must_use]
pub fn nullifier_race_cast() -> (Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey) {
    (
        signer_from_seed(191),
        signer_from_seed(192),
        signer_from_seed(193),
    )
}

/// Genesis funding for the nullifier race: both composers covered for
/// the payment and its fee ceiling, the requesting account holding dust.
#[must_use]
pub fn nullifier_race_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let (first, second, requester) = nullifier_race_cast();
    vec![
        (account_address(&first.public_key().0), 10_000),
        (account_address(&second.public_key().0), 10_000),
        (account_address(&requester.public_key().0), 10),
    ]
}

/// The cross-shard fault family's cast, over the depth-1 split.
///
/// One funded account in each child, so a transfer runs in either
/// direction over the pair, plus an intra-shard control pair per child.
/// The controls must be disjoint from the crossing pair: a transfer
/// between the crossing accounts would declare the same vault cells as
/// the in-flight cross-shard tick and queue behind it instead of proving
/// the shard still settles locally.
pub struct CrossShardFaultCast {
    /// The payer and account in `leaf(1, 0)`.
    pub left: (Ed25519PrivateKey, PrincipalAddr),
    /// The payer and account in `leaf(1, 1)`.
    pub right: (Ed25519PrivateKey, PrincipalAddr),
    /// One intra-shard control per child: `(payer key, payer, recipient)`,
    /// both accounts in the same child.
    pub controls: Vec<(Ed25519PrivateKey, PrincipalAddr, PrincipalAddr)>,
}

/// Build the cross-shard fault family's cast.
#[must_use]
pub fn cross_shard_fault_cast() -> CrossShardFaultCast {
    let mut taken = Vec::new();
    let left = account_routing_to(ShardId::leaf(1, 0), &mut taken);
    let right = account_routing_to(ShardId::leaf(1, 1), &mut taken);
    let controls = [ShardId::leaf(1, 0), ShardId::leaf(1, 1)]
        .into_iter()
        .map(|shard| {
            let (key, payer) = account_routing_to(shard, &mut taken);
            let (_, recipient) = account_routing_to(shard, &mut taken);
            (key, payer, recipient)
        })
        .collect();
    CrossShardFaultCast {
        left,
        right,
        controls,
    }
}

/// Genesis accounts for the cross-shard fault family.
///
/// Every account is funded: the crossing pair pays in both directions, so
/// each is a payer as well as a recipient, and a control recipient must
/// exist before a deposit can land in it.
#[must_use]
pub fn cross_shard_fault_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let cast = cross_shard_fault_cast();
    let mut accounts = vec![(cast.left.1, 10_000), (cast.right.1, 10_000)];
    for (_, payer, recipient) in &cast.controls {
        accounts.push((*payer, 10_000));
        accounts.push((*recipient, 10));
    }
    accounts
}

/// Genesis funding for the insolvent-payer scenario: the same cast as
/// [`cross_shard_genesis_accounts`], but the payer holds dust — below
/// any transfer's signed fee ceiling.
#[must_use]
pub fn insolvent_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let (_payer, from, to) = cross_shard_cast();
    vec![(from, 10), (to, 10)]
}

/// A lottery instance whose settled-round cell lands on `shard`.
///
/// An instance's address is the hash of its package, configuration and
/// salt, and its address *is* its placement, so putting one on a chosen
/// shard is a scan over salts — the same grind an account's signing seed
/// takes, one derivation along.
///
/// # Panics
///
/// Panics if no salt in the `u8` space lands on `shard`.
#[must_use]
pub fn lottery_on(shard: ShardId) -> InstanceMeta {
    let trie = ShardTrie::uniform_from_count(2);
    for salt in 0..=u8::MAX {
        let meta = InstanceMeta {
            package: lottery_package_hash(&ProtocolHasher),
            config: Vec::new(),
            salt: Hash32([salt; 32]),
        };
        if trie.shard_for_prefix(meta.address(&ProtocolHasher).address()) == shard {
            return meta;
        }
    }
    panic!("no lottery salt lands on {shard:?}");
}

/// Seal the lotteries: one node per instance, each writing its own
/// creation-fixed record into its configuration leaf.
///
/// What makes a derivable component actual, and a transaction of its own
/// because a presence condition is judged against committed state — the
/// leaf has to be there before any call's fence can find it.
///
/// # Panics
///
/// If the scenario world does not answer the seal, which would be a
/// defect in the world rather than in the seal.
#[must_use]
pub fn build_instantiate_tx(
    payer: &Ed25519PrivateKey,
    lotteries: &[InstanceMeta],
    validity: TimestampRange,
) -> Transaction {
    let client = client();
    let chain = client.records();
    let composed = Composed::new(&chain, lotteries, &ProtocolHasher);
    let addresses: Vec<_> = lotteries
        .iter()
        .map(|meta| meta.address(&ProtocolHasher))
        .collect();
    let founder = account_address(&payer.public_key().0);
    let (mut env, mut root) = EnvelopeBuilder::new(
        &composed,
        &ProtocolHasher,
        founder,
        scenario_header(validity),
    );
    for address in addresses {
        instantiate(&mut root, founder, address, ()).expect("a derivable lottery answers its seal");
    }
    for meta in lotteries {
        env.register_instance(meta.clone());
    }
    env.seal(root)
        .expect("the root declares nothing to discharge")
        .none()
        .expect("the root declares no socket");
    let tree = env.build().expect("the intent declares no hole");

    Transaction::new(client.sign_tree(
        &tree,
        Vec::new(),
        payer,
        Terms {
            max_fee: MAX_FEE,
            validity,
            message: Vec::new(),
        },
    ))
}

/// Build a cross-shard draw: two lottery instances, one per shard,
/// settling their rounds in one transaction — so the two recorded draws
/// are equal exactly when the two committees executed under one value.
///
/// Each round's result is an exclusive write, so each shard owes the
/// other the prior value of the cell it owns — the read-set-provisioned
/// shape, in both directions.
///
/// One intent and one signature, because a draw is public: the payer
/// signs the fee and nothing else is anyone's to authorize. That is the
/// package's own point rather than a convenience here — the value the
/// round turns on is not a signer's to choose.
///
/// # Panics
///
/// If the scenario world does not answer a draw, which would be a defect
/// in the world rather than in the draw.
#[must_use]
pub fn build_close_tx(
    payer: &Ed25519PrivateKey,
    lotteries: &[InstanceMeta],
    validity: TimestampRange,
) -> Transaction {
    build_lottery_tx(payer, lotteries, validity, &|round, root| {
        round.close(root).expect("a lottery answers a close");
    })
}

/// A cross-shard settlement over every round named, each on its own
/// shard.
///
/// # Panics
///
/// If the scenario world does not answer a settlement, which would be a
/// defect in the world rather than in the settlement.
#[must_use]
pub fn build_draw_tx(
    payer: &Ed25519PrivateKey,
    lotteries: &[InstanceMeta],
    validity: TimestampRange,
) -> Transaction {
    build_lottery_tx(payer, lotteries, validity, &|round, root| {
        round
            .settle(root, 64)
            .expect("a lottery answers a settlement");
    })
}

/// One leg per round named, on whichever shard each lives.
///
/// # Panics
///
/// If the scenario world does not answer the leg.
fn build_lottery_tx(
    payer: &Ed25519PrivateKey,
    lotteries: &[InstanceMeta],
    validity: TimestampRange,
    leg: &dyn Fn(&lottery::Lottery, &mut TypedBuilder<'_>),
) -> Transaction {
    let client = client();
    // The composer knows each round's record and types the calls against
    // them; the envelope carries none, because the seals have committed
    // by the time this runs and the chain answers for the targets.
    let chain = client.records();
    let composed = Composed::new(&chain, lotteries, &ProtocolHasher);
    let addresses: Vec<_> = lotteries
        .iter()
        .map(|meta| meta.address(&ProtocolHasher))
        .collect();
    let (mut env, mut root) = EnvelopeBuilder::new(
        &composed,
        &ProtocolHasher,
        account_address(&payer.public_key().0),
        scenario_header(validity),
    );
    for address in addresses {
        leg(&lottery::Lottery::at(address), &mut root);
    }
    env.seal(root)
        .expect("the root declares nothing to discharge")
        .none()
        .expect("the root declares no socket");
    let tree = env.build().expect("the intent declares no hole");

    Transaction::new(client.sign_tree(
        &tree,
        Vec::new(),
        payer,
        Terms {
            max_fee: MAX_FEE,
            validity,
            message: Vec::new(),
        },
    ))
}

/// Build a transfer at the scenario fee terms: the account guest's
/// withdraw+deposit graph, wrapped in a single-intent envelope signed by
/// `payer`.
///
/// The transaction hash covers the whole signed envelope — validity
/// window included — so distinct submissions differ in signed content;
/// byte-identical envelopes are one transaction, which is the hash-dedup
/// replay protection working as designed.
///
/// # Panics
///
/// If the scenario world does not answer a transfer, which would be a
/// defect in the world rather than in the transfer.
#[must_use]
pub fn build_transfer_tx<S: AccountSigner>(
    payer: &S,
    from: PrincipalAddr,
    to: PrincipalAddr,
    amount: u128,
    validity: TimestampRange,
) -> Transaction {
    let graph = client()
        .transfer_graph(from, to, amount)
        .expect("the stdlib account answers a transfer");
    Transaction::new(envelope(graph, payer, validity))
}

/// Build a transfer whose fee payer's account is not the signing key's
/// own.
///
/// The payer field names `payer`, and whether the signer's identity may
/// spend it is the payer shard's binding verdict — refused where the
/// payer's rule does not admit it, engaged where it does.
///
/// # Panics
///
/// If the scenario world does not answer a transfer, which would be a
/// defect in the world rather than in the transfer.
#[must_use]
pub fn build_transfer_paid_by<S: AccountSigner>(
    signer: &S,
    from: PrincipalAddr,
    to: PrincipalAddr,
    amount: u128,
    payer: PrincipalAddr,
    validity: TimestampRange,
) -> Transaction {
    let client = client();
    let graph = client
        .transfer_graph(from, to, amount)
        .expect("the stdlib account answers a transfer");
    let envelope = signing::wrap(
        &EnvelopeTree {
            root: IntentDecl {
                header: scenario_header(validity),
                graph,
                sockets: Vec::new(),
            },
            root_bindings: Vec::new(),
            subintents: Vec::new(),
            instances: Vec::new(),
            resources: Vec::new(),
        },
        Vec::new(),
        payer,
        client.network(),
        signing::Terms {
            max_fee: MAX_FEE,
            gas_limit: DEFAULT_GAS_LIMIT,
            validity_start_ms: validity.start_timestamp_inclusive.as_millis(),
            validity_end_ms: validity.end_timestamp_exclusive.as_millis(),
            message: Vec::new(),
        },
    );
    Transaction::new(
        signing::sign(envelope, signer, &ProtocolHasher)
            .expect("a composed envelope stays within the wire caps"),
    )
}

/// Build a transfer whose fee payer is somebody else's account, which
/// the signer's key does not open — the unbound case of
/// [`build_transfer_paid_by`], where the binding must refuse.
#[must_use]
pub fn build_unbound_payer_tx(
    signer: &Ed25519PrivateKey,
    from: PrincipalAddr,
    to: PrincipalAddr,
    payer: PrincipalAddr,
    validity: TimestampRange,
) -> Transaction {
    build_transfer_paid_by(signer, from, to, 5, payer, validity)
}

/// The unbound-payer cast: the signer's key and account on `leaf(1, 0)`,
/// the recipient on `leaf(1, 1)`, and a victim account also on
/// `leaf(1, 0)` that the signer's key does not open.
#[must_use]
pub fn unbound_payer_cast() -> (
    Ed25519PrivateKey,
    PrincipalAddr,
    PrincipalAddr,
    PrincipalAddr,
) {
    let mut taken = Vec::new();
    let (signer, from) = account_routing_to(ShardId::leaf(1, 0), &mut taken);
    let (_, to) = account_routing_to(ShardId::leaf(1, 1), &mut taken);
    let (_, victim) = account_routing_to(ShardId::leaf(1, 0), &mut taken);
    (signer, from, to, victim)
}

/// Genesis funding for the unbound-payer cast: everyone funded, the
/// victim well past any fee ceiling — so the only thing that can refuse
/// the transaction is the payer binding, never solvency.
#[must_use]
pub fn unbound_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let (_signer, from, to, victim) = unbound_payer_cast();
    vec![(from, 10_000), (to, 10), (victim, 10_000)]
}

/// The remote unbound-payer cast: the whole manifest — signer, sender,
/// recipient — on `leaf(1, 1)`, and the victim payer on `leaf(1, 0)`.
///
/// The payer's shard is touched through no key but the payer's own —
/// the fee vault and the stored-authority cell — so its binding verdict
/// stands alone rather than beside a manifest leg.
#[must_use]
pub fn unbound_remote_payer_cast() -> (
    Ed25519PrivateKey,
    PrincipalAddr,
    PrincipalAddr,
    PrincipalAddr,
) {
    let mut taken = Vec::new();
    let (signer, from) = account_routing_to(ShardId::leaf(1, 1), &mut taken);
    let (_, to) = account_routing_to(ShardId::leaf(1, 1), &mut taken);
    let (_, victim) = account_routing_to(ShardId::leaf(1, 0), &mut taken);
    (signer, from, to, victim)
}

/// Genesis funding for the remote unbound-payer cast, on the same
/// terms as [`unbound_genesis_accounts`].
#[must_use]
pub fn unbound_remote_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let (_signer, from, to, victim) = unbound_remote_payer_cast();
    vec![(from, 10_000), (to, 10), (victim, 10_000)]
}

/// The securify cast.
///
/// The account to be securified and its founding ed25519 key on
/// `leaf(1, 0)`, the rule holder's key and account on `leaf(1, 1)`, and
/// a recipient on `leaf(1, 1)` for the transfers that prove who pays.
///
/// The holder's key is ML-DSA-65, which is what makes this the migration
/// an account actually performs: the address the founding key derived
/// keeps its balance and its placement, and the identity governing it
/// afterwards is post-quantum. A rule names an address and an address
/// commits to a scheme, so nothing between the two knows which happened.
#[must_use]
pub fn securify_cast() -> (
    Ed25519PrivateKey,
    PrincipalAddr,
    MlDsa65PrivateKey,
    PrincipalAddr,
    PrincipalAddr,
) {
    let mut taken = Vec::new();
    let (owner_key, owner) = account_routing_to(ShardId::leaf(1, 0), &mut taken);
    let (_, to) = account_routing_to(ShardId::leaf(1, 1), &mut taken);
    let (holder_key, holder) = ml_dsa_account_routing_to(ShardId::leaf(1, 1), &mut Vec::new());
    (owner_key, owner, holder_key, holder, to)
}

/// Genesis funding for the securify cast.
///
/// The account is funded well past every ceiling it will pay, and the
/// recipient's starting balance is a constant the scenario counts
/// deposits from. The holder is deliberately unfunded — its account is
/// an identity, and identities are addresses.
#[must_use]
pub fn securify_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let (_owner_key, owner, _holder_key, _holder, to) = securify_cast();
    vec![(owner, 10_000), (to, 10)]
}

/// The native post-quantum cast.
///
/// An account whose founding key is ML-DSA-65 on `leaf(1, 0)`, and a
/// recipient on `leaf(1, 1)` so what it pays for crosses shards.
///
/// The counterpart to [`securify_cast`]: nothing here migrates, because
/// there is no classical key to migrate off. The address the ML-DSA key
/// derives *is* the account, and it opens by signature alone — a virtual
/// account's rule is the identity its own address derives.
#[must_use]
pub fn native_pq_cast() -> (MlDsa65PrivateKey, PrincipalAddr, PrincipalAddr) {
    let (payer_key, payer) = ml_dsa_account_routing_to(ShardId::leaf(1, 0), &mut Vec::new());
    let (_, to) = account_routing_to(ShardId::leaf(1, 1), &mut Vec::new());
    (payer_key, payer, to)
}

/// Genesis funding for the native post-quantum cast.
///
/// Genesis funds an address, and an address is where a scheme has
/// already been folded in — so a post-quantum account is seeded by the
/// same call that seeds a classical one, with nothing to say about
/// which it is.
#[must_use]
pub fn native_pq_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let (_payer_key, payer, to) = native_pq_cast();
    vec![(payer, 10_000), (to, 10)]
}

/// Build the securify transaction: `owner`'s key signs its account over
/// to the rule requiring `holder`'s identity.
///
/// # Panics
///
/// If the scenario world does not answer a securify, which would be a
/// defect in the world rather than in the transition.
#[must_use]
pub fn build_securify_tx(
    owner_key: &Ed25519PrivateKey,
    owner: PrincipalAddr,
    holder: PrincipalAddr,
    validity: TimestampRange,
) -> Transaction {
    let graph = client()
        .securify_graph(owner, holder, 86_400_000)
        .expect("the stdlib account answers a securify");
    Transaction::new(envelope(graph, owner_key, validity))
}

/// Every stake pool any scenario in this crate seats.
///
/// One list for the whole crate because the client that types every
/// scenario's graphs is built once: a pool is an instance keyed by its
/// configuration, so unlike an account — resolved by its address class —
/// it has to be in the world a call is typed against. Seating a pool
/// writes no genesis state and a pool nobody delegates to emits nothing,
/// so recognising one everywhere costs a registry entry.
#[must_use]
pub fn world_pools() -> Vec<StakePoolSeat> {
    staking_pools()
}

/// The badge sale's buyer.
///
/// An account funded on the shard the genesis pool does not live on, so
/// operating after the sale is a cross-shard custody transaction — the
/// holdings provisioned from the buyer's shard, the vote leaf written
/// on the pool's.
#[must_use]
pub fn badge_buyer() -> (Ed25519PrivateKey, PrincipalAddr) {
    off_genesis_pool_shard(0)
}

/// A delegator whose stake into the genesis pool crosses shards.
///
/// An account on the shard the genesis pool does not live on, so its
/// withdrawal is an inbound leg and the pool — which takes the funds and
/// hands back units — is a core elsewhere. The one shape among the
/// scenario builders where the payer's shard waits on another's verdict.
#[must_use]
pub fn remote_delegator() -> (Ed25519PrivateKey, PrincipalAddr) {
    off_genesis_pool_shard(1)
}

/// The `index`th account grinded onto the shard the genesis pool does
/// not live on.
fn off_genesis_pool_shard(index: usize) -> (Ed25519PrivateKey, PrincipalAddr) {
    let trie = ShardTrie::uniform_from_count(2);
    let pool_shard = trie.shard_for_prefix(pool_at(GENESIS_POOL_ID));
    let shard = if pool_shard == ShardId::leaf(1, 0) {
        ShardId::leaf(1, 1)
    } else {
        ShardId::leaf(1, 0)
    };
    let mut taken = Vec::new();
    (0..=index)
        .map(|_| account_routing_to(shard, &mut taken))
        .last()
        .expect("at least one account is grinded")
}

/// Sell the genesis pool: withdraw its owner badge from the seller's
/// holdings and deposit it into `buyer`'s. An ordinary NF transfer —
/// which is the point.
#[must_use]
pub fn build_badge_sale_tx(
    seller: &Ed25519PrivateKey,
    buyer: PrincipalAddr,
    validity: TimestampRange,
) -> Transaction {
    let pool = pool_at(GENESIS_POOL_ID);
    let graph = graph(account_address(&seller.public_key().0), |b| {
        let seller = account_address(&seller.public_key().0);
        let funds = account::withdraw_nf(b, seller, pool_owner_badge(pool), &[OWNER_BADGE_ID])?;
        account::deposit_nf(b, buyer, funds)
    });
    Transaction::new(envelope(graph, seller, validity))
}

/// The publishers a deploy storm spams from: one per depth-1 shard, so
/// the storm lands on both committees at once.
#[must_use]
pub fn storm_publishers() -> Vec<(Ed25519PrivateKey, PrincipalAddr)> {
    let mut taken = Vec::new();
    vec![
        account_routing_to(ShardId::leaf(1, 0), &mut taken),
        account_routing_to(ShardId::leaf(1, 1), &mut taken),
    ]
}

/// Genesis funding for the storm publishers.
///
/// Publishing is priced per artifact byte, so a publisher needs orders
/// more than a payment sender: the balances the transfer scenarios use
/// would not cover one deploy.
#[must_use]
pub fn storm_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    storm_publishers()
        .into_iter()
        .map(|(_, address)| (address, STORM_FUNDING))
        .collect()
}

/// What a storm publisher is funded with, and the ceiling each publish
/// signs. Placeholder pricing, sized to cover the stdlib-shaped artifact
/// the storm deploys.
pub const STORM_FUNDING: u128 = 100_000_000;
const PUBLISH_MAX_FEE: u128 = 1_000_000;

/// The `nonce`-th distinct publishable artifact.
///
/// The stdlib guest carrying a metadata section that differs only in one
/// event name, so every variant is a different content address and
/// therefore a different package — which is what makes a storm a storm
/// rather than one publish repeated idempotently.
///
/// # Panics
///
/// Panics if the metadata does not attach, which would be a defect in
/// the codec rather than a runtime condition.
#[must_use]
pub fn storm_artifact(nonce: u16) -> Vec<u8> {
    // The staking package rather than the account: a published package
    // serves instances, and a component becomes actual through the seal
    // its own package declares — which the account, serving principals,
    // has no reason to carry.
    let mut metadata = staking::metadata();
    // An event is a name and a shape, so the name that varies the address
    // arrives with the empty one — what an event carrying nothing
    // declares.
    let named = format!("storm-{nonce}");
    metadata
        .types
        .insert(named.clone(), TypeShape::Tuple(Vec::new()));
    metadata.events.push(named);
    // The mark is granted to protocol code seeded at genesis, and this
    // artifact publishes through the ordinary path.
    for signature in metadata.methods.values_mut() {
        if signature.totality == Totality::Total {
            signature.totality = Totality::Infallible;
        }
    }
    attach_metadata(STAKING_MODULE, &metadata).expect("storm metadata attaches")
}

/// Build a signed publish of `artifact`, paid for by `payer` from their
/// own account — the publisher and the payer are the same signer.
#[must_use]
pub fn build_publish_tx(
    payer: &Ed25519PrivateKey,
    artifact: Vec<u8>,
    validity: TimestampRange,
) -> Transaction {
    Transaction::new(
        TransactionEnvelope {
            body: TransactionBody::Publish(artifact),
            subintent_sigs: Vec::new(),
            fee_payer: account_address(&payer.public_key().0),
            max_fee: PUBLISH_MAX_FEE,
            gas_limit: 1_000_000,
            validity_start_ms: validity.start_timestamp_inclusive.as_millis(),
            validity_end_ms: validity.end_timestamp_exclusive.as_millis(),
            message: Vec::new(),
            network: SCENARIO_NETWORK,
            signer_scheme: SchemeId::NONE,
            signer: Vec::new(),
            signature: Vec::new(),
        }
        .sign(payer),
    )
}

/// The instance record a call to `artifact`'s package presents.
///
/// An instance is computed rather than created: its address is the hash
/// of the package, the config it is bound to, and the salt that
/// distinguishes it from every other instance of the same code. Nothing
/// is registered anywhere — the envelope carries the record, and every
/// node composes the same registry from it.
#[must_use]
pub fn published_instance(artifact: &[u8], salt: u8, founder: PrincipalAddr) -> InstanceMeta {
    // The staking package's own configuration: what a delegation is
    // denominated in, and who may bring the component up. The founder is
    // folded into the address, so the caller that seals it is fixed
    // before the transaction exists.
    InstanceMeta {
        package: package_hash(&ProtocolHasher, artifact),
        config: vec![
            Value::Address((*XRD).address()),
            Value::Address(founder.address()),
        ],
        salt: Hash32([salt; 32]),
    }
}

/// The fee a scenario venue takes: thirty basis points, at the scale the
/// pool's bounded fee type holds.
const VENUE_FEE: u128 = 30 * (1_000_000_000_000_000_000 / 10_000);

/// The metadata of a venue trading `pair` whose address routes to
/// `shard`.
///
/// A venue's address derives from its package, its configuration and a
/// salt, so a venue on one shard in particular asks for the salt that
/// puts it there.
///
/// # Panics
///
/// If no salt in a byte lands the venue on `shard`, which would mean the
/// derivation had stopped spreading addresses.
#[must_use]
pub fn venue_on(shard: ShardId, pair: (ResourceAddr, ResourceAddr)) -> InstanceMeta {
    // The uniform trie the target leaf belongs to, so a venue grinds onto
    // a shard of whatever depth the world has.
    let trie = ShardTrie::uniform_from_count(1u64 << shard.depth());
    for salt in 0..=u8::MAX {
        let meta = InstanceMeta {
            package: amm_package_hash(&ProtocolHasher),
            config: vec![
                Value::Address(pair.0.address()),
                Value::Address(pair.1.address()),
                Value::U128(VENUE_FEE),
            ],
            salt: Hash32([salt; 32]),
        };
        if trie.shard_for_prefix(meta.address(&ProtocolHasher).address()) == shard {
            return meta;
        }
    }
    panic!("no venue salt lands on {shard:?}");
}

/// Stock a venue: both sides withdrawn from one account, handed in
/// together, and the claim they mint filed back.
///
/// One transaction because the curve prices a pair — a pool holding one
/// side quotes against an empty reserve, which is the shape its own
/// refusal exists to name.
///
/// # Panics
///
/// If the scenario world does not answer the call, which would be a
/// defect in the world rather than in the call.
#[must_use]
pub fn build_add_liquidity_tx(
    payer: &Ed25519PrivateKey,
    from: PrincipalAddr,
    venue: &InstanceMeta,
    pair: (ResourceAddr, ResourceAddr),
    sides: (u128, u128),
    validity: TimestampRange,
) -> Transaction {
    build_venue_tx(payer, venue, validity, &|pool, b| {
        let x = account::withdraw(b, from, pair.0, sides.0)?;
        let y = account::withdraw(b, from, pair.1, sides.1)?;
        let claim = pool.add_liquidity(b, x, y)?;
        account::deposit(b, from, claim)
    })
}

/// A swap: withdraw one side, hand it to the venue, bank what comes
/// back.
///
/// The shape the whole venue question is about: the withdraw is a leg
/// on the caller's shard, the pricing is the core on the venue's, and
/// the deposit is a delivery back — so the caller is the leg and the
/// venue the core, as a stake into a remote pool is.
///
/// # Panics
///
/// If the scenario world does not answer the call, which would be a
/// defect in the world rather than in the call.
#[must_use]
pub fn build_swap_tx(
    payer: &Ed25519PrivateKey,
    from: PrincipalAddr,
    venue: &InstanceMeta,
    paying: ResourceAddr,
    amount: u128,
    min_out: u128,
    validity: TimestampRange,
) -> Transaction {
    build_venue_tx(payer, venue, validity, &|pool, b| {
        let funds = account::withdraw(b, from, paying, amount)?;
        let bought = pool.swap(b, funds, min_out)?;
        account::deposit(b, from, bought)
    })
}

/// A two-hop route: withdraw one side, price it at the first venue,
/// price what comes back at the second, and bank the result.
///
/// `second_min_out` is the floor the second hop holds out for — zero to
/// take whatever it is quoted, and more than the pool can pay to make
/// the route refuse at its second venue, where a refusal has the most to
/// take back.
///
/// The shape a multi-shard core takes. Both venues are core — a swap
/// prices against reserves it also writes, so neither is reservation
/// shaped nor total — and where they sit on different shards the core
/// spans both and each awaits the other's certificate.
///
/// # Panics
///
/// If the scenario world does not answer either call.
#[must_use]
pub fn build_route_tx(
    payer: &Ed25519PrivateKey,
    from: PrincipalAddr,
    venues: (&InstanceMeta, &InstanceMeta),
    paying: ResourceAddr,
    amount: u128,
    second_min_out: u128,
    validity: TimestampRange,
) -> Transaction {
    let metas = [venues.0.clone(), venues.1.clone()];
    build_venues_tx(payer, &metas, validity, &|pools, b| {
        let funds = account::withdraw(b, from, paying, amount)?;
        let mid = pools[0].swap(b, funds, 0)?;
        let out = pools[1].swap(b, mid, second_min_out)?;
        account::deposit(b, from, out)
    })
}

/// One call against a sealed venue, typed against the record the seal
/// wrote.
fn build_venue_tx(
    payer: &Ed25519PrivateKey,
    venue: &InstanceMeta,
    validity: TimestampRange,
    leg: &dyn Fn(&amm::Amm, &mut TypedBuilder<'_>) -> Result<(), TypedError>,
) -> Transaction {
    build_venues_tx(payer, std::slice::from_ref(venue), validity, &|pools, b| {
        leg(&pools[0], b)
    })
}

/// What a route does with the venues an envelope composed: one closure
/// over all of them, so a hop can hand its output to the next.
type VenueRoute<'a> = dyn Fn(&[amm::Amm], &mut TypedBuilder<'_>) -> Result<(), TypedError> + 'a;

/// One call against every venue in `venues`, each typed against the
/// record its own seal wrote.
///
/// The composer is handed all of them at once, which is what lets a
/// route hand one venue's output to the next: a call types against the
/// record the chain answers with, and a bucket only names a producer the
/// same envelope declares.
///
/// # Panics
///
/// If the scenario world does not answer the call.
fn build_venues_tx(
    payer: &Ed25519PrivateKey,
    venues: &[InstanceMeta],
    validity: TimestampRange,
    route: &VenueRoute<'_>,
) -> Transaction {
    let client = client();
    let chain = client.records();
    let composed = Composed::new(&chain, venues, &ProtocolHasher);
    let pools: Vec<amm::Amm> = venues
        .iter()
        .map(|venue| amm::Amm::at(venue.address(&ProtocolHasher)))
        .collect();
    let (mut env, mut root) = EnvelopeBuilder::new(
        &composed,
        &ProtocolHasher,
        account_address(&payer.public_key().0),
        scenario_header(validity),
    );
    route(&pools, &mut root).expect("every venue call types against its signature");
    env.seal(root)
        .expect("the root declares nothing to discharge")
        .none()
        .expect("the root declares no socket");
    let tree = env.build().expect("the intent declares no hole");

    Transaction::new(client.sign_tree(
        &tree,
        Vec::new(),
        payer,
        Terms {
            max_fee: MAX_FEE,
            validity,
            message: Vec::new(),
        },
    ))
}

/// Build the seal of an instance of a runtime-published package.
///
/// Untyped, because the signature this types against lives in metadata
/// the scenario's own client learns only from the chain it is driving;
/// the graph is the same shape the typed builder would emit.
///
/// This is the probe the artifact fetch has to answer, and instantiation
/// is the first call anyone makes on a published package: the code runs
/// on the shard holding the component, which is not in general the
/// publisher's own, so unless the artifact reached that committee the
/// call cannot run at all.
///
/// # Panics
///
/// If the graph does not build, which would be a defect here rather than
/// in the chain.
#[must_use]
pub fn build_instance_instantiate_tx(
    payer: &Ed25519PrivateKey,
    artifact: &[u8],
    salt: u8,
    validity: TimestampRange,
) -> Transaction {
    let founder = account_address(&payer.public_key().0);
    let meta = published_instance(artifact, salt, founder);
    let component = meta.address(&ProtocolHasher);

    // Bringing up is one node: the founder its configuration names signs
    // in, the seal mints the owner badge the component comes up holding,
    // and that edge is filed in the founder's own account.
    let mut b = GraphBuilder::new();
    let [] = b.call_signed(founder, "authorize", ());
    let [badge] = b.call_bearing(component, "instantiate", (), 0);
    let owner_badge = issued_resource(
        &ProtocolHasher,
        component,
        ResourceKind::NonFungible,
        staking::OWNER_BADGE,
    );
    let [] = b.call(founder, "deposit-nf", (badge.resource_is(owner_badge),));
    let graph = b.build().expect("every output is consumed");

    let tree = EnvelopeTree {
        root: IntentDecl {
            header: scenario_header(validity),
            graph,
            sockets: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
        instances: vec![meta],
        resources: Vec::new(),
    };
    Transaction::new(client().sign_tree(
        &tree,
        Vec::new(),
        payer,
        Terms {
            max_fee: MAX_FEE,
            validity,
            message: Vec::new(),
        },
    ))
}

/// The identifier the beacon folds the VM staking scenario's pool under.
///
/// Distinct from the genesis pool every seated validator belongs to, so a
/// delegation through the VM is the only source of this pool's stake and
/// the assertion cannot be satisfied by anything else.
pub const STAKE_POOL_ID: StakePoolId = StakePoolId::new(7777);

/// The delegator's signing key and account.
#[must_use]
pub fn delegator() -> (Ed25519PrivateKey, PrincipalAddr) {
    let key = signer_from_seed(180);
    let account = account_address(&key.public_key().0);
    (key, account)
}

/// What the delegator holds at genesis.
///
/// The beacon's stake floor is denominated in whole tokens and the
/// witness scenarios move multiples of it, so the delegator has to hold
/// stake-scale funds rather than the token amounts the transfer
/// scenarios use. Sized above every delegation any scenario makes plus
/// their fees.
pub const DELEGATOR_FUNDING: u128 = 40 * MIN_STAKE_FLOOR.attos();

/// Genesis accounts for the staking scenarios.
///
/// The delegator is funded well above its delegations and their fee
/// ceilings; the operator is funded for the fees its own actions cost —
/// an operator action moves no funds, but it still pays to be included.
#[must_use]
pub fn staking_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    vec![
        (delegator().1, DELEGATOR_FUNDING),
        (pool_operator().1, MAX_FEE * 64),
    ]
}

/// The identifier the beacon folds the second staking pool under.
pub const SECOND_POOL_ID: StakePoolId = StakePoolId::new(7778);

/// The identifier beacon genesis creates the founding pool under.
///
/// Beacon genesis creates that pool and its members; seating an instance
/// for it is what gives it an operator, which is how a deployment retires
/// a founding validator. Nothing else about the pool changes — its stake
/// and its membership are still genesis's.
pub const GENESIS_POOL_ID: StakePoolId = StakePoolId::new(0);

/// The cell a stake pool keeps its delegations in: the pool's declared
/// vault of the resource it is configured to hold, under the pool's own
/// address.
#[must_use]
pub fn pool_vault_cell(pool: ComponentAddr) -> SubstateKey {
    child_key(
        &ProtocolHasher,
        pool.address(),
        SlotId(staking::Pool::SLOT),
        &[Value::Address(XRD.address()).canonical_bytes()],
    )
}

/// Where genesis seats the pool with `id` — derived from the record, so
/// a scenario names a pool the way genesis places it.
#[must_use]
pub fn pool_at(id: StakePoolId) -> ComponentAddr {
    let seat = StakePoolSeat {
        id,
        operator: pool_operator().1,
        founding: Vec::new(),
    };
    pool_address(package_hash(&ProtocolHasher, staking_artifact()), &seat)
}

/// The pools a staking cluster seats.
///
/// Both name the same operator, which is an entity running two pools
/// rather than a shortcut: what a pool's operator field admits is
/// exercised where it can be isolated, and here the interesting question
/// is what two *pools* may say about each other.
#[must_use]
pub fn staking_pools() -> Vec<StakePoolSeat> {
    let operator = pool_operator().1;
    vec![
        StakePoolSeat {
            id: STAKE_POOL_ID,
            operator,
            founding: Vec::new(),
        },
        StakePoolSeat {
            id: SECOND_POOL_ID,
            operator,
            founding: Vec::new(),
        },
        // The founding pool's members are the beacon's to name, and
        // genesis fills them in from its own folded state.
        StakePoolSeat {
            id: GENESIS_POOL_ID,
            operator,
            founding: Vec::new(),
        },
    ]
}

/// Retire `validator`, which `pool` must operate.
#[must_use]
pub fn build_deactivate_tx(
    operator: &Ed25519PrivateKey,
    pool: ComponentAddr,
    validator: ValidatorId,
    validity: TimestampRange,
) -> Transaction {
    let graph = graph(account_address(&operator.public_key().0), |b| {
        let proof = account::present_instance(
            b,
            account_address(&operator.public_key().0),
            pool_owner_badge(pool),
            OWNER_BADGE_ID,
        )?;
        b.presenting(proof, |b| {
            staking::Staking::at(pool).deactivate_validator(b, validator.inner())
        })
    });
    Transaction::new(envelope(graph, operator, validity))
}

/// Register `validator` against `pool`, carrying the consensus key it
/// will be known by and the proof it holds that key.
///
/// Signed by the badge holder, whose presentation of the pool's owner
/// badge is the whole of the action's authority: the operator surface
/// admits exactly that identity, and the custody gate refuses a
/// presenter who does not hold it.
#[must_use]
pub fn build_register_tx(
    operator: &Ed25519PrivateKey,
    pool: ComponentAddr,
    validator: ValidatorId,
    pubkey: &ConsensusPublicKey,
    possession_proof: &ConsensusSignature,
    validity: TimestampRange,
) -> Transaction {
    let graph = graph(account_address(&operator.public_key().0), |b| {
        let proof = account::present_instance(
            b,
            account_address(&operator.public_key().0),
            pool_owner_badge(pool),
            OWNER_BADGE_ID,
        )?;
        b.presenting(proof, |b| {
            staking::Staking::at(pool).register_validator(
                b,
                validator.inner(),
                *pubkey.as_bytes(),
                *possession_proof.as_bytes(),
            )
        })
    });
    Transaction::new(envelope(graph, operator, validity))
}

/// Return `amount` worth of stake units to `pool`, moving that much of
/// the delegator's position into the pool's unbonding total.
///
/// The units are withdrawn from the delegator's own account like any
/// other balance — a staking position is an ordinary fungible holding,
/// so unwinding one is an ordinary withdrawal.
#[must_use]
pub fn build_unstake_tx(
    delegator: &Ed25519PrivateKey,
    from: PrincipalAddr,
    pool: ComponentAddr,
    amount: u128,
    validity: TimestampRange,
) -> Transaction {
    let graph = graph(account_address(&delegator.public_key().0), |b| {
        let units = account::withdraw(b, from, stake_unit(pool), amount)?;
        staking::Staking::at(pool).unstake(b, units)
    });
    Transaction::new(envelope(graph, delegator, validity))
}

/// The principal the staking scenario's pool admits on its operator
/// surface, and the key that satisfies it.
#[must_use]
pub fn pool_operator() -> (Ed25519PrivateKey, PrincipalAddr) {
    let key = signer_from_seed(181);
    let account = account_address(&key.public_key().0);
    (key, account)
}

/// Build a delegation: withdraw `amount` from the delegator's native
/// vault, stake it into the pool, and bank the units the pool issues.
///
/// The units are an ordinary fungible balance in the delegator's own
/// account, which is what makes a staking position something a holder can
/// hold rather than a record only the pool can read.
#[must_use]
pub fn build_stake_tx(
    delegator: &Ed25519PrivateKey,
    from: PrincipalAddr,
    pool: ComponentAddr,
    amount: u128,
    validity: TimestampRange,
) -> Transaction {
    let graph = graph(account_address(&delegator.public_key().0), |b| {
        let funds = account::withdraw(b, from, *XRD, amount)?;
        let units = staking::Staking::at(pool).stake(b, funds)?;
        account::deposit(b, from, units)
    });
    Transaction::new(envelope(graph, delegator, validity))
}

/// The one-time payment request `signer` puts their name to: whoever
/// hands them at least `amount` XRD, they will bank it.
///
/// A declaration and nothing else — no envelope, no fee terms, no
/// composer. Its hash is a function of this content alone, which is what
/// lets the signer sign it before any composer exists and lets two
/// composers bind the identical declaration afterwards.
#[must_use]
pub fn payment_request(signer: PrincipalAddr, amount: u128) -> IntentDecl {
    declaration(signer, |b| {
        let incoming = b.declare(*XRD, [Constraint::MinAmount(amount)]);
        account::deposit(b, signer, incoming)
    })
}

/// [`payment_request`] standing only for `window`.
///
/// The nullifier a spend of it takes lives for that window plus
/// [`ARTIFACT_GRACE_MS`](hyperscale_vm_types::ARTIFACT_GRACE_MS), so a
/// request signed for a transaction-shaped window yields a nullifier a
/// scenario's clock can outrun and watch the sweep retire.
#[must_use]
pub fn payment_request_for(
    signer: PrincipalAddr,
    amount: u128,
    window: TimestampRange,
) -> IntentDecl {
    declaration_under(signer, scenario_header(window), |b| {
        let incoming = b.declare(*XRD, [Constraint::MinAmount(amount)]);
        account::deposit(b, signer, incoming)
    })
}

/// Compose `request` — signed by `signer_key`, whose account is the
/// request's target — into a transaction that fills it from `from`.
///
/// The composer withdraws the funds and yields them to the request; the
/// request deposits them. Committing spends the request's nullifier
/// under its signer's prefix, so two compositions carrying one request
/// contend on that key and exactly one settles.
///
/// # Panics
///
/// Panics if the composed envelope does not derive, which would be a
/// defect in the builder rather than a runtime condition.
#[must_use]
pub fn build_composed_tx(
    composer: &Ed25519PrivateKey,
    from: PrincipalAddr,
    signer_key: &Ed25519PrivateKey,
    request: &IntentDecl,
    amount: u128,
    validity: TimestampRange,
) -> Transaction {
    // The signer signs its own declaration's hash, which no part of the
    // envelope enters — the composer binds it afterwards and signs the
    // whole, subintent signatures included.
    let signed = sign_subintent(signer_key, &request.hash(&ProtocolHasher).0.0);

    let client = client();
    let chain = client.records();
    let (mut env, mut root) = EnvelopeBuilder::new(
        &chain,
        &ProtocolHasher,
        account_address(&composer.public_key().0),
        scenario_header(validity),
    );
    let funds =
        account::withdraw(&mut root, from, *XRD, amount).expect("an account answers a withdrawal");
    let paid = root.export(funds);
    let wants = env
        .adopt(account_address(&signer_key.public_key().0), request.clone())
        .expect("the request discharges its own hole")
        .one()
        .expect("the request declares one parameter");
    env.seal(root)
        .expect("the composer declares no hole")
        .none()
        .expect("the composer declares no socket");
    env.bind(wants, paid)
        .expect("the request's hole takes an edge");
    let tree = env.build().expect("the request's hole is bound");

    Transaction::new(client.sign_tree(
        &tree,
        vec![signed],
        composer,
        Terms {
            max_fee: 1_000,
            validity,
            message: Vec::new(),
        },
    ))
}

/// The fee ceiling every built call envelope signs.
///
/// A placeholder awaiting measured pricing, but a load-bearing one: the
/// payer shard's reservation check demands
/// the ceiling be coverable, so it must sit below the funded balances, and a
/// scenario probing for a stale reservation sizes its funding against it.
pub const MAX_FEE: u128 = 1_000;

/// The network every built envelope names: both harnesses run the
/// simulator definition, and admission refuses an envelope naming any
/// other network.
pub const SCENARIO_NETWORK: NetworkId = NetworkId(242);

/// The client every scenario transaction is built through: the world its
/// pools are seated in, and the one network both harnesses run.
///
/// Built once because seating pools admits the stdlib artifacts, and the
/// seat list is the same for every scenario in the binary.
fn client() -> &'static Client {
    static CLIENT: LazyLock<Client> = LazyLock::new(|| {
        Client::new(
            genesis_world_with_pools(&world_pools(), &GenesisPackages::with_fixtures()),
            SCENARIO_NETWORK,
        )
    });
    &CLIENT
}

/// Build a graph against the scenario world, so every call is typed by
/// the signature it names and every edge carries the resource that
/// signature declares.
///
/// # Panics
///
/// If a call does not type or an output dangles, which is a defect in the
/// builder rather than a runtime condition.
fn graph(
    signer: PrincipalAddr,
    write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>,
) -> ManifestGraph {
    let client = client();
    let chain = client.records();
    let mut b = client.builder(&chain, signer);
    write(&mut b).expect("every scenario call types against its signature");
    b.build().expect("every output is consumed")
}

/// Build a declaration against the scenario world, for its own signer to
/// sign and a composer to present later.
///
/// # Panics
///
/// As [`graph`].
fn declaration(
    signer: PrincipalAddr,
    write: impl FnOnce(&mut IntentBuilder<'_>) -> Result<(), TypedError>,
) -> IntentDecl {
    declaration_under(signer, offer_header(), write)
}

/// [`declaration`] for a signer who names its own terms.
///
/// A standing offer runs the whole cap, which is what
/// [`offer_header`] gives and what most scenarios want. One that stands
/// only as long as the composition binding it produces a nullifier whose
/// life a scenario can outrun, which is what a sweep needs to observe.
fn declaration_under(
    signer: PrincipalAddr,
    header: IntentHeader,
    write: impl FnOnce(&mut IntentBuilder<'_>) -> Result<(), TypedError>,
) -> IntentDecl {
    let client = client();
    let chain = client.records();
    let mut decl = IntentBuilder::declaration(&chain, &ProtocolHasher, signer, header);
    write(&mut decl).expect("every scenario call types against its signature");
    decl.into_decl()
        .expect("the declaration discharges its own holes")
}

/// Wrap a single-intent graph in a signed envelope at the scenario fee
/// terms, with no message.
fn envelope<S: AccountSigner>(
    graph: ManifestGraph,
    payer: &S,
    validity: TimestampRange,
) -> TransactionEnvelope {
    client().sign(
        graph,
        payer,
        Terms {
            max_fee: MAX_FEE,
            validity,
            message: Vec::new(),
        },
    )
}

/// Cast the founding pool's vote to retune the reshape `split_bytes`,
/// activating at `activate_at`.
///
/// The founding pool holds every genesis validator's stake, so one vote
/// is a majority. Raising `split_bytes` lifts the derived `merge_bytes`
/// above a grown topology's children so they fall under the merge
/// threshold.
///
/// Every governed parameter travels, not just the one being changed: a
/// vote is a whole proposal, and the tally buckets by the exact pair, so
/// a vote that omitted the others would be voting to reset them.
#[must_use]
pub fn build_reshape_threshold_vote_tx(
    operator: &Ed25519PrivateKey,
    split_bytes: u64,
    activate_at: Epoch,
    validity: TimestampRange,
) -> Transaction {
    let graph = graph(account_address(&operator.public_key().0), |b| {
        let proof = account::present_instance(
            b,
            account_address(&operator.public_key().0),
            pool_owner_badge(pool_at(GENESIS_POOL_ID)),
            OWNER_BADGE_ID,
        )?;
        b.presenting(proof, |b| {
            staking::Staking::at(pool_at(GENESIS_POOL_ID)).cast_param_vote(
                b,
                split_bytes,
                NetworkParams::default().impound_epochs,
                activate_at.inner(),
            )
        })
    });
    Transaction::new(envelope(graph, operator, validity))
}

#[cfg(test)]
mod tests {
    use hyperscale_types::NetworkDefinition;

    use super::*;

    /// The hardcoded scenario network is the simulator definition's id;
    /// drifting apart would have every built envelope refused at
    /// admission.
    #[test]
    fn the_scenario_network_is_the_simulators() {
        assert_eq!(
            SCENARIO_NETWORK,
            NetworkId::from(&NetworkDefinition::simulator())
        );
    }
}
