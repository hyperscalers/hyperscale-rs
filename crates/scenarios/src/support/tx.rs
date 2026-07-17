//! Portable transaction builders.
//!
//! These construct a [`RoutableTransaction`] from explicit inputs and so are
//! harness-agnostic; account discovery and the submit routing live in the
//! adaptors. A scenario submits the result via [`Cluster::submit`].
//!
//! [`Cluster::submit`]: crate::Cluster::submit

use std::time::Duration;

use hyperscale_types::{
    BeaconWitnessEvent, Ed25519PrivateKey, Epoch, NetworkParams, NodeId, NotarizeOptions,
    ParamProposal, ParamVote, ReshapeThresholds, RoutableTransaction, ShardId, StakePoolId,
    TimestampRange, WeightedTimestamp, ed25519_keypair_from_seed, encode_system_action,
    routable_from_notarized_v1, sign_and_notarize, sign_and_notarize_with_options,
    uniform_shard_for_node,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use radix_transactions::model::{MessageContentsV1, MessageV1, PlaintextMessageV1};

/// A deterministic Ed25519 signer from a one-byte seed. A faucet transaction's
/// fee comes from the faucet, so any key notarizes it.
#[must_use]
pub fn signer_from_seed(seed: u8) -> Ed25519PrivateKey {
    ed25519_keypair_from_seed(&[seed; 32])
}

/// The preallocated account address for the [`signer_from_seed`] of `seed` —
/// the account that signer controls, so a genesis that funds this address can
/// be spent by that key.
#[must_use]
pub fn account_from_seed(seed: u8) -> ComponentAddress {
    ComponentAddress::preallocated_account_from_public_key(&signer_from_seed(seed).public_key())
}

/// The splitting shard of the grown surviving-sibling shape — `leaf(1, 0)`, the
/// heavier child the engine bootstrap concentrates substates into, which crosses
/// the voted-down threshold and terminates.
pub const STRADDLER_SPLITTER: ShardId = ShardId::leaf(1, 0);

/// The surviving sibling — `leaf(1, 1)`, the lighter child that stays under the
/// threshold. Straddler payers live here; their cross-shard waves name the
/// terminating splitter.
pub const STRADDLER_SURVIVOR: ShardId = ShardId::leaf(1, 1);

/// Bulk accounts funded into the splitter to reinforce the engine bootstrap's
/// natural low-prefix skew, so the splitter clears the voted-down threshold and
/// the survivor stays under it.
const STRADDLER_BULK: usize = 20;

/// Straddler pairs submitted across the splitter's grow — enough to span its
/// terminal cut: the earliest settle on it before it crosses, the latest name a
/// splitter that has already terminated.
pub const STRADDLER_COUNT: usize = 8;

/// The surviving shard of the depth-2 merge-straddler topology — `leaf(2, 0)`.
///
/// The heaviest engine-bootstrap quarter, bulk-funded over `merge_bytes` so its
/// sibling pair never merges. Straddler payers live here; their cross-shard
/// waves name the terminating merge-left child.
pub const MERGE_STRADDLER_SURVIVOR: ShardId = ShardId::leaf(2, 0);

/// The merge-left child — `leaf(2, 2)`.
///
/// Light enough to fall under `merge_bytes` and collapse into `leaf(1, 1)` with
/// its sibling. Straddler recipients live here, so the survivor's wave names the
/// shard that terminates at the merge.
pub const MERGE_STRADDLER_LEFT: ShardId = ShardId::leaf(2, 2);

/// The merge-right child — `leaf(2, 3)`, the lightest quarter, which merges with
/// [`MERGE_STRADDLER_LEFT`] into their parent `leaf(1, 1)`.
pub const MERGE_STRADDLER_RIGHT: ShardId = ShardId::leaf(2, 3);

/// Bulk accounts funded into the lighter surviving quarter `leaf(2, 1)`.
///
/// The engine bootstrap leaves `leaf(2, 1)` (~89k) below `merge_bytes`, so
/// without this it would emit an unpairable merge against its heavy sibling
/// `leaf(2, 0)` (~522k) and churn the schedule. Lifting it to ~403k keeps the
/// whole surviving pair above the threshold while the lighter merging pair stays
/// under it. The `u8`-seeded [`account_in_n`] tops out at 255 keys; this draws
/// from the wide `u64` seed space of [`bulk_fund_into`].
const MERGE_SURVIVOR_BULK: usize = 500;

/// Merge-straddler pairs submitted across the merge.
///
/// Each payer in the survivor `leaf(2, 0)`, each recipient in the merging
/// `leaf(2, 2)`. Submitted in two waves — the first settles before the
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

/// Genesis funding for the witness scenarios.
///
/// Funds the witness payer's account well above the fee any single system action
/// locks. Both adaptors install these so the witness bodies run identically on
/// either harness.
#[must_use]
pub fn witness_genesis_balances() -> Vec<(ComponentAddress, Decimal)> {
    vec![(
        account_from_seed(WITNESS_PAYER_SEED),
        Decimal::from(100_000),
    )]
}

/// Genesis funding for the halted-shard recovery scenario.
///
/// Both children of the root are bulk-funded into the stable band — above
/// the derived merge floor, below the split threshold, summing over it —
/// so the root splits exactly once and the grown pair holds: neither
/// child re-splits or asserts a merge half while the halt and its
/// recovery play out (a pending reshape would exempt the halted shard
/// from detection).
#[must_use]
pub fn halt_recovery_genesis_balances() -> Vec<(ComponentAddress, Decimal)> {
    let mut balances = vec![(
        account_from_seed(MERGE_VOTE_PAYER_SEED),
        Decimal::from(100_000),
    )];
    bulk_fund_into(ShardId::leaf(1, 0), 2, STRADDLER_BULK, &mut balances);
    bulk_fund_into(ShardId::leaf(1, 1), 2, STRADDLER_BULK, &mut balances);
    balances
}

/// Probe pairs per submission batch of the halted-shard straddler scenario.
///
/// Two transfers sourced on the surviving sibling into the halting shard,
/// one sourced on the halting shard itself, so both wave directions cross
/// each phase of the freeze.
pub const HALT_STRADDLER_BATCH: usize = 3;

/// The genesis funding and probe transfers for the halted-shard straddler
/// scenario.
///
/// The stable-band bulk of [`halt_recovery_genesis_balances`] plus three
/// probe batches (submitted before the fault installs, at the freeze edge,
/// and against the frozen shard) and a post-recovery transfer per
/// direction. One definition the adaptors and the scenario body share, so
/// the funded accounts cannot drift from the transfers spent against them.
pub struct HaltStraddlerSetup {
    /// Genesis XRD balances: the halt-recovery stable-band bulk plus every
    /// probe account.
    pub balances: Vec<(ComponentAddress, Decimal)>,
    /// Probe transfers in submission order, [`HALT_STRADDLER_BATCH`] per
    /// batch: `(payer key, payer account, recipient account)`.
    pub straddlers: Vec<(Ed25519PrivateKey, ComponentAddress, ComponentAddress)>,
    /// Transfers submitted after the recovery record clears, one per
    /// direction — the recovered shard's cross-shard rail must serve both.
    pub post_recovery: Vec<(Ed25519PrivateKey, ComponentAddress, ComponentAddress)>,
}

/// Build the halted-shard straddler genesis funding and probe transfers.
///
/// The halting `leaf(1, 0)` and surviving `leaf(1, 1)` keep the
/// [`halt_recovery_genesis_balances`] stable-band bulk; the probe accounts
/// ride on top, small enough to leave both children inside the band.
#[must_use]
pub fn halt_straddler_setup() -> HaltStraddlerSetup {
    fn transfer_pair(
        from: ShardId,
        to: ShardId,
        taken: &mut Vec<u8>,
        balances: &mut Vec<(ComponentAddress, Decimal)>,
    ) -> (Ed25519PrivateKey, ComponentAddress, ComponentAddress) {
        let (payer_key, payer) = account_in(from, taken);
        let (_, recipient) = account_in(to, taken);
        balances.push((payer, Decimal::from(10_000)));
        balances.push((recipient, Decimal::from(10_000)));
        (payer_key, payer, recipient)
    }

    let halting = ShardId::leaf(1, 0);
    let surviving = ShardId::leaf(1, 1);
    // The vote payer's seed is excluded from the probe draw — it already
    // carries the grow vote's nonce sequence.
    let mut taken = vec![MERGE_VOTE_PAYER_SEED];
    let mut balances = halt_recovery_genesis_balances();

    let mut straddlers = Vec::new();
    for _ in 0..3 {
        straddlers.push(transfer_pair(surviving, halting, &mut taken, &mut balances));
        straddlers.push(transfer_pair(surviving, halting, &mut taken, &mut balances));
        straddlers.push(transfer_pair(halting, surviving, &mut taken, &mut balances));
    }
    let post_recovery = vec![
        transfer_pair(surviving, halting, &mut taken, &mut balances),
        transfer_pair(halting, surviving, &mut taken, &mut balances),
    ];
    HaltStraddlerSetup {
        balances,
        straddlers,
        post_recovery,
    }
}

/// The genesis funding and straddler transfers for the merge-straddler scenario.
///
/// Mirrors [`SplitStraddlerSetup`] but for a four-shard topology: the surviving
/// quarter pair (`leaf(2, 0)`/`leaf(2, 1)`) is bulk-funded over `merge_bytes`,
/// the merging pair (`leaf(2, 2)`/`leaf(2, 3)`) is left under it, and the
/// straddlers run from the survivor into the merging left child. The funding is
/// installed at the single-shard genesis and partitions across the quarters as
/// the cluster grows.
pub struct MergeStraddlerSetup {
    /// Genesis XRD balances: survivor-pair bulk plus straddler payers in the
    /// survivor, straddler recipients in the merging left child.
    pub balances: Vec<(ComponentAddress, Decimal)>,
    /// Straddler transfers: `(payer key, payer account in the survivor,
    /// recipient in the merging left child)`.
    pub straddlers: Vec<(Ed25519PrivateKey, ComponentAddress, ComponentAddress)>,
}

/// The genesis funding and straddler transfers for the split-straddler scenario.
///
/// One definition both adaptors and the scenario body derive from, so the funded
/// accounts can't drift from the transfers spent against them.
pub struct SplitStraddlerSetup {
    /// Genesis XRD balances: bulk + straddler recipients in the splitter, payers
    /// in the survivor.
    pub balances: Vec<(ComponentAddress, Decimal)>,
    /// Straddler transfers: `(payer key, payer account in survivor, recipient in
    /// splitter)`.
    pub straddlers: Vec<(Ed25519PrivateKey, ComponentAddress, ComponentAddress)>,
}

/// A deterministic seeded account routing to `shard` under the two-shard uniform
/// trie the grow produces, skipping seeds already `taken`.
fn account_in(shard: ShardId, taken: &mut Vec<u8>) -> (Ed25519PrivateKey, ComponentAddress) {
    account_in_n(shard, 2, taken)
}

/// A deterministic seeded account routing to `shard` under the `num_shards`-wide
/// uniform trie, skipping seeds already `taken`.
fn account_in_n(
    shard: ShardId,
    num_shards: u64,
    taken: &mut Vec<u8>,
) -> (Ed25519PrivateKey, ComponentAddress) {
    for seed in 1u8..=u8::MAX {
        if taken.contains(&seed) {
            continue;
        }
        let key = ed25519_keypair_from_seed(&[seed; 32]);
        let address = ComponentAddress::preallocated_account_from_public_key(&key.public_key());
        let node = NodeId::from_radix(address.into_node_id());
        if uniform_shard_for_node(&node, num_shards) == shard {
            taken.push(seed);
            return (key, address);
        }
    }
    panic!("no account seed routes to {shard:?}");
}

/// The first seeded account routing to `shard` under a `num_shards`-wide
/// uniform trie, with its signing key — for tests that pin a payer or payee
/// to a specific leaf.
#[must_use]
pub fn account_routing_to(
    shard: ShardId,
    num_shards: u64,
) -> (Ed25519PrivateKey, ComponentAddress) {
    account_in_n(shard, num_shards, &mut Vec::new())
}

/// Push `count` funded accounts routing to `shard` under a `num_shards`-wide
/// trie onto `balances`, drawing from the wide `u64` seed space so a single
/// shard's prefix can be funded far past the `u8`-seeded [`account_in_n`] ceiling
/// — needed to lift a light quarter above `merge_bytes` so it stays a live leaf.
fn bulk_fund_into(
    shard: ShardId,
    num_shards: u64,
    count: usize,
    balances: &mut Vec<(ComponentAddress, Decimal)>,
) {
    let mut found = 0;
    let mut seed: u64 = 1;
    while found < count {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let key = ed25519_keypair_from_seed(&bytes);
        let address = ComponentAddress::preallocated_account_from_public_key(&key.public_key());
        let node = NodeId::from_radix(address.into_node_id());
        if uniform_shard_for_node(&node, num_shards) == shard {
            balances.push((address, Decimal::from(10_000)));
            found += 1;
        }
        seed += 1;
    }
}

/// Build the split-straddler genesis funding and straddler transfers.
///
/// The splitter (`leaf(1, 0)`) is funded over the voted-down threshold (bulk plus
/// straddler recipients), the survivor (`leaf(1, 1)`) under it (straddler
/// payers), so only the splitter crosses and terminates.
#[must_use]
pub fn split_straddler_setup() -> SplitStraddlerSetup {
    let mut taken = Vec::new();
    let mut balances = Vec::new();
    for _ in 0..STRADDLER_BULK {
        let (_, account) = account_in(STRADDLER_SPLITTER, &mut taken);
        balances.push((account, Decimal::from(10_000)));
    }
    let mut straddlers = Vec::new();
    for _ in 0..STRADDLER_COUNT {
        let (payer_key, payer) = account_in(STRADDLER_SURVIVOR, &mut taken);
        let (_, recipient) = account_in(STRADDLER_SPLITTER, &mut taken);
        balances.push((payer, Decimal::from(10_000)));
        balances.push((recipient, Decimal::from(10_000)));
        straddlers.push((payer_key, payer, recipient));
    }
    SplitStraddlerSetup {
        balances,
        straddlers,
    }
}

/// Build the merge-straddler genesis funding and straddler transfers.
///
/// Across the four-shard topology the surviving quarters (`leaf(2, 0)`/`leaf(2,
/// 1)`) are bulk-funded over the derived `merge_bytes` so neither auto-merges,
/// while the lighter merging pair (`leaf(2, 2)`/`leaf(2, 3)`) stays under it and
/// collapses into `leaf(1, 1)`. Straddler payers sit in the survivor
/// `leaf(2, 0)` and recipients in the merging `leaf(2, 2)`, so each cross-shard
/// wave names the shard that terminates at the merge.
#[must_use]
pub fn merge_straddler_setup() -> MergeStraddlerSetup {
    let num_shards = 4;
    let mut taken = Vec::new();
    let mut balances = vec![(
        account_from_seed(MERGE_VOTE_PAYER_SEED),
        Decimal::from(100_000),
    )];

    // Lift the naturally light survivor quarter `leaf(2, 1)` above `merge_bytes`:
    // its heavy sibling `leaf(2, 0)` already clears it, but `leaf(2, 1)` would
    // otherwise emit an unpairable merge and churn the schedule.
    bulk_fund_into(
        ShardId::leaf(2, 1),
        num_shards,
        MERGE_SURVIVOR_BULK,
        &mut balances,
    );

    let mut straddlers = Vec::new();
    for _ in 0..MERGE_STRADDLER_COUNT {
        let (payer_key, payer) = account_in_n(MERGE_STRADDLER_SURVIVOR, num_shards, &mut taken);
        let (_, recipient) = account_in_n(MERGE_STRADDLER_LEFT, num_shards, &mut taken);
        balances.push((payer, Decimal::from(10_000)));
        balances.push((recipient, Decimal::from(10_000)));
        straddlers.push((payer_key, payer, recipient));
    }
    MergeStraddlerSetup {
        balances,
        straddlers,
    }
}

/// Genesis XRD balances that seat a funded account in each child span of the
/// first root split: seed `31` lands in the left child, seed `30` in the right.
///
/// Both adaptors install these at genesis from this one definition so the
/// cross-shard scenarios spend `account_from_seed(31)` and `account_from_seed(30)`
/// across the two children identically on either harness — the funding can't
/// drift between sim and production.
#[must_use]
pub fn straddler_genesis_balances() -> Vec<(ComponentAddress, Decimal)> {
    vec![
        (account_from_seed(31), Decimal::from(10_000)),
        (account_from_seed(30), Decimal::from(10_000)),
    ]
}

/// The cross-shard accounts (`31` left, `30` right) plus two extra funded
/// accounts (`40`, `41`) for single-shard control transfers.
///
/// The inter-shard partition scenario needs control accounts *disjoint* from the
/// cross-shard pair: a self-transfer on `31` or `30` would collide with the
/// in-flight cross-shard wave's reserved writes and stall behind it, so the
/// controls run on `40` / `41` instead and settle purely intra-shard.
#[must_use]
pub fn intershard_partition_genesis_balances() -> Vec<(ComponentAddress, Decimal)> {
    vec![
        (account_from_seed(31), Decimal::from(10_000)),
        (account_from_seed(30), Decimal::from(10_000)),
        (account_from_seed(40), Decimal::from(10_000)),
        (account_from_seed(41), Decimal::from(10_000)),
    ]
}

/// Build a faucet-funded transfer.
///
/// The faucet pays the fee and supplies free XRD, deposited to `to`. Portable —
/// the faucet is a fixed native component on every network — so no
/// funded-account discovery is needed.
///
/// # Panics
///
/// Panics if signing or the routability conversion fails (malformed manifest).
#[must_use]
pub fn build_faucet_tx(
    to: ComponentAddress,
    signer: &Ed25519PrivateKey,
    network: &NetworkDefinition,
    nonce: u32,
    validity: TimestampRange,
) -> RoutableTransaction {
    let manifest = ManifestBuilder::new()
        .lock_fee_from_faucet()
        .get_free_xrd_from_faucet()
        .try_deposit_entire_worktop_or_abort(to, None)
        .build();
    let notarized = sign_and_notarize(manifest, network, nonce, signer).expect("faucet tx signs");
    routable_from_notarized_v1(notarized, validity).expect("faucet tx is routable")
}

/// A validity window bracketing `now`.
///
/// Opens 5 s before and closes 150 s after, well under Radix's ~5-minute
/// ceiling, so a transaction built with this window stays valid across a
/// reshape that shuffles placement meanwhile.
#[must_use]
pub fn validity_around(now: Duration) -> TimestampRange {
    TimestampRange::new(
        WeightedTimestamp::ZERO.plus(now.saturating_sub(Duration::from_secs(5))),
        WeightedTimestamp::ZERO.plus(now + Duration::from_secs(150)),
    )
}

/// Build a withdraw-from-`from`, deposit-to-`to` XRD transfer, signed and
/// notarized by `payer` and valid across `validity`.
///
/// # Panics
///
/// Panics if signing or the routability conversion fails — both fire only on a
/// malformed manifest (programmer error).
#[must_use]
pub fn build_transfer_tx(
    payer: &Ed25519PrivateKey,
    from: ComponentAddress,
    to: ComponentAddress,
    amount: Decimal,
    network: &NetworkDefinition,
    nonce: u32,
    validity: TimestampRange,
) -> RoutableTransaction {
    let manifest = ManifestBuilder::new()
        .lock_fee(from, Decimal::from(10))
        .withdraw_from_account(from, XRD, amount)
        .try_deposit_entire_worktop_or_abort(to, None)
        .build();
    let notarized = sign_and_notarize(manifest, network, nonce, payer).expect("transfer signs");
    routable_from_notarized_v1(notarized, validity).expect("transfer is routable")
}

/// Build a system-action transaction reporting `event` to the beacon.
///
/// A system action is a `lock_fee` no-op paid from `payer`'s account, carrying
/// the [`BeaconWitnessEvent`] in its plaintext message. It routes to the shard
/// owning that account; once committed, that shard witnesses the event to the
/// beacon over the usual rail and the beacon folds it. This is the path an
/// operator stakes, registers a validator, or votes through — the portable
/// counterpart of those flows.
///
/// `payer` must control a genesis-funded account so the fee lock succeeds — a
/// transaction whose fee fails witnesses nothing.
///
/// # Panics
///
/// Panics if signing or the routability conversion fails (malformed manifest).
#[must_use]
pub fn build_witness_tx(
    payer: &Ed25519PrivateKey,
    event: &BeaconWitnessEvent,
    network: &NetworkDefinition,
    nonce: u32,
    validity: TimestampRange,
) -> RoutableTransaction {
    let account = ComponentAddress::preallocated_account_from_public_key(&payer.public_key());
    let manifest = ManifestBuilder::new()
        .lock_fee(account, Decimal::from(10))
        .build();
    let message = MessageV1::Plaintext(PlaintextMessageV1 {
        mime_type: "application/octet-stream".to_string(),
        message: MessageContentsV1::Bytes(encode_system_action(event)),
    });
    let notarized = sign_and_notarize_with_options(
        manifest,
        network,
        nonce,
        NotarizeOptions {
            message,
            ..Default::default()
        },
        payer,
    )
    .expect("witness transaction signs");
    routable_from_notarized_v1(notarized, validity).expect("witness transaction is routable")
}

/// Build a stake-pool parameter vote that retunes the reshape `split_bytes`,
/// activating at `activate_at`.
///
/// Rides the system-action rail via [`build_witness_tx`]: the single genesis
/// stake pool (id 0) holds all stake, so one vote is a majority. Raising
/// `split_bytes` lifts the derived `merge_bytes` above a grown topology's
/// children so they fall under the merge threshold.
///
/// # Panics
///
/// Panics if signing or the routability conversion fails (malformed manifest).
#[must_use]
pub fn build_reshape_threshold_vote_tx(
    payer: &Ed25519PrivateKey,
    split_bytes: u64,
    activate_at: Epoch,
    network: &NetworkDefinition,
    nonce: u32,
    validity: TimestampRange,
) -> RoutableTransaction {
    let vote = BeaconWitnessEvent::ParamVote(ParamVote {
        pool: StakePoolId::new(0),
        proposal: Some(ParamProposal {
            params: NetworkParams {
                reshape_thresholds: ReshapeThresholds { split_bytes },
            },
            activate_at,
        }),
    });
    build_witness_tx(payer, &vote, network, nonce, validity)
}
