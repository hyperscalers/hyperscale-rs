//! Portable transaction builders.
//!
//! These construct a [`RoutableTransaction`] from explicit inputs and so are
//! harness-agnostic; account discovery and the submit routing live in the
//! adaptors. A scenario submits the result via [`Cluster::submit`].
//!
//! [`Cluster::submit`]: crate::Cluster::submit

use std::time::Duration;

use hyperscale_types::{
    BeaconWitnessEvent, Ed25519PrivateKey, Epoch, NetworkParams, NotarizeOptions, ParamProposal,
    ParamVote, ReshapeThresholds, RoutableTransaction, StakePoolId, TimestampRange,
    WeightedTimestamp, ed25519_keypair_from_seed, encode_system_action, routable_from_notarized_v1,
    sign_and_notarize, sign_and_notarize_with_options,
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

/// Build a stake-pool parameter vote that retunes the reshape `split_bytes`,
/// activating at `activate_at`.
///
/// The vote rides the system-action rail: a `lock_fee` no-op paid by `payer`
/// carrying the `ParamVote` in its plaintext message. It routes to the shard
/// owning `payer`'s account, witnesses to the beacon, and the beacon tallies it.
/// The single genesis stake pool (id 0) holds all stake, so one vote is a
/// majority. Raising `split_bytes` lifts the derived `merge_bytes` above a grown
/// topology's children so they fall under the merge threshold.
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
    let account = ComponentAddress::preallocated_account_from_public_key(&payer.public_key());
    let manifest = ManifestBuilder::new()
        .lock_fee(account, Decimal::from(10))
        .build();
    let message = MessageV1::Plaintext(PlaintextMessageV1 {
        mime_type: "application/octet-stream".to_string(),
        message: MessageContentsV1::Bytes(encode_system_action(&vote)),
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
    .expect("vote transaction signs");
    routable_from_notarized_v1(notarized, validity).expect("vote is routable")
}
