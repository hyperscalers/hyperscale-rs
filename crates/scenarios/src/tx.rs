//! Portable transaction builders.
//!
//! These construct a [`RoutableTransaction`] from explicit inputs and so are
//! harness-agnostic; account discovery and the submit routing live in the
//! adaptors. A scenario submits the result via [`Cluster::submit`].
//!
//! [`Cluster::submit`]: crate::Cluster::submit

use std::time::Duration;

use hyperscale_types::{
    Ed25519PrivateKey, RoutableTransaction, TimestampRange, WeightedTimestamp,
    ed25519_keypair_from_seed, routable_from_notarized_v1, sign_and_notarize,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;

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
