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
    routable_from_notarized_v1, sign_and_notarize,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;

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
