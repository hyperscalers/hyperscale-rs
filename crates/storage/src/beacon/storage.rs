//! Umbrella trait composing the beacon storage capabilities.

use super::chain_reader::BeaconChainReader;
use super::chain_writer::BeaconChainWriter;
use super::packages::FetchedPackageStore;
use super::ratify_registers::RatifyRegisterStore;
use super::vote_registers::BeaconVoteRegisterStore;

/// Process-level beacon storage.
///
/// Composes [`BeaconChainReader`], [`BeaconChainWriter`], the
/// [`RatifyRegisterStore`] and [`BeaconVoteRegisterStore`] signing
/// registers, and [`FetchedPackageStore`] so a single `Arc<impl BeaconStorage>` can be
/// shared across every vnode's `BeaconCoordinator`. Blanket-impl'd for
/// any type satisfying the components — concrete backends just
/// implement the component traits.
pub trait BeaconStorage:
    BeaconChainReader
    + BeaconChainWriter
    + RatifyRegisterStore
    + BeaconVoteRegisterStore
    + FetchedPackageStore
{
}

impl<S> BeaconStorage for S where
    S: BeaconChainReader
        + BeaconChainWriter
        + RatifyRegisterStore
        + BeaconVoteRegisterStore
        + FetchedPackageStore
{
}
