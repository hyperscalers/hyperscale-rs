//! Umbrella trait composing the beacon storage capabilities.

use super::chain_reader::BeaconChainReader;
use super::chain_writer::BeaconChainWriter;
use super::ratify_registers::RatifyRegisterStore;

/// Process-level beacon storage.
///
/// Composes [`BeaconChainReader`], [`BeaconChainWriter`], and
/// [`RatifyRegisterStore`] so a single `Arc<impl BeaconStorage>` can be
/// shared across every vnode's `BeaconCoordinator`. Blanket-impl'd for
/// any type satisfying the components — concrete backends just
/// implement the component traits.
pub trait BeaconStorage: BeaconChainReader + BeaconChainWriter + RatifyRegisterStore {}

impl<S> BeaconStorage for S where S: BeaconChainReader + BeaconChainWriter + RatifyRegisterStore {}
