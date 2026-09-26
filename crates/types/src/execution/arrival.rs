//! The value a crossing brings to its consumer.

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::{ResourceAddr, SubstateKey};

/// One crossing's value arriving at its consumer, read off the producer's
/// proven record.
///
/// Per edge, not per resource: a sum would leave two edges carrying one
/// resource with no way to say which value fed which consumer, and the
/// consuming node takes its own argument rather than a share of a total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct EscrowedValue {
    /// The producing node.
    pub node: u32,
    /// Which of its outputs left.
    pub output: u32,
    /// The resource that left.
    pub resource: ResourceAddr,
    /// How much of it.
    pub amount: u128,
    /// The record cell the reading proved, under the producing node's
    /// target.
    pub record: SubstateKey,
}
