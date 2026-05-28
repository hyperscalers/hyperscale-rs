//! Merkle root computation and verification for the per-block fields in
//! [`BlockHeader`](crate::BlockHeader).
//!
//! Each per-root type's verified form is `Verified<XRoot>`; predicate at
//! the `impl Verify<&XRootContext<'_>>` in the corresponding submodule.
//! Construction goes through one of three gates per type:
//!
//! - `Verified::<XRoot>::compute(data) -> Self` — produce the canonical
//!   root from leaf data. Infallible; verified-by-construction.
//! - `<XRoot as Verify>::verify(&self, ctx)` — recompute from data
//!   carried in `ctx` and compare against `self`. On success the
//!   returned wrapper carries `self`, which (by the predicate) equals
//!   `compute(data)`. The error reports the computed/claimed pair on
//!   mismatch.
//! - `Verified::<XRoot>::from_pipeline_attestation(root)` — re-wrap a
//!   root the verification pipeline's per-root tracking has already
//!   confirmed (skip case or previously-verified entry).
//!
//! [`state`] is the one outlier: it carries the JMT-replay byproduct
//! (`PreparedCommit`) in its `Verified<StateRoot, _>` augment slot.

pub mod beacon_witness;
pub mod certificate;
pub mod local_receipt;
pub mod provision_tx;
pub mod provisions;
pub mod state;
pub mod transaction;

pub use beacon_witness::{
    BeaconWitnessRootContext, BeaconWitnessRootVerifyError, derive_leaves,
    missed_proposals_since_prev_commit,
};
pub use certificate::{CertRootVerifyError, CertificateRootContext};
pub use local_receipt::{LocalReceiptRootContext, LocalReceiptRootVerifyError};
pub use provision_tx::{ProvisionTxRootsContext, ProvisionTxRootsMap, ProvisionTxRootsVerifyError};
pub use provisions::{ProvisionRootVerifyError, ProvisionsRootContext};
pub use state::{StateRootContext, StateRootVerifyError};
pub use transaction::{TransactionRootContext, TxRootVerifyError};
