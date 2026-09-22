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

pub mod abandonment;
pub mod beacon_witness;
pub mod certificate;
pub mod committed_txs;
pub mod leaf;
pub mod local_receipt;
pub mod provision_tx;
pub mod provisions;
pub mod reveal_chain;
pub mod settled_txs;
pub mod state;
pub mod state_claims;
pub mod terminal;
pub mod transaction;

pub use beacon_witness::{
    BeaconWitnessRootContext, BeaconWitnessRootVerifyError, commit_witness_window, derive_leaves,
    derive_reshape_trigger, missed_proposals_since_prev_commit, ready_leaf_payload,
};
pub use committed_txs::{
    CommittedTxAbsence, committed_tx_leaf, committed_txs_root_from_hashes,
    prove_committed_tx_absent,
};
pub use leaf::{LeafRoot, RootMismatch, SetRoot};
pub use provision_tx::{
    ProvisionTxRootsContext, ProvisionTxRootsMap, ProvisionTxRootsVerifyError, committed_crossings,
};
pub use reveal_chain::{REVEAL_CHAIN_DOMAIN_TAG, extend_reveal_chain, next_reveal_chain};
pub use settled_txs::{local_settled_tx_hashes, settled_txs_root_from_hashes};
pub use state::{SplitChildRoots, StateRootContext, StateRootVerifyError};
pub use terminal::TerminalRoots;
pub use transaction::{TransactionRootContext, TxRootVerifyError};
