//! Per-transaction wire limits.
//!
//! Hard caps applied at decode time on peer-supplied transaction
//! payloads. Bound the wire pre-allocation a
//! single transaction can claim — independent of how many transactions
//! a block carries (which is governed by [`crate::shard::limits`]).

pub use hyperscale_vm_types::{MAX_ARTIFACT_BYTES, MAX_CALL_BYTES, MAX_ENVELOPE_BYTES};
