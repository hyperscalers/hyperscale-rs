//! Domain-separated signing for cryptographic operations.
//!
//! This module provides type-safe domain separation tags for all signed messages
//! in the consensus protocol. Domain separation prevents cross-protocol attacks
//! where a signature from one context could be replayed in another.
//!
//! # Domain Tags
//!
//! Each signable message type has a unique domain tag prefix:
//!
//! | Tag | Purpose |
//! |-----|---------|
//! | `BLOCK_VOTE` | shard consensus block votes |
//! | `BLOCK_HEADER` | Block header proposal gossip |
//! | `COMMITTED_BLOCK_HEADER` | Committed block header gossip |
//! | `STATE_PROVISION_BATCH` | Cross-shard state provisions gossip |
//! | `VALIDATOR_BIND` | Validator-bind `PeerId` authentication |
//! | `VALIDATOR_ADDRESS` | Validator address announcement gossip |
//! | `EXEC_VOTE` | Execution votes |
//! | `EXEC_VOTE_BATCH` | Execution vote batch gossip |
//! | `EXEC_CERT_BATCH` | Execution certificate batch gossip |
//! | `HYPERSCALE_READY_SIGNAL_v1` | Validator "ready on shard" signals |
//! | `HYPERSCALE_PC_VOTE{1,2,3}_v1` | Beacon PC inner-consensus votes |
//! | `HYPERSCALE_PC_VOTE2_LENGTH_v1` | Length attestation rider on PC round-2 |
//! | `HYPERSCALE_PC_EMPTY_VIEW_v1` | SPC empty-view skip statement |
//! | `HYPERSCALE_PC_VRF_v1` | Beacon VRF reveal (per-epoch randomness contribution) |
//! | `HYPERSCALE_RATIFY_VOTE_v1` | Epoch ratification vote + aggregated ratify cert sig |
//!
//! # Usage
//!
//! Each signable type pairs with a free `signing_message()` function that
//! constructs the bytes to sign by prepending its domain tag to the
//! serialized content.

mod beacon_pc;
mod beacon_ratify;
mod beacon_vrf;
mod execution;
mod provisions;
mod ready_signal;
mod shard;
mod shard_reveal;
mod validator_address;
mod validator_bind;

pub use beacon_pc::{
    DOMAIN_PC_EMPTY_VIEW, DOMAIN_PC_VOTE1, DOMAIN_PC_VOTE2, DOMAIN_PC_VOTE2_LENGTH,
    DOMAIN_PC_VOTE3, DOMAIN_SPC_NEW_COMMIT, DOMAIN_SPC_NEW_VIEW, PcContext, SpcContext, pc_context,
    pc_vote_signing_message, spc_context, spc_relay_signing_message,
};
pub use beacon_ratify::{DOMAIN_RATIFY_VOTE, ratify_vote_message};
pub use beacon_vrf::{
    DOMAIN_PC_VRF, vrf_output_from_proof, vrf_reveal_message, vrf_sign, vrf_verify,
};
pub use execution::{
    DOMAIN_EXEC_CERT_BATCH, DOMAIN_EXEC_VOTE, DOMAIN_EXEC_VOTE_BATCH, exec_cert_batch_message,
    exec_vote_batch_message, exec_vote_message,
};
pub use provisions::{DOMAIN_STATE_PROVISION_BATCH, state_provisions_message};
pub use ready_signal::{DOMAIN_READY_SIGNAL, ready_signal_message};
pub use shard::{
    DOMAIN_BLOCK_HEADER, DOMAIN_BLOCK_VOTE, DOMAIN_COMMITTED_BLOCK_HEADER, DOMAIN_TIMEOUT,
    block_header_message, block_vote_message, certified_block_header_message, timeout_message,
};
pub use shard_reveal::{
    DOMAIN_SHARD_REVEAL, shard_reveal_message, shard_reveal_sign, shard_reveal_verify,
};
pub use validator_address::{DOMAIN_VALIDATOR_ADDRESS, validator_address_message};
pub use validator_bind::{DOMAIN_VALIDATOR_BIND, VALIDATOR_BIND_NONCE_LEN, validator_bind_message};
