//! Protocol state machines and inbound serve handlers used by the I/O loop.
//!
//! - [`fetch`] generic per-id fetch state machine, with per-payload bindings
//!   in [`binding`] and the I/O-loop-owned bundle in [`host`].
//! - [`sync`] block sync state machine.
//! - [`block_serve`] / [`provision_serve`] / [`transaction_serve`] inbound
//!   request handlers that serve cached state to peers.

pub mod binding;
pub mod block_serve;
pub mod fetch;
pub mod host;
pub mod provision_serve;
pub mod remote_header_serve;
pub mod sync;
pub mod transaction_serve;
