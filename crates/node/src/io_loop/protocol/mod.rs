//! Protocol state machines and inbound serve handlers used by the I/O loop.
//!
//! - [`fetch`] generic per-id fetch state machine, with per-payload bindings
//!   in [`fetch_instances`].
//! - [`sync`] block sync state machine + inbound block-request server handlers.
//! - [`provision_serve`] / [`transaction_serve`] inbound request handlers
//!   that serve cached state to peers.

pub mod binding;
pub mod fetch;
pub mod host;
pub mod provision_serve;
pub mod sync;
pub mod transaction_serve;
