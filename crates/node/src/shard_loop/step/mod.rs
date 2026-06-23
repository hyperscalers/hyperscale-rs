//! Per-category handlers for `NodeHost::step()`.
//!
//! Each submodule owns the handlers for one cluster of `NodeInput` variants,
//! plus the `NodeHost`-internal helpers that only those variants need. The
//! main `step()` match in [`super`] is a thin dispatcher that destructures
//! variant payloads and forwards to the appropriate `handle_*` method.

mod beacon_block_sync;
mod protocol_event;
mod remote_header_sync;
mod settled_set_sync;
mod tick;
mod tx_validation;
