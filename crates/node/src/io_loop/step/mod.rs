//! Per-category handlers for `IoLoop::step()`.
//!
//! Each submodule owns the handlers for one cluster of `NodeInput` variants,
//! plus the `IoLoop`-internal helpers that only those variants need. The
//! main `step()` match in [`super`] is a thin dispatcher that destructures
//! variant payloads and forwards to the appropriate `handle_*` method.

mod fetch_delivery;
mod fetch_failure;
mod sync;
