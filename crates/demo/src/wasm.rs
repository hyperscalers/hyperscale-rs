//! The JavaScript surface.
//!
//! Also installs the panic channel: wasm32 has no unwinding, so a panic
//! aborts the instance with a bare `unreachable` trap and the message is
//! lost. The hook stashes it in linear memory where the page can read it
//! back after the trap, which is the difference between a diagnosis and a
//! bisect.

use std::cell::RefCell;

use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::event::ShardPath;
use crate::session::{Session, SessionConfig};

thread_local! {
    static LAST_PANIC: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Capture panic messages for [`last_panic`]. Idempotent.
#[wasm_bindgen(start)]
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let message = format!("{info}");
        LAST_PANIC.with(|slot| *slot.borrow_mut() = message);
    }));
}

/// The most recent panic message, or empty if the session has not panicked.
#[wasm_bindgen]
#[must_use]
pub fn last_panic() -> String {
    LAST_PANIC.with(|slot| slot.borrow().clone())
}

/// A running cluster.
#[wasm_bindgen]
pub struct DemoSession {
    inner: Session,
}

#[wasm_bindgen]
impl DemoSession {
    /// Build a `shard_size`-validator cluster at `seed`, grown to `shards`
    /// leaves through the real split lifecycle, carrying `pool_spares`
    /// validators the splits do not consume.
    ///
    /// # Panics
    ///
    /// Panics if `shards` is not a power of two, or if the grow misses its
    /// epoch budget.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(seed: u32, shard_size: u32, max_shards: u32, pool_spares: u32) -> Self {
        Self {
            inner: Session::new(
                SessionConfig {
                    shard_size,
                    max_shards,
                    pool_spares,
                },
                u64::from(seed),
            ),
        }
    }

    /// Advance simulated time by `ms`, returning the events observed as a
    /// JavaScript array.
    ///
    /// # Errors
    ///
    /// Returns the serialization error if an event cannot be represented as a
    /// JavaScript value.
    pub fn step(&mut self, ms: u32) -> Result<JsValue, JsValue> {
        let events = self.inner.step(u64::from(ms));
        serde_wasm_bindgen::to_value(&events).map_err(Into::into)
    }

    /// Submit a protocol resource transfer between two funded accounts, returning its
    /// short label — the same one the resulting events carry.
    pub fn submit_transfer(&mut self) -> String {
        crate::event::TxLabel::from(self.inner.submit_transfer()).0
    }

    /// What each host serves, in host order — the roster the network view
    /// opens on. Every later move arrives as a `hostsChanged` event.
    ///
    /// # Errors
    ///
    /// Returns the serialization error if the roster cannot be represented
    /// as a JavaScript value.
    pub fn hosts(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.inner.hosts()).map_err(Into::into)
    }

    /// The shards currently served by at least one host, in trie order.
    ///
    /// # Errors
    ///
    /// Returns the serialization error if the shard list cannot be
    /// represented as a JavaScript value.
    pub fn shards(&self) -> Result<JsValue, JsValue> {
        let shards: Vec<ShardPath> = self
            .inner
            .live_shards()
            .into_iter()
            .map(ShardPath::from)
            .collect();
        serde_wasm_bindgen::to_value(&shards).map_err(Into::into)
    }
}
