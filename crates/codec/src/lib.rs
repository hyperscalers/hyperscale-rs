//! Codec facade for Hyperscale.
//!
//! All crates should import codec traits and functions through this crate
//! rather than depending on `sbor` directly. This centralizes the codec
//! dependency so a future migration has one place to change.

// Re-export everything from sbor's root (traits, functions, derive macros).
pub use sbor::*;

// Re-export the prelude module for `use hyperscale_codec::prelude::*;` patterns.
pub mod prelude {
    pub use sbor::prelude::*;
}
