//! Parallel (non-deterministic) simulation for multi-core performance testing.
//!
//! Unlike the deterministic `hyperscale-simulation` crate which runs all nodes
//! sequentially on a single thread, this crate runs nodes in parallel using
//! rayon for multi-core CPU utilization.
//!
//! # Goals
//!
//! 1. **Multi-core Performance**: Utilize all available CPU cores via rayon
//! 2. **Simulated Time**: No wall-clock delays, timers fire instantly
//! 3. **Synchronous Processing**: Step-based simulation with explicit control
//! 4. **Feature Parity**: Support same network simulation features (latency, loss)
//!
//! # Non-Goals
//!
//! - **Determinism**: Results may vary between runs due to rayon scheduling
//! - **Replacing Deterministic Simulation**: Use `hyperscale-simulation` for correctness testing
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                        ParallelSimulator                                    │
//! │                      (step-based simulation loop)                           │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐                   │
//! │   │   SimNode 0   │  │   SimNode 1   │  │   SimNode 2   │  ...              │
//! │   │               │  │               │  │               │                   │
//! │   │  ┌─────────┐  │  │  ┌─────────┐  │  │  ┌─────────┐  │                   │
//! │   │  │ State   │  │  │  │ State   │  │  │  │ State   │  │                   │
//! │   │  │ Machine │  │  │  │ Machine │  │  │  │ Machine │  │                   │
//! │   │  └─────────┘  │  │  └─────────┘  │  │  └─────────┘  │                   │
//! │   │  ┌─────────┐  │  │  ┌─────────┐  │  │  ┌─────────┐  │                   │
//! │   │  │ Storage │  │  │  │ Storage │  │  │  │ Storage │  │                   │
//! │   │  └─────────┘  │  │  └─────────┘  │  │  └─────────┘  │                   │
//! │   └───────────────┘  └───────────────┘  └───────────────┘                   │
//! │                                                                             │
//! │   Step 1: Process all nodes in parallel (rayon par_iter_mut)                │
//! │   Step 2: Collect outbound messages                                         │
//! │   Step 3: Route messages to recipients                                      │
//! │   Step 4: Collect status updates                                            │
//! │   Step 5: Advance simulated time                                            │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Each step processes nodes in parallel using rayon, then synchronously
//! routes messages between nodes. Crypto verification is done inline
//! (synchronous) and timers fire instantly.

mod cache;
mod config;
mod metrics;
mod router;
mod simulator;

pub use config::ParallelConfig;
pub use metrics::SimulationReport;
pub use simulator::ParallelSimulator;
