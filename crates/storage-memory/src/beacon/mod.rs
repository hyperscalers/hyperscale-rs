//! Beacon-side in-memory storage backend — `SimBeaconStorage`.

pub(crate) mod chain_reader;
pub(crate) mod chain_writer;
pub(crate) mod core;
pub(crate) mod ratify_registers;

#[cfg(test)]
mod tests;
