//! Beacon-side in-memory storage backend — `SimBeaconStorage`.

pub(crate) mod chain_reader;
pub(crate) mod chain_writer;
pub(crate) mod core;
mod instances;
pub(crate) mod packages;
mod ratify_registers;
mod vote_registers;

#[cfg(test)]
mod tests;
