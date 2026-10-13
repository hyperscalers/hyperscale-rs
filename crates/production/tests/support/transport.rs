//! What the harnesses need from whichever network backend the build
//! compiles in, under one set of names.

#[cfg_attr(feature = "iroh", path = "transport/iroh.rs")]
#[cfg_attr(not(feature = "iroh"), path = "transport/libp2p.rs")]
mod backend;

pub use backend::{
    Bootstrap, DropSpec, HostId, HostKey, PeerKey, Rewrite, RuleHandle, TestFixtures,
    bootstrap_addr, new_host_key, peer_key, test_config,
};
