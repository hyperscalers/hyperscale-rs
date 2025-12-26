//! Production networking via libp2p.
//!
//! This module provides the network layer for the production runner:
//!
//! - **Gossipsub** for efficient broadcast messaging (shard-scoped topics)
//! - **Request-Response** for sync block fetching
//! - **QUIC** transport for reliable, encrypted connections
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────┐
//! │                     Libp2pAdapter                              │
//! │                                                                │
//! │  ┌─────────────────────────────────────────────────────────┐  │
//! │  │  Swarm Task (background tokio task)                     │  │
//! │  │                                                         │  │
//! │  │  Gossipsub ─────► Topic routing ─────► Event channel    │  │
//! │  │  Kademlia  ─────► Peer discovery                        │  │
//! │  │  ReqResp   ─────► Sync requests/responses               │  │
//! │  └─────────────────────────────────────────────────────────┘  │
//! │                           │                                    │
//! │                           ▼                                    │
//! │  ┌─────────────────────────────────────────────────────────┐  │
//! │  │  ProductionRunner                                       │  │
//! │  │  - Receives Events via mpsc channel                     │  │
//! │  │  - Sends broadcasts via SwarmCommand channel            │  │
//! │  └─────────────────────────────────────────────────────────┘  │
//! └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Topics
//!
//! Messages are routed via gossipsub topics:
//! - Shard-scoped: `hyperscale/{msg_type}/shard-{id}/1.0.0`
//! - Global: `hyperscale/{msg_type}/1.0.0`
//!
//! Message type is determined by the topic, so no separate type field is needed
//! in the wire format.
//!
//! # Wire Format
//!
//! ```text
//! [version: u8][payload: SBOR-encoded message]
//! ```
//!
//! - Version is currently `1`
//! - Payload is the gossip struct (e.g., `BlockHeaderGossip`) encoded with SBOR

mod adapter;
mod codec;
mod config;
pub mod direct;
mod rate_limiter;
mod topic;

pub use adapter::{
    compute_peer_id_for_validator, derive_libp2p_keypair, InboundCertificateRequest,
    InboundSyncRequest, InboundTransactionRequest, Libp2pAdapter, NetworkError,
};
pub use config::{Libp2pConfig, VersionInteroperabilityMode};
pub use rate_limiter::{RateLimitConfig, SyncRateLimiter};
pub use topic::{ProtocolVersion, Topic};
