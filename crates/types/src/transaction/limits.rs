//! Per-transaction wire limits.
//!
//! Hard caps applied at decode time on peer-supplied transaction
//! payloads. Bound the SBOR `Vec<u8>` / `Vec<NodeId>` pre-allocation a
//! single transaction can claim — independent of how many transactions
//! a block carries (which is governed by [`crate::block::limits`]).

/// Cap on `RoutableTransaction.tx_bytes` length at decode time.
///
/// Bounds the manifest payload a peer can pre-allocate via the SBOR
/// `Vec<u8>` fast path. Realistic transactions sit comfortably below
/// this; it exists to reject obviously malformed or oversized payloads
/// early instead of admitting them and stressing mempool / commit
/// pipelines.
pub const MAX_TX_BYTES_LEN: usize = 256 * 1024;

/// Cap on a transaction's declared read or write set length at decode
/// time.
///
/// Each `NodeId` is 30 bytes; this cap leaves ~120 KB of declared-set
/// allocation as the worst case. Tx authors with unusual access patterns
/// have ample headroom; everything beyond is rejected.
pub const MAX_DECLARED_NODES_PER_TX: usize = 4_096;
