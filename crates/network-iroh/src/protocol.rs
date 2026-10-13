//! Wire constants every stream and connection of the transport shares.

use iroh::endpoint::VarInt;

/// Protocol identifier of every connection between two hosts. A QUIC
/// connection negotiates one, so each host pair holds one connection and
/// tells its streams apart by their first byte.
pub const ALPN: &[u8] = b"hyperscale/1";

/// First byte of the stream that carries the validator bind handshake.
pub const STREAM_BIND: u8 = 1;

/// Close code: the validator bind handshake failed or timed out.
pub const CLOSE_BIND_FAILED: VarInt = VarInt::from_u32(1);

/// Close code: another connection between the same two hosts was kept.
pub const CLOSE_SUPERSEDED: VarInt = VarInt::from_u32(2);

/// Close code: the host is shutting down.
pub const CLOSE_SHUTDOWN: VarInt = VarInt::from_u32(3);

/// The version this build announces in the bind handshake.
pub fn local_version() -> &'static str {
    option_env!("HYPERSCALE_VERSION").unwrap_or("localdev")
}
