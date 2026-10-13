//! Wire constants every stream and connection of the transport shares.

use hyperscale_types::{MessageClass, ShardId};
use iroh::endpoint::VarInt;

/// Protocol identifier of every connection between two hosts. A QUIC
/// connection negotiates one, so each host pair holds one connection and
/// tells its streams apart by their first byte.
pub const ALPN: &[u8] = b"hyperscale/1";

/// First byte of the stream that carries the validator bind handshake.
pub const STREAM_BIND: u8 = 1;

/// First byte of a unidirectional stream of notifications, all of one
/// class.
pub const STREAM_NOTIFY: u8 = 2;

/// First byte of a unidirectional stream of gossip, all of one class.
pub const STREAM_GOSSIP: u8 = 4;

/// First byte of a unidirectional stream that asks the peer for every
/// global gossip item it accepts. The stream carries nothing else; the
/// subscription lasts as long as it stays open.
pub const STREAM_SUBSCRIBE: u8 = 5;

/// Gossip frame scope byte: the frame is for every host.
pub const SCOPE_GLOBAL: u8 = 0;

/// Gossip frame scope byte: the frame is for one shard, whose id follows.
pub const SCOPE_SHARD: u8 = 1;

/// First byte of a bidirectional stream carrying one request and its
/// response.
pub const STREAM_REQUEST: u8 = 3;

/// Response status: the response frame follows.
pub const RESPONSE_OK: u8 = 0;

/// Response status: the responder does not serve the shard asked for.
pub const RESPONSE_SHARD_UNSUPPORTED: u8 = 1;

/// Response status: the responder serves the shard but has no handler for
/// the request type.
pub const RESPONSE_UNKNOWN_TYPE: u8 = 2;

/// Response status: the responder is at its concurrency limit for the
/// requester.
pub const RESPONSE_BUSY: u8 = 3;

/// Response status: the path between the two hosts is relayed and does not
/// carry a response of this class.
pub const RESPONSE_RELAYED: u8 = 4;

/// Length of a shard id on the wire: its depth, then its path.
pub const SHARD_WIRE_LEN: usize = 4 + 8;

/// Stop code: the reader is not taking gossip from this peer for now.
pub const STOP_GOSSIP_REFUSED: VarInt = VarInt::from_u32(1);

/// Stop code: the reader holds as many subscribers as it allows.
pub const STOP_SUBSCRIBERS_FULL: VarInt = VarInt::from_u32(2);

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

/// The class a wire byte names.
pub fn class_from_byte(byte: u8) -> Option<MessageClass> {
    MessageClass::ALL.get(usize::from(byte)).copied()
}

/// Priority of a stream carrying `class`. The connection transmits buffered
/// data from a higher priority stream before any from a lower one, so a
/// queued bulk transfer never delays a consensus frame to the same peer.
pub const fn class_priority(class: MessageClass) -> i32 {
    match class {
        MessageClass::Consensus => 4,
        MessageClass::BlockCompletion => 3,
        MessageClass::CrossShardProgress => 2,
        MessageClass::Recovery => 1,
        MessageClass::Bulk => 0,
    }
}

/// Encode a shard id for a stream header.
pub fn encode_shard(shard: ShardId) -> [u8; SHARD_WIRE_LEN] {
    let mut bytes = [0u8; SHARD_WIRE_LEN];
    bytes[..4].copy_from_slice(&shard.depth().to_le_bytes());
    bytes[4..].copy_from_slice(&shard.path().to_le_bytes());
    bytes
}

/// Decode a shard id from a stream header, refusing bytes that name no
/// shard.
pub fn decode_shard(bytes: [u8; SHARD_WIRE_LEN]) -> Option<ShardId> {
    let depth = u32::from_le_bytes(bytes[..4].try_into().ok()?);
    let path = u64::from_le_bytes(bytes[4..].try_into().ok()?);
    let fits = if depth == 0 {
        path == 0
    } else {
        depth < 64 && path < (1u64 << depth)
    };
    fits.then(|| ShardId::leaf(depth, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_survives_its_wire_byte_and_orders_by_urgency() {
        for (index, class) in MessageClass::ALL.into_iter().enumerate() {
            assert_eq!(class_from_byte(class as u8), Some(class));
            if let Some(next) = MessageClass::ALL.get(index + 1) {
                assert!(class_priority(class) > class_priority(*next));
            }
        }
        assert_eq!(class_from_byte(5), None);
    }

    #[test]
    fn a_shard_id_survives_its_header_and_garbage_names_none() {
        for shard in [ShardId::ROOT, ShardId::leaf(1, 1), ShardId::leaf(63, 7)] {
            assert_eq!(decode_shard(encode_shard(shard)), Some(shard));
        }

        let mut too_deep = [0u8; SHARD_WIRE_LEN];
        too_deep[..4].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(decode_shard(too_deep), None);

        let mut path_past_depth = encode_shard(ShardId::leaf(1, 1));
        path_past_depth[4] = 2;
        assert_eq!(decode_shard(path_past_depth), None);

        let mut root_with_path = encode_shard(ShardId::ROOT);
        root_with_path[4] = 1;
        assert_eq!(decode_shard(root_with_path), None);
    }
}
