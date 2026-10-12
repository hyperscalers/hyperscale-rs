//! Terminal-lines response: a departed shard's terminal manifest with
//! what binds it to the terminal's hash.

use hyperscale_hbor::Hbor;

use crate::{MessageClass, NetworkMessage, TerminalLines};

/// The tick manifest of a terminated shard's terminal block.
///
/// Verified, not trusted bare: the requester holds the header to the
/// terminal's beacon-attested block hash, the section roots to the
/// header's body root and the lines to the manifest root among them, so
/// a server can neither drop a line nor add one.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetTerminalLinesResponse {
    /// The terminal's lines, or `None` when this peer doesn't hold the
    /// terminal block — the requester rotates to another
    /// terminal-committee member.
    pub lines: Option<TerminalLines>,
}

impl GetTerminalLinesResponse {
    /// The lines of the terminal asked about.
    #[must_use]
    pub const fn found(lines: TerminalLines) -> Self {
        Self { lines: Some(lines) }
    }

    /// This peer can't serve the requested terminal block.
    #[must_use]
    pub const fn not_found() -> Self {
        Self { lines: None }
    }
}

impl NetworkMessage for GetTerminalLinesResponse {
    fn message_type_id() -> &'static str {
        "terminal_lines.response"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Capped, from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{BlockHeader, BlockHeaderParts, Hash, SectionRoots, TickLine, TxHash};

    #[test]
    fn test_hbor_roundtrip_not_found() {
        let response = GetTerminalLinesResponse::not_found();
        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetTerminalLinesResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_hbor_roundtrip_found() {
        let tx = TxHash::from(Hash::from_bytes(b"ended tx"));
        let response = GetTerminalLinesResponse::found(TerminalLines {
            header: BlockHeader::new(BlockHeaderParts::default()),
            roots: SectionRoots::EMPTY,
            manifest: Capped::from_array([TickLine::End { tx }]),
        });
        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetTerminalLinesResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
