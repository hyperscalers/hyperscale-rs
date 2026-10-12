//! Terminal-lines request: the tick manifest of a departed shard's
//! terminal block.
//!
//! A terminal ends every accepted row it still holds by a line of its
//! manifest, so a surviving sibling reads which transactions the
//! departed shard had accepted off those lines. It names the terminal by
//! the height and block hash its own beacon fold records, and holds the
//! answer to that hash (see
//! [`TerminalLines::ended_under`](crate::TerminalLines::ended_under)).
//!
//! Asked apart from the settled-transaction window of the same terminal:
//! the lines are the terminal block's own and any holder of the block
//! answers whole, while the window is walked off the chain behind it and
//! can run short or over its cap.

use hyperscale_hbor::Hbor;

use crate::network::response::GetTerminalLinesResponse;
use crate::{BlockHash, BlockHeight, MessageClass, NetworkMessage, Request};

/// Request the tick manifest of a terminated shard's terminal block,
/// with what binds it to the block's hash.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetTerminalLinesRequest {
    /// Height the server resolves the terminal block by.
    pub terminal_height: BlockHeight,
    /// The beacon-attested terminal the requester reads from its fold. A
    /// block held at the height under another hash is answered empty.
    pub terminal_block_hash: BlockHash,
}

impl GetTerminalLinesRequest {
    /// Request the lines of the terminal block
    /// `(terminal_height, terminal_block_hash)`.
    #[must_use]
    pub const fn new(terminal_height: BlockHeight, terminal_block_hash: BlockHash) -> Self {
        Self {
            terminal_height,
            terminal_block_hash,
        }
    }
}

impl NetworkMessage for GetTerminalLinesRequest {
    fn message_type_id() -> &'static str {
        "terminal_lines.request"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl Request for GetTerminalLinesRequest {
    type Response = GetTerminalLinesResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.lines.is_none()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Capped, from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{BlockHeader, BlockHeaderParts, Hash, SectionRoots, TerminalLines};

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetTerminalLinesRequest::new(
            BlockHeight::new(98),
            BlockHash::from_raw(Hash::from_bytes(b"terminal")),
        );
        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetTerminalLinesRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }

    /// Only an answer with no lines sends the transport on to another
    /// peer; a terminal that ended nothing still answers.
    #[test]
    fn only_an_answer_without_lines_is_empty() {
        assert!(GetTerminalLinesRequest::is_empty_response(
            &GetTerminalLinesResponse::not_found()
        ));
        let no_end_line = GetTerminalLinesResponse::found(TerminalLines {
            header: BlockHeader::new(BlockHeaderParts::default()),
            roots: SectionRoots::EMPTY,
            manifest: Capped::empty(),
        });
        assert!(!GetTerminalLinesRequest::is_empty_response(&no_end_line));
    }
}
