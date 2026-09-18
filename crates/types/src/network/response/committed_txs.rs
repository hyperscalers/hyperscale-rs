//! Committed-transaction membership answers for a reshape successor.

use hyperscale_hbor::{Capped, Hbor};

use crate::{CommittedTxAbsence, MAX_PROOFS_PER_QUERY, MessageClass, NetworkMessage};

/// What a terminated shard says about one queried transaction.
///
/// **Only absence carries a proof, and deliberately.** The successor's
/// standing rule is to refuse everything from before the cut, so
/// `Committed` is the answer it already assumes — a server that returns
/// it falsely costs exactly what a server that never answers costs, and
/// the requester rotates to another member of the terminal committee.
/// `Absent` is the answer that relaxes the rule, so that is the one that
/// has to be proven, against a root the successor commit-proved for
/// itself.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub enum CommittedTxVerdict {
    /// The terminated shard committed this transaction within its
    /// retention window. The successor keeps refusing it.
    Committed,
    /// The transaction is absent from the shard's committed set, proven
    /// against the terminal's `committed_txs_root`.
    Absent(CommittedTxAbsence),
}

/// One verdict per queried transaction, in the order asked.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetCommittedTxsResponse {
    /// Verdicts positionally matched to the request's `tx_hashes`, or
    /// `None` when this peer doesn't hold the named terminal — the
    /// requester rotates to another terminal-committee member.
    ///
    /// A requester must check the length against what it asked before
    /// pairing them up; a short list is a malformed answer, not a
    /// partial one.
    pub verdicts: Option<Capped<Vec<CommittedTxVerdict>, MAX_PROOFS_PER_QUERY>>,
}

impl GetCommittedTxsResponse {
    /// Verdicts for every queried transaction.
    #[must_use]
    pub const fn found(verdicts: Capped<Vec<CommittedTxVerdict>, MAX_PROOFS_PER_QUERY>) -> Self {
        Self {
            verdicts: Some(verdicts),
        }
    }

    /// This peer can't serve the requested terminal block.
    #[must_use]
    pub const fn not_found() -> Self {
        Self { verdicts: None }
    }
}

impl NetworkMessage for GetCommittedTxsResponse {
    fn message_type_id() -> &'static str {
        "committed_txs.response"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{Hash, TxHash, committed_txs_root_from_hashes, prove_committed_tx_absent};

    #[test]
    fn test_hbor_roundtrip_not_found() {
        let response = GetCommittedTxsResponse::not_found();
        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetCommittedTxsResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    /// Both verdicts survive the wire, and a decoded absence proof still
    /// verifies — the proof is the payload, so a round trip that dropped
    /// part of it would be silent otherwise.
    #[test]
    fn test_hbor_roundtrip_verdicts() {
        let members: Vec<TxHash> = {
            let mut m: Vec<TxHash> = (0..8u8)
                .map(|s| TxHash::from(Hash::from_bytes(&[s])))
                .collect();
            m.sort_unstable();
            m
        };
        let root = committed_txs_root_from_hashes(members.iter());
        let probe = TxHash::from(Hash::from_bytes(b"absent probe"));
        let absence = prove_committed_tx_absent(&members, &probe).expect("probe is not a member");

        let response = GetCommittedTxsResponse::found(Capped::from_array([
            CommittedTxVerdict::Committed,
            CommittedTxVerdict::Absent(absence),
        ]));
        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetCommittedTxsResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);

        let verdicts = decoded.verdicts.expect("found");
        let CommittedTxVerdict::Absent(decoded_absence) = &verdicts[1] else {
            panic!("second verdict is an absence proof");
        };
        assert!(decoded_absence.proves_absent(&probe, root));
    }
}
