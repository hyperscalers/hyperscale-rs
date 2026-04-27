//! Transaction fetch instance binding.
//!
//! Wires `IdFetch<TxHash>` to transaction fetches. The protocol is keyless;
//! its lifetime is bounded by `TransactionsAdmitted` admission events and
//! explicit cancels from emitters that abandon their request.

use crate::protocol::fetch::{IdFetch, IdFetchInput};
use hyperscale_core::ProtocolEvent;
use hyperscale_types::TxHash;

/// The typed fetch protocol instance for transactions.
pub type TransactionFetch = IdFetch<TxHash>;

/// Drain admitted ids from the fetch protocol on the canonical admission
/// event. Called from `io_loop`'s `Action::Continuation` interception arm.
pub fn apply_admission(fetch: &mut TransactionFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::TransactionsAdmitted { txs } = event {
        let ids: Vec<TxHash> = txs.iter().map(|tx| tx.hash()).collect();
        fetch.handle(IdFetchInput::Admitted { ids });
    }
}
