//! Transaction fetch instance binding.
//!
//! Wires `HashSetFetch<BlockHash, TxHash>` to per-block transaction fetches
//! pinned to the proposer.

use crate::protocol::fetch::{HashSetFetch, HashSetFetchInput};
use crate::state::NodeStateMachine;
use hyperscale_core::ProtocolEvent;
use hyperscale_types::{BlockHash, TxHash};

/// Composite scope key — the block whose tx set we're fetching.
pub type Scope = BlockHash;

/// The typed fetch protocol instance for transactions.
pub type TransactionFetch = HashSetFetch<Scope, TxHash>;

/// A scope is abandoned once BFT no longer holds a pending block for it.
#[must_use]
pub fn is_abandoned(state: &NodeStateMachine, scope: &Scope) -> bool {
    !state.bft().has_pending_block(*scope)
}

/// Drain admitted ids from the fetch protocol on the canonical admission
/// event. No-op for events this instance doesn't subscribe to. Called from
/// `io_loop`'s `Action::Continuation` interception arm.
pub fn apply_admission(fetch: &mut TransactionFetch, event: &ProtocolEvent) {
    if let ProtocolEvent::TransactionsAdmitted { txs } = event {
        let ids: Vec<TxHash> = txs.iter().map(|tx| tx.hash()).collect();
        fetch.handle(HashSetFetchInput::Admitted { ids });
    }
}
