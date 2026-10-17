//! Inbound finalization fetch request handling.

use std::sync::Arc;

use hyperscale_hbor::{Capped, to_vec as hbor_to_vec};
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::cache::BoundedCache;
use hyperscale_types::network::request::GetFinalizationsRequest;
use hyperscale_types::network::response::GetFinalizationsResponse;
use hyperscale_types::{Finalization, FinalizationHash, MAX_FETCH_RESPONSE_BYTES, Verifiable};

/// The longest prefix of `found` that encodes under the response's byte
/// budget, in the order given, and never less than its first.
///
/// A response is cut by bytes rather than by count: a stating half
/// carries the yes receipts of its tick, so a few halves asked by hash
/// can overrun the frame however few they are, and a message past the
/// frame is dropped whole. One half alone fits the frame, so the first is
/// always answered and every request makes progress. What is cut is
/// simply not answered, and the requester asks for it again.
fn within_byte_budget(found: Vec<Arc<Finalization>>) -> Vec<Arc<Finalization>> {
    let mut bytes = 0usize;
    let mut kept = Vec::with_capacity(found.len());
    for fw in found {
        let size = hbor_to_vec(&*fw).map_or(usize::MAX, |encoded| encoded.len());
        bytes = bytes.saturating_add(size);
        if bytes > MAX_FETCH_RESPONSE_BYTES && !kept.is_empty() {
            break;
        }
        kept.push(fw);
    }
    kept
}

/// Serve an inbound finalization fetch request.
///
/// Two tiers: an in-memory cache (entries live here between EC aggregation
/// and its containing block committing) and chain storage via
/// [`PendingChain`]. Storage holds attestations and per-tx receipts
/// separately; for anything missed by the cache, we reconstruct the full
/// `Finalization` by pulling both halves. Peers requesting
/// finalizations past the cache window must still get a complete answer from
/// durable storage.
///
/// The wire response carries raw `Arc<Finalization>` bodies — the
/// verification marker is process-local and doesn't cross the network.
pub fn serve_finalizations_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    fw_cache: &BoundedCache<FinalizationHash, Arc<Verifiable<Finalization>>>,
    req: &GetFinalizationsRequest,
) -> GetFinalizationsResponse {
    let mut found: Vec<Arc<Finalization>> = Vec::new();
    let mut missing: Vec<FinalizationHash> = Vec::new();
    for id in &req.finalization_hashes {
        if let Some(fw) = fw_cache.get(id) {
            found.push(Arc::new(fw.as_unverified().clone()));
        } else {
            missing.push(*id);
        }
    }
    if !missing.is_empty() {
        found.extend(
            pending_chain
                .certificates_batch(&missing)
                .into_iter()
                .filter_map(|cert| {
                    Finalization::reconstruct(cert, |tx_hash, receipt_hash| {
                        pending_chain.consensus_receipt(tx_hash, receipt_hash)
                    })
                })
                .map(Arc::new),
        );
    }

    // One finalization per hash asked, so the answer meets the cap the
    // request already met; one past it is simply absent, which is what a
    // partial answer already means here.
    let mut finalizations = Capped::empty();
    for fw in within_byte_budget(found) {
        if finalizations.push(fw).is_err() {
            break;
        }
    }

    record_fetch_response_sent("finalization", finalizations.len());
    GetFinalizationsResponse::new(finalizations)
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        Address, AddressClass, BlockHeight, ConsensusReceipt, GlobalReceiptHash, Hash, LocalKey,
        MAX_CELL_VALUE_LEN, MAX_WIRE_MESSAGE_BYTES, ShardId, StateWrites, StoredReceipt,
        SubstateKey, TickId, TxHash,
    };

    use super::*;

    /// A legs half of tick `height` whose members' receipts each write
    /// one cell at the value cap: about as heavy as a full tick's stating
    /// half.
    fn heavy(height: u64) -> Arc<Finalization> {
        let receipts: Vec<StoredReceipt> = (0..21u8)
            .map(|seed| {
                let mut writes = StateWrites::default();
                writes.cells.insert(
                    SubstateKey {
                        owner: Address::new([seed; 31], AddressClass::Component),
                        local: LocalKey([seed; 16]),
                    },
                    Some(vec![seed; MAX_CELL_VALUE_LEN]),
                );
                StoredReceipt::new(
                    TxHash::from(Hash::from_bytes(&[seed; 4])),
                    Arc::new(ConsensusReceipt::Succeeded {
                        receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed])),
                        writes,
                        beacon_witness_events: Capped::empty(),
                        events: Capped::empty(),
                    }),
                )
            })
            .collect();
        Arc::new(Finalization::accepting(
            TickId::new(ShardId::ROOT, BlockHeight::new(height)),
            Capped::new(receipts).expect("a few receipts"),
        ))
    }

    /// Two heavy halves do not fit one response: the budget answers the
    /// first alone, under the frame, and leaves the second for the next
    /// request rather than dropping the whole message.
    #[test]
    fn a_response_of_two_heavy_halves_is_cut_to_fit() {
        let found = vec![heavy(1), heavy(2)];
        let size = |fw: &Arc<Finalization>| hbor_to_vec(&**fw).expect("encodes").len();
        assert!(
            found.iter().map(size).sum::<usize>() > MAX_WIRE_MESSAGE_BYTES,
            "two heavy halves overrun the frame",
        );

        let kept = within_byte_budget(found.clone());
        assert_eq!(kept, found[..1]);
        assert!(size(&kept[0]) <= MAX_FETCH_RESPONSE_BYTES);
        assert_eq!(
            within_byte_budget(found[1..].to_vec()),
            found[1..],
            "and the half cut is answered when asked again",
        );
    }
}
