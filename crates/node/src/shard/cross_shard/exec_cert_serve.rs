//! Inbound execution-certificate fetch request handling.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use hyperscale_execution::ExecCertStore;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::GetExecutionCertsRequest;
use hyperscale_types::network::response::GetExecutionCertsResponse;
use hyperscale_types::{ExecutionCertificate, TickId, TxHash};

/// Serve an inbound execution-certificate fetch request.
///
/// Two tiers: the in-memory [`ExecCertStore`] (entries live here between
/// EC aggregation and the tick's containing block committing) and chain
/// storage via [`PendingChain`]. Cache eviction happens at finalization
/// commit, at which point storage is the authoritative source.
///
/// Both tiers are read for every transaction asked about, not the chain
/// only on a cache miss. A shard certifies one transaction more than
/// once — its verdict, and then the retirement, reclaim or abandonment
/// that settles what the verdict left — so the two tiers can hold
/// different certificates for it, and which one answers the asker's
/// question is not something either tier knows. Answering with the one
/// that happened to be found leaves a counterpart waiting on a verdict
/// holding a retirement that covers nothing its tick awaits, and asking
/// again gets the same answer for as long as it asks.
///
/// The request names transactions, and one certificate covers a whole
/// batch of them, so several requested transactions commonly resolve to
/// the same certificate — it is answered once, projected to the
/// transactions that were actually asked about. A requester asks for what
/// it is missing, so that projection is what it needs and no more; the
/// broadcast this request stands in for was projected the same way.
///
/// A certificate this shard did not produce is already a projection and
/// cannot be narrowed further — the sibling nodes to rebuild the root
/// around a smaller set are exactly what it does not carry. It is
/// answered as it stands.
pub fn serve_execution_certs_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    exec_cert_store: &ExecCertStore,
    req: &GetExecutionCertsRequest,
) -> GetExecutionCertsResponse {
    // Certificates in first-asked order, each with the transactions this
    // request named it for.
    let mut asked: HashMap<TickId, (Arc<ExecutionCertificate>, HashSet<TxHash>)> = HashMap::new();
    let mut order: Vec<TickId> = Vec::new();

    for &tx_hash in &req.tx_hashes {
        for cert in exec_cert_store.certificates_for_tx(tx_hash) {
            record(&mut asked, &mut order, Arc::new((**cert).clone()), tx_hash);
        }
    }

    for cert in pending_chain.execution_certificates_for_txs(&req.tx_hashes) {
        let cert = Arc::new(cert.into_inner());
        for &tx_hash in &req.tx_hashes {
            if cert.covers(&tx_hash) {
                record(&mut asked, &mut order, Arc::clone(&cert), tx_hash);
            }
        }
    }

    let certs: Vec<Arc<ExecutionCertificate>> = order
        .into_iter()
        .filter_map(|tick_id| {
            let (cert, txs) = asked.remove(&tick_id)?;
            if cert.is_complete() {
                cert.project_to(&txs).map(Arc::new)
            } else {
                Some(cert)
            }
        })
        .collect();

    if certs.is_empty() {
        GetExecutionCertsResponse { certificates: None }
    } else {
        record_fetch_response_sent("exec_cert", certs.len());
        GetExecutionCertsResponse {
            certificates: Some(certs),
        }
    }
}

/// File `tx_hash` under the certificate answering for it, preserving the
/// order certificates were first asked about.
fn record(
    asked: &mut HashMap<TickId, (Arc<ExecutionCertificate>, HashSet<TxHash>)>,
    order: &mut Vec<TickId>,
    cert: Arc<ExecutionCertificate>,
    tx_hash: TxHash,
) {
    let tick_id = *cert.tick_id();
    asked
        .entry(tick_id)
        .or_insert_with(|| {
            order.push(tick_id);
            (cert, HashSet::new())
        })
        .1
        .insert(tx_hash);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::{
        commit_settled_at, make_test_block, make_test_certified, push_certificate,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessCommit, BeaconWitnessLeafCount, BlockHeight, ChainOrigin,
        ExecutionOutcome, Finalization, GlobalReceiptHash, GlobalReceiptRoot, Hash, Role, ShardId,
        SignerBitfield, TickHalf, TxOutcome, Verified, WeightedTimestamp,
    };

    use super::*;

    fn cert(height: u64, tx_hash: TxHash, role: Role) -> ExecutionCertificate {
        ExecutionCertificate::new(
            TickId::new(ShardId::ROOT, BlockHeight::new(height)),
            WeightedTimestamp::from_millis(height + 1),
            GlobalReceiptRoot::ZERO,
            vec![
                TxOutcome::new(
                    tx_hash,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
                .as_role(role),
            ],
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        )
    }

    /// A transaction this shard certified twice is answered with both,
    /// whichever tier each is in.
    ///
    /// The verdict's certificate leaves the cache when its finalization
    /// commits and stays on the chain; whatever settles what the verdict
    /// left is certified later and is in the cache. Reading the chain
    /// only on a cache miss answers a counterpart waiting on the verdict
    /// with the settling certificate alone, which covers nothing its tick
    /// awaits — and asking again gets the same answer for as long as it
    /// asks.
    #[test]
    fn both_tiers_answer_for_a_transaction_certified_twice() {
        let tx_hash = TxHash::from(Hash::from_bytes(&[3u8; 32]));
        let verdict = cert(1, tx_hash, Role::Core);
        let settling = cert(2, tx_hash, Role::Retiring);

        // The verdict is on the chain, where its committed finalization
        // put it; the settling certificate is still in the cache.
        let storage = Arc::new(SimShardStorage::default());
        let block = push_certificate(
            make_test_block(BlockHeight::new(1)),
            Arc::new(
                Finalization::new(
                    *verdict.tick_id(),
                    TickHalf::Legs,
                    vec![Arc::new(verdict.clone())],
                    vec![],
                )
                .into(),
            ),
        );
        commit_settled_at(
            &*storage,
            &make_test_certified(block),
            &[],
            &[],
            &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        );
        let pending_chain = PendingChain::new(storage, ChainOrigin::ROOT);
        let store = ExecCertStore::new();
        store.insert(Arc::new(Verified::new_unchecked_for_test(settling.clone())));

        let answered = serve_execution_certs_request(
            &pending_chain,
            &store,
            &GetExecutionCertsRequest {
                tx_hashes: vec![tx_hash],
            },
        );
        let mut ticks: Vec<TickId> = answered
            .certificates
            .expect("both answer")
            .iter()
            .map(|cert| *cert.tick_id())
            .collect();
        ticks.sort_unstable();
        assert_eq!(ticks, vec![*verdict.tick_id(), *settling.tick_id()]);
    }
}
