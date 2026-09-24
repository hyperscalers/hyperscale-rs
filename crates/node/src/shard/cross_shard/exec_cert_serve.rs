//! Inbound execution-certificate fetch request handling.

use std::collections::HashSet;
use std::sync::Arc;

use hyperscale_execution::ExecCertStore;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::GetExecutionCertsRequest;
use hyperscale_types::network::response::GetExecutionCertsResponse;
use hyperscale_types::{ExecutionCertificate, TxHash};

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
    let mut asked: Vec<(Arc<ExecutionCertificate>, HashSet<TxHash>)> = Vec::new();

    // Filtered by what each certificate carries, as the chain tier is: a
    // copy of the tick held here can be narrower than the tick, and a
    // certificate that does not cover the transaction answers nothing
    // the asker waits on.
    for &tx_hash in &req.tx_hashes {
        for cert in exec_cert_store.certificates_for_tx(tx_hash) {
            if cert.covers(&tx_hash) {
                record(&mut asked, Arc::new((**cert).clone()), tx_hash);
            }
        }
    }

    for cert in pending_chain.execution_certificates_for_txs(&req.tx_hashes) {
        let cert = Arc::new(cert.into_inner());
        for &tx_hash in &req.tx_hashes {
            if cert.covers(&tx_hash) {
                record(&mut asked, Arc::clone(&cert), tx_hash);
            }
        }
    }

    let certs: Vec<Arc<ExecutionCertificate>> = asked
        .into_iter()
        .filter_map(|(cert, txs)| {
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

/// File `tx_hash` under a certificate of `cert`'s tick that answers for
/// it, preserving the order certificates were first asked about.
///
/// A copy of the tick already filed answers when it carries the
/// transaction, so transactions of one batch resolve to one certificate.
/// One that does not is a disjoint copy — a shard's own tick finalizes in
/// two halves, each carrying the members it settles — and `cert` is filed
/// beside it rather than under it.
fn record(
    asked: &mut Vec<(Arc<ExecutionCertificate>, HashSet<TxHash>)>,
    cert: Arc<ExecutionCertificate>,
    tx_hash: TxHash,
) {
    match asked
        .iter_mut()
        .find(|(held, _)| held.tick_id() == cert.tick_id() && held.covers(&tx_hash))
    {
        Some((_, txs)) => {
            txs.insert(tx_hash);
        }
        None => asked.push((cert, HashSet::from([tx_hash]))),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_hbor::Capped;
    use hyperscale_storage::test_helpers::{
        commit_settled_at, make_test_block, make_test_certified, push_certificate,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessCommit, BeaconWitnessLeafCount, BlockHeight, ChainOrigin,
        ExecutionOutcome, Finalization, GlobalReceiptHash, GlobalReceiptRoot, Hash, Role, ShardId,
        SignerBitfield, TickHalf, TickId, TxOutcome, Verified, WeightedTimestamp,
        compute_global_receipt_root,
    };

    use super::*;

    fn cert(height: u64, tx_hash: TxHash, role: Role) -> ExecutionCertificate {
        ExecutionCertificate::new(
            TickId::new(ShardId::ROOT, BlockHeight::new(height)),
            WeightedTimestamp::from_millis(height + 1),
            GlobalReceiptRoot::ZERO,
            Capped::from_array([TxOutcome::new(
                tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )
            .as_role(role)]),
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
                    &Capped::from_array([Arc::new(verdict.clone())]),
                    Capped::from_array([]),
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
                tx_hashes: Capped::from_array([tx_hash]),
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

    /// A certificate the store tier holds for the tick that does not
    /// carry the asked transaction is omitted.
    ///
    /// The tier holds one copy per tick, which can be narrower than the
    /// tick; a copy that does not cover the transaction answers nothing
    /// the asker waits on.
    #[test]
    fn the_store_tier_omits_a_certificate_that_does_not_cover_the_asked_transaction() {
        let carried = TxHash::from(Hash::from_bytes(&[6u8; 32]));
        let asked = TxHash::from(Hash::from_bytes(&[7u8; 32]));
        let outcomes: Vec<TxOutcome> = [carried, asked]
            .into_iter()
            .map(|tx_hash| {
                TxOutcome::new(
                    tx_hash,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
            })
            .collect();
        let complete = ExecutionCertificate::new(
            TickId::new(ShardId::ROOT, BlockHeight::new(1)),
            WeightedTimestamp::from_millis(2),
            compute_global_receipt_root(&outcomes),
            Capped::new(outcomes).expect("two outcomes"),
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        );
        let narrow = complete
            .project_to(&HashSet::from([carried]))
            .expect("the tick carries it");

        let store = ExecCertStore::new();
        store.insert(Arc::new(Verified::new_unchecked_for_test(narrow)));
        let pending_chain =
            PendingChain::new(Arc::new(SimShardStorage::default()), ChainOrigin::ROOT);

        let answered = serve_execution_certs_request(
            &pending_chain,
            &store,
            &GetExecutionCertsRequest {
                tx_hashes: Capped::from_array([asked]),
            },
        );
        assert!(
            answered.certificates.is_none(),
            "the held copy does not carry the asked transaction",
        );
    }

    /// The two halves of one of this shard's ticks each answer for the
    /// transaction they carry.
    ///
    /// A tick finalizes its determined members and its legs separately,
    /// each half carrying a projection of the tick's certificate to the
    /// members it settles. The two are disjoint, so neither can stand in
    /// for the other: filed under whichever copy of the tick was found
    /// first, the second transaction is answered with a certificate that
    /// does not carry it.
    #[test]
    fn both_halves_of_one_tick_answer_for_their_own_transactions() {
        let determined = TxHash::from(Hash::from_bytes(&[4u8; 32]));
        let leg = TxHash::from(Hash::from_bytes(&[5u8; 32]));
        let outcomes: Vec<TxOutcome> = [determined, leg]
            .into_iter()
            .map(|tx_hash| {
                TxOutcome::new(
                    tx_hash,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
            })
            .collect();
        let complete = ExecutionCertificate::new(
            TickId::new(ShardId::ROOT, BlockHeight::new(1)),
            WeightedTimestamp::from_millis(2),
            compute_global_receipt_root(&outcomes),
            Capped::new(outcomes).expect("two outcomes"),
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        );
        let half = |tx_hash: TxHash| {
            complete
                .project_to(&HashSet::from([tx_hash]))
                .expect("the tick carries it")
        };

        let storage = Arc::new(SimShardStorage::default());
        for (height, half_of, tx_hash) in [
            (1, TickHalf::Determined, determined),
            (2, TickHalf::Legs, leg),
        ] {
            let block = push_certificate(
                make_test_block(BlockHeight::new(height)),
                Arc::new(
                    Finalization::new(
                        *complete.tick_id(),
                        half_of,
                        &Capped::from_array([Arc::new(half(tx_hash))]),
                        Capped::from_array([]),
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
        }
        let pending_chain = PendingChain::new(storage, ChainOrigin::ROOT);

        let answered = serve_execution_certs_request(
            &pending_chain,
            &ExecCertStore::new(),
            &GetExecutionCertsRequest {
                tx_hashes: Capped::from_array([determined, leg]),
            },
        )
        .certificates
        .expect("both halves answer");
        assert_eq!(answered.len(), 2, "one certificate per half");
        for tx_hash in [determined, leg] {
            assert_eq!(
                answered.iter().filter(|cert| cert.covers(&tx_hash)).count(),
                1,
                "each transaction is answered by the half that carries it",
            );
        }
    }
}
