//! Transaction-validation pipeline step handlers.
//!
//! Every envelope enters through [`ShardLoop::admit`] beside its
//! [`Origin`]: gossip and local submissions are unbidden, a fetch
//! response is asked, and an envelope held back for records is offered
//! again under the origin it arrived with. One batch verifies them all;
//! the origin decides whether the payer filters apply and which event the
//! verdict surfaces as.
//!
//! - unbidden and valid: `ShardScopedInput::TransactionValidated`, which
//!   settles the loop's tracking and feeds
//!   `ProtocolEvent::TransactionValidated` to admission under the pool's
//!   ceiling;
//! - asked and valid: one `ProtocolEvent::TransactionsReceived` per
//!   batch, admitted past the ceiling;
//! - a derivation gap: `ShardScopedInput::RecordsWanted`, holding the
//!   envelope for what it names;
//! - refused: `ShardScopedInput::TransactionValidationsFailed`, clearing
//!   the tracking so the hash can be offered again.

use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::{Dispatch, DispatchPool, Parallelism};
use hyperscale_hbor::Capped;
use hyperscale_network::Network;
use hyperscale_storage::{ShardStorage, SubstateStore};
use hyperscale_types::network::gossip::TransactionGossip;
use hyperscale_types::{
    MAX_FETCH_RESPONSE_BYTES, NetworkId, ShardId, TopologySnapshot, Transaction,
    TransactionContext, TransactionVerifyError, TxHash, Unresolved, Verified, Verify,
};

use super::{DeferredTransaction, Origin};
use crate::batch_accumulator::BatchAccumulator;
use crate::event::{HostEvent, ShardScopedInput};
use crate::shard::{ShardLoop, push_protocol_event, push_shard_input};

/// Byte budget one outbound gossip batch accumulates before it flushes:
/// the fetch response's, since both answer with envelopes into one frame.
const TX_GOSSIP_BYTE_BUDGET: usize = MAX_FETCH_RESPONSE_BYTES;

/// One envelope's verdict: the envelope, how it reached admission, its
/// verified form where it passed, and what a derivation gap wanted.
struct Verdict {
    tx: Transaction,
    origin: Origin,
    verified: Option<Verified<Transaction>>,
    wanted: Unresolved,
}

/// Verify `tx`, separating what derivation could not resolve from a
/// refusal.
///
/// What a refusal wanted but this node did not hold is a gap rather than
/// a verdict: the same envelope derives wherever the seals it names have
/// landed and the code they run was fetched, so what is named here is
/// what to ask for and the envelope waits rather than being dropped.
fn verify_envelope(
    tx: &Transaction,
    ctx: TransactionContext<'_>,
) -> (Option<Verified<Transaction>>, Unresolved) {
    match tx.verify(ctx) {
        Ok(verified) => (Some(verified), Unresolved::default()),
        Err(TransactionVerifyError::Derivation(error)) => {
            (None, error.unresolved().cloned().unwrap_or_default())
        }
        Err(_) => (None, Unresolved::default()),
    }
}

/// Send back what a validation batch decided, each verdict through the
/// path its origin names.
///
/// A gap and a refusal are different answers and the split is the whole
/// point. A refusal is every node's; a gap is this one's, and the same
/// envelope derives wherever the seals it names have landed — so it
/// waits for the fetch instead of being forgotten, which is what keeps a
/// transaction nobody can yet derive from being dropped by everyone who
/// could propose it. It waits under its origin, so an envelope a block
/// asked for comes back as one.
fn report_validation_outcomes(
    event_tx: &Sender<HostEvent>,
    local_shard: ShardId,
    verdicts: Vec<Verdict>,
) {
    let mut received: Vec<Verified<Transaction>> = Vec::new();
    let mut wanted: Vec<DeferredTransaction> = Vec::new();
    let mut failed_hashes: Vec<TxHash> = Vec::new();
    for verdict in verdicts {
        match (verdict.verified, verdict.origin) {
            (Some(v), Origin::Unbidden) => push_shard_input(
                event_tx,
                local_shard,
                ShardScopedInput::TransactionValidated { tx: v },
            ),
            (Some(v), Origin::Asked) => received.push(v),
            (None, origin) if !verdict.wanted.is_empty() => wanted.push(
                DeferredTransaction::offered(verdict.tx, verdict.wanted, origin),
            ),
            (None, _) => failed_hashes.push(verdict.tx.hash()),
        }
    }
    if !received.is_empty() {
        push_protocol_event(
            event_tx,
            local_shard,
            ProtocolEvent::TransactionsReceived {
                transactions: received,
            },
        );
    }
    if !wanted.is_empty() {
        push_shard_input(
            event_tx,
            local_shard,
            ShardScopedInput::RecordsWanted { wanted },
        );
    }
    if !failed_hashes.is_empty() {
        push_shard_input(
            event_tx,
            local_shard,
            ShardScopedInput::TransactionValidationsFailed {
                hashes: failed_hashes,
            },
        );
    }
}

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    // ─── step() handlers ────────────────────────────────────────────────

    /// Validation succeeded — settle the locally-submitted flag and feed
    /// the tx into the state machine's gossip-admission path. Body
    /// insertion into [`TxStore`] happens inside
    /// [`MempoolCoordinator::on_transaction_gossip`] on successful
    /// admission, not here — we only serve bodies we vouched for.
    ///
    /// [`TxStore`]: hyperscale_mempool::TxStore
    /// [`MempoolCoordinator::on_transaction_gossip`]: hyperscale_mempool::MempoolCoordinator
    pub(crate) fn handle_transaction_validated(&mut self, tx: Verified<Transaction>) {
        self.settle_validated(&tx);
        let submitted_locally = self.io.mempool.locally_submitted.remove(&tx.hash());
        self.dispatch_event(ProtocolEvent::TransactionValidated {
            tx,
            submitted_locally,
        });
    }

    /// Asked envelopes that passed validation — settle each one's
    /// tracking and hand the batch to the fetch-delivery admission path.
    pub(crate) fn handle_transactions_received(
        &mut self,
        transactions: Vec<Verified<Transaction>>,
    ) {
        for tx in &transactions {
            self.settle_validated(tx);
        }
        self.dispatch_event(ProtocolEvent::TransactionsReceived { transactions });
    }

    /// Clear what the pipeline held for an envelope that passed.
    fn settle_validated(&mut self, tx: &Verified<Transaction>) {
        let tx_hash = tx.hash();
        self.io.mempool.pending_validation.remove(&tx_hash);
        // An envelope that derives wants nothing, so this retires only
        // asks whose answers are already seated — but it is what frees
        // the slot the re-offer was holding.
        self.settle_deferred(&[tx_hash]);
        // The earliest this node can know it will be asked to run this
        // code. Deriving the envelope needed the metadata and nothing
        // more, so a node holding that and not the compiled artifact
        // reaches here with no gap to report and a tick to run later.
        self.fetch_wanted_packages(tx.packages().to_vec());
    }

    /// Validation failed — drop tracking entries so the tx can be
    /// re-validated if it shows up again.
    pub(crate) fn handle_transaction_validations_failed(&mut self, hashes: &[TxHash]) {
        for hash in hashes {
            self.io.mempool.pending_validation.remove(hash);
            self.io.mempool.locally_submitted.remove(hash);
        }
        self.settle_deferred(hashes);
    }

    /// Passive co-host admission of a locally-submitted tx: admit to
    /// the validation pipeline if not already pending or cached. Does
    /// NOT mark `locally_submitted` and does NOT enqueue outbound
    /// gossip — both of those are the source shard's role via
    /// [`Self::handle_admit_and_gossip_transaction`]. Co-locating
    /// `locally_submitted` on a single shard per node keeps the
    /// finalization metric from double-counting txs whose touched set
    /// spans multiple hosted shards.
    pub(crate) fn handle_admit_transaction(&mut self, tx: Transaction) {
        self.admit(tx, Origin::Unbidden);
    }

    /// Source-shard handling for a locally-submitted tx: enqueue
    /// outbound gossip for every destination in `touched_shards`, then
    /// admit locally and mark `locally_submitted` so the resulting
    /// `ProtocolEvent::TransactionValidated` carries the
    /// submitted-locally flag. The source shard owns the
    /// `outbound_gossip_batches` map; one batch per destination shard
    /// (hosted or not) gets the tx appended.
    pub(crate) fn handle_admit_and_gossip_transaction(
        &mut self,
        tx: Transaction,
        touched_shards: &[ShardId],
    ) {
        for dst in touched_shards {
            self.enqueue_tx_for_gossip(*dst, tx.clone());
        }
        let tx_hash = tx.hash();
        if self.admit(tx, Origin::Unbidden) {
            self.io.mempool.locally_submitted.insert(tx_hash);
        }
    }

    /// Gossip-only handling for a locally-submitted tx whose touched
    /// shards are all non-hosted on this node: enqueue outbound gossip
    /// for every destination. No admission, no validation, no
    /// `locally_submitted` entry — this shard isn't part of the tx's
    /// touched set and won't see it in mempool.
    pub(crate) fn handle_gossip_transaction(
        &mut self,
        tx: &Transaction,
        touched_shards: &[ShardId],
    ) {
        for dst in touched_shards {
            self.enqueue_tx_for_gossip(*dst, tx.clone());
        }
    }

    /// Intercept a gossip-received transaction before it reaches the state
    /// machine and offer it to validation as unbidden.
    pub(crate) fn handle_gossip_received_tx_for_validation(&mut self, tx: Transaction) {
        self.admit(tx, Origin::Unbidden);
    }

    /// Intercept a fetch-delivered batch before it reaches the state
    /// machine and offer it to validation as asked, flushing at once
    /// rather than waiting out the batch window a block is stalled
    /// behind. The response boundary has already retired the delivered
    /// ids, whatever validation makes of them.
    pub(crate) fn handle_fetched_txs_for_validation(&mut self, batch: Vec<Transaction>) {
        if batch.is_empty() {
            return;
        }

        // Each shard's fetch responses decode fresh instances;
        // canonicalizing lets co-hosted shards share one validation
        // verdict.
        let batch: Vec<Transaction> = batch
            .into_iter()
            .map(|tx| self.process.canonical_txs.canonicalize(&tx))
            .collect();

        for tx in batch {
            self.admit(tx, Origin::Asked);
        }
        self.flush_validation_batch();
    }

    /// Offer `tx` to validation from `origin`, returning whether it was
    /// queued.
    ///
    /// An unbidden envelope is skipped when its body is already vouched
    /// for, its hash is tombstoned, or it is already in the pipeline —
    /// queued, being verified, or held for records — so a gossip echo
    /// is not verified twice. An asked one is always queued: an unbidden
    /// copy in the pipeline can still be refused by the filters and the
    /// ceiling an asked one is exempt from, and the block that asked
    /// would be left without it.
    pub(crate) fn admit(&mut self, tx: Transaction, origin: Origin) -> bool {
        let tx_hash = tx.hash();
        if origin == Origin::Unbidden
            && (self.io.mempool.pending_validation.contains(&tx_hash)
                || self.io.caches.tx_store.contains(&tx_hash)
                || self.replica.mempool_coordinator().is_tombstoned(&tx_hash))
        {
            return false;
        }
        self.io.mempool.pending_validation.insert(tx_hash);
        self.queue_validation(tx, origin);
        true
    }

    /// Append a tx to the destination shard's outbound gossip
    /// accumulator on this shard, flushing immediately if the count cap
    /// is hit. Time-based flushes happen via
    /// [`NodeHost::flush_expired_batches`]. The accumulator lives on the
    /// "source" `ShardLoop` (this one) — when the gossip flushes it
    /// publishes to the destination shard's topic.
    pub(crate) fn enqueue_tx_for_gossip(&mut self, dst: ShardId, tx: Transaction) {
        let now = self.now;
        let max = self.io.mempool.tx_gossip_max;
        let window = self.io.mempool.tx_gossip_window;
        let batch = self
            .io
            .mempool
            .outbound_gossip_batches
            .entry(dst)
            .or_insert_with(|| BatchAccumulator::new(TX_GOSSIP_BYTE_BUDGET, window));
        // Weighted by encoded size: the transport refuses frames past its
        // size cap, and a refused batch un-gossips every transaction in
        // it, so the accumulator flushes on bytes — a window of maximum
        // envelopes must still ship. The count cap rides alongside so a
        // flood of tiny transactions stays under the decode-side batch
        // bound.
        let bytes = tx.serialized_bytes().len();
        if batch.push_weighted(tx, bytes, now) || batch.len() >= max {
            self.flush_tx_gossip_batch(dst);
        }
    }

    /// Drain this shard's outbound gossip accumulator for destination
    /// shard `dst` and publish it as a single `TransactionGossip` batch.
    /// No-op if empty.
    ///
    /// The drained accumulator goes with it, and the next transaction for
    /// `dst` opens a fresh one: a reshape mints new shard ids, so keeping
    /// an empty one per destination would grow the map, and every scan of
    /// it, with each shard this one ever gossiped to.
    pub(crate) fn flush_tx_gossip_batch(&mut self, dst: ShardId) {
        let Some(mut batch) = self.io.mempool.outbound_gossip_batches.remove(&dst) else {
            return;
        };
        let txs = batch.take();
        if txs.is_empty() {
            return;
        }
        let gossip = TransactionGossip::new(
            Capped::new(txs).expect("the flush point is clamped to the gossip batch cap"),
        );
        self.process.network.broadcast_to_shard(dst, &gossip);
    }

    // ─── Validation batching ────────────────────────────────────────────

    /// Queue a transaction for batch validation on this shard, beside
    /// the origin its verdict is reported through. The caller holds the
    /// dedup guard for it.
    pub(crate) fn queue_validation(&mut self, tx: Transaction, origin: Origin) {
        let now = self.now;
        if self.io.mempool.validation_batch.push((tx, origin), now) {
            self.flush_validation_batch();
        }
    }

    /// Flush this shard's validation batch to the throughput pool,
    /// reporting each verdict through its origin's path.
    pub(crate) fn flush_validation_batch(&mut self) {
        let batch = self.io.mempool.validation_batch.take();
        if batch.is_empty() {
            return;
        }

        let event_tx = self.event_sender().clone();
        let local_shard = self.shard;
        let par: Parallelism = self.process.dispatch.parallelism();
        let topology = self.process.topology_snapshot.load_full();
        let storage = Arc::clone(&self.io.storage);
        let derivation = self.process.dispatch_handles.executor.derivation();
        self.process
            .dispatch
            .spawn(DispatchPool::Throughput, move || {
                let ctx = TransactionContext {
                    network: NetworkId::from(topology.network()),
                    derivation: derivation.as_ref(),
                };
                let verdicts: Vec<Verdict> = par.map(batch, |(tx, origin)| {
                    let (verified, wanted) = verify_envelope(&tx, ctx);
                    let verified =
                        verified.filter(|v| solvent(v, origin, &topology, local_shard, &*storage));
                    Verdict {
                        tx,
                        origin,
                        verified,
                        wanted,
                    }
                });
                report_validation_outcomes(&event_tx, local_shard, verdicts);
            });
    }
}

/// Whether admission solvency policy admits `tx` from `origin`.
///
/// Policy, not consensus: a transaction whose local payer cannot cover
/// its signed fee ceiling at the current tip never enters the mempool —
/// envelopes are free to mint, and an uncoverable one would otherwise
/// occupy ready slots and camp its declared keys until its window
/// expires. The builder and vote checks stay the deterministic
/// authorities. An asked envelope is never judged here: it is chain
/// content a valid block already carries.
fn solvent<S: SubstateStore>(
    tx: &Verified<Transaction>,
    origin: Origin,
    topology: &TopologySnapshot,
    local_shard: ShardId,
    storage: &S,
) -> bool {
    match origin {
        Origin::Asked => true,
        Origin::Unbidden => {
            payer_binding_holds(tx, topology, local_shard, storage)
                && payer_covers_fee_ceiling(tx, topology, local_shard, storage)
        }
    }
}

/// Whether the payer's rule admits the signer of a transaction whose
/// payer is local. `true` for a remote payer — the rule is the payer
/// shard's state, so only that shard's admission judges it. Advisory
/// like the ceiling check beside it: the builder and vote checks stay
/// the deterministic authorities.
fn payer_binding_holds<S: SubstateStore>(
    tx: &Verified<Transaction>,
    topology: &TopologySnapshot,
    local_shard: ShardId,
    storage: &S,
) -> bool {
    if topology.shard_trie().shard_for_prefix(tx.fee_vault().owner) != local_shard {
        return true;
    }
    let auth_cell = storage
        .get_substate_at_height(tx.auth_cell(), storage.jmt_height())
        .flatten();
    if !tx.payer_admits_attesters(auth_cell.as_deref()) {
        tracing::debug!(
            tx_hash = ?tx.hash(),
            "Refusing admission: the payer's rule does not admit the signer"
        );
        return false;
    }
    true
}

/// Whether the payer of a transaction can cover its signed fee
/// ceiling, read at the local committed tip. `true` for anything the
/// policy does not judge: remote payers (their balance is unreadable
/// here — the payer shard's own admission judges them), or unavailable
/// history.
fn payer_covers_fee_ceiling<S: SubstateStore>(
    tx: &Verified<Transaction>,
    topology: &TopologySnapshot,
    local_shard: ShardId,
    storage: &S,
) -> bool {
    let terms = tx.terms();
    let vault = tx.fee_vault();
    if topology.shard_trie().shard_for_prefix(vault.owner) != local_shard {
        return true;
    }
    let Some(cell) = storage.get_substate_at_height(vault, storage.jmt_height()) else {
        return true;
    };
    let balance = cell
        .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
        .map_or(0u128, u128::from_le_bytes);
    if balance < terms.max_fee {
        tracing::debug!(
            tx_hash = ?tx.hash(),
            balance,
            max_fee = terms.max_fee,
            "Refusing admission: payer cannot cover the signed fee ceiling"
        );
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use crossbeam::channel::{Receiver, unbounded};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::test_utils::{test_prefix, test_transaction};
    use hyperscale_types::{BlockHeight, shard_prefix_path};

    use super::*;
    use crate::shard::test_host::{Fixture, SHARD, loop_of};

    /// Every hash a validation verdict named among `events`, however it
    /// was reported.
    fn verdicts_named(events: &Receiver<HostEvent>) -> Vec<TxHash> {
        let mut named = Vec::new();
        for event in events.try_iter() {
            let HostEvent::Shard(_, input) = event else {
                continue;
            };
            match input {
                ShardScopedInput::TransactionValidated { tx } => named.push(tx.hash()),
                ShardScopedInput::TransactionValidationsFailed { hashes } => named.extend(hashes),
                ShardScopedInput::RecordsWanted { wanted } => {
                    named.extend(wanted.iter().map(|deferred| deferred.tx.hash()));
                }
                ShardScopedInput::Protocol(event) => {
                    if let ProtocolEvent::TransactionsReceived { transactions } = *event {
                        named.extend(transactions.iter().map(|tx| tx.hash()));
                    }
                }
                _ => {}
            }
        }
        named
    }

    /// A flushed destination leaves no accumulator behind, so the map
    /// holds only destinations with something waiting to go.
    #[test]
    fn a_flushed_gossip_destination_leaves_nothing_behind() {
        let fixture = Fixture::new();
        let mut host = fixture.host(BlockHeight::GENESIS);
        let shard_loop = loop_of(&mut host);
        let dst = ShardId::leaf(1, 1);
        shard_loop.enqueue_tx_for_gossip(dst, test_transaction(5));
        assert!(
            shard_loop
                .io
                .mempool
                .outbound_gossip_batches
                .contains_key(&dst)
        );

        shard_loop.flush_tx_gossip_batch(dst);

        assert!(shard_loop.io.mempool.outbound_gossip_batches.is_empty());
    }

    /// A gossip echo arriving while the first copy is still in the
    /// pipeline is not verified a second time.
    #[test]
    fn a_gossip_echo_is_verified_once() {
        let fixture = Fixture::new();
        let (mut host, events) = fixture.host_with_events(BlockHeight::GENESIS);
        let shard_loop = loop_of(&mut host);
        let tx = test_transaction(7);

        for _ in 0..3 {
            shard_loop.step(ShardScopedInput::TransactionGossipReceived { tx: tx.clone() });
        }
        shard_loop.flush_validation_batch();

        assert_eq!(verdicts_named(&events), vec![tx.hash()]);
    }

    /// An envelope held back for records is still in the pipeline: a
    /// gossip copy of it queues nothing behind it.
    #[test]
    fn a_gossip_echo_of_a_held_envelope_queues_nothing() {
        let fixture = Fixture::new();
        let mut host = fixture.host(BlockHeight::GENESIS);
        let shard_loop = loop_of(&mut host);
        let tx = test_transaction(8);
        let wanted = Unresolved {
            instances: vec![test_prefix(0xA1)],
            packages: Vec::new(),
        };
        shard_loop.defer_for_records(vec![DeferredTransaction::new(tx.clone(), wanted)]);

        shard_loop.step(ShardScopedInput::TransactionGossipReceived { tx });

        assert!(shard_loop.io.mempool.validation_batch.take().is_empty());
    }

    /// A fetched envelope held back for records goes back through the
    /// asked path when the record lands, so the block that named it is
    /// not left to the payer filters and the pool's ceiling.
    #[test]
    fn a_held_fetched_envelope_is_offered_again_as_asked() {
        let fixture = Fixture::new();
        let mut host = fixture.host(BlockHeight::GENESIS);
        let shard_loop = loop_of(&mut host);
        let tx = test_transaction(9);
        let record = test_prefix(0xA1);
        let wanted = Unresolved {
            instances: vec![record],
            packages: Vec::new(),
        };
        shard_loop.defer_for_records(vec![DeferredTransaction::offered(
            tx.clone(),
            wanted,
            Origin::Asked,
        )]);

        shard_loop.release_deferred(&[record]);

        let queued = shard_loop.io.mempool.validation_batch.take();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].0.hash(), tx.hash());
        assert_eq!(queued[0].1, Origin::Asked);
    }

    /// Each verdict surfaces through its origin's path: an unbidden
    /// pass to the loop's gossip admission, an asked pass as a fetch
    /// delivery, and a gap held under the origin it came from.
    #[test]
    fn a_verdict_is_reported_through_its_origin() {
        let (event_tx, events) = unbounded();
        let unbidden = test_transaction(1);
        let asked = test_transaction(2);
        let gapped = test_transaction(3);
        let verdict = |tx: &Transaction, origin| Verdict {
            tx: tx.clone(),
            origin,
            verified: Some(Verified::new_unchecked_for_test(tx.clone())),
            wanted: Unresolved::default(),
        };
        report_validation_outcomes(
            &event_tx,
            SHARD,
            vec![
                verdict(&unbidden, Origin::Unbidden),
                verdict(&asked, Origin::Asked),
                Verdict {
                    tx: gapped.clone(),
                    origin: Origin::Asked,
                    verified: None,
                    wanted: Unresolved {
                        instances: vec![test_prefix(0xA1)],
                        packages: Vec::new(),
                    },
                },
            ],
        );

        let mut validated = Vec::new();
        let mut received = Vec::new();
        let mut held = Vec::new();
        for event in events.try_iter() {
            let HostEvent::Shard(_, input) = event else {
                continue;
            };
            match input {
                ShardScopedInput::TransactionValidated { tx } => validated.push(tx.hash()),
                ShardScopedInput::Protocol(event) => {
                    if let ProtocolEvent::TransactionsReceived { transactions } = *event {
                        received.extend(transactions.iter().map(|tx| tx.hash()));
                    }
                }
                ShardScopedInput::RecordsWanted { wanted } => {
                    held.extend(wanted.iter().map(|d| (d.tx.hash(), d.origin)));
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(validated, vec![unbidden.hash()]);
        assert_eq!(received, vec![asked.hash()]);
        assert_eq!(held, vec![(gapped.hash(), Origin::Asked)]);
    }

    /// The solvency filters judge only what nobody here asked for: a
    /// local payer with nothing in its vault refuses an unbidden
    /// envelope and not an asked one.
    #[test]
    fn an_asked_envelope_skips_the_solvency_filters() {
        let fixture = Fixture::new();
        let topology = fixture.topology(std::collections::BTreeMap::new());
        let tx = Verified::new_unchecked_for_test(test_transaction(4));
        let payer_shard = topology.shard_trie().shard_for_prefix(tx.fee_vault().owner);
        let storage = SimShardStorage::new(shard_prefix_path(payer_shard));

        assert!(!solvent(
            &tx,
            Origin::Unbidden,
            &topology,
            payer_shard,
            &storage
        ));
        assert!(solvent(
            &tx,
            Origin::Asked,
            &topology,
            payer_shard,
            &storage
        ));
    }
}
