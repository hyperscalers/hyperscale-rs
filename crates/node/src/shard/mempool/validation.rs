//! Transaction-validation pipeline step handlers.
//!
//! Five `NodeInput` variants drive the pipeline:
//!
//! - `TransactionGossipReceived` — raw gossip arrival; queue for batched
//!   validation if not already cached/tombstoned. Never reaches the state
//!   machine.
//! - `TransactionsFetched` — raw fetch-response delivery; drive the
//!   fetch-FSM drain for every delivered hash, dispatch the batch for
//!   validation, then surface the valid subset as
//!   `ProtocolEvent::TransactionsReceived`.
//! - `SubmitTransaction` — locally-submitted tx: gossip to relevant shards,
//!   then queue for validation if needed;
//! - `TransactionValidated` — async-validation success: resolve
//!   locally-submitted from the tracking set, feed
//!   `ProtocolEvent::TransactionValidated` to state-machine admission;
//! - `TransactionValidationsFailed` — async-validation failure: clean up
//!   tracking sets so the tx can be re-validated later.

use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::{Dispatch, DispatchPool, Parallelism};
use hyperscale_network::Network;
use hyperscale_storage::{ShardStorage, SubstateStore};
use hyperscale_types::network::gossip::TransactionGossip;
use hyperscale_types::{
    MAX_FETCH_RESPONSE_BYTES, NetworkId, ShardId, TopologySnapshot, Transaction,
    TransactionContext, TransactionVerifyError, TxHash, Unresolved, Verified, Verify,
};

use super::{DeferredOrigin, DeferredTransaction, TransactionBinding};
use crate::batch_accumulator::BatchAccumulator;
use crate::fetch::FetchInput;
use crate::host::NodeHost;
use crate::process::SubmitFanout;
use crate::shard::{HostEvent, ShardLoop, ShardScopedInput, push_protocol_event, push_shard_input};

/// Byte budget one outbound gossip batch accumulates before it flushes:
/// the fetch response's, since both answer with envelopes into one frame.
const TX_GOSSIP_BYTE_BUDGET: usize = MAX_FETCH_RESPONSE_BYTES;

/// One envelope's verdict: the envelope itself, its verified form where
/// it has one, and what a derivation gap wanted.
type ValidationOutcome = (Arc<Transaction>, Option<Verified<Transaction>>, Unresolved);

/// Send back what a validation batch decided about the envelopes it
/// could not admit: the ones held back for records this node has not
/// seen, and the ones genuinely refused.
///
/// The two are different answers and the split is the whole point. A
/// refusal is every node's; a gap is this one's, and the same envelope
/// derives wherever the seals it names have landed — so it waits for the
/// fetch instead of being forgotten, which is what keeps a transaction
/// nobody can yet derive from being dropped by everyone who could
/// propose it.
fn report_validation_outcomes(
    event_tx: &Sender<HostEvent>,
    local_shard: ShardId,
    outcomes: Vec<ValidationOutcome>,
) {
    let mut wanted: Vec<DeferredTransaction> = Vec::new();
    let mut failed_hashes: Vec<TxHash> = Vec::new();
    for (tx, verified, gap) in outcomes {
        if let Some(v) = verified {
            push_shard_input(
                event_tx,
                local_shard,
                ShardScopedInput::TransactionValidated { tx: Arc::new(v) },
            );
        } else if gap.is_empty() {
            failed_hashes.push(tx.hash());
        } else {
            wanted.push(DeferredTransaction::new(
                tx,
                gap,
                DeferredOrigin::Validation,
            ));
        }
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
    pub(crate) fn handle_transaction_validated(&mut self, tx: Arc<Verified<Transaction>>) {
        let tx_hash = tx.hash();
        self.io.mempool.pending_validation.remove(&tx_hash);
        // An envelope that derives wants nothing, so this retires only
        // asks whose answers are already seated — but it is what frees
        // the slot the re-offer was holding.
        self.settle_deferred(&[tx_hash]);
        let submitted_locally = self.io.mempool.locally_submitted.remove(&tx_hash);
        // The earliest this node can know it will be asked to run this
        // code. Deriving the envelope needed the metadata and nothing
        // more, so a node holding that and not the compiled artifact
        // reaches here with no gap to report and a tick to run later.
        self.fetch_wanted_packages(tx.packages().to_vec());
        self.dispatch_event(ProtocolEvent::TransactionValidated {
            tx,
            submitted_locally,
        });
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
    pub(crate) fn handle_admit_transaction(&mut self, tx: Arc<Transaction>) {
        let tx_hash = tx.hash();
        if !self.io.mempool.pending_validation.contains(&tx_hash)
            && !self.io.caches.tx_store.contains(&tx_hash)
        {
            self.io.mempool.pending_validation.insert(tx_hash);
            self.queue_validation(tx);
        }
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
        tx: Arc<Transaction>,
        touched_shards: &[ShardId],
    ) {
        for dst in touched_shards {
            self.enqueue_tx_for_gossip(*dst, Arc::clone(&tx));
        }
        let tx_hash = tx.hash();
        if !self.io.mempool.pending_validation.contains(&tx_hash)
            && !self.io.caches.tx_store.contains(&tx_hash)
        {
            self.io.mempool.locally_submitted.insert(tx_hash);
            self.io.mempool.pending_validation.insert(tx_hash);
            self.queue_validation(tx);
        }
    }

    /// Gossip-only handling for a locally-submitted tx whose touched
    /// shards are all non-hosted on this node: enqueue outbound gossip
    /// for every destination. No admission, no validation, no
    /// `locally_submitted` entry — this shard isn't part of the tx's
    /// touched set and won't see it in mempool.
    pub(crate) fn handle_gossip_transaction(
        &mut self,
        tx: &Arc<Transaction>,
        touched_shards: &[ShardId],
    ) {
        for dst in touched_shards {
            self.enqueue_tx_for_gossip(*dst, Arc::clone(tx));
        }
    }

    /// Intercept a gossip-received transaction before it reaches the state
    /// machine: queue for batched async validation if we don't already
    /// have it cached and it isn't tombstoned by mempool.
    pub(crate) fn handle_gossip_received_tx_for_validation(&mut self, tx: Arc<Transaction>) {
        let tx_hash = tx.hash();
        // Already-vouched (in TxStore) or terminally-rejected (tombstoned)
        // are skipped. `pending_validation` blocks duplicate enqueues.
        // Tombstones are identical across same-shard vnodes (deterministic
        // mempool processing) — peek at vnode 0's set as representative.
        if !self.io.caches.tx_store.contains(&tx_hash)
            && !self
                .vnode(0)
                .state
                .mempool_coordinator()
                .is_tombstoned(&tx_hash)
        {
            self.io.mempool.pending_validation.insert(tx_hash);
            self.queue_validation(tx);
        }
    }

    /// Intercept a fetch-delivered batch before it reaches the state
    /// machine. Drives the fetch-FSM drain for every delivered hash
    /// (releases in-flight slots regardless of validation outcome,
    /// so an invalid-signature payload can't pin a slot) and dispatches
    /// the batch for async validation. The valid subset surfaces as
    /// `ProtocolEvent::TransactionsReceived`; invalid hashes surface as
    /// `ShardScopedInput::TransactionValidationsFailed`, mirroring the
    /// gossip-path tracking-set cleanup.
    pub(crate) fn handle_fetched_txs_for_validation(&mut self, batch: Vec<Arc<Transaction>>) {
        if batch.is_empty() {
            return;
        }

        // Each shard's fetch responses decode fresh instances;
        // canonicalizing lets co-hosted shards share one validation
        // verdict.
        let batch: Vec<Arc<Transaction>> = batch
            .into_iter()
            .map(|tx| self.process.canonical_txs.canonicalize(&tx))
            .collect();

        let delivered_ids: Vec<TxHash> = batch.iter().map(|tx| tx.hash()).collect();
        self.drive_fetch::<TransactionBinding>(FetchInput::Admitted { ids: delivered_ids });

        let event_tx = self.event_sender().clone();
        let local_shard = self.shard;
        let par: Parallelism = self.process.dispatch.parallelism();
        let network = NetworkId::from(self.process.topology_snapshot.load().network());
        let derivation = self.process.dispatch_handles.executor.derivation();
        self.process
            .dispatch
            .spawn(DispatchPool::Throughput, move || {
                let ctx = TransactionContext {
                    network,
                    derivation: derivation.as_ref(),
                };
                let results: Vec<ValidationOutcome> = par.map(batch, |tx| {
                    let mut wanted = Unresolved::default();
                    let verified = match tx.verify(ctx) {
                        Ok(v) => Some(v),
                        Err(TransactionVerifyError::Derivation(error)) => {
                            wanted = error.unresolved().cloned().unwrap_or_default();
                            None
                        }
                        Err(_) => None,
                    };
                    (tx, verified, wanted)
                });

                let mut valid: Vec<Arc<Verified<Transaction>>> = Vec::new();
                let mut undecided: Vec<ValidationOutcome> = Vec::new();
                for (tx, verified, wanted) in results {
                    match verified {
                        Some(v) => valid.push(Arc::new(v)),
                        None => undecided.push((tx, None, wanted)),
                    }
                }

                if !valid.is_empty() {
                    push_protocol_event(
                        &event_tx,
                        local_shard,
                        ProtocolEvent::TransactionsReceived {
                            transactions: valid,
                        },
                    );
                }
                report_validation_outcomes(&event_tx, local_shard, undecided);
            });
    }

    /// Append a tx to the destination shard's outbound gossip
    /// accumulator on this shard, flushing immediately if the count cap
    /// is hit. Time-based flushes happen via
    /// [`NodeHost::flush_expired_batches`]. The accumulator lives on the
    /// "source" `ShardLoop` (this one) — when the gossip flushes it
    /// publishes to the destination shard's topic.
    pub(crate) fn enqueue_tx_for_gossip(&mut self, dst: ShardId, tx: Arc<Transaction>) {
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
    pub(crate) fn flush_tx_gossip_batch(&mut self, dst: ShardId) {
        let Some(batch) = self.io.mempool.outbound_gossip_batches.get_mut(&dst) else {
            return;
        };
        let txs = batch.take();
        if txs.is_empty() {
            return;
        }
        let gossip = TransactionGossip::new(txs);
        self.process.network.broadcast_to_shard(dst, &gossip);
    }

    // ─── Validation batching ────────────────────────────────────────────

    /// Queue a transaction for batch validation on this shard.
    pub(crate) fn queue_validation(&mut self, tx: Arc<Transaction>) {
        let now = self.now;
        if self.io.mempool.validation_batch.push(tx, now) {
            self.flush_validation_batch();
        }
    }

    /// Flush this shard's validation batch, dispatching to the
    /// `tx_validation` pool.
    ///
    /// Valid transactions are sent back as `TransactionValidated` events
    /// through the event channel; failures land as
    /// `TransactionValidationsFailed` so the shard can clean up
    /// `pending_validation` / `locally_submitted`.
    pub(crate) fn flush_validation_batch(&mut self) {
        let batch = self.io.mempool.validation_batch.take();
        if batch.is_empty() {
            return;
        }

        let event_tx = self.event_sender().clone();
        let local_shard = self.shard;
        let par: Parallelism = self.process.dispatch.parallelism();
        // Admission solvency policy, not consensus: a transaction
        // whose local payer cannot cover its signed fee ceiling at the
        // current tip never enters the mempool — envelopes are free to
        // mint, and an uncoverable one would otherwise occupy ready
        // slots and camp its declared keys until its window expires.
        // The builder and vote checks stay the deterministic
        // authorities; the fetch path deliberately skips this filter,
        // since fetched transactions are chain content a valid block
        // already carries.
        let topology = self.process.topology_snapshot.load_full();
        // The advisory instant the payer binding's maturity comparison
        // uses: local admission time approximates the clock a block
        // committing this transaction will carry. The builder and vote
        // checks stay the deterministic authorities.
        let clock_ms = self.now.as_millis();
        let storage = self
            .process
            .dispatch_handles
            .per_shard
            .load()
            .get(&self.shard)
            .map(|handles| Arc::clone(&handles.storage));
        let derivation = self.process.dispatch_handles.executor.derivation();
        self.process
            .dispatch
            .spawn(DispatchPool::Throughput, move || {
                let ctx = TransactionContext {
                    network: NetworkId::from(topology.network()),
                    derivation: derivation.as_ref(),
                };
                let results: Vec<ValidationOutcome> = par.map(batch, |tx| {
                    // What a refusal wanted but this node did not hold.
                    // A gap rather than a verdict: the same envelope
                    // derives wherever the seals it names have landed
                    // and the code they run was fetched, so what is
                    // named here is what to ask for and the envelope
                    // waits rather than being dropped.
                    let mut wanted = Unresolved::default();
                    let verified = match tx.verify(ctx) {
                        Ok(v) => Some(v),
                        Err(TransactionVerifyError::Derivation(error)) => {
                            wanted = error.unresolved().cloned().unwrap_or_default();
                            None
                        }
                        Err(_) => None,
                    };
                    let verified = verified.filter(|v| {
                        payer_binding_holds(v, &topology, local_shard, storage.as_deref(), clock_ms)
                            && payer_covers_fee_ceiling(
                                v,
                                &topology,
                                local_shard,
                                storage.as_deref(),
                            )
                    });
                    (tx, verified, wanted)
                });
                report_validation_outcomes(&event_tx, local_shard, results);
            });
    }
}

impl<S, N, D> NodeHost<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Locally-submitted transaction (sim): compute the routing decision
    /// via [`ProcessIo::compute_submit_fanout`] and apply it synchronously
    /// — each affected hosted shard's `step()` runs in this call frame.
    ///
    /// Production's RPC ingestion thread reuses
    /// [`ProcessIo::compute_submit_fanout`] but applies the decision via
    /// `process.shard_event_senders` so cross-thread fan-out doesn't
    /// require a `&mut NodeHost`.
    ///
    /// [`ProcessIo::compute_submit_fanout`]: crate::process::ProcessIo::compute_submit_fanout
    pub(crate) fn handle_submit_transaction(&mut self, tx: &Arc<Transaction>) {
        // Seed the canonical-instance cache so gossip echoes of this tx
        // arriving on other hosted shards' topics share its validation
        // verdict.
        let tx = &self.process.canonical_txs.canonicalize(tx);
        match self.process.compute_submit_fanout(tx) {
            SubmitFanout::Admit {
                source,
                passive,
                touched_shards,
            } => {
                self.shard_loop_mut(source)
                    .step(ShardScopedInput::AdmitAndGossipTransaction {
                        tx: Arc::clone(tx),
                        touched_shards,
                    });
                for shard in passive {
                    self.shard_loop_mut(shard)
                        .step(ShardScopedInput::AdmitTransaction { tx: Arc::clone(tx) });
                }
            }
            SubmitFanout::GossipOnly {
                host,
                touched_shards,
            } => {
                self.shard_loop_mut(host)
                    .step(ShardScopedInput::GossipTransaction {
                        tx: Arc::clone(tx),
                        touched_shards,
                    });
            }
            SubmitFanout::WantsRecords { host, wanted } => {
                self.shard_loop_mut(host)
                    .step(ShardScopedInput::RecordsWanted {
                        wanted: vec![DeferredTransaction::new(
                            Arc::clone(tx),
                            wanted,
                            DeferredOrigin::Submission,
                        )],
                    });
            }
            SubmitFanout::NoHostedShard => {
                tracing::warn!("Dropping locally-submitted transaction: host carries no shard");
            }
            SubmitFanout::Underivable => {}
        }
    }
}

/// Whether the payer's rule admits the signer of a transaction whose
/// payer is local, with maturity judged at `clock_ms` — the local
/// admission instant. `true` for a remote payer — the rule is the payer
/// shard's state, so only that shard's admission judges it. Advisory
/// like the ceiling check beside it: the builder and vote checks stay
/// the deterministic authorities.
fn payer_binding_holds<S: SubstateStore>(
    tx: &Verified<Transaction>,
    topology: &TopologySnapshot,
    local_shard: ShardId,
    storage: Option<&S>,
    clock_ms: u64,
) -> bool {
    if topology.shard_trie().shard_for_prefix(tx.fee_vault().owner) != local_shard {
        return true;
    }
    let auth_cell = storage
        .and_then(|storage| storage.get_substate_at_height(tx.auth_cell(), storage.jmt_height()))
        .flatten();
    if !tx.payer_admits_signer(auth_cell.as_deref(), clock_ms) {
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
/// here — the payer shard's own admission judges them), an unwired
/// store, or unavailable history.
fn payer_covers_fee_ceiling<S: SubstateStore>(
    tx: &Verified<Transaction>,
    topology: &TopologySnapshot,
    local_shard: ShardId,
    storage: Option<&S>,
) -> bool {
    let vm = tx.body();
    let vault = tx.fee_vault();
    if topology.shard_trie().shard_for_prefix(vault.owner) != local_shard {
        return true;
    }
    let Some(storage) = storage else {
        return true;
    };
    let Some(cell) = storage.get_substate_at_height(vault, storage.jmt_height()) else {
        return true;
    };
    let balance = cell
        .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
        .map_or(0u128, u128::from_le_bytes);
    if balance < vm.max_fee {
        tracing::debug!(
            tx_hash = ?tx.hash(),
            balance,
            max_fee = vm.max_fee,
            "Refusing admission: payer cannot cover the signed fee ceiling"
        );
        return false;
    }
    true
}
