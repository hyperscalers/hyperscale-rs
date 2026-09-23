//! Execution certificate persistence helpers.
//!
//! Writes ECs to a column family keyed by [`hyperscale_types::TickId`] —
//! every copy of the tick no other copy carries — plus an index from each
//! attested transaction to every certificate of this shard's carrying an
//! outcome for it, the key a counterpart shard actually asks by. All of
//! them, because a shard certifies one transaction its verdict and then
//! again whatever settles what the verdict left, and only the asker can
//! tell which answers the question its tick waits on.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_storage::{fold_tick_copy, tick_copies};
use hyperscale_types::{Block, Hash, TickId};
use rocksdb::WriteBatch;

use super::column_families::{ExecutionCertsCf, TxCertIndexCf};
use super::core::RocksDbShardStorage;
use crate::typed_cf::{TypedCf, batch_put, get};

/// Append execution certificate writes for a block to an existing `WriteBatch`.
///
/// Extracts ECs from the block's finalizations and folds them into the
/// same atomic batch as JMT + block data (one fsync per block). The
/// transaction index rides the same batch, so a crash can't leave an index
/// entry pointing at a certificate that was never written.
///
/// Reads the stored copies of each tick, so the caller must hold
/// `commit_lock` — otherwise a concurrent commit could land between the
/// read and the write and drop a copy the other one kept.
pub fn append_block_certs_to_batch(
    storage: &RocksDbShardStorage,
    batch: &mut WriteBatch,
    block: &Block,
) {
    // Resolve the CF handles once for the whole append loop. Per-call
    // `cf_put_raw` would each invoke `storage.cf()`, re-walking the
    // name → handle map per certificate.
    let cf = storage.cf();
    let primary_cf = ExecutionCertsCf::handle(&cf);
    let index_cf = TxCertIndexCf::handle(&cf);
    // Every finalization in a block is this shard's own, so its tick names
    // the local shard — the index below must only ever point there.
    let local_shard = block
        .certificates()
        .first()
        .map(|finalization| finalization.tick_id().shard_id());

    // The transaction index this block widens, seeded from what is
    // stored the first time each transaction is reached.
    let mut widened: BTreeMap<Hash, BTreeSet<TickId>> = BTreeMap::new();
    for (tick_id, copies) in tick_copies(block) {
        // The block's own copies resolve against each other, then against
        // what is stored. A remote tick reaches this shard through
        // whichever of its own finalizations needed it, and a shard's own
        // tick finalizes in two halves that each carry the members they
        // settle, so two blocks can each carry a copy of one tick — nested
        // or disjoint, in either order.
        let mut held =
            get::<ExecutionCertsCf>(&*storage.db, primary_cf, &tick_id).unwrap_or_default();
        let mut changed = false;
        for cert in &copies {
            changed |= fold_tick_copy(&mut held, (*cert).clone());
        }
        if changed {
            batch_put::<ExecutionCertsCf>(batch, primary_cf, &tick_id, &held);
        }
        // Index only this shard's own certificates. A settled cross-shard
        // transaction lands here under both sides' certificates, and the
        // index answers "what did THIS shard attest for the transaction" —
        // the question a counterpart's fallback fetch asks this shard. A
        // remote copy in there serves the requester its own certificate
        // back, which it rightly refuses as unsolicited, and the fetch
        // loops forever. Indexed whether or not the copy was kept: one the
        // fold turns away is carried by a held copy of the same tick.
        if Some(tick_id.shard_id()) != local_shard {
            continue;
        }
        for outcome in copies.iter().flat_map(|cert| cert.tx_outcomes()) {
            widened
                .entry(Hash::from(outcome.tx_hash()))
                .or_insert_with(|| {
                    get::<TxCertIndexCf>(&*storage.db, index_cf, &Hash::from(outcome.tx_hash()))
                        .unwrap_or_default()
                })
                .insert(tick_id);
        }
    }
    // Written once per transaction, after the loop: one block can carry
    // two of this shard's ticks naming one transaction — the tick that
    // ran it and the tick that settled what it left — and a per-tick
    // write would read the stored set before either landed and drop the
    // first.
    for (tx_hash, ticks) in widened {
        batch_put::<TxCertIndexCf>(batch, index_cf, &tx_hash, &ticks);
    }
}
