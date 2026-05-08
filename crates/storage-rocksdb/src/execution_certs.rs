//! Execution certificate persistence helpers.
//!
//! Writes ECs to a single column family keyed by [`hyperscale_types::WaveId`].

use std::sync::Arc;

use hyperscale_types::{Block, ExecutionCertificate};
use rocksdb::{ColumnFamily, WriteBatch};

use crate::column_families::ExecutionCertsCf;
use crate::core::RocksDbStorage;
use crate::typed_cf::{TypedCf, batch_put_raw};

/// Append execution certificate writes for a block to an existing `WriteBatch`.
///
/// Extracts ECs from the block's wave certificates and folds them into the
/// same atomic batch as JMT + block data (one fsync per block).
pub fn append_block_certs_to_batch(
    storage: &RocksDbStorage,
    batch: &mut WriteBatch,
    block: &Arc<Block>,
) {
    // Resolve the CF handle once for the whole append loop. Per-call
    // `cf_put_raw` would each invoke `storage.cf()`, re-walking the
    // name → handle map per certificate.
    let cf = storage.cf();
    let primary_cf = ExecutionCertsCf::handle(&cf);
    for fw in block.certificates().iter() {
        for ec in fw.certificate().execution_certificates() {
            append_ec_to_batch(batch, primary_cf, ec);
        }
    }
}

fn append_ec_to_batch(
    batch: &mut WriteBatch,
    primary_cf: &ColumnFamily,
    cert: &ExecutionCertificate,
) {
    batch_put_raw::<ExecutionCertsCf>(
        batch,
        primary_cf,
        &cert.wave_id,
        cert,
        cert.cached_sbor_bytes(),
    );
}
