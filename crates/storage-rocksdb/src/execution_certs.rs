//! Execution certificate persistence helpers.
//!
//! Writes ECs to two column families:
//! - Primary: `EXECUTION_CERTS_CF` (key: `canonical_hash`, value: EC)
//! - Index: `EXECUTION_CERTS_BY_HEIGHT_CF` (key: `height_BE` ++ `canonical_hash`, value: ())

use std::sync::Arc;

use hyperscale_types::{Block, ExecutionCertificate};
use rocksdb::{ColumnFamily, WriteBatch};

use crate::column_families::{ExecutionCertsByHeightCf, ExecutionCertsCf};
use crate::core::RocksDbStorage;
use crate::typed_cf::{TypedCf, batch_put, batch_put_raw};

/// Append execution certificate writes for a block to an existing `WriteBatch`.
///
/// Extracts ECs from the block's wave certificates and folds them into the
/// same atomic batch as JMT + block data (one fsync per block).
pub fn append_block_certs_to_batch(
    storage: &RocksDbStorage,
    batch: &mut WriteBatch,
    block: &Arc<Block>,
) {
    // Resolve column-family handles once for the whole append loop. Per-call
    // `cf_put`/`cf_put_raw` would each invoke `storage.cf()`, re-walking all
    // 12 CFs through `RocksDB`'s name → handle map per certificate.
    let cf = storage.cf();
    let primary_cf = ExecutionCertsCf::handle(&cf);
    let index_cf = ExecutionCertsByHeightCf::handle(&cf);
    for fw in block.certificates().iter() {
        for ec in &fw.certificate.execution_certificates {
            append_ec_to_batch(batch, primary_cf, index_cf, ec);
        }
    }
}

fn append_ec_to_batch(
    batch: &mut WriteBatch,
    primary_cf: &ColumnFamily,
    index_cf: &ColumnFamily,
    cert: &Arc<ExecutionCertificate>,
) {
    let canonical_hash = cert.canonical_hash().into_raw();

    // Primary: canonical_hash → EC (use cached SBOR bytes if available)
    batch_put_raw::<ExecutionCertsCf>(
        batch,
        primary_cf,
        &canonical_hash,
        cert,
        cert.cached_sbor_bytes(),
    );

    // Index: (block_height, canonical_hash) → ()
    batch_put::<ExecutionCertsByHeightCf>(
        batch,
        index_cf,
        &(cert.block_height().inner(), canonical_hash),
        &(),
    );
}
