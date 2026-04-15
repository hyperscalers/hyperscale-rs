//! Execution certificate persistence helpers.
//!
//! Writes ECs to two column families:
//! - Primary: `EXECUTION_CERTS_CF` (key: canonical_hash, value: EC)
//! - Index: `EXECUTION_CERTS_BY_HEIGHT_CF` (key: height_BE ++ canonical_hash, value: ())

use crate::column_families::{ExecutionCertsByHeightCf, ExecutionCertsCf};
use crate::core::RocksDbStorage;

use hyperscale_types::{Block, ExecutionCertificate};
use rocksdb::WriteBatch;
use std::sync::Arc;

/// Append execution certificate writes for a block to an existing `WriteBatch`.
///
/// Extracts ECs from the block's wave certificates and folds them into the
/// same atomic batch as JVT + block data (one fsync per block).
pub(crate) fn append_block_certs_to_batch(
    storage: &RocksDbStorage,
    batch: &mut WriteBatch,
    block: &Arc<Block>,
) {
    for wc in &block.certificates {
        for ec in &wc.execution_certificates {
            append_ec_to_batch(storage, batch, ec);
        }
    }
}

fn append_ec_to_batch(
    storage: &RocksDbStorage,
    batch: &mut WriteBatch,
    cert: &Arc<ExecutionCertificate>,
) {
    let canonical_hash = cert.canonical_hash();

    // Primary: canonical_hash → EC (use cached SBOR bytes if available)
    storage.cf_put_raw::<ExecutionCertsCf>(batch, &canonical_hash, cert, cert.cached_sbor_bytes());

    // Index: (block_height, canonical_hash) → ()
    storage.cf_put::<ExecutionCertsByHeightCf>(batch, &(cert.block_height(), canonical_hash), &());
}
