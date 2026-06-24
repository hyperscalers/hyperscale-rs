//! Transaction scenarios.

use std::sync::Arc;

use hyperscale_types::{ShardId, TransactionDecision, TransactionStatus};
use radix_common::network::NetworkDefinition;

use crate::tx::{account_from_seed, build_faucet_tx, signer_from_seed, validity_around};
use crate::wait::{await_height, await_tx_terminal};
use crate::{Cluster, epochs};

/// Submit a faucet-funded single-shard transfer and assert it accepts.
///
/// Awaits the transfer completing with an `Accept` decision and the root shard
/// advancing past genesis. The faucet is a fixed native component on both
/// harnesses, so no funded-account discovery is needed.
///
/// # Panics
///
/// Panics if the transfer does not accept within budget or the root shard does
/// not advance past genesis.
pub fn single_shard_tx(c: &mut impl Cluster) {
    let signer = signer_from_seed(1);
    let to = account_from_seed(2);
    let transfer = build_faucet_tx(
        to,
        &signer,
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    let hash = transfer.hash();
    c.submit(Arc::new(transfer));

    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "single-shard tx did not accept within budget; status = {status:?}"
    );
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(2)),
        "root shard did not advance past genesis"
    );
}
