//! Common BLS signature verification helpers.

use hyperscale_metrics as metrics;
use hyperscale_types::{
    Bls12381G1PublicKey, Bls12381G2Signature, ShardGroupId, Topology, ValidatorId,
};
use tracing::warn;

/// Verify a BLS12-381 signature and record latency metrics.
pub(super) fn verify_bls_with_metrics(
    msg: &[u8],
    public_key: &Bls12381G1PublicKey,
    signature: &Bls12381G2Signature,
    label: &str,
) -> bool {
    let start = std::time::Instant::now();
    let valid = hyperscale_types::verify_bls12381_v1(msg, public_key, signature);
    metrics::record_signature_verification_latency(label, start.elapsed().as_secs_f64());
    valid
}

/// Resolve a sender's public key after verifying committee membership.
///
/// Returns `None` (with a warning) if the sender is not in the shard's
/// committee or their public key cannot be resolved.
pub(super) fn resolve_sender_key(
    topology: &dyn Topology,
    sender: ValidatorId,
    shard: ShardGroupId,
    context: &str,
) -> Option<Bls12381G1PublicKey> {
    let committee = topology.committee_for_shard(shard);
    if !committee.contains(&sender) {
        warn!(
            sender = sender.0,
            shard = shard.0,
            "{} sender not in shard committee",
            context
        );
        return None;
    }
    let Some(public_key) = topology.public_key(sender) else {
        warn!(
            sender = sender.0,
            "Could not resolve public key for {} sender", context
        );
        return None;
    };
    Some(public_key)
}

/// Verify that a sender is in the expected committee and their BLS signature
/// is valid. Combines [`resolve_sender_key`] and [`verify_bls_with_metrics`].
///
/// Returns `false` (with warnings) on any failure.
pub(super) fn verify_sender_signature(
    topology: &dyn Topology,
    sender: ValidatorId,
    shard: ShardGroupId,
    msg: &[u8],
    signature: &Bls12381G2Signature,
    metric_label: &str,
    context: &str,
) -> bool {
    let Some(public_key) = resolve_sender_key(topology, sender, shard, context) else {
        return false;
    };
    let valid = verify_bls_with_metrics(msg, &public_key, signature, metric_label);
    if !valid {
        warn!(
            sender = sender.0,
            "{} sender signature invalid — dropping", context
        );
    }
    valid
}
