//! Common BLS signature verification helpers.

use hyperscale_metrics::record_signature_verification_latency;
use hyperscale_types::{
    Bls12381G1PublicKey, Bls12381G2Signature, ShardGroupId, TopologySnapshot, ValidatorId,
    verify_bls12381_v1,
};
use tracing::warn;

/// Verify a BLS12-381 signature and record latency metrics.
pub fn verify_bls_with_metrics(
    msg: &[u8],
    public_key: &Bls12381G1PublicKey,
    signature: &Bls12381G2Signature,
    label: &str,
) -> bool {
    let start = std::time::Instant::now();
    let valid = verify_bls12381_v1(msg, public_key, signature);
    record_signature_verification_latency(label, start.elapsed().as_secs_f64());
    valid
}

/// Resolve a sender's public key after verifying committee membership.
///
/// Returns `None` (with a warning) if the sender is not in the shard's
/// committee or their public key cannot be resolved.
pub fn resolve_sender_key(
    topology: &TopologySnapshot,
    sender: ValidatorId,
    shard: ShardGroupId,
    context: &str,
) -> Option<Bls12381G1PublicKey> {
    let committee = topology.committee_for_shard(shard);
    if !committee.contains(&sender) {
        warn!(
            sender = sender.inner(),
            shard = shard.inner(),
            "{} sender not in shard committee",
            context
        );
        return None;
    }
    let Some(public_key) = topology.public_key(sender) else {
        warn!(
            sender = sender.inner(),
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
pub fn verify_sender_signature(
    topology: &TopologySnapshot,
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
            sender = sender.inner(),
            "{} sender signature invalid — dropping", context
        );
    }
    valid
}
