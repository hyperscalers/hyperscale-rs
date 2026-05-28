//! Common BLS signature verification helpers.

use hyperscale_metrics::record_signature_verification_latency;
use hyperscale_types::{
    Bls12381G1PublicKey, Bls12381G2Signature, ShardGroupId, Signed, SignedContext,
    TopologySnapshot, ValidatorId, verify_bls12381_v1,
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

/// Resolve a signer's public key from topology (without a committee
/// membership check) and verify the BLS signature on a [`Signed`] wire
/// message. Used for block-header proposals, where the proposer identity
/// is the consensus-determined leader rather than a sender claim that
/// needs committee gating.
///
/// Returns `false` (with warnings) when the proposer's key cannot be
/// resolved or the signature fails to validate.
pub fn verify_signed_by_proposer<T: Signed>(
    topology: &TopologySnapshot,
    notification: &T,
    metric_label: &str,
    context: &str,
) -> bool {
    let signer = notification.signer();
    let Some(public_key) = topology.public_key(signer) else {
        warn!(signer = signer.inner(), "Unknown proposer for {}", context);
        return false;
    };
    let start = std::time::Instant::now();
    let valid = notification
        .verify_signature(&SignedContext {
            network: topology.network(),
            public_key: &public_key,
        })
        .is_ok();
    record_signature_verification_latency(metric_label, start.elapsed().as_secs_f64());
    if !valid {
        warn!(
            signer = signer.inner(),
            "{} proposer signature invalid — dropping", context
        );
    }
    valid
}

/// Verify a [`Signed`] wire message whose signer must be a current member
/// of `shard`'s committee. Combines [`resolve_sender_key`] (committee
/// membership gate + key lookup) with the BLS check from the [`Signed`]
/// trait.
///
/// Returns `false` (with warnings) on any failure.
pub fn verify_signed_by_committee<T: Signed>(
    topology: &TopologySnapshot,
    shard: ShardGroupId,
    notification: &T,
    metric_label: &str,
    context: &str,
) -> bool {
    let signer = notification.signer();
    let Some(public_key) = resolve_sender_key(topology, signer, shard, context) else {
        return false;
    };
    let start = std::time::Instant::now();
    let valid = notification
        .verify_signature(&SignedContext {
            network: topology.network(),
            public_key: &public_key,
        })
        .is_ok();
    record_signature_verification_latency(metric_label, start.elapsed().as_secs_f64());
    if !valid {
        warn!(
            signer = signer.inner(),
            "{} sender signature invalid — dropping", context
        );
    }
    valid
}
