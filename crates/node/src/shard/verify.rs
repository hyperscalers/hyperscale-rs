//! Common signature verification helpers.

use hyperscale_metrics::record_signature_verification_latency;
use hyperscale_types::{
    ConsensusPublicKey, ConsensusSignature, ShardId, Signed, SignedContext, Stopwatch,
    TopologySnapshot, ValidatorId, Verifier,
};
use tracing::warn;

/// Verify a consensus signature and record latency metrics.
pub fn verify_sig_with_metrics(
    verifier: &dyn Verifier,
    msg: &[u8],
    public_key: &ConsensusPublicKey,
    signature: &ConsensusSignature,
    label: &str,
) -> bool {
    let start = Stopwatch::start();
    let valid = verifier.verify(public_key, msg, signature);
    record_signature_verification_latency(label, start.elapsed().as_secs_f64());
    valid
}

/// Resolve a sender's public key after verifying committee membership.
///
/// Membership is read from `committee_snapshot` and the key from
/// `topology_snapshot`, which are the head for a live shard and differ
/// only where the artifact's own window does: a split parent's coast
/// headers are signed by the committee of its terminal window, which the
/// head no longer carries, while its members' keys outlive it in the
/// validator set.
///
/// Returns `None` (with a warning) if the sender is not in the shard's
/// committee or their public key cannot be resolved.
pub fn resolve_sender_key(
    committee_snapshot: &TopologySnapshot,
    topology_snapshot: &TopologySnapshot,
    sender: ValidatorId,
    shard: ShardId,
    context: &str,
) -> Option<ConsensusPublicKey> {
    let committee = committee_snapshot.committee_for_shard(shard);
    if !committee.contains(&sender) {
        warn!(
            sender = sender.inner(),
            shard = shard.inner(),
            "{} sender not in shard committee",
            context
        );
        return None;
    }
    let Some(public_key) = topology_snapshot.public_key(sender) else {
        warn!(
            sender = sender.inner(),
            "Could not resolve public key for {} sender", context
        );
        return None;
    };
    Some(public_key)
}

/// Resolve a signer's public key from topology (without a committee
/// membership check) and verify the signature on a [`Signed`] wire
/// message. Used for block-header proposals, where the proposer identity
/// is the consensus-determined leader rather than a sender claim that
/// needs committee gating.
///
/// Returns `false` (with warnings) when the proposer's key cannot be
/// resolved or the signature fails to validate.
pub fn verify_signed_by_proposer<T: Signed>(
    verifier: &dyn Verifier,
    topology_snapshot: &TopologySnapshot,
    notification: &T,
    metric_label: &str,
    context: &str,
) -> bool {
    let signer = notification.signer();
    let Some(public_key) = topology_snapshot.public_key(signer) else {
        warn!(signer = signer.inner(), "Unknown proposer for {}", context);
        return false;
    };
    let start = Stopwatch::start();
    let valid = notification
        .verify_signature(&SignedContext {
            network: topology_snapshot.network(),
            public_key: &public_key,
            verifier,
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
/// membership gate + key lookup) with the signature check from the [`Signed`]
/// trait.
///
/// Returns `false` (with warnings) on any failure.
pub fn verify_signed_by_committee<T: Signed>(
    verifier: &dyn Verifier,
    topology_snapshot: &TopologySnapshot,
    shard: ShardId,
    notification: &T,
    metric_label: &str,
    context: &str,
) -> bool {
    let signer = notification.signer();
    let Some(public_key) =
        resolve_sender_key(topology_snapshot, topology_snapshot, signer, shard, context)
    else {
        return false;
    };
    let start = Stopwatch::start();
    let valid = notification
        .verify_signature(&SignedContext {
            network: topology_snapshot.network(),
            public_key: &public_key,
            verifier,
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
