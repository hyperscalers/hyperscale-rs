//! Common signature verification helpers.

use hyperscale_metrics::{
    record_signature_verification_failure, record_signature_verification_latency,
};
use hyperscale_network::Verdict;
use hyperscale_types::{
    ConsensusPublicKey, ConsensusSignature, ShardId, Signed, SignedContext, Stopwatch,
    TopologySnapshot, ValidatorId, Verifier,
};
use tracing::warn;

/// Verify a consensus signature, recording its latency and any failure.
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
    if !valid {
        record_signature_verification_failure(label);
    }
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

/// The verdict of a signature check: the message is taken when the
/// signature holds, and is its sender's fault when it does not.
const fn signature_verdict(valid: bool) -> Verdict {
    if valid {
        Verdict::Accept
    } else {
        Verdict::Reject
    }
}

/// Resolve a signer's public key from topology (without a committee
/// membership check) and verify the signature on a [`Signed`] wire
/// message. Used for block-header proposals, where the proposer identity
/// is the consensus-determined leader rather than a sender claim that
/// needs committee gating.
///
/// [`Verdict::Ignore`] (with a warning) when the proposer's key cannot be
/// resolved, which a host whose topology is behind cannot tell from a false
/// claim; [`Verdict::Reject`] when the signature fails to validate.
pub fn verify_signed_by_proposer<T: Signed>(
    verifier: &dyn Verifier,
    topology_snapshot: &TopologySnapshot,
    notification: &T,
    metric_label: &str,
    context: &str,
) -> Verdict {
    let signer = notification.signer();
    let Some(public_key) = topology_snapshot.public_key(signer) else {
        warn!(signer = signer.inner(), "Unknown proposer for {}", context);
        return Verdict::Ignore;
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
        record_signature_verification_failure(metric_label);
        warn!(
            signer = signer.inner(),
            "{} proposer signature invalid — dropping", context
        );
    }
    signature_verdict(valid)
}

/// Verify a [`Signed`] wire message whose signer must be a member of
/// `shard`'s committee in `committee_snapshot`. Combines
/// [`resolve_sender_key`] (committee membership gate + key lookup) with the
/// signature check from the [`Signed`] trait.
///
/// [`Verdict::Ignore`] (with a warning) when the signer is outside the
/// committee or its key cannot be resolved: a host whose view of the
/// committee is behind refuses an honest message that way.
/// [`Verdict::Reject`] when the signature fails to validate.
pub fn verify_signed_by_committee<T: Signed>(
    verifier: &dyn Verifier,
    committee_snapshot: &TopologySnapshot,
    topology_snapshot: &TopologySnapshot,
    shard: ShardId,
    notification: &T,
    metric_label: &str,
    context: &str,
) -> Verdict {
    let signer = notification.signer();
    let Some(public_key) = resolve_sender_key(
        committee_snapshot,
        topology_snapshot,
        signer,
        shard,
        context,
    ) else {
        return Verdict::Ignore;
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
        record_signature_verification_failure(metric_label);
        warn!(
            signer = signer.inner(),
            "{} sender signature invalid — dropping", context
        );
    }
    signature_verdict(valid)
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_types::test_utils::TestCommittee;
    use hyperscale_types::{NetworkDefinition, ValidatorId};

    use super::*;

    /// A message whose signer signs a fixed string.
    struct Note {
        signer: ValidatorId,
        signature: ConsensusSignature,
    }

    impl Signed for Note {
        fn signer(&self) -> ValidatorId {
            self.signer
        }

        fn signature(&self) -> &ConsensusSignature {
            &self.signature
        }

        fn signing_message(&self, _network: &NetworkDefinition) -> Vec<u8> {
            b"note".to_vec()
        }
    }

    fn note(committee: &TestCommittee, claimed: ValidatorId, by: usize) -> Note {
        Note {
            signer: claimed,
            signature: committee.signer(by).sign(b"note").expect("signs"),
        }
    }

    #[test]
    fn a_proposer_signature_that_holds_is_taken_and_one_that_fails_is_the_senders() {
        let committee = TestCommittee::new(4, 7);
        let topology = committee.topology_snapshot(1);
        let check =
            |note: &Note| verify_signed_by_proposer(&BlsVerifier, &topology, note, "test", "test");

        let own = note(&committee, committee.validator_id(1), 1);
        assert_eq!(check(&own), Verdict::Accept);
        let forged = note(&committee, committee.validator_id(1), 2);
        assert_eq!(check(&forged), Verdict::Reject);
    }

    #[test]
    fn a_signer_this_host_has_no_key_for_is_not_the_senders_fault() {
        let committee = TestCommittee::new(4, 7);
        let topology = committee.topology_snapshot(1);
        let stranger = ValidatorId::new(1_000);
        let unknown = note(&committee, stranger, 2);

        assert_eq!(
            verify_signed_by_proposer(&BlsVerifier, &topology, &unknown, "test", "test"),
            Verdict::Ignore
        );
        assert_eq!(
            verify_signed_by_committee(
                &BlsVerifier,
                &topology,
                &topology,
                ShardId::ROOT,
                &unknown,
                "test",
                "test",
            ),
            Verdict::Ignore
        );
    }

    #[test]
    fn a_committee_signature_that_fails_is_the_senders() {
        let committee = TestCommittee::new(4, 7);
        let topology = committee.topology_snapshot(1);
        let shard = ShardId::ROOT;
        let member = topology.committee_for_shard(shard)[0];
        let index = committee
            .validator_ids()
            .iter()
            .position(|id| *id == member)
            .expect("the member is in the test committee");
        let check = |note: &Note| {
            verify_signed_by_committee(
                &BlsVerifier,
                &topology,
                &topology,
                shard,
                note,
                "test",
                "test",
            )
        };

        assert_eq!(check(&note(&committee, member, index)), Verdict::Accept);
        assert_eq!(
            check(&note(&committee, member, (index + 1) % 4)),
            Verdict::Reject
        );
    }
}
