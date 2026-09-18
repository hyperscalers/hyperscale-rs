//! Package artifact fetch response (cross-shard code availability).

use hyperscale_hbor::{Bytes, Capped, Hbor};

use crate::network::request::MAX_PACKAGE_ARTIFACTS_PER_REQUEST;
use crate::{MAX_ARTIFACT_BYTES, MessageClass, NetworkMessage};

/// Response to a package artifact fetch request.
///
/// Carries the requested artifacts the responder holds, verbatim;
/// missing entries are simply absent. The receiver identifies each
/// artifact by hashing it — the request's own ids are the only trust
/// anchor, so no ids ride back.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetPackageArtifactsResponse {
    /// The found artifacts' bytes, each no larger than the publish that
    /// could have carried it — so a well-formed frame cannot name an
    /// artifact no publish transaction could have put on the chain.
    pub artifacts: Capped<Vec<Bytes<MAX_ARTIFACT_BYTES>>, MAX_PACKAGE_ARTIFACTS_PER_REQUEST>,
}

impl GetPackageArtifactsResponse {
    /// Build a response carrying the supplied artifacts.
    #[must_use]
    pub const fn new(
        artifacts: Capped<Vec<Bytes<MAX_ARTIFACT_BYTES>>, MAX_PACKAGE_ARTIFACTS_PER_REQUEST>,
    ) -> Self {
        Self { artifacts }
    }
}

impl NetworkMessage for GetPackageArtifactsResponse {
    fn message_type_id() -> &'static str {
        "package_artifact.response"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}
