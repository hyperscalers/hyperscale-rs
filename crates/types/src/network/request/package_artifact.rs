//! Package artifact fetch request (cross-shard code availability).

use hyperscale_hbor::{Capped, Hbor};

use crate::network::response::GetPackageArtifactsResponse;
use crate::{Hash, MessageClass, NetworkMessage, Request};

/// The most artifacts one request may name.
///
/// An artifact runs to a transaction's whole byte budget, so the batch
/// stays small enough that a full response sits well inside the frame
/// cap.
pub const MAX_PACKAGE_ARTIFACTS_PER_REQUEST: usize = 4;

/// Request to fetch package artifacts by content address.
///
/// Served by nodes of the shard owning the publisher's prefix, from the
/// package index their own commits wrote. No scope rides along: the
/// identity is the hash of the artifact's own bytes, so any answer is
/// self-verifying and any holder may serve.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetPackageArtifactsRequest {
    /// The requested content addresses.
    pub packages: Capped<Vec<Hash>, MAX_PACKAGE_ARTIFACTS_PER_REQUEST>,
}

impl GetPackageArtifactsRequest {
    /// Build a request for the listed `packages`.
    #[must_use]
    pub const fn new(packages: Capped<Vec<Hash>, MAX_PACKAGE_ARTIFACTS_PER_REQUEST>) -> Self {
        Self { packages }
    }
}

impl NetworkMessage for GetPackageArtifactsRequest {
    fn message_type_id() -> &'static str {
        "package_artifact.request"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl Request for GetPackageArtifactsRequest {
    type Response = GetPackageArtifactsResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.artifacts.is_empty()
    }
}
