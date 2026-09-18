//! Instance record fetch request (cross-shard component resolution).

use hyperscale_hbor::{Capped, Hbor};
use hyperscale_vm_types::Address;

use crate::network::response::GetInstanceRecordsResponse;
use crate::{MessageClass, NetworkMessage, Request};

/// The most records one request may name.
///
/// A record is a package hash, a bounded configuration and a salt, so
/// the batch can be far wider than the artifact one and still sit well
/// inside the frame cap. What bounds it in practice is the manifest: a
/// transaction naming more components than this declares more calls than
/// one envelope carries.
pub const MAX_INSTANCE_RECORDS_PER_REQUEST: usize = 32;

/// Request to fetch the creation-fixed records of component addresses.
///
/// Served by nodes of the shard owning each component's own prefix, from
/// the configuration leaf its seal wrote. No scope rides along: a
/// component's address is the hash of its record, so any answer is
/// self-verifying and any holder may serve.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetInstanceRecordsRequest {
    /// The component addresses whose records are wanted.
    pub instances: Capped<Vec<Address>, MAX_INSTANCE_RECORDS_PER_REQUEST>,
}

impl GetInstanceRecordsRequest {
    /// Build a request for the listed `instances`.
    #[must_use]
    pub const fn new(instances: Capped<Vec<Address>, MAX_INSTANCE_RECORDS_PER_REQUEST>) -> Self {
        Self { instances }
    }
}

impl NetworkMessage for GetInstanceRecordsRequest {
    fn message_type_id() -> &'static str {
        "instance_record.request"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl Request for GetInstanceRecordsRequest {
    type Response = GetInstanceRecordsResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.records.is_empty()
    }
}
