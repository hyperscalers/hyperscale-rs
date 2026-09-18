//! Instance record fetch response (cross-shard component resolution).

use hyperscale_hbor::{Bytes, Capped, Hbor};
use hyperscale_vm_types::MAX_CELL_VALUE_LEN;

use crate::network::request::MAX_INSTANCE_RECORDS_PER_REQUEST;
use crate::{MessageClass, NetworkMessage};

/// Response to an instance record fetch request.
///
/// Carries the configuration leaves the responder holds, verbatim;
/// missing entries are simply absent. The receiver identifies each
/// record by re-deriving the address its contents commit — the request's
/// own ids are the only trust anchor, so no addresses ride back.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetInstanceRecordsResponse {
    /// The found records, as their configuration leaves store them, each
    /// no larger than the cell that held it — so a well-formed frame
    /// cannot name a record no configuration leaf could have stored.
    pub records: Capped<Vec<Bytes<MAX_CELL_VALUE_LEN>>, MAX_INSTANCE_RECORDS_PER_REQUEST>,
}

impl GetInstanceRecordsResponse {
    /// Build a response carrying the supplied records.
    #[must_use]
    pub const fn new(
        records: Capped<Vec<Bytes<MAX_CELL_VALUE_LEN>>, MAX_INSTANCE_RECORDS_PER_REQUEST>,
    ) -> Self {
        Self { records }
    }
}

impl NetworkMessage for GetInstanceRecordsResponse {
    fn message_type_id() -> &'static str {
        "instance_record.response"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}
