//! Inbound execution-certificate fetch request handling.

use std::sync::Arc;

use hyperscale_execution::ExecCertStore;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::GetExecutionCertsRequest;
use hyperscale_types::network::response::GetExecutionCertsResponse;
use hyperscale_types::{ExecutionCertificate, WaveId};

/// Serve an inbound execution-certificate fetch request.
///
/// Two tiers: the in-memory [`ExecCertStore`] (entries live here between
/// EC aggregation and the wave's containing block committing) and chain
/// storage via [`PendingChain`]. Cache eviction happens at wave-cert
/// commit, at which point storage is the authoritative source.
pub fn serve_execution_certs_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    exec_cert_store: &ExecCertStore,
    req: &GetExecutionCertsRequest,
) -> GetExecutionCertsResponse {
    let mut certs: Vec<Arc<ExecutionCertificate>> = Vec::new();
    let mut missing: Vec<WaveId> = Vec::new();
    for wave_id in &req.wave_ids {
        match exec_cert_store.get(wave_id) {
            Some(cert) => certs.push(Arc::new((**cert).clone())),
            None => missing.push(wave_id.clone()),
        }
    }

    if !missing.is_empty() {
        for cert in pending_chain.execution_certificates_batch(&missing) {
            certs.push(Arc::new(cert));
        }
    }

    if certs.is_empty() {
        GetExecutionCertsResponse { certificates: None }
    } else {
        record_fetch_response_sent("exec_cert", certs.len());
        GetExecutionCertsResponse {
            certificates: Some(certs),
        }
    }
}
