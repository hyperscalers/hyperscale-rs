//! Core retry loop with peer selection, backoff, and rotation.
//!
//! Implements request-centric retry: retries the same peer first (packet loss
//! is probabilistic), only rotating after a threshold of failures.

use super::{RequestError, RequestManager, RequestPriority};
use crate::adapter::NetworkError;
use bytes::Bytes;
use hyperscale_metrics as metrics;
use libp2p::PeerId;
use std::time::Duration;
use tracing::{debug, trace, warn};

impl RequestManager {
    pub(super) async fn request_inner(
        &self,
        peers: &[PeerId],
        preferred_peer: Option<PeerId>,
        request_desc: &str,
        data: &[u8],
        priority: RequestPriority,
    ) -> Result<(PeerId, Bytes), RequestError> {
        let mut attempts: u32 = 0;
        let mut current_peer_attempts: u32 = 0;

        // Select initial peer.
        // Use the preferred peer if provided and it's in our peer list,
        // otherwise fall back to health-weighted random selection.
        let mut current_peer = match preferred_peer {
            Some(peer) if peers.contains(&peer) => peer,
            _ => self
                .health
                .select_peer(peers)
                .ok_or(RequestError::NoPeers)?,
        };

        // Compute initial backoff based on peer RTT (if known) and priority
        let mut backoff = self.compute_initial_backoff(&current_peer, priority);

        loop {
            // Record request start
            self.health.record_request_started(&current_peer);

            debug!(
                peer = ?current_peer,
                attempts,
                request = %request_desc,
                "Starting request attempt"
            );

            // Use speculative retry to race against packet loss
            let result = self
                .send_request_with_speculative_retry(&current_peer, data, priority)
                .await;

            debug!(
                peer = ?current_peer,
                attempts,
                request = %request_desc,
                result_ok = result.is_ok(),
                "Request attempt completed"
            );

            match result {
                Ok((response, elapsed)) => {
                    // Success! Update health and return.
                    self.health.record_success(&current_peer, elapsed);

                    // Maybe increase concurrency if we're doing well
                    self.maybe_increase_concurrency();

                    trace!(
                        peer = ?current_peer,
                        attempts,
                        elapsed_ms = elapsed.as_millis(),
                        request = %request_desc,
                        "Request succeeded"
                    );
                    return Ok((current_peer, response.into()));
                }

                Err(NetworkError::Timeout) => {
                    // Timeout is NOT necessarily a peer problem—could be packet loss.
                    // Retry same peer first before rotating.
                    current_peer_attempts += 1;
                    attempts += 1;
                    metrics::record_request_retry("timeout");

                    self.health.record_failure(&current_peer, true);

                    if current_peer_attempts >= self.config.retries_before_rotation {
                        // Rotate to next peer
                        debug!(
                            peer = ?current_peer,
                            current_peer_attempts,
                            request = %request_desc,
                            "Rotating to next peer after retries"
                        );

                        if let Some(next_peer) =
                            self.health.select_peer_excluding(peers, &current_peer)
                        {
                            current_peer = next_peer;
                        }
                        // If no other peer available, continue with current
                        current_peer_attempts = 0;
                    } else {
                        debug!(
                            peer = ?current_peer,
                            current_peer_attempts,
                            retries_before_rotation = self.config.retries_before_rotation,
                            request = %request_desc,
                            "Retrying same peer after timeout"
                        );
                    }

                    // Backoff before retry
                    tokio::time::sleep(backoff).await;
                    backoff = Duration::from_secs_f64(
                        (backoff.as_secs_f64() * self.config.backoff_multiplier)
                            .min(self.config.max_backoff.as_secs_f64()),
                    );
                }

                Err(NetworkError::NetworkShutdown) => {
                    // Network is shutting down, don't retry
                    self.health.record_request_cancelled(&current_peer);
                    return Err(RequestError::Shutdown);
                }

                Err(e) => {
                    // Other error—record and rotate.
                    attempts += 1;
                    metrics::record_request_retry("error");
                    self.health.record_failure(&current_peer, false);

                    warn!(
                        peer = ?current_peer,
                        error = ?e,
                        request = %request_desc,
                        "Request failed with error, rotating"
                    );

                    if let Some(next_peer) = self.health.select_peer_excluding(peers, &current_peer)
                    {
                        current_peer = next_peer;
                    }
                    current_peer_attempts = 0;
                }
            }

            // Check if we've exhausted all attempts
            if attempts >= self.config.max_total_attempts {
                metrics::increment_dispatch_failures(request_desc);
                warn!(
                    attempts,
                    max = self.config.max_total_attempts,
                    request = %request_desc,
                    "Request exhausted all attempts"
                );
                return Err(RequestError::Exhausted { attempts });
            }
        }
    }
}
