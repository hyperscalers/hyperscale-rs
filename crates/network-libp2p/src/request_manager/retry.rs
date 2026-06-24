//! Core retry loop with peer selection, backoff, and rotation.
//!
//! Implements request-centric retry: retries the same peer first (packet loss
//! is probabilistic), only rotating after a threshold of failures.

use std::time::{Duration, Instant};

use bytes::Bytes;
use hyperscale_metrics::{increment_dispatch_failures, record_request_retry};
use hyperscale_types::{MessageClass, ShardId};
use libp2p::PeerId;
use tokio::time::sleep;
use tracing::{debug, trace, warn};

use super::peer_health::FailureKind;
use super::{RequestError, RequestManager};
use crate::adapter::NetworkError;

impl RequestManager {
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)] // single retry/backoff/peer-rotation loop; splitting would scatter shared state
    pub(super) async fn request_inner(
        &self,
        peers: &[PeerId],
        preferred_peer: Option<PeerId>,
        shard: ShardId,
        request_desc: &str,
        type_id: &'static str,
        data: &[u8],
        class: MessageClass,
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

        let mut backoff = self.compute_initial_backoff(&current_peer, class);

        loop {
            // Record request start
            self.health.record_request_started(&current_peer);

            debug!(
                peer = ?current_peer,
                attempts,
                request = %request_desc,
                "Starting request attempt"
            );

            let start = Instant::now();
            let result = self
                .send_request(&current_peer, shard, type_id, data, class)
                .await;
            let elapsed = start.elapsed();

            debug!(
                peer = ?current_peer,
                attempts,
                request = %request_desc,
                result_ok = result.is_ok(),
                "Request attempt completed"
            );

            match result {
                Ok(response) => {
                    // Success! Update health and return.
                    self.health.record_success(&current_peer, elapsed);

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
                    record_request_retry("timeout");

                    self.health
                        .record_failure(&current_peer, FailureKind::Timeout);

                    if current_peer_attempts >= self.config.retries_before_rotation {
                        // Rotate to next peer
                        warn!(
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
                        warn!(
                            peer = ?current_peer,
                            current_peer_attempts,
                            retries_before_rotation = self.config.retries_before_rotation,
                            request = %request_desc,
                            "Retrying same peer after timeout"
                        );
                    }

                    // Backoff before retry
                    sleep(backoff).await;
                    backoff = self.grow_backoff(backoff);
                }

                Err(NetworkError::NetworkShutdown) => {
                    // Network is shutting down, don't retry
                    self.health.record_request_cancelled(&current_peer);
                    return Err(RequestError::Shutdown);
                }

                Err(e) => {
                    // Other error—record and rotate.
                    attempts += 1;
                    record_request_retry("error");
                    self.health
                        .record_failure(&current_peer, FailureKind::Other);

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

                    // Backoff before retry
                    sleep(backoff).await;
                    backoff = self.grow_backoff(backoff);
                }
            }

            // Check if we've exhausted all attempts
            if attempts >= self.config.max_total_attempts {
                increment_dispatch_failures(request_desc);
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

    /// Grow the retry backoff toward `max_backoff` by the configured
    /// multiplier.
    fn grow_backoff(&self, backoff: Duration) -> Duration {
        Duration::from_secs_f64(
            (backoff.as_secs_f64() * self.config.backoff_multiplier)
                .min(self.config.max_backoff.as_secs_f64()),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::request_manager::{RequestManager, RequestManagerConfig};
    use crate::request_pool::RequestPool;

    /// Deterministic stand-in for `RequestStreamPool`. Pre-programmed with a
    /// queue of responses; records every send call so tests can assert on
    /// peer rotation order without depending on health-weighted RNG.
    struct MockPool {
        inner: Mutex<MockState>,
    }

    struct MockState {
        responses: VecDeque<Result<Vec<u8>, NetworkError>>,
        calls: Vec<MockCall>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockCall {
        peer: PeerId,
        type_id: &'static str,
    }

    impl MockPool {
        fn new(responses: Vec<Result<Vec<u8>, NetworkError>>) -> Arc<Self> {
            Arc::new(Self {
                inner: Mutex::new(MockState {
                    responses: responses.into(),
                    calls: Vec::new(),
                }),
            })
        }

        fn calls(&self) -> Vec<MockCall> {
            self.inner.lock().unwrap().calls.clone()
        }
    }

    impl RequestPool for MockPool {
        fn send<'a>(
            &'a self,
            peer: PeerId,
            _shard: ShardId,
            type_id: &'static str,
            _data: Vec<u8>,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, NetworkError>> + Send + 'a>> {
            // Pop the next pre-programmed response and record the call.
            // Defaulting to Timeout when the queue runs dry lets tests
            // pre-program only the responses they care about — exhaustion
            // tests can supply zero responses without binding to the exact
            // attempt budget. The lock is released before the future awaits.
            let response = {
                let mut state = self.inner.lock().unwrap();
                state.calls.push(MockCall { peer, type_id });
                state
                    .responses
                    .pop_front()
                    .unwrap_or(Err(NetworkError::Timeout))
            };
            Box::pin(async move { response })
        }
    }

    /// Config tuned for fast, deterministic retry tests: zero backoff (so
    /// `tokio::time::sleep` returns immediately) and a small attempt budget
    /// so exhaustion paths complete quickly.
    fn fast_config() -> RequestManagerConfig {
        RequestManagerConfig {
            max_concurrent: 16,
            max_per_peer: 8,
            retries_before_rotation: 2,
            max_total_attempts: 5,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            backoff_multiplier: 1.0,
            sheddable_max_concurrent: 4,
            cross_shard_max_concurrent: 4,
        }
    }

    fn manager_with(
        responses: Vec<Result<Vec<u8>, NetworkError>>,
    ) -> (Arc<MockPool>, RequestManager) {
        let pool = MockPool::new(responses);
        let manager = RequestManager::new(pool.clone(), fast_config());
        (pool, manager)
    }

    async fn send(
        manager: &RequestManager,
        peers: &[PeerId],
        preferred: Option<PeerId>,
    ) -> Result<(PeerId, Bytes), RequestError> {
        manager
            .request(
                peers,
                preferred,
                ShardId::ROOT,
                "test".to_string(),
                "test.req",
                vec![1, 2, 3],
                MessageClass::Recovery,
            )
            .await
    }

    #[tokio::test]
    async fn success_on_first_attempt_returns_response() {
        let peer = PeerId::random();
        let (pool, manager) = manager_with(vec![Ok(b"response".to_vec())]);

        let result = send(&manager, &[peer], None).await;
        let (responding_peer, bytes) = result.expect("first attempt succeeds");
        assert_eq!(responding_peer, peer);
        assert_eq!(bytes.as_ref(), b"response");
        assert_eq!(
            pool.calls(),
            vec![MockCall {
                peer,
                type_id: "test.req"
            }]
        );
    }

    #[tokio::test]
    async fn timeout_under_rotation_threshold_retries_same_peer() {
        // retries_before_rotation = 2 → after 1 timeout we should retry the
        // same peer (rotation only triggers on the 2nd consecutive timeout).
        // Use a 2-peer list with preferred=A so an erroneous early rotation
        // would visibly send the second attempt to peer B — a 1-peer list
        // would mask the bug because there's no other peer to rotate to.
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let (pool, manager) =
            manager_with(vec![Err(NetworkError::Timeout), Ok(b"response".to_vec())]);

        let (responding_peer, _) = send(&manager, &[peer_a, peer_b], Some(peer_a))
            .await
            .expect("retry succeeds");
        assert_eq!(responding_peer, peer_a);
        assert_eq!(
            pool.calls(),
            vec![
                MockCall {
                    peer: peer_a,
                    type_id: "test.req"
                },
                MockCall {
                    peer: peer_a,
                    type_id: "test.req"
                },
            ],
            "second attempt must stay on peer A — early rotation would route to B"
        );
    }

    #[tokio::test]
    async fn rotates_after_retries_before_rotation_consecutive_timeouts() {
        // retries_before_rotation = 2 → first two timeouts hit peer A, then
        // we rotate to peer B for the third attempt.
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let (pool, manager) = manager_with(vec![
            Err(NetworkError::Timeout),
            Err(NetworkError::Timeout),
            Ok(b"response".to_vec()),
        ]);

        let (responding_peer, _) = send(&manager, &[peer_a, peer_b], Some(peer_a))
            .await
            .expect("rotated retry succeeds");
        assert_eq!(responding_peer, peer_b);
        assert_eq!(
            pool.calls(),
            vec![
                MockCall {
                    peer: peer_a,
                    type_id: "test.req"
                },
                MockCall {
                    peer: peer_a,
                    type_id: "test.req"
                },
                MockCall {
                    peer: peer_b,
                    type_id: "test.req"
                },
            ],
            "third attempt must rotate to peer B"
        );
    }

    #[tokio::test]
    async fn non_timeout_error_rotates_immediately() {
        // Errors other than Timeout/NetworkShutdown rotate on the very next
        // attempt without consuming the per-peer retry budget.
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let (pool, manager) = manager_with(vec![
            Err(NetworkError::InvalidPeerId),
            Ok(b"response".to_vec()),
        ]);

        let (responding_peer, _) = send(&manager, &[peer_a, peer_b], Some(peer_a))
            .await
            .expect("rotation after non-timeout succeeds");
        assert_eq!(responding_peer, peer_b);
        assert_eq!(
            pool.calls(),
            vec![
                MockCall {
                    peer: peer_a,
                    type_id: "test.req"
                },
                MockCall {
                    peer: peer_b,
                    type_id: "test.req"
                },
            ]
        );
    }

    #[tokio::test]
    async fn network_shutdown_returns_immediately_without_retry() {
        let peer = PeerId::random();
        let (pool, manager) = manager_with(vec![Err(NetworkError::NetworkShutdown)]);

        let result = send(&manager, &[peer], None).await;
        assert!(
            matches!(result, Err(RequestError::Shutdown)),
            "shutdown must short-circuit retry, got {result:?}"
        );
        assert_eq!(pool.calls().len(), 1, "no retry after shutdown");
    }

    #[tokio::test]
    async fn empty_peer_list_returns_no_peers_without_calling_pool() {
        let (pool, manager) = manager_with(vec![]);
        let result = send(&manager, &[], None).await;
        assert!(
            matches!(result, Err(RequestError::NoPeers)),
            "empty list must short-circuit before any send, got {result:?}"
        );
        assert!(pool.calls().is_empty());
    }

    #[tokio::test]
    async fn exhausts_after_max_total_attempts_persistent_timeouts() {
        // No pre-programmed responses → MockPool returns Timeout for every
        // call until the manager exhausts its attempt budget. The exact
        // count is asserted to catch off-by-one in the increment-then-check
        // ordering at the bottom of the loop.
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let (pool, manager) = manager_with(Vec::new());

        let result = send(&manager, &[peer_a, peer_b], Some(peer_a)).await;
        match result {
            Err(RequestError::Exhausted { attempts }) => assert_eq!(attempts, 5),
            other => panic!("expected Exhausted{{attempts: 5}}, got {other:?}"),
        }
        assert_eq!(pool.calls().len(), 5);
    }

    #[tokio::test]
    async fn preferred_peer_is_honored_when_in_list() {
        // Without a preferred peer, the initial selection is health-weighted
        // random — so this test pins peer_b explicitly to prove the
        // preferred-peer override works rather than just getting lucky.
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let (pool, manager) = manager_with(vec![Ok(b"r".to_vec())]);

        let (responding_peer, _) = send(&manager, &[peer_a, peer_b], Some(peer_b))
            .await
            .expect("succeeds");
        assert_eq!(responding_peer, peer_b);
        assert_eq!(pool.calls()[0].peer, peer_b);
    }

    #[tokio::test]
    async fn preferred_peer_falls_back_to_selection_when_not_in_list() {
        let in_list = PeerId::random();
        let not_in_list = PeerId::random();
        let (pool, manager) = manager_with(vec![Ok(b"r".to_vec())]);

        let (responding_peer, _) = send(&manager, &[in_list], Some(not_in_list))
            .await
            .expect("succeeds");
        assert_eq!(
            responding_peer, in_list,
            "preferred peer absent from list must be ignored, not used"
        );
        assert_eq!(pool.calls()[0].peer, in_list);
    }
}
