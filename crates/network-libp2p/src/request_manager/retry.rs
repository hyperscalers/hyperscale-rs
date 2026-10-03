//! The transport side of the request retry loop: dispatches each attempt
//! [`Attempts`] picks, sleeps the backoff it asks for, and reports what came
//! back.

use std::time::Instant;

use bytes::Bytes;
use hyperscale_metrics::{increment_dispatch_failures, record_request_retry};
use hyperscale_network::retry::{Attempts, Outcome, Resolution};
use hyperscale_types::{MessageClass, ShardId};
use libp2p::PeerId;
use rand::rng;
use tokio::time::sleep;
use tracing::{debug, trace, warn};

use super::{RequestError, RequestManager};
use crate::adapter::NetworkError;

impl RequestManager {
    #[allow(clippy::too_many_arguments)] // one request's peers, payload and class
    pub(super) async fn request_inner(
        &self,
        peers: &[PeerId],
        preferred_peer: Option<PeerId>,
        shard: ShardId,
        request_desc: &str,
        type_id: &'static str,
        data: &[u8],
        class: MessageClass,
        is_empty: fn(&[u8]) -> bool,
    ) -> Result<(PeerId, Bytes), RequestError> {
        let mut attempts = Attempts::start(
            self.config.retry,
            peers.to_vec(),
            preferred_peer,
            class,
            &self.health.lock(),
            self.now(),
            &mut rng(),
        )
        .ok_or(RequestError::NoPeers)?;

        loop {
            // A peer whose (peer, shard) stream is in pool backoff would only
            // instant-fail and re-escalate the backoff, pinning it: the
            // lockout that wedges a freshly split child's sync when
            // co-hosting collapses its committee onto a few peers. When
            // every candidate is backed off, NoPeers lets the caller defer
            // on its own backoff instead of spinning to Exhausted.
            let (peer, timeout) = attempts
                .dispatch(
                    |peer| !self.pool.is_backed_off(peer, shard),
                    &mut self.health.lock(),
                    self.now(),
                    &mut rng(),
                )
                .ok_or(RequestError::NoPeers)?;

            debug!(?peer, request = %request_desc, "Starting request attempt");

            let start = Instant::now();
            let result = self
                .send_request(&peer, shard, type_id, data, timeout)
                .await;
            let outcome = match result {
                Ok(response) if is_empty(&response) => {
                    let rtt = start.elapsed();
                    let resolution = attempts.resolve(
                        Outcome::Empty { rtt },
                        &mut self.health.lock(),
                        self.now(),
                        &mut rng(),
                    );
                    trace!(
                        ?peer,
                        elapsed_ms = rtt.as_millis(),
                        request = %request_desc,
                        "Request answered empty"
                    );
                    if resolution == Resolution::Done {
                        return Ok((peer, response.into()));
                    }
                    continue;
                }
                Ok(response) => {
                    let rtt = start.elapsed();
                    attempts.resolve(
                        Outcome::Answered { rtt },
                        &mut self.health.lock(),
                        self.now(),
                        &mut rng(),
                    );
                    trace!(
                        ?peer,
                        elapsed_ms = rtt.as_millis(),
                        request = %request_desc,
                        "Request succeeded"
                    );
                    return Ok((peer, response.into()));
                }
                Err(NetworkError::NetworkShutdown) => {
                    self.health.lock().record_cancelled(peer);
                    return Err(RequestError::Shutdown);
                }
                Err(NetworkError::Timeout) => {
                    record_request_retry("timeout");
                    warn!(?peer, request = %request_desc, "Request attempt timed out");
                    Outcome::TimedOut
                }
                Err(e) => {
                    record_request_retry("error");
                    warn!(?peer, error = ?e, request = %request_desc, "Request attempt failed");
                    Outcome::Failed
                }
            };

            let resolution =
                attempts.resolve(outcome, &mut self.health.lock(), self.now(), &mut rng());
            match resolution {
                Resolution::Retry { after } => sleep(after).await,
                Resolution::Exhausted { attempts, after } => {
                    sleep(after).await;
                    increment_dispatch_failures(request_desc);
                    warn!(attempts, request = %request_desc, "Request exhausted all attempts");
                    return Err(RequestError::Exhausted { attempts });
                }
                Resolution::Done => unreachable!("only an answer resolves a request as done"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, VecDeque};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use hyperscale_network::retry::RetryConfig;

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
        backed_off: HashSet<PeerId>,
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
                    backed_off: HashSet::new(),
                }),
            })
        }

        fn calls(&self) -> Vec<MockCall> {
            self.inner.lock().unwrap().calls.clone()
        }

        fn mark_backed_off(&self, peers: &[PeerId]) {
            self.inner.lock().unwrap().backed_off.extend(peers);
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

        fn is_backed_off(&self, peer: PeerId, _shard: ShardId) -> bool {
            self.inner.lock().unwrap().backed_off.contains(&peer)
        }
    }

    /// Config tuned for fast, deterministic retry tests: zero backoff (so
    /// `tokio::time::sleep` returns immediately) and a small attempt budget
    /// so exhaustion paths complete quickly.
    fn fast_config() -> RequestManagerConfig {
        RequestManagerConfig {
            max_concurrent: 16,
            retry: RetryConfig {
                retries_before_rotation: 2,
                max_total_attempts: 5,
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                backoff_multiplier: 1.0,
            },
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
                |bytes| bytes == b"empty",
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
    async fn an_empty_answer_moves_on_to_a_peer_that_holds_it() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let (pool, manager) = manager_with(vec![Ok(b"empty".to_vec()), Ok(b"response".to_vec())]);

        let (responding_peer, bytes) = send(&manager, &[peer_a, peer_b], Some(peer_a))
            .await
            .expect("the second peer answers");
        assert_eq!(responding_peer, peer_b);
        assert_eq!(bytes.as_ref(), b"response");
        assert_eq!(
            pool.calls()
                .iter()
                .map(|call| call.peer)
                .collect::<Vec<_>>(),
            vec![peer_a, peer_b]
        );
    }

    #[tokio::test]
    async fn every_peer_answering_empty_returns_the_empty_answer() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let (pool, manager) = manager_with(vec![Ok(b"empty".to_vec()), Ok(b"empty".to_vec())]);

        let (_, bytes) = send(&manager, &[peer_a, peer_b], Some(peer_a))
            .await
            .expect("an empty answer is an answer");
        assert_eq!(bytes.as_ref(), b"empty");
        assert_eq!(pool.calls().len(), 2, "each peer is asked once");
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
    async fn all_peers_backed_off_returns_no_peers_without_dispatch() {
        // Every candidate's (peer, shard) stream is in pool backoff, so the
        // retry loop must bail with NoPeers before dispatching — re-trying into
        // a backed-off peer would only re-escalate its backoff and spin.
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let (pool, manager) = manager_with(vec![Ok(b"r".to_vec())]);
        pool.mark_backed_off(&[peer_a, peer_b]);

        let result = send(&manager, &[peer_a, peer_b], Some(peer_a)).await;
        assert!(
            matches!(result, Err(RequestError::NoPeers)),
            "all-backed-off must surface NoPeers, got {result:?}"
        );
        assert!(
            pool.calls().is_empty(),
            "no request should be dispatched into a backed-off peer"
        );
    }

    #[tokio::test]
    async fn a_backed_off_peer_is_skipped_for_a_live_one() {
        // One of two candidates is backed off; the dispatch must go to the live
        // peer, even when the backed-off one is preferred.
        let backed_off = PeerId::random();
        let live = PeerId::random();
        let (pool, manager) = manager_with(vec![Ok(b"r".to_vec())]);
        pool.mark_backed_off(&[backed_off]);

        let (responding_peer, _) = send(&manager, &[backed_off, live], Some(backed_off))
            .await
            .expect("succeeds against the live peer");
        assert_eq!(responding_peer, live);
        assert_eq!(pool.calls().len(), 1);
        assert_eq!(pool.calls()[0].peer, live);
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
