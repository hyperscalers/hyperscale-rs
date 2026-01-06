//! Request manager with intelligent retry and peer selection.
//!
//! The key insight: under packet loss, a failed request doesn't mean the peer
//! is bad—it means the network dropped packets. Retrying the SAME peer first
//! is often correct because packet loss is probabilistic.
//!
//! # Design Philosophy
//!
//! This module implements **request-centric** retry logic, in contrast to the
//! traditional **peer-centric** approach:
//!
//! - **Peer-centric** (old): Timeout → blame peer → cooldown → try next peer
//! - **Request-centric** (new): Timeout → retry same peer → rotate after threshold
//!
//! The request-centric approach works better under packet loss because:
//! 1. Packet loss is probabilistic—the peer that timed out might succeed on retry
//! 2. Rotating too quickly exhausts all peers and triggers "desperation mode"
//! 3. Weighted selection ensures unhealthy peers still get occasional chances
//!
//! # Example
//!
//! ```ignore
//! let manager = RequestManager::new(adapter.clone(), RequestManagerConfig::default());
//!
//! // Send a request with automatic retry
//! match manager.request_block(&peers, height, RequestPriority::Background).await {
//!     Ok((peer, response)) => { /* success */ }
//!     Err(RequestError::Exhausted { attempts }) => { /* all retries failed */ }
//!     Err(RequestError::NoPeers) => { /* no peers available */ }
//! }
//! ```

use super::adapter::{Libp2pAdapter, NetworkError};
use super::peer_health::{PeerHealthConfig, PeerHealthTracker};
use bytes::Bytes;
use futures::{AsyncReadExt, AsyncWriteExt};
use hyperscale_types::{BlockHeight, Hash};
use libp2p::PeerId;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, info, trace, warn};

/// Maximum timeout for stream operations.
const MAX_STREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum timeout for stream operations (floor for RTT-based calculation).
const MIN_STREAM_TIMEOUT: Duration = Duration::from_millis(500);

/// Default timeout for stream operations when no RTT data is available.
/// Based on default RTT of 100ms × 5 = 500ms, but we use 1s to be safe for cold start.
const DEFAULT_STREAM_TIMEOUT: Duration = Duration::from_secs(1);

/// Multiplier for RTT to compute stream timeout.
/// Timeout = RTT * multiplier, clamped to [MIN, MAX].
const STREAM_TIMEOUT_RTT_MULTIPLIER: f64 = 5.0;

/// Errors from request operations.
#[derive(Debug, Error)]
pub enum RequestError {
    /// All retry attempts exhausted.
    #[error("request exhausted after {attempts} attempts")]
    Exhausted { attempts: u32 },

    /// No peers available to send to.
    #[error("no peers available")]
    NoPeers,

    /// Network-level error (non-retryable).
    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    /// Network is shutting down.
    #[error("network shutdown")]
    Shutdown,
}

/// Priority levels for requests.
///
/// Priority affects timeout tolerance and retry aggressiveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestPriority {
    /// Critical requests (pending block completion).
    /// Tighter timeouts, more aggressive retries.
    Critical,

    /// Normal requests.
    Normal,

    /// Background requests (sync).
    /// Higher timeout tolerance, less aggressive.
    Background,
}

/// Configuration for the request manager.
#[derive(Debug, Clone)]
pub struct RequestManagerConfig {
    /// Maximum total concurrent requests across all peers.
    pub max_concurrent: usize,

    /// Maximum concurrent requests per peer.
    pub max_per_peer: u32,

    /// Number of retries to same peer before rotating to a different peer.
    /// Higher values are better for packet loss scenarios.
    pub retries_before_rotation: u32,

    /// Maximum total retry attempts before giving up.
    pub max_total_attempts: u32,

    /// Initial backoff delay between retries.
    pub initial_backoff: Duration,

    /// Maximum backoff delay.
    pub max_backoff: Duration,

    /// Backoff multiplier (exponential backoff).
    pub backoff_multiplier: f64,

    /// Target success rate. If global rate drops below this, reduce concurrency.
    pub target_success_rate: f64,

    /// Minimum concurrency (won't reduce below this even under poor conditions).
    pub min_concurrent: usize,

    /// Multiplier for speculative retry timeout based on observed RTT.
    /// After `rtt * speculative_retry_multiplier`, send a duplicate request to race.
    /// Set to 0.0 to disable speculative retries.
    /// Default: 2.0 (retry after 2× observed RTT)
    pub speculative_retry_multiplier: f64,

    /// Minimum time before speculative retry, regardless of RTT.
    /// Prevents too-aggressive retries on very fast networks.
    /// Default: 200ms
    pub speculative_retry_min: Duration,

    /// Maximum time before speculative retry.
    /// After this, just wait for libp2p timeout rather than speculative retry.
    /// Default: 2s
    pub speculative_retry_max: Duration,
}

impl Default for RequestManagerConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 64,
            max_per_peer: 8,
            retries_before_rotation: 3, // Retry same peer 3x before rotating (good for packet loss)
            max_total_attempts: 15,     // More attempts to handle lossy networks
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(500), // Cap backoff to match stream timeout
            backoff_multiplier: 1.5,
            target_success_rate: 0.5,
            min_concurrent: 4,
            speculative_retry_multiplier: 2.0, // Speculative retry after 2× RTT
            speculative_retry_min: Duration::from_millis(200),
            speculative_retry_max: Duration::from_secs(2),
        }
    }
}

/// Request types that can be sent through the manager.
#[derive(Debug, Clone)]
pub enum Request {
    /// Request a block at a given height.
    Block { height: BlockHeight },
    /// Request transactions for a block.
    Transactions {
        block_hash: Hash,
        tx_hashes: Vec<Hash>,
    },
    /// Request certificates for a block.
    Certificates {
        block_hash: Hash,
        cert_hashes: Vec<Hash>,
    },
}

impl Request {
    /// Get a short description for logging.
    fn description(&self) -> String {
        match self {
            Request::Block { height } => format!("block@{}", height.0),
            Request::Transactions { tx_hashes, .. } => format!("{}txs", tx_hashes.len()),
            Request::Certificates { cert_hashes, .. } => format!("{}certs", cert_hashes.len()),
        }
    }
}

/// Request manager with intelligent retry and peer selection.
///
/// Wraps the network adapter and provides:
/// - Request-centric retry logic (same peer first, then rotate)
/// - Weighted peer selection based on health metrics
/// - Adaptive concurrency control
/// - Exponential backoff between retries
pub struct RequestManager {
    adapter: Arc<Libp2pAdapter>,
    config: RequestManagerConfig,
    /// Peer health tracker (uses DashMap internally, no external lock needed).
    health: PeerHealthTracker,
    /// Current in-flight request count.
    in_flight: AtomicUsize,
    /// Current effective concurrency limit (may be reduced adaptively).
    effective_concurrent: AtomicUsize,
}

impl RequestManager {
    /// Create a new request manager.
    pub fn new(adapter: Arc<Libp2pAdapter>, config: RequestManagerConfig) -> Self {
        let effective = config.max_concurrent;
        Self {
            adapter,
            health: PeerHealthTracker::new(PeerHealthConfig {
                max_in_flight_per_peer: config.max_per_peer,
                ..Default::default()
            }),
            in_flight: AtomicUsize::new(0),
            effective_concurrent: AtomicUsize::new(effective),
            config,
        }
    }

    /// Send a request with automatic retry and peer failover.
    ///
    /// # Arguments
    /// * `peers` - Candidate peers to try (caller provides based on topology)
    /// * `request` - The request to send
    /// * `priority` - Request priority (affects timeout and retry behavior)
    ///
    /// # Returns
    /// On success, returns the peer that responded and the response bytes.
    pub async fn request(
        &self,
        peers: &[PeerId],
        request: Request,
        priority: RequestPriority,
    ) -> Result<(PeerId, Bytes), RequestError> {
        if peers.is_empty() {
            return Err(RequestError::NoPeers);
        }

        // Wait for concurrency slot
        self.acquire_slot().await?;

        let result = self.request_inner(peers, request, priority).await;

        // Release concurrency slot
        self.in_flight.fetch_sub(1, Ordering::Relaxed);

        result
    }

    /// Convenience method for block requests.
    pub async fn request_block(
        &self,
        peers: &[PeerId],
        height: BlockHeight,
        priority: RequestPriority,
    ) -> Result<(PeerId, Bytes), RequestError> {
        self.request(peers, Request::Block { height }, priority)
            .await
    }

    /// Convenience method for transaction requests.
    pub async fn request_transactions(
        &self,
        peers: &[PeerId],
        block_hash: Hash,
        tx_hashes: Vec<Hash>,
        priority: RequestPriority,
    ) -> Result<(PeerId, Bytes), RequestError> {
        self.request(
            peers,
            Request::Transactions {
                block_hash,
                tx_hashes,
            },
            priority,
        )
        .await
    }

    /// Convenience method for certificate requests.
    pub async fn request_certificates(
        &self,
        peers: &[PeerId],
        block_hash: Hash,
        cert_hashes: Vec<Hash>,
        priority: RequestPriority,
    ) -> Result<(PeerId, Bytes), RequestError> {
        self.request(
            peers,
            Request::Certificates {
                block_hash,
                cert_hashes,
            },
            priority,
        )
        .await
    }

    async fn request_inner(
        &self,
        peers: &[PeerId],
        request: Request,
        priority: RequestPriority,
    ) -> Result<(PeerId, Bytes), RequestError> {
        let mut attempts: u32 = 0;
        let mut current_peer_attempts: u32 = 0;
        let request_desc = request.description();

        // Select initial peer
        let mut current_peer = self
            .health
            .select_peer(peers)
            .ok_or(RequestError::NoPeers)?;

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
                .send_request_with_speculative_retry(&current_peer, &request, priority)
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

    /// Send the actual request through the adapter using raw streams.
    ///
    /// Opens a stream, writes the length-prefixed request, reads the length-prefixed
    /// response, all wrapped in timeouts. The adapter is a "dumb pipe" - all timeout
    /// logic is here in RequestManager.
    async fn send_request(
        &self,
        peer: &PeerId,
        request: &Request,
        _priority: RequestPriority,
    ) -> Result<Vec<u8>, NetworkError> {
        let timeout = self.compute_stream_timeout(peer);
        Self::send_request_static(&self.adapter, peer, request, timeout).await
    }

    /// Send a request with speculative retry based on RTT.
    ///
    /// If we have RTT data for the peer, we send a speculative duplicate request
    /// after `RTT * multiplier` to race against packet loss. Both requests are
    /// identical, so the responder returns the same data and we take whichever
    /// arrives first.
    ///
    /// Returns the response and the actual elapsed time (for RTT tracking).
    async fn send_request_with_speculative_retry(
        &self,
        peer: &PeerId,
        request: &Request,
        priority: RequestPriority,
    ) -> Result<(Vec<u8>, Duration), NetworkError> {
        let start = Instant::now();

        // Compute speculative retry timeout based on peer's RTT history
        let speculative_timeout = self.compute_speculative_timeout(peer);

        // If speculative retry is disabled or timeout is too long, just send once
        if self.config.speculative_retry_multiplier == 0.0
            || speculative_timeout >= self.config.speculative_retry_max
        {
            let result = self.send_request(peer, request, priority).await?;
            return Ok((result, start.elapsed()));
        }

        // Compute stream timeout based on peer RTT (do this before spawning)
        let stream_timeout = self.compute_stream_timeout(peer);
        debug!(
            ?peer,
            stream_timeout_ms = stream_timeout.as_millis(),
            speculative_timeout_ms = speculative_timeout.as_millis(),
            "Computed timeouts for request"
        );

        // Send initial request (as a spawned task so it keeps running even if we move on)
        let adapter_clone = self.adapter.clone();
        let request_clone = request.clone();
        let peer_clone = *peer;

        // Spawn the first request so it continues running independently
        let mut first_handle = tokio::spawn(async move {
            Self::send_request_static(&adapter_clone, &peer_clone, &request_clone, stream_timeout)
                .await
        });

        // Wait for either: first request completes, or speculative timeout
        let sleep = tokio::time::sleep(speculative_timeout);
        tokio::pin!(sleep);

        tokio::select! {
            // First request completes before speculative timeout
            result = &mut first_handle => {
                match result {
                    Ok(Ok(response)) => return Ok((response, start.elapsed())),
                    Ok(Err(e)) => return Err(e),
                    Err(_join_error) => return Err(NetworkError::NetworkShutdown),
                }
            }

            // Speculative timeout elapsed - send second request and race both
            _ = &mut sleep => {
                trace!(
                    peer = ?peer,
                    speculative_timeout_ms = speculative_timeout.as_millis(),
                    "Sending speculative retry"
                );
            }
        }

        // If we get here, speculative timeout fired. Send second request and race both.
        let adapter_clone2 = self.adapter.clone();
        let request_clone2 = request.clone();
        let peer_clone2 = *peer;

        let mut second_handle = tokio::spawn(async move {
            Self::send_request_static(
                &adapter_clone2,
                &peer_clone2,
                &request_clone2,
                stream_timeout,
            )
            .await
        });

        // Race both requests - first SUCCESS wins.
        // If one fails, wait for the other. Only return error if both fail.
        let mut first_done = false;
        let mut second_done = false;
        #[allow(unused_assignments)] // False positive: always assigned before loop exit
        let mut last_error: Option<NetworkError> = None;

        loop {
            tokio::select! {
                result = &mut first_handle, if !first_done => {
                    match result {
                        Ok(Ok(response)) => return Ok((response, start.elapsed())),
                        Ok(Err(e)) => {
                            first_done = true;
                            last_error = Some(e);
                        }
                        Err(_) => {
                            first_done = true;
                            last_error = Some(NetworkError::NetworkShutdown);
                        }
                    }
                }
                result = &mut second_handle, if !second_done => {
                    match result {
                        Ok(Ok(response)) => return Ok((response, start.elapsed())),
                        Ok(Err(e)) => {
                            second_done = true;
                            last_error = Some(e);
                        }
                        Err(_) => {
                            second_done = true;
                            last_error = Some(NetworkError::NetworkShutdown);
                        }
                    }
                }
            }

            // Both requests failed - return the last error
            if first_done && second_done {
                return Err(last_error.unwrap_or(NetworkError::Timeout));
            }
        }
    }

    /// Static version of send_request for use in spawned tasks.
    ///
    /// Uses raw streams with length-prefixed framing:
    /// 1. Open stream to peer
    /// 2. Write [4-byte big-endian length][request data]
    /// 3. Read [4-byte big-endian length][response data]
    /// 4. Close stream
    ///
    /// All I/O operations are wrapped with the provided timeout (RTT-based).
    async fn send_request_static(
        adapter: &Arc<Libp2pAdapter>,
        peer: &PeerId,
        request: &Request,
        timeout: Duration,
    ) -> Result<Vec<u8>, NetworkError> {
        use hyperscale_messages::request::{GetCertificatesRequest, GetTransactionsRequest};

        // Encode request data
        let data: Vec<u8> = match request {
            Request::Block { height } => height.0.to_le_bytes().to_vec(),
            Request::Transactions {
                block_hash,
                tx_hashes,
            } => {
                let req = GetTransactionsRequest::new(*block_hash, tx_hashes.clone());
                sbor::basic_encode(&req).unwrap_or_default()
            }
            Request::Certificates {
                block_hash,
                cert_hashes,
            } => {
                let req = GetCertificatesRequest::new(*block_hash, cert_hashes.clone());
                sbor::basic_encode(&req).unwrap_or_default()
            }
        };

        // Open stream with timeout
        let mut stream = tokio::time::timeout(timeout, adapter.open_stream(*peer))
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| NetworkError::StreamOpenFailed(format!("{:?}", e)))?;

        // Write length-prefixed request with timeout
        let len = data.len() as u32;
        let write_result = tokio::time::timeout(timeout, async {
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(&data).await?;
            stream.flush().await?;
            // Close write side to signal end of request
            stream.close().await?;
            Ok::<(), std::io::Error>(())
        })
        .await;

        match write_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(NetworkError::StreamIo(format!("write failed: {}", e))),
            Err(_) => return Err(NetworkError::Timeout),
        }

        // Read length-prefixed response with timeout
        let read_result = tokio::time::timeout(timeout, async {
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await?;
            let response_len = u32::from_be_bytes(len_bytes) as usize;

            // Sanity check response size (max 10MB)
            if response_len > 10 * 1024 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "response too large",
                ));
            }

            let mut response = vec![0u8; response_len];
            stream.read_exact(&mut response).await?;
            Ok::<Vec<u8>, std::io::Error>(response)
        })
        .await;

        match read_result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(NetworkError::StreamIo(format!("read failed: {}", e))),
            Err(_) => Err(NetworkError::Timeout),
        }
    }

    /// Compute the speculative retry timeout based on peer's RTT history.
    fn compute_speculative_timeout(&self, peer: &PeerId) -> Duration {
        self.health
            .get_health(peer)
            .map(|h| {
                let rtt_based = Duration::from_secs_f64(
                    h.rtt_ema_secs * self.config.speculative_retry_multiplier,
                );
                rtt_based.clamp(
                    self.config.speculative_retry_min,
                    self.config.speculative_retry_max,
                )
            })
            .unwrap_or(self.config.speculative_retry_max) // No RTT data = no speculative retry
    }

    /// Compute the stream timeout based on peer's RTT history.
    ///
    /// Uses 5× RTT as the timeout, clamped to reasonable bounds.
    /// This ensures we don't wait 5 seconds for a peer with 100ms RTT.
    fn compute_stream_timeout(&self, peer: &PeerId) -> Duration {
        self.health
            .get_health(peer)
            .map(|h| {
                let rtt_based =
                    Duration::from_secs_f64(h.rtt_ema_secs * STREAM_TIMEOUT_RTT_MULTIPLIER);
                rtt_based.clamp(MIN_STREAM_TIMEOUT, MAX_STREAM_TIMEOUT)
            })
            .unwrap_or(DEFAULT_STREAM_TIMEOUT) // No RTT data = use 1s default (not 5s)
    }

    /// Compute initial backoff based on peer RTT and priority.
    ///
    /// For peers with known RTT, use a fraction of their RTT as initial backoff.
    /// Priority adjusts this: Critical requests use shorter backoff, Background longer.
    fn compute_initial_backoff(&self, peer: &PeerId, priority: RequestPriority) -> Duration {
        // Get peer RTT if known, otherwise use config default
        let base_backoff = self
            .health
            .get_health(peer)
            .map(|h| {
                // Use 50% of observed RTT as base backoff, clamped to reasonable range
                let rtt_based = Duration::from_secs_f64(h.rtt_ema_secs * 0.5);
                rtt_based.clamp(Duration::from_millis(50), Duration::from_secs(1))
            })
            .unwrap_or(self.config.initial_backoff);

        // Adjust based on priority
        match priority {
            RequestPriority::Critical => base_backoff.mul_f32(0.7), // Faster retry for critical
            RequestPriority::Normal => base_backoff,
            RequestPriority::Background => base_backoff.mul_f32(1.5), // Slower for background
        }
    }

    /// Wait for a concurrency slot to become available.
    async fn acquire_slot(&self) -> Result<(), RequestError> {
        let start = Instant::now();
        let max_wait = Duration::from_secs(30);

        loop {
            let current = self.in_flight.load(Ordering::Relaxed);
            let limit = self.effective_concurrent.load(Ordering::Relaxed);

            if current < limit {
                // Try to acquire slot with CAS
                if self
                    .in_flight
                    .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::Relaxed)
                    .is_ok()
                {
                    return Ok(());
                }
                // CAS failed, another thread got it, loop and retry
            }

            // Check for timeout
            if start.elapsed() > max_wait {
                warn!(current, limit, "Timed out waiting for concurrency slot");
                return Err(RequestError::Exhausted { attempts: 0 });
            }

            // Wait a bit before retrying
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Reduce effective concurrency due to poor network conditions.
    /// Currently unused but kept for future adaptive concurrency control.
    #[allow(dead_code)]
    fn reduce_concurrency(&self) {
        let current = self.effective_concurrent.load(Ordering::Relaxed);
        let new = (current / 2).max(self.config.min_concurrent);

        if new < current {
            self.effective_concurrent.store(new, Ordering::Relaxed);
            info!(
                from = current,
                to = new,
                "Reduced concurrency due to network conditions"
            );
        }
    }

    /// Maybe increase concurrency if conditions are good.
    ///
    /// Uses additive increase: grows faster when further from max to enable
    /// quick recovery after congestion events that reduced concurrency.
    fn maybe_increase_concurrency(&self) {
        let current = self.effective_concurrent.load(Ordering::Relaxed);

        if current >= self.config.max_concurrent {
            return;
        }

        // Only increase if success rate is above target
        let success_rate = self.health.global_success_rate();
        if success_rate >= self.config.target_success_rate {
            // Increase by larger amount when further from max (faster recovery)
            // At 50% of max: increase by 4, at 75%: increase by 2, at 90%+: increase by 1
            let headroom_ratio = current as f64 / self.config.max_concurrent as f64;
            let increment = if headroom_ratio < 0.5 {
                4
            } else if headroom_ratio < 0.75 {
                2
            } else {
                1
            };

            let new = (current + increment).min(self.config.max_concurrent);
            self.effective_concurrent.store(new, Ordering::Relaxed);
            trace!(
                from = current,
                to = new,
                increment,
                success_rate,
                "Increased concurrency"
            );
        }
    }

    /// Get the peer health tracker for external monitoring.
    pub fn health_tracker(&self) -> &PeerHealthTracker {
        &self.health
    }

    /// Get current statistics for monitoring.
    pub fn stats(&self) -> RequestManagerStats {
        RequestManagerStats {
            in_flight: self.in_flight.load(Ordering::Relaxed),
            effective_concurrent: self.effective_concurrent.load(Ordering::Relaxed),
            max_concurrent: self.config.max_concurrent,
            global_success_rate: self.health.global_success_rate(),
            health_stats: self.health.stats(),
        }
    }

    /// Cleanup stale peer health data.
    pub fn cleanup_stale(&self) {
        self.health.cleanup_stale();
    }
}

/// Statistics from the request manager.
#[derive(Debug, Clone)]
pub struct RequestManagerStats {
    /// Requests currently in flight.
    pub in_flight: usize,
    /// Current effective concurrency limit.
    pub effective_concurrent: usize,
    /// Maximum configured concurrency.
    pub max_concurrent: usize,
    /// Global success rate across all peers.
    pub global_success_rate: f64,
    /// Detailed peer health statistics.
    pub health_stats: super::peer_health::PeerHealthStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full integration tests require a mock adapter.
    // These tests verify the configuration and basic logic.

    #[test]
    fn test_default_config() {
        let config = RequestManagerConfig::default();
        assert_eq!(config.max_concurrent, 64);
        assert_eq!(config.retries_before_rotation, 3); // Good for packet loss
        assert_eq!(config.max_total_attempts, 15); // More attempts for lossy networks
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
    }

    #[test]
    fn test_request_description() {
        let block_req = Request::Block {
            height: BlockHeight(100),
        };
        assert_eq!(block_req.description(), "block@100");

        let test_hash = Hash::from_bytes(b"test_hash_data_here!");

        let tx_req = Request::Transactions {
            block_hash: test_hash,
            tx_hashes: vec![test_hash; 5],
        };
        assert_eq!(tx_req.description(), "5txs");

        let cert_req = Request::Certificates {
            block_hash: test_hash,
            cert_hashes: vec![test_hash; 3],
        };
        assert_eq!(cert_req.description(), "3certs");
    }

    #[test]
    fn test_priority_values() {
        // Just verify the enum values exist
        let _critical = RequestPriority::Critical;
        let _normal = RequestPriority::Normal;
        let _background = RequestPriority::Background;
    }
}
