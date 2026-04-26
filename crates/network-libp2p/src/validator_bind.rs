//! Validator-bind protocol: cryptographic `ValidatorId` ↔ `PeerId` binding.
//!
//! After libp2p's Noise transport proves `PeerId` ownership, this protocol
//! proves the peer also controls the BLS signing key for a given `ValidatorId`
//! (as known from the topology).
//!
//! # Protocol
//!
//! Stream protocol: `/hyperscale/validator-bind/1.0.0`
//!
//! ## Wire exchange (single bidirectional stream)
//!
//! ```text
//! Initiator                          Listener
//!     ── ValidatorBindMsg ──────────────▶
//!     ◀────────────────── ValidatorBindMsg
//! ```
//!
//! Each side sends `(ValidatorId, BLS-signature-over-own-PeerId)`.
//! The receiver verifies the signature using the BLS public key from topology.

use crate::stream_framing;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use hyperscale_network::ValidatorKeyMap;
use hyperscale_types::{
    Bls12381G2Signature, ValidatorId, validator_bind_message, verify_bls12381_v1,
};
use libp2p::{PeerId as Libp2pPeerId, StreamProtocol};
use libp2p_stream as stream;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Shared validator key map, updated atomically on epoch transitions.
type SharedValidatorKeys = Arc<ArcSwap<ValidatorKeyMap>>;

/// Stream protocol identifier for the validator-bind handshake.
pub(crate) const VALIDATOR_BIND_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/hyperscale/validator-bind/1.0.0");

/// Timeout for the complete bind exchange (read + write).
const BIND_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum frame size for bind messages (~200 bytes SBOR-encoded).
const MAX_BIND_FRAME: usize = 4096;

/// Maximum number of retry attempts for a failed outbound bind.
const MAX_BIND_RETRIES: u32 = 5;

/// Base delay for exponential backoff on bind retries.
const BIND_RETRY_BASE_DELAY: Duration = Duration::from_secs(2);

// ─── Wire format ────────────────────────────────────────────────────────

/// Encode a bind message: `[8-byte LE validator_id][96-byte BLS signature]`.
///
/// Fixed 104-byte layout avoids SBOR dependency for this security-critical path.
fn encode_bind_message(validator_id: ValidatorId, signature: &Bls12381G2Signature) -> Vec<u8> {
    let mut buf = Vec::with_capacity(104);
    buf.extend_from_slice(&validator_id.0.to_le_bytes());
    buf.extend_from_slice(&signature.0);
    buf
}

/// Decode a bind message from the fixed 104-byte layout.
fn decode_bind_message(data: &[u8]) -> Option<(ValidatorId, Bls12381G2Signature)> {
    if data.len() != 104 {
        return None;
    }
    let vid = u64::from_le_bytes(data[..8].try_into().ok()?);
    let mut sig_bytes = [0u8; 96];
    sig_bytes.copy_from_slice(&data[8..104]);
    Some((ValidatorId(vid), Bls12381G2Signature(sig_bytes)))
}

// ─── Verification ───────────────────────────────────────────────────────

/// Verify a bind message: the BLS signature over the peer's `PeerId` must be
/// valid for the claimed `ValidatorId`'s public key.
fn verify_bind(
    peer_id: &Libp2pPeerId,
    claimed_vid: ValidatorId,
    signature: &Bls12381G2Signature,
    keys: &ValidatorKeyMap,
) -> Result<(), BindError> {
    let pubkey = keys
        .get(&claimed_vid)
        .ok_or(BindError::UnknownValidator(claimed_vid))?;

    let message = validator_bind_message(&peer_id.to_bytes());
    if verify_bls12381_v1(&message, pubkey, signature) {
        Ok(())
    } else {
        Err(BindError::InvalidSignature(claimed_vid))
    }
}

/// Errors during a bind exchange.
#[derive(Debug)]
enum BindError {
    UnknownValidator(ValidatorId),
    InvalidSignature(ValidatorId),
    InvalidMessage,
    StreamOpen(String),
    Io(std::io::Error),
    Frame(stream_framing::FrameError),
    Timeout,
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindError::UnknownValidator(v) => write!(f, "unknown validator {}", v.0),
            BindError::InvalidSignature(v) => {
                write!(f, "invalid BLS signature for validator {}", v.0)
            }
            BindError::InvalidMessage => write!(f, "malformed bind message"),
            BindError::StreamOpen(e) => write!(f, "stream open failed: {e}"),
            BindError::Io(e) => write!(f, "I/O error: {e}"),
            BindError::Frame(e) => write!(f, "frame error: {e}"),
            BindError::Timeout => write!(f, "bind exchange timed out"),
        }
    }
}

// ─── Handle (public interface) ──────────────────────────────────────────

/// Handle for the validator-bind service.
///
/// Kept alive inside `Libp2pAdapter` to prevent the background task from
/// being aborted. Provides a channel to trigger outbound bind exchanges
/// from the event loop.
pub(crate) struct ValidatorBindHandle {
    /// Trigger an outbound bind to a newly-identified peer.
    pub(crate) bind_tx: mpsc::UnboundedSender<Libp2pPeerId>,
    /// Keep the background task alive.
    #[allow(dead_code)]
    join_handle: tokio::task::JoinHandle<()>,
}

// ─── Service ────────────────────────────────────────────────────────────

/// Spawn the validator-bind service.
///
/// The service runs two concurrent loops:
/// 1. **Inbound**: accepts `/hyperscale/validator-bind/1.0.0` streams from peers.
/// 2. **Outbound**: opens bind streams to peers when triggered by the event loop.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_validator_bind_service(
    mut control: stream::Control,
    validator_peers: Arc<DashMap<ValidatorId, Libp2pPeerId>>,
    local_validator_id: ValidatorId,
    local_bind_signature: Bls12381G2Signature,
    validator_keys: SharedValidatorKeys,
) -> ValidatorBindHandle {
    let (bind_tx, bind_rx) = mpsc::unbounded_channel();

    let join_handle = tokio::spawn(async move {
        // Accept incoming validator-bind streams.
        let mut incoming = match control.accept(VALIDATOR_BIND_PROTOCOL) {
            Ok(incoming) => incoming,
            Err(e) => {
                tracing::error!(error = ?e, "Failed to register validator-bind protocol");
                return;
            }
        };

        info!("Validator-bind service started");

        run_service(
            &mut incoming,
            bind_rx,
            control.clone(),
            validator_peers,
            local_validator_id,
            local_bind_signature,
            validator_keys,
        )
        .await;

        info!("Validator-bind service stopped");
    });

    ValidatorBindHandle {
        bind_tx,
        join_handle,
    }
}

/// A retry request: peer ID + which attempt this is (0-based).
struct BindRetry {
    peer_id: Libp2pPeerId,
    attempt: u32,
}

/// Main service loop: select between inbound streams and outbound triggers.
async fn run_service(
    incoming: &mut stream::IncomingStreams,
    mut bind_rx: mpsc::UnboundedReceiver<Libp2pPeerId>,
    control: stream::Control,
    validator_peers: Arc<DashMap<ValidatorId, Libp2pPeerId>>,
    local_vid: ValidatorId,
    local_sig: Bls12381G2Signature,
    validator_keys: SharedValidatorKeys,
) {
    use futures::StreamExt;

    // Internal channel for scheduling bind retries with backoff.
    let (retry_tx, mut retry_rx) = mpsc::unbounded_channel::<BindRetry>();

    loop {
        tokio::select! {
            // Inbound: a remote peer initiated the bind exchange.
            Some((peer_id, stream)) = incoming.next() => {
                let vp = validator_peers.clone();
                let keys = validator_keys.clone();
                let sig = local_sig;

                tokio::spawn(async move {
                    let keys_guard = keys.load();
                    if let Err(e) = handle_inbound(peer_id, stream, &vp, local_vid, &sig, &keys_guard).await {
                        warn!(peer = %peer_id, error = %e, "Inbound validator-bind failed");
                    }
                });
            }

            // Outbound: the event loop identified a new hyperscale peer.
            Some(peer_id) = bind_rx.recv() => {
                // Skip if we already have this peer bound.
                let already_bound = validator_peers
                    .iter()
                    .any(|entry| *entry.value() == peer_id);
                if already_bound {
                    continue;
                }

                let ctrl = control.clone();
                let vp = validator_peers.clone();
                let keys = validator_keys.clone();
                let sig = local_sig;
                let rtx = retry_tx.clone();

                tokio::spawn(async move {
                    let keys_guard = keys.load();
                    if let Err(e) = handle_outbound(peer_id, ctrl, &vp, local_vid, &sig, &keys_guard).await {
                        warn!(peer = %peer_id, error = %e, "Outbound validator-bind failed, scheduling retry");
                        schedule_retry(rtx, peer_id, 0);
                    }
                });
            }

            // Retry: a previous outbound bind failed — try again with backoff.
            Some(retry) = retry_rx.recv() => {
                // Skip if the peer got bound in the meantime (e.g. via inbound).
                let already_bound = validator_peers
                    .iter()
                    .any(|entry| *entry.value() == retry.peer_id);
                if already_bound {
                    continue;
                }

                let peer_id = retry.peer_id;
                let attempt = retry.attempt;
                let ctrl = control.clone();
                let vp = validator_peers.clone();
                let keys = validator_keys.clone();
                let sig = local_sig;
                let rtx = retry_tx.clone();

                tokio::spawn(async move {
                    let keys_guard = keys.load();
                    if let Err(e) = handle_outbound(peer_id, ctrl, &vp, local_vid, &sig, &keys_guard).await {
                        if attempt + 1 < MAX_BIND_RETRIES {
                            warn!(
                                peer = %peer_id,
                                error = %e,
                                attempt = attempt + 1,
                                max = MAX_BIND_RETRIES,
                                "Outbound validator-bind retry failed, will retry again"
                            );
                            schedule_retry(rtx, peer_id, attempt + 1);
                        } else {
                            warn!(
                                peer = %peer_id,
                                error = %e,
                                attempts = MAX_BIND_RETRIES,
                                "Outbound validator-bind exhausted all retries"
                            );
                        }
                    }
                });
            }

            else => break,
        }
    }
}

/// Schedule a bind retry after exponential backoff.
///
/// Spawns a background task that sleeps for `BIND_RETRY_BASE_DELAY * 2^attempt`
/// then sends the peer ID back to the retry channel.
fn schedule_retry(retry_tx: mpsc::UnboundedSender<BindRetry>, peer_id: Libp2pPeerId, attempt: u32) {
    let delay = BIND_RETRY_BASE_DELAY * 2u32.saturating_pow(attempt);
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let _ = retry_tx.send(BindRetry { peer_id, attempt });
    });
}

/// Handle an inbound bind stream (we are the listener).
///
/// 1. Read remote's bind message
/// 2. Verify
/// 3. Register in `validator_peers`
/// 4. Send our bind message as response
async fn handle_inbound(
    peer_id: Libp2pPeerId,
    mut stream: libp2p::Stream,
    validator_peers: &DashMap<ValidatorId, Libp2pPeerId>,
    local_vid: ValidatorId,
    local_sig: &Bls12381G2Signature,
    keys: &ValidatorKeyMap,
) -> Result<(), BindError> {
    let result = tokio::time::timeout(BIND_TIMEOUT, async {
        // Read remote's bind message.
        let remote_bytes = stream_framing::read_frame(&mut stream, MAX_BIND_FRAME)
            .await
            .map_err(BindError::Frame)?;

        let (remote_vid, remote_sig) =
            decode_bind_message(&remote_bytes).ok_or(BindError::InvalidMessage)?;

        // Verify remote's BLS signature over their PeerId.
        verify_bind(&peer_id, remote_vid, &remote_sig, keys)?;

        // Verified — register the binding.
        info!(
            peer = %peer_id,
            validator_id = remote_vid.0,
            "Validator-bind verified (inbound)"
        );
        validator_peers.insert(remote_vid, peer_id);

        // Send our bind message as the response.
        let our_bytes = encode_bind_message(local_vid, local_sig);
        stream_framing::write_frame(&mut stream, &our_bytes)
            .await
            .map_err(BindError::Io)?;

        Ok(())
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(BindError::Timeout),
    }
}

/// Handle an outbound bind (we are the initiator).
///
/// 1. Open stream to peer
/// 2. Send our bind message
/// 3. Read remote's bind message
/// 4. Verify
/// 5. Register in `validator_peers`
async fn handle_outbound(
    peer_id: Libp2pPeerId,
    mut control: stream::Control,
    validator_peers: &DashMap<ValidatorId, Libp2pPeerId>,
    local_vid: ValidatorId,
    local_sig: &Bls12381G2Signature,
    keys: &ValidatorKeyMap,
) -> Result<(), BindError> {
    let result = tokio::time::timeout(BIND_TIMEOUT, async {
        // Open a stream to the remote peer.
        let mut stream = control
            .open_stream(peer_id, VALIDATOR_BIND_PROTOCOL)
            .await
            .map_err(|e| BindError::StreamOpen(format!("{e:?}")))?;

        // Send our bind message.
        let our_bytes = encode_bind_message(local_vid, local_sig);

        // Write length-prefixed compressed frame, but do NOT close the write side yet —
        // we still need to read the response. Manually write the frame.
        {
            use futures::AsyncWriteExt;
            let compressed = hyperscale_network::compression::compress(&our_bytes);
            let len = u32::try_from(compressed.len()).unwrap_or(u32::MAX);
            stream
                .write_all(&len.to_be_bytes())
                .await
                .map_err(BindError::Io)?;
            stream.write_all(&compressed).await.map_err(BindError::Io)?;
            stream.flush().await.map_err(BindError::Io)?;
            stream.close().await.map_err(BindError::Io)?;
        }

        // Read remote's response.
        let remote_bytes = stream_framing::read_frame(&mut stream, MAX_BIND_FRAME)
            .await
            .map_err(BindError::Frame)?;

        let (remote_vid, remote_sig) =
            decode_bind_message(&remote_bytes).ok_or(BindError::InvalidMessage)?;

        // Verify remote's BLS signature over their PeerId.
        verify_bind(&peer_id, remote_vid, &remote_sig, keys)?;

        // Verified — register the binding.
        info!(
            peer = %peer_id,
            validator_id = remote_vid.0,
            "Validator-bind verified (outbound)"
        );
        validator_peers.insert(remote_vid, peer_id);

        Ok(())
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(BindError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{generate_bls_keypair, zero_bls_signature};

    /// Build a single-validator key map for bind tests.
    fn make_bind_keys(
        vid: ValidatorId,
        pubkey: hyperscale_types::Bls12381G1PublicKey,
    ) -> ValidatorKeyMap {
        let mut keys = ValidatorKeyMap::new();
        keys.insert(vid, pubkey);
        keys
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let vid = ValidatorId(42);
        let sig = zero_bls_signature();

        let encoded = encode_bind_message(vid, &sig);
        assert_eq!(encoded.len(), 104);

        let (decoded_vid, decoded_sig) = decode_bind_message(&encoded).unwrap();
        assert_eq!(decoded_vid, vid);
        assert_eq!(decoded_sig.0, sig.0);
    }

    #[test]
    fn test_decode_wrong_length() {
        assert!(decode_bind_message(&[0u8; 50]).is_none());
        assert!(decode_bind_message(&[0u8; 200]).is_none());
        assert!(decode_bind_message(&[]).is_none());
    }

    #[test]
    fn test_verify_bind_valid() {
        let keypair = generate_bls_keypair();
        let pubkey = keypair.public_key();
        let peer_id = Libp2pPeerId::random();
        let vid = ValidatorId(7);

        let msg = validator_bind_message(&peer_id.to_bytes());
        let sig = keypair.sign_v1(&msg);

        let keys = make_bind_keys(vid, pubkey);
        assert!(verify_bind(&peer_id, vid, &sig, &keys).is_ok());
    }

    #[test]
    fn test_verify_bind_wrong_peer_id() {
        let keypair = generate_bls_keypair();
        let pubkey = keypair.public_key();
        let peer_a = Libp2pPeerId::random();
        let peer_b = Libp2pPeerId::random();
        let vid = ValidatorId(7);

        // Sign peer_a's ID but try to verify as peer_b.
        let msg = validator_bind_message(&peer_a.to_bytes());
        let sig = keypair.sign_v1(&msg);

        let keys = make_bind_keys(vid, pubkey);
        assert!(verify_bind(&peer_b, vid, &sig, &keys).is_err());
    }

    #[test]
    fn test_verify_bind_unknown_validator() {
        let keypair = generate_bls_keypair();
        let pubkey = keypair.public_key();
        let peer_id = Libp2pPeerId::random();

        let msg = validator_bind_message(&peer_id.to_bytes());
        let sig = keypair.sign_v1(&msg);

        // Key map has validator 7 but we claim to be validator 99.
        let keys = make_bind_keys(ValidatorId(7), pubkey);
        assert!(matches!(
            verify_bind(&peer_id, ValidatorId(99), &sig, &keys),
            Err(BindError::UnknownValidator(ValidatorId(99)))
        ));
    }

    #[test]
    fn test_verify_bind_wrong_key() {
        let keypair_a = generate_bls_keypair();
        let keypair_b = generate_bls_keypair();
        let peer_id = Libp2pPeerId::random();
        let vid = ValidatorId(7);

        // Sign with key_a but key map has key_b for this validator.
        let msg = validator_bind_message(&peer_id.to_bytes());
        let sig = keypair_a.sign_v1(&msg);

        let keys = make_bind_keys(vid, keypair_b.public_key());
        assert!(matches!(
            verify_bind(&peer_id, vid, &sig, &keys),
            Err(BindError::InvalidSignature(ValidatorId(7)))
        ));
    }
}
