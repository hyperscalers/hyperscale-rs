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
//! Three-message mutual challenge-response — each side signs over a nonce
//! chosen by the *other* side, so signatures are fresh per session and cannot
//! be replayed against the same `(validator_id, peer_id)` pair across
//! different sessions.
//!
//! ## Wire exchange (single bidirectional stream)
//!
//! ```text
//! Initiator (A)                                Listener (B)
//!     ── nonce_a (32B) ─────────────────────────────▶
//!     ◀────── (vid_b, sig_b, nonce_b) (136B)
//!     ── (vid_a, sig_a) (104B), close-write ────────▶
//! ```
//!
//! Where `sig_b = BLS_sign(B_key, "VALIDATOR_BIND" || B_peer_id || nonce_a)`
//! and `sig_a = BLS_sign(A_key, "VALIDATOR_BIND" || A_peer_id || nonce_b)`.
//! Each verifier checks the signature against its *own* nonce, so an attacker
//! can't pre-compute a sig for a nonce they didn't choose.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use hyperscale_network::ValidatorKeyMap;
use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G2Signature, VALIDATOR_BIND_NONCE_LEN, ValidatorId,
    validator_bind_message, verify_bls12381_v1,
};
use libp2p::{PeerId as Libp2pPeerId, Stream, StreamProtocol};
use libp2p_stream::{Control, IncomingStreams};
use rand::random;
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tracing::{error, info, warn};

use crate::stream_framing;

/// Shared validator key map, updated atomically on topology changes.
type SharedValidatorKeys = Arc<ArcSwap<ValidatorKeyMap>>;

/// Stream protocol identifier for the validator-bind handshake.
pub const VALIDATOR_BIND_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/hyperscale/validator-bind/1.0.0");

/// Timeout for the complete bind exchange (read + write).
const BIND_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum frame size for bind messages (~200 bytes wire-encoded).
const MAX_BIND_FRAME: usize = 4096;

/// Maximum number of retry attempts for a failed outbound bind.
const MAX_BIND_RETRIES: u32 = 5;

/// Base delay for exponential backoff on bind retries.
const BIND_RETRY_BASE_DELAY: Duration = Duration::from_secs(2);

/// Length of the challenge frame on the wire.
const CHALLENGE_FRAME_LEN: usize = VALIDATOR_BIND_NONCE_LEN;

/// Length of the response frame on the wire (validator id + sig + counter-nonce).
const RESPONSE_FRAME_LEN: usize = 8 + 96 + VALIDATOR_BIND_NONCE_LEN;

/// Length of the final frame on the wire (validator id + sig).
const FINAL_FRAME_LEN: usize = 8 + 96;

// ─── Wire format ────────────────────────────────────────────────────────

/// Encode the initiator's challenge: `[32-byte nonce]`.
fn encode_challenge(nonce: &[u8; VALIDATOR_BIND_NONCE_LEN]) -> Vec<u8> {
    nonce.to_vec()
}

/// Decode the initiator's challenge.
const fn decode_challenge(data: &[u8]) -> Option<[u8; VALIDATOR_BIND_NONCE_LEN]> {
    if data.len() != CHALLENGE_FRAME_LEN {
        return None;
    }
    let mut nonce = [0u8; VALIDATOR_BIND_NONCE_LEN];
    let mut i = 0;
    while i < VALIDATOR_BIND_NONCE_LEN {
        nonce[i] = data[i];
        i += 1;
    }
    Some(nonce)
}

/// Encode the listener's response: `[8-byte LE validator_id][96-byte sig][32-byte nonce]`.
fn encode_response(
    validator_id: ValidatorId,
    signature: &Bls12381G2Signature,
    nonce: &[u8; VALIDATOR_BIND_NONCE_LEN],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(RESPONSE_FRAME_LEN);
    buf.extend_from_slice(&validator_id.0.to_le_bytes());
    buf.extend_from_slice(&signature.0);
    buf.extend_from_slice(nonce);
    buf
}

/// Decode the listener's response.
fn decode_response(
    data: &[u8],
) -> Option<(
    ValidatorId,
    Bls12381G2Signature,
    [u8; VALIDATOR_BIND_NONCE_LEN],
)> {
    if data.len() != RESPONSE_FRAME_LEN {
        return None;
    }
    let vid = u64::from_le_bytes(data[..8].try_into().ok()?);
    let mut sig_bytes = [0u8; 96];
    sig_bytes.copy_from_slice(&data[8..104]);
    let mut nonce = [0u8; VALIDATOR_BIND_NONCE_LEN];
    nonce.copy_from_slice(&data[104..136]);
    Some((ValidatorId(vid), Bls12381G2Signature(sig_bytes), nonce))
}

/// Encode the initiator's final response: `[8-byte LE validator_id][96-byte sig]`.
fn encode_final(validator_id: ValidatorId, signature: &Bls12381G2Signature) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FINAL_FRAME_LEN);
    buf.extend_from_slice(&validator_id.0.to_le_bytes());
    buf.extend_from_slice(&signature.0);
    buf
}

/// Decode the initiator's final response.
fn decode_final(data: &[u8]) -> Option<(ValidatorId, Bls12381G2Signature)> {
    if data.len() != FINAL_FRAME_LEN {
        return None;
    }
    let vid = u64::from_le_bytes(data[..8].try_into().ok()?);
    let mut sig_bytes = [0u8; 96];
    sig_bytes.copy_from_slice(&data[8..104]);
    Some((ValidatorId(vid), Bls12381G2Signature(sig_bytes)))
}

/// Generate a fresh 32-byte nonce from the thread-local CSPRNG (seeded from OS).
fn fresh_nonce() -> [u8; VALIDATOR_BIND_NONCE_LEN] {
    random()
}

// ─── Verification ───────────────────────────────────────────────────────

/// Verify a bind signature: the BLS signature over `("VALIDATOR_BIND" ||
/// peer_id_bytes || nonce)` must be valid for the claimed `ValidatorId`'s
/// public key.
///
/// `nonce` must be the one *we* generated and sent to the remote — verifying
/// against a remote-supplied nonce defeats replay protection.
fn verify_bind(
    peer_id: &Libp2pPeerId,
    claimed_vid: ValidatorId,
    nonce: &[u8; VALIDATOR_BIND_NONCE_LEN],
    signature: &Bls12381G2Signature,
    keys: &ValidatorKeyMap,
) -> Result<(), BindError> {
    let pubkey = keys
        .get(&claimed_vid)
        .ok_or(BindError::UnknownValidator(claimed_vid))?;

    let message = validator_bind_message(&peer_id.to_bytes(), nonce);
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
            Self::UnknownValidator(v) => write!(f, "unknown validator {}", v.0),
            Self::InvalidSignature(v) => {
                write!(f, "invalid BLS signature for validator {}", v.0)
            }
            Self::InvalidMessage => write!(f, "malformed bind message"),
            Self::StreamOpen(e) => write!(f, "stream open failed: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Frame(e) => write!(f, "frame error: {e}"),
            Self::Timeout => write!(f, "bind exchange timed out"),
        }
    }
}

// ─── Context ────────────────────────────────────────────────────────────

/// Shared inputs for every bind exchange.
///
/// Held by the service loop and cloned into each spawned handler task. Every
/// field is `Clone`-cheap (`Arc` or `Copy`).
#[derive(Clone)]
struct BindContext {
    /// BLS signing key — used to produce a fresh signature per session.
    signing_key: Arc<Bls12381G1PrivateKey>,
    /// Local validator id (announced to peers in our response/final).
    local_vid: ValidatorId,
    /// Local libp2p peer id (signed over to bind it to `local_vid`).
    local_peer_id: Libp2pPeerId,
    /// Validator BLS key map (consulted to verify remote signatures).
    validator_keys: SharedValidatorKeys,
    /// Validator-id → peer-id map populated on successful bind.
    validator_peers: Arc<DashMap<ValidatorId, Libp2pPeerId>>,
}

// ─── Handle (public interface) ──────────────────────────────────────────

/// Handle for the validator-bind service.
///
/// Kept alive inside `Libp2pAdapter` to prevent the background task from
/// being aborted. Provides a channel to trigger outbound bind exchanges
/// from the event loop.
pub struct ValidatorBindHandle {
    /// Trigger an outbound bind to a newly-identified peer.
    pub(crate) bind_tx: mpsc::UnboundedSender<Libp2pPeerId>,
    /// Keep the background task alive.
    #[allow(dead_code)]
    join_handle: JoinHandle<()>,
}

// ─── Service ────────────────────────────────────────────────────────────

/// Spawn the validator-bind service.
///
/// The service runs two concurrent loops:
/// 1. **Inbound**: accepts `/hyperscale/validator-bind/1.0.0` streams from peers.
/// 2. **Outbound**: opens bind streams to peers when triggered by the event loop.
pub fn spawn_validator_bind_service(
    mut control: Control,
    validator_peers: Arc<DashMap<ValidatorId, Libp2pPeerId>>,
    signing_key: Arc<Bls12381G1PrivateKey>,
    local_vid: ValidatorId,
    local_peer_id: Libp2pPeerId,
    validator_keys: SharedValidatorKeys,
) -> ValidatorBindHandle {
    let (bind_tx, bind_rx) = mpsc::unbounded_channel();

    let ctx = BindContext {
        signing_key,
        local_vid,
        local_peer_id,
        validator_keys,
        validator_peers,
    };

    let join_handle = spawn(async move {
        // Accept incoming validator-bind streams.
        let mut incoming = match control.accept(VALIDATOR_BIND_PROTOCOL) {
            Ok(incoming) => incoming,
            Err(e) => {
                error!(error = ?e, "Failed to register validator-bind protocol");
                return;
            }
        };

        info!("Validator-bind service started");

        run_service(&mut incoming, bind_rx, control.clone(), ctx).await;

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
    incoming: &mut IncomingStreams,
    mut bind_rx: mpsc::UnboundedReceiver<Libp2pPeerId>,
    control: Control,
    ctx: BindContext,
) {
    use futures::StreamExt;

    // Internal channel for scheduling bind retries with backoff.
    let (retry_tx, mut retry_rx) = mpsc::unbounded_channel::<BindRetry>();

    loop {
        tokio::select! {
            // Inbound: a remote peer initiated the bind exchange.
            Some((peer_id, stream)) = incoming.next() => {
                let ctx = ctx.clone();
                spawn(async move {
                    if let Err(e) = handle_inbound(peer_id, stream, &ctx).await {
                        warn!(peer = %peer_id, error = %e, "Inbound validator-bind failed");
                    }
                });
            }

            // Outbound: the event loop identified a new hyperscale peer.
            Some(peer_id) = bind_rx.recv() => {
                // Skip if we already have this peer bound.
                let already_bound = ctx.validator_peers
                    .iter()
                    .any(|entry| *entry.value() == peer_id);
                if already_bound {
                    continue;
                }

                let ctrl = control.clone();
                let ctx = ctx.clone();
                let rtx = retry_tx.clone();

                spawn(async move {
                    if let Err(e) = handle_outbound(peer_id, ctrl, &ctx).await {
                        warn!(peer = %peer_id, error = %e, "Outbound validator-bind failed, scheduling retry");
                        schedule_retry(rtx, peer_id, 0);
                    }
                });
            }

            // Retry: a previous outbound bind failed — try again with backoff.
            Some(retry) = retry_rx.recv() => {
                // Skip if the peer got bound in the meantime (e.g. via inbound).
                let already_bound = ctx.validator_peers
                    .iter()
                    .any(|entry| *entry.value() == retry.peer_id);
                if already_bound {
                    continue;
                }

                let peer_id = retry.peer_id;
                let attempt = retry.attempt;
                let ctrl = control.clone();
                let ctx = ctx.clone();
                let rtx = retry_tx.clone();

                spawn(async move {
                    if let Err(e) = handle_outbound(peer_id, ctrl, &ctx).await {
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
fn schedule_retry(retry_tx: mpsc::UnboundedSender<BindRetry>, peer_id: Libp2pPeerId, attempt: u32) {
    let delay = BIND_RETRY_BASE_DELAY * 2u32.saturating_pow(attempt);
    spawn(async move {
        sleep(delay).await;
        let _ = retry_tx.send(BindRetry { peer_id, attempt });
    });
}

/// Write a bind frame and keep the stream open for further exchange.
async fn write_bind_frame(stream: &mut Stream, data: &[u8]) -> Result<(), BindError> {
    stream_framing::write_frame(stream, data)
        .await
        .map_err(BindError::Io)?;
    Ok(())
}

/// Write the final bind frame and half-close the write side so the peer reads EOF.
async fn write_bind_frame_final(stream: &mut Stream, data: &[u8]) -> Result<(), BindError> {
    use futures::AsyncWriteExt;
    write_bind_frame(stream, data).await?;
    stream.close().await.map_err(BindError::Io)?;
    Ok(())
}

/// Handle an inbound bind stream (we are the listener).
///
/// 1. Read remote's challenge (their nonce)
/// 2. Sign over remote's nonce, send our (vid, sig, our nonce)
/// 3. Read remote's final (vid, sig over our nonce)
/// 4. Verify, register binding
async fn handle_inbound(
    peer_id: Libp2pPeerId,
    mut stream: Stream,
    ctx: &BindContext,
) -> Result<(), BindError> {
    let result = timeout(BIND_TIMEOUT, async {
        // 1. Read remote's challenge.
        let challenge_bytes = stream_framing::read_frame(&mut stream, MAX_BIND_FRAME)
            .await
            .map_err(BindError::Frame)?;
        let remote_nonce = decode_challenge(&challenge_bytes).ok_or(BindError::InvalidMessage)?;

        // 2. Sign over remote's nonce, generate our own nonce, send response.
        let our_nonce = fresh_nonce();
        let our_sig = ctx.signing_key.sign_v1(&validator_bind_message(
            &ctx.local_peer_id.to_bytes(),
            &remote_nonce,
        ));
        write_bind_frame(
            &mut stream,
            &encode_response(ctx.local_vid, &our_sig, &our_nonce),
        )
        .await?;

        // 3. Read remote's final (their signed response over our nonce).
        let final_bytes = stream_framing::read_frame(&mut stream, MAX_BIND_FRAME)
            .await
            .map_err(BindError::Frame)?;
        let (remote_vid, remote_sig) =
            decode_final(&final_bytes).ok_or(BindError::InvalidMessage)?;

        // 4. Verify remote's sig is over OUR nonce.
        let keys_guard = ctx.validator_keys.load();
        verify_bind(&peer_id, remote_vid, &our_nonce, &remote_sig, &keys_guard)?;

        info!(
            peer = %peer_id,
            validator_id = remote_vid.0,
            "Validator-bind verified (inbound)"
        );
        ctx.validator_peers.insert(remote_vid, peer_id);

        Ok(())
    })
    .await;

    result.map_or(Err(BindError::Timeout), |inner| inner)
}

/// Handle an outbound bind (we are the initiator).
///
/// 1. Open stream
/// 2. Send our challenge (our nonce)
/// 3. Read remote's response: their (vid, sig over our nonce, their nonce)
/// 4. Verify; sign over their nonce; send our final (vid, sig)
/// 5. Register binding
async fn handle_outbound(
    peer_id: Libp2pPeerId,
    mut control: Control,
    ctx: &BindContext,
) -> Result<(), BindError> {
    let result = timeout(BIND_TIMEOUT, async {
        let mut stream = control
            .open_stream(peer_id, VALIDATOR_BIND_PROTOCOL)
            .await
            .map_err(|e| BindError::StreamOpen(format!("{e:?}")))?;

        // 1. Send our challenge.
        let our_nonce = fresh_nonce();
        write_bind_frame(&mut stream, &encode_challenge(&our_nonce)).await?;

        // 2. Read remote's response.
        let response_bytes = stream_framing::read_frame(&mut stream, MAX_BIND_FRAME)
            .await
            .map_err(BindError::Frame)?;
        let (remote_vid, remote_sig, remote_nonce) =
            decode_response(&response_bytes).ok_or(BindError::InvalidMessage)?;

        // 3. Verify remote's sig is over OUR nonce.
        let keys_guard = ctx.validator_keys.load();
        verify_bind(&peer_id, remote_vid, &our_nonce, &remote_sig, &keys_guard)?;

        // 4. Sign over remote's nonce, send final + close write side.
        let our_sig = ctx.signing_key.sign_v1(&validator_bind_message(
            &ctx.local_peer_id.to_bytes(),
            &remote_nonce,
        ));
        write_bind_frame_final(&mut stream, &encode_final(ctx.local_vid, &our_sig)).await?;

        info!(
            peer = %peer_id,
            validator_id = remote_vid.0,
            "Validator-bind verified (outbound)"
        );
        ctx.validator_peers.insert(remote_vid, peer_id);

        Ok(())
    })
    .await;

    result.map_or(Err(BindError::Timeout), |inner| inner)
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Bls12381G1PublicKey, generate_bls_keypair, zero_bls_signature};

    use super::*;

    /// Build a single-validator key map for bind tests.
    fn make_bind_keys(vid: ValidatorId, pubkey: Bls12381G1PublicKey) -> ValidatorKeyMap {
        let mut keys = ValidatorKeyMap::new();
        keys.insert(vid, pubkey);
        keys
    }

    #[test]
    fn challenge_roundtrip() {
        let nonce = [0xAB; VALIDATOR_BIND_NONCE_LEN];
        let encoded = encode_challenge(&nonce);
        assert_eq!(encoded.len(), CHALLENGE_FRAME_LEN);
        assert_eq!(decode_challenge(&encoded), Some(nonce));
    }

    #[test]
    fn response_roundtrip() {
        let vid = ValidatorId(42);
        let sig = zero_bls_signature();
        let nonce = [0xCD; VALIDATOR_BIND_NONCE_LEN];

        let encoded = encode_response(vid, &sig, &nonce);
        assert_eq!(encoded.len(), RESPONSE_FRAME_LEN);

        let (decoded_vid, decoded_sig, decoded_nonce) = decode_response(&encoded).unwrap();
        assert_eq!(decoded_vid, vid);
        assert_eq!(decoded_sig.0, sig.0);
        assert_eq!(decoded_nonce, nonce);
    }

    #[test]
    fn final_roundtrip() {
        let vid = ValidatorId(7);
        let sig = zero_bls_signature();

        let encoded = encode_final(vid, &sig);
        assert_eq!(encoded.len(), FINAL_FRAME_LEN);

        let (decoded_vid, decoded_sig) = decode_final(&encoded).unwrap();
        assert_eq!(decoded_vid, vid);
        assert_eq!(decoded_sig.0, sig.0);
    }

    #[test]
    fn decode_rejects_wrong_lengths() {
        assert!(decode_challenge(&[0u8; 16]).is_none());
        assert!(decode_response(&[0u8; 50]).is_none());
        assert!(decode_response(&[0u8; 200]).is_none());
        assert!(decode_final(&[0u8; 50]).is_none());
        assert!(decode_final(&[0u8; 200]).is_none());
    }

    #[test]
    fn verify_bind_accepts_valid_signature_over_nonce() {
        let keypair = generate_bls_keypair();
        let pubkey = keypair.public_key();
        let peer_id = Libp2pPeerId::random();
        let vid = ValidatorId(7);
        let nonce = [9u8; VALIDATOR_BIND_NONCE_LEN];

        let sig = keypair.sign_v1(&validator_bind_message(&peer_id.to_bytes(), &nonce));

        let keys = make_bind_keys(vid, pubkey);
        assert!(verify_bind(&peer_id, vid, &nonce, &sig, &keys).is_ok());
    }

    #[test]
    fn verify_bind_rejects_signature_over_different_nonce() {
        // Forward-security check: a signature produced over nonce_a must NOT
        // verify against nonce_b. This is what makes replay across sessions
        // impossible.
        let keypair = generate_bls_keypair();
        let pubkey = keypair.public_key();
        let peer_id = Libp2pPeerId::random();
        let vid = ValidatorId(7);

        let nonce_a = [1u8; VALIDATOR_BIND_NONCE_LEN];
        let nonce_b = [2u8; VALIDATOR_BIND_NONCE_LEN];

        // Sign over nonce_a — what the remote would have produced in session A.
        let sig = keypair.sign_v1(&validator_bind_message(&peer_id.to_bytes(), &nonce_a));

        // Verifier in session B challenged with nonce_b, so they verify the
        // replayed signature against nonce_b and reject.
        let keys = make_bind_keys(vid, pubkey);
        assert!(matches!(
            verify_bind(&peer_id, vid, &nonce_b, &sig, &keys),
            Err(BindError::InvalidSignature(_))
        ));
    }

    #[test]
    fn verify_bind_rejects_wrong_peer_id() {
        let keypair = generate_bls_keypair();
        let pubkey = keypair.public_key();
        let peer_a = Libp2pPeerId::random();
        let peer_b = Libp2pPeerId::random();
        let vid = ValidatorId(7);
        let nonce = [3u8; VALIDATOR_BIND_NONCE_LEN];

        // Sign peer_a's id but try to verify as peer_b.
        let sig = keypair.sign_v1(&validator_bind_message(&peer_a.to_bytes(), &nonce));

        let keys = make_bind_keys(vid, pubkey);
        assert!(verify_bind(&peer_b, vid, &nonce, &sig, &keys).is_err());
    }

    #[test]
    fn verify_bind_rejects_unknown_validator() {
        let keypair = generate_bls_keypair();
        let pubkey = keypair.public_key();
        let peer_id = Libp2pPeerId::random();
        let nonce = [4u8; VALIDATOR_BIND_NONCE_LEN];

        let sig = keypair.sign_v1(&validator_bind_message(&peer_id.to_bytes(), &nonce));

        // Key map has validator 7 but we claim to be validator 99.
        let keys = make_bind_keys(ValidatorId(7), pubkey);
        assert!(matches!(
            verify_bind(&peer_id, ValidatorId(99), &nonce, &sig, &keys),
            Err(BindError::UnknownValidator(_))
        ));
    }

    #[test]
    fn verify_bind_rejects_wrong_key() {
        let keypair_a = generate_bls_keypair();
        let keypair_b = generate_bls_keypair();
        let peer_id = Libp2pPeerId::random();
        let vid = ValidatorId(7);
        let nonce = [5u8; VALIDATOR_BIND_NONCE_LEN];

        // Sign with key_a but key map has key_b for this validator.
        let sig = keypair_a.sign_v1(&validator_bind_message(&peer_id.to_bytes(), &nonce));

        let keys = make_bind_keys(vid, keypair_b.public_key());
        assert!(matches!(
            verify_bind(&peer_id, vid, &nonce, &sig, &keys),
            Err(BindError::InvalidSignature(_))
        ));
    }

    #[test]
    fn fresh_nonce_is_nonzero_with_overwhelming_probability() {
        // Sanity check on the RNG: we'd be in trouble if `fresh_nonce` returned
        // [0; 32]. The probability of that under OsRng is 2^-256 — if it ever
        // fires in practice, something is very wrong.
        let nonce = fresh_nonce();
        assert_ne!(nonce, [0u8; VALIDATOR_BIND_NONCE_LEN]);
    }
}
