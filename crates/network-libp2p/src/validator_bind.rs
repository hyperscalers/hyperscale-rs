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
//! Initiator (A)                                              Listener (B)
//!     ── nonce_a (32B) ────────────────────────────────────────────▶
//!     ◀── [count_b][count_b × (vid_b_i, sig_b_i)][nonce_b]
//!     ── [count_a][count_a × (vid_a_i, sig_a_i)], close-write ─────▶
//! ```
//!
//! Each side attests as **every** validator it hosts in one handshake: a
//! multi-vnode process emits one `(validator_id, signature)` pair per hosted
//! vnode. The verifier checks every signature against the corresponding
//! validator's BLS pubkey from the topology; any failure rejects the whole
//! exchange.
//!
//! Where `sig_x_i = BLS_sign(x_i_key, "VALIDATOR_BIND" || x_peer_id ||
//! their_nonce)`. Each side signs over the **other** side's nonce, so
//! signatures are fresh per session and cannot be replayed against the same
//! `(validator_id, peer_id)` pair across different sessions.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use hyperscale_network::ValidatorKeyMap;
use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G2Signature, NetworkDefinition, VALIDATOR_BIND_NONCE_LEN,
    ValidatorId, validator_bind_message, verify_bls12381_v1,
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

/// Per-vnode signing identity used by the bind service to attest as one
/// hosted validator. A multi-vnode host supplies one entry per vnode; each
/// entry contributes one `(validator_id, signature)` pair to the attestation
/// list on every bind exchange.
pub type LocalVnodeIdentity = (ValidatorId, Arc<Bls12381G1PrivateKey>);

/// List of `(validator_id, signature)` attestations carried in one bind
/// frame. Each entry proves that the holder of `validator_id`'s BLS key
/// signed `("VALIDATOR_BIND" || peer_id || nonce)` for this session.
type Attestations = Vec<(ValidatorId, Bls12381G2Signature)>;

/// Shared validator key map, updated atomically on topology changes.
type SharedValidatorKeys = Arc<ArcSwap<ValidatorKeyMap>>;

/// Stream protocol identifier for the validator-bind handshake.
pub const VALIDATOR_BIND_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/hyperscale/validator-bind/1.0.0");

/// Timeout for the complete bind exchange (read + write).
const BIND_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum frame size for bind messages. Sized to fit a fully-populated
/// attestation list at the per-bind cap plus framing overhead, with margin
/// for the LZ4 wrapper (BLS sigs barely compress).
const MAX_BIND_FRAME: usize = 64 * 1024;

/// Maximum number of retry attempts for a failed outbound bind.
const MAX_BIND_RETRIES: u32 = 5;

/// Base delay for exponential backoff on bind retries.
const BIND_RETRY_BASE_DELAY: Duration = Duration::from_secs(2);

/// Maximum number of `(validator_id, signature)` attestations a peer may
/// claim in a single bind exchange. Bounds frame size and decode work;
/// `u16`-encoded count is sized accordingly.
const MAX_VNODES_PER_BIND: usize = 256;

/// Length of one `(validator_id, signature)` attestation pair.
const PAIR_LEN: usize = 8 + 96;

/// Length of the challenge frame on the wire.
const CHALLENGE_FRAME_LEN: usize = VALIDATOR_BIND_NONCE_LEN;

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

/// Append one attestation list to `buf`: `[2-byte LE count][count × pair]`.
fn write_attestations(buf: &mut Vec<u8>, attestations: &[(ValidatorId, Bls12381G2Signature)]) {
    let count = u16::try_from(attestations.len()).expect("caller bounds attestations by u16::MAX");
    buf.extend_from_slice(&count.to_le_bytes());
    for (vid, sig) in attestations {
        buf.extend_from_slice(&vid.to_le_bytes());
        buf.extend_from_slice(&sig.0);
    }
}

/// Parse one attestation list starting at `data[0]`. On success returns the
/// decoded pairs and the remaining byte slice. Rejects empty lists, lists
/// over [`MAX_VNODES_PER_BIND`], truncated bodies, and duplicate validator
/// ids in the same exchange.
fn read_attestations(data: &[u8]) -> Option<(Attestations, &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let count = u16::from_le_bytes(data[..2].try_into().ok()?) as usize;
    if count == 0 || count > MAX_VNODES_PER_BIND {
        return None;
    }
    let body_len = count.checked_mul(PAIR_LEN)?;
    let total = 2usize.checked_add(body_len)?;
    if data.len() < total {
        return None;
    }
    let mut pairs = Vec::with_capacity(count);
    let mut seen = HashSet::with_capacity(count);
    let mut cursor = 2;
    for _ in 0..count {
        let vid = ValidatorId::new(u64::from_le_bytes(
            data[cursor..cursor + 8].try_into().ok()?,
        ));
        if !seen.insert(vid) {
            return None;
        }
        let mut sig_bytes = [0u8; 96];
        sig_bytes.copy_from_slice(&data[cursor + 8..cursor + PAIR_LEN]);
        pairs.push((vid, Bls12381G2Signature(sig_bytes)));
        cursor += PAIR_LEN;
    }
    Some((pairs, &data[total..]))
}

/// Encode the listener's response:
/// `[2-byte LE count][count × (8-byte LE vid)(96-byte sig)][32-byte nonce]`.
fn encode_response(
    attestations: &[(ValidatorId, Bls12381G2Signature)],
    nonce: &[u8; VALIDATOR_BIND_NONCE_LEN],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + attestations.len() * PAIR_LEN + VALIDATOR_BIND_NONCE_LEN);
    write_attestations(&mut buf, attestations);
    buf.extend_from_slice(nonce);
    buf
}

/// Decode the listener's response.
fn decode_response(data: &[u8]) -> Option<(Attestations, [u8; VALIDATOR_BIND_NONCE_LEN])> {
    let (pairs, rest) = read_attestations(data)?;
    if rest.len() != VALIDATOR_BIND_NONCE_LEN {
        return None;
    }
    let mut nonce = [0u8; VALIDATOR_BIND_NONCE_LEN];
    nonce.copy_from_slice(rest);
    Some((pairs, nonce))
}

/// Encode the initiator's final response:
/// `[2-byte LE count][count × (8-byte LE vid)(96-byte sig)]`.
fn encode_final(attestations: &[(ValidatorId, Bls12381G2Signature)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + attestations.len() * PAIR_LEN);
    write_attestations(&mut buf, attestations);
    buf
}

/// Decode the initiator's final response.
fn decode_final(data: &[u8]) -> Option<Attestations> {
    let (pairs, rest) = read_attestations(data)?;
    if !rest.is_empty() {
        return None;
    }
    Some(pairs)
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
    network: &NetworkDefinition,
    peer_id: &Libp2pPeerId,
    claimed_vid: ValidatorId,
    nonce: &[u8; VALIDATOR_BIND_NONCE_LEN],
    signature: &Bls12381G2Signature,
    keys: &ValidatorKeyMap,
) -> Result<(), BindError> {
    let pubkey = keys
        .get(&claimed_vid)
        .ok_or(BindError::UnknownValidator(claimed_vid))?;

    let message = validator_bind_message(network, &peer_id.to_bytes(), nonce);
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
            Self::UnknownValidator(v) => write!(f, "unknown validator {}", v.inner()),
            Self::InvalidSignature(v) => {
                write!(f, "invalid BLS signature for validator {}", v.inner())
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
    /// Radix network identity, bound into every BLS-signed bind message.
    network: NetworkDefinition,
    /// Per-vnode signing identities. One `(validator_id, signature)` pair
    /// is produced per entry on every bind exchange. Must be non-empty.
    local_vnodes: Arc<[LocalVnodeIdentity]>,
    /// Local libp2p peer id, signed over to bind it to every hosted vnode.
    local_peer_id: Libp2pPeerId,
    /// Validator BLS key map (consulted to verify remote signatures).
    validator_keys: SharedValidatorKeys,
    /// Validator-id → peer-id map populated on successful bind.
    validator_peers: Arc<DashMap<ValidatorId, Libp2pPeerId>>,
}

impl BindContext {
    /// Sign over `peer_id || remote_nonce` once per hosted vnode.
    fn sign_all(&self, remote_nonce: &[u8; VALIDATOR_BIND_NONCE_LEN]) -> Attestations {
        let message =
            validator_bind_message(&self.network, &self.local_peer_id.to_bytes(), remote_nonce);
        self.local_vnodes
            .iter()
            .map(|(vid, key)| (*vid, key.sign_v1(&message)))
            .collect()
    }
}

/// Verify every `(vid, sig)` claim against the local-chosen nonce. All must
/// verify — any failure rejects the whole bind.
fn verify_all(
    network: &NetworkDefinition,
    peer_id: &Libp2pPeerId,
    nonce: &[u8; VALIDATOR_BIND_NONCE_LEN],
    attestations: &[(ValidatorId, Bls12381G2Signature)],
    keys: &ValidatorKeyMap,
) -> Result<(), BindError> {
    for (vid, sig) in attestations {
        verify_bind(network, peer_id, *vid, nonce, sig, keys)?;
    }
    Ok(())
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
    network: NetworkDefinition,
    validator_peers: Arc<DashMap<ValidatorId, Libp2pPeerId>>,
    local_vnodes: Arc<[LocalVnodeIdentity]>,
    local_peer_id: Libp2pPeerId,
    validator_keys: SharedValidatorKeys,
) -> ValidatorBindHandle {
    assert!(
        !local_vnodes.is_empty(),
        "validator-bind service requires at least one hosted vnode"
    );
    assert!(
        local_vnodes.len() <= MAX_VNODES_PER_BIND,
        "hosted vnode count {} exceeds per-bind cap {MAX_VNODES_PER_BIND}",
        local_vnodes.len(),
    );

    let (bind_tx, bind_rx) = mpsc::unbounded_channel();

    let ctx = BindContext {
        network,
        local_vnodes,
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
/// 2. Sign over remote's nonce with every hosted vnode key, send our
///    `[count][N × (vid, sig)][our nonce]`
/// 3. Read remote's final `[count][N × (vid, sig over our nonce)]`
/// 4. Verify each remote attestation; register every binding
async fn handle_inbound(
    peer_id: Libp2pPeerId,
    mut stream: Stream,
    ctx: &BindContext,
) -> Result<(), BindError> {
    let result = timeout(BIND_TIMEOUT, async {
        let challenge_bytes = stream_framing::read_frame(&mut stream, MAX_BIND_FRAME)
            .await
            .map_err(BindError::Frame)?;
        let remote_nonce = decode_challenge(&challenge_bytes).ok_or(BindError::InvalidMessage)?;

        let our_nonce = fresh_nonce();
        let our_attestations = ctx.sign_all(&remote_nonce);
        write_bind_frame(&mut stream, &encode_response(&our_attestations, &our_nonce)).await?;

        let final_bytes = stream_framing::read_frame(&mut stream, MAX_BIND_FRAME)
            .await
            .map_err(BindError::Frame)?;
        let remote_attestations = decode_final(&final_bytes).ok_or(BindError::InvalidMessage)?;

        let keys_guard = ctx.validator_keys.load();
        verify_all(
            &ctx.network,
            &peer_id,
            &our_nonce,
            &remote_attestations,
            &keys_guard,
        )?;

        for (vid, _) in &remote_attestations {
            info!(
                peer = %peer_id,
                validator_id = vid.inner(),
                "Validator-bind verified (inbound)"
            );
            ctx.validator_peers.insert(*vid, peer_id);
        }

        Ok(())
    })
    .await;

    result.unwrap_or(Err(BindError::Timeout))
}

/// Handle an outbound bind (we are the initiator).
///
/// 1. Open stream
/// 2. Send our challenge (our nonce)
/// 3. Read remote's `[count][N × (vid, sig over our nonce)][their nonce]`
/// 4. Verify each attestation; sign their nonce with every hosted vnode
///    key; send our `[count][N × (vid, sig)]`
/// 5. Register every binding
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

        let our_nonce = fresh_nonce();
        write_bind_frame(&mut stream, &encode_challenge(&our_nonce)).await?;

        let response_bytes = stream_framing::read_frame(&mut stream, MAX_BIND_FRAME)
            .await
            .map_err(BindError::Frame)?;
        let (remote_attestations, remote_nonce) =
            decode_response(&response_bytes).ok_or(BindError::InvalidMessage)?;

        let keys_guard = ctx.validator_keys.load();
        verify_all(
            &ctx.network,
            &peer_id,
            &our_nonce,
            &remote_attestations,
            &keys_guard,
        )?;

        let our_attestations = ctx.sign_all(&remote_nonce);
        write_bind_frame_final(&mut stream, &encode_final(&our_attestations)).await?;

        for (vid, _) in &remote_attestations {
            info!(
                peer = %peer_id,
                validator_id = vid.inner(),
                "Validator-bind verified (outbound)"
            );
            ctx.validator_peers.insert(*vid, peer_id);
        }

        Ok(())
    })
    .await;

    result.unwrap_or(Err(BindError::Timeout))
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

    /// Build a distinct `(ValidatorId, sig)` pair for each `i` so duplicate
    /// detection in `read_attestations` has a stable test surface.
    fn pair_for(i: u64) -> (ValidatorId, Bls12381G2Signature) {
        let mut sig_bytes = [0u8; 96];
        sig_bytes[..8].copy_from_slice(&i.to_le_bytes());
        (ValidatorId::new(i), Bls12381G2Signature(sig_bytes))
    }

    #[test]
    fn challenge_roundtrip() {
        let nonce = [0xAB; VALIDATOR_BIND_NONCE_LEN];
        let encoded = encode_challenge(&nonce);
        assert_eq!(encoded.len(), CHALLENGE_FRAME_LEN);
        assert_eq!(decode_challenge(&encoded), Some(nonce));
    }

    #[test]
    fn response_roundtrip_multi() {
        let pairs = vec![pair_for(1), pair_for(42), pair_for(1000)];
        let nonce = [0xCD; VALIDATOR_BIND_NONCE_LEN];

        let encoded = encode_response(&pairs, &nonce);
        assert_eq!(
            encoded.len(),
            2 + pairs.len() * PAIR_LEN + VALIDATOR_BIND_NONCE_LEN
        );

        let (decoded_pairs, decoded_nonce) = decode_response(&encoded).unwrap();
        assert_eq!(decoded_pairs.len(), pairs.len());
        for ((dv, ds), (ov, os)) in decoded_pairs.iter().zip(pairs.iter()) {
            assert_eq!(dv, ov);
            assert_eq!(ds.0, os.0);
        }
        assert_eq!(decoded_nonce, nonce);
    }

    #[test]
    fn final_roundtrip_multi() {
        let pairs = vec![pair_for(7), pair_for(8)];

        let encoded = encode_final(&pairs);
        assert_eq!(encoded.len(), 2 + pairs.len() * PAIR_LEN);

        let decoded_pairs = decode_final(&encoded).unwrap();
        assert_eq!(decoded_pairs.len(), pairs.len());
        for ((dv, ds), (ov, os)) in decoded_pairs.iter().zip(pairs.iter()) {
            assert_eq!(dv, ov);
            assert_eq!(ds.0, os.0);
        }
    }

    #[test]
    fn decode_rejects_wrong_lengths() {
        assert!(decode_challenge(&[0u8; 16]).is_none());
        // Too short to hold the count prefix.
        assert!(decode_response(&[0u8; 1]).is_none());
        assert!(decode_final(&[0u8; 1]).is_none());
        // Count prefix says 1 but no pair bytes follow.
        let bogus = 1u16.to_le_bytes().to_vec();
        assert!(decode_final(&bogus).is_none());
        // Final frame with extra trailing bytes.
        let mut trailing = encode_final(&[pair_for(3)]);
        trailing.push(0);
        assert!(decode_final(&trailing).is_none());
        // Response missing its 32-byte trailing nonce.
        let no_nonce = encode_final(&[pair_for(3)]);
        assert!(decode_response(&no_nonce).is_none());
    }

    #[test]
    fn decode_rejects_zero_count() {
        let mut buf = 0u16.to_le_bytes().to_vec();
        assert!(decode_final(&buf).is_none());
        buf.extend_from_slice(&[0u8; VALIDATOR_BIND_NONCE_LEN]);
        assert!(decode_response(&buf).is_none());
    }

    #[test]
    fn decode_rejects_count_over_cap() {
        let mut buf = u16::try_from(MAX_VNODES_PER_BIND + 1)
            .unwrap()
            .to_le_bytes()
            .to_vec();
        // Body bytes aren't actually present; the count check fires first.
        buf.resize(2 + (MAX_VNODES_PER_BIND + 1) * PAIR_LEN, 0);
        assert!(decode_final(&buf).is_none());
    }

    #[test]
    fn decode_rejects_duplicate_validator_ids() {
        let pairs = vec![pair_for(5), pair_for(5)];
        let encoded = encode_final(&pairs);
        assert!(decode_final(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_truncated_body() {
        let mut encoded = encode_final(&[pair_for(1), pair_for(2)]);
        // Drop the last byte: count claims 2 pairs but body is short.
        encoded.pop();
        assert!(decode_final(&encoded).is_none());
    }

    #[test]
    fn verify_all_rejects_when_any_signature_fails() {
        let keypair = generate_bls_keypair();
        let peer_id = Libp2pPeerId::random();
        let nonce = [4u8; VALIDATOR_BIND_NONCE_LEN];
        let good_vid = ValidatorId::new(1);
        let bad_vid = ValidatorId::new(2);

        let good_sig = keypair.sign_v1(&validator_bind_message(
            &NetworkDefinition::simulator(),
            &peer_id.to_bytes(),
            &nonce,
        ));
        let bad_sig = zero_bls_signature();

        let mut keys = ValidatorKeyMap::new();
        keys.insert(good_vid, keypair.public_key());
        keys.insert(bad_vid, keypair.public_key());

        let attestations = vec![(good_vid, good_sig), (bad_vid, bad_sig)];
        assert!(matches!(
            verify_all(
                &NetworkDefinition::simulator(),
                &peer_id,
                &nonce,
                &attestations,
                &keys
            ),
            Err(BindError::InvalidSignature(_))
        ));
    }

    #[test]
    fn verify_bind_accepts_valid_signature_over_nonce() {
        let keypair = generate_bls_keypair();
        let pubkey = keypair.public_key();
        let peer_id = Libp2pPeerId::random();
        let vid = ValidatorId::new(7);
        let nonce = [9u8; VALIDATOR_BIND_NONCE_LEN];

        let sig = keypair.sign_v1(&validator_bind_message(
            &NetworkDefinition::simulator(),
            &peer_id.to_bytes(),
            &nonce,
        ));

        let keys = make_bind_keys(vid, pubkey);
        assert!(
            verify_bind(
                &NetworkDefinition::simulator(),
                &peer_id,
                vid,
                &nonce,
                &sig,
                &keys
            )
            .is_ok()
        );
    }

    #[test]
    fn verify_bind_rejects_signature_over_different_nonce() {
        // Forward-security check: a signature produced over nonce_a must NOT
        // verify against nonce_b. This is what makes replay across sessions
        // impossible.
        let keypair = generate_bls_keypair();
        let pubkey = keypair.public_key();
        let peer_id = Libp2pPeerId::random();
        let vid = ValidatorId::new(7);

        let nonce_a = [1u8; VALIDATOR_BIND_NONCE_LEN];
        let nonce_b = [2u8; VALIDATOR_BIND_NONCE_LEN];

        // Sign over nonce_a — what the remote would have produced in session A.
        let sig = keypair.sign_v1(&validator_bind_message(
            &NetworkDefinition::simulator(),
            &peer_id.to_bytes(),
            &nonce_a,
        ));

        // Verifier in session B challenged with nonce_b, so they verify the
        // replayed signature against nonce_b and reject.
        let keys = make_bind_keys(vid, pubkey);
        assert!(matches!(
            verify_bind(
                &NetworkDefinition::simulator(),
                &peer_id,
                vid,
                &nonce_b,
                &sig,
                &keys
            ),
            Err(BindError::InvalidSignature(_))
        ));
    }

    #[test]
    fn verify_bind_rejects_wrong_peer_id() {
        let keypair = generate_bls_keypair();
        let pubkey = keypair.public_key();
        let peer_a = Libp2pPeerId::random();
        let peer_b = Libp2pPeerId::random();
        let vid = ValidatorId::new(7);
        let nonce = [3u8; VALIDATOR_BIND_NONCE_LEN];

        // Sign peer_a's id but try to verify as peer_b.
        let sig = keypair.sign_v1(&validator_bind_message(
            &NetworkDefinition::simulator(),
            &peer_a.to_bytes(),
            &nonce,
        ));

        let keys = make_bind_keys(vid, pubkey);
        assert!(
            verify_bind(
                &NetworkDefinition::simulator(),
                &peer_b,
                vid,
                &nonce,
                &sig,
                &keys
            )
            .is_err()
        );
    }

    #[test]
    fn verify_bind_rejects_unknown_validator() {
        let keypair = generate_bls_keypair();
        let pubkey = keypair.public_key();
        let peer_id = Libp2pPeerId::random();
        let nonce = [4u8; VALIDATOR_BIND_NONCE_LEN];

        let sig = keypair.sign_v1(&validator_bind_message(
            &NetworkDefinition::simulator(),
            &peer_id.to_bytes(),
            &nonce,
        ));

        // Key map has validator 7 but we claim to be validator 99.
        let keys = make_bind_keys(ValidatorId::new(7), pubkey);
        assert!(matches!(
            verify_bind(
                &NetworkDefinition::simulator(),
                &peer_id,
                ValidatorId::new(99),
                &nonce,
                &sig,
                &keys,
            ),
            Err(BindError::UnknownValidator(_))
        ));
    }

    #[test]
    fn verify_bind_rejects_wrong_key() {
        let keypair_a = generate_bls_keypair();
        let keypair_b = generate_bls_keypair();
        let peer_id = Libp2pPeerId::random();
        let vid = ValidatorId::new(7);
        let nonce = [5u8; VALIDATOR_BIND_NONCE_LEN];

        // Sign with key_a but key map has key_b for this validator.
        let sig = keypair_a.sign_v1(&validator_bind_message(
            &NetworkDefinition::simulator(),
            &peer_id.to_bytes(),
            &nonce,
        ));

        let keys = make_bind_keys(vid, keypair_b.public_key());
        assert!(matches!(
            verify_bind(
                &NetworkDefinition::simulator(),
                &peer_id,
                vid,
                &nonce,
                &sig,
                &keys
            ),
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
