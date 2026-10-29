//! Validator-bind protocol: cryptographic `ValidatorId` ↔ `EndpointId` binding.
//!
//! The QUIC handshake proves the peer holds its endpoint's network key. This
//! protocol proves it also controls the consensus signing key of every
//! validator it claims to host, as known from the topology.
//!
//! # Protocol
//!
//! The dialer opens one bidirectional stream, marked with
//! [`STREAM_BIND`](crate::protocol::STREAM_BIND), as soon as the connection
//! is up. Each side first states its version; a side that finds the other's
//! incompatible abandons the exchange. Three messages follow, each side
//! signing a nonce chosen by the other, so signatures are fresh per
//! connection and cannot be replayed.
//!
//! ```text
//! Dialer (A)                                                 Listener (B)
//!     ── version_a, nonce_a (32B) ─────────────────────────────────▶
//!     ◀── version_b, [count_b][count_b × (vid_b_i, sig_b_i)][nonce_b]
//!     ── [count_a][count_a × (vid_a_i, sig_a_i)], finish ──────────▶
//! ```
//!
//! Each side attests as **every** validator it hosts: a multi-vnode process
//! emits one `(validator_id, signature)` pair per hosted vnode, where
//! `sig_x_i = sign(x_i_key, "hyperscale-validator-bind-v1" || x_endpoint_id
//! || their_nonce)`. The verifier checks each signature against that
//! validator's consensus key from the topology. A validator the topology
//! gives no key yet, because its registration has not folded here, is set
//! aside as claimed rather than refusing the exchange; any signature that
//! does not verify, or an exchange proving no validator, refuses it.
//!
//! # Pulling an attestation
//!
//! A claim the verifier could not check is proved later over the same
//! connection, once the verifier's topology holds its key. The verifier
//! opens a bidirectional stream marked
//! [`STREAM_ATTEST`](crate::protocol::STREAM_ATTEST), names a fresh nonce
//! and the validators it wants, and the attester answers with a signature
//! for each one it hosts, made exactly as a bind's.
//!
//! ```text
//! Verifier                                                   Attester
//!     ── nonce (32B), [count][count × vid] ───────────────────────▶
//!     ◀── [count][count × (vid, sig)], finish ──────────────────────
//! ```
//!
//! The listener signs before the dialer has proved anything, so the
//! endpoint runs the exchange only for a dialer that has a turn at it
//! (see [`crate::bind_gate`]).

use std::collections::HashSet;
use std::sync::Arc;
use std::{fmt, io};

use arc_swap::ArcSwap;
use hyperscale_crypto::Verifier;
use hyperscale_network::ValidatorKeyMap;
use hyperscale_types::{
    ConsensusSignature, NetworkDefinition, Signer, VALIDATOR_BIND_NONCE_LEN, ValidatorBindMessage,
    ValidatorId, signed_bytes,
};
use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use rand::random;
use tracing::{error, info};

use crate::config::VersionInteroperabilityMode;
use crate::framing::{self, FrameError};
use crate::protocol::{STREAM_ATTEST, STREAM_BIND, local_version};

/// Per-vnode signing identity the host attests as. A multi-vnode host
/// supplies one entry per vnode; each contributes one `(validator_id,
/// signature)` pair to every bind exchange.
pub type LocalVnodeIdentity = (ValidatorId, Arc<dyn Signer>);

/// `(validator_id, signature)` attestations carried in one bind frame.
type Attestations = Vec<(ValidatorId, ConsensusSignature)>;

/// Maximum frame size for bind messages. Fits a fully populated attestation
/// list at the per-bind cap with margin for the compression wrapper.
const MAX_BIND_FRAME: usize = 64 * 1024;

/// Maximum number of attestations a peer may claim in one bind exchange.
/// Bounds frame size and decode work.
pub const MAX_VNODES_PER_BIND: usize = 256;

/// Length of one `(validator_id, signature)` attestation pair.
const PAIR_LEN: usize = 8 + 96;

/// Prefix of the version string each side states.
const VERSION_PREFIX: &str = "hyperscale/";

// ─── Wire format ────────────────────────────────────────────────────────

/// What a bind or a pull established: the validators the peer proved it
/// hosts, and those it claimed that the verifier's topology gives no key
/// yet.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Bound {
    /// Validators proved by a signature over this connection.
    pub validators: Vec<ValidatorId>,
    /// Validators claimed and not yet checkable.
    pub claimed: Vec<ValidatorId>,
}

/// Append one attestation list to `buf`: `[2-byte LE count][count × pair]`.
fn write_attestations(buf: &mut Vec<u8>, attestations: &[(ValidatorId, ConsensusSignature)]) {
    let count = u16::try_from(attestations.len()).expect("caller bounds attestations by u16::MAX");
    buf.extend_from_slice(&count.to_le_bytes());
    for (vid, sig) in attestations {
        buf.extend_from_slice(&vid.to_le_bytes());
        buf.extend_from_slice(sig.as_bytes());
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
        pairs.push((vid, ConsensusSignature::new(sig_bytes)));
        cursor += PAIR_LEN;
    }
    Some((pairs, &data[total..]))
}

/// Encode the listener's response:
/// `[2-byte LE count][count × (8-byte LE vid)(96-byte sig)][32-byte nonce]`.
fn encode_response(
    attestations: &[(ValidatorId, ConsensusSignature)],
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
    let nonce = rest.try_into().ok()?;
    Some((pairs, nonce))
}

/// Encode the dialer's final message:
/// `[2-byte LE count][count × (8-byte LE vid)(96-byte sig)]`.
fn encode_final(attestations: &[(ValidatorId, ConsensusSignature)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + attestations.len() * PAIR_LEN);
    write_attestations(&mut buf, attestations);
    buf
}

/// Decode the dialer's final message.
fn decode_final(data: &[u8]) -> Option<Attestations> {
    let (pairs, rest) = read_attestations(data)?;
    rest.is_empty().then_some(pairs)
}

/// The version a peer stated, if its statement is well formed.
fn parse_version(stated: &[u8]) -> Option<&str> {
    std::str::from_utf8(stated)
        .ok()?
        .strip_prefix(VERSION_PREFIX)
        .filter(|version| !version.is_empty())
}

// ─── Verification ───────────────────────────────────────────────────────

/// Errors during a bind exchange.
#[derive(Debug)]
pub enum BindError {
    UnknownValidator(ValidatorId),
    InvalidSignature(ValidatorId),
    InvalidMessage,
    IncompatibleVersion(String),
    StreamOpen(String),
    Io(io::Error),
    Frame(FrameError),
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownValidator(v) => write!(f, "unknown validator {}", v.inner()),
            Self::InvalidSignature(v) => {
                write!(f, "invalid signature for validator {}", v.inner())
            }
            Self::InvalidMessage => write!(f, "malformed bind message"),
            Self::IncompatibleVersion(version) => write!(f, "incompatible version {version}"),
            Self::StreamOpen(e) => write!(f, "stream open failed: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Frame(e) => write!(f, "frame error: {e}"),
        }
    }
}

/// Verify a bind signature: the signature over `("hyperscale-validator-bind-v1"
/// || endpoint_id || nonce)` must be valid for the claimed validator's
/// consensus key.
///
/// `nonce` must be the one *we* generated and sent to the remote: verifying
/// against a remote-supplied nonce defeats replay protection.
fn verify_bind(
    verifier: &dyn Verifier,
    network: &NetworkDefinition,
    endpoint: EndpointId,
    claimed_vid: ValidatorId,
    nonce: &[u8; VALIDATOR_BIND_NONCE_LEN],
    signature: &ConsensusSignature,
    keys: &ValidatorKeyMap,
) -> Result<(), BindError> {
    let pubkey = keys
        .get(&claimed_vid)
        .ok_or(BindError::UnknownValidator(claimed_vid))?;

    let message = signed_bytes(
        &ValidatorBindMessage {
            endpoint_id: *endpoint.as_bytes(),
            nonce: *nonce,
        },
        network,
    );
    if verifier.verify(pubkey, &message, signature) {
        Ok(())
    } else {
        Err(BindError::InvalidSignature(claimed_vid))
    }
}

/// Verify every `(vid, sig)` claim against the locally chosen nonce: a
/// claim whose validator `keys` holds must verify, and one it does not hold
/// is set aside as claimed. Only the verified ones are bound; nothing
/// downstream sees the rest as proven.
fn verify_all(
    verifier: &dyn Verifier,
    network: &NetworkDefinition,
    endpoint: EndpointId,
    nonce: &[u8; VALIDATOR_BIND_NONCE_LEN],
    attestations: &[(ValidatorId, ConsensusSignature)],
    keys: &ValidatorKeyMap,
) -> Result<Bound, BindError> {
    let mut bound = Bound::default();
    for (vid, sig) in attestations {
        if keys.contains_key(vid) {
            verify_bind(verifier, network, endpoint, *vid, nonce, sig, keys)?;
            bound.validators.push(*vid);
        } else {
            bound.claimed.push(*vid);
        }
    }
    Ok(bound)
}

/// [`verify_all`] for a bind, which has to prove at least one validator:
/// a connection standing for no validator the verifier knows binds nothing.
fn verify_bind_exchange(
    verifier: &dyn Verifier,
    network: &NetworkDefinition,
    endpoint: EndpointId,
    nonce: &[u8; VALIDATOR_BIND_NONCE_LEN],
    attestations: &[(ValidatorId, ConsensusSignature)],
    keys: &ValidatorKeyMap,
) -> Result<Bound, BindError> {
    let bound = verify_all(verifier, network, endpoint, nonce, attestations, keys)?;
    match bound.claimed.first() {
        Some(&unknown) if bound.validators.is_empty() => Err(BindError::UnknownValidator(unknown)),
        _ => Ok(bound),
    }
}

// ─── Context ────────────────────────────────────────────────────────────

/// Shared inputs for every bind exchange. Cheap to clone.
#[derive(Clone)]
pub struct BindContext {
    /// The network identity, bound into every signed bind message.
    pub(crate) network: NetworkDefinition,
    /// Per-vnode signing identities. Non-empty.
    pub(crate) local_vnodes: Arc<[LocalVnodeIdentity]>,
    /// Local endpoint id, signed over to bind it to every hosted vnode.
    pub(crate) local_endpoint: EndpointId,
    /// Validator consensus keys remote signatures are verified against.
    pub(crate) validator_keys: Arc<ArcSwap<ValidatorKeyMap>>,
    /// Scheme verifier every inbound attestation is checked against.
    pub(crate) verifier: Arc<dyn Verifier>,
    /// How strictly the peer's stated version must match ours.
    pub(crate) version_interop_mode: VersionInteroperabilityMode,
}

impl BindContext {
    /// Sign over `endpoint_id || remote_nonce` once per hosted vnode. A
    /// vnode whose signer cannot sign contributes no attestation; the
    /// exchange proceeds with the rest.
    fn sign_all(&self, remote_nonce: &[u8; VALIDATOR_BIND_NONCE_LEN]) -> Attestations {
        self.sign_where(remote_nonce, |_| true)
    }

    /// [`Self::sign_all`] for the hosted vnodes `wanted` selects.
    fn sign_where(
        &self,
        remote_nonce: &[u8; VALIDATOR_BIND_NONCE_LEN],
        wanted: impl Fn(ValidatorId) -> bool,
    ) -> Attestations {
        let message = signed_bytes(
            &ValidatorBindMessage {
                endpoint_id: *self.local_endpoint.as_bytes(),
                nonce: *remote_nonce,
            },
            &self.network,
        );
        self.local_vnodes
            .iter()
            .filter(|(vid, _)| wanted(*vid))
            .filter_map(|(vid, key)| match key.sign(&message) {
                Ok(sig) => Some((*vid, sig)),
                Err(err) => {
                    error!(
                        validator = vid.inner(),
                        ?err,
                        "cannot sign bind attestation"
                    );
                    None
                }
            })
            .collect()
    }

    /// Our version statement.
    fn version_statement() -> Vec<u8> {
        format!("{VERSION_PREFIX}{}", local_version()).into_bytes()
    }

    /// Check the version a peer stated against ours.
    fn check_version(&self, stated: &[u8]) -> Result<(), BindError> {
        let remote = parse_version(stated).ok_or(BindError::InvalidMessage)?;
        if self.version_interop_mode.check(local_version(), remote) {
            Ok(())
        } else {
            Err(BindError::IncompatibleVersion(remote.to_string()))
        }
    }

    fn verify(
        &self,
        remote: EndpointId,
        nonce: &[u8; VALIDATOR_BIND_NONCE_LEN],
        attestations: &Attestations,
    ) -> Result<Bound, BindError> {
        verify_bind_exchange(
            self.verifier.as_ref(),
            &self.network,
            remote,
            nonce,
            attestations,
            &self.validator_keys.load(),
        )
    }
}

async fn write(send: &mut SendStream, data: &[u8]) -> Result<(), BindError> {
    framing::write_frame(send, data)
        .await
        .map(drop)
        .map_err(BindError::Io)
}

async fn read(recv: &mut RecvStream) -> Result<Vec<u8>, BindError> {
    framing::read_frame(recv, MAX_BIND_FRAME)
        .await
        .map_err(BindError::Frame)
}

/// `bound`, its proven validators logged against their peer.
fn proven(remote: EndpointId, bound: Bound, side: &str) -> Bound {
    for vid in &bound.validators {
        info!(
            peer = %remote.fmt_short(),
            validator_id = vid.inner(),
            side,
            "Validator-bind verified"
        );
    }
    bound
}

/// Run the exchange as the side that dialed `connection`. Returns the
/// validators the peer proved it hosts and those it claimed unchecked.
///
/// # Errors
///
/// Returns [`BindError`] when the stream fails, the peer's version is
/// incompatible, any of its attestations does not verify, or it proves no
/// validator the topology holds.
pub async fn initiate(connection: &Connection, ctx: &BindContext) -> Result<Bound, BindError> {
    let remote = connection.remote_id();
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| BindError::StreamOpen(e.to_string()))?;
    send.write_all(&[STREAM_BIND])
        .await
        .map_err(|e| BindError::Io(io::Error::other(e)))?;

    let our_nonce: [u8; VALIDATOR_BIND_NONCE_LEN] = random();
    write(&mut send, &BindContext::version_statement()).await?;
    write(&mut send, &our_nonce).await?;

    ctx.check_version(&read(&mut recv).await?)?;
    let (remote_attestations, remote_nonce) =
        decode_response(&read(&mut recv).await?).ok_or(BindError::InvalidMessage)?;
    let bound = ctx.verify(remote, &our_nonce, &remote_attestations)?;

    write(&mut send, &encode_final(&ctx.sign_all(&remote_nonce))).await?;
    send.finish()
        .map_err(|e| BindError::Io(io::Error::other(e)))?;

    Ok(proven(remote, bound, "dialer"))
}

/// Run the exchange as the side that accepted `connection`. Returns the
/// validators the peer proved it hosts and those it claimed unchecked.
///
/// # Errors
///
/// Returns [`BindError`] when the peer's first stream is not a bind stream,
/// the stream fails, the peer's version is incompatible, any of its
/// attestations does not verify, or it proves no validator the topology
/// holds.
pub async fn respond(connection: &Connection, ctx: &BindContext) -> Result<Bound, BindError> {
    let remote = connection.remote_id();
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|e| BindError::StreamOpen(e.to_string()))?;
    let mut kind = [0u8; 1];
    recv.read_exact(&mut kind)
        .await
        .map_err(|e| BindError::Io(io::Error::other(e)))?;
    if kind[0] != STREAM_BIND {
        return Err(BindError::InvalidMessage);
    }

    ctx.check_version(&read(&mut recv).await?)?;
    let remote_nonce: [u8; VALIDATOR_BIND_NONCE_LEN] = read(&mut recv)
        .await?
        .try_into()
        .map_err(|_| BindError::InvalidMessage)?;

    let our_nonce: [u8; VALIDATOR_BIND_NONCE_LEN] = random();
    write(&mut send, &BindContext::version_statement()).await?;
    write(
        &mut send,
        &encode_response(&ctx.sign_all(&remote_nonce), &our_nonce),
    )
    .await?;

    let remote_attestations =
        decode_final(&read(&mut recv).await?).ok_or(BindError::InvalidMessage)?;
    let bound = ctx.verify(remote, &our_nonce, &remote_attestations)?;

    Ok(proven(remote, bound, "listener"))
}

/// Encode a pull's request: `[32-byte nonce][2-byte LE count][count × 8-byte
/// LE vid]`.
fn encode_pull(nonce: &[u8; VALIDATOR_BIND_NONCE_LEN], wanted: &[ValidatorId]) -> Vec<u8> {
    let count = u16::try_from(wanted.len()).expect("caller bounds a pull by MAX_VNODES_PER_BIND");
    let mut buf = Vec::with_capacity(VALIDATOR_BIND_NONCE_LEN + 2 + wanted.len() * 8);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&count.to_le_bytes());
    for vid in wanted {
        buf.extend_from_slice(&vid.to_le_bytes());
    }
    buf
}

/// Decode a pull's request. Rejects an empty or oversized list, a truncated
/// or overlong body, and a repeated id.
fn decode_pull(data: &[u8]) -> Option<([u8; VALIDATOR_BIND_NONCE_LEN], Vec<ValidatorId>)> {
    let nonce: [u8; VALIDATOR_BIND_NONCE_LEN] =
        data.get(..VALIDATOR_BIND_NONCE_LEN)?.try_into().ok()?;
    let rest = &data[VALIDATOR_BIND_NONCE_LEN..];
    let count = u16::from_le_bytes(rest.get(..2)?.try_into().ok()?) as usize;
    if count == 0 || count > MAX_VNODES_PER_BIND || rest.len() != 2 + count * 8 {
        return None;
    }
    let mut seen = HashSet::with_capacity(count);
    let mut wanted = Vec::with_capacity(count);
    for chunk in rest[2..].as_chunks::<8>().0 {
        let vid = ValidatorId::new(u64::from_le_bytes(*chunk));
        if !seen.insert(vid) {
            return None;
        }
        wanted.push(vid);
    }
    Some((nonce, wanted))
}

/// Encode a pull's answer: `[2-byte LE count][count × pair]`, empty when the
/// attester hosts none of what was asked.
fn encode_pull_answer(attestations: &[(ValidatorId, ConsensusSignature)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + attestations.len() * PAIR_LEN);
    write_attestations(&mut buf, attestations);
    buf
}

/// Decode a pull's answer.
fn decode_pull_answer(data: &[u8]) -> Option<Attestations> {
    if data == [0, 0] {
        return Some(Vec::new());
    }
    let (pairs, rest) = read_attestations(data)?;
    rest.is_empty().then_some(pairs)
}

/// Ask the peer at the far end of `connection` to prove it hosts `wanted`,
/// as the verifier. Returns the ones it proved, and any it answered for that
/// the verifier's topology still gives no key.
///
/// # Errors
///
/// Returns [`BindError`] when the stream fails or an answered signature
/// does not verify.
pub async fn pull(
    connection: &Connection,
    ctx: &BindContext,
    wanted: &[ValidatorId],
) -> Result<Bound, BindError> {
    let remote = connection.remote_id();
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| BindError::StreamOpen(e.to_string()))?;
    send.write_all(&[STREAM_ATTEST])
        .await
        .map_err(|e| BindError::Io(io::Error::other(e)))?;
    let nonce: [u8; VALIDATOR_BIND_NONCE_LEN] = random();
    write(&mut send, &encode_pull(&nonce, wanted)).await?;
    send.finish()
        .map_err(|e| BindError::Io(io::Error::other(e)))?;
    let answered = decode_pull_answer(&read(&mut recv).await?).ok_or(BindError::InvalidMessage)?;
    // Only what was asked counts: an answer naming anything else is not one.
    if answered.iter().any(|(vid, _)| !wanted.contains(vid)) {
        return Err(BindError::InvalidMessage);
    }
    let bound = verify_all(
        ctx.verifier.as_ref(),
        &ctx.network,
        remote,
        &nonce,
        &answered,
        &ctx.validator_keys.load(),
    )?;
    Ok(proven(remote, bound, "pull"))
}

/// Answer a pull read from `recv`, its stream kind already taken: sign for
/// each validator asked for that this host runs. Returns how many it signed
/// for.
///
/// # Errors
///
/// Returns [`BindError`] when the stream fails or the request is malformed.
pub async fn answer_pull(
    mut send: SendStream,
    mut recv: RecvStream,
    ctx: &BindContext,
) -> Result<usize, BindError> {
    let (nonce, wanted) = decode_pull(&read(&mut recv).await?).ok_or(BindError::InvalidMessage)?;
    let attestations = ctx.sign_where(&nonce, |vid| wanted.contains(&vid));
    write(&mut send, &encode_pull_answer(&attestations)).await?;
    send.finish()
        .map_err(|e| BindError::Io(io::Error::other(e)))?;
    Ok(attestations.len())
}

/// Open a bind exchange on `connection` as a dialer that proves nothing:
/// state a version and a nonce, read the listener's signatures, and stop.
/// Returns how many validators the listener signed for.
#[cfg(feature = "test-utils")]
pub async fn hello_only(connection: &Connection) -> Result<usize, BindError> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| BindError::StreamOpen(e.to_string()))?;
    send.write_all(&[STREAM_BIND])
        .await
        .map_err(|e| BindError::Io(io::Error::other(e)))?;
    let nonce: [u8; VALIDATOR_BIND_NONCE_LEN] = random();
    write(&mut send, &BindContext::version_statement()).await?;
    write(&mut send, &nonce).await?;
    let _version = read(&mut recv).await?;
    let (attestations, _) =
        decode_response(&read(&mut recv).await?).ok_or(BindError::InvalidMessage)?;
    Ok(attestations.len())
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_types::ConsensusPublicKey;
    use iroh::SecretKey;

    use super::*;

    fn endpoint(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn keys_for(vid: ValidatorId, pubkey: ConsensusPublicKey) -> ValidatorKeyMap {
        let mut keys = ValidatorKeyMap::new();
        keys.insert(vid, pubkey);
        keys
    }

    /// A distinct `(ValidatorId, sig)` pair for each `i`.
    fn pair_for(i: u64) -> (ValidatorId, ConsensusSignature) {
        let mut sig_bytes = [0u8; 96];
        sig_bytes[..8].copy_from_slice(&i.to_le_bytes());
        (ValidatorId::new(i), ConsensusSignature::new(sig_bytes))
    }

    fn signature(
        key: &BlsSigner,
        endpoint: EndpointId,
        nonce: [u8; VALIDATOR_BIND_NONCE_LEN],
    ) -> ConsensusSignature {
        key.sign(&signed_bytes(
            &ValidatorBindMessage {
                endpoint_id: *endpoint.as_bytes(),
                nonce,
            },
            &NetworkDefinition::simulator(),
        ))
        .expect("sign")
    }

    fn verify(
        endpoint: EndpointId,
        vid: ValidatorId,
        nonce: [u8; VALIDATOR_BIND_NONCE_LEN],
        sig: &ConsensusSignature,
        keys: &ValidatorKeyMap,
    ) -> Result<(), BindError> {
        verify_bind(
            &BlsVerifier,
            &NetworkDefinition::simulator(),
            endpoint,
            vid,
            &nonce,
            sig,
            keys,
        )
    }

    #[test]
    fn response_and_final_roundtrip_several_attestations() {
        let pairs = vec![pair_for(1), pair_for(42), pair_for(1000)];
        let nonce = [0xCD; VALIDATOR_BIND_NONCE_LEN];

        let (decoded, decoded_nonce) = decode_response(&encode_response(&pairs, &nonce)).unwrap();
        assert_eq!(decoded, pairs);
        assert_eq!(decoded_nonce, nonce);

        assert_eq!(decode_final(&encode_final(&pairs)).unwrap(), pairs);
    }

    #[test]
    fn decode_rejects_malformed_lists() {
        // Too short to hold the count prefix.
        assert!(decode_response(&[0u8; 1]).is_none());
        assert!(decode_final(&[0u8; 1]).is_none());
        // Count prefix says 1 but no pair bytes follow.
        assert!(decode_final(&1u16.to_le_bytes()).is_none());
        // Trailing bytes after the last pair.
        let mut trailing = encode_final(&[pair_for(3)]);
        trailing.push(0);
        assert!(decode_final(&trailing).is_none());
        // A response missing its trailing nonce.
        assert!(decode_response(&encode_final(&[pair_for(3)])).is_none());
        // An empty list.
        assert!(decode_final(&0u16.to_le_bytes()).is_none());
        // A list over the cap.
        let mut over = u16::try_from(MAX_VNODES_PER_BIND + 1)
            .unwrap()
            .to_le_bytes()
            .to_vec();
        over.resize(2 + (MAX_VNODES_PER_BIND + 1) * PAIR_LEN, 0);
        assert!(decode_final(&over).is_none());
        // The same validator twice.
        assert!(decode_final(&encode_final(&[pair_for(5), pair_for(5)])).is_none());
        // A body one byte short.
        let mut short = encode_final(&[pair_for(1), pair_for(2)]);
        short.pop();
        assert!(decode_final(&short).is_none());
    }

    /// A bind binds the validators the verifier knows and sets the rest
    /// aside: a known one with a bad signature refuses the whole exchange,
    /// and so does an exchange proving nothing the verifier knows.
    #[test]
    fn a_bind_binds_only_the_validators_its_verifier_knows() {
        let known_key = BlsSigner::generate();
        let unknown_key = BlsSigner::generate();
        let (known, unknown) = (ValidatorId::new(1), ValidatorId::new(2));
        let nonce = [7u8; VALIDATOR_BIND_NONCE_LEN];
        let keys = keys_for(known, known_key.public_key());
        let check = |attestations: &[(ValidatorId, ConsensusSignature)]| {
            verify_bind_exchange(
                &BlsVerifier,
                &NetworkDefinition::simulator(),
                endpoint(1),
                &nonce,
                attestations,
                &keys,
            )
        };
        let both = [
            (known, signature(&known_key, endpoint(1), nonce)),
            (unknown, signature(&unknown_key, endpoint(1), nonce)),
        ];
        assert_eq!(
            check(&both).unwrap(),
            Bound {
                validators: vec![known],
                claimed: vec![unknown],
            },
        );
        let forged = [
            (known, signature(&unknown_key, endpoint(1), nonce)),
            (unknown, signature(&unknown_key, endpoint(1), nonce)),
        ];
        assert!(matches!(check(&forged), Err(BindError::InvalidSignature(v)) if v == known));
        let strangers = [(unknown, signature(&unknown_key, endpoint(1), nonce))];
        assert!(matches!(check(&strangers), Err(BindError::UnknownValidator(v)) if v == unknown));
    }

    #[test]
    fn a_pull_and_its_answer_roundtrip() {
        let nonce = [3u8; VALIDATOR_BIND_NONCE_LEN];
        let wanted = vec![ValidatorId::new(4), ValidatorId::new(9)];
        assert_eq!(
            decode_pull(&encode_pull(&nonce, &wanted)),
            Some((nonce, wanted))
        );
        let pairs = vec![pair_for(4)];
        assert_eq!(decode_pull_answer(&encode_pull_answer(&pairs)), Some(pairs));
        assert_eq!(
            decode_pull_answer(&encode_pull_answer(&[])),
            Some(Vec::new())
        );
    }

    #[test]
    fn a_malformed_pull_is_refused() {
        let nonce = [3u8; VALIDATOR_BIND_NONCE_LEN];
        assert!(decode_pull(&encode_pull(&nonce, &[])).is_none());
        let repeated = [ValidatorId::new(4), ValidatorId::new(4)];
        assert!(decode_pull(&encode_pull(&nonce, &repeated)).is_none());
        let mut trailing = encode_pull(&nonce, &[ValidatorId::new(4)]);
        trailing.push(0);
        assert!(decode_pull(&trailing).is_none());
        assert!(decode_pull(&nonce).is_none());
    }

    #[test]
    fn a_version_statement_needs_the_prefix_and_a_version() {
        assert_eq!(parse_version(b"hyperscale/1.0.0"), Some("1.0.0"));
        assert_eq!(parse_version(b"hyperscale/localdev"), Some("localdev"));
        assert!(parse_version(b"hyperscale/").is_none());
        assert!(parse_version(b"other/1.0.0").is_none());
        assert!(parse_version(&[0xFF, 0xFE]).is_none());
    }

    #[test]
    fn a_signature_over_our_nonce_and_its_endpoint_verifies() {
        let key = BlsSigner::generate();
        let vid = ValidatorId::new(7);
        let nonce = [9u8; VALIDATOR_BIND_NONCE_LEN];
        let sig = signature(&key, endpoint(1), nonce);
        let keys = keys_for(vid, key.public_key());
        assert!(verify(endpoint(1), vid, nonce, &sig, &keys).is_ok());
    }

    #[test]
    fn a_signature_replayed_under_another_nonce_is_refused() {
        let key = BlsSigner::generate();
        let vid = ValidatorId::new(7);
        let sig = signature(&key, endpoint(1), [1u8; VALIDATOR_BIND_NONCE_LEN]);
        let keys = keys_for(vid, key.public_key());
        assert!(matches!(
            verify(
                endpoint(1),
                vid,
                [2u8; VALIDATOR_BIND_NONCE_LEN],
                &sig,
                &keys
            ),
            Err(BindError::InvalidSignature(_))
        ));
    }

    #[test]
    fn a_signature_for_another_endpoint_is_refused() {
        let key = BlsSigner::generate();
        let vid = ValidatorId::new(7);
        let nonce = [3u8; VALIDATOR_BIND_NONCE_LEN];
        let sig = signature(&key, endpoint(1), nonce);
        let keys = keys_for(vid, key.public_key());
        assert!(verify(endpoint(2), vid, nonce, &sig, &keys).is_err());
    }

    #[test]
    fn an_unknown_validator_and_a_wrong_key_are_refused() {
        let key = BlsSigner::generate();
        let other = BlsSigner::generate();
        let nonce = [4u8; VALIDATOR_BIND_NONCE_LEN];
        let sig = signature(&key, endpoint(1), nonce);

        let keys = keys_for(ValidatorId::new(7), key.public_key());
        assert!(matches!(
            verify(endpoint(1), ValidatorId::new(99), nonce, &sig, &keys),
            Err(BindError::UnknownValidator(_))
        ));

        let keys = keys_for(ValidatorId::new(7), other.public_key());
        assert!(matches!(
            verify(endpoint(1), ValidatorId::new(7), nonce, &sig, &keys),
            Err(BindError::InvalidSignature(_))
        ));
    }

    #[test]
    fn one_bad_attestation_rejects_the_whole_list() {
        let key = BlsSigner::generate();
        let nonce = [4u8; VALIDATOR_BIND_NONCE_LEN];
        let good = ValidatorId::new(1);
        let bad = ValidatorId::new(2);
        let mut keys = keys_for(good, key.public_key());
        keys.insert(bad, key.public_key());

        let attestations = vec![
            (good, signature(&key, endpoint(1), nonce)),
            (bad, ConsensusSignature::ZERO),
        ];
        assert!(matches!(
            verify_all(
                &BlsVerifier,
                &NetworkDefinition::simulator(),
                endpoint(1),
                &nonce,
                &attestations,
                &keys
            ),
            Err(BindError::InvalidSignature(_))
        ));
    }
}
