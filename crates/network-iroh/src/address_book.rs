//! Signed validator address book.
//!
//! Caches the `ValidatorId → (EndpointId, relays, addresses)` records
//! validators gossip about themselves ([`ValidatorAddressGossip`]), so this
//! host can dial a committee-relevant validator it has never connected to.
//! Unicast resolves recipients through live validator-bind entries, which
//! exist only over an established connection; the book supplies the missing
//! `ValidatorId → address` step for cold links.
//!
//! Records are self-signed: only the named validator's consensus key can
//! produce one, so a book entry is exactly as trustworthy as the bind
//! handshake's attestation. A replayed stale record can only point a dial at
//! an address the validator once announced; the per-validator sequence keeps
//! the newest record and the next announce supersedes stragglers everywhere.
//!
//! # Record bytes
//!
//! The record type carries its peer id and addresses as opaque bytes. Here
//! the peer id is the 32-byte endpoint id, and each address is one tag byte
//! followed by text: [`TAG_RELAY`] and a relay URL, or [`TAG_SOCKET`] and a
//! socket address.

use std::collections::{BTreeSet, HashSet};
use std::net::SocketAddr;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use hyperscale_crypto::Verifier;
use hyperscale_hbor::Bytes;
use hyperscale_network::ValidatorKeyMap;
use hyperscale_types::network::gossip::{AnnouncedAddresses, ValidatorAddressGossip};
use hyperscale_types::{
    NetworkDefinition, Signed, SignedContext, ValidatorAddressMessage, ValidatorId, signed_bytes,
};
use iroh::{EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use tracing::error;

use crate::bind::LocalVnodeIdentity;
use crate::config::MAX_RELAYS;

/// Tag of an address that names a relay by URL.
const TAG_RELAY: u8 = 0;

/// Tag of an address that names a socket.
const TAG_SOCKET: u8 = 1;

/// One validator's newest verified announcement.
#[derive(Debug, Clone)]
pub struct AddressRecord {
    /// The endpoint the validator binds as, with every way to reach it the
    /// record named.
    pub(crate) endpoint: EndpointAddr,
    /// Announce sequence of this record; higher supersedes.
    pub(crate) sequence: u64,
}

/// Outcome of ingesting one announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// Verified and stored: a new validator or a newer sequence.
    Recorded,
    /// Verified but not newer than the stored record.
    Stale,
    /// The claimed validator has no key in the current topology; the local
    /// beacon may simply lag the announcer's.
    UnknownValidator,
    /// An unparseable endpoint id, no usable address, or a bad signature.
    Invalid,
}

fn encode_address(addr: &TransportAddr) -> Option<Vec<u8>> {
    let (tag, text) = match addr {
        TransportAddr::Relay(url) => (TAG_RELAY, url.to_string()),
        TransportAddr::Ip(socket) => (TAG_SOCKET, socket.to_string()),
        _ => return None,
    };
    let mut bytes = Vec::with_capacity(1 + text.len());
    bytes.push(tag);
    bytes.extend_from_slice(text.as_bytes());
    Some(bytes)
}

fn decode_address(bytes: &[u8]) -> Option<TransportAddr> {
    let (tag, text) = bytes.split_first()?;
    let text = std::str::from_utf8(text).ok()?;
    match *tag {
        TAG_RELAY => text.parse::<RelayUrl>().ok().map(TransportAddr::Relay),
        TAG_SOCKET => text.parse::<SocketAddr>().ok().map(TransportAddr::Ip),
        _ => None,
    }
}

/// The addresses of `endpoint` a record carries: at most [`MAX_RELAYS`]
/// relays, then as many sockets as the record's caps admit. An address past
/// a cap is one no receiver would admit, so it is left out.
fn announced_addresses(endpoint: &EndpointAddr) -> AnnouncedAddresses {
    let relays = endpoint
        .relay_urls()
        .take(MAX_RELAYS)
        .cloned()
        .map(TransportAddr::Relay);
    let sockets = endpoint.ip_addrs().copied().map(TransportAddr::Ip);

    let mut announced = AnnouncedAddresses::empty();
    for addr in relays.chain(sockets) {
        let Some(Ok(bytes)) = encode_address(&addr).map(Bytes::new) else {
            continue;
        };
        if announced.push(bytes).is_err() {
            break;
        }
    }
    announced
}

/// One signed address record per hosted vnode, naming `endpoint` at
/// `sequence`. Empty when `endpoint` has no address a record can carry. A
/// vnode whose signer cannot sign contributes no record.
#[must_use]
pub fn sign_records(
    endpoint: &EndpointAddr,
    sequence: u64,
    network: &NetworkDefinition,
    vnodes: &[LocalVnodeIdentity],
) -> Vec<ValidatorAddressGossip> {
    let addresses = announced_addresses(endpoint);
    if addresses.is_empty() {
        return Vec::new();
    }
    let peer_id = Bytes::from_array(*endpoint.id.as_bytes());
    let message = signed_bytes(
        &ValidatorAddressMessage::new(&peer_id, &addresses, sequence),
        network,
    );
    vnodes
        .iter()
        .filter_map(|(validator, key)| match key.sign(&message) {
            Ok(signature) => Some(ValidatorAddressGossip {
                validator: *validator,
                peer_id: peer_id.clone(),
                addresses: addresses.clone(),
                sequence,
                signature,
            }),
            Err(err) => {
                error!(
                    validator = validator.inner(),
                    ?err,
                    "cannot sign validator address announcement"
                );
                None
            }
        })
        .collect()
}

/// Concurrent `ValidatorId → AddressRecord` map. Shared between the gossip
/// ingest path and the dial passes.
#[derive(Default)]
pub struct AddressBook {
    records: DashMap<ValidatorId, AddressRecord>,
}

impl AddressBook {
    /// Verify one gossiped announcement and store it if it is the newest
    /// for its validator, returning the stored record's endpoint.
    pub(crate) fn ingest(
        &self,
        verifier: &dyn Verifier,
        network: &NetworkDefinition,
        keys: &ValidatorKeyMap,
        gossip: &ValidatorAddressGossip,
    ) -> (IngestOutcome, Option<EndpointAddr>) {
        if gossip.addresses.is_empty() {
            return (IngestOutcome::Invalid, None);
        }

        let Some(public_key) = keys.get(&gossip.validator) else {
            return (IngestOutcome::UnknownValidator, None);
        };
        let ctx = SignedContext {
            verifier,
            network,
            public_key,
        };
        if gossip.verify_signature(&ctx).is_err() {
            return (IngestOutcome::Invalid, None);
        }

        let Ok(id) = EndpointId::try_from(&gossip.peer_id[..]) else {
            return (IngestOutcome::Invalid, None);
        };
        let mut relays = 0;
        let addrs: Vec<TransportAddr> = gossip
            .addresses
            .iter()
            .filter_map(|bytes| decode_address(bytes))
            .filter(|addr| {
                if addr.is_relay() {
                    relays += 1;
                    relays <= MAX_RELAYS
                } else {
                    true
                }
            })
            .collect();
        if addrs.is_empty() {
            return (IngestOutcome::Invalid, None);
        }

        let endpoint = EndpointAddr::from_parts(id, addrs);
        let record = AddressRecord {
            endpoint: endpoint.clone(),
            sequence: gossip.sequence,
        };
        match self.records.entry(gossip.validator) {
            Entry::Occupied(mut occupied) => {
                if gossip.sequence <= occupied.get().sequence {
                    return (IngestOutcome::Stale, None);
                }
                occupied.insert(record);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(record);
            }
        }
        (IngestOutcome::Recorded, Some(endpoint))
    }

    /// The newest verified record for `validator`, if any.
    #[must_use]
    pub(crate) fn get(&self, validator: ValidatorId) -> Option<AddressRecord> {
        self.records.get(&validator).map(|r| r.clone())
    }

    /// Endpoints to dial so every validator in `wanted` becomes reachable:
    /// the wanted validators with no live bind entry in `bound` whose
    /// address is known, deduplicated by endpoint (a multi-vnode host
    /// announces the same endpoint for each of its validators). A validator
    /// that is wanted, unbound, and absent from the book resolves nothing;
    /// the caller retries once its announcement arrives.
    #[must_use]
    pub(crate) fn dial_candidates(
        &self,
        wanted: &BTreeSet<ValidatorId>,
        bound: &DashMap<ValidatorId, EndpointId>,
    ) -> Vec<EndpointAddr> {
        let mut seen: HashSet<EndpointId> = HashSet::new();
        let mut candidates = Vec::new();
        for &validator in wanted {
            if bound.contains_key(&validator) {
                continue;
            }
            let Some(record) = self.get(validator) else {
                continue;
            };
            if seen.insert(record.endpoint.id) {
                candidates.push(record.endpoint);
            }
        }
        candidates
    }

    /// Number of validators with a record.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the book holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_types::Signer;
    use iroh::SecretKey;

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn keypair() -> Arc<BlsSigner> {
        Arc::new(BlsSigner::from_seed(&[9u8; 32]))
    }

    fn endpoint(seed: u8) -> EndpointAddr {
        EndpointAddr::new(SecretKey::from_bytes(&[seed; 32]).public())
            .with_relay_url("https://relay.example".parse().unwrap())
            .with_ip_addr("127.0.0.1:4001".parse().unwrap())
    }

    fn announce(
        vid: ValidatorId,
        endpoint: &EndpointAddr,
        sequence: u64,
    ) -> ValidatorAddressGossip {
        let signer: Arc<dyn Signer> = keypair();
        sign_records(endpoint, sequence, &net(), &[(vid, signer)])
            .pop()
            .expect("one record per vnode")
    }

    fn keys_for(vids: &[ValidatorId]) -> ValidatorKeyMap {
        vids.iter()
            .map(|vid| (*vid, keypair().public_key()))
            .collect()
    }

    fn ingest(
        book: &AddressBook,
        keys: &ValidatorKeyMap,
        gossip: &ValidatorAddressGossip,
    ) -> IngestOutcome {
        book.ingest(&BlsVerifier, &net(), keys, gossip).0
    }

    #[test]
    fn a_record_carries_its_relay_and_socket_back_out() {
        let book = AddressBook::default();
        let vid = ValidatorId::new(4);
        let keys = keys_for(&[vid]);
        let announced = endpoint(1);

        assert_eq!(
            ingest(&book, &keys, &announce(vid, &announced, 5)),
            IngestOutcome::Recorded
        );
        let record = book.get(vid).unwrap();
        assert_eq!(record.endpoint, announced);
        assert_eq!(record.sequence, 5);
    }

    #[test]
    fn keeps_the_newest_record_per_validator() {
        let book = AddressBook::default();
        let vid = ValidatorId::new(4);
        let keys = keys_for(&[vid]);

        assert_eq!(
            ingest(&book, &keys, &announce(vid, &endpoint(1), 5)),
            IngestOutcome::Recorded
        );
        assert_eq!(
            ingest(&book, &keys, &announce(vid, &endpoint(1), 5)),
            IngestOutcome::Stale
        );
        assert_eq!(
            ingest(&book, &keys, &announce(vid, &endpoint(1), 4)),
            IngestOutcome::Stale
        );
        assert_eq!(
            ingest(&book, &keys, &announce(vid, &endpoint(2), 6)),
            IngestOutcome::Recorded
        );
        assert_eq!(book.get(vid).unwrap().endpoint.id, endpoint(2).id);
    }

    #[test]
    fn rejects_a_bad_signature_and_an_unknown_validator() {
        let book = AddressBook::default();
        let vid = ValidatorId::new(4);
        let keys = keys_for(&[vid]);

        let mut tampered = announce(vid, &endpoint(1), 1);
        tampered.sequence = 2;
        assert_eq!(ingest(&book, &keys, &tampered), IngestOutcome::Invalid);

        let unknown = announce(ValidatorId::new(99), &endpoint(1), 1);
        assert_eq!(
            ingest(&book, &keys, &unknown),
            IngestOutcome::UnknownValidator
        );
        assert!(book.is_empty());
    }

    #[test]
    fn rejects_signed_content_that_names_no_endpoint() {
        let book = AddressBook::default();
        let vid = ValidatorId::new(4);
        let keys = keys_for(&[vid]);

        // Three bytes are not an endpoint id, though the signature verifies.
        let bogus_id = Bytes::from_array([1u8, 2, 3]);
        let addresses = announced_addresses(&endpoint(1));
        let signature = keypair()
            .sign(&signed_bytes(
                &ValidatorAddressMessage::new(&bogus_id, &addresses, 3),
                &net(),
            ))
            .expect("sign");
        let unparseable = ValidatorAddressGossip {
            validator: vid,
            peer_id: bogus_id,
            addresses,
            sequence: 3,
            signature,
        };
        assert_eq!(ingest(&book, &keys, &unparseable), IngestOutcome::Invalid);
    }

    #[test]
    fn a_record_admits_two_relays_and_no_more() {
        let three_relays = EndpointAddr::new(endpoint(1).id)
            .with_relay_url("https://a.example".parse().unwrap())
            .with_relay_url("https://b.example".parse().unwrap())
            .with_relay_url("https://c.example".parse().unwrap());
        let announced = announced_addresses(&three_relays);
        assert_eq!(announced.len(), MAX_RELAYS);
    }

    #[test]
    fn an_endpoint_with_no_address_signs_no_record() {
        let signer: Arc<dyn Signer> = keypair();
        let bare = EndpointAddr::new(endpoint(1).id);
        assert!(sign_records(&bare, 1, &net(), &[(ValidatorId::new(1), signer)]).is_empty());
    }

    #[test]
    fn dial_candidates_skip_bound_and_dedup_by_endpoint() {
        let book = AddressBook::default();
        let bound_vid = ValidatorId::new(1);
        let cohost_a = ValidatorId::new(2);
        let cohost_b = ValidatorId::new(3);
        let unknown_vid = ValidatorId::new(4);
        let keys = keys_for(&[bound_vid, cohost_a, cohost_b]);

        for (vid, seed) in [(bound_vid, 1), (cohost_a, 2), (cohost_b, 2)] {
            assert_eq!(
                ingest(&book, &keys, &announce(vid, &endpoint(seed), 1)),
                IngestOutcome::Recorded
            );
        }

        let bound = DashMap::new();
        bound.insert(bound_vid, endpoint(1).id);
        let wanted: BTreeSet<ValidatorId> = [bound_vid, cohost_a, cohost_b, unknown_vid]
            .into_iter()
            .collect();

        // The bound validator needs no dial, the co-hosted pair collapses
        // to one endpoint, and the validator with no record resolves
        // nothing.
        let candidates = book.dial_candidates(&wanted, &bound);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id, endpoint(2).id);
    }
}
