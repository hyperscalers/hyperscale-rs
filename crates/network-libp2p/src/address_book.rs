//! Signed validator address book.
//!
//! Caches the `ValidatorId → (PeerId, addresses)` records validators gossip
//! about themselves ([`ValidatorAddressGossip`]), so this node can dial a
//! committee-relevant validator it has never connected to. The unicast
//! rails (provisions, execution certificates) resolve recipients through
//! live validator-bind entries, which only exist over an established
//! connection — the book supplies the missing `ValidatorId → address` step
//! for cold links, with the Identify → validator-bind path taking over once
//! the dialed connection lands.
//!
//! Records are self-signed: only the named validator's BLS key can produce
//! one, so a book entry is exactly as trustworthy as the bind handshake's
//! attestation. A replayed stale record can only point a dial at an address
//! the validator once announced; the per-validator sequence keeps the
//! newest record and the next announce supersedes stragglers everywhere.

use std::collections::HashSet;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use hyperscale_network::ValidatorKeyMap;
use hyperscale_types::network::gossip::{
    MAX_ANNOUNCED_ADDRESS_BYTES, MAX_ANNOUNCED_ADDRESSES, MAX_ANNOUNCED_PEER_ID_BYTES,
    ValidatorAddressGossip,
};
use hyperscale_types::{NetworkDefinition, Signed, SignedContext, ValidatorId};
use libp2p::{Multiaddr, PeerId as Libp2pPeerId};

/// One validator's newest verified announcement.
#[derive(Debug, Clone)]
pub struct AddressRecord {
    /// libp2p peer id the validator binds as.
    pub peer_id: Libp2pPeerId,
    /// Dialable multiaddrs, parsed and non-empty.
    pub addresses: Vec<Multiaddr>,
    /// Announce sequence of this record; higher supersedes.
    pub sequence: u64,
}

/// Outcome of ingesting one announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// Verified and stored — a new validator or a newer sequence.
    Recorded,
    /// Verified but not newer than the stored record.
    Stale,
    /// The claimed validator has no key in the current topology; the local
    /// beacon may simply lag the announcer's.
    UnknownValidator,
    /// Over caps, unparseable peer id / addresses, or a bad signature.
    Invalid,
}

/// Concurrent `ValidatorId → AddressRecord` map. Shared between the gossip
/// ingest path, the swarm event loop, and the seating-triggered dial pass.
#[derive(Default)]
pub struct AddressBook {
    records: DashMap<ValidatorId, AddressRecord>,
}

impl AddressBook {
    /// Verify one gossiped announcement and store it if it is the newest
    /// for its validator. Caps are enforced before the signature check so
    /// oversized spam never reaches BLS verification.
    #[must_use]
    pub fn ingest(
        &self,
        network: &NetworkDefinition,
        keys: &ValidatorKeyMap,
        gossip: &ValidatorAddressGossip,
    ) -> IngestOutcome {
        if gossip.peer_id.len() > MAX_ANNOUNCED_PEER_ID_BYTES
            || gossip.addresses.is_empty()
            || gossip.addresses.len() > MAX_ANNOUNCED_ADDRESSES
            || gossip
                .addresses
                .iter()
                .any(|a| a.len() > MAX_ANNOUNCED_ADDRESS_BYTES)
        {
            return IngestOutcome::Invalid;
        }

        let Some(public_key) = keys.get(&gossip.validator) else {
            return IngestOutcome::UnknownValidator;
        };
        let ctx = SignedContext {
            network,
            public_key,
        };
        if gossip.verify_signature(&ctx).is_err() {
            return IngestOutcome::Invalid;
        }

        let Ok(peer_id) = Libp2pPeerId::from_bytes(&gossip.peer_id) else {
            return IngestOutcome::Invalid;
        };
        let addresses: Vec<Multiaddr> = gossip
            .addresses
            .iter()
            .filter_map(|bytes| Multiaddr::try_from(bytes.clone()).ok())
            .collect();
        if addresses.is_empty() {
            return IngestOutcome::Invalid;
        }

        let record = AddressRecord {
            peer_id,
            addresses,
            sequence: gossip.sequence,
        };
        match self.records.entry(gossip.validator) {
            Entry::Occupied(mut occupied) => {
                if gossip.sequence <= occupied.get().sequence {
                    return IngestOutcome::Stale;
                }
                occupied.insert(record);
                IngestOutcome::Recorded
            }
            Entry::Vacant(vacant) => {
                vacant.insert(record);
                IngestOutcome::Recorded
            }
        }
    }

    /// The newest verified record for `validator`, if any.
    #[must_use]
    pub fn get(&self, validator: ValidatorId) -> Option<AddressRecord> {
        self.records.get(&validator).map(|r| r.clone())
    }

    /// Records to dial so every validator in `wanted` becomes reachable:
    /// the wanted validators with no live bind entry in `bound` whose
    /// address is known, deduplicated by peer id (a multi-vnode host
    /// announces the same peer for each of its validators). A validator
    /// that is wanted, unbound, and absent from the book resolves nothing —
    /// the caller retries once its announcement arrives.
    #[must_use]
    pub fn dial_candidates(
        &self,
        wanted: &HashSet<ValidatorId>,
        bound: &DashMap<ValidatorId, Libp2pPeerId>,
    ) -> Vec<AddressRecord> {
        let mut seen_peers: HashSet<Libp2pPeerId> = HashSet::new();
        let mut candidates = Vec::new();
        for &validator in wanted {
            if bound.contains_key(&validator) {
                continue;
            }
            let Some(record) = self.get(validator) else {
                continue;
            };
            if seen_peers.insert(record.peer_id) {
                candidates.push(record);
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
    use hyperscale_types::{
        Bls12381G1PrivateKey, bls_keypair_from_seed, validator_address_message,
    };

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn keypair() -> Bls12381G1PrivateKey {
        bls_keypair_from_seed(&[9u8; 32])
    }

    fn announce(vid: ValidatorId, peer_id: &Libp2pPeerId, sequence: u64) -> ValidatorAddressGossip {
        let peer_bytes = peer_id.to_bytes();
        let addresses = vec![
            "/ip4/127.0.0.1/udp/4001/quic-v1"
                .parse::<Multiaddr>()
                .unwrap()
                .to_vec(),
        ];
        let signature = keypair().sign_v1(&validator_address_message(
            &net(),
            &peer_bytes,
            &addresses,
            sequence,
        ));
        ValidatorAddressGossip {
            validator: vid,
            peer_id: peer_bytes,
            addresses,
            sequence,
            signature,
        }
    }

    fn keys_for(vid: ValidatorId) -> ValidatorKeyMap {
        let mut keys = ValidatorKeyMap::new();
        keys.insert(vid, keypair().public_key());
        keys
    }

    #[test]
    fn records_verified_announcement_and_keeps_newest() {
        let book = AddressBook::default();
        let vid = ValidatorId::new(4);
        let keys = keys_for(vid);
        let peer = Libp2pPeerId::random();

        assert_eq!(
            book.ingest(&net(), &keys, &announce(vid, &peer, 5)),
            IngestOutcome::Recorded
        );
        assert_eq!(
            book.ingest(&net(), &keys, &announce(vid, &peer, 5)),
            IngestOutcome::Stale
        );
        assert_eq!(
            book.ingest(&net(), &keys, &announce(vid, &peer, 4)),
            IngestOutcome::Stale
        );

        let newer_peer = Libp2pPeerId::random();
        assert_eq!(
            book.ingest(&net(), &keys, &announce(vid, &newer_peer, 6)),
            IngestOutcome::Recorded
        );
        let record = book.get(vid).unwrap();
        assert_eq!(record.peer_id, newer_peer);
        assert_eq!(record.sequence, 6);
        assert!(!record.addresses.is_empty());
    }

    #[test]
    fn rejects_bad_signature_and_unknown_validator() {
        let book = AddressBook::default();
        let vid = ValidatorId::new(4);
        let keys = keys_for(vid);
        let peer = Libp2pPeerId::random();

        let mut tampered = announce(vid, &peer, 1);
        tampered.sequence = 2;
        assert_eq!(
            book.ingest(&net(), &keys, &tampered),
            IngestOutcome::Invalid
        );

        let unknown = announce(ValidatorId::new(99), &peer, 1);
        assert_eq!(
            book.ingest(&net(), &keys, &unknown),
            IngestOutcome::UnknownValidator
        );
        assert!(book.is_empty());
    }

    #[test]
    fn dial_candidates_skip_bound_and_dedup_by_peer() {
        let book = AddressBook::default();
        let bound_vid = ValidatorId::new(1);
        let cohost_a = ValidatorId::new(2);
        let cohost_b = ValidatorId::new(3);
        let unknown_vid = ValidatorId::new(4);
        let keys = {
            let mut keys = ValidatorKeyMap::new();
            for vid in [bound_vid, cohost_a, cohost_b] {
                keys.insert(vid, keypair().public_key());
            }
            keys
        };

        let bound_peer = Libp2pPeerId::random();
        let cohost_peer = Libp2pPeerId::random();
        for (vid, peer) in [
            (bound_vid, &bound_peer),
            (cohost_a, &cohost_peer),
            (cohost_b, &cohost_peer),
        ] {
            assert_eq!(
                book.ingest(&net(), &keys, &announce(vid, peer, 1)),
                IngestOutcome::Recorded
            );
        }

        let bound = DashMap::new();
        bound.insert(bound_vid, bound_peer);
        let wanted: HashSet<ValidatorId> = [bound_vid, cohost_a, cohost_b, unknown_vid]
            .into_iter()
            .collect();

        // The bound validator needs no dial, the co-hosted pair collapses
        // to one peer, and the validator with no record resolves nothing.
        let candidates = book.dial_candidates(&wanted, &bound);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].peer_id, cohost_peer);
    }

    #[test]
    fn rejects_over_cap_and_malformed_content() {
        let book = AddressBook::default();
        let vid = ValidatorId::new(4);
        let keys = keys_for(vid);
        let peer = Libp2pPeerId::random();

        let mut oversized = announce(vid, &peer, 1);
        oversized.addresses = vec![vec![0u8; MAX_ANNOUNCED_ADDRESS_BYTES + 1]];
        assert_eq!(
            book.ingest(&net(), &keys, &oversized),
            IngestOutcome::Invalid
        );

        // A signed record whose peer id bytes don't parse is invalid even
        // though the signature verifies.
        let bogus_peer_bytes = vec![1u8, 2, 3];
        let addresses = vec![
            "/ip4/127.0.0.1/udp/4001/quic-v1"
                .parse::<Multiaddr>()
                .unwrap()
                .to_vec(),
        ];
        let signature = keypair().sign_v1(&validator_address_message(
            &net(),
            &bogus_peer_bytes,
            &addresses,
            3,
        ));
        let unparseable = ValidatorAddressGossip {
            validator: vid,
            peer_id: bogus_peer_bytes,
            addresses,
            sequence: 3,
            signature,
        };
        assert_eq!(
            book.ingest(&net(), &keys, &unparseable),
            IngestOutcome::Invalid
        );
    }
}
