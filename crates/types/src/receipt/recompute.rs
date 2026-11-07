//! A receipt's hash recomputed from what it carries.

use blake3::hash;
use hyperscale_hbor::to_vec as hbor_to_vec;

use crate::receipt::event::EventExt;
use crate::{
    BeaconWitnessEvent, BeaconWitnessRoot, ConsensusReceipt, EffectsDigest, EventRoot,
    GlobalReceipt, GlobalReceiptHash, Hash, StateWrites, WritesRoot, compute_merkle_root,
};

/// Domain tag separating a receipt's beacon-fact leaf from every other
/// leaf preimage the codebase hashes.
const RECEIPT_WITNESS_LEAF_TAG: &[u8] = b"hyperscale.receipt_witness_leaf.v1";

/// Domain tag separating an effects digest from every other preimage
/// the codebase hashes.
const EFFECTS_DIGEST_TAG: &[u8] = b"hyperscale.effects_digest.v1";

/// The digest of a whole run: `whole` is its delta projected over every
/// owner, the fee burn apart, and `events` the root of all its events in
/// emission order, whoever emitted them.
///
/// What a shared member's shards compare, so it reads no term any one
/// shard's slice of the run would decide.
#[must_use]
pub fn effects_digest(whole: &StateWrites, events: EventRoot) -> EffectsDigest {
    EffectsDigest::from_raw(Hash::from_parts(&[
        EFFECTS_DIGEST_TAG,
        writes_root(whole).as_raw().as_bytes(),
        events.as_raw().as_bytes(),
    ]))
}

/// The `writes_root` for a [`GlobalReceipt`] over the writes the
/// executing shard attests — the shard-projected delta for a batch with
/// cross-shard members, the full fold for a whole-locality batch.
///
/// [`StateWrites`] encodes in canonical key order by construction, so the
/// root is the protocol hash of the encoding — a pure function of content
/// with no sort step. Empty writes commit to [`WritesRoot::ZERO`].
#[must_use]
pub fn writes_root(writes: &StateWrites) -> WritesRoot {
    if writes.is_empty() {
        return WritesRoot::ZERO;
    }
    WritesRoot::from_raw(Hash::from(writes.root(|data| *hash(data).as_bytes())))
}

/// The witness root for a [`GlobalReceipt`] over the beacon facts a
/// receipt carries, in the order it carries them.
///
/// One leaf per fact, the tag and the fact's canonical encoding. No
/// facts commit to [`BeaconWitnessRoot::ZERO`].
///
/// A receipt's own commitment, and nothing a header states: a block's
/// witness root is taken over the shard's whole window, under another
/// leaf.
///
/// # Panics
///
/// If a fact does not encode, which a closed wire type always does.
pub fn witness_root<'a>(
    facts: impl IntoIterator<Item = &'a BeaconWitnessEvent>,
) -> BeaconWitnessRoot {
    let leaves: Vec<Hash> = facts
        .into_iter()
        .map(|fact| {
            let bytes = hbor_to_vec(fact).expect("a beacon fact encodes");
            Hash::from_parts(&[RECEIPT_WITNESS_LEAF_TAG, &bytes])
        })
        .collect();
    BeaconWitnessRoot::from_raw(compute_merkle_root(&leaves))
}

/// A receipt's hash, recomputed from what the receipt carries.
///
/// `projected` is whether the batch that produced the receipt hashed
/// under this shard's own locality, which a batch with a member reaching
/// beyond the shard does and which the receipt does not record. Its
/// writes, events and beacon facts are then exactly what the three roots
/// were taken over, and its digest is the fourth term as it stands, so
/// the answer is the hash a quorum signed for an honest receipt and some
/// other hash for one altered since.
///
/// `None` for a success hashed under whole locality: its writes root can
/// cover more than the slice the receipt holds. Every failure is the one
/// canonical hash, whatever it ran under.
#[must_use]
pub fn receipt_hash_of(receipt: &ConsensusReceipt, projected: bool) -> Option<GlobalReceiptHash> {
    let ConsensusReceipt::Succeeded {
        writes,
        beacon_witness_events,
        events,
        effects,
        ..
    } = receipt
    else {
        return Some(receipt.receipt_hash());
    };
    projected.then(|| {
        let event_hashes: Vec<Hash> = events.iter().map(EventExt::hash).collect();
        GlobalReceipt::new(
            true,
            EventRoot::from_raw(compute_merkle_root(&event_hashes)),
            witness_root(beacon_witness_events.iter()),
            writes_root(writes),
            effects.unwrap_or(EffectsDigest::ZERO),
        )
        .receipt_hash()
    })
}
