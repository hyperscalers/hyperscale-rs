//! The push of the crossing changes a block made, as self-proving claims
//! at the block's own anchor, to the shards that read them.
//!
//! One push per target shard per block. A record the block wrote goes
//! to its consumer as a held reading, an answer it wrote to its
//! record's producer as a presence, and a record it removed to its
//! consumer as the absence the block itself wrote. A push never carries
//! a reading at another anchor, so it can be delayed or withheld and
//! never forged.

use std::collections::{BTreeMap, HashMap};

use hyperscale_core::ActionContext;
use hyperscale_hbor::{Bytes, Capped};
use hyperscale_jmt::TreeReader as JmtTreeReader;
use hyperscale_network::Network;
use hyperscale_storage::tree::proofs::generate_proof;
use hyperscale_storage::{ShardStorage, SubstateStore, SubstateView, VersionedStore};
use hyperscale_types::network::notification::CrossingReadingsNotification;
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    Anchor, Block, BlockHash, BlockHeight, CrossingReadingsSenderMessage, Inclusion,
    MAX_PROOFS_PER_QUERY, MAX_STATE_CLAIMS_BYTES, MAX_STATE_CLAIMS_PER_BLOCK, ShardId, ShardTrie,
    StateClaim, Stated, SubstateKey, ValidatorId, signed_bytes,
};
use hyperscale_vm_effects::{Answered, CrossingId, CrossingLeaf, ProtocolHasher};
use tracing::warn;

/// One crossing cell a block changed that a counterpart reads: an answer
/// written, pushed to its record's producer, or a record removed,
/// pushed to its consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossingChange {
    /// The shard that reads the change.
    pub target: ShardId,
    /// The cell.
    pub key: SubstateKey,
    /// The crossing it answers for or records.
    pub id: CrossingId,
    /// Whether the block left the cell present: an answer written, or,
    /// absent, a record removed.
    pub present: bool,
}

/// The `Taken` keys of the owed records `claim` reads with their value,
/// each of which the commit fold writes where it credits the reading.
fn credited(claim: &StateClaim) -> impl Iterator<Item = SubstateKey> + '_ {
    claim
        .crossings
        .iter()
        .filter(move |(key, id)| {
            *key == id.record_key(&ProtocolHasher) && claim.held(*key).is_some()
        })
        .map(|(_, id)| id.answer_key(&ProtocolHasher, Answered::Taken))
}

/// The crossing changes `block` made that a counterpart reads, judged
/// from each written cell's value before (`prior`) and after (`after`)
/// the block: an answer put, and a record deleted.
///
/// The cells a block's crossing state moves on are its settling
/// receipts' writes, the records and answers its claims settle in the
/// fold, and the `Taken` its fold writes crediting an owed record's
/// reading; nothing else it writes is a crossing leaf. A target equal
/// to `local` is left out: the local rule reads the cell at the parent.
/// An answer deleted is not pushed, since nothing reads it, and a
/// record written is the records' own push.
#[must_use]
pub fn crossing_changes(
    block: &Block,
    prior: impl Fn(SubstateKey) -> Option<Vec<u8>>,
    after: impl Fn(SubstateKey) -> Option<Vec<u8>>,
    trie: &ShardTrie,
    local: ShardId,
) -> Vec<CrossingChange> {
    let mut written: Vec<SubstateKey> = block
        .certificates()
        .iter()
        .flat_map(|finalization| finalization.settling_receipts())
        .filter_map(|receipt| {
            receipt
                .consensus
                .writes()
                .map(|writes| writes.cells.clone())
        })
        .flat_map(BTreeMap::into_keys)
        .chain(block.state_claims().iter().flat_map(StateClaim::settles))
        .chain(
            block
                .state_claims()
                .iter()
                .flat_map(credited)
                .filter(|taken| prior(*taken).is_none()),
        )
        .collect();
    written.sort_unstable();
    written.dedup();
    written
        .into_iter()
        .filter_map(|key| {
            let now = after(key);
            let change = match now
                .as_deref()
                .and_then(|value| CrossingLeaf::read(&ProtocolHasher, key, value))
            {
                Some(CrossingLeaf::Answer { id, .. }) => CrossingChange {
                    target: trie.shard_for_prefix(id.record_key(&ProtocolHasher).owner),
                    key,
                    id,
                    present: true,
                },
                None if now.is_none() => {
                    let was = prior(key)?;
                    let Some(CrossingLeaf::Record { cell, crossing }) =
                        CrossingLeaf::read(&ProtocolHasher, key, &was)
                    else {
                        return None;
                    };
                    CrossingChange {
                        target: trie.shard_for_prefix(cell.consumer),
                        key,
                        id: crossing.id,
                        present: false,
                    }
                }
                Some(CrossingLeaf::Record { .. }) | None => return None,
            };
            (change.target != local).then_some(change)
        })
        .collect()
}

/// Prove what the block at `anchor` changed for each target — the
/// records `targets` names, and the answers and removals its own delta
/// holds — and send it to the target's committee, one signed
/// notification per section.
pub fn push_crossing_readings<S, N>(
    ctx: &ActionContext<'_, S, N>,
    block_hash: BlockHash,
    anchor: Anchor,
    targets: &BTreeMap<ShardId, Vec<SubstateKey>>,
    shard_recipients: &HashMap<ShardId, Vec<ValidatorId>>,
) where
    S: ShardStorage,
    N: Network,
{
    let view = ctx.pending_chain.view_at(block_hash, anchor.height);
    let changes = ctx
        .pending_chain
        .certified_block(anchor.height)
        .filter(|certified| certified.block().hash() == block_hash)
        .map_or_else(Vec::new, |certified| {
            let block = certified.block();
            let parent = block.header().parent_qc();
            let before = ctx
                .pending_chain
                .view_at(parent.block_hash(), parent.height());
            let parent_height = parent.height();
            crossing_changes(
                block,
                |key| before.get_substate_at_height(key, parent_height).flatten(),
                |key| view.get_substate_at_height(key, anchor.height).flatten(),
                ctx.topology_snapshot.shard_trie(),
                anchor.shard,
            )
        });
    let mut pushes = build_pushes(&view, anchor, targets);
    for (target, claims) in prove_changes(&view, anchor, &changes) {
        match pushes.iter_mut().find(|(shard, _)| *shard == target) {
            Some((_, sections)) => sections.extend(claims),
            None => pushes.push((target, claims)),
        }
    }
    for (target_shard, sections) in pushes {
        let recipients = shard_recipients
            .get(&target_shard)
            .cloned()
            .unwrap_or_else(|| {
                ctx.topology_snapshot
                    .committee_for_shard(target_shard)
                    .to_vec()
            });
        if recipients.is_empty() {
            continue;
        }
        let recipients = &recipients;
        for claims in sections {
            let msg = signed_bytes(
                &CrossingReadingsSenderMessage::new(target_shard, &claims),
                ctx.topology_snapshot.network(),
            );
            let Ok(sig) = ctx.signer.sign(&msg) else {
                tracing::error!("cannot sign crossing readings push; skipping");
                return;
            };
            let notification = CrossingReadingsNotification::new(claims, target_shard, ctx.me, sig);
            ctx.network.notify(recipients, &notification);
        }
    }
}

/// The claims to push to each target, each list cut into the sections
/// a consumer can carry: at most one block's claims, weighing at most
/// one block's section.
fn build_pushes<S>(
    view: &SubstateView<S>,
    anchor: Anchor,
    targets: &BTreeMap<ShardId, Vec<SubstateKey>>,
) -> Vec<(
    ShardId,
    Vec<Capped<Vec<StateClaim>, MAX_STATE_CLAIMS_PER_BLOCK>>,
)>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    targets
        .iter()
        .map(|(&target, keys)| {
            let mut claims = Vec::new();
            for chunk in keys.chunks(MAX_PROOFS_PER_QUERY) {
                prove_chunk(view, anchor, chunk, &mut claims);
            }
            (target, cut_to_sections(claims))
        })
        .filter(|(_, sections)| !sections.is_empty())
        .collect()
}

/// Prove `keys` present at the anchor as one claim, halving the chunk
/// where the proof would not fit its decoder's cap, and skipping a key
/// the view does not hold: a push carries only what the block wrote.
fn prove_chunk<S>(
    view: &SubstateView<S>,
    anchor: Anchor,
    keys: &[SubstateKey],
    out: &mut Vec<StateClaim>,
) where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    let mut cells = Vec::with_capacity(keys.len());
    for &key in keys {
        let Some(Some(value)) = view.get_substate_at_height(key, anchor.height) else {
            warn!(
                shard = anchor.shard.inner(),
                height = anchor.height.inner(),
                "a record to push is not present at its own block"
            );
            continue;
        };
        let Ok(held) = Bytes::new(value) else {
            warn!(
                shard = anchor.shard.inner(),
                height = anchor.height.inner(),
                "a record to push is wider than a held value"
            );
            continue;
        };
        cells.push((key, Stated::Held(held)));
    }
    if cells.is_empty() {
        return;
    }
    let present: Vec<SubstateKey> = cells.iter().map(|(key, _)| *key).collect();
    match generate_proof(view, &present, anchor.height) {
        Some(proof) => out.push(StateClaim::new(anchor, cells, proof)),
        None if present.len() > 1 => {
            let (left, right) = present.split_at(present.len() / 2);
            prove_chunk(view, anchor, left, out);
            prove_chunk(view, anchor, right, out);
        }
        None => warn!(
            shard = anchor.shard.inner(),
            height = anchor.height.inner(),
            "a single record's proof cannot be built at its own block"
        ),
    }
}

/// The changes each target reads, proved at the block's own root and
/// named for their crossings, cut into sections.
fn prove_changes<S>(
    view: &SubstateView<S>,
    anchor: Anchor,
    changes: &[CrossingChange],
) -> Vec<(
    ShardId,
    Vec<Capped<Vec<StateClaim>, MAX_STATE_CLAIMS_PER_BLOCK>>,
)>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    let mut by_target: BTreeMap<ShardId, Vec<CrossingChange>> = BTreeMap::new();
    for change in changes {
        by_target.entry(change.target).or_default().push(*change);
    }
    by_target
        .into_iter()
        .map(|(target, changes)| {
            let mut claims = Vec::new();
            for chunk in changes.chunks(MAX_PROOFS_PER_QUERY) {
                prove_change_chunk(view, anchor, chunk, &mut claims);
            }
            (target, cut_to_sections(claims))
        })
        .filter(|(_, sections)| !sections.is_empty())
        .collect()
}

/// Prove one chunk of changes as one claim, each cell read as the block
/// left it and named for its crossing, halving where the proof would
/// not fit its decoder's cap.
fn prove_change_chunk<S>(
    view: &SubstateView<S>,
    anchor: Anchor,
    changes: &[CrossingChange],
    out: &mut Vec<StateClaim>,
) where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    let height: BlockHeight = anchor.height;
    let cells: Vec<(SubstateKey, Inclusion)> = changes
        .iter()
        .map(|change| {
            let inclusion = view
                .get_substate_at_height(change.key, height)
                .flatten()
                .map_or(Inclusion::Absent, |value| {
                    Inclusion::Present(jmt_value_hash(&value))
                });
            (change.key, inclusion)
        })
        .collect();
    let keys: Vec<SubstateKey> = cells.iter().map(|(key, _)| *key).collect();
    match generate_proof(view, &keys, height) {
        Some(proof) => out.push(
            StateClaim::new(anchor, cells, proof)
                .naming(changes.iter().map(|change| (change.key, change.id))),
        ),
        None if changes.len() > 1 => {
            let (left, right) = changes.split_at(changes.len() / 2);
            prove_change_chunk(view, anchor, left, out);
            prove_change_chunk(view, anchor, right, out);
        }
        None => warn!(
            shard = anchor.shard.inner(),
            height = anchor.height.inner(),
            "a crossing change's proof cannot be built at its own block"
        ),
    }
}

/// Cut claims into sections a consumer can carry whole.
fn cut_to_sections(
    claims: Vec<StateClaim>,
) -> Vec<Capped<Vec<StateClaim>, MAX_STATE_CLAIMS_PER_BLOCK>> {
    let mut sections = Vec::new();
    let mut section: Vec<StateClaim> = Vec::new();
    let mut weight = 0usize;
    for claim in claims {
        let cost = claim.wire_weight();
        if !section.is_empty()
            && (section.len() >= MAX_STATE_CLAIMS_PER_BLOCK
                || weight + cost > MAX_STATE_CLAIMS_BYTES)
        {
            sections.push(Capped::new(std::mem::take(&mut section)).expect("cut under the cap"));
            weight = 0;
        }
        weight += cost;
        section.push(claim);
    }
    if !section.is_empty() {
        sections.push(Capped::new(section).expect("cut under the cap"));
    }
    sections
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::{block_settling, with_state_claims};
    use hyperscale_types::{
        Address, AddressClass, ConsensusReceipt, GlobalReceiptHash, Hash, MerkleInclusionProof,
        ResourceAddr, StateRoot, StateWrites, StoredReceipt, TxHash, WeightedTimestamp,
    };
    use hyperscale_vm_effects::{Answered, Hash32, IntentHash, Terms};

    use super::*;

    const LOCAL: ShardId = ShardId::leaf(1, 0);
    const REMOTE: ShardId = ShardId::leaf(1, 1);

    /// An owner on `LOCAL` below `0x80`, or on `REMOTE` at or above it.
    fn owner(byte: u8) -> Address {
        Address::new([byte; 31], AddressClass::Component)
    }

    fn crossing(seed: u8, producer: u8, consumer: u8) -> CrossingId {
        CrossingId {
            producer: owner(producer),
            consumer: owner(consumer),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        }
    }

    fn record(id: CrossingId) -> (SubstateKey, Vec<u8>) {
        let key = id.record_key(&ProtocolHasher);
        let cell = id.cell(
            TxHash::from(Hash::from_bytes(&[9; 32])),
            ResourceAddr::new([0xE1; 31]),
            10,
            1_000,
            Terms::Escrowed { credit: key },
        );
        (key, cell.to_bytes())
    }

    fn answer(id: CrossingId, answered: Answered) -> (SubstateKey, Vec<u8>) {
        (
            id.answer_key(&ProtocolHasher, answered),
            id.answer(TxHash::from(Hash::from_bytes(&[8; 32])), answered, 1_000)
                .to_bytes(),
        )
    }

    /// The delta names an answer written, pushed to its record's
    /// producer, and a record removed — by a reclaim's receipt or by the
    /// fold on its consumer's `Taken` — pushed to its consumer. An answer
    /// deleted, and a change whose reader is this shard, are not pushed.
    #[test]
    fn the_delta_names_answers_written_and_records_removed() {
        let taken = crossing(1, 0x90, 0x10);
        let reclaimed = crossing(2, 0x20, 0xA0);
        let folded = crossing(3, 0x30, 0xB0);
        let answered_gone = crossing(4, 0xC0, 0x40);
        let local_both = crossing(5, 0x50, 0x60);
        let (taken_key, taken_value) = answer(taken, Answered::Taken);
        let (reclaimed_key, reclaimed_value) = record(reclaimed);
        let (folded_key, folded_value) = record(folded);
        let (gone_key, gone_value) = answer(answered_gone, Answered::Taken);
        let (local_key, local_value) = record(local_both);

        let writes = StateWrites {
            cells: BTreeMap::from([
                (taken_key, Some(taken_value.clone())),
                (reclaimed_key, None),
                (gone_key, None),
                (local_key, None),
            ]),
            ..StateWrites::default()
        };
        let receipt = StoredReceipt::synced(
            TxHash::from(Hash::from_bytes(b"delta")),
            Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                writes,
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        );
        let folded_taken = folded.answer_key(&ProtocolHasher, Answered::Taken);
        let settling = StateClaim::new(
            Anchor {
                shard: REMOTE,
                height: BlockHeight::new(3),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(3_000),
            },
            [(folded_taken, Inclusion::Present([7; 32]))],
            MerkleInclusionProof::dummy(),
        )
        .naming([(folded_taken, folded)]);
        let block = with_state_claims(
            block_settling(BlockHeight::new(4), vec![receipt]),
            vec![settling],
        );

        let before: BTreeMap<SubstateKey, Vec<u8>> = BTreeMap::from([
            (reclaimed_key, reclaimed_value),
            (folded_key, folded_value),
            (gone_key, gone_value),
            (local_key, local_value),
        ]);
        let after: BTreeMap<SubstateKey, Vec<u8>> = BTreeMap::from([(taken_key, taken_value)]);
        let mut changes = crossing_changes(
            &block,
            |key| before.get(&key).cloned(),
            |key| after.get(&key).cloned(),
            &ShardTrie::from_leaves([LOCAL, REMOTE]),
            LOCAL,
        );
        changes.sort_by_key(|change| change.key);
        let mut expected = vec![
            CrossingChange {
                target: REMOTE,
                key: taken_key,
                id: taken,
                present: true,
            },
            CrossingChange {
                target: REMOTE,
                key: reclaimed_key,
                id: reclaimed,
                present: false,
            },
            CrossingChange {
                target: REMOTE,
                key: folded_key,
                id: folded,
                present: false,
            },
        ];
        expected.sort_by_key(|change| change.key);
        assert_eq!(changes, expected);
    }
}
