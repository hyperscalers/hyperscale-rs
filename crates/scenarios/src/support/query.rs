//! Derived read-only combinators over a [`Cluster`], plus the store-level
//! queries the adaptors share.
//!
//! The combinators are projections of [`Cluster::beacon_state`]; the
//! store-level queries ([`chain_fate`], [`status_rank`]) back both adaptors'
//! trait impls. All are kept out of the trait so the two adaptors share one
//! definition and cannot drift apart.

use std::collections::BTreeSet;

use hyperscale_engine::genesis::vault_key;
use hyperscale_engine::{XRD, publish_work};
use hyperscale_storage::ShardChainReader;
use hyperscale_types::{
    Address, BlockHash, BlockHeight, ConsensusPublicKey, Epoch, MAX_SWEEPABLE_CREATED_PER_BLOCK,
    MAX_TXS_PER_BLOCK, PendingReshape, ResourceAddr, ShardId, ShardTrie, Stake, StakePool,
    StakePoolId, StateRoot, SubstateKey, Transaction, TransactionDecision, TransactionStatus,
    TxHash, ValidatorId, ValidatorStatus, WeightedTimestamp, sweep_admits_block,
};

use super::Cluster;

/// The deepest leaf [`served_shards`] looks for. A scenario that grows or
/// splits reaches depth two; nothing here goes deeper.
pub(crate) const MAX_SEARCHED_DEPTH: u32 = 3;

/// What a scenario transaction is charged, whatever refuses it.
///
/// The one figure the fee schedule has: a success burns it, and so does
/// every refusal a sender can reach, so a scenario asserting what a
/// vault moved reads it once and compares against it either way.
/// Borrowed from the cluster's own derivation, because a transaction a
/// scenario assembled has been derived by nobody. A publish is priced by
/// its artifact's length and held to its ceiling rather than by the call
/// rule.
///
/// # Panics
///
/// Panics if the transaction does not derive, which for a scenario
/// fixture means it was built wrong.
pub fn declared_price<C: Cluster + ?Sized>(c: &C, tx: &Transaction) -> u128 {
    let body = tx.try_body().expect("a scenario fixture decodes");
    if let Some(artifact) = body.artifact() {
        return u128::from(publish_work(artifact)).min(body.max_fee);
    }
    tx.price_under(c.derivation().as_ref())
        .expect("a scenario fixture derives")
}

/// Assert that a full block of transactions shaped like `tx` fits the
/// per-block cap on sweepable creation, on whichever live shard `tx`
/// creates most on.
///
/// The cap is sized so a full block of any corpus shape stays
/// admissible; this reads that off the shape the corpus actually
/// produces rather than the arithmetic the constant's doc recites. The
/// count is linear in a block's transactions, so one transaction's share
/// taken a block's worth of times is exactly what a full block sums to.
///
/// Read where the price is, once the verdict is in: a call into an
/// instance on a shard the derivation host does not serve derives only
/// once a provision has carried the record over, so nothing here can be
/// asked of a transaction before it ran.
///
/// # Panics
///
/// Panics if the transaction does not derive, or if a full block of it
/// would be refused.
pub fn assert_a_full_block_fits<C: Cluster + ?Sized>(c: &C, tx: &Transaction) {
    tx.try_derived(c.derivation().as_ref())
        .expect("a scenario fixture derives");
    let live = live_shards(c);
    let (trie, shards) = if live.is_empty() {
        (ShardTrie::uniform_from_count(1), vec![ShardId::ROOT])
    } else {
        (
            ShardTrie::from_leaves(live.iter().copied()),
            live.iter().copied().collect(),
        )
    };
    let busiest = shards
        .iter()
        .map(|shard| tx.sweepable_writes_on(&trie, *shard) + 1)
        .max()
        .unwrap_or(0);
    let full_block = MAX_TXS_PER_BLOCK * busiest;
    assert!(
        sweep_admits_block(full_block),
        "a full block of this shape creates {full_block} sweepable cells on its busiest \
         shard, past the cap of {MAX_SWEEPABLE_CREATED_PER_BLOCK}",
    );
}

/// Every shard this cluster currently serves, ascending.
///
/// There is no enumeration on [`Cluster`] — a scenario names the shards
/// it stood up — so this asks the only question the trait answers, over
/// every leaf a scenario could have reached.
#[must_use]
pub fn served_shards<C: Cluster + ?Sized>(c: &C) -> Vec<ShardId> {
    (0..=MAX_SEARCHED_DEPTH)
        .flat_map(|depth| (0..1u64 << depth).map(move |path| ShardId::leaf(depth, path)))
        .filter(|shard| c.serves_shard(*shard))
        .collect()
}

/// What `owner` holds of `resource`, wherever its prefix currently sits.
///
/// Routed rather than searched, because a scenario that reshapes moves
/// the answer: the cell keeps its key across a split — the key is the
/// owner's prefix and a local half, neither of which a reshape rewrites
/// — but the shard serving it changes, and a shard that has handed its
/// prefix on still answers for it, at the state it froze at.
#[must_use]
pub fn held<C: Cluster + ?Sized>(c: &C, owner: Address, resource: ResourceAddr) -> u128 {
    held_at(c, vault_key(owner, resource))
}

/// The committed amount in one cell, wherever its prefix currently sits.
///
/// The general form of [`held`], for value a component keeps in its own
/// state rather than in the protocol's vault slot: an account's balance
/// is reachable from its address, and a pool's reserves are reachable
/// only from the package's own slot, which the scenario declaring the
/// package is what knows.
#[must_use]
pub fn held_at<C: Cluster + ?Sized>(c: &C, cell: SubstateKey) -> u128 {
    let shard = owning_shard(c, cell.owner);
    c.substate(shard, cell.owner, cell.local.0)
        .map_or(0, |bytes| {
            <[u8; 16]>::try_from(bytes.as_slice()).map_or(0, u128::from_le_bytes)
        })
}

/// The live shard whose prefix `owner` falls under.
///
/// The beacon's live leaf partition is the authority: a split's parent
/// and a merge's children keep serving their frozen stores after the
/// cut, and a search over everything served would read whichever of
/// them answered first. Before the beacon has folded anything the root
/// is the one shard there is.
#[must_use]
pub fn owning_shard<C: Cluster + ?Sized>(c: &C, owner: Address) -> ShardId {
    let live = live_shards(c);
    if live.is_empty() {
        return ShardId::ROOT;
    }
    ShardTrie::from_leaves(live).shard_for_prefix(owner)
}

/// Walk `store`'s committed chain from height 1 for `tx`'s fate.
///
/// Returns the height at which `tx` was committed (rides a block's
/// `transactions`) and the height plus decision at which it was finalized
/// (rides a `Finalization` certificate). The decision matters at a reshape
/// boundary: a counterpart abort finalizes the straddler with `Aborted`,
/// which a presence-only check would misread as a one-sided apply.
#[must_use]
pub fn chain_fate(
    store: &impl ShardChainReader,
    tx: TxHash,
) -> (
    Option<BlockHeight>,
    Option<(BlockHeight, TransactionDecision)>,
) {
    let mut committed = None;
    let mut finalized = None;
    let tip = store.committed_height();
    let mut height = BlockHeight::new(1);
    while height <= tip {
        if let Some(certified) = store.get_block(height) {
            let block = certified.block();
            if block.transactions().iter().any(|t| t.hash() == tx) {
                committed = Some(height);
            }
            for fw in block.certificates().iter() {
                if let Some((_, decision)) = fw.tx_decisions().into_iter().find(|(h, _)| *h == tx) {
                    finalized = Some((height, decision));
                }
            }
        }
        height = height.next();
    }
    (committed, finalized)
}

/// Walk `store`'s committed chain for every abandonment record naming
/// `tx`: the height each committed at and the departed shard it speaks
/// for.
#[must_use]
pub fn records_naming(store: &impl ShardChainReader, tx: TxHash) -> Vec<(BlockHeight, ShardId)> {
    let tip = store.committed_height();
    let mut named = Vec::new();
    let mut height = BlockHeight::new(1);
    while height <= tip {
        if let Some(certified) = store.get_block(height) {
            named.extend(
                certified
                    .block()
                    .abandonment_records()
                    .iter()
                    .filter(|record| record.tx_hashes().any(|named| named == tx))
                    .map(|record| (height, record.shard())),
            );
        }
        height = height.next();
    }
    named
}

/// One thing a shard's own certificate said it ran of a transaction.
///
/// Read off the local execution certificate's outcome, so it is the
/// membership the shard froze and attested rather than anything a
/// scenario can infer from an end state: a whole-shape run and a divided
/// one reach the same balances, and differ here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RanAs {
    /// The other shards whose certificates this shard's settlement
    /// waited on. Empty for a leg, a delivery, or a single-shard core.
    pub awaited: Vec<ShardId>,
    /// Whether this outcome bore the verdict on the transaction. False
    /// for a leg that succeeded and for a delivering member.
    pub decides: bool,
    /// Whether the transaction reached beyond this shard. False for a
    /// member this shard composed for itself — a reclaim or a
    /// retirement.
    pub reaches_beyond: bool,
    /// The shards this execution's crossings were issued to.
    pub crossing_targets: Vec<ShardId>,
}

impl RanAs {
    /// Whether this is a member the shard composed for itself off
    /// committed evidence — a reclaim or a retirement — rather than one
    /// the transaction's own admission put there.
    #[must_use]
    pub const fn is_local_only(&self) -> bool {
        !self.reaches_beyond
    }
}

/// Walk `store`'s committed chain for everything its own certificates
/// said it ran of `tx`, in commit order.
///
/// Empty until a finalization whose local certificate names `tx` has
/// committed, and more than one entry where the shard ran a member and
/// later composed a reclaim or a retirement for the same transaction.
#[must_use]
pub fn chain_membership(store: &impl ShardChainReader, tx: TxHash) -> Vec<RanAs> {
    let tip = store.committed_height();
    let mut ran = Vec::new();
    let mut height = BlockHeight::new(1);
    while height <= tip {
        if let Some(certified) = store.get_block(height) {
            for fw in certified.block().certificates().iter() {
                ran.extend(
                    fw.local_ec()
                        .tx_outcomes()
                        .iter()
                        .filter(|outcome| outcome.tx_hash() == tx)
                        .map(|outcome| RanAs {
                            awaited: outcome.counterparts().to_vec(),
                            decides: outcome.decides(),
                            reaches_beyond: outcome.reaches_beyond(),
                            crossing_targets: outcome.crossing_targets().to_vec(),
                        }),
                );
            }
        }
        height = height.next();
    }
    ran
}

/// Assert `shard` ran `tx` divided — nothing it attested for a
/// transaction reaching past it bore the verdict — and composed exactly
/// one member of its own off committed evidence.
///
/// The reclaim of a refused leg is that member. Under whole-shape
/// replication the shard would attest one deciding member reaching
/// beyond and compose nothing of its own, and every end state the
/// refusal scenarios assert would be reached identically; this is what
/// tells the two apart.
///
/// # Panics
///
/// Panics if the shard attested nothing for `tx`, if anything it
/// attested for the wider transaction decided it, or if it composed any
/// number of local members but one.
pub fn assert_reclaimed_leg<C: Cluster + ?Sized>(c: &C, shard: ShardId, tx: TxHash, context: &str) {
    let ran = c.ran(shard, tx);
    assert!(
        !ran.is_empty(),
        "{context}: {shard:?} attested nothing for the transaction",
    );
    let deciding = ran.iter().filter(|r| r.reaches_beyond && r.decides).count();
    assert_eq!(
        deciding, 0,
        "{context}: {shard:?} ran a leg, which decides nothing — a member \
         deciding here is the whole shape replicated; ran {ran:?}",
    );
    let reclaims = ran.iter().filter(|r| r.is_local_only()).count();
    assert_eq!(
        reclaims, 1,
        "{context}: {shard:?} reclaims the leg's crossing exactly once; ran {ran:?}",
    );
}

/// The committed balance of `owner`'s native vault on `shard`, read through
/// the harness's client-proven snapshot seam.
///
/// # Panics
///
/// Panics if the cell holds anything but an amount.
#[must_use]
pub fn vault_balance<C: Cluster>(c: &C, shard: ShardId, owner: impl Into<Address>) -> u128 {
    let vault = vault_key(owner, *XRD);
    c.substate(shard, vault.owner, vault.local.0)
        .map_or(0, |bytes| {
            let cell: [u8; 16] = bytes.as_slice().try_into().expect("an amount cell");
            u128::from_le_bytes(cell)
        })
}

/// Rank a transaction status so a cluster-wide view takes the most advanced
/// observation.
#[must_use]
pub const fn status_rank(status: &TransactionStatus) -> u8 {
    match status {
        TransactionStatus::Pending => 0,
        TransactionStatus::Committed(_) => 1,
        TransactionStatus::LegFinalized => 2,
        TransactionStatus::Completed(_) => 3,
    }
}

/// The latest committed beacon epoch, if the cluster has folded one.
#[must_use]
pub fn beacon_epoch<C: Cluster>(c: &C) -> Option<Epoch> {
    c.beacon_state().map(|state| state.current_epoch)
}

/// The cluster's clock as the weighted timestamp a block anchored now
/// carries.
#[must_use]
pub fn clock<C: Cluster + ?Sized>(c: &C) -> WeightedTimestamp {
    WeightedTimestamp::ZERO.plus(c.now())
}

/// Whether the beacon has admitted a split for `parent` — a pending `Split`
/// record carrying the drawn observer cohort.
#[must_use]
pub fn split_admitted<C: Cluster>(c: &C, parent: ShardId) -> bool {
    c.beacon_state().is_some_and(|state| {
        matches!(
            state.pending_reshapes.get(&parent),
            Some(PendingReshape::Split { .. })
        )
    })
}

/// The final epoch window the beacon has scheduled `parent`'s reshape to
/// terminate on — the cut its chain ends at and its successors take over
/// at.
///
/// `None` while the reshape is admitted but its readiness gate has yet to
/// stamp a cut. A `Some` answer is irrevocable, so a scenario may build
/// against it.
#[must_use]
pub fn scheduled_terminal_epoch<C: Cluster>(c: &C, parent: ShardId) -> Option<Epoch> {
    c.beacon_state()
        .and_then(|state| state.pending_reshapes.get(&parent)?.scheduled_terminal())
}

/// Milliseconds of weighted time per epoch, off the beacon's own chain
/// config — what turns an epoch number into the boundary it starts at.
#[must_use]
pub fn epoch_duration_ms<C: Cluster>(c: &C) -> Option<u64> {
    c.beacon_state()
        .map(|state| state.chain_config.epoch_duration_ms)
}

/// The beacon-composed anchor root for `shard` — the `boundaries` `state_root`
/// a flip must reproduce.
#[must_use]
pub fn anchor_root<C: Cluster>(c: &C, shard: ShardId) -> Option<StateRoot> {
    c.beacon_state()
        .and_then(|state| state.boundaries.get(&shard).map(|b| b.state_root))
}

/// The genesis height the beacon composed onto `shard`'s boundary, once the
/// fold that publishes the anchor has run.
///
/// `None` while the record is still the placeholder a reshape cut installs,
/// which carries a zero block hash. A split child outruns that fold — it
/// flips from its own follow of the parent and serves from the cut — so
/// "served" no longer implies "anchored".
#[must_use]
pub fn anchored_genesis_height<C: Cluster>(c: &C, shard: ShardId) -> Option<BlockHeight> {
    c.beacon_state().and_then(|state| {
        state
            .boundaries
            .get(&shard)
            .filter(|boundary| boundary.block_hash != BlockHash::ZERO)
            .map(|boundary| boundary.height)
    })
}

/// The number of keepers drawn for a merge into `parent`, once paired (both
/// children hold a live half). `None` before pairing.
#[must_use]
pub fn merge_keeper_count<C: Cluster>(c: &C, parent: ShardId) -> Option<usize> {
    c.beacon_state()
        .and_then(|state| match state.pending_reshapes.get(&parent) {
            Some(PendingReshape::Merge {
                keepers,
                admitted_at: Some(_),
                ..
            }) => Some(keepers.len()),
            _ => None,
        })
}

/// The number of validators seated on `shard`'s current committee, or `None` if
/// the beacon seats no committee there (the shard is unborn or terminated).
#[must_use]
pub fn committee_size<C: Cluster>(c: &C, shard: ShardId) -> Option<usize> {
    c.beacon_state().and_then(|state| {
        state
            .shard_committees
            .get(&shard)
            .map(|cm| cm.members.len())
    })
}

/// The set of shards the beacon currently seats a committee for — the live leaf
/// partition.
#[must_use]
pub fn live_shards<C: Cluster + ?Sized>(c: &C) -> BTreeSet<ShardId> {
    c.beacon_state()
        .map(|state| state.shard_committees.keys().copied().collect())
        .unwrap_or_default()
}

/// The total stake folded into `pool`, or `None` if the beacon holds no record
/// of it — counting deposits whether or not they have unbonded.
#[must_use]
pub fn pool_total_stake<C: Cluster>(c: &C, pool: StakePoolId) -> Option<Stake> {
    c.beacon_state()
        .and_then(|state| state.pools.get(&pool).map(|p| p.total_stake))
}

/// The effective (bonded) stake of `pool` — total less any stake still inside
/// its unbonding window. A withdrawal drops this immediately while
/// [`pool_total_stake`] holds until the unbond matures.
#[must_use]
pub fn pool_effective_stake<C: Cluster>(c: &C, pool: StakePoolId) -> Option<Stake> {
    c.beacon_state()
        .and_then(|state| state.pools.get(&pool).map(StakePool::effective_stake))
}

/// The folded status of validator `id`, or `None` if the beacon holds no record
/// of it.
#[must_use]
pub fn validator_status<C: Cluster>(c: &C, id: ValidatorId) -> Option<ValidatorStatus> {
    c.beacon_state()
        .and_then(|state| state.validators.get(&id).map(|r| r.status))
}

/// The registered consensus public key of validator `id`, or `None` if unregistered.
#[must_use]
pub fn validator_pubkey<C: Cluster>(c: &C, id: ValidatorId) -> Option<ConsensusPublicKey> {
    c.beacon_state()
        .and_then(|state| state.validators.get(&id).map(|r| r.pubkey))
}
