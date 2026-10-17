//! What the proposal wire budget's arithmetic rests on.
//!
//! `limits.rs` asserts at compile time that a proposal with every section
//! at its cap fits [`MAX_WIRE_MESSAGE_BYTES`], out of a per-item byte
//! figure for each section. That assertion is only worth as much as those
//! figures, and nothing in the type system ties them to what HBOR
//! actually writes. So they are tied here: each is measured against a
//! maximal value of its type, and a widened field fails this before it
//! can quietly overrun the frame.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_hbor::{
    Bytes, Capped, Hash32, Hbor, from_slice as hbor_from_slice, to_vec as hbor_to_vec,
};
use hyperscale_jmt::{
    Blake3Hasher, Key as JmtKey, LeafValue, MAX_SINGLE_CLAIM_PROOF_BYTES, MemoryStore, MultiProof,
    NodeKey, Tree,
};
use hyperscale_types::network::response::GetTerminalLinesResponse;
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    ABANDONMENT_RECORD_BYTES, AbandonmentRecord, AbortCharge, Address, AddressClass,
    AggregateSignature, Anchor, BLOCK_RESPONSE_INLINE_BYTES, BlockHeader, BlockHeaderParts,
    BlockHeight, CollectionId, CommittedAt, ConsensusReceipt, Crossings, Deadline, DeclaredKey,
    DeclaredRange, DiscardCause, ENGAGEMENT_BYTES, ElidedCertifiedBlock, Engagement,
    ExecutionCertificate, ExecutionOutcome, Finalization, FinalizationHash, GlobalReceiptHash,
    Hash, Joins, LocalKey, MAX_ARTIFACT_BYTES, MAX_CLAIMS_PER_BLOCK, MAX_ENGAGEMENTS_PER_BLOCK,
    MAX_ENVELOPE_BYTES, MAX_FINALIZED_TX_PER_BLOCK, MAX_HELD_VALUE_BYTES, MAX_HOLDS_PER_MEMBER,
    MAX_PREFIXES_PER_TX, MAX_PROPOSAL_EVIDENCE_BYTES, MAX_PROVISION_TARGET_SHARDS,
    MAX_PROVISIONS_PER_BLOCK, MAX_STAGED_RECEIPT_BYTES, MAX_STATE_CLAIMS_BYTES,
    MAX_STATE_CLAIMS_PER_BLOCK, MAX_TERMINAL_LINES_RESPONSE_BYTES, MAX_TICK_LINES_PER_BLOCK,
    MAX_TICK_MANIFEST_BYTES, MAX_TICK_STAGED_BYTES, MAX_TICK_TERMS_BYTES, MAX_TXS_PER_BLOCK,
    MAX_UNSETTLED_PER_BLOCK, MAX_VERDICT_CLAIMS_BYTES, MAX_WIRE_MESSAGE_BYTES, MemberTerms,
    MerkleInclusionProof, Movement, ProvisionHash, ProvisionTxRoot, Provisions, QuorumCertificate,
    ROUTE_PREFIX_BYTES, Reach, Reserves, Role, RoutePrefix, SINGLE_CELL_CLAIM_P99_BYTES,
    STATE_CLAIM_BYTES, STATE_CLAIM_CELL_BYTES, STATE_CLAIM_VERDICT_BYTES, STATE_CLAIMS_HEADROOM,
    SchemeId, SectionRoots, Settlement, ShardId, SignerBitfield, StateClaim, StateRoot,
    StateWrites, Stated, StatedTerms, StoredReceipt, SubstateKey, TICK_CROSSING_BYTES,
    TICK_HOLD_BYTES, TICK_LINE_BYTES, TICK_REACH_BYTES, TICK_RESERVE_BYTES, TICK_TERMS_BYTES,
    TerminalLines, TickHalf, TickId, TickLine, TickManifest, Transaction, TransactionEnvelope,
    TxHash, TxOutcome, UNSETTLED_TX_BYTES, UnsettledTx, Verifiable, WeightedTimestamp,
    WitnessSources, compute_global_receipt_root, evidence_admits_block, receipt_hash_of,
    shard_prefix_path, staged_yes_bytes, state_claims_admit_block, tick_manifest_admits_block,
    tick_terms_admit_block,
};
use hyperscale_vm_effects::CrossingId;
use hyperscale_vm_types::{IntentHash, MAX_CROSSINGS_PER_TX, Mode, Moves, ResourceAddr};

type Jmt = Tree<Blake3Hasher, 1>;

/// The widest envelope the caps admit: an artifact at its ceiling,
/// every signature it may bind at the widest registered scheme, a
/// ceiling per manifest node, and a full message.
///
/// [`MAX_ENVELOPE_BYTES`] is arithmetic over those caps, so it moves
/// when they do — but arithmetic over guesses is what this file exists
/// to prevent, and nothing else ties the figure to what HBOR writes.
#[test]
fn a_maximal_envelope_encodes_under_the_bound_it_is_budgeted_at() {
    use hyperscale_vm_types::{
        Attestation, MAX_ATTESTATIONS, MAX_KEY_BYTES, MAX_MANIFEST_NODES, MAX_MESSAGE_LEN,
        MAX_SIG_BYTES, MAX_TREE_BYTES, PrincipalAddr, Terms,
    };

    let widest = SchemeId::ML_DSA_65;
    let vm = TransactionEnvelope {
        tree: vec![0xAB; MAX_TREE_BYTES].try_into().unwrap(),
        terms: Terms {
            fee_payer: PrincipalAddr::new([0xAA; 31]),
            max_fee: u128::MAX,
            gas_limits: vec![u64::MAX; MAX_MANIFEST_NODES].try_into().unwrap(),
            priority_bp: u32::MAX,
            message: vec![0xAB; MAX_MESSAGE_LEN].try_into().unwrap(),
        },
        artifact: Some(vec![0xAB; MAX_ARTIFACT_BYTES].try_into().unwrap()),
        signatures: (0..MAX_ATTESTATIONS)
            .map(|_| Attestation {
                scheme: widest,
                public_key: vec![0x11; MAX_KEY_BYTES].try_into().unwrap(),
                signature: vec![0x22; MAX_SIG_BYTES].try_into().unwrap(),
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    };
    let encoded = hbor_to_vec(&vm).expect("a maximal envelope encodes").len();
    println!("widest envelope: {encoded} bytes against a {MAX_ENVELOPE_BYTES} budget");
    assert!(
        encoded <= MAX_ENVELOPE_BYTES,
        "the widest envelope encodes to {encoded} bytes against a budget of \
         {MAX_ENVELOPE_BYTES}"
    );
    // And the budget is not absurdly loose, or it is not a measurement
    // of anything: a decoder allocating against it wastes what the slack
    // is.
    assert!(
        encoded * 2 > MAX_ENVELOPE_BYTES,
        "the budget is more than twice what the widest envelope needs: \
         {encoded} against {MAX_ENVELOPE_BYTES}"
    );
}

/// A key seeded from `seed`.
const fn key(seed: u8) -> SubstateKey {
    SubstateKey {
        owner: Address::new([seed; 31], AddressClass::Component),
        local: LocalKey([seed; 16]),
    }
}

/// One name at its widest in every fixed field, reaching `routes`
/// prefixes.
fn name(seed: u8, routes: usize) -> UnsettledTx {
    UnsettledTx {
        tx_hash: TxHash::from(Hash::from_bytes(&[seed; 32])),
        deadline: Deadline::of(WeightedTimestamp::from_millis(u64::MAX / 2)),
        charged: u128::MAX,
        charge: AbortCharge {
            vault: key(seed),
            amount: u128::MAX,
        },
        committed: CommittedAt {
            height: BlockHeight::new(u64::MAX),
            anchor: WeightedTimestamp::from_millis(u64::MAX / 2),
            committee_anchor: WeightedTimestamp::from_millis(u64::MAX / 2),
        },
        reach: Capped::new(
            (0..routes)
                .map(|at| {
                    RoutePrefix::from(Address::new(
                        [u8::try_from(at % 256).expect("masked"); 31],
                        AddressClass::Component,
                    ))
                })
                .collect(),
        )
        .expect("a reach written out in a test"),
    }
}

/// The fixed and per-route halves of a name's weight each bound what
/// HBOR writes.
///
/// Measured at two reaches rather than one, so a field moving from the
/// fixed half into the reach cannot be absorbed by slack in the other.
#[test]
fn a_names_weight_bounds_its_encoding() {
    for routes in [0, 1, 2, 6, 64, 512] {
        let name = name(1, routes);
        let encoded = hbor_to_vec(&name).expect("a name encodes");
        assert!(
            encoded.len() <= name.wire_weight(),
            "a name reaching {routes} routes encodes to {} bytes, over the {} its weight claims",
            encoded.len(),
            name.wire_weight(),
        );
    }
    assert_eq!(
        name(1, 0).wire_weight(),
        UNSETTLED_TX_BYTES,
        "a name reaching nothing costs the fixed half alone",
    );
    assert_eq!(
        name(1, 4).wire_weight() - name(1, 3).wire_weight(),
        ROUTE_PREFIX_BYTES,
        "and one route more costs one route",
    );
}

/// A record's weight bounds its encoding, over its own terms and every
/// name it carries.
#[test]
fn a_records_weight_bounds_its_encoding() {
    let deep = ShardId::leaf(9, 300);
    for names in [1usize, 2, 64] {
        for routes in [0, 2, 64] {
            let record = AbandonmentRecord::new(
                deep,
                WeightedTimestamp::from_millis(u64::MAX / 2),
                (0..names).map(|at| name(u8::try_from(at % 256).expect("masked"), routes)),
            );
            let encoded = hbor_to_vec(&record).expect("a record encodes");
            assert!(
                encoded.len() <= record.wire_weight(),
                "a record of {names} names at {routes} routes encodes to {} bytes, over the {} \
                 its weight claims",
                encoded.len(),
                record.wire_weight(),
            );
        }
    }
    let empty = AbandonmentRecord::new(deep, WeightedTimestamp::ZERO, []);
    assert_eq!(empty.wire_weight(), ABANDONMENT_RECORD_BYTES);
    assert!(hbor_to_vec(&empty).expect("encodes").len() <= ABANDONMENT_RECORD_BYTES);
}

/// A state tree of `leaves` cells for `shard`, spread across as many
/// owners from a fixed seed, and the keys it holds.
///
/// Every key sits under the shard's prefix, as a shard's tree has it,
/// and the tree is rooted there; the prefix is written into the owner's
/// first byte, so the shard is at most eight deep.
fn spread_tree(
    shard: ShardId,
    leaves: usize,
    seed: u64,
) -> (MemoryStore, StateRoot, Vec<SubstateKey>) {
    let root_path = shard_prefix_path(shard);
    let mut state = seed;
    let mut next = move || {
        // splitmix64: a fixed sequence, so the measurement is one figure.
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let mut random_key = move || {
        let mut body = [0u8; 31];
        for chunk in body.chunks_mut(8) {
            let word = next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        let shard_first = root_path.as_bytes().first().copied().unwrap_or(0);
        let keep = u8::try_from(root_path.len().min(8)).unwrap_or(8);
        if keep > 0 {
            let mask = 0xFFu8 << (8 - keep);
            body[0] = (body[0] & !mask) | (shard_first & mask);
        }
        let mut local = [0u8; 16];
        for chunk in local.chunks_mut(8) {
            chunk.copy_from_slice(&next().to_le_bytes());
        }
        SubstateKey {
            owner: Address::new(body, AddressClass::Component),
            local: LocalKey(local),
        }
    };
    let keys: Vec<SubstateKey> = (0..leaves).map(|_| random_key()).collect();
    let mut store = MemoryStore::new();
    let updates: BTreeMap<JmtKey, Option<LeafValue>> = keys
        .iter()
        .map(|key| {
            let value = key.to_bytes().to_vec();
            (
                key.to_bytes(),
                Some(LeafValue::new(jmt_value_hash(&value), value.len() as u64)),
            )
        })
        .collect();
    let result = Jmt::apply_updates_at(&store, None, 1, &shard_prefix_path(shard), &updates)
        .expect("a fresh tree takes its first version");
    let root = StateRoot::from_raw(Hash::from_hash_bytes(&result.root_hash));
    store.apply(&result);
    (store, root, keys)
}

/// A claim over `asked` against `shard`'s tree in `store` at version
/// one, read off a real proof.
fn claim_over(
    store: &MemoryStore,
    shard: ShardId,
    root: StateRoot,
    asked: &[SubstateKey],
) -> StateClaim {
    let jmt_keys: Vec<JmtKey> = asked.iter().map(SubstateKey::to_bytes).collect();
    let proof = Jmt::prove(store, &NodeKey::new(1, shard_prefix_path(shard)), &jmt_keys)
        .expect("every key proves against a held version");
    let proof = MerkleInclusionProof::new(proof.encode());
    let cells = proof
        .inclusions(root, shard, asked)
        .expect("the proof answers for its keys");
    let anchor = Anchor {
        shard,
        height: BlockHeight::new(u64::MAX / 2),
        state_root: root,
        ts: WeightedTimestamp::from_millis(u64::MAX / 2),
    };
    StateClaim::new(anchor, cells, proof)
}

/// A claim's weight bounds its encoding, over its terms, every cell it
/// carries and the proof of them.
///
/// Measured over real proofs at several widths, so a field moving from
/// the fixed half into the cells cannot be absorbed by slack in the
/// other, and the proof is priced as it encodes rather than guessed.
#[test]
fn a_claims_weight_bounds_its_encoding() {
    let shard = ShardId::leaf(4, 5);
    let (store, root, keys) = spread_tree(shard, 400, 7);
    for cells in [1usize, 2, 200] {
        let claim = claim_over(&store, shard, root, &keys[..cells]);
        assert!(claim.verify().is_ok());
        let encoded = hbor_to_vec(&claim).expect("a claim encodes").len();
        assert!(
            encoded <= claim.wire_weight(),
            "a claim of {cells} cells encodes to {encoded} bytes, over the {} its weight claims",
            claim.wire_weight(),
        );
    }
    let one = claim_over(&store, shard, root, &keys[..1]);
    let empty = StateClaim {
        anchor: one.anchor,
        cells: Capped::empty(),
        crossings: Capped::empty(),
        verdicts: Capped::empty(),
        proof: MerkleInclusionProof::new(Vec::new()),
    };
    assert!(hbor_to_vec(&empty).expect("encodes").len() <= STATE_CLAIM_BYTES);
    assert_eq!(
        one.wire_weight() - empty.wire_weight(),
        STATE_CLAIM_CELL_BYTES + one.proof.as_bytes().len(),
        "one cell more costs one cell and its proof",
    );
}

/// A claim naming a member beside every cell encodes under its weight,
/// each name priced at `STATE_CLAIM_VERDICT_BYTES`.
#[test]
fn a_claim_naming_verdicts_encodes_under_its_weight() {
    let shard = ShardId::leaf(4, 5);
    let (store, root, keys) = spread_tree(shard, 400, 7);
    for cells in [1usize, 2, 200] {
        let bare = claim_over(&store, shard, root, &keys[..cells]);
        let members = (0..cells).map(|at| {
            let mut bytes = [0xFF; 32];
            bytes[..8].copy_from_slice(&(at as u64).to_be_bytes());
            TxHash::from(Hash::from_hash_bytes(&bytes))
        });
        let named = bare.clone().hearing(members);
        assert_eq!(named.verdicts.len(), cells);
        let encoded = hbor_to_vec(&named).expect("a claim encodes").len();
        assert!(
            encoded <= named.wire_weight(),
            "a claim of {cells} named cells encodes to {encoded} bytes, over the {} its weight \
             claims",
            named.wire_weight(),
        );
        assert_eq!(
            named.wire_weight() - bare.wire_weight(),
            cells * STATE_CLAIM_VERDICT_BYTES,
            "each name costs its hash",
        );
    }
}

/// A claim whose cells carry their values at the widest a value may be
/// encodes under its weight: the values are priced beside the key and
/// the reading, and the single-cell assert counts one of them.
#[test]
fn a_claim_of_held_values_encodes_under_its_weight() {
    let shard = ShardId::leaf(4, 5);
    let (store, root, keys) = spread_tree(shard, 400, 7);
    for cells in [1usize, 2, 200] {
        let bare = claim_over(&store, shard, root, &keys[..cells]);
        let holding = StateClaim::new(
            bare.anchor,
            bare.cells.iter().map(|(key, _)| {
                (
                    *key,
                    Stated::Held(Bytes::new(vec![0xFF; MAX_HELD_VALUE_BYTES]).unwrap()),
                )
            }),
            bare.proof.clone(),
        );
        let encoded = hbor_to_vec(&holding).expect("a claim encodes").len();
        assert!(
            encoded <= holding.wire_weight(),
            "a claim of {cells} held cells encodes to {encoded} bytes, over the {} its weight \
             claims",
            holding.wire_weight(),
        );
        assert_eq!(
            holding.wire_weight() - bare.wire_weight(),
            cells * (MAX_HELD_VALUE_BYTES + 4),
            "each value costs its bytes and a length prefix",
        );
    }
}

/// The figure the claims budget is derived from, measured.
///
/// A tree of twenty thousand leaves under one leaf shard's prefix,
/// spread across as many owners from a fixed seed; a thousand single
/// keys proven against it, half present and half absent; each encoded
/// as a one-cell claim; and the 99th percentile of those encodings is
/// what `SINGLE_CELL_CLAIM_P99_BYTES` states: 772 bytes, against a
/// median of 692. From it the budget is `MAX_STATE_CLAIMS_PER_BLOCK`
/// such claims rounded up to 16 KiB, 208 KiB, which is the bound that
/// binds today: the frame leaves 2,678,783 bytes, of which the bytes
/// only verdict claims spend take 65,536. At that budget a block
/// carries 275 single-cell claims at the p99, of which the count admits
/// 256.
#[test]
fn a_single_cell_claims_p99_is_what_the_budget_is_derived_from() {
    let shard = ShardId::leaf(1, 0);
    let (store, root, keys) = spread_tree(shard, 20_000, 20_000);
    let (_, _, absent) = spread_tree(shard, 500, 500);
    let asked = keys.iter().step_by(40).take(500).chain(absent.iter());
    let mut sizes: Vec<usize> = asked
        .map(|key| {
            let claim = claim_over(&store, shard, root, std::slice::from_ref(key));
            assert!(claim.verify().is_ok());
            hbor_to_vec(&claim).expect("a claim encodes").len()
        })
        .collect();
    assert_eq!(sizes.len(), 1_000);
    sizes.sort_unstable();
    let p99 = sizes[sizes.len() * 99 / 100 - 1];
    println!(
        "single-cell claim: p50 {} p99 {p99} max {} bytes; budget {MAX_STATE_CLAIMS_BYTES}, and \
         {MAX_VERDICT_CLAIMS_BYTES} for verdict claims alone, of {STATE_CLAIMS_HEADROOM} headroom",
        sizes[sizes.len() / 2],
        sizes[sizes.len() - 1],
    );
    assert_eq!(
        p99, SINGLE_CELL_CLAIM_P99_BYTES,
        "the measured p99 is what the constant states, so a change to the encoding or the \
         method moves the budget through it",
    );
    let rounding = 16 * 1024;
    assert!(
        MAX_STATE_CLAIMS_BYTES
            < (STATE_CLAIMS_HEADROOM - MAX_VERDICT_CLAIMS_BYTES) / rounding * rounding,
        "the measured bound binds, not what the frame's headroom leaves beside the verdict claims",
    );
    const {
        assert!(
            MAX_STATE_CLAIMS_PER_BLOCK * SINGLE_CELL_CLAIM_P99_BYTES <= MAX_STATE_CLAIMS_BYTES,
            "while the measured bound binds, the decode cap's count of single-cell claims at the \
             p99 fits the budget",
        );
    }
    // The bound in `hyperscale_jmt` is read off the format, which is
    // what the encoding above is; a claim cannot decode wider than it.
    let widest = sizes[sizes.len() - 1];
    assert!(widest < MAX_SINGLE_CLAIM_PROOF_BYTES);
    let _: MultiProof =
        MultiProof::decode(claim_over(&store, shard, root, &keys[..1]).proof.as_bytes())
            .expect("a claim's proof decodes");
}

/// The budget is what bounds the section, not the name count: the names
/// the drain's own bound admits, at a reach an ordinary route reaches,
/// weigh several frames.
///
/// This is the whole reason for the byte budget, so it is stated as a
/// test rather than left to the reader of two constants.
#[test]
fn the_drains_name_count_alone_would_overrun_the_frame() {
    let ordinary = name(1, 6).wire_weight();
    assert!(
        !evidence_admits_block(MAX_UNSETTLED_PER_BLOCK * ordinary),
        "the drain's {MAX_UNSETTLED_PER_BLOCK} names at {ordinary} bytes each fit the budget, \
         which would make the count the bound after all",
    );
    let admitted = MAX_PROPOSAL_EVIDENCE_BYTES / ordinary;
    assert!(
        admitted > 4_096,
        "the budget carries only {admitted} ordinary names a block, fewer than one block of \
         transactions can open",
    );
}

/// The widest abort charge: a vault and an amount at their last values.
const fn widest_charge() -> AbortCharge {
    AbortCharge {
        vault: SubstateKey {
            owner: Address::new([0xFF; 31], AddressClass::Component),
            local: LocalKey([0xFF; 16]),
        },
        amount: u128::MAX,
    }
}

/// The widest declared access, the `at`th of its member, under `mode`.
const fn widest_hold(at: usize, mode: Mode) -> (DeclaredKey, Mode) {
    (
        DeclaredKey::Range(DeclaredRange {
            owner: Address::new([0xFF; 31], AddressClass::Component),
            collection: CollectionId([0xFF; 16]),
            lo: u128::MAX - at as u128,
            hi: u128::MAX,
            cap: u32::MAX,
        }),
        mode,
    )
}

/// `count` shards at the deepest a shard is named, up to a reach's cap.
fn deepest(count: usize) -> Reach {
    Capped::new(
        (0..count.min(MAX_PREFIXES_PER_TX))
            .map(|at| ShardId::leaf(63, (u64::MAX >> 1) - at as u64))
            .collect(),
    )
    .expect("a list under the cap")
}

/// `count` reserved vaults at the widest a key and an amount encode to.
fn widest_reserves(count: usize) -> Reserves {
    Capped::new(
        (0..count)
            .map(|at| {
                (
                    SubstateKey {
                        owner: Address::new([0xFF; 31], AddressClass::Component),
                        local: LocalKey(u128::MAX.wrapping_sub(at as u128).to_be_bytes()),
                    },
                    u128::MAX,
                )
            })
            .collect(),
    )
    .expect("a list under the cap")
}

/// `count` crossings at their widest, all distinct.
fn widest_crossings(count: usize) -> Crossings {
    let widest = Address::new([0xFF; 31], AddressClass::Component);
    Capped::new(
        (0..count)
            .map(|at| CrossingId {
                producer: widest,
                consumer: widest,
                intent: IntentHash(Hash32([0xFF; 32])),
                local: u32::MAX - u32::try_from(at).expect("under the cap"),
                output: u32::MAX,
            })
            .collect(),
    )
    .expect("a list under the cap")
}

/// The latest deadline a line can state.
fn widest_deadline() -> Deadline {
    Deadline::of(WeightedTimestamp::from_millis(u64::MAX))
}

/// A tick line's weight bounds its encoding, at the widest values each
/// kind's terms encode to: a member at every count of holds, shards and
/// reserved vaults up to a transaction's worth and of stated crossings
/// up to their cap, and a discard at each cause.
#[test]
fn a_tick_lines_weight_bounds_its_encoding() {
    let widest_tx = TxHash::from(Hash::from_bytes(&[0xFF; 32]));
    let widest_charge = widest_charge();
    let hold = |at: usize| widest_hold(at, Mode::Reserve { amount: u128::MAX });
    for holds in [0usize, 1, 2, 64, MAX_HOLDS_PER_MEMBER] {
        for mode in [
            Mode::Reserve { amount: u128::MAX },
            Mode::Write { moves: Moves::Both },
        ] {
            for crossings in [0usize, 1, MAX_CROSSINGS_PER_TX] {
                let line = TickLine::Member {
                    staged: 0,
                    tx: widest_tx,
                    joins: Joins::ExecutesAborted,
                    settlement: Settlement::Awaited,
                    holds: Capped::new((0..holds).map(|at| widest_hold(at, mode)).collect())
                        .expect("a list under the cap"),
                    reach: deepest(holds),
                    awaits: deepest(holds),
                    charge: widest_charge,
                    share: u128::MAX,
                    reserves: widest_reserves(holds),
                    deadline: widest_deadline(),
                    crossings: widest_crossings(crossings),
                };
                let encoded = hbor_to_vec(&line).expect("a member line encodes");
                assert!(
                    encoded.len() <= line.wire_weight(),
                    "a member line of {holds} holds, reached and awaited shards and reserved \
                     vaults each and {crossings} stated crossings encodes to {} bytes, over the \
                     {} its weight claims",
                    encoded.len(),
                    line.wire_weight(),
                );
            }
        }
    }
    let deep = TickId::new(ShardId::leaf(9, 300), BlockHeight::new(u64::MAX));
    for cause in [
        DiscardCause::Abandoned(widest_tx),
        DiscardCause::Unanswerable(widest_tx),
        DiscardCause::Recovery,
    ] {
        let line = TickLine::Discard { tick: deep, cause };
        let encoded = hbor_to_vec(&line).expect("a discard line encodes");
        assert!(
            encoded.len() <= line.wire_weight(),
            "{cause:?} encodes to {}",
            encoded.len()
        );
        assert_eq!(line.wire_weight(), TICK_LINE_BYTES);
    }
    let fate = TickLine::Fate {
        tx: widest_tx,
        charge: widest_charge,
    };
    let encoded = hbor_to_vec(&fate).expect("a fate line encodes");
    assert!(
        encoded.len() <= fate.wire_weight(),
        "a fate encodes to {}",
        encoded.len()
    );
    assert_eq!(fate.wire_weight(), TICK_LINE_BYTES);
    let one = TickLine::Member {
        staged: 0,
        tx: widest_tx,
        joins: Joins::Executes,
        settlement: Settlement::Alone,
        holds: Capped::from_array([hold(0)]),
        reach: Capped::empty(),
        awaits: Capped::empty(),
        charge: widest_charge,
        share: u128::MAX,
        reserves: widest_reserves(1),
        deadline: widest_deadline(),
        crossings: widest_crossings(1),
    };
    assert_eq!(
        one.wire_weight(),
        TICK_LINE_BYTES + TICK_HOLD_BYTES + TICK_RESERVE_BYTES + TICK_CROSSING_BYTES,
        "one hold costs one hold, one reserved vault one, and one stated crossing one"
    );
}

/// An end line decodes to the line encoded, weighs the bare line it is
/// charged as, which bounds its encoding, and a manifest of them at the
/// line cap fits the section's budget and decodes whole.
#[test]
fn an_end_line_round_trips_within_the_bare_line_weight() {
    let end = TickLine::End {
        tx: TxHash::from(Hash::from_bytes(&[0xFF; 32])),
    };
    let encoded = hbor_to_vec(&end).expect("an end line encodes");
    assert_eq!(
        hbor_from_slice::<TickLine>(&encoded).expect("an end line decodes"),
        end,
    );
    assert!(
        encoded.len() <= end.wire_weight(),
        "an end encodes to {}",
        encoded.len()
    );
    assert_eq!(end.wire_weight(), TICK_LINE_BYTES);
    assert!(tick_manifest_admits_block(
        MAX_TICK_LINES_PER_BLOCK * end.wire_weight()
    ));

    let fate = TickLine::Fate {
        tx: TxHash::from(Hash::from_bytes(&[0xFF; 32])),
        charge: widest_charge(),
    };
    assert_ne!(
        encoded,
        hbor_to_vec(&fate).expect("a fate line encodes"),
        "an end is no fate on the wire",
    );
    let manifest: TickManifest =
        Capped::new(vec![end; MAX_TICK_LINES_PER_BLOCK]).expect("a list at the line cap");
    let bytes = hbor_to_vec(&manifest).expect("a manifest encodes");
    assert!(bytes.len() <= MAX_TICK_MANIFEST_BYTES);
    assert_eq!(
        hbor_from_slice::<TickManifest>(&bytes).expect("a manifest decodes"),
        manifest,
    );
}

/// An abort answering every crossing a transaction may consume, with
/// every other list at its cap, is one line an empty manifest carries:
/// its weight bounds its encoding and fits the section's budget, so no
/// abort waits on a budget it can never meet.
#[test]
fn a_line_at_the_crossings_cap_fits_an_empty_manifest() {
    let line = TickLine::Member {
        staged: 0,
        tx: TxHash::from(Hash::from_bytes(&[0xFF; 32])),
        joins: Joins::Aborted,
        settlement: Settlement::Awaited,
        holds: Capped::new(
            (0..MAX_HOLDS_PER_MEMBER)
                .map(|at| widest_hold(at, Mode::Reserve { amount: u128::MAX }))
                .collect(),
        )
        .expect("a list at the cap"),
        reach: deepest(MAX_PREFIXES_PER_TX),
        awaits: deepest(MAX_PREFIXES_PER_TX),
        charge: widest_charge(),
        share: u128::MAX,
        reserves: widest_reserves(MAX_HOLDS_PER_MEMBER),
        deadline: widest_deadline(),
        crossings: widest_crossings(MAX_CROSSINGS_PER_TX),
    };
    let encoded = hbor_to_vec(&line).expect("a member line encodes").len();
    assert!(
        encoded <= line.wire_weight(),
        "the line encodes to {encoded} bytes, over the {} its weight claims",
        line.wire_weight(),
    );
    assert_eq!(
        line.wire_weight(),
        TICK_LINE_BYTES
            + MAX_HOLDS_PER_MEMBER * (TICK_HOLD_BYTES + TICK_RESERVE_BYTES)
            + 2 * MAX_PREFIXES_PER_TX * TICK_REACH_BYTES
            + MAX_CROSSINGS_PER_TX * TICK_CROSSING_BYTES,
        "every list is charged at its own figure",
    );
    assert!(
        tick_manifest_admits_block(line.wire_weight()),
        "a line of {} bytes fits a {MAX_TICK_MANIFEST_BYTES} byte manifest",
        line.wire_weight(),
    );
    let manifest: TickManifest = Capped::from_array([line]);
    let decoded: TickManifest =
        hbor_from_slice(&hbor_to_vec(&manifest).expect("a manifest encodes"))
            .expect("a manifest of one line at its caps decodes");
    assert_eq!(decoded, manifest);
}

/// A terms entry at its widest in every fixed field, with `declared`
/// accesses, `shards` in each of its three reaches, `crossings`
/// crossings and `reserves` reserved vaults.
fn widest_terms(declared: usize, shards: usize, crossings: usize, reserves: usize) -> StatedTerms {
    StatedTerms {
        tx: TxHash::from(Hash::from_bytes(&[0xFF; 32])),
        terms: MemberTerms {
            staged: 0,
            leg: true,
            settlement: Settlement::Awaited,
            declared: Capped::new(
                (0..declared)
                    .map(|at| widest_hold(at, Mode::Reserve { amount: u128::MAX }))
                    .collect(),
            )
            .expect("a list under the cap"),
            reach: deepest(shards),
            awaits: deepest(shards),
            engages: deepest(shards),
            crossings: widest_crossings(crossings),
            waits: true,
            charge: widest_charge(),
            share: u128::MAX,
            reserves: widest_reserves(reserves),
        },
    }
}

/// A terms entry's weight bounds its encoding at the widest values its
/// terms encode to, with each of its lists empty, short and at its cap,
/// and each list is charged at its own figure, so a field moving from
/// the fixed half into a list cannot be absorbed by slack in another.
#[test]
fn a_terms_entry_encodes_under_its_weight() {
    let encoded = |entry: &StatedTerms| hbor_to_vec(entry).expect("an entry encodes").len();
    for declared in [0usize, 1, 2, 64, MAX_HOLDS_PER_MEMBER] {
        for crossings in [0usize, 1, MAX_CROSSINGS_PER_TX] {
            for reserves in [0usize, 1, MAX_HOLDS_PER_MEMBER] {
                let entry = widest_terms(declared, declared, crossings, reserves);
                assert!(
                    encoded(&entry) <= entry.terms.wire_weight(),
                    "an entry of {declared} declared accesses and shards in each reach, \
                     {crossings} crossings and {reserves} reserved vaults encodes to {} bytes, \
                     over the {} its weight claims",
                    encoded(&entry),
                    entry.terms.wire_weight(),
                );
            }
        }
    }

    let bare = widest_terms(0, 0, 0, 0);
    let maximal = widest_terms(
        MAX_HOLDS_PER_MEMBER,
        MAX_PREFIXES_PER_TX,
        MAX_CROSSINGS_PER_TX,
        MAX_HOLDS_PER_MEMBER,
    );
    println!(
        "terms entry: bare {} of {TICK_TERMS_BYTES}; a hold {} of {TICK_HOLD_BYTES}; a shard {} \
         of {TICK_REACH_BYTES}; a crossing {} of {TICK_CROSSING_BYTES}; a reserved vault {} of \
         {TICK_RESERVE_BYTES}; maximal {} of {} against a {MAX_TICK_TERMS_BYTES} budget",
        encoded(&bare),
        encoded(&widest_terms(65, 0, 0, 0)) - encoded(&widest_terms(64, 0, 0, 0)),
        (encoded(&widest_terms(0, 65, 0, 0)) - encoded(&widest_terms(0, 64, 0, 0))) / 3,
        encoded(&widest_terms(0, 0, 65, 0)) - encoded(&widest_terms(0, 0, 64, 0)),
        encoded(&widest_terms(0, 0, 0, 65)) - encoded(&widest_terms(0, 0, 0, 64)),
        encoded(&maximal),
        maximal.terms.wire_weight(),
    );
    assert_eq!(bare.terms.wire_weight(), TICK_TERMS_BYTES);
    assert_eq!(
        widest_terms(1, 0, 0, 0).terms.wire_weight(),
        TICK_TERMS_BYTES + TICK_HOLD_BYTES,
        "one declared access costs one hold",
    );
    assert_eq!(
        widest_terms(0, 1, 0, 0).terms.wire_weight(),
        TICK_TERMS_BYTES + 3 * TICK_REACH_BYTES,
        "one shard in each reach costs three",
    );
    assert_eq!(
        widest_terms(0, 0, 1, 0).terms.wire_weight(),
        TICK_TERMS_BYTES + TICK_CROSSING_BYTES,
        "one crossing costs one crossing",
    );
    assert_eq!(
        widest_terms(0, 0, 0, 1).terms.wire_weight(),
        TICK_TERMS_BYTES + TICK_RESERVE_BYTES,
        "one reserved vault costs one",
    );
    assert!(
        tick_terms_admit_block(maximal.terms.wire_weight()),
        "the widest entry fits an empty section",
    );
}

/// The elided block's own wire shape, written out so a response can be
/// built with every body absent and every list at its cap, which no
/// block a test could assemble reaches.
#[derive(Hbor)]
struct ResponseWire {
    header: BlockHeader,
    qc: QuorumCertificate,
    transactions: Vec<(TxHash, Option<Arc<Verifiable<Transaction>>>)>,
    certificates: Vec<(FinalizationHash, Option<Arc<Verifiable<Finalization>>>)>,
    provisions: ProvisionsWire,
    abandonment_records: Vec<AbandonmentRecord>,
    state_claims: Vec<StateClaim>,
    tick_manifest: Vec<TickLine>,
    terms: Vec<StatedTerms>,
    witness_sources: WitnessSources,
}

/// The provisions payload of [`ResponseWire`], in both forms.
#[derive(Hbor)]
enum ProvisionsWire {
    Live(Vec<(ProvisionHash, Option<Arc<Verifiable<Provisions>>>)>),
    Sealed {
        hashes: Vec<ProvisionHash>,
        engagements: Vec<Engagement>,
    },
}

/// A hash that is a function of `at`, for a list of distinct ones.
fn hash_at(at: usize) -> Hash {
    Hash::from_bytes(&at.to_le_bytes())
}

/// One record carrying as many names as the evidence budget admits.
fn full_record() -> AbandonmentRecord {
    let ordinary = name(1, 6);
    let names = (MAX_PROPOSAL_EVIDENCE_BYTES - ABANDONMENT_RECORD_BYTES) / ordinary.wire_weight();
    let record = AbandonmentRecord::new(
        ShardId::leaf(9, 300),
        WeightedTimestamp::from_millis(u64::MAX / 2),
        (0..names).map(|at| UnsettledTx {
            tx_hash: TxHash::from(hash_at(at)),
            ..ordinary.clone()
        }),
    );
    assert!(evidence_admits_block(record.wire_weight()));
    assert!(!evidence_admits_block(
        record.wire_weight() + ordinary.wire_weight()
    ));
    record
}

/// Claims of four cells each, as many as the claims budget admits.
fn full_claims() -> Vec<StateClaim> {
    let shard = ShardId::leaf(4, 5);
    let (store, root, keys) = spread_tree(shard, 2_000, 11);
    let mut claims = Vec::new();
    let mut weight = 0;
    for asked in keys.chunks(4) {
        let claim = claim_over(&store, shard, root, asked);
        if !state_claims_admit_block(weight + claim.wire_weight()) {
            break;
        }
        weight += claim.wire_weight();
        claims.push(claim);
    }
    assert!(
        claims.len() < MAX_STATE_CLAIMS_PER_BLOCK && claims.len() < keys.len() / 4,
        "the budget is what stopped the fill",
    );
    claims
}

/// Verdict claims of four named cells each, as many as the bytes only
/// verdict claims spend hold, anchored above [`full_claims`] so the two
/// make one section at its budget.
fn full_verdict_claims() -> Vec<StateClaim> {
    let shard = ShardId::leaf(4, 6);
    let (store, root, keys) = spread_tree(shard, 2_000, 13);
    let mut claims = Vec::new();
    let mut weight = 0;
    for (at, asked) in keys.chunks(4).enumerate() {
        let members = (0..asked.len()).map(|cell| {
            let mut bytes = [0xFF; 32];
            bytes[..8].copy_from_slice(&((at * 4 + cell) as u64).to_be_bytes());
            TxHash::from(Hash::from_hash_bytes(&bytes))
        });
        let claim = claim_over(&store, shard, root, asked).hearing(members);
        if weight + claim.wire_weight() > MAX_VERDICT_CLAIMS_BYTES {
            break;
        }
        weight += claim.wire_weight();
        claims.push(claim);
    }
    assert!(
        claims.len() < MAX_CLAIMS_PER_BLOCK - MAX_STATE_CLAIMS_PER_BLOCK
            && claims.len() < keys.len() / 4,
        "the bytes are what stopped the fill",
    );
    assert!(claims.iter().all(StateClaim::is_verdict_claim));
    claims
}

/// Member lines of sixty-four holds, reserved vaults, stated crossings
/// and shards in each reach, as many as the tick manifest's budget
/// admits.
fn full_manifest() -> Vec<TickLine> {
    let line = TickLine::Member {
        staged: 0,
        tx: TxHash::from(Hash::from_bytes(&[0xFF; 32])),
        joins: Joins::ExecutesAborted,
        settlement: Settlement::Awaited,
        holds: Capped::new(
            (0..64)
                .map(|at| widest_hold(at, Mode::Reserve { amount: u128::MAX }))
                .collect(),
        )
        .expect("a list under the cap"),
        reach: deepest(64),
        awaits: deepest(64),
        charge: widest_charge(),
        share: u128::MAX,
        reserves: widest_reserves(64),
        deadline: widest_deadline(),
        crossings: widest_crossings(64),
    };

    let lines = vec![line.clone(); MAX_TICK_MANIFEST_BYTES / line.wire_weight()];
    assert!(lines.len() < MAX_TICK_LINES_PER_BLOCK);
    lines
}

/// Terms entries of sixty-four of each list, as many as the terms budget
/// admits.
fn full_terms() -> Vec<StatedTerms> {
    let entry = widest_terms(64, 64, 64, 64);
    let entries = vec![entry.clone(); MAX_TICK_TERMS_BYTES / entry.terms.wire_weight()];
    assert!(entries.len() < MAX_TXS_PER_BLOCK);
    assert!(!tick_terms_admit_block(
        (entries.len() + 1) * entry.terms.wire_weight()
    ));
    entries
}

/// A header naming a provision root for every shard a block may target,
/// and a certificate over it.
fn widest_header() -> (BlockHeader, QuorumCertificate) {
    let header = BlockHeader::new(BlockHeaderParts {
        shard_id: ShardId::leaf(63, u64::MAX >> 1),
        height: BlockHeight::new(u64::MAX),
        provision_tx_roots: Capped::new(
            (0..MAX_PROVISION_TARGET_SHARDS)
                .map(|at| {
                    (
                        ShardId::leaf(63, (u64::MAX >> 1) - at as u64),
                        ProvisionTxRoot::from_raw(hash_at(at)),
                    )
                })
                .collect(),
        )
        .expect("a map at its cap"),
        ..Default::default()
    });
    let qc = QuorumCertificate::new(
        header.hash(),
        header.shard_id(),
        header.height(),
        header.parent_block_hash(),
        header.round(),
        SignerBitfield::new(0),
        AggregateSignature::ZERO,
        WeightedTimestamp::from_millis(u64::MAX / 2),
    );
    (header, qc)
}

/// The engagements a sealed block keeps at their cap, each at its widest.
fn full_engagements() -> Vec<Engagement> {
    (0..MAX_ENGAGEMENTS_PER_BLOCK)
        .map(|at| Engagement {
            source: ShardId::leaf(63, u64::MAX >> 1),
            tx_hash: TxHash::from(hash_at(at)),
            source_height: BlockHeight::new(u64::MAX),
        })
        .collect()
}

/// A block fetch response with every body elided, every hash list at its
/// cap and the record, claim, tick manifest and terms sections each
/// filled to its byte budget encodes within
/// [`BLOCK_RESPONSE_INLINE_BYTES`], in the live form and the sealed one.
///
/// The response is what a peer is sent before any body rides in it, so
/// this is what says a block whose terms section is full can still be
/// synced: 8,294,656 bytes of the frame's 10,485,760 at the most, the
/// terms section 4,194,304 of them.
#[test]
fn a_block_response_with_a_full_terms_section_fits_the_frame() {
    let (header, qc) = widest_header();
    let provision_hashes: Vec<ProvisionHash> = (0..MAX_PROVISIONS_PER_BLOCK)
        .map(|at| ProvisionHash::from_raw(hash_at(at)))
        .collect();
    let engagements = full_engagements();
    let engagement_bytes = hbor_to_vec(&engagements).expect("engagements encode").len();
    assert!(engagement_bytes <= MAX_ENGAGEMENTS_PER_BLOCK * ENGAGEMENT_BYTES);
    let (record, mut claims, lines, entries) =
        (full_record(), full_claims(), full_manifest(), full_terms());
    claims.extend(full_verdict_claims());

    for sealed in [false, true] {
        let wire = ResponseWire {
            header: header.clone(),
            qc: qc.clone(),
            transactions: (0..MAX_TXS_PER_BLOCK)
                .map(|at| (TxHash::from(hash_at(at)), None))
                .collect(),
            certificates: (0..MAX_FINALIZED_TX_PER_BLOCK)
                .map(|at| (FinalizationHash::from_raw(hash_at(at)), None))
                .collect(),
            provisions: if sealed {
                ProvisionsWire::Sealed {
                    hashes: provision_hashes.clone(),
                    engagements: engagements.clone(),
                }
            } else {
                ProvisionsWire::Live(provision_hashes.iter().map(|hash| (*hash, None)).collect())
            },
            abandonment_records: vec![record.clone()],
            state_claims: claims.clone(),
            tick_manifest: lines.clone(),
            terms: entries.clone(),
            witness_sources: WitnessSources::empty(),
        };
        let bytes = hbor_to_vec(&wire).expect("a response encodes");
        let response: ElidedCertifiedBlock =
            hbor_from_slice(&bytes).expect("the shape written out is the response's own");
        assert_eq!(
            hbor_to_vec(&response).expect("a response encodes"),
            bytes,
            "and the response encodes back to the same bytes",
        );
        assert_eq!(response.transactions().len(), MAX_TXS_PER_BLOCK);
        println!(
            "block response, {}: {} bytes of {BLOCK_RESPONSE_INLINE_BYTES} inline, in a frame \
             of {MAX_WIRE_MESSAGE_BYTES}; engagements {engagement_bytes}",
            if sealed { "sealed" } else { "live" },
            bytes.len(),
        );
        assert!(
            bytes.len() <= BLOCK_RESPONSE_INLINE_BYTES,
            "a response with every section full encodes to {} bytes, over the {} it is bounded at",
            bytes.len(),
            BLOCK_RESPONSE_INLINE_BYTES,
        );
    }
    const {
        assert!(BLOCK_RESPONSE_INLINE_BYTES < MAX_WIRE_MESSAGE_BYTES);
    }
}

/// A terminal-lines response encodes under the bound it is budgeted at
/// and decodes whole, both with the manifest at the section's byte
/// budget and with a manifest of end lines at the line cap.
#[test]
fn a_terminal_lines_response_over_a_full_manifest_fits_the_frame() {
    let (header, _) = widest_header();
    let ends = vec![
        TickLine::End {
            tx: TxHash::from(Hash::from_bytes(&[0xFF; 32])),
        };
        MAX_TICK_LINES_PER_BLOCK
    ];

    for (shape, lines) in [("widest lines", full_manifest()), ("end lines", ends)] {
        let response = GetTerminalLinesResponse::found(TerminalLines {
            header: header.clone(),
            roots: SectionRoots::EMPTY,
            manifest: Capped::new(lines).expect("a manifest within the line cap"),
        });
        let bytes = hbor_to_vec(&response).expect("a response encodes");
        assert_eq!(
            hbor_from_slice::<GetTerminalLinesResponse>(&bytes).expect("a response decodes"),
            response,
        );
        println!(
            "terminal-lines response, {shape}: {} bytes of {MAX_TERMINAL_LINES_RESPONSE_BYTES}, \
             in a frame of {MAX_WIRE_MESSAGE_BYTES}",
            bytes.len(),
        );
        assert!(
            bytes.len() <= MAX_TERMINAL_LINES_RESPONSE_BYTES,
            "a response over a full manifest encodes to {} bytes, over the {} it is bounded at",
            bytes.len(),
            MAX_TERMINAL_LINES_RESPONSE_BYTES,
        );
    }
    const {
        assert!(MAX_TERMINAL_LINES_RESPONSE_BYTES < MAX_WIRE_MESSAGE_BYTES);
    }
}

/// `seed`'s effects receipt, writing one cell `width` bytes wide and
/// stating the hash its content recomputes to.
fn effects(seed: u32, width: usize) -> StoredReceipt {
    let mut writes = StateWrites::default();
    writes.cells.insert(
        SubstateKey {
            owner: Address::new([0xAB; 31], AddressClass::Component),
            local: LocalKey(
                Hash::from_bytes(&seed.to_be_bytes()).as_bytes()[..16]
                    .try_into()
                    .expect("16 bytes"),
            ),
        },
        Some(vec![0xCD; width]),
    );
    let unhashed = ConsensusReceipt::Succeeded {
        receipt_hash: GlobalReceiptHash::ZERO,
        writes,
        beacon_witness_events: Capped::empty(),
        events: Capped::empty(),
    };
    let receipt_hash = receipt_hash_of(&unhashed, true).expect("a projected success");
    let ConsensusReceipt::Succeeded { writes, .. } = unhashed else {
        unreachable!("built a success")
    };
    StoredReceipt::new(
        TxHash::from(Hash::from_bytes(&seed.to_be_bytes())),
        Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash,
            writes,
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        }),
    )
}

/// A refused member's outcome beside its refusal receipt, a charge at its
/// widest.
fn refused(seed: usize, sibling: ShardId) -> (TxOutcome, StoredReceipt) {
    let tx_hash = TxHash::from(Hash::from_bytes(&(seed as u64 | 1 << 63).to_be_bytes()));
    let mut writes = StateWrites::default();
    writes.movements.insert(
        SubstateKey {
            owner: Address::new([0xEE; 31], AddressClass::Component),
            local: LocalKey([0xEE; 16]),
        },
        Movement::unjudged(ResourceAddr::new([0xFE; 31]), u128::MAX),
    );
    let refusal = StoredReceipt::new(
        tx_hash,
        Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(tx_hash.as_bytes())),
            writes,
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        }),
    );
    let outcome = TxOutcome::with_refusal(
        tx_hash,
        ExecutionOutcome::Failed,
        refusal.consensus.receipt_hash(),
    )
    .charging(u128::MAX)
    .awaiting([sibling])
    .as_role(Role::Core);
    (outcome, refusal)
}

/// A stating half of a full tick encodes within the frame: yes receipts
/// staging [`MAX_TICK_STAGED_BYTES`] between them, each at the receipt
/// cap, beside a refused member for every other transaction a block may
/// carry, each with its charge, and the certificate over all of them.
#[test]
fn a_stating_half_of_a_full_tick_encodes_within_the_frame() {
    let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
    let sibling = ShardId::leaf(1, 1);
    // The value's length prefix widens with it, so the width is the
    // widest at which the receipt still meets the cap.
    let width = (0..=usize::try_from(MAX_STAGED_RECEIPT_BYTES).expect("a cell width"))
        .rev()
        .find(|&width| staged_yes_bytes(&effects(0, width).consensus) <= MAX_STAGED_RECEIPT_BYTES)
        .expect("an empty receipt meets the cap");
    let yes_count = u32::try_from(MAX_TICK_STAGED_BYTES / MAX_STAGED_RECEIPT_BYTES).expect("few");
    let yeses: Vec<StoredReceipt> = (0..yes_count).map(|seed| effects(seed, width)).collect();
    let staged: u64 = yeses
        .iter()
        .map(|receipt| staged_yes_bytes(&receipt.consensus))
        .sum();
    assert!(staged <= MAX_TICK_STAGED_BYTES);
    assert!(staged + MAX_STAGED_RECEIPT_BYTES > MAX_TICK_STAGED_BYTES);

    let mut outcomes = Vec::new();
    let mut receipts = Vec::new();
    for receipt in &yeses {
        outcomes.push(
            TxOutcome::new(
                receipt.tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: receipt.consensus.receipt_hash(),
                },
            )
            .charging(u128::MAX)
            .awaiting([sibling])
            .as_role(Role::Core),
        );
        receipts.push(receipt.clone());
    }
    let refusing = MAX_TXS_PER_BLOCK - yeses.len();
    for seed in 0..refusing {
        let (outcome, refusal) = refused(seed, sibling);
        outcomes.push(outcome);
        receipts.push(refusal);
    }
    let certificate = ExecutionCertificate::new(
        tick_id,
        WeightedTimestamp::from_millis(u64::MAX),
        compute_global_receipt_root(&outcomes),
        Capped::new(outcomes).expect("a full tick's outcomes"),
        AggregateSignature::ZERO,
        SignerBitfield::new(1024),
    );
    let half = Finalization::new(
        tick_id,
        TickHalf::Stated,
        Some(Arc::new(certificate)),
        Capped::new(receipts).expect("a receipt per outcome"),
    );
    assert_eq!(half.validate_against_certificates(), Ok(()));
    let bytes = hbor_to_vec(&half).expect("a stating half encodes");
    println!(
        "a stating half of a full tick: {} bytes in a frame of {MAX_WIRE_MESSAGE_BYTES}",
        bytes.len(),
    );
    assert!(
        bytes.len() <= MAX_WIRE_MESSAGE_BYTES,
        "a stating half of a full tick encodes to {} bytes, past the frame",
        bytes.len(),
    );
    assert_eq!(
        hbor_from_slice::<Finalization>(&bytes).expect("and decodes"),
        half
    );
}
