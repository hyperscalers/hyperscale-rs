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

use hyperscale_hbor::{Bytes, Capped, to_vec as hbor_to_vec};
use hyperscale_jmt::{
    Blake3Hasher, Key as JmtKey, LeafValue, MAX_SINGLE_CLAIM_PROOF_BYTES, MemoryStore, MultiProof,
    NodeKey, Tree,
};
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    ABANDONMENT_RECORD_BYTES, AbandonmentRecord, AbortCharge, Address, AddressClass, Anchor,
    BlockHeight, CommittedAt, Deadline, ESCROWED_RECORD_BYTES, Hash, LocalKey, MAX_ARTIFACT_BYTES,
    MAX_ENVELOPE_BYTES, MAX_HELD_VALUE_BYTES, MAX_PROPOSAL_EVIDENCE_BYTES, MAX_STATE_CLAIMS_BYTES,
    MAX_STATE_CLAIMS_PER_BLOCK, MAX_UNSETTLED_PER_BLOCK, MerkleInclusionProof, ROUTE_PREFIX_BYTES,
    RoutePrefix, SINGLE_CELL_CLAIM_P99_BYTES, STATE_CLAIM_BYTES, STATE_CLAIM_CELL_BYTES,
    STATE_CLAIMS_HEADROOM, SchemeId, ShardId, StateClaim, StateRoot, Stated, SubstateKey,
    TransactionEnvelope, TxHash, UNSETTLED_TX_BYTES, UnclaimedCrossing, UnsettledTx,
    WeightedTimestamp, evidence_admits_block, shard_prefix_path,
};

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
        escrowed: Capped::empty(),
    }
}

/// The fixed and per-route halves of a name's weight each bound what
/// HBOR writes.
///
/// Measured at two reaches rather than one, so a field moving from the
/// fixed half into the reach cannot be absorbed by slack in the other.
#[test]
fn a_names_weight_bounds_its_encoding() {
    for (routes, records) in [(0, 0), (1, 1), (2, 2), (6, 0), (64, 128), (512, 128)] {
        let name = UnsettledTx {
            escrowed: Capped::new(
                (0..records)
                    .map(|at| SubstateKey {
                        owner: Address::new([0xFF; 31], AddressClass::Component),
                        local: LocalKey(u128::MAX.wrapping_sub(at).to_be_bytes()),
                    })
                    .collect(),
            )
            .expect("a list under the cap"),
            ..name(1, routes)
        };
        let encoded = hbor_to_vec(&name).expect("a name encodes");
        assert!(
            encoded.len() <= name.wire_weight(),
            "a name reaching {routes} routes with {records} records encodes to {} bytes, over the \
             {} its weight claims",
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
    assert_eq!(
        UnsettledTx {
            escrowed: Capped::from_array([key(2)]),
            ..name(1, 0)
        }
        .wire_weight()
            - name(1, 0).wire_weight(),
        ESCROWED_RECORD_BYTES,
        "and one escrowed record costs one key",
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

    // A crossing named off its leaf costs its fixed width, at the widest
    // values each term encodes to.
    for crossings in [1usize, 2, 64] {
        let record = AbandonmentRecord::new(
            deep,
            WeightedTimestamp::from_millis(u64::MAX),
            (0..crossings).map(|at| name(u8::try_from(at % 256).expect("masked"), 64)),
        )
        .with_unclaimed((0..crossings).map(|at| UnclaimedCrossing {
            record: SubstateKey {
                owner: Address::new([0xFF; 31], AddressClass::Component),
                local: LocalKey(u128::MAX.wrapping_sub(at as u128).to_be_bytes()),
            },
            tx: TxHash::from(Hash::from_bytes(&[0xFF; 32])),
            consumer: RoutePrefix::of(Address::new([0xFF; 31], AddressClass::Component)),
            validity_end: WeightedTimestamp::from_millis(u64::MAX),
        }));
        let encoded = hbor_to_vec(&record).expect("a record encodes");
        assert!(
            encoded.len() <= record.wire_weight(),
            "a record naming {crossings} crossings encodes to {} bytes, over the {} its weight \
             claims",
            encoded.len(),
            record.wire_weight(),
        );
    }
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
        proof: MerkleInclusionProof::new(Vec::new()),
    };
    assert!(hbor_to_vec(&empty).expect("encodes").len() <= STATE_CLAIM_BYTES);
    assert_eq!(
        one.wire_weight() - empty.wire_weight(),
        STATE_CLAIM_CELL_BYTES + one.proof.as_bytes().len(),
        "one cell more costs one cell and its proof",
    );
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
/// what `SINGLE_CELL_CLAIM_P99_BYTES` states: 770 bytes, against a
/// median of 690. From it the budget is `MAX_STATE_CLAIMS_PER_BLOCK`
/// such claims rounded up to 16 KiB, 208 KiB, which is the bound that
/// binds today: the frame leaves 8,970,239 bytes. At that budget the
/// section carries 276 single-cell claims at the p99, of which the
/// decode cap admits 256.
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
        "single-cell claim: p50 {} p99 {p99} max {} bytes; budget {MAX_STATE_CLAIMS_BYTES} of \
         {STATE_CLAIMS_HEADROOM} headroom",
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
        MAX_STATE_CLAIMS_BYTES < STATE_CLAIMS_HEADROOM / rounding * rounding,
        "the measured bound binds, not the frame's headroom",
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

/// A tick line's weight bounds its encoding, at the widest values each
/// kind's terms encode to: a member at every count of holds up to a
/// transaction's worth, and a discard at each cause.
#[test]
fn a_tick_lines_weight_bounds_its_encoding() {
    use hyperscale_types::{
        CollectionId, DeclaredKey, DeclaredRange, DiscardCause, Joins, MAX_HOLDS_PER_MEMBER,
        Settlement, TICK_HOLD_BYTES, TICK_LINE_BYTES, TickId, TickLine,
    };
    use hyperscale_vm_types::{Mode, Moves};

    let widest_tx = TxHash::from(Hash::from_bytes(&[0xFF; 32]));
    let widest_owner = Address::new([0xFF; 31], AddressClass::Component);
    let hold = |at: usize| {
        (
            DeclaredKey::Range(DeclaredRange {
                owner: widest_owner,
                collection: CollectionId([0xFF; 16]),
                lo: u128::MAX - at as u128,
                hi: u128::MAX,
                cap: u32::MAX,
            }),
            Mode::Reserve { amount: u128::MAX },
        )
    };
    for holds in [0usize, 1, 2, 64, MAX_HOLDS_PER_MEMBER] {
        for mode in [
            Mode::Reserve { amount: u128::MAX },
            Mode::Write { moves: Moves::Both },
        ] {
            let line = TickLine::Member {
                tx: widest_tx,
                joins: Joins::ExecutesAborted,
                settlement: Settlement::Awaited,
                holds: Capped::new((0..holds).map(|at| (hold(at).0, mode)).collect())
                    .expect("a list under the cap"),
            };
            let encoded = hbor_to_vec(&line).expect("a member line encodes");
            assert!(
                encoded.len() <= line.wire_weight(),
                "a member line of {holds} holds encodes to {} bytes, over the {} its weight \
                 claims",
                encoded.len(),
                line.wire_weight(),
            );
        }
    }
    let deep = TickId::new(ShardId::leaf(9, 300), BlockHeight::new(u64::MAX));
    for cause in [
        DiscardCause::Abandoned(widest_tx),
        DiscardCause::Unanswerable(widest_tx),
        DiscardCause::Rejected,
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
    let one = TickLine::Member {
        tx: widest_tx,
        joins: Joins::Executes,
        settlement: Settlement::Alone,
        holds: Capped::from_array([hold(0)]),
    };
    assert_eq!(
        one.wire_weight(),
        TICK_LINE_BYTES + TICK_HOLD_BYTES,
        "one hold costs one hold"
    );
}
