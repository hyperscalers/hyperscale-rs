//! What the proposal wire budget's arithmetic rests on.
//!
//! `limits.rs` asserts at compile time that a proposal with every section
//! at its cap fits [`MAX_WIRE_MESSAGE_BYTES`], out of a per-item byte
//! figure for each section. That assertion is only worth as much as those
//! figures, and nothing in the type system ties them to what HBOR
//! actually writes. So they are tied here: each is measured against a
//! maximal value of its type, and a widened field fails this before it
//! can quietly overrun the frame.

use hyperscale_hbor::to_vec as hbor_to_vec;
use hyperscale_types::{
    ABANDONMENT_RECORD_BYTES, AbandonmentRecord, AbortCharge, Address, AddressClass, Anchor,
    BlockHeight, Deadline, Hash, Inclusion, LocalKey, MAX_PROPOSAL_EVIDENCE_BYTES,
    MAX_UNSETTLED_PER_BLOCK, ROUTE_PREFIX_BYTES, RoutePrefix, ShardId, StateClaim, StateRoot,
    SubstateKey, TxHash, UNSETTLED_TX_BYTES, UnsettledTx, WeightedTimestamp, evidence_admits_block,
};

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
        declared_work: u64::MAX,
        charge: AbortCharge {
            vault: key(seed),
            amount: u128::MAX,
        },
        reach: (0..routes)
            .map(|at| {
                RoutePrefix::from(Address::new(
                    [u8::try_from(at % 256).expect("masked"); 31],
                    AddressClass::Component,
                ))
            })
            .collect(),
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

/// The per-cell figure the compile-time assertion prices state claims at
/// bounds what a claim encodes, at its widest reading.
///
/// A presence carries a value hash and an absence does not, so the
/// presence is what has to fit.
#[test]
fn a_claims_cells_encode_under_the_figure_the_frame_is_budgeted_at() {
    /// The figure `limits.rs` prices a claim's cell at.
    const CELL_BYTES: usize = 82;
    /// The figure it prices a claim's own terms at.
    const CLAIM_BYTES: usize = 64;

    let anchor = Anchor {
        shard: ShardId::leaf(9, 300),
        height: BlockHeight::new(u64::MAX / 2),
        state_root: StateRoot::from_raw(Hash::from_bytes(b"root")),
        ts: WeightedTimestamp::from_millis(u64::MAX / 2),
    };
    let claim = |cells: usize| {
        StateClaim::new(
            anchor,
            (0..cells).map(|at| {
                (
                    key(u8::try_from(at % 256).expect("masked")),
                    Inclusion::Present([0xFF; 32]),
                )
            }),
        )
    };
    for cells in [1usize, 2, 200] {
        let encoded = hbor_to_vec(&claim(cells)).expect("a claim encodes");
        assert!(
            encoded.len() <= CLAIM_BYTES + cells * CELL_BYTES,
            "a claim of {cells} cells encodes to {} bytes, over the {} the frame budgets it at",
            encoded.len(),
            CLAIM_BYTES + cells * CELL_BYTES,
        );
    }
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
