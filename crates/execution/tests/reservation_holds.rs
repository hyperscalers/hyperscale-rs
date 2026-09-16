//! What a provisional leg holds, at the seam where tick outputs are
//! accumulated: a completed leg holds exactly its declared reservations,
//! and a leg that failed holds nothing.
//!
//! The kernel refuses a reservation by failing its transaction whole —
//! judging runs before execution, so a refused leg never runs, and every
//! abort is a `Failed` receipt carrying no writes. The writes gate in
//! `accumulate_tick_output` therefore separates granted from refused
//! without re-asking the kernel: a receipt with writes is a leg whose
//! every declared reservation was granted at its declared amount, and a
//! receipt without writes granted none.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_core::CrossShardExecutionRequest;
use hyperscale_engine::ExecutedTx;
use hyperscale_engine::legs::{Classified, Member, Runs, Side};
use hyperscale_execution::action_handlers::accumulate_tick_output;
use hyperscale_storage::TickOutput;
use hyperscale_types::test_utils::StubTree;
use hyperscale_types::{
    Address, AddressClass, CollectionId, ConsensusReceipt, DeclaredKey, DeclaredRange,
    DeclaredWork, Derivation, DerivationError, Derived, ExecutionMetadata, GlobalReceiptHash, Hash,
    LocalKey, Mode, NetworkId, PriceTable, PrincipalAddr, Routing, ShardId, StateWrites,
    SubstateKey, Terms, TimestampRange, Transaction, TransactionEnvelope, TxHash, Verified,
    WeightedTimestamp,
};
use hyperscale_vm_types::{Moves, attestation_work};

/// The two amount cells every fixture transaction declares a reservation
/// on. Real derivation folds duplicate reservations per cell before the
/// declaration leaves the bridge, so each cell appears once, at its
/// folded amount.
const fn payer_vault() -> SubstateKey {
    SubstateKey {
        owner: Address::new([0x11; 31], AddressClass::Component),
        local: LocalKey([0xEE; 16]),
    }
}

const fn counterparty_vault() -> SubstateKey {
    SubstateKey {
        owner: Address::new([0x22; 31], AddressClass::Component),
        local: LocalKey([0xEE; 16]),
    }
}

/// Statics under which every transaction declares two cell reservations,
/// an exclusive write, and a range delta — the last two being what hold
/// accounting must ignore: an exclusive write is not a reservation, and
/// a reservation targets an amount cell, which no range is.
struct ReservingStatics;

impl Derivation for ReservingStatics {
    fn derive(&self, vm: &TransactionEnvelope) -> Result<Derived, DerivationError> {
        let written = DeclaredKey::Cell(SubstateKey {
            owner: Address::new([0x33; 31], AddressClass::Component),
            local: LocalKey([0x01; 16]),
        });
        let ranged = DeclaredKey::Range(DeclaredRange {
            owner: Address::new([0x44; 31], AddressClass::Component),
            collection: CollectionId([7; 16]),
            lo: 0,
            hi: 10,
            cap: 8,
        });
        let mut declared_modes = vec![
            (
                DeclaredKey::Cell(payer_vault()),
                Mode::Reserve { amount: 60 },
            ),
            (
                DeclaredKey::Cell(counterparty_vault()),
                Mode::Reserve { amount: 25 },
            ),
            (written, Mode::Write { moves: Moves::Both }),
            (ranged, Mode::Delta { moves: Moves::Both }),
        ];
        declared_modes.sort_unstable();
        let stub = StubTree::decode(vm)?;
        let work = DeclaredWork {
            compute: stub.terms.gas_limit_total(),
            footprint: 4,
            ..DeclaredWork::ZERO
        }
        .saturating_add(attestation_work(&vm.signatures));
        Ok(Derived {
            accounts: Vec::new(),
            // This stub derives no tree; the root's window stands.
            effective_window: stub.window(),
            network: stub.network,
            routing: Routing {
                read_keys: Vec::new(),
                write_keys: declared_modes.iter().map(|(key, _)| *key).collect(),
                read_prefixes: Vec::new(),
                write_prefixes: declared_modes.iter().map(|(key, _)| key.owner()).collect(),
                provision_keys: Vec::new(),
                provision_prefixes: Vec::new(),
                declared_modes,
            },
            attested_by: vec![stub.terms.fee_payer],
            attestations: Vec::new(),
            fee_vault_local: [0xEE; 16],
            auth_cell_local: [0xAE; 16],
            work,
            shares: Vec::new(),
            node_terms: Vec::new(),
            artifacts: Vec::new(),
            everywhere: work,
            legs: Vec::new(),
            nullifiers: Vec::new(),
            packages: Vec::new(),
            terms: stub.terms,
        })
    }
}

/// A transaction distinguished only by `seed`; its declaration is fixed
/// by [`ReservingStatics`].
fn reserving_transaction(seed: u8) -> Arc<Verified<Transaction>> {
    let vm = StubTree {
        terms: Terms {
            fee_payer: PrincipalAddr::new([0xAA; 31]),
            max_fee: 1_000,
            gas_limits: vec![1_000_000],
            priority_bp: 0,
            message: Vec::new(),
        },
        network: NetworkId(242),
        members: 0,
        validity: TimestampRange::new(
            WeightedTimestamp::from_millis(0),
            WeightedTimestamp::from_millis(u64::MAX),
        ),
        body: vec![seed],
    }
    .envelope();
    let tx = Transaction::new(vm);
    tx.try_derived(&ReservingStatics)
        .expect("the fixture declaration is fixed");
    Arc::new(Verified::<Transaction>::from_persisted(tx))
}

/// A request for `tx` as a whole shape reaching a counterpart: a member
/// whose verdict that counterpart can still discard, so its declared
/// cells are held against it.
fn request_for(tx: &Arc<Verified<Transaction>>) -> CrossShardExecutionRequest {
    let (local, counterpart) = ShardId::ROOT.children();
    CrossShardExecutionRequest {
        prices: PriceTable::GENESIS,
        tx_hash: tx.hash(),
        transaction: Some(Arc::clone(tx)),
        provisions: Vec::new(),
        clock: WeightedTimestamp::from_millis(1_000),
        runs: Runs::Shape(Member::of(
            Classified::whole(),
            local,
            Side::Issuing,
            BTreeSet::from([local, counterpart]),
        )),
        arrivals: Vec::new(),
    }
}

fn succeeded(tx_hash: TxHash) -> ExecutedTx {
    ExecutedTx::new(
        tx_hash,
        ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"receipt")),
            writes: StateWrites::default(),
            beacon_witness_events: Vec::new(),
            events: Vec::new(),
        },
        ExecutionMetadata::empty(),
    )
}

#[test]
fn a_completed_leg_holds_its_declared_reservations() {
    let tx = reserving_transaction(1);
    let requests = vec![request_for(&tx)];
    let executed = vec![succeeded(tx.hash())];

    let mut output = TickOutput::default();
    accumulate_tick_output(&mut output, &requests, &executed);

    assert_eq!(output.provisional.len(), 1);
    let leg = &output.provisional[0];
    assert!(leg.writes.is_some(), "a completed leg carries its writes");
    assert_eq!(
        leg.reserved,
        BTreeMap::from([(payer_vault(), 60), (counterparty_vault(), 25)]),
        "each declared cell reservation is held at its declared amount; \
         the exclusive write and the range are not reservations"
    );
}

#[test]
fn a_failed_leg_holds_nothing_against_its_declaration() {
    let tx = reserving_transaction(2);
    let requests = vec![request_for(&tx)];
    let executed = vec![ExecutedTx::failure(tx.hash())];

    let mut output = TickOutput::default();
    accumulate_tick_output(&mut output, &requests, &executed);

    assert_eq!(output.provisional.len(), 1);
    let leg = &output.provisional[0];
    assert!(leg.writes.is_none(), "a failed attempt produced no effects");
    assert!(
        leg.reserved.is_empty(),
        "a leg that failed granted no reservation, whatever it declared: {:?}",
        leg.reserved
    );
}
