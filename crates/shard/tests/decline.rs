//! A decline driven through consensus: a proposer offered an escrowed
//! record nobody on its chain can take builds a block that reads the
//! record's row absent at its parent, the committee votes it, and the
//! committed block's fold writes the `Never`.

mod common;

use common::ShardCoordinatorSim;
use hyperscale_hbor::Bytes;
use hyperscale_storage::member_row_leaf;
use hyperscale_types::test_utils::{state_and_proof_holding, test_key};
use hyperscale_types::{
    Address, AddressClass, Anchor, BlockHeight, Hash, Inclusion, ShardTrie, StateClaim, Stated,
    TxHash, WeightedTimestamp,
};
use hyperscale_vm_effects::{Answered, CrossingId, Hash32, IntentHash, ProtocolHasher, Terms};
use hyperscale_vm_types::ResourceAddr;

/// Step budget for a run of a few blocks.
const MAX_STEPS: usize = 50_000;

/// A block declining a record is built by the production handler, voted
/// on and committed by every replica, and lands the `Never`.
///
/// The chain is the left of two shards and holds the crossing's
/// consumer; the record sits on the right, issued by a transaction this
/// chain never committed, its validity end passed. Every replica holds
/// the record's anchor as proven and the proposer is offered the
/// reading. The block that carries it carries the issuer's row leaf read
/// absent at its parent beside it, every voter's parent checks pass it,
/// and each replica's state after the block holds the decline where its
/// parent held none.
#[test]
fn a_declining_block_is_built_voted_on_and_committed() {
    let mut sim = ShardCoordinatorSim::beside_a_sibling(4, 0xDEC1);
    sim.build_through_the_production_handler();
    let local = sim.shard;
    let producer = local.sibling().expect("a leaf beside its sibling");

    let id = CrossingId {
        producer: Address::new([0x91; 31], AddressClass::Component),
        consumer: Address::new([0x11; 31], AddressClass::Component),
        intent: IntentHash(Hash32([0x31; 32])),
        local: 0,
        output: 0,
    };
    assert!(ShardTrie::shard_owns_prefix(producer, id.producer));
    assert!(ShardTrie::shard_owns_prefix(local, id.consumer));
    let issuer = TxHash::from(Hash::from_bytes(b"never committed here"));
    let record = id.record_key(&ProtocolHasher);
    let value = id
        .cell(
            issuer,
            ResourceAddr::new([0xE1; 31]),
            250,
            0,
            Terms::Escrowed {
                credit: test_key(0x91),
            },
        )
        .to_bytes();
    let (state_root, proof) =
        state_and_proof_holding(producer, &[(record, value.clone())], &[record]);
    let anchor = Anchor {
        shard: producer,
        height: BlockHeight::new(3),
        state_root,
        ts: WeightedTimestamp::ZERO,
    };
    let held = StateClaim::new(
        anchor,
        [(
            record,
            Stated::Held(Bytes::new(value).expect("a record fits")),
        )],
        proof,
    )
    .naming([(record, id)]);

    sim.prove_anchor(anchor);
    sim.offered_claims = vec![held.clone()];
    sim.kick_off();
    sim.run_until_committed(3, MAX_STEPS);

    let never = id.answer_key(&ProtocolHasher, Answered::Never);
    let decline = id.answer(issuer, Answered::Never, 0).to_bytes();
    let row = member_row_leaf(local, issuer);
    for replica in 0..sim.n() {
        let commits = &sim.commits[replica];
        let at = commits
            .iter()
            .position(|commit| commit.certified.block().state_claims().contains(&held))
            .unwrap_or_else(|| panic!("replica {replica} committed no block carrying the record"));
        let block = commits[at].certified.block();
        assert_eq!(
            block
                .state_claims()
                .iter()
                .filter(|claim| claim.anchor.shard == local)
                .filter_map(|claim| claim.reading(row))
                .collect::<Vec<_>>(),
            [Inclusion::Absent],
            "the block reads the issuer's row absent at its parent",
        );
        assert_eq!(
            sim.cell_after(replica, &commits[at], never),
            Some(decline.clone()),
            "replica {replica} holds the decline once the block lands",
        );
        if let Some(parent) = at.checked_sub(1) {
            assert_eq!(sim.cell_after(replica, &commits[parent], never), None);
        }
    }
}
