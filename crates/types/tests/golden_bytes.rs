//! Golden-bytes pins for the wire structs whose signature/key fields the
//! crypto seam touches. Any drift in the expected hex means a wire-format
//! break — deliberate re-pins accompany deliberate encoding changes.

use hex::encode as hex_encode;
use hyperscale_hbor::{Capped, HborEncode, to_vec as hbor_to_vec};
use hyperscale_types::{
    AggregateSignature, BlockHash, BlockHeight, BlockVote, ConsensusPublicKey, ConsensusReceipt,
    ConsensusSignature, EffectsDigest, Epoch, EventRoot, FAILED_RECEIPT_HASH, GlobalReceiptHash,
    Hash, PcCompactVote, PcQc1, PcValueElement, PcVector, PositionalBundle, ProposerTimestamp,
    QuorumCertificate, Round, ShardId, SignerBitfield, StateWrites, ValidatorId, ValidatorInfo,
    WeightedTimestamp, effects_digest,
};

fn assert_golden<T: HborEncode>(value: &T, expected_hex: &str, label: &str) {
    let actual = hex_encode(hbor_to_vec(value).unwrap());
    assert_eq!(
        actual, expected_hex,
        "{label}: encoding drifted from the golden bytes"
    );
}

fn golden_signers() -> SignerBitfield {
    let mut signers = SignerBitfield::new(4);
    signers.set(0);
    signers.set(2);
    signers
}

#[test]
fn quorum_certificate_golden_bytes() {
    let qc = QuorumCertificate::new(
        BlockHash::from_raw(Hash::from_bytes(b"golden-qc-block")),
        ShardId::leaf(2, 0b10),
        BlockHeight::new(42),
        BlockHash::from_raw(Hash::from_bytes(b"golden-qc-parent")),
        Round::new(3),
        Epoch::new(9),
        golden_signers(),
        AggregateSignature::new([0x22; 96]),
        WeightedTimestamp::from_millis(1_700_000_000_123),
    );
    assert_golden(&qc, EXPECTED_QC, "QuorumCertificate");
}

/// A success carrying nothing but `effects`.
fn golden_receipt(effects: Option<EffectsDigest>) -> ConsensusReceipt {
    ConsensusReceipt::Succeeded {
        receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"golden-receipt")),
        writes: StateWrites::default(),
        beacon_witness_events: Capped::empty(),
        events: Capped::empty(),
        effects,
    }
}

#[test]
fn consensus_receipt_golden_bytes() {
    assert_golden(
        &golden_receipt(None),
        EXPECTED_RECEIPT_UNDIGESTED,
        "ConsensusReceipt without a digest",
    );
    assert_golden(
        &golden_receipt(Some(effects_digest(
            &StateWrites::default(),
            EventRoot::ZERO,
        ))),
        EXPECTED_RECEIPT_DIGESTED,
        "ConsensusReceipt with a digest",
    );
    assert_eq!(
        hex_encode(FAILED_RECEIPT_HASH.as_raw().as_bytes()),
        EXPECTED_FAILED_RECEIPT_HASH,
        "FAILED_RECEIPT_HASH drifted from the golden bytes",
    );
}

#[test]
fn block_vote_golden_bytes() {
    let vote = BlockVote::from_parts(
        BlockHash::from_raw(Hash::from_bytes(b"golden-vote-block")),
        ShardId::leaf(1, 0b1),
        BlockHeight::new(7),
        Round::new(1),
        Epoch::new(9),
        ValidatorId::new(5),
        ConsensusSignature::new([0x33; 96]),
        ProposerTimestamp::from_millis(1_700_000_000_456),
    );
    assert_golden(&vote, EXPECTED_BLOCK_VOTE, "BlockVote");
}

#[test]
fn validator_info_golden_bytes() {
    let info = ValidatorInfo {
        validator_id: ValidatorId::new(9),
        public_key: ConsensusPublicKey::new([0x44; 48]),
    };
    assert_golden(&info, EXPECTED_VALIDATOR_INFO, "ValidatorInfo");
}

#[test]
fn pc_qc1_golden_bytes() {
    let x = PcVector::new([
        PcValueElement::from_digest([0x55; 32], b"golden"),
        PcValueElement::from_digest([0x66; 32], b"golden"),
    ]);
    let x_signers = PositionalBundle::new(
        golden_signers(),
        Capped::from_array([
            PcCompactVote::new(2, None),
            PcCompactVote::new(1, Some(PcValueElement::from_digest([0x77; 32], b"golden"))),
        ]),
    );
    let qc1 = PcQc1::new(x, x_signers, AggregateSignature::new([0x88; 96]));
    assert_golden(&qc1, EXPECTED_PC_QC1, "PcQc1");
}

const EXPECTED_RECEIPT_UNDIGESTED: &str =
    "00d784cf810b9f5ce2a7bd2a82871b99de634115a2c12181ea1bd5edac104362fb000000000000";
const EXPECTED_RECEIPT_DIGESTED: &str = "00d784cf810b9f5ce2a7bd2a82871b99de634115a2c12181ea1bd5edac104362fb000000000001e33ac9c04ddab6a393632dee8b124dca8d89acbc75a1d5aba62b913bf06f3433";
const EXPECTED_FAILED_RECEIPT_HASH: &str =
    "b514c810e69b9b7144b79bceb4574254de96d7b21f6efa9d7f20ef6be9e503c1";
const EXPECTED_QC: &str = "e7c8d8fecb84404480148f65172ce95b9984e1ec56f84494e6ad90391dc36cd70200000002000000000000002a000000000000002356d22ed37a6538fc945a8e30ea532612029962653bf993560b365ae3fe594c03000000000000000900000000000000010504002222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222227b68e5cf8b010000";
const EXPECTED_BLOCK_VOTE: &str = "b3e13454f2b0dab7471e3e5db927fd492e114b13595a462f5a4c066bd516783b0100000001000000000000000700000000000000010000000000000009000000000000000500000000000000333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333c869e5cf8b010000";
const EXPECTED_VALIDATOR_INFO: &str = "0900000000000000444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444";
const EXPECTED_PC_QC1: &str = "02555555555555555555555555555555555555555555555555555555555555555566666666666666666666666666666666666666666666666666666666666666660105040002020000000001000000017777777777777777777777777777777777777777777777777777777777777777888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888";

/// The record family: what a departing or silent counterpart writes down
/// and every voter compares whole.
///
/// A record's figures are checked field by field against the ones the
/// voter derives itself, so a field added, reordered or re-widened is a
/// consensus break rather than a decode failure — and one arm of a
/// vocabulary enum renumbered re-reads every record ever written as a
/// different answer.
mod records {
    use hyperscale_hbor::Capped;
    use hyperscale_types::{
        AbandonmentRecord, AbortCharge, Address, AddressClass, BlockHeight, CommittedAt, Deadline,
        Epoch, LocalKey, RoutePrefix, SubstateKey, TxHash, UnsettledTx,
    };

    use super::{Hash, ShardId, WeightedTimestamp, assert_golden};

    fn golden_unsettled() -> UnsettledTx {
        UnsettledTx {
            tx_hash: TxHash::from(Hash::from_bytes(b"golden-record-tx")),
            deadline: Deadline::of(WeightedTimestamp::from_millis(1_700_000_000_789)),
            charged: 4_096,
            charge: AbortCharge {
                vault: SubstateKey {
                    owner: Address::new([0x11; 31], AddressClass::Component),
                    local: LocalKey([0x22; 16]),
                },
                amount: 1_000_000,
            },
            committed: CommittedAt {
                height: BlockHeight::new(12_345),
                anchor: WeightedTimestamp::from_millis(1_700_000_000_321),
                committee_epoch: Epoch::new(4_321),
            },
            reach: Capped::from_array([
                RoutePrefix::of(Address::new([0x33; 31], AddressClass::Principal)),
                RoutePrefix::of(Address::new([0x44; 31], AddressClass::Resource)),
            ]),
        }
    }

    #[test]
    fn unsettled_tx_golden_bytes() {
        assert_golden(&golden_unsettled(), EXPECTED_UNSETTLED_TX, "UnsettledTx");
    }

    #[test]
    fn departed_record_golden_bytes() {
        let record = AbandonmentRecord::new(
            ShardId::leaf(2, 0b01),
            WeightedTimestamp::from_millis(1_700_000_000_111),
            [golden_unsettled()],
        );
        assert_golden(
            &record,
            EXPECTED_DEPARTED_RECORD,
            "AbandonmentRecord::departed",
        );
    }

    const EXPECTED_UNSETTLED_TX: &str = "611a9160425d3d1a581a5376ac0408af253ce284e06fbe959a6c7b08c779d4b7d5c8e5cf8b0100000010000000000000000000000000000011111111111111111111111111111111111111111111111111111111111111022222222222222222222222222222222240420f0000000000000000000000000039300000000000004169e5cf8b010000e1100000000000000233333333333333334444444444444444";
    const EXPECTED_DEPARTED_RECORD: &str = "0200000001000000000000006f68e5cf8b01000001611a9160425d3d1a581a5376ac0408af253ce284e06fbe959a6c7b08c779d4b7d5c8e5cf8b0100000010000000000000000000000000000011111111111111111111111111111111111111111111111111111111111111022222222222222222222222222222222240420f0000000000000000000000000039300000000000004169e5cf8b010000e1100000000000000233333333333333334444444444444444";
}
