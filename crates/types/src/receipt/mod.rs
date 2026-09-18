//! Receipt model for transaction execution results.
//!
//! | Tier | Type | Contents |
//! |------|------|----------|
//! | **Global**    | [`GlobalReceipt`](global::GlobalReceipt)         | success bit + `event_root` + `beacon_witness_root` + `writes_root` |
//! | **Consensus** | [`ConsensusReceipt`](consensus::ConsensusReceipt) | variant tag + (Succeeded:) shard-filtered writes + events + beacon-witness events + precomputed `receipt_hash` |
//! | **Metadata**  | [`ExecutionMetadata`](metadata::ExecutionMetadata) | fees, logs, errors (local-only) |
//! | **Stored**    | [`StoredReceipt`](stored::StoredReceipt)         | `tx_hash` + consensus + optional metadata |
//!
//! `GlobalReceipt::receipt_hash()` is what execution votes and
//! certificates sign: the executing shard's own attestation. A batch
//! with cross-shard members hashes the shard-projected delta, and the
//! fee burn is a payer-shard write, so participants certify per-shard
//! hashes and no verifier compares them across shards — agreement is
//! outcome-level, settlement combines verdicts. The event root is per
//! shard on the same terms: it covers the events this shard's own
//! emitters produced, which is what it stores. A shard that ran only
//! its own legs of a transaction could not attest a union anyway.
//! Per-shard state correctness is enforced by `state_root` in the block
//! header, with per-tx attribution via `local_receipt_root`
//! (`ConsensusReceipt::local_receipt_hash`).

pub mod consensus;
pub mod event;
pub mod global;
pub mod metadata;
pub mod stored;

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Capped;
    use hyperscale_vm_types::{Address, AddressClass};

    use crate::receipt::event::EventExt;
    use crate::{
        BeaconWitnessRoot, ConsensusReceipt, Event, EventRoot, GlobalReceipt, GlobalReceiptHash,
        Hash, StateWrites, WritesRoot,
    };

    fn make_event(seed: u8) -> Event {
        Event {
            emitter: Address::new([seed; 31], AddressClass::Component),
            event_type: u32::from(seed),
            payload: vec![seed, seed + 1].try_into().unwrap(),
        }
    }

    fn make_succeeded(events: Vec<Event>) -> ConsensusReceipt {
        ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes: StateWrites::default(),
            beacon_witness_events: Capped::empty(),
            events: Capped::new(events).expect("a list written out in a test"),
        }
    }

    #[test]
    fn test_global_receipt_hash_changes_with_outcome() {
        let success = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            WritesRoot::ZERO,
        );
        let failure = GlobalReceipt::new(
            false,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            WritesRoot::ZERO,
        );
        assert_ne!(success.receipt_hash(), failure.receipt_hash());
    }

    #[test]
    fn test_global_receipt_hash_changes_with_writes_root() {
        let a = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            WritesRoot::ZERO,
        );
        let b = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            WritesRoot::from_raw(Hash::from_bytes(b"different")),
        );
        assert_ne!(a.receipt_hash(), b.receipt_hash());
    }

    #[test]
    fn test_global_receipt_hash_changes_with_beacon_witness_root() {
        let a = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            WritesRoot::ZERO,
        );
        let b = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::from_raw(Hash::from_bytes(b"witness")),
            WritesRoot::ZERO,
        );
        assert_ne!(a.receipt_hash(), b.receipt_hash());
    }

    #[test]
    fn test_event_hash_deterministic() {
        let event = make_event(42);
        assert_eq!(event.hash(), event.hash());
        assert_eq!(event.hash(), make_event(42).hash());
        assert_ne!(event.hash(), make_event(43).hash());
    }

    #[test]
    fn test_local_receipt_hash_deterministic() {
        let receipt = make_succeeded(vec![make_event(1)]);
        assert_eq!(receipt.local_receipt_hash(), receipt.local_receipt_hash());
    }

    #[test]
    fn test_local_receipt_hash_changes_with_outcome() {
        let succeeded = make_succeeded(vec![]);
        let failed = ConsensusReceipt::Failed;
        assert_ne!(succeeded.local_receipt_hash(), failed.local_receipt_hash());
    }

    #[test]
    fn test_local_receipt_hash_changes_with_events() {
        let receipt_a = make_succeeded(vec![make_event(1)]);
        let receipt_b = make_succeeded(vec![make_event(1), make_event(2)]);
        assert_ne!(
            receipt_a.local_receipt_hash(),
            receipt_b.local_receipt_hash()
        );
    }
}
