//! Three-tier receipt model for transaction execution results.
//!
//! | Tier | Type | Contents | Cross-shard identical? |
//! |------|------|----------|------------------------|
//! | **Global** | [`GlobalReceipt`](global::GlobalReceipt) | outcome + `event_root` + `writes_root` | Yes |
//! | **Local**  | [`LocalReceipt`](local::LocalReceipt)   | outcome + shard-filtered state changes + events | No |
//! | **Output** | [`ExecutionMetadata`](metadata::ExecutionMetadata) | fees, logs, errors | No |
//!
//! The global receipt hash is signed over in execution votes/certificates.
//! Per-shard state correctness is enforced by `state_root` in the block header,
//! with per-tx attribution via `local_receipt_root`.

pub mod bundle;
pub mod global;
pub mod local;
pub mod metadata;
pub mod outcome;

#[cfg(test)]
mod tests {
    use crate::{
        ApplicationEvent, DatabaseUpdates, EventRoot, GlobalReceipt, Hash, LocalReceipt,
        TransactionOutcome, WritesRoot, compute_merkle_root,
    };

    fn make_event(seed: u8) -> ApplicationEvent {
        ApplicationEvent {
            type_id: vec![seed],
            data: vec![seed, seed + 1],
        }
    }

    fn make_receipt(events: Vec<ApplicationEvent>) -> LocalReceipt {
        LocalReceipt {
            outcome: TransactionOutcome::Success,
            database_updates: DatabaseUpdates::default(),
            application_events: events,
        }
    }

    #[test]
    fn test_empty_receipt_has_zero_event_root() {
        let receipt = make_receipt(vec![]);
        let global = receipt.global_receipt(WritesRoot::ZERO);
        assert_eq!(global.event_root, EventRoot::ZERO);
    }

    #[test]
    fn test_global_receipt_derivation() {
        let events = vec![make_event(1), make_event(2)];
        let receipt = make_receipt(events.clone());

        let global = receipt.global_receipt(WritesRoot::ZERO);
        assert_eq!(global.outcome, TransactionOutcome::Success);

        let event_hashes: Vec<Hash> = events.iter().map(ApplicationEvent::hash).collect();
        let expected_root = EventRoot::from_raw(compute_merkle_root(&event_hashes));
        assert_eq!(global.event_root, expected_root);
    }

    #[test]
    fn test_receipt_hash_changes_with_outcome() {
        let success = GlobalReceipt {
            outcome: TransactionOutcome::Success,
            event_root: EventRoot::ZERO,
            writes_root: WritesRoot::ZERO,
        };
        let failure = GlobalReceipt {
            outcome: TransactionOutcome::Failure,
            event_root: EventRoot::ZERO,
            writes_root: WritesRoot::ZERO,
        };
        assert_ne!(success.receipt_hash(), failure.receipt_hash());
    }

    #[test]
    fn test_receipt_hash_changes_with_events() {
        let receipt_a = make_receipt(vec![make_event(1)]);
        let receipt_b = make_receipt(vec![make_event(1), make_event(2)]);
        assert_ne!(
            receipt_a.global_receipt(WritesRoot::ZERO).receipt_hash(),
            receipt_b.global_receipt(WritesRoot::ZERO).receipt_hash()
        );
    }

    #[test]
    fn test_receipt_hash_changes_with_writes_root() {
        let a = GlobalReceipt {
            outcome: TransactionOutcome::Success,
            event_root: EventRoot::ZERO,
            writes_root: WritesRoot::ZERO,
        };
        let b = GlobalReceipt {
            outcome: TransactionOutcome::Success,
            event_root: EventRoot::ZERO,
            writes_root: WritesRoot::from_raw(Hash::from_bytes(b"different")),
        };
        assert_ne!(a.receipt_hash(), b.receipt_hash());
    }

    #[test]
    fn test_application_event_hash_deterministic() {
        let event = make_event(42);
        assert_eq!(event.hash(), event.hash());

        let same_event = ApplicationEvent {
            type_id: vec![42],
            data: vec![42, 43],
        };
        assert_eq!(event.hash(), same_event.hash());
    }

    #[test]
    fn test_local_receipt_hash_deterministic() {
        let receipt = make_receipt(vec![make_event(1)]);
        assert_eq!(receipt.receipt_hash(), receipt.receipt_hash());
    }

    #[test]
    fn test_local_receipt_hash_changes_with_updates() {
        let a = LocalReceipt {
            outcome: TransactionOutcome::Success,
            database_updates: DatabaseUpdates::default(),
            application_events: vec![],
        };
        let b = LocalReceipt {
            outcome: TransactionOutcome::Failure,
            database_updates: DatabaseUpdates::default(),
            application_events: vec![],
        };
        assert_ne!(a.receipt_hash(), b.receipt_hash());
    }
}
