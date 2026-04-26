//! Constructors that turn a notarized Radix transaction into a `RoutableTransaction`.
//!
//! `validity_range` is required at every call site — there is no chain-side
//! default. These helpers replace earlier `TryFrom` impls so the missing
//! argument is a compile-time error rather than a silent default.

use crate::{RoutableTransaction, TimestampRange, TransactionError};
use radix_transactions::model::{NotarizedTransactionV1, NotarizedTransactionV2, UserTransaction};
use std::collections::HashSet;

use super::manifest_analysis::{analyze_instructions_v1, analyze_instructions_v2};

/// Convert a `NotarizedTransactionV1` into a `RoutableTransaction`.
///
/// # Errors
///
/// Currently infallible; the `Result` is reserved for future
/// validation paths (e.g. unsupported instruction kinds).
pub fn routable_from_notarized_v1(
    notarized: NotarizedTransactionV1,
    validity_range: TimestampRange,
) -> Result<RoutableTransaction, TransactionError> {
    let instructions = &notarized.signed_intent.intent.instructions.0;
    let (read_nodes, write_nodes) = analyze_instructions_v1(instructions);
    Ok(RoutableTransaction::new(
        UserTransaction::V1(notarized),
        read_nodes,
        write_nodes,
        validity_range,
    ))
}

/// Convert a `NotarizedTransactionV2` into a `RoutableTransaction`.
///
/// # Errors
///
/// Currently infallible; the `Result` is reserved for future
/// validation paths (e.g. unsupported instruction kinds).
pub fn routable_from_notarized_v2(
    notarized: NotarizedTransactionV2,
    validity_range: TimestampRange,
) -> Result<RoutableTransaction, TransactionError> {
    let root_instructions = &notarized
        .signed_transaction_intent
        .transaction_intent
        .root_intent_core
        .instructions
        .0;

    let (mut read_nodes, mut write_nodes) = analyze_instructions_v2(root_instructions);

    // Also analyze all non-root subintents
    for subintent in &notarized
        .signed_transaction_intent
        .transaction_intent
        .non_root_subintents
        .0
    {
        let (sub_reads, sub_writes) =
            analyze_instructions_v2(&subintent.intent_core.instructions.0);
        read_nodes.extend(sub_reads);
        write_nodes.extend(sub_writes);
    }

    // Deduplicate
    let write_set: HashSet<_> = write_nodes.into_iter().collect();
    let read_set: HashSet<_> = read_nodes
        .into_iter()
        .filter(|n| !write_set.contains(n))
        .collect();

    Ok(RoutableTransaction::new(
        UserTransaction::V2(notarized),
        read_set.into_iter().collect(),
        write_set.into_iter().collect(),
        validity_range,
    ))
}

/// Convert a `UserTransaction` (V1 or V2) into a `RoutableTransaction`.
///
/// # Errors
///
/// Forwards any error from
/// [`routable_from_notarized_v1`] / [`routable_from_notarized_v2`];
/// both are currently infallible.
pub fn routable_from_user_transaction(
    transaction: UserTransaction,
    validity_range: TimestampRange,
) -> Result<RoutableTransaction, TransactionError> {
    match transaction {
        UserTransaction::V1(v1) => routable_from_notarized_v1(v1, validity_range),
        UserTransaction::V2(v2) => routable_from_notarized_v2(v2, validity_range),
    }
}
