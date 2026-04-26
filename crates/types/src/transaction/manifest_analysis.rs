//! Read/write set extraction from Radix manifest instructions.

use crate::NodeId;
use radix_common::data::manifest::model::{ManifestGlobalAddress, ManifestPackageAddress};
use radix_transactions::model::{InstructionV1, InstructionV2};
use std::collections::HashSet;

/// Analyze V1 transaction instructions to extract accessed `NodeIds`.
pub(super) fn analyze_instructions_v1(
    instructions: &[InstructionV1],
) -> (Vec<NodeId>, Vec<NodeId>) {
    let mut reads = HashSet::new();
    let mut writes = HashSet::new();

    for instruction in instructions {
        extract_node_ids_from_instruction_v1(instruction, &mut reads, &mut writes);
    }

    filter_and_deduplicate(reads, writes)
}

/// Analyze V2 transaction instructions to extract accessed `NodeIds`.
pub(super) fn analyze_instructions_v2(
    instructions: &[InstructionV2],
) -> (Vec<NodeId>, Vec<NodeId>) {
    let mut reads = HashSet::new();
    let mut writes = HashSet::new();

    for instruction in instructions {
        extract_node_ids_from_instruction_v2(instruction, &mut reads, &mut writes);
    }

    filter_and_deduplicate(reads, writes)
}

/// Filter out system entities and deduplicate read/write sets.
fn filter_and_deduplicate(
    reads: HashSet<NodeId>,
    writes: HashSet<NodeId>,
) -> (Vec<NodeId>, Vec<NodeId>) {
    let writes: HashSet<NodeId> = writes
        .into_iter()
        .filter(|node_id| !is_system_entity(node_id))
        .collect();

    let mut reads: Vec<NodeId> = reads
        .into_iter()
        .filter(|node_id| !is_system_entity(node_id) && !writes.contains(node_id))
        .collect();
    reads.sort();

    let mut writes: Vec<NodeId> = writes.into_iter().collect();
    writes.sort();

    (reads, writes)
}

/// Extract `NodeIds` from a single V1 instruction.
fn extract_node_ids_from_instruction_v1(
    instruction: &InstructionV1,
    reads: &mut HashSet<NodeId>,
    writes: &mut HashSet<NodeId>,
) {
    match instruction {
        InstructionV1::CallMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
                writes.insert(node_id);
            }
        }
        InstructionV1::CallRoyaltyMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
            }
        }
        InstructionV1::CallMetadataMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
                writes.insert(node_id);
            }
        }
        InstructionV1::CallRoleAssignmentMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
                writes.insert(node_id);
            }
        }
        InstructionV1::CallDirectVaultMethod(inner) => {
            let node_id = NodeId(inner.address.into_node_id().0);
            reads.insert(node_id);
            writes.insert(node_id);
        }
        InstructionV1::CallFunction(inner) => {
            if let Some(node_id) = manifest_package_to_node_id(&inner.package_address) {
                reads.insert(node_id);
            }
        }
        InstructionV1::TakeFromWorktop(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::TakeNonFungiblesFromWorktop(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::TakeAllFromWorktop(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::AssertWorktopContainsAny(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::AssertWorktopContains(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::AssertWorktopContainsNonFungibles(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::CreateProofFromAuthZoneOfAmount(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::CreateProofFromAuthZoneOfNonFungibles(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::CreateProofFromAuthZoneOfAll(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::AllocateGlobalAddress(inner) => {
            reads.insert(NodeId(inner.package_address.into_node_id().0));
        }
        _ => {}
    }
}

/// Extract `NodeIds` from a single V2 instruction.
fn extract_node_ids_from_instruction_v2(
    instruction: &InstructionV2,
    reads: &mut HashSet<NodeId>,
    writes: &mut HashSet<NodeId>,
) {
    match instruction {
        InstructionV2::CallMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
                writes.insert(node_id);
            }
        }
        InstructionV2::CallRoyaltyMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
            }
        }
        InstructionV2::CallMetadataMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
                writes.insert(node_id);
            }
        }
        InstructionV2::CallRoleAssignmentMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
                writes.insert(node_id);
            }
        }
        InstructionV2::CallDirectVaultMethod(inner) => {
            let node_id = NodeId(inner.address.into_node_id().0);
            reads.insert(node_id);
            writes.insert(node_id);
        }
        InstructionV2::CallFunction(inner) => {
            if let Some(node_id) = manifest_package_to_node_id(&inner.package_address) {
                reads.insert(node_id);
            }
        }
        InstructionV2::TakeFromWorktop(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::TakeNonFungiblesFromWorktop(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::TakeAllFromWorktop(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::AssertWorktopContainsAny(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::AssertWorktopContains(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::AssertWorktopContainsNonFungibles(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::CreateProofFromAuthZoneOfAmount(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::CreateProofFromAuthZoneOfNonFungibles(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::CreateProofFromAuthZoneOfAll(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::AllocateGlobalAddress(inner) => {
            reads.insert(NodeId(inner.package_address.into_node_id().0));
        }
        // Yield/verify ops touch no state; remaining variants conservatively touch nothing.
        _ => {}
    }
}

/// Convert a manifest global address to a `NodeId` if possible.
fn manifest_address_to_node_id(address: &ManifestGlobalAddress) -> Option<NodeId> {
    match address {
        ManifestGlobalAddress::Static(addr) => Some(NodeId(addr.into_node_id().0)),
        ManifestGlobalAddress::Named(_) => None,
    }
}

/// Convert a manifest package address to a `NodeId` if possible.
fn manifest_package_to_node_id(address: &ManifestPackageAddress) -> Option<NodeId> {
    match address {
        ManifestPackageAddress::Static(addr) => Some(NodeId(addr.into_node_id().0)),
        ManifestPackageAddress::Named(_) => None,
    }
}

/// Check if a `NodeId` is a system entity that should be replicated to all shards.
fn is_system_entity(node_id: &NodeId) -> bool {
    is_system_package(node_id) || is_system_component(node_id) || is_system_resource(node_id)
}

/// Check if a `NodeId` belongs to a well-known system package.
fn is_system_package(node_id: &NodeId) -> bool {
    use radix_common::constants::{
        ACCESS_CONTROLLER_PACKAGE, ACCOUNT_PACKAGE, CONSENSUS_MANAGER_PACKAGE, FAUCET_PACKAGE,
        GENESIS_HELPER_PACKAGE, IDENTITY_PACKAGE, LOCKER_PACKAGE, METADATA_MODULE_PACKAGE,
        PACKAGE_PACKAGE, POOL_PACKAGE, RESOURCE_PACKAGE, ROLE_ASSIGNMENT_MODULE_PACKAGE,
        ROYALTY_MODULE_PACKAGE, TRANSACTION_PROCESSOR_PACKAGE, TRANSACTION_TRACKER_PACKAGE,
    };

    let radix_node_id = radix_common::types::NodeId(node_id.0);
    let well_known_packages = [
        PACKAGE_PACKAGE,
        RESOURCE_PACKAGE,
        ACCOUNT_PACKAGE,
        IDENTITY_PACKAGE,
        CONSENSUS_MANAGER_PACKAGE,
        ACCESS_CONTROLLER_PACKAGE,
        POOL_PACKAGE,
        TRANSACTION_PROCESSOR_PACKAGE,
        METADATA_MODULE_PACKAGE,
        ROYALTY_MODULE_PACKAGE,
        ROLE_ASSIGNMENT_MODULE_PACKAGE,
        GENESIS_HELPER_PACKAGE,
        FAUCET_PACKAGE,
        TRANSACTION_TRACKER_PACKAGE,
        LOCKER_PACKAGE,
    ];

    well_known_packages
        .iter()
        .any(|pkg| pkg.as_node_id() == &radix_node_id)
}

/// Check if a `NodeId` belongs to a well-known system component.
fn is_system_component(node_id: &NodeId) -> bool {
    use radix_common::constants::{CONSENSUS_MANAGER, FAUCET, GENESIS_HELPER, TRANSACTION_TRACKER};

    let radix_node_id = radix_common::types::NodeId(node_id.0);
    let well_known_components = [
        CONSENSUS_MANAGER,
        GENESIS_HELPER,
        FAUCET,
        TRANSACTION_TRACKER,
    ];

    well_known_components
        .iter()
        .any(|comp| comp.as_node_id() == &radix_node_id)
}

/// Check if a `NodeId` belongs to a well-known system resource.
fn is_system_resource(node_id: &NodeId) -> bool {
    use radix_common::constants::{
        ACCOUNT_OWNER_BADGE, ED25519_SIGNATURE_RESOURCE, GLOBAL_CALLER_RESOURCE,
        IDENTITY_OWNER_BADGE, PACKAGE_OF_DIRECT_CALLER_RESOURCE, PACKAGE_OWNER_BADGE,
        SECP256K1_SIGNATURE_RESOURCE, SYSTEM_EXECUTION_RESOURCE, VALIDATOR_OWNER_BADGE, XRD,
    };

    let radix_node_id = radix_common::types::NodeId(node_id.0);
    let well_known_resources = [
        XRD,
        SECP256K1_SIGNATURE_RESOURCE,
        ED25519_SIGNATURE_RESOURCE,
        SYSTEM_EXECUTION_RESOURCE,
        PACKAGE_OF_DIRECT_CALLER_RESOURCE,
        GLOBAL_CALLER_RESOURCE,
        PACKAGE_OWNER_BADGE,
        VALIDATOR_OWNER_BADGE,
        ACCOUNT_OWNER_BADGE,
        IDENTITY_OWNER_BADGE,
    ];

    well_known_resources
        .iter()
        .any(|res| res.as_node_id() == &radix_node_id)
}
