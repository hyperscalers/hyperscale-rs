//! Hand-built leg shapes for tests that need a divided classification.
//!
//! A stubbed transaction derives no legs, so a divided answer comes from
//! shapes built here and frozen with `Classified::freeze` against
//! [`trie`].

use hyperscale_types::{Address, AddressClass, ShardId, ShardTrie};
use hyperscale_vm_effects::{Hash32, IntentHash};
use hyperscale_vm_types::{LegRole, LegShape, ValueEdge};

/// The four-leaf trie every shape here is placed on.
pub fn trie() -> ShardTrie {
    ShardTrie::uniform(2)
}

/// The leaf at `path` of [`trie`].
pub fn leaf(path: u64) -> ShardId {
    ShardId::leaf(2, path)
}

/// The address a node on the leaf at `path` targets.
pub fn owner_at(path: u8) -> Address {
    let mut body = [0x11; 31];
    body[0] = path << 6;
    Address::new(body, AddressClass::Component)
}

/// The fee payer every shape here is composed by: the caller on leaf 0,
/// which each shape's first node targets.
pub fn payer() -> Address {
    owner_at(0)
}

/// A leg on the leaf at `path`, consuming `edges` as `(source, output)`.
pub fn leg(path: u8, role: LegRole, edges: &[(u32, u32)]) -> LegShape {
    let target = owner_at(path);
    LegShape {
        target,
        role,
        edges: edges
            .iter()
            .map(|(source, output)| ValueEdge {
                source: *source,
                output: *output,
                non_fungible: false,
            })
            .collect(),
        presents: Vec::new(),
        declares: vec![target],
        intent: IntentHash(Hash32([7; 32])),
        local: 0,
        expiry_ms: 1_000,
    }
}

/// A swap: sign-in, withdraw and deposit on leaf 0, the venue on leaf 1.
/// The core is the venue alone.
pub fn swap() -> Vec<LegShape> {
    vec![
        leg(0, LegRole::Attesting, &[]),
        leg(0, LegRole::Inbound, &[]),
        leg(1, LegRole::Core, &[(1, 0)]),
        leg(0, LegRole::Outbound, &[(2, 0)]),
    ]
}

/// Two core nodes on leaves 1 and 2, fed by an inbound leg on leaf 0.
pub fn route() -> Vec<LegShape> {
    vec![
        leg(0, LegRole::Inbound, &[]),
        leg(1, LegRole::Core, &[(0, 0)]),
        leg(2, LegRole::Core, &[(1, 0)]),
    ]
}
