//! [`Pin`]: one key a member stands on in its shard's queue, under the
//! modes it declares there.
//!
//! A member pins the declared entries whose keys its shard owns. A range
//! pins its collection, since two intervals of one collection contend by
//! mode alone. A held pin refuses a candidate exactly where the
//! scheduling relation says an in-flight claim does: [`Modes::refuses`],
//! the relation `ProvisionalCells::blocks` holds, debit rule included.
//! Between two abortable members, the earlier one still waiting, the
//! queue reads it both ways ([`Modes::conflicts`]).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use blake3::Hasher;
use hyperscale_hbor::{Capped, Hbor, to_vec};
use hyperscale_vm_effects::protocol_resource;
use hyperscale_vm_effects::vocabulary::vault_cell;
use hyperscale_vm_types::Mode;

use crate::{
    AddressClass, DeclaredKey, MAX_HOLDS_PER_MEMBER, ProtocolHasher, ResourceAddr, ShardId,
    ShardTrie, SubstateKey,
};

/// The domain a pin key is hashed under.
const PIN_DOMAIN: &[u8] = b"hyperscale-pin-v1";

/// The byte a cell's pin key is hashed behind.
const CELL_TAG: u8 = 0;

/// The byte a range's pin key is hashed behind.
const RANGE_TAG: u8 = 1;

/// The protocol resource, derived once.
static PROTOCOL_RESOURCE: LazyLock<ResourceAddr> =
    LazyLock::new(|| protocol_resource(&ProtocolHasher));

/// Whether `key` is a principal's vault of the protocol resource: the
/// one kind of cell a fee hold stands on.
///
/// A component's cell of the same resource is not one. No transaction
/// names a component as its fee payer, so nothing is ever held against
/// its balance.
#[must_use]
pub fn is_protocol_vault(key: &SubstateKey) -> bool {
    key.owner.class() == AddressClass::Principal
        && *key == vault_cell(&ProtocolHasher, key.owner, *PROTOCOL_RESOURCE)
}

/// What a pin stands on: the first 16 bytes of the key's hash under the
/// pin domain. A collision only adds a wait.
///
/// The key is a cell, or a range's owner and collection, behind a byte
/// telling the two apart, since a cell's local key and a collection
/// encode alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct PinKey(pub [u8; 16]);

impl PinKey {
    /// The key `declared` pins.
    ///
    /// # Panics
    ///
    /// Never: a declared key encodes.
    #[must_use]
    pub fn of(declared: &DeclaredKey) -> Self {
        let (tag, encoded) = match declared {
            DeclaredKey::Cell(cell) => (CELL_TAG, to_vec(cell)),
            DeclaredKey::Range(range) => (RANGE_TAG, to_vec(&(range.owner, range.collection))),
        };
        let mut hasher = Hasher::new();
        hasher.update(PIN_DOMAIN);
        hasher.update(&[tag]);
        hasher.update(&encoded.expect("a declared key encodes"));
        let mut key = [0u8; 16];
        key.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Self(key)
    }

    /// The key's first 64 bits: the bucket a queue entry is ordered by.
    #[must_use]
    pub fn bucket(self) -> u64 {
        let mut high = [0u8; 8];
        high.copy_from_slice(&self.0[..8]);
        u64::from_be_bytes(high)
    }
}

/// One class a pin stands in, as the queue orders its entries.
///
/// A held class refuses a candidate class where the scheduling relation
/// keeps the two apart:
///
/// | Candidate | Refused by a held |
/// |---|---|
/// | `Read` | `Credit`, `Reserve`, `Write`, `Debit` |
/// | `Credit` | `Read`, `Write` |
/// | `Reserve` | `Read`, `Write`, `Debit` |
/// | `Write` | every class |
/// | `Debit` | `Read`, `Write`, `Debit` |
///
/// The one pair refused one way only is a held `Reserve` beside a
/// candidate `Debit`: a reservation's amount is held against the cell
/// once it runs, and a debiting delta states none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PinClass {
    /// A `Read`.
    Read = 0,
    /// A `Delta` without the debit bit: a credit, or a debiting delta on
    /// a principal's protocol vault, which its fee hold bounds.
    Credit = 1,
    /// A `Reserve`.
    Reserve = 2,
    /// A `Write`.
    Write = 3,
    /// A `Delta` with the debit bit: a debiting delta on a cell that is
    /// not a principal's protocol vault. A pin holding it stands in
    /// `Debit` alone, whose refusals include `Credit`'s both ways.
    Debit = 4,
}

impl PinClass {
    /// Every class, in order.
    pub const ALL: [Self; 5] = [
        Self::Read,
        Self::Credit,
        Self::Reserve,
        Self::Write,
        Self::Debit,
    ];

    /// The class `bits` encode, or `None` past the last.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Read),
            1 => Some(Self::Credit),
            2 => Some(Self::Reserve),
            3 => Some(Self::Write),
            4 => Some(Self::Debit),
            _ => None,
        }
    }
}

/// The modes one member declares on one pinned key: a bit per mode kind,
/// and a bit for a debiting delta on a cell that is not a principal's
/// protocol vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct Modes(pub u8);

impl Modes {
    /// A `Read`.
    pub const READ: Self = Self(1);
    /// A `Delta`.
    pub const DELTA: Self = Self(1 << 1);
    /// A `Reserve`.
    pub const RESERVE: Self = Self(1 << 2);
    /// A `Write`.
    pub const WRITE: Self = Self(1 << 3);
    /// A debiting `Delta` on a cell that is not a principal's protocol
    /// vault.
    pub const DEBIT: Self = Self(1 << 4);

    /// The modes `mode` takes on `key`.
    #[must_use]
    pub fn of(key: &DeclaredKey, mode: &Mode) -> Self {
        match mode {
            Mode::Read => Self::READ,
            Mode::Delta { moves } => {
                let debit = moves.debits()
                    && matches!(key, DeclaredKey::Cell(cell) if !is_protocol_vault(cell));
                if debit {
                    Self(Self::DELTA.0 | Self::DEBIT.0)
                } else {
                    Self::DELTA
                }
            }
            Mode::Reserve { .. } => Self::RESERVE,
            Mode::Write { .. } => Self::WRITE,
        }
    }

    /// Both sets of modes.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The modes both sets hold.
    #[must_use]
    pub const fn and(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Whether no mode is held.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    const fn has(self, mode: Self) -> bool {
        self.0 & mode.0 != 0
    }

    /// The modes a part serves: the `Read` and the `Write`.
    #[must_use]
    pub const fn served(self) -> Self {
        self.and(Self(Self::READ.0 | Self::WRITE.0))
    }

    /// Whether a candidate holding these modes takes value off the key:
    /// a reservation or a debiting delta.
    const fn debits(self) -> bool {
        self.has(Self::RESERVE) || self.has(Self::DEBIT)
    }

    /// Whether a claim holding these modes refuses a candidate holding
    /// `candidate` on the same key: a pair of kinds the scheduling
    /// relation keeps apart, or a debit beside a standing debiting
    /// delta. Not symmetric: a reservation beside a later debiting delta
    /// is admitted, and the reverse is refused.
    #[must_use]
    pub const fn refuses(self, candidate: Self) -> bool {
        let (reads, moves, writes) = (
            self.has(Self::READ),
            self.has(Self::DELTA) || self.has(Self::RESERVE),
            self.has(Self::WRITE),
        );
        let (their_reads, their_moves, their_writes) = (
            candidate.has(Self::READ),
            candidate.has(Self::DELTA) || candidate.has(Self::RESERVE),
            candidate.has(Self::WRITE),
        );
        (writes && (their_reads || their_moves || their_writes))
            || ((reads || moves || writes) && their_writes)
            || (reads && their_moves)
            || (moves && their_reads)
            || (self.has(Self::DEBIT) && candidate.debits())
    }

    /// Whether these modes stand in `class`.
    #[must_use]
    pub const fn stands_in(self, class: PinClass) -> bool {
        match class {
            PinClass::Read => self.has(Self::READ),
            PinClass::Credit => self.has(Self::DELTA) && !self.has(Self::DEBIT),
            PinClass::Reserve => self.has(Self::RESERVE),
            PinClass::Write => self.has(Self::WRITE),
            PinClass::Debit => self.has(Self::DEBIT),
        }
    }

    /// Whether a claim standing in `class` refuses a candidate holding
    /// these modes, whatever else that claim holds.
    #[must_use]
    pub const fn refused_by(self, class: PinClass) -> bool {
        match class {
            PinClass::Read => {
                self.has(Self::DELTA) || self.has(Self::RESERVE) || self.has(Self::WRITE)
            }
            PinClass::Credit | PinClass::Reserve => self.has(Self::READ) || self.has(Self::WRITE),
            PinClass::Write => !self.is_empty(),
            PinClass::Debit => self.has(Self::READ) || self.has(Self::WRITE) || self.debits(),
        }
    }

    /// Whether a claim holding these modes refuses a candidate standing
    /// in `class`, whatever else that candidate holds: [`Self::refused_by`]
    /// with the two sides exchanged.
    #[must_use]
    pub const fn refuses_class(self, class: PinClass) -> bool {
        match class {
            PinClass::Read => {
                self.has(Self::DELTA) || self.has(Self::RESERVE) || self.has(Self::WRITE)
            }
            PinClass::Credit => self.has(Self::READ) || self.has(Self::WRITE),
            PinClass::Reserve | PinClass::Debit => {
                self.has(Self::READ) || self.has(Self::WRITE) || self.has(Self::DEBIT)
            }
            PinClass::Write => !self.is_empty(),
        }
    }

    /// Whether the two conflict both ways: either refuses the other.
    #[must_use]
    pub const fn conflicts(self, other: Self) -> bool {
        self.refuses(other) || other.refuses(self)
    }
}

/// One key a member pins, under the modes it declares there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct Pin {
    /// The key.
    pub key: PinKey,
    /// The modes, unioned over every declared entry on the key.
    pub modes: Modes,
}

/// A member's pins, ascending by key, one per key.
pub type Pins = Capped<Vec<Pin>, MAX_HOLDS_PER_MEMBER>;

/// The pins `declared` takes on `local`: one per key `local` owns,
/// ascending, its modes unioned over every entry on it. Ownership is
/// read off the key's owner alone, as [`ShardTrie::shard_owns_prefix`]
/// reads it.
///
/// # Panics
///
/// Never: there are no more keys than declared entries, and `declared`
/// is within the cap the pins share.
#[must_use]
pub fn pins_of(declared: &[(DeclaredKey, Mode)], local: ShardId) -> Pins {
    let mut pins: BTreeMap<PinKey, Modes> = BTreeMap::new();
    for (key, mode) in declared {
        let owner = match key {
            DeclaredKey::Cell(cell) => cell.owner,
            DeclaredKey::Range(range) => range.owner,
        };
        if !ShardTrie::shard_owns_prefix(local, owner) {
            continue;
        }
        let modes = pins.entry(PinKey::of(key)).or_default();
        *modes = modes.union(Modes::of(key, mode));
    }
    Capped::new(
        pins.into_iter()
            .map(|(key, modes)| Pin { key, modes })
            .collect(),
    )
    .expect("no more pins than declared entries")
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::Moves;

    use super::*;
    use crate::{Address, CollectionId, DeclaredRange, LocalKey};

    fn every_modes() -> impl Iterator<Item = Modes> {
        // A debit stands only beside the delta it debits by.
        (0u8..32)
            .map(Modes)
            .filter(|modes| !modes.has(Modes::DEBIT) || modes.has(Modes::DELTA))
    }

    /// The queue answers a refusal by class alone: a claim refuses a
    /// candidate exactly where it stands in a class the candidate is
    /// refused by, over all five classes.
    #[test]
    fn a_refusal_is_read_off_the_classes_a_claim_stands_in() {
        for held in every_modes() {
            for candidate in every_modes() {
                let by_class = PinClass::ALL
                    .into_iter()
                    .any(|class| held.stands_in(class) && candidate.refused_by(class));
                assert_eq!(
                    held.refuses(candidate),
                    by_class,
                    "{held:?} against {candidate:?}"
                );
            }
        }
    }

    /// The reverse reading by class is the relation transposed: a
    /// candidate refuses a claim exactly where the claim stands in a
    /// class the candidate refuses, so the two readings together are the
    /// relation's union with its transpose.
    #[test]
    fn a_conflict_is_read_off_the_classes_a_claim_stands_in_both_ways() {
        for held in every_modes() {
            for candidate in every_modes() {
                let reverse = PinClass::ALL
                    .into_iter()
                    .any(|class| held.stands_in(class) && candidate.refuses_class(class));
                assert_eq!(
                    candidate.refuses(held),
                    reverse,
                    "{candidate:?} against {held:?}"
                );
                let both = PinClass::ALL.into_iter().any(|class| {
                    held.stands_in(class)
                        && (candidate.refused_by(class) || candidate.refuses_class(class))
                });
                assert_eq!(
                    held.conflicts(candidate),
                    both,
                    "{held:?} and {candidate:?}"
                );
                assert_eq!(held.conflicts(candidate), candidate.conflicts(held));
            }
        }
    }

    #[test]
    fn a_reserve_and_a_credit_stand_in_different_classes() {
        let classes = |modes: Modes| -> Vec<PinClass> {
            PinClass::ALL
                .into_iter()
                .filter(|class| modes.stands_in(*class))
                .collect()
        };
        assert_eq!(classes(Modes::RESERVE), [PinClass::Reserve]);
        assert_eq!(classes(Modes::DELTA), [PinClass::Credit]);
        assert!(!Modes::DELTA.refuses(Modes::RESERVE) && !Modes::RESERVE.refuses(Modes::DELTA));
    }

    #[test]
    fn a_delta_with_the_debit_bit_stands_in_debit_alone() {
        let debit = Modes::DELTA.union(Modes::DEBIT);
        let classes: Vec<PinClass> = PinClass::ALL
            .into_iter()
            .filter(|class| debit.stands_in(*class))
            .collect();
        assert_eq!(classes, [PinClass::Debit]);
        // Everything a credit conflicts with, a debit conflicts with too.
        for other in every_modes() {
            if Modes::DELTA.conflicts(other) {
                assert!(debit.conflicts(other), "{other:?}");
            }
        }
    }

    #[test]
    fn a_debit_and_a_reserve_conflict_both_ways() {
        let debit = Modes::DELTA.union(Modes::DEBIT);
        assert!(!Modes::RESERVE.refuses(debit), "admitted one way");
        assert!(debit.refuses(Modes::RESERVE));
        assert!(Modes::RESERVE.conflicts(debit) && debit.conflicts(Modes::RESERVE));
        assert!(debit.refuses_class(PinClass::Reserve));
        assert!(!debit.refused_by(PinClass::Reserve));
    }

    #[test]
    fn a_class_past_the_last_decodes_to_none() {
        for class in PinClass::ALL {
            assert_eq!(PinClass::from_bits(class as u8), Some(class));
        }
        for bits in 5..=7 {
            assert_eq!(PinClass::from_bits(bits), None);
        }
    }

    fn cell(owner: Address, local: u8) -> SubstateKey {
        SubstateKey {
            owner,
            local: LocalKey([local; 16]),
        }
    }

    #[test]
    fn a_member_pins_only_the_keys_its_shard_owns_once_each() {
        let local = ShardId::leaf(1, 0);
        let (mine, theirs) = (0u8..=255)
            .map(|byte| Address::new([byte; 31], AddressClass::Principal))
            .fold((None, None), |(mine, theirs), owner| {
                if ShardTrie::shard_owns_prefix(local, owner) {
                    (mine.or(Some(owner)), theirs)
                } else {
                    (mine, theirs.or(Some(owner)))
                }
            });
        let (mine, theirs) = (mine.expect("an owner here"), theirs.expect("one elsewhere"));
        let range = |lo| {
            DeclaredKey::Range(DeclaredRange {
                owner: mine,
                collection: CollectionId([7; 16]),
                lo,
                hi: lo + 10,
                cap: 4,
            })
        };
        let declared = [
            (DeclaredKey::Cell(cell(mine, 1)), Mode::Read),
            (
                DeclaredKey::Cell(cell(mine, 1)),
                Mode::Delta { moves: Moves::Out },
            ),
            (DeclaredKey::Cell(cell(theirs, 1)), Mode::Read),
            (range(0), Mode::Read),
            (range(50), Mode::Write { moves: Moves::Both }),
        ];
        let pins = pins_of(&declared, local);
        assert_eq!(pins.len(), 2, "one per owned key, a collection once");
        let held = |key: &DeclaredKey| {
            pins.iter()
                .find(|pin| pin.key == PinKey::of(key))
                .expect("pinned")
                .modes
        };
        assert_eq!(
            held(&DeclaredKey::Cell(cell(mine, 1))),
            Modes(Modes::READ.0 | Modes::DELTA.0 | Modes::DEBIT.0)
        );
        assert_eq!(
            held(&range(0)),
            Modes(Modes::READ.0 | Modes::WRITE.0),
            "two intervals of one collection pin one key"
        );
        assert!(pins.windows(2).all(|pair| pair[0].key < pair[1].key));
    }

    /// A cell and a range whose local key and collection share their
    /// bytes, under one owner, pin two keys.
    #[test]
    fn a_cell_and_a_range_of_like_bytes_pin_apart() {
        let owner = Address::new([3; 31], AddressClass::Principal);
        let cell = DeclaredKey::Cell(SubstateKey {
            owner,
            local: LocalKey([7; 16]),
        });
        let range = DeclaredKey::Range(DeclaredRange {
            owner,
            collection: CollectionId([7; 16]),
            lo: 0,
            hi: 10,
            cap: 4,
        });
        assert_eq!(
            to_vec(&SubstateKey {
                owner,
                local: LocalKey([7; 16])
            })
            .expect("encodes"),
            to_vec(&(owner, CollectionId([7; 16]))).expect("encodes"),
            "the two encode alike"
        );
        assert_ne!(PinKey::of(&cell), PinKey::of(&range));
    }

    #[test]
    fn a_fee_vault_delta_takes_no_debit_bit() {
        let payer = Address::new([3; 31], AddressClass::Principal);
        let vault = DeclaredKey::Cell(vault_cell(&ProtocolHasher, payer, *PROTOCOL_RESOURCE));
        assert_eq!(
            Modes::of(&vault, &Mode::Delta { moves: Moves::Out }),
            Modes::DELTA
        );
        let other = DeclaredKey::Cell(cell(payer, 9));
        assert!(Modes::of(&other, &Mode::Delta { moves: Moves::Out }).has(Modes::DEBIT));
        assert!(!Modes::of(&other, &Mode::Delta { moves: Moves::In }).has(Modes::DEBIT));
    }
}
