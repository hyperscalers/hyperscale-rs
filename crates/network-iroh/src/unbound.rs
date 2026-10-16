//! Slots for inbound connections that have not bound yet.
//!
//! Every inbound connection holds a slot from its first packet until it
//! binds or is closed, at most [`crate::endpoint`]'s bind timeout. Which
//! slots it may take is decided from that first packet alone:
//!
//! - A dialer a signed record names, by the endpoint its relay names or the
//!   address it arrives from, takes one of [`NAMED_SLOTS`], and at most
//!   [`SLOTS_PER_ORIGIN`] of them from one origin.
//! - Any other dialer takes one of [`STRANGER_SLOTS`] of its own, so
//!   strangers whose handshakes never finish cannot keep a committee member
//!   from connecting.
//! - A dialer that came straight from an address it has not shown it
//!   receives at is first sent a retry, which costs this host one packet and
//!   no state: a stranger always, so a forged address cannot spend the
//!   strangers' slots or turns, and anyone once the slots it would take are
//!   half held, so a forged named address cannot fill the named ones.

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::bind_gate::Origin;

/// Inbound connections from dialers a record names that may be
/// mid-handshake at once.
const NAMED_SLOTS: usize = 64;

/// Of those, how many one origin may hold.
const SLOTS_PER_ORIGIN: u32 = 4;

/// Inbound connections from dialers no record names that may be
/// mid-handshake at once.
const STRANGER_SLOTS: usize = 32;

/// What becomes of an inbound connection's first packet.
pub enum Admission {
    /// It goes on to its handshake, holding this slot.
    Admit(Slot),
    /// It is sent a retry, and comes back with its address shown.
    Retry,
    /// It is refused, for the reason given.
    Refuse(&'static str),
}

/// The slot an inbound connection holds until it binds or is closed: one of
/// its pool's, and for a dialer a record names, one of its origin's share
/// as well.
pub struct Slot {
    _pool: OwnedSemaphorePermit,
    _origin: Option<OriginShare>,
}

/// One of an origin's share of the named dialers' slots, given back when
/// dropped.
struct OriginShare {
    held: Arc<DashMap<Origin, u32>>,
    origin: Origin,
}

impl OriginShare {
    /// Take one of `origin`'s share, if it has one left.
    fn take(held: &Arc<DashMap<Origin, u32>>, origin: Origin) -> Option<Self> {
        let mut count = held.entry(origin).or_default();
        if *count >= SLOTS_PER_ORIGIN {
            return None;
        }
        *count += 1;
        drop(count);
        Some(Self {
            held: Arc::clone(held),
            origin,
        })
    }
}

impl Drop for OriginShare {
    fn drop(&mut self) {
        self.held.remove_if_mut(&self.origin, |_, count| {
            *count -= 1;
            *count == 0
        });
    }
}

/// The host's unbound slots.
pub struct UnboundSlots {
    named: Arc<Semaphore>,
    origins: Arc<DashMap<Origin, u32>>,
    strangers: Arc<Semaphore>,
}

impl Default for UnboundSlots {
    fn default() -> Self {
        Self {
            named: Arc::new(Semaphore::new(NAMED_SLOTS)),
            origins: Arc::new(DashMap::new()),
            strangers: Arc::new(Semaphore::new(STRANGER_SLOTS)),
        }
    }
}

impl UnboundSlots {
    /// Decide on a connection from `origin`, which a record names or not,
    /// and whose address its packet has shown to be its own or not.
    pub fn admit(&self, origin: Origin, named: bool, validated: bool) -> Admission {
        let (pool, slots) = if named {
            (&self.named, NAMED_SLOTS)
        } else {
            (&self.strangers, STRANGER_SLOTS)
        };
        if matches!(origin, Origin::Direct(_))
            && !validated
            && (!named || pool.available_permits() < slots / 2)
        {
            return Admission::Retry;
        }
        let Ok(permit) = Arc::clone(pool).try_acquire_owned() else {
            return Admission::Refuse("too many are mid-handshake");
        };
        let share = if named {
            let Some(share) = OriginShare::take(&self.origins, origin) else {
                return Admission::Refuse("its origin holds its share");
            };
            Some(share)
        } else {
            None
        };
        Admission::Admit(Slot {
            _pool: permit,
            _origin: share,
        })
    }

    /// A slot for a re-dial from a bound peer, admitted already by the
    /// re-dial budget.
    pub fn redial(&self) -> Option<Slot> {
        let permit = Arc::clone(&self.named).try_acquire_owned().ok()?;
        Some(Slot {
            _pool: permit,
            _origin: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use iroh::SecretKey;

    use super::*;

    fn direct(port: u16) -> Origin {
        Origin::Direct(SocketAddr::from(([192, 0, 2, 1], port)))
    }

    fn admitted(admission: Admission) -> Option<Slot> {
        match admission {
            Admission::Admit(slot) => Some(slot),
            Admission::Retry | Admission::Refuse(_) => None,
        }
    }

    /// Admit connections from one port after another for as long as each is
    /// let on, holding every slot taken.
    fn hold_while(mut admit: impl FnMut(u16) -> Admission) -> Vec<Slot> {
        let mut held = Vec::new();
        for port in 0.. {
            let Some(slot) = admitted(admit(port)) else {
                break;
            };
            held.push(slot);
        }
        held
    }

    #[test]
    fn strangers_holding_every_slot_of_theirs_leave_a_named_dialer_its_own() {
        let slots = UnboundSlots::default();
        let held = hold_while(|port| slots.admit(direct(port), false, true));
        assert_eq!(held.len(), STRANGER_SLOTS);
        assert!(matches!(
            slots.admit(direct(60_000), false, true),
            Admission::Refuse(_)
        ));
        assert!(
            admitted(slots.admit(direct(60_001), true, true)).is_some(),
            "a named dialer still connects"
        );
    }

    #[test]
    fn a_stranger_whose_address_is_unshown_is_sent_a_retry() {
        let slots = UnboundSlots::default();
        assert!(matches!(
            slots.admit(direct(1), false, false),
            Admission::Retry
        ));
        let relayed = Origin::Relayed(SecretKey::generate().public());
        assert!(
            admitted(slots.admit(relayed, false, false)).is_some(),
            "a relay shows no address to retry"
        );
    }

    #[test]
    fn unshown_named_addresses_are_retried_once_half_the_slots_are_held() {
        let slots = UnboundSlots::default();
        let held = hold_while(|port| slots.admit(direct(port), true, false));
        assert_eq!(
            held.len(),
            NAMED_SLOTS / 2 + 1,
            "taken without a retry until half are held"
        );
        assert!(matches!(
            slots.admit(direct(60_000), true, false),
            Admission::Retry
        ));
        assert!(
            admitted(slots.admit(direct(60_001), true, true)).is_some(),
            "a named dialer that has shown its address still connects"
        );
    }

    #[test]
    fn one_origin_holds_only_its_share_of_the_named_slots() {
        let slots = UnboundSlots::default();
        let origin = direct(1);
        let held: Vec<Slot> = (0..SLOTS_PER_ORIGIN)
            .filter_map(|_| admitted(slots.admit(origin, true, true)))
            .collect();
        assert_eq!(held.len(), SLOTS_PER_ORIGIN as usize);
        assert!(matches!(
            slots.admit(origin, true, true),
            Admission::Refuse(_)
        ));
        drop(held);
        assert!(
            admitted(slots.admit(origin, true, true)).is_some(),
            "a closed connection gives its share back"
        );
    }
}
