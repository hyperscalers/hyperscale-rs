//! Network identity — which chain a signature is for.
//!
//! [`NetworkDefinition::id`] is bound into every signed consensus message
//! and into the validator bind handshake, so a signature produced for one
//! network cannot be replayed against another. Nothing else about the
//! definition is signed; the name exists so a config file can say which
//! network it means.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use hyperscale_hbor::Hbor;

/// The identity of a network.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct NetworkDefinition {
    /// Domain byte mixed into every signed message. Distinct per network,
    /// which is what makes a cross-network replay produce a different
    /// digest and so fail verification.
    pub(crate) id: u8,
    /// The name a config file names this network by.
    pub(crate) logical_name: String,
}

impl NetworkDefinition {
    /// The deterministic simulation and test harnesses.
    #[must_use]
    pub fn simulator() -> Self {
        Self {
            id: 242,
            logical_name: "simulator".to_string(),
        }
    }

    /// The public test network.
    #[must_use]
    pub(crate) fn testnet() -> Self {
        Self {
            id: 2,
            logical_name: "testnet".to_string(),
        }
    }

    /// The production network.
    #[must_use]
    pub fn mainnet() -> Self {
        Self {
            id: 1,
            logical_name: "mainnet".to_string(),
        }
    }

    /// The word an address's human-readable form is suffixed with on this
    /// network — the `sim` of `account_sim1…` — or `None` for an id no
    /// network here claims.
    ///
    /// Short because it rides in front of every address a human reads, and
    /// separate from [`Self::logical_name`] for the same reason: a config
    /// file says `simulator` once, an address says `sim` every time. The
    /// vocabulary crate holds the encoding and asks for this word rather
    /// than keeping its own list, so this is the only register of them.
    ///
    /// An unclaimed id has no word rather than a default one: the id
    /// arrives off the wire, and a fallback would render two networks'
    /// addresses under one suffix — the collision [`Self::id`]'s own
    /// distinctness exists to prevent.
    #[must_use]
    pub const fn hrp_suffix(&self) -> Option<&'static str> {
        match self.id {
            1 => Some("hs"),
            2 => Some("test"),
            242 => Some("sim"),
            _ => None,
        }
    }

    /// The network whose addresses carry `suffix`, or `None` for a word no
    /// network uses — which is how a pasted address for another network is
    /// caught before anything is signed for this one.
    #[must_use]
    pub fn from_hrp_suffix(suffix: &str) -> Option<Self> {
        [Self::mainnet(), Self::testnet(), Self::simulator()]
            .into_iter()
            .find(|network| network.hrp_suffix() == Some(suffix))
    }
}

impl Display for NetworkDefinition {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.logical_name)
    }
}

/// A network name no definition claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownNetwork(pub String);

impl Display for UnknownNetwork {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "unknown network `{}`", self.0)
    }
}

impl std::error::Error for UnknownNetwork {}

impl FromStr for NetworkDefinition {
    type Err = UnknownNetwork;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "simulator" => Ok(Self::simulator()),
            "testnet" => Ok(Self::testnet()),
            "mainnet" => Ok(Self::mainnet()),
            _ => Err(UnknownNetwork(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Address, PrincipalAddr};

    /// Ids are what a signature binds, so two networks must never share
    /// one — a collision would make a cross-network replay verify.
    #[test]
    fn every_network_has_a_distinct_id() {
        let nets = [
            NetworkDefinition::simulator(),
            NetworkDefinition::testnet(),
            NetworkDefinition::mainnet(),
        ];
        for (i, a) in nets.iter().enumerate() {
            for b in &nets[i + 1..] {
                assert_ne!(a.id, b.id, "{a} and {b} share an id");
            }
        }
    }

    /// A suffix is what a human reads a network off an address by, so a
    /// shared one would let an address for one network be pasted as an
    /// address for another.
    #[test]
    fn every_network_has_a_distinct_suffix_that_names_it_back() {
        let nets = [
            NetworkDefinition::simulator(),
            NetworkDefinition::testnet(),
            NetworkDefinition::mainnet(),
        ];
        for (i, a) in nets.iter().enumerate() {
            let suffix = a.hrp_suffix().expect("a registered network has a word");
            assert_eq!(
                NetworkDefinition::from_hrp_suffix(suffix).as_ref(),
                Some(a),
                "{a}'s suffix must name it back"
            );
            for b in &nets[i + 1..] {
                assert_ne!(a.hrp_suffix(), b.hrp_suffix(), "{a} and {b} share a suffix");
            }
        }
        assert_eq!(NetworkDefinition::from_hrp_suffix("rdx"), None);
    }

    /// An id off the wire that no network here claims has no address form
    /// at all, rather than borrowing another network's.
    #[test]
    fn an_unclaimed_id_has_no_suffix() {
        let unclaimed = NetworkDefinition {
            id: 7,
            logical_name: "unclaimed".to_string(),
        };
        assert_eq!(unclaimed.hrp_suffix(), None);
    }

    /// The register and the encoding are two halves of one thing: the word
    /// this hands out is the word an address comes back under.
    #[test]
    fn an_address_reads_back_under_the_network_that_wrote_it() {
        let account = PrincipalAddr::new([0x11; 31]).address();
        for network in [
            NetworkDefinition::mainnet(),
            NetworkDefinition::testnet(),
            NetworkDefinition::simulator(),
        ] {
            let suffix = network.hrp_suffix().unwrap();
            let text = account.to_text(suffix).expect("a registered word fits");
            let (decoded, word) = Address::from_text(&text).expect("its own encoding decodes");
            assert_eq!(decoded, account);
            assert_eq!(
                NetworkDefinition::from_hrp_suffix(&word.0),
                Some(network.clone()),
                "{text} must name {network}"
            );
        }
    }

    #[test]
    fn names_round_trip_through_parsing() {
        for net in [
            NetworkDefinition::simulator(),
            NetworkDefinition::testnet(),
            NetworkDefinition::mainnet(),
        ] {
            assert_eq!(
                net.logical_name.parse::<NetworkDefinition>(),
                Ok(net.clone())
            );
            // Parsing is case-insensitive so a config file can shout.
            assert_eq!(
                net.logical_name.to_uppercase().parse::<NetworkDefinition>(),
                Ok(net)
            );
        }
        assert!("nosuchnet".parse::<NetworkDefinition>().is_err());
    }
}
