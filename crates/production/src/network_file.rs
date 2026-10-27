//! A network's definition as a file: what every host of one network shares.
//!
//! [`Genesis`] is the validator set, funded accounts and staking pools a
//! network starts from, as the validator binary's `[genesis]` table and a
//! [`NetworkFile`]'s both write it. A [`NetworkFile`] adds the rest a host
//! needs to join: which network, its chain parameters and how to reach it.

use std::collections::BTreeSet;

use hex::decode as hex_decode;
use hyperscale_engine::GenesisConfig as EngineGenesisConfig;
#[cfg(feature = "iroh")]
use hyperscale_network_iroh::{
    EndpointAddr, IrohConfig, RelayUrl, SecretKey, VersionInteroperabilityMode, parse_endpoint_addr,
};
use hyperscale_types::{
    Address, BeaconChainConfig, ConsensusPublicKey, GenesisValidators, MIN_EPOCH_DURATION,
    NetworkDefinition, NetworkParams, ParamBoundsError, PrincipalAddr, ReshapeThresholds,
    StakePoolSeat, ValidatorId, ValidatorInfo, ValidatorSet,
};
use serde::Deserialize;
use thiserror::Error;
use toml::de::Error as TomlError;
use toml::from_str as toml_from_str;
use tracing::{info, warn};

/// Why a network's definition does not make a network.
#[derive(Debug, Error)]
pub enum NetworkFileError {
    /// The text is not TOML in the file's schema.
    #[error("not a network file: {0}")]
    Parse(#[from] TomlError),
    /// A listed validator's public key is not a 48-byte BLS key in hex.
    #[error("validator {id}'s public key: {reason}")]
    PublicKey {
        /// The validator.
        id: u64,
        /// What is wrong with it.
        reason: String,
    },
    /// An account or pool operator address is not a 32-byte principal in hex.
    #[error("address '{address}': {reason}")]
    Address {
        /// The address as written.
        address: String,
        /// What is wrong with it.
        reason: String,
    },
    /// A balance is not a whole number of base units.
    #[error("balance '{0}' is not a whole number")]
    Balance(String),
    /// No validator is listed and none is hosted to run alone.
    #[error("no genesis validator is listed and none is hosted here")]
    NoValidators,
    /// A validator id is listed twice.
    #[error("validator {0} is listed twice")]
    Repeated(u64),
    /// More validators are listed than the one genesis shard has seats.
    #[error("{listed} validators are listed for {seats} seats")]
    Oversized {
        /// Validators listed.
        listed: usize,
        /// Seats on the genesis shard.
        seats: u32,
    },
    /// A governable parameter the chain section sets is out of the bounds a
    /// vote could not move it past either.
    #[error("chain: {0}")]
    Params(#[from] ParamBoundsError),
    /// The epoch is shorter than any chain may run.
    #[error("{epoch_ms} ms epochs are shorter than the {floor_ms} ms a chain may run")]
    EpochTooShort {
        /// The epoch the file sets.
        epoch_ms: u64,
        /// The shortest epoch a chain may run.
        floor_ms: u128,
    },
    /// A hosted validator signs with another key than the file lists for it,
    /// which would start this host on a genesis of its own.
    #[error("validator {0} is hosted with a key the network file does not list")]
    KeyMismatch(u64),
    /// A bootstrap peer is not an address the transport reads.
    #[error("bootstrap peer '{peer}': {reason}")]
    Peer {
        /// The peer as written.
        peer: String,
        /// What is wrong with it.
        reason: String,
    },
    /// A relay is not a URL.
    #[error("relay '{relay}': {reason}")]
    Relay {
        /// The relay as written.
        relay: String,
        /// What is wrong with it.
        reason: String,
    },
}

/// The validator set, funded accounts and staking pools a network starts
/// from.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    /// Validators in the network, every one seated on the genesis shard.
    #[serde(default)]
    pub validators: Vec<ValidatorEntry>,

    /// Initial balances for funded accounts, keyed by their 32-byte
    /// address. An account's address *is* its shard placement, so the list
    /// needs no routing metadata.
    #[serde(default)]
    pub accounts: Vec<AccountBalanceEntry>,

    /// Staking pools seated at genesis. Every genesis validator belongs to
    /// pool number 0, so a network whose validators vote on parameters seats
    /// it with an operator.
    #[serde(default)]
    pub pools: Vec<PoolEntry>,
}

/// A staking pool seated at genesis. Its founding members are not listed:
/// genesis fills them from the validator set, for the pool they belong to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolEntry {
    /// The seat's number: the salt its instance's address derives under.
    /// Number 0 is the pool every genesis validator belongs to.
    pub number: u32,

    /// Hex-encoded 32-byte address of the account that receives the pool's
    /// owner badge.
    pub operator: String,
}

/// A funded account at genesis.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBalanceEntry {
    /// Hex-encoded 32-byte account address.
    pub address: String,

    /// Balance as a string, parsed as `u128`.
    pub balance: String,
}

/// A validator at genesis.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorEntry {
    /// Validator id.
    pub id: u64,

    /// Hex-encoded 48-byte BLS public key.
    pub public_key: String,
}

impl ValidatorEntry {
    /// The listed public key.
    ///
    /// # Errors
    ///
    /// When it is not 48 bytes of hex.
    pub fn key(&self) -> Result<ConsensusPublicKey, NetworkFileError> {
        let bad = |reason: String| NetworkFileError::PublicKey {
            id: self.id,
            reason,
        };
        let bytes = hex_decode(&self.public_key).map_err(|e| bad(e.to_string()))?;
        let key: [u8; 48] = bytes
            .try_into()
            .map_err(|b: Vec<u8>| bad(format!("expected 48 bytes (BLS), got {}", b.len())))?;
        Ok(ConsensusPublicKey::new(key))
    }
}

impl Genesis {
    /// The genesis validators, every one seated on the single ROOT shard.
    ///
    /// A validator this host runs takes its key from `local` rather than the
    /// listed hex, keeping the set consistent with what this process signs
    /// with. With nothing listed, the first local validator runs alone.
    ///
    /// # Errors
    ///
    /// When a listed key is malformed, or nothing is listed and nothing is
    /// hosted.
    pub fn validators(
        &self,
        network: NetworkDefinition,
        local: &[(ValidatorId, ConsensusPublicKey)],
    ) -> Result<GenesisValidators, NetworkFileError> {
        let local_key = |id: ValidatorId| local.iter().find_map(|(v, k)| (*v == id).then_some(*k));
        let validators: Vec<ValidatorInfo> = if self.validators.is_empty() {
            warn!("No validators in genesis config, running in single-validator mode");
            let &(validator_id, public_key) =
                local.first().ok_or(NetworkFileError::NoValidators)?;
            vec![ValidatorInfo {
                validator_id,
                public_key,
            }]
        } else {
            self.validators
                .iter()
                .map(|v| {
                    let validator_id = ValidatorId::new(v.id);
                    let public_key = match local_key(validator_id) {
                        Some(key) => key,
                        None => v.key()?,
                    };
                    Ok(ValidatorInfo {
                        validator_id,
                        public_key,
                    })
                })
                .collect::<Result<_, NetworkFileError>>()?
        };
        let validator_set = ValidatorSet::new(validators);
        let committee: Vec<ValidatorId> = validator_set
            .validators
            .iter()
            .map(|v| v.validator_id)
            .collect();
        Ok(GenesisValidators::new(network, validator_set, committee))
    }

    /// The engine's genesis: funded accounts and seated pools.
    ///
    /// # Errors
    ///
    /// When an address or balance is malformed.
    pub fn engine(&self) -> Result<EngineGenesisConfig, NetworkFileError> {
        let mut engine = EngineGenesisConfig::default();
        for entry in &self.accounts {
            let address = parse_principal(&entry.address)?;
            let balance = entry
                .balance
                .parse::<u128>()
                .map_err(|_| NetworkFileError::Balance(entry.balance.clone()))?;
            engine.accounts.push((address, balance));
        }
        for entry in &self.pools {
            engine.pools.push(StakePoolSeat {
                number: entry.number,
                operator: parse_principal(&entry.operator)?,
                founding: Vec::new(),
            });
        }
        info!(
            accounts = engine.accounts.len(),
            pools = engine.pools.len(),
            "Parsed genesis balances and pools"
        );
        Ok(engine)
    }
}

/// A principal's address from its 64 hex characters.
fn parse_principal(hex: &str) -> Result<PrincipalAddr, NetworkFileError> {
    let bad = |reason: String| NetworkFileError::Address {
        address: hex.to_owned(),
        reason,
    };
    let bytes = hex_decode(hex).map_err(|e| bad(e.to_string()))?;
    let raw = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| bad("not 32 bytes".into()))?;
    let address = Address::from_bytes(raw).map_err(|e| bad(e.to_string()))?;
    PrincipalAddr::try_from(address).map_err(|e| bad(e.to_string()))
}

/// The chain parameters a network file sets over
/// [`BeaconChainConfig::production`]; the rest are the build's, and the
/// governable ones move by vote.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    /// When the network's epoch clock starts, in Unix milliseconds. A
    /// network whose genesis time is far behind its hosts' clocks never
    /// commits.
    pub genesis_timestamp_ms: u64,
    /// Epoch length.
    pub epoch_duration_ms: Option<u64>,
    /// Seats on a shard, the genesis shard included.
    pub shard_size: Option<u32>,
    /// Epochs a drawn seat has to report itself ready.
    pub ready_timeout_epochs: Option<u64>,
    /// Committed state, in bytes, at or above which a shard splits. Unset,
    /// no shard reshapes on its size, and no header attests one.
    pub split_bytes: Option<u64>,
}

/// One network's definition, everything its hosts share: the network, its
/// chain parameters, its genesis and how to reach it.
///
/// A file is the network's, not a host's: genesis accounts are outside the
/// genesis hash, so two hosts whose files differ there handshake and later
/// part ways on state.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkFile {
    /// Which network, by name: `mainnet`, `testnet` or `simulator`.
    #[serde(with = "network_name")]
    pub network: NetworkDefinition,
    /// Hosts to dial first, in the transport's own address form.
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    /// Relays the network's hosts share, for hosts that cannot be dialled
    /// directly.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Chain parameters over the build's production defaults.
    pub chain: Chain,
    /// The validators, accounts and pools the network starts from.
    pub genesis: Genesis,
}

impl NetworkFile {
    /// Reads a network file.
    ///
    /// # Errors
    ///
    /// When the text is not in the schema, its epoch is shorter than a chain
    /// may run, or its genesis lists no validator, one twice, or more than
    /// the genesis shard seats.
    pub fn from_toml(text: &str) -> Result<Self, NetworkFileError> {
        let file: Self = toml_from_str(text)?;
        NetworkParams::from_genesis(&file.beacon_chain()).validate()?;
        let epoch_ms = file.beacon_chain().epoch_duration_ms;
        if u128::from(epoch_ms) < MIN_EPOCH_DURATION.as_millis() {
            return Err(NetworkFileError::EpochTooShort {
                epoch_ms,
                floor_ms: MIN_EPOCH_DURATION.as_millis(),
            });
        }
        let listed = &file.genesis.validators;
        if listed.is_empty() {
            return Err(NetworkFileError::NoValidators);
        }
        let mut seen = BTreeSet::new();
        if let Some(repeated) = listed.iter().find(|v| !seen.insert(v.id)) {
            return Err(NetworkFileError::Repeated(repeated.id));
        }
        let seats = file.beacon_chain().shard_size;
        if listed.len() > seats as usize {
            return Err(NetworkFileError::Oversized {
                listed: listed.len(),
                seats,
            });
        }
        Ok(file)
    }

    /// Checks every validator this host runs signs with the key the file
    /// lists for it; one that does not would start this host on a genesis
    /// of its own.
    ///
    /// # Errors
    ///
    /// [`NetworkFileError::KeyMismatch`] for the first that does not, or a
    /// malformed listed key.
    pub fn check_hosted(
        &self,
        local: &[(ValidatorId, ConsensusPublicKey)],
    ) -> Result<(), NetworkFileError> {
        for listed in &self.genesis.validators {
            let hosted = local.iter().find(|(id, _)| id.inner() == listed.id);
            if let Some((_, key)) = hosted
                && *key != listed.key()?
            {
                return Err(NetworkFileError::KeyMismatch(listed.id));
            }
        }
        Ok(())
    }

    /// The network's chain configuration.
    #[must_use]
    pub fn beacon_chain(&self) -> BeaconChainConfig {
        let base = BeaconChainConfig::production();
        BeaconChainConfig {
            genesis_timestamp_ms: self.chain.genesis_timestamp_ms,
            epoch_duration_ms: self
                .chain
                .epoch_duration_ms
                .unwrap_or(base.epoch_duration_ms),
            shard_size: self.chain.shard_size.unwrap_or(base.shard_size),
            ready_timeout_epochs: self
                .chain
                .ready_timeout_epochs
                .unwrap_or(base.ready_timeout_epochs),
            reshape_thresholds: ReshapeThresholds {
                split_bytes: self
                    .chain
                    .split_bytes
                    .unwrap_or(base.reshape_thresholds.split_bytes),
                ..base.reshape_thresholds
            },
            ..base
        }
    }

    /// The iroh transport this file's network is reached by, for a host
    /// keyed `secret_key`: its peers less the host itself, its relays, and
    /// every other setting the transport's default.
    ///
    /// # Errors
    ///
    /// When a peer or relay is malformed.
    #[cfg(feature = "iroh")]
    pub fn iroh_transport(&self, secret_key: SecretKey) -> Result<IrohConfig, NetworkFileError> {
        iroh_config(secret_key, &self.bootstrap_peers, &self.relays)
    }
}

/// The iroh transport for a host keyed `secret_key` that dials `peers`,
/// itself left out, and relays through `relays`, versions held strictly.
///
/// # Errors
///
/// When a peer or relay is malformed.
#[cfg(feature = "iroh")]
pub fn iroh_config(
    secret_key: SecretKey,
    peers: &[String],
    relays: &[String],
) -> Result<IrohConfig, NetworkFileError> {
    let relays = relays
        .iter()
        .map(|relay| {
            relay
                .parse::<RelayUrl>()
                .map_err(|e| NetworkFileError::Relay {
                    relay: relay.clone(),
                    reason: e.to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let me = secret_key.public();
    let bootstrap_peers = peers
        .iter()
        .map(|peer| {
            parse_endpoint_addr(peer).map_err(|reason| NetworkFileError::Peer {
                peer: peer.clone(),
                reason,
            })
        })
        .collect::<Result<Vec<EndpointAddr>, _>>()?
        .into_iter()
        .filter(|peer| peer.id != me)
        .collect();
    Ok(IrohConfig {
        relays,
        bootstrap_peers,
        version_interop_mode: VersionInteroperabilityMode::Strict,
        ..IrohConfig::new(secret_key)
    })
}

/// `serde` adapter reading a [`NetworkDefinition`] by its name.
///
/// A definition is fixed by which network it is, not assembled field by
/// field: the name is the whole of it.
pub mod network_name {
    use std::str::FromStr;

    use hyperscale_types::NetworkDefinition;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};

    /// Reads a network by name.
    ///
    /// # Errors
    ///
    /// When the name is not a known network.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<NetworkDefinition, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        NetworkDefinition::from_str(&name).map_err(|_| {
            D::Error::custom(format!(
                "unknown network `{name}` (expected one of: mainnet, testnet, simulator, ...)"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use hex::encode as hex_encode;
    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_scenarios::tx::world_pools;
    use hyperscale_types::Signer;

    use super::*;

    fn key(seed: u8) -> ConsensusPublicKey {
        BlsSigner::from_seed(&[seed; 32]).public_key()
    }

    /// A network file of `ids`, keyed by seed `id + 1`, with `extra` text
    /// after its genesis.
    fn file(ids: &[u64], extra: &str) -> String {
        let mut text = String::from(
            "network = \"simulator\"\nbootstrap_peers = [\"peer\"]\nrelays = [\"https://relay.example\"]\n\n[chain]\ngenesis_timestamp_ms = 1700000000000\nepoch_duration_ms = 30000\nshard_size = 4\n\n[genesis]\n",
        );
        for &id in ids {
            let seed = u8::try_from(id + 1).expect("a small id");
            writeln!(
                text,
                "[[genesis.validators]]\nid = {id}\npublic_key = \"{}\"",
                hex_encode(key(seed).as_bytes())
            )
            .expect("writing to a string");
        }
        text.push_str(extra);
        text
    }

    #[test]
    fn a_network_file_reads_its_chain_genesis_and_peers() {
        let parsed = NetworkFile::from_toml(&file(&[0, 1, 2], "")).expect("parses");
        let chain = parsed.beacon_chain();
        assert_eq!(chain.genesis_timestamp_ms, 1_700_000_000_000);
        assert_eq!(chain.epoch_duration_ms, 30_000);
        assert_eq!(chain.shard_size, 4);
        assert_eq!(
            chain.ready_timeout_epochs,
            BeaconChainConfig::production().ready_timeout_epochs
        );
        assert_eq!(
            chain.reshape_thresholds,
            BeaconChainConfig::production().reshape_thresholds
        );
        assert_eq!(parsed.bootstrap_peers, ["peer"]);
        assert_eq!(parsed.relays, ["https://relay.example"]);
        let genesis = parsed
            .genesis
            .validators(parsed.network.clone(), &[])
            .expect("builds");
        assert_eq!(genesis.validators.validators.len(), 3);
    }

    #[test]
    fn a_network_file_sets_the_split_threshold_and_keeps_fullness() {
        let text =
            file(&[0], "").replace("shard_size = 4\n", "shard_size = 4\nsplit_bytes = 5000\n");
        let chain = NetworkFile::from_toml(&text)
            .expect("parses")
            .beacon_chain();
        assert_eq!(
            chain.reshape_thresholds,
            ReshapeThresholds {
                split_bytes: 5_000,
                ..BeaconChainConfig::production().reshape_thresholds
            }
        );
    }

    #[test]
    fn a_network_file_refuses_what_would_not_start_a_network() {
        let refused = |text: &str| NetworkFile::from_toml(text).unwrap_err();
        assert!(matches!(
            refused(&file(&[0], "stray = 1\n")),
            NetworkFileError::Parse(_)
        ));
        assert!(matches!(
            refused(&file(&[0], "").replace("network = \"simulator\"\n", "")),
            NetworkFileError::Parse(_)
        ));
        assert!(matches!(
            refused(&file(&[0], "").replace("genesis_timestamp_ms = 1700000000000\n", "")),
            NetworkFileError::Parse(_)
        ));
        assert!(matches!(
            refused(
                &file(&[0], "").replace("epoch_duration_ms = 30000", "epoch_duration_ms = 29999")
            ),
            NetworkFileError::EpochTooShort {
                epoch_ms: 29_999,
                floor_ms: 30_000
            }
        ));
        assert!(matches!(
            refused(
                &file(&[0], "").replace("shard_size = 4\n", "shard_size = 4\nsplit_bytes = 0\n")
            ),
            NetworkFileError::Params(ParamBoundsError::ZeroSplitThreshold)
        ));
        assert!(matches!(
            refused(&file(&[], "")),
            NetworkFileError::NoValidators
        ));
        assert!(matches!(
            refused(&file(&[0, 1, 0], "")),
            NetworkFileError::Repeated(0)
        ));
        assert!(matches!(
            refused(&file(&[0, 1, 2, 3, 4], "")),
            NetworkFileError::Oversized {
                listed: 5,
                seats: 4
            }
        ));
    }

    #[test]
    fn a_hosted_validator_must_sign_with_its_listed_key() {
        let parsed = NetworkFile::from_toml(&file(&[0, 1], "")).expect("parses");
        assert!(
            parsed
                .check_hosted(&[(ValidatorId::new(1), key(2))])
                .is_ok()
        );
        assert!(matches!(
            parsed.check_hosted(&[(ValidatorId::new(1), key(9))]),
            Err(NetworkFileError::KeyMismatch(1))
        ));
    }

    /// A `pools` table seats exactly the pools it names: the scenario
    /// world's seats, written out as an operator would, read back equal.
    #[test]
    fn genesis_pools_parse_to_their_seats() {
        let seats = world_pools();
        let mut toml = String::new();
        for seat in &seats {
            writeln!(
                toml,
                "[[pools]]\nnumber = {}\noperator = \"{}\"",
                seat.number,
                hex_encode(seat.operator.to_bytes())
            )
            .expect("writing to a string");
        }
        let genesis: Genesis = toml_from_str(&toml).expect("pools table parses");
        let engine = genesis.engine().expect("pools build");
        assert_eq!(engine.pools, seats);
    }

    /// Founding members come from the validator set, never the config: a
    /// listed one would enter the genesis hash and then be overwritten.
    #[test]
    fn genesis_pools_refuse_founding_members() {
        let toml = "[[pools]]\nnumber = 0\noperator = \"00\"\nfounding = []\n";
        assert!(toml_from_str::<Genesis>(toml).is_err());
    }

    #[test]
    fn an_empty_genesis_with_nothing_hosted_is_refused() {
        assert!(matches!(
            Genesis::default().validators(NetworkDefinition::simulator(), &[]),
            Err(NetworkFileError::NoValidators)
        ));
    }

    /// The iroh transport dials the file's peers less the host itself,
    /// through its relays, with versions held strictly.
    #[cfg(feature = "iroh")]
    #[test]
    fn the_iroh_transport_leaves_the_host_out_of_its_peers() {
        let me = SecretKey::generate();
        let other = SecretKey::generate();
        let peers = [
            format!("{}@127.0.0.1:9000", me.public()),
            format!("{}@127.0.0.1:9001", other.public()),
        ];
        let relays = ["https://relay.example".to_owned()];
        let config = iroh_config(me, &peers, &relays).expect("builds");
        let ids: Vec<_> = config.bootstrap_peers.iter().map(|p| p.id).collect();
        assert_eq!(ids, [other.public()]);
        assert_eq!(config.relays.len(), 1);
        assert_eq!(
            config.version_interop_mode,
            VersionInteroperabilityMode::Strict
        );
        assert!(iroh_config(SecretKey::generate(), &["nonsense".to_owned()], &[]).is_err());
    }
}
