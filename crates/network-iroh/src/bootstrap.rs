//! Bootstrap peers named by DNS.
//!
//! A bootstrap entry is either a host's address in the
//! [`parse_endpoint_addr`] form, or a domain. A domain's peers are the TXT
//! records at `_hyperscale.<domain>`, one peer each, in that same form:
//!
//! ```text
//! _hyperscale.boot.example.  TXT  "<endpoint id>@203.0.113.7:9000,https://relay.example"
//! ```
//!
//! A record longer than one TXT string may be split across several; they
//! are read joined. The domain is looked up again on every
//! [`RESOLVE_INTERVAL`], so a record changed in DNS reaches hosts already
//! running, and one lookup that fails keeps the peers the last one found.

use std::time::Duration;

use iroh::dns::DnsResolver;
use iroh::{EndpointAddr, EndpointId};
use tracing::{debug, warn};

use crate::config::parse_endpoint_addr;

/// Label under which a domain lists its bootstrap peers.
pub const TXT_LABEL: &str = "_hyperscale";

/// How often a bootstrap domain is looked up again.
pub const RESOLVE_INTERVAL: Duration = Duration::from_mins(1);

/// Longest one domain's lookup may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// One bootstrap entry, as configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapEntry {
    /// A host at known addresses.
    Peer(EndpointAddr),
    /// A domain whose TXT records name the hosts.
    Domain(String),
}

/// Parse a bootstrap entry: an address when it holds `@`, a domain
/// otherwise.
///
/// # Errors
///
/// Returns a description of an address that does not parse, or of text
/// that is no domain name.
pub fn parse_bootstrap_entry(text: &str) -> Result<BootstrapEntry, String> {
    if text.contains('@') {
        return parse_endpoint_addr(text).map(BootstrapEntry::Peer);
    }
    let domain = text.trim_end_matches('.');
    let well_formed = !domain.is_empty()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if well_formed {
        Ok(BootstrapEntry::Domain(domain.to_ascii_lowercase()))
    } else {
        Err(format!(
            "{text}: neither <endpoint id>@<address>[,<address>...] nor a domain name"
        ))
    }
}

/// The name a domain's bootstrap records are looked up at.
#[must_use]
pub fn txt_name(domain: &str) -> String {
    format!("{TXT_LABEL}.{domain}")
}

/// The peers `domains` name, less `me`, or `None` for a domain whose lookup
/// failed. A record that does not parse is skipped.
pub async fn resolve(
    resolver: &DnsResolver,
    domains: &[String],
    me: EndpointId,
) -> Vec<Option<Vec<EndpointAddr>>> {
    let mut found = Vec::with_capacity(domains.len());
    for domain in domains {
        let txt = txt_name(domain);
        match resolver.lookup_txt(&txt, LOOKUP_TIMEOUT).await {
            Ok(records) => {
                let peers: Vec<EndpointAddr> = records
                    .filter_map(|record| match parse_endpoint_addr(&record.to_string()) {
                        Ok(addr) => Some(addr),
                        Err(reason) => {
                            warn!(%txt, %reason, "Skipping a bootstrap record that does not parse");
                            None
                        }
                    })
                    .filter(|addr| addr.id != me)
                    .collect();
                debug!(%txt, peers = peers.len(), "Resolved bootstrap domain");
                found.push(Some(peers));
            }
            Err(err) => {
                warn!(%txt, %err, "Bootstrap domain lookup failed");
                found.push(None);
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    #[test]
    fn an_entry_with_an_at_is_an_address() {
        let id = SecretKey::generate().public();
        let entry = parse_bootstrap_entry(&format!("{id}@127.0.0.1:9000")).expect("parses");
        assert!(matches!(entry, BootstrapEntry::Peer(addr) if addr.id == id));
    }

    #[test]
    fn an_entry_without_one_is_a_domain() {
        assert_eq!(
            parse_bootstrap_entry("Boot.Example.org."),
            Ok(BootstrapEntry::Domain("boot.example.org".into()))
        );
    }

    #[test]
    fn text_that_is_neither_is_refused() {
        for text in [
            "",
            "boot..example",
            "-boot.example",
            "boot example",
            "boot_x.example",
        ] {
            assert!(parse_bootstrap_entry(text).is_err(), "{text:?} parsed");
        }
    }

    #[test]
    fn records_live_under_the_label() {
        assert_eq!(txt_name("boot.example"), "_hyperscale.boot.example");
    }
}
