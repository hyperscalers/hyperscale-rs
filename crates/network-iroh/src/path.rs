//! What kind of path a connection is sending on.

use iroh::TransportAddr;
use iroh::endpoint::{Connection, Path};

/// The two kinds of path a connection to a validator's host can send on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathKind {
    /// Datagrams travel between the two hosts' own sockets.
    Direct,
    /// Datagrams travel through a relay server, over its TCP link to each
    /// host.
    Relayed,
}

impl PathKind {
    /// The kind of a path to `remote`.
    #[must_use]
    pub fn of(remote: &TransportAddr) -> Self {
        if remote.is_relay() {
            Self::Relayed
        } else {
            Self::Direct
        }
    }
}

/// The kind of the path `connection` currently sends on, or `None` while it
/// has selected none.
#[must_use]
pub fn selected(connection: &Connection) -> Option<PathKind> {
    connection
        .paths()
        .iter()
        .find(Path::is_selected)
        .map(|path| PathKind::of(path.remote_addr()))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;

    #[test]
    fn a_relay_url_is_relayed_and_a_socket_is_direct() {
        let relay = TransportAddr::Relay("https://relay.example".parse().unwrap());
        let socket = TransportAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 4001)));
        assert_eq!(PathKind::of(&relay), PathKind::Relayed);
        assert_eq!(PathKind::of(&socket), PathKind::Direct);
    }
}
