//! Loopback fixtures for exercising relay and direct paths on one machine.
//!
//! Two endpoints on the same host always find a direct path, so a relayed
//! path cannot be studied there without help. Binding one endpoint to IPv4
//! loopback and the other to IPv6 loopback leaves the pair with no route of
//! their own; a [`UdpBridge`] between them is then the only direct path, and
//! closing it is a UDP blackout between the two hosts that leaves each one's
//! relay link untouched.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use iroh::RelayUrl;
use iroh_relay::server::{RelayConfig, Server, ServerConfig, SpawnError, SupervisorError};
use tokio::net::UdpSocket;
use tokio::spawn;
use tokio::task::JoinHandle;

/// Largest UDP payload the bridge forwards.
const MAX_DATAGRAM_BYTES: usize = 65_535;

/// A relay server on loopback, serving plain HTTP on a free port.
///
/// It offers no QUIC address discovery: endpoints that use it learn their
/// own addresses from their sockets and from what the test configures.
pub struct LocalRelay {
    server: Server,
    url: RelayUrl,
}

impl LocalRelay {
    /// Start a relay on a free loopback port.
    ///
    /// # Errors
    ///
    /// Returns the relay's [`SpawnError`] when the listener cannot bind.
    ///
    /// # Panics
    ///
    /// Panics if the server reports no HTTP address or one that does not
    /// form a URL; both are impossible for a configured relay.
    pub async fn spawn() -> Result<Self, SpawnError> {
        let mut config = ServerConfig::default();
        config.relay = Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0)));
        let server = Server::spawn(config).await?;
        let addr = server.http_addr().expect("the relay was configured");
        let url = format!("http://{addr}")
            .parse()
            .expect("a socket address forms a relay url");
        Ok(Self { server, url })
    }

    /// The URL endpoints name this relay by.
    #[must_use]
    pub fn url(&self) -> RelayUrl {
        self.url.clone()
    }

    /// Stop the relay, dropping every client link it holds.
    ///
    /// # Errors
    ///
    /// Returns the relay's [`SupervisorError`] when a server task failed.
    pub async fn shutdown(self) -> Result<(), SupervisorError> {
        self.server.shutdown().await
    }
}

/// A userspace UDP path between two sockets of different address families.
///
/// The bridge holds one socket in each family. A datagram that `left` sends
/// to [`Self::seen_by_left`] leaves the bridge's other socket addressed to
/// `right`, and the reverse; each side therefore sees its peer at a stable
/// address in its own family, as it would behind a one to one address
/// translation. Datagrams from any other source are dropped.
pub struct UdpBridge {
    seen_by_left: SocketAddr,
    seen_by_right: SocketAddr,
    open: Arc<AtomicBool>,
    forwarded: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    tasks: [JoinHandle<()>; 2],
}

impl UdpBridge {
    /// Bridge `left` and `right`, which must be loopback sockets of
    /// different address families.
    ///
    /// # Errors
    ///
    /// Returns the bind error when a bridge socket cannot be opened, or
    /// [`io::ErrorKind::InvalidInput`] when both addresses share a family.
    pub async fn spawn(left: SocketAddr, right: SocketAddr) -> io::Result<Self> {
        if left.is_ipv4() == right.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the bridged sockets must be of different address families",
            ));
        }
        let facing_left = Arc::new(UdpSocket::bind(loopback_in_family_of(left)).await?);
        let facing_right = Arc::new(UdpSocket::bind(loopback_in_family_of(right)).await?);
        let open = Arc::new(AtomicBool::new(true));
        let forwarded = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));

        let leg = |from: Arc<UdpSocket>, source: SocketAddr, to: Arc<UdpSocket>, dest| {
            spawn(forward(
                from,
                source,
                to,
                dest,
                Arc::clone(&open),
                Arc::clone(&forwarded),
                Arc::clone(&dropped),
            ))
        };
        let tasks = [
            leg(
                Arc::clone(&facing_left),
                left,
                Arc::clone(&facing_right),
                right,
            ),
            leg(
                Arc::clone(&facing_right),
                right,
                Arc::clone(&facing_left),
                left,
            ),
        ];

        Ok(Self {
            seen_by_left: facing_left.local_addr()?,
            seen_by_right: facing_right.local_addr()?,
            open,
            forwarded,
            dropped,
            tasks,
        })
    }

    /// The address at which `left` reaches `right`: what `right` advertises
    /// as its external address.
    #[must_use]
    pub const fn seen_by_left(&self) -> SocketAddr {
        self.seen_by_left
    }

    /// The address at which `right` reaches `left`: what `left` advertises
    /// as its external address.
    #[must_use]
    pub const fn seen_by_right(&self) -> SocketAddr {
        self.seen_by_right
    }

    /// Open or close the path. While closed, every datagram is dropped.
    pub fn set_open(&self, open: bool) {
        self.open.store(open, Ordering::Relaxed);
    }

    /// Datagrams carried across since the bridge started.
    #[must_use]
    pub fn forwarded(&self) -> u64 {
        self.forwarded.load(Ordering::Relaxed)
    }

    /// Datagrams dropped, while closed or from an unknown source.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl Drop for UdpBridge {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The loopback address, on a free port, in the family of `addr`.
fn loopback_in_family_of(addr: SocketAddr) -> SocketAddr {
    if addr.is_ipv4() {
        (Ipv4Addr::LOCALHOST, 0).into()
    } else {
        (Ipv6Addr::LOCALHOST, 0).into()
    }
}

/// Carry datagrams that `source` sends to `from` out of `to`, addressed to
/// `dest`.
async fn forward(
    from: Arc<UdpSocket>,
    source: SocketAddr,
    to: Arc<UdpSocket>,
    dest: SocketAddr,
    open: Arc<AtomicBool>,
    forwarded: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
    loop {
        let Ok((len, sender)) = from.recv_from(&mut buf).await else {
            return;
        };
        if sender != source || !open.load(Ordering::Relaxed) {
            dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if to.send_to(&buf[..len], dest).await.is_ok() {
            forwarded.fetch_add(1, Ordering::Relaxed);
        } else {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    async fn recv_within(socket: &UdpSocket, wait: Duration) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buf = [0u8; 64];
        let (len, from) = timeout(wait, socket.recv_from(&mut buf)).await.ok()?.ok()?;
        Some((buf[..len].to_vec(), from))
    }

    #[tokio::test]
    async fn carries_datagrams_both_ways_and_drops_them_while_closed() {
        let left = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let right = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        let bridge = UdpBridge::spawn(left.local_addr().unwrap(), right.local_addr().unwrap())
            .await
            .unwrap();

        left.send_to(b"to-right", bridge.seen_by_left())
            .await
            .unwrap();
        let (payload, from) = recv_within(&right, Duration::from_secs(5))
            .await
            .expect("the datagram crosses");
        assert_eq!(payload, b"to-right");
        assert_eq!(from, bridge.seen_by_right());

        right
            .send_to(b"to-left", bridge.seen_by_right())
            .await
            .unwrap();
        let (payload, from) = recv_within(&left, Duration::from_secs(5))
            .await
            .expect("the reply crosses");
        assert_eq!(payload, b"to-left");
        assert_eq!(from, bridge.seen_by_left());
        assert_eq!(bridge.forwarded(), 2);

        bridge.set_open(false);
        left.send_to(b"lost", bridge.seen_by_left()).await.unwrap();
        assert!(
            recv_within(&right, Duration::from_millis(200))
                .await
                .is_none(),
            "a closed bridge carries nothing"
        );
        assert_eq!(bridge.dropped(), 1);
    }

    #[tokio::test]
    async fn refuses_two_sockets_of_one_family() {
        let a: SocketAddr = (Ipv4Addr::LOCALHOST, 1).into();
        let b: SocketAddr = (Ipv4Addr::LOCALHOST, 2).into();
        assert!(UdpBridge::spawn(a, b).await.is_err());
    }
}
