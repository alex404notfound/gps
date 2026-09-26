//! Connect-only evidence for the LocalDevVPN route. This is deliberately
//! separate from the authenticated transport and never changes its sockets.

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple {
    use std::ffi::CStr;
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::os::fd::AsRawFd;
    use std::ptr;
    use std::time::Duration;

    use serde::Serialize;
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum InterfaceKind {
        Vpn,
        Cellular,
        Wifi,
        Other,
    }

    impl InterfaceKind {
        fn from_name(name: &[u8]) -> Self {
            if name.starts_with(b"utun") {
                Self::Vpn
            } else if name.starts_with(b"pdp_ip") {
                Self::Cellular
            } else if name.starts_with(b"en") {
                Self::Wifi
            } else {
                Self::Other
            }
        }

        fn label(self) -> &'static str {
            match self {
                Self::Vpn => "vpn",
                Self::Cellular => "cellular",
                Self::Wifi => "wifi",
                Self::Other => "other",
            }
        }
    }

    #[derive(Clone, Copy)]
    struct Interface {
        index: u32,
        address: Ipv4Addr,
        peer: Option<Ipv4Addr>,
        point_to_point: bool,
        kind: InterfaceKind,
    }

    enum PeerInterface {
        Unique(u32),
        None,
        Ambiguous,
        Unavailable,
    }

    impl PeerInterface {
        fn label(&self) -> &'static str {
            match self {
                Self::Unique(_) => "unique",
                Self::None => "none",
                Self::Ambiguous => "ambiguous",
                Self::Unavailable => "unavailable",
            }
        }

        fn index(&self) -> Option<u32> {
            match self {
                Self::Unique(index) => Some(*index),
                _ => None,
            }
        }
    }

    fn matching_peer_interface(interfaces: &[Interface], target: Ipv4Addr) -> PeerInterface {
        let mut selected = None;
        for interface in interfaces {
            if !interface.point_to_point
                || interface.kind != InterfaceKind::Vpn
                || interface.peer != Some(target)
                || interface.index == 0
            {
                continue;
            }
            if let Some(previous) = selected {
                if previous != interface.index {
                    return PeerInterface::Ambiguous;
                }
            } else {
                selected = Some(interface.index);
            }
        }
        selected.map_or(PeerInterface::None, PeerInterface::Unique)
    }

    fn source_class(local: Ipv4Addr, interfaces: &[Interface]) -> &'static str {
        let mut kind = None;
        for interface in interfaces.iter().filter(|entry| entry.address == local) {
            if let Some(previous) = kind {
                if previous != interface.kind {
                    return "unavailable";
                }
            } else {
                kind = Some(interface.kind);
            }
        }
        kind.map_or("unavailable", InterfaceKind::label)
    }

    // UDP connect performs a destination-specific route lookup without sending
    // a datagram. It is a route preview, not proof of the TCP socket's path.
    fn preview_source(target: Ipv4Addr, interfaces: &[Interface]) -> &'static str {
        let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            return "unavailable";
        };
        if socket.connect((target, 62078)).is_err() {
            return "unavailable";
        }
        let Ok(SocketAddr::V4(local)) = socket.local_addr() else {
            return "unavailable";
        };
        source_class(*local.ip(), interfaces)
    }

    unsafe fn ipv4_address(address: *const libc::sockaddr) -> Option<Ipv4Addr> {
        if address.is_null() || unsafe { (*address).sa_family } as i32 != libc::AF_INET {
            return None;
        }
        if unsafe { (*address).sa_len } < mem::size_of::<libc::sockaddr_in>() as u8 {
            return None;
        }
        let sin = unsafe { &*(address.cast::<libc::sockaddr_in>()) };
        Some(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()))
    }

    struct IfAddrs(*mut libc::ifaddrs);

    impl Drop for IfAddrs {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }

    fn local_interfaces() -> Option<Vec<Interface>> {
        let mut first = ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut first) } != 0 {
            return None;
        }
        let _guard = IfAddrs(first);
        let mut entries = Vec::new();
        let mut current = first;
        let mut examined = 0;
        while !current.is_null() && examined < 1024 {
            examined += 1;
            let entry = unsafe { &*current };
            if !entry.ifa_name.is_null() {
                if let Some(address) = unsafe { ipv4_address(entry.ifa_addr) } {
                    let name = unsafe { CStr::from_ptr(entry.ifa_name) }.to_bytes();
                    let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
                    let point_to_point = entry.ifa_flags & (libc::IFF_POINTOPOINT as u32) != 0;
                    entries.push(Interface {
                        index,
                        address,
                        peer: if point_to_point {
                            unsafe { ipv4_address(entry.ifa_dstaddr) }
                        } else {
                            None
                        },
                        point_to_point,
                        kind: InterfaceKind::from_name(name),
                    });
                }
            }
            current = entry.ifa_next;
        }
        if !current.is_null() {
            None
        } else {
            Some(entries)
        }
    }

    fn outcome(error: &io::Error) -> &'static str {
        match error.kind() {
            io::ErrorKind::ConnectionRefused => "refused",
            io::ErrorKind::TimedOut => "timedOut",
            io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::AddrNotAvailable => "unreachable",
            _ => "otherError",
        }
    }

    #[derive(Clone, Copy)]
    struct TcpOutcome {
        result: &'static str,
        source: &'static str,
    }

    impl TcpOutcome {
        fn unavailable() -> Self {
            Self {
                result: "unavailable",
                source: "unavailable",
            }
        }

        fn other_error() -> Self {
            Self {
                result: "otherError",
                source: "unavailable",
            }
        }
    }

    fn tcp_probe(
        target: Ipv4Addr,
        port: u16,
        bound_interface: Option<u32>,
        interfaces: &[Interface],
    ) -> TcpOutcome {
        let Ok(socket) = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) else {
            return TcpOutcome::other_error();
        };
        if let Some(index) = bound_interface {
            let Ok(index) = libc::c_int::try_from(index) else {
                return TcpOutcome::other_error();
            };
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_BOUND_IF,
                    (&index as *const libc::c_int).cast(),
                    mem::size_of_val(&index) as libc::socklen_t,
                )
            };
            if result != 0 {
                return TcpOutcome::other_error();
            }
        }
        let endpoint = SockAddr::from(SocketAddr::new(IpAddr::V4(target), port));
        let result = match socket.connect_timeout(&endpoint, PROBE_TIMEOUT) {
            Ok(()) => "connected",
            Err(error) => outcome(&error),
        };
        let source = socket
            .local_addr()
            .ok()
            .and_then(|address| address.as_socket())
            .and_then(|address| match address {
                SocketAddr::V4(address) => Some(source_class(*address.ip(), interfaces)),
                SocketAddr::V6(_) => None,
            })
            .unwrap_or("unavailable");
        TcpOutcome { result, source }
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SocketResults {
        ordinary: &'static str,
        ordinary_source: &'static str,
        vpn_bound: &'static str,
        vpn_bound_source: &'static str,
    }

    impl SocketResults {
        fn new(ordinary: TcpOutcome, vpn_bound: TcpOutcome) -> Self {
            Self {
                ordinary: ordinary.result,
                ordinary_source: ordinary.source,
                vpn_bound: vpn_bound.result,
                vpn_bound_source: vpn_bound.source,
            }
        }
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Report {
        version: u8,
        route_source: &'static str,
        peer_interface: &'static str,
        lockdown: SocketResults,
        pairing: SocketResults,
    }

    pub(crate) fn probe(target: Ipv4Addr, pairing_port: u16) -> Result<String, String> {
        let interfaces = local_interfaces();
        let peer = interfaces
            .as_ref()
            .map_or(PeerInterface::Unavailable, |entries| {
                matching_peer_interface(entries, target)
            });
        let route_source = interfaces
            .as_ref()
            .map_or("unavailable", |entries| preview_source(target, entries));
        let entries = interfaces.as_deref().unwrap_or(&[]);
        let bound = peer.index();
        let lockdown = SocketResults::new(
            tcp_probe(target, 62078, None, entries),
            bound.map_or_else(TcpOutcome::unavailable, |index| {
                tcp_probe(target, 62078, Some(index), entries)
            }),
        );
        let pairing = SocketResults::new(
            tcp_probe(target, pairing_port, None, entries),
            bound.map_or_else(TcpOutcome::unavailable, |index| {
                tcp_probe(target, pairing_port, Some(index), entries)
            }),
        );
        serde_json::to_string(&Report {
            version: 1,
            route_source,
            peer_interface: peer.label(),
            lockdown,
            pairing,
        })
        .map_err(|_| "route check serialization failed".to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn entry(index: u32, peer: Option<Ipv4Addr>, kind: InterfaceKind) -> Interface {
            Interface {
                index,
                address: Ipv4Addr::new(10, 7, 1, 1),
                peer,
                point_to_point: true,
                kind,
            }
        }

        #[test]
        fn selects_only_the_exact_vpn_peer() {
            let target = Ipv4Addr::new(10, 7, 0, 1);
            let entries = [
                entry(8, Some(Ipv4Addr::new(10, 7, 0, 2)), InterfaceKind::Vpn),
                entry(9, Some(target), InterfaceKind::Cellular),
                entry(10, Some(target), InterfaceKind::Vpn),
            ];
            assert!(matches!(
                matching_peer_interface(&entries, target),
                PeerInterface::Unique(10)
            ));
        }

        #[test]
        fn refuses_an_ambiguous_peer_interface() {
            let target = Ipv4Addr::new(10, 7, 0, 1);
            let entries = [
                entry(8, Some(target), InterfaceKind::Vpn),
                entry(8, Some(target), InterfaceKind::Vpn),
                entry(9, Some(target), InterfaceKind::Vpn),
            ];
            assert!(matches!(
                matching_peer_interface(&entries, target),
                PeerInterface::Ambiguous
            ));
        }

        #[test]
        fn unrelated_tunnel_is_not_a_binding_candidate() {
            let target = Ipv4Addr::new(10, 7, 0, 1);
            let entries = [entry(
                8,
                Some(Ipv4Addr::new(10, 7, 0, 2)),
                InterfaceKind::Vpn,
            )];
            assert!(matches!(
                matching_peer_interface(&entries, target),
                PeerInterface::None
            ));
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) use apple::probe;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub(crate) fn probe(_target: std::net::Ipv4Addr, _pairing_port: u16) -> Result<String, String> {
    Err("local VPN route check is available only on Apple platforms".into())
}
