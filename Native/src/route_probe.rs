//! Connect-only evidence for the LocalDevVPN peer and local loopback ports.
//! This is separate from the authenticated transport and never changes its sockets.

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple {
    use std::ffi::CStr;
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
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

    #[derive(Clone, Copy)]
    enum BindingBasis {
        ExactPeer,
        TcpSource,
        None,
        Unavailable,
    }

    impl BindingBasis {
        fn label(self) -> &'static str {
            match self {
                Self::ExactPeer => "exactPeer",
                Self::TcpSource => "tcpSource",
                Self::None => "none",
                Self::Unavailable => "unavailable",
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
            io::ErrorKind::PermissionDenied => "permissionDenied",
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
        local_ipv4: Option<Ipv4Addr>,
    }

    impl TcpOutcome {
        fn unavailable() -> Self {
            Self {
                result: "unavailable",
                source: "unavailable",
                local_ipv4: None,
            }
        }

        fn other_error() -> Self {
            Self {
                result: "otherError",
                source: "unavailable",
                local_ipv4: None,
            }
        }
    }

    enum SourceInterface {
        Unique(Ipv4Addr, u32),
        None,
        Ambiguous,
        Unavailable,
    }

    fn source_interface(outcome: TcpOutcome, interfaces: &[Interface]) -> SourceInterface {
        let Some(local) = outcome
            .local_ipv4
            .filter(|address| !address.is_unspecified())
        else {
            return SourceInterface::Unavailable;
        };
        let mut selected = None;
        for interface in interfaces.iter().filter(|entry| entry.address == local) {
            if interface.kind != InterfaceKind::Vpn
                || !interface.point_to_point
                || interface.index == 0
            {
                return SourceInterface::None;
            }
            if let Some(previous) = selected {
                if previous != interface.index {
                    return SourceInterface::Ambiguous;
                }
            } else {
                selected = Some(interface.index);
            }
        }
        selected.map_or(SourceInterface::Unavailable, |index| {
            SourceInterface::Unique(local, index)
        })
    }

    fn matching_tcp_source_interface(
        interfaces: &[Interface],
        lockdown: TcpOutcome,
        pairing: TcpOutcome,
    ) -> PeerInterface {
        // A source address is evidence even when interface enumeration cannot
        // classify it. Never bind if the two TCP destinations chose different
        // concrete local addresses.
        if let (Some(first), Some(second)) = (lockdown.local_ipv4, pairing.local_ipv4) {
            if !first.is_unspecified() && !second.is_unspecified() && first != second {
                return PeerInterface::Ambiguous;
            }
        }
        use SourceInterface::*;
        match (
            source_interface(lockdown, interfaces),
            source_interface(pairing, interfaces),
        ) {
            (Ambiguous, _) | (_, Ambiguous) => PeerInterface::Ambiguous,
            (None, _) | (_, None) => PeerInterface::None,
            (Unique(first_address, first_index), Unique(second_address, second_index)) => {
                if first_address == second_address && first_index == second_index {
                    PeerInterface::Unique(first_index)
                } else {
                    PeerInterface::Ambiguous
                }
            }
            (Unique(_, index), Unavailable) | (Unavailable, Unique(_, index)) => {
                PeerInterface::Unique(index)
            }
            (Unavailable, Unavailable) => PeerInterface::Unavailable,
        }
    }

    fn binding_interface(
        interfaces: Option<&[Interface]>,
        target: Ipv4Addr,
        lockdown: TcpOutcome,
        pairing: TcpOutcome,
    ) -> (PeerInterface, BindingBasis) {
        let Some(interfaces) = interfaces else {
            return (PeerInterface::Unavailable, BindingBasis::Unavailable);
        };
        match matching_peer_interface(interfaces, target) {
            PeerInterface::Unique(index) => (PeerInterface::Unique(index), BindingBasis::ExactPeer),
            PeerInterface::None => {
                let candidate = matching_tcp_source_interface(interfaces, lockdown, pairing);
                let basis = match candidate {
                    PeerInterface::Unique(_) => BindingBasis::TcpSource,
                    PeerInterface::Unavailable => BindingBasis::Unavailable,
                    _ => BindingBasis::None,
                };
                (candidate, basis)
            }
            PeerInterface::Ambiguous => (PeerInterface::Ambiguous, BindingBasis::None),
            PeerInterface::Unavailable => (PeerInterface::Unavailable, BindingBasis::Unavailable),
        }
    }

    fn tcp_probe(
        endpoint: SocketAddr,
        bound_interface: Option<u32>,
        interfaces: &[Interface],
    ) -> TcpOutcome {
        let domain = match endpoint {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };
        let Ok(socket) = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) else {
            return TcpOutcome::other_error();
        };
        if let Some(index) = bound_interface {
            if !endpoint.is_ipv4() {
                return TcpOutcome::other_error();
            }
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
        let endpoint = SockAddr::from(endpoint);
        let result = match socket.connect_timeout(&endpoint, PROBE_TIMEOUT) {
            Ok(()) => "connected",
            Err(error) => outcome(&error),
        };
        let local_ipv4 = socket
            .local_addr()
            .ok()
            .and_then(|address| address.as_socket())
            .and_then(|address| match address {
                SocketAddr::V4(address) => Some(*address.ip()),
                SocketAddr::V6(_) => None,
            });
        let source = local_ipv4
            .map(|address| source_class(address, interfaces))
            .unwrap_or("unavailable");
        TcpOutcome {
            result,
            source,
            local_ipv4,
        }
    }

    // The two ports are independent. Both ordinary probes must finish before
    // choosing a bound interface, but they need not consume consecutive timeouts.
    fn probe_pair(
        endpoints: [SocketAddr; 2],
        bound_interface: Option<u32>,
        interfaces: &[Interface],
        probe: impl Fn(SocketAddr, Option<u32>, &[Interface]) -> TcpOutcome + Sync,
    ) -> [TcpOutcome; 2] {
        std::thread::scope(|scope| {
            let first = scope.spawn(|| probe(endpoints[0], bound_interface, interfaces));
            let second = probe(endpoints[1], bound_interface, interfaces);
            [
                first.join().unwrap_or_else(|_| TcpOutcome::other_error()),
                second,
            ]
        })
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SocketResults {
        ordinary: &'static str,
        ordinary_source: &'static str,
        vpn_bound: &'static str,
        vpn_bound_source: &'static str,
    }

    #[derive(Serialize)]
    struct LoopbackResults {
        lockdown: &'static str,
        pairing: &'static str,
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
        binding_basis: &'static str,
        lockdown: SocketResults,
        pairing: SocketResults,
        #[serde(rename = "loopbackIPv4")]
        loopback_ipv4: LoopbackResults,
        #[serde(rename = "loopbackIPv6")]
        loopback_ipv6: LoopbackResults,
    }

    pub(crate) fn probe(target: Ipv4Addr, pairing_port: u16) -> Result<String, String> {
        let interfaces = local_interfaces();
        let route_source = interfaces
            .as_ref()
            .map_or("unavailable", |entries| preview_source(target, entries));
        let entries = interfaces.as_deref().unwrap_or(&[]);
        let (peer, basis, lockdown, pairing, loopback_ipv4, loopback_ipv6) =
            std::thread::scope(|scope| {
                // These four independent fixed-port checks run alongside the
                // ordinary and bound VPN checks to keep the total wait bounded.
                let v4_lockdown = scope.spawn(|| {
                    tcp_probe(
                        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 62078),
                        None,
                        &[],
                    )
                    .result
                });
                let v4_pairing = scope.spawn(|| {
                    tcp_probe(
                        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), pairing_port),
                        None,
                        &[],
                    )
                    .result
                });
                let v6_lockdown = scope.spawn(|| {
                    tcp_probe(
                        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 62078),
                        None,
                        &[],
                    )
                    .result
                });
                let v6_pairing = scope.spawn(|| {
                    tcp_probe(
                        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), pairing_port),
                        None,
                        &[],
                    )
                    .result
                });

                let lockdown_endpoint = SocketAddr::new(IpAddr::V4(target), 62078);
                let pairing_endpoint = SocketAddr::new(IpAddr::V4(target), pairing_port);
                let endpoints = [lockdown_endpoint, pairing_endpoint];
                let [ordinary_lockdown, ordinary_pairing] =
                    probe_pair(endpoints, None, entries, tcp_probe);
                let (peer, basis) = binding_interface(
                    interfaces.as_deref(),
                    target,
                    ordinary_lockdown,
                    ordinary_pairing,
                );
                let [bound_lockdown, bound_pairing] = peer.index().map_or_else(
                    || [TcpOutcome::unavailable(); 2],
                    |index| probe_pair(endpoints, Some(index), entries, tcp_probe),
                );
                let lockdown = SocketResults::new(ordinary_lockdown, bound_lockdown);
                let pairing = SocketResults::new(ordinary_pairing, bound_pairing);
                let loopback_ipv4 = LoopbackResults {
                    lockdown: v4_lockdown.join().unwrap_or("otherError"),
                    pairing: v4_pairing.join().unwrap_or("otherError"),
                };
                let loopback_ipv6 = LoopbackResults {
                    lockdown: v6_lockdown.join().unwrap_or("otherError"),
                    pairing: v6_pairing.join().unwrap_or("otherError"),
                };
                (peer, basis, lockdown, pairing, loopback_ipv4, loopback_ipv6)
            });
        serde_json::to_string(&Report {
            version: 1,
            route_source,
            peer_interface: peer.label(),
            binding_basis: basis.label(),
            lockdown,
            pairing,
            loopback_ipv4,
            loopback_ipv6,
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

        fn socket_source(address: Option<Ipv4Addr>) -> TcpOutcome {
            TcpOutcome {
                result: "refused",
                source: if address.is_some() {
                    "vpn"
                } else {
                    "unavailable"
                },
                local_ipv4: address,
            }
        }

        #[test]
        fn port_probes_overlap_and_preserve_endpoint_order_and_binding() {
            use std::sync::{Mutex, mpsc};

            let (first_tx, first_rx) = mpsc::channel();
            let (second_tx, second_rx) = mpsc::channel();
            let first_rx = Mutex::new(first_rx);
            let second_rx = Mutex::new(second_rx);
            let endpoints = [
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 62078),
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 49152),
            ];
            let entries = [entry(8, None, InterfaceKind::Vpn)];
            let results = probe_pair(
                endpoints,
                Some(8),
                &entries,
                |endpoint, bound, interfaces| {
                    assert_eq!(bound, Some(8));
                    assert_eq!(interfaces.len(), 1);
                    if endpoint == endpoints[0] {
                        first_tx.send(()).unwrap();
                        second_rx
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(2))
                            .unwrap();
                        socket_source(Some(Ipv4Addr::LOCALHOST))
                    } else {
                        assert_eq!(endpoint, endpoints[1]);
                        second_tx.send(()).unwrap();
                        first_rx
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(2))
                            .unwrap();
                        TcpOutcome::unavailable()
                    }
                },
            );
            assert_eq!(results[0].result, "refused");
            assert_eq!(results[0].local_ipv4, Some(Ipv4Addr::LOCALHOST));
            assert_eq!(results[1].result, "unavailable");
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

        #[test]
        fn selects_unique_vpn_interface_from_actual_tcp_source() {
            let source = Ipv4Addr::new(10, 7, 1, 1);
            let target = Ipv4Addr::new(10, 7, 0, 1);
            let entries = [entry(8, None, InterfaceKind::Vpn)];
            let (peer, basis) = binding_interface(
                Some(&entries),
                target,
                socket_source(Some(source)),
                socket_source(Some(source)),
            );
            assert!(matches!(peer, PeerInterface::Unique(8)));
            assert!(matches!(basis, BindingBasis::TcpSource));

            let (peer, basis) = binding_interface(
                Some(&entries),
                target,
                socket_source(Some(source)),
                socket_source(None),
            );
            assert!(matches!(peer, PeerInterface::Unique(8)));
            assert!(matches!(basis, BindingBasis::TcpSource));
        }

        #[test]
        fn refuses_ambiguous_tcp_source_interface() {
            let source = Ipv4Addr::new(10, 7, 1, 1);
            let entries = [
                entry(8, None, InterfaceKind::Vpn),
                entry(9, None, InterfaceKind::Vpn),
            ];
            assert!(matches!(
                matching_tcp_source_interface(
                    &entries,
                    socket_source(Some(source)),
                    socket_source(None)
                ),
                PeerInterface::Ambiguous
            ));
        }

        #[test]
        fn refuses_non_vpn_or_non_point_to_point_source() {
            let source = Ipv4Addr::new(10, 7, 1, 1);
            let cellular = [entry(8, None, InterfaceKind::Cellular)];
            assert!(matches!(
                matching_tcp_source_interface(
                    &cellular,
                    socket_source(Some(source)),
                    socket_source(None)
                ),
                PeerInterface::None
            ));
            let mut tunnel = entry(8, None, InterfaceKind::Vpn);
            tunnel.point_to_point = false;
            assert!(matches!(
                matching_tcp_source_interface(
                    &[tunnel],
                    socket_source(Some(source)),
                    socket_source(None)
                ),
                PeerInterface::None
            ));
        }

        #[test]
        fn refuses_disagreeing_endpoint_sources_even_on_one_vpn() {
            let first = Ipv4Addr::new(10, 7, 1, 1);
            let second = Ipv4Addr::new(10, 7, 1, 2);
            let mut second_entry = entry(8, None, InterfaceKind::Vpn);
            second_entry.address = second;
            let entries = [entry(8, None, InterfaceKind::Vpn), second_entry];
            assert!(matches!(
                matching_tcp_source_interface(
                    &entries,
                    socket_source(Some(first)),
                    socket_source(Some(second))
                ),
                PeerInterface::Ambiguous
            ));

            // The second source need not be mapped by getifaddrs to be a
            // contradictory TCP result.
            assert!(matches!(
                matching_tcp_source_interface(
                    &[entry(8, None, InterfaceKind::Vpn)],
                    socket_source(Some(first)),
                    socket_source(Some(second))
                ),
                PeerInterface::Ambiguous
            ));
        }

        #[test]
        fn ipv6_loopback_tcp_probe_uses_an_ipv6_socket() {
            let listener = std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
            let result = tcp_probe(listener.local_addr().unwrap(), None, &[]);
            assert_eq!(result.result, "connected");
            assert!(result.local_ipv4.is_none());
        }

        #[test]
        fn report_keeps_version_one_loopback_field_names() {
            let report = Report {
                version: 1,
                route_source: "vpn",
                peer_interface: "unique",
                binding_basis: "tcpSource",
                lockdown: SocketResults::new(TcpOutcome::unavailable(), TcpOutcome::unavailable()),
                pairing: SocketResults::new(TcpOutcome::unavailable(), TcpOutcome::unavailable()),
                loopback_ipv4: LoopbackResults {
                    lockdown: "connected",
                    pairing: "refused",
                },
                loopback_ipv6: LoopbackResults {
                    lockdown: "refused",
                    pairing: "connected",
                },
            };
            let value = serde_json::to_value(report).unwrap();
            assert_eq!(value["version"], 1);
            assert_eq!(value["bindingBasis"], "tcpSource");
            assert_eq!(value["loopbackIPv4"]["lockdown"], "connected");
            assert_eq!(value["loopbackIPv6"]["pairing"], "connected");
            assert!(value.get("loopbackIpv4").is_none());
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) use apple::probe;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub(crate) fn probe(_target: std::net::Ipv4Addr, _pairing_port: u16) -> Result<String, String> {
    Err("local VPN route check is available only on Apple platforms".into())
}
