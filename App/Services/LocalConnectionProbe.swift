import Foundation

struct LocalConnectionProbeResult: Decodable, Sendable {
    enum Source: String, Decodable, Sendable {
        case vpn, cellular, wifi, other, unavailable
        var title: String {
            switch self {
            case .vpn: "local VPN"
            case .cellular: "cellular interface"
            case .wifi: "Wi-Fi interface"
            case .other: "another local interface"
            case .unavailable: "unavailable"
            }
        }
    }
    enum PeerInterface: String, Decodable, Sendable { case unique, none, ambiguous, unavailable }
    enum BindingBasis: String, Decodable, Sendable { case exactPeer, tcpSource, none, unavailable }
    enum Outcome: String, Decodable, Sendable {
        case connected, refused, timedOut, unreachable, permissionDenied, otherError, unavailable
        var title: String {
            switch self {
            case .connected: "TCP accepted"
            case .refused: "TCP refused"
            case .timedOut: "timed out"
            case .unreachable: "unreachable"
            case .permissionDenied: "access denied by iOS"
            case .otherError: "socket error"
            case .unavailable: "not available"
            }
        }
    }
    struct Endpoint: Decodable, Sendable {
        let ordinary: Outcome
        let vpnBound: Outcome
        let ordinarySource: Source?
        let vpnBoundSource: Source?
    }
    struct Loopback: Decodable, Sendable {
        let lockdown: Outcome
        let pairing: Outcome
    }
    let version: Int
    let routeSource: Source
    let peerInterface: PeerInterface
    let lockdown: Endpoint
    let pairing: Endpoint
    let bindingBasis: BindingBasis?
    let loopbackIPv4: Loopback?
    let loopbackIPv6: Loopback?

    var directConnectionCandidates: [String] {
        [("127.0.0.1", loopbackIPv4), ("::1", loopbackIPv6)].compactMap { host, result in
            result?.pairing == .connected ? host : nil
        }
    }

    var summary: String {
        var lines = ["Route preview: \(routeSource.title).",
                     "Lockdown: \(lockdown.ordinary.title).",
                     "Remote pairing: \(pairing.ordinary.title)."]
        if let source = lockdown.ordinarySource, source != .unavailable {
            lines.append("Lockdown source: \(source.title).")
        }
        if let source = pairing.ordinarySource, source != .unavailable {
            lines.append("Remote pairing source: \(source.title).")
        }
        switch peerInterface {
        case .unique:
            lines.append(bindingBasis == .tcpSource
                ? "VPN interface selected from the TCP socket source."
                : "Exact VPN peer interface found.")
            lines.append("VPN-bound Lockdown: \(lockdown.vpnBound.title).")
            lines.append("VPN-bound remote pairing: \(pairing.vpnBound.title).")
        case .none: lines.append("No matching VPN interface was found; no forced route was tried.")
        case .ambiguous: lines.append("The VPN interface evidence was ambiguous; no forced route was tried.")
        case .unavailable: lines.append("The VPN interface could not be checked; no forced route was tried.")
        }
        for (host, result) in [("127.0.0.1", loopbackIPv4), ("::1", loopbackIPv6)] {
            if let result {
                lines.append("\(host) Lockdown: \(result.lockdown.title).")
                lines.append("\(host) remote pairing: \(result.pairing.title).")
            }
        }
        if !directConnectionCandidates.isEmpty {
            lines.append("A direct pairing port accepted TCP. Use a direct connection button below to test authentication and service access. Your saved Device IP stays unchanged.")
        }
        lines.append("The preview uses a separate route lookup. TCP acceptance does not confirm authentication or later service access. No pairing or location command was sent.")
        return lines.joined(separator: "\n")
    }
}

final class LocalConnectionProbe: @unchecked Sendable {
    static let shared = LocalConnectionProbe()
    private let queue = DispatchQueue(label: "app.gps.reconstruction.route-check", qos: .utility)

    private init() {}

    func check(configuration: SetupConfiguration) async throws -> LocalConnectionProbeResult {
        let data = try configuration.encoded()
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                var output: UnsafeMutablePointer<CChar>?
                var error: UnsafeMutablePointer<CChar>?
                let status = data.withUnsafeBytes { bytes in
                    gps_native_probe_local_route(bytes.bindMemory(to: UInt8.self).baseAddress,
                                                 bytes.count, &output, &error)
                }
                defer {
                    if let output { gps_native_error_free(output) }
                    if let error { gps_native_error_free(error) }
                }
                do {
                    guard status == 0, let output else {
                        throw GPSError.transport(error.map { String(cString: $0) }
                            ?? "The local connection check could not finish.")
                    }
                    let result = try JSONDecoder().decode(LocalConnectionProbeResult.self,
                                                         from: Data(String(cString: output).utf8))
                    guard result.version == 1 else {
                        throw GPSError.transport("The local connection check returned an unsupported result.")
                    }
                    continuation.resume(returning: result)
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
}
