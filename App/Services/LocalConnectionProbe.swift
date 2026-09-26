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
    enum Outcome: String, Decodable, Sendable {
        case connected, refused, timedOut, unreachable, otherError, unavailable
        var title: String {
            switch self {
            case .connected: "TCP accepted"
            case .refused: "TCP refused"
            case .timedOut: "timed out"
            case .unreachable: "unreachable"
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
    let version: Int
    let routeSource: Source
    let peerInterface: PeerInterface
    let lockdown: Endpoint
    let pairing: Endpoint

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
            lines.append("Matching VPN interface found.")
            lines.append("VPN-bound Lockdown: \(lockdown.vpnBound.title).")
            lines.append("VPN-bound remote pairing: \(pairing.vpnBound.title).")
        case .none: lines.append("No exact peer interface was advertised; no forced route was tried.")
        case .ambiguous: lines.append("The peer interface was ambiguous; no forced route was tried.")
        case .unavailable: lines.append("The peer interface could not be checked; no forced route was tried.")
        }
        lines.append("The preview uses a separate route lookup. TCP availability only; no pairing or location command was sent.")
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
