import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Newly defined reconstruction format, not a recovered file format.
/// The raw credential document belongs in Keychain, never UserDefaults or diagnostics.
public struct SetupConfiguration: Codable, Equatable, Sendable {
    public struct Device: Codable, Equatable, Sendable {
        public var identifier: String
        public var name: String?
        public init(identifier: String, name: String? = nil) {
            self.identifier = identifier
            self.name = name
        }
    }

    public struct Transport: Codable, Equatable, Sendable {
        public var host: String
        public var port: UInt16
        public init(host: String, port: UInt16) {
            self.host = host
            self.port = port
        }
    }

    public struct Pairing: Codable, Equatable, Sendable {
        public var identifier: String
        public var privateKey: String
        public var publicKey: String
        public var peerIdentifier: String
        public var peerPublicKey: String
        public init(identifier: String, privateKey: String, publicKey: String,
                    peerIdentifier: String, peerPublicKey: String) {
            self.identifier = identifier
            self.privateKey = privateKey
            self.publicKey = publicKey
            self.peerIdentifier = peerIdentifier
            self.peerPublicKey = peerPublicKey
        }
    }

    /// Optional classic Lockdown credential for a cellular-only local tunnel.
    /// Keep the minimized plist opaque after validation; it belongs in Keychain.
    public struct Lockdown: Codable, Equatable, Sendable {
        public var pairingRecord: String
        public init(pairingRecord: String) { self.pairingRecord = pairingRecord }
    }

    public var format: String
    public var version: Int
    public var createdAt: String
    public var device: Device
    public var transport: Transport
    public var pairing: Pairing
    public var lockdown: Lockdown?

    public init(format: String = "gps.setup", version: Int = 1, createdAt: String,
                device: Device, transport: Transport, pairing: Pairing,
                lockdown: Lockdown? = nil) {
        self.format = format
        self.version = version
        self.createdAt = createdAt
        self.device = device
        self.transport = transport
        self.pairing = pairing
        self.lockdown = lockdown
    }

    public static let maximumFileSize = 64 * 1024

    public static func decode(_ data: Data) throws -> Self {
        guard !data.isEmpty, data.count <= maximumFileSize else {
            throw GPSError.invalidSetup("Choose a GPS setup file smaller than 64 KB.")
        }
        let configuration: Self
        do { configuration = try JSONDecoder().decode(Self.self, from: data) }
        catch { throw GPSError.invalidSetup("The expected GPS setup fields are missing or malformed.") }
        return try configuration.validated()
    }

    public func validated() throws -> Self {
        guard format == "gps.setup", version == 1 else {
            throw GPSError.invalidSetup("This version of the setup format is not supported.")
        }
        guard !device.identifier.isEmpty, device.identifier.utf8.count <= 256,
              !pairing.peerIdentifier.isEmpty, pairing.peerIdentifier.utf8.count <= 256,
              !pairing.identifier.isEmpty, pairing.identifier.utf8.count <= 256,
              !device.identifier.contains(where: { $0.isWhitespace || $0.isNewline }),
              !pairing.peerIdentifier.contains(where: { $0.isWhitespace || $0.isNewline }),
              !pairing.identifier.contains(where: { $0.isWhitespace || $0.isNewline }) else {
            throw GPSError.invalidSetup("The paired device identity is inconsistent.")
        }
        guard ISO8601DateFormatter().date(from: createdAt) != nil else {
            throw GPSError.invalidSetup("The creation date is missing or invalid.")
        }
        guard transport.port > 0, Self.isLocalHost(transport.host) else {
            throw GPSError.invalidSetup("The connection must use a local VPN or private network address.")
        }
        for key in [pairing.privateKey, pairing.publicKey, pairing.peerPublicKey] {
            guard let bytes = Data(base64Encoded: key), bytes.count == 32,
                  bytes.contains(where: { $0 != 0 }) else {
                throw GPSError.invalidSetup("A required pairing key is missing or invalid.")
            }
        }
        if let lockdown {
            try validateLockdownRecord(lockdown.pairingRecord)
        }
        return self
    }

    public func encoded() throws -> Data {
        _ = try validated()
        let data = try JSONEncoder().encode(self)
        guard data.count <= Self.maximumFileSize else {
            throw GPSError.invalidSetup("The setup file exceeds 64 KB.")
        }
        return data
    }

    private func validateLockdownRecord(_ encoded: String) throws {
        guard encoded.utf8.count <= 43_692,
              let bytes = Data(base64Encoded: encoded),
              !bytes.isEmpty, bytes.count <= 32 * 1024 else {
            throw GPSError.invalidSetup("The optional local pairing record is invalid or too large.")
        }
        var format = PropertyListSerialization.PropertyListFormat.binary
        guard let propertyList = try? PropertyListSerialization.propertyList(
            from: bytes, options: [], format: &format),
              let record = propertyList as? [String: Any] else {
            throw GPSError.invalidSetup("The optional local pairing record is not a valid property list.")
        }
        let allowedKeys: Set<String> = ["UDID", "DeviceCertificate", "HostCertificate",
                                        "HostPrivateKey", "RootCertificate", "HostID",
                                        "SystemBUID", "RootPrivateKey", "WiFiMACAddress"]
        guard Set(record.keys).isSubset(of: allowedKeys),
              let udid = record["UDID"] as? String, udid == device.identifier else {
            throw GPSError.invalidSetup("The optional local pairing record does not match this iPhone.")
        }
        for key in ["DeviceCertificate", "HostCertificate", "HostPrivateKey", "RootCertificate"] {
            guard let data = record[key] as? Data, !data.isEmpty else {
                throw GPSError.invalidSetup("The optional local pairing record is incomplete.")
            }
        }
        guard let hostID = record["HostID"] as? String, !hostID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let systemBUID = record["SystemBUID"] as? String, !systemBUID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let rootPrivateKey = record["RootPrivateKey"] as? Data, rootPrivateKey.isEmpty,
              record["WiFiMACAddress"] is String else {
            throw GPSError.invalidSetup("The optional local pairing record is incomplete.")
        }
    }

    private static func isLocalHost(_ host: String) -> Bool {
        // No arbitrary DNS destinations: pairing credentials never go to a public hostname.
        guard !host.utf8.contains(0), host.utf8.count <= 45 else { return false }
        if host.contains(":") {
            var address = in6_addr()
            guard host.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return false }
            return withUnsafeBytes(of: address) { bytes in
                let loopback = bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1
                return loopback || (bytes[0] & 0xfe) == 0xfc ||
                    (bytes[0] == 0xfe && bytes[1] == 0x80)
            }
        }
        let components = host.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 4, components.allSatisfy({
            !$0.isEmpty && ($0.count == 1 || $0.first != "0") && $0.allSatisfy { $0.isASCII && $0.isNumber }
        }) else { return false }
        var address = in_addr()
        guard host.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else { return false }
        return withUnsafeBytes(of: address) { bytes in
            bytes[0] == 10 || bytes[0] == 127 ||
                (bytes[0] == 192 && bytes[1] == 168) ||
                (bytes[0] == 172 && (16...31).contains(bytes[1])) ||
                (bytes[0] == 169 && bytes[1] == 254)
        }
    }
}
