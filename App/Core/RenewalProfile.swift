import CoreFoundation
import Foundation

/// An informational view of the XML property list embedded in a provisioning profile.
/// Parsing and policy checks do not verify the CMS signature. The device must accept the
/// original CMS bytes through its provisioning service and confirm the installed result.
public struct RenewalProfile: Sendable {
    public static let maximumCMSSize = 2 * 1024 * 1024
    public static let rebuiltBundleIdentifier = "app.gps.reconstruction"

    public enum PlistValue: Equatable, Sendable {
        case string(String)
        case boolean(Bool)
        case integer(Int64)
        case real(Double)
        case data(Data)
        case date(Date)
        case array([PlistValue])
        case dictionary([String: PlistValue])
    }

    public let uuid: String
    public let teamID: String
    public let applicationIdentifier: String
    public let bundleIdentifier: String
    public let creation: Date
    public let expiration: Date
    public let deviceIDs: Set<String>
    public let developerCertificates: [Data]
    public let entitlements: [String: PlistValue]

    public init(cmsData: Data) throws {
        guard !cmsData.isEmpty, cmsData.count <= Self.maximumCMSSize else {
            throw RenewalProfileError.invalidSize
        }
        let opening = Data("<plist".utf8)
        let closing = Data("</plist>".utf8)
        guard let start = cmsData.range(of: opening),
              let end = cmsData.range(of: closing, in: start.upperBound..<cmsData.endIndex),
              cmsData.range(of: opening, in: start.upperBound..<cmsData.endIndex) == nil,
              cmsData.range(of: closing, in: end.upperBound..<cmsData.endIndex) == nil else {
            throw RenewalProfileError.malformed
        }

        let xml = Data(cmsData[start.lowerBound..<end.upperBound])
        var format = PropertyListSerialization.PropertyListFormat.xml
        guard let plist = try? PropertyListSerialization.propertyList(
            from: xml, options: [], format: &format),
              format == .xml,
              let fields = plist as? [String: Any],
              let uuid = fields["UUID"] as? String, UUID(uuidString: uuid) != nil,
              let teamIDs = fields["TeamIdentifier"] as? [String], teamIDs.count == 1,
              let teamID = teamIDs.first, Self.isIdentifier(teamID),
              let creation = fields["CreationDate"] as? Date,
              let expiration = fields["ExpirationDate"] as? Date,
              creation < expiration,
              let devices = fields["ProvisionedDevices"] as? [String], !devices.isEmpty,
              devices.allSatisfy(Self.isIdentifier),
              let certificates = fields["DeveloperCertificates"] as? [Data],
              !certificates.isEmpty, certificates.allSatisfy({ !$0.isEmpty }),
              let rawEntitlements = fields["Entitlements"] as? [String: Any] else {
            throw RenewalProfileError.malformed
        }
        if let allDevices = fields["ProvisionsAllDevices"] {
            guard let value = Self.boolean(allDevices), !value else {
                throw RenewalProfileError.malformed
            }
        }

        var parsedNodes = 0
        let parsed = try Self.parseValue(rawEntitlements, depth: 0, nodes: &parsedNodes)
        guard case .dictionary(let entitlements) = parsed,
              case .string(let appID)? = entitlements["application-identifier"],
              case .string(let entitlementTeam)? = entitlements["com.apple.developer.team-identifier"],
              entitlementTeam == teamID,
              entitlements["get-task-allow"] == .boolean(true),
              appID.hasPrefix(teamID + "."),
              appID.count > teamID.count + 1 else {
            throw RenewalProfileError.malformed
        }

        self.uuid = uuid
        self.teamID = teamID
        self.applicationIdentifier = appID
        self.bundleIdentifier = String(appID.dropFirst(teamID.count + 1))
        self.creation = creation
        self.expiration = expiration
        self.deviceIDs = Set(devices)
        self.developerCertificates = certificates
        self.entitlements = entitlements
    }

    public func isDue(now: Date, leadTime: TimeInterval = 72 * 60 * 60) -> Bool {
        let safeLeadTime = leadTime.isFinite && leadTime > 0 ? leadTime : 0
        return now.addingTimeInterval(safeLeadTime) >= expiration
    }

    /// A conservative preflight for a profile meant to renew GPS Rebuilt.
    /// Strings, numbers, booleans, dates, and data must retain their exact typed value.
    /// Dictionaries may add keys; arrays may add entries, but each reference entry must
    /// still be present. Wildcard strings receive no special matching treatment.
    @discardableResult
    public func validatedCandidate(
        reference: RenewalProfile,
        deviceID: String,
        now: Date,
        minimumExpiration: Date? = nil
    ) throws -> RenewalProfile {
        guard bundleIdentifier == Self.rebuiltBundleIdentifier,
              reference.bundleIdentifier == Self.rebuiltBundleIdentifier,
              teamID == reference.teamID,
              applicationIdentifier == reference.applicationIdentifier else {
            throw RenewalProfileError.wrongApplication
        }
        guard Self.isIdentifier(deviceID),
              reference.deviceIDs.contains(deviceID),
              deviceIDs.contains(deviceID) else {
            throw RenewalProfileError.wrongDevice
        }
        guard creation <= now, expiration > now else {
            throw RenewalProfileError.notCurrentlyValid
        }
        guard expiration > reference.expiration,
              minimumExpiration.map({ expiration > $0 }) ?? true else {
            throw RenewalProfileError.notNewer
        }
        guard reference.developerCertificates.allSatisfy(developerCertificates.contains) else {
            throw RenewalProfileError.incompatibleCertificates
        }
        guard Self.covers(.dictionary(entitlements), .dictionary(reference.entitlements)) else {
            throw RenewalProfileError.incompatibleEntitlements
        }
        return self
    }

    private static func isIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 256 &&
        !value.contains(where: { $0.isWhitespace || $0.isNewline || $0 == "\0" })
    }

    private static func boolean(_ value: Any) -> Bool? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }

    private static func parseValue(_ value: Any, depth: Int, nodes: inout Int) throws -> PlistValue {
        nodes += 1
        guard depth <= 32, nodes <= 8_192 else { throw RenewalProfileError.malformed }
        if let dictionary = value as? [String: Any] {
            var result: [String: PlistValue] = [:]
            for (key, entry) in dictionary {
                result[key] = try parseValue(entry, depth: depth + 1, nodes: &nodes)
            }
            return .dictionary(result)
        }
        if let array = value as? [Any] {
            return .array(try array.map { try parseValue($0, depth: depth + 1, nodes: &nodes) })
        }
        if let string = value as? String { return .string(string) }
        if let data = value as? Data { return .data(data) }
        if let date = value as? Date { return .date(date) }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return .boolean(number.boolValue) }
            let type = number.objCType.pointee
            if type == 102 || type == 100 {
                guard number.doubleValue.isFinite else { throw RenewalProfileError.malformed }
                return .real(number.doubleValue)
            }
            guard let integer = Int64(number.stringValue) else { throw RenewalProfileError.malformed }
            return .integer(integer)
        }
        throw RenewalProfileError.malformed
    }

    private static func covers(_ candidate: PlistValue, _ reference: PlistValue) -> Bool {
        switch (candidate, reference) {
        case (.dictionary(let available), .dictionary(let required)):
            return required.allSatisfy { key, value in
                available[key].map { covers($0, value) } ?? false
            }
        case (.array(let available), .array(let required)):
            return required.allSatisfy { needed in available.contains { covers($0, needed) } }
        default:
            return candidate == reference
        }
    }
}

public enum RenewalProfileError: LocalizedError, Equatable, Sendable {
    case invalidSize
    case malformed
    case wrongApplication
    case wrongDevice
    case notCurrentlyValid
    case notNewer
    case incompatibleCertificates
    case incompatibleEntitlements

    public var errorDescription: String? {
        switch self {
        case .invalidSize: "The provisioning profile is empty or too large."
        case .malformed: "The provisioning profile is malformed or incomplete."
        case .wrongApplication: "The profile does not match GPS Rebuilt."
        case .wrongDevice: "The profile does not include this iPhone."
        case .notCurrentlyValid: "The profile is not currently valid."
        case .notNewer: "The profile does not extend the current expiration."
        case .incompatibleCertificates: "The profile does not retain the app’s signing certificates."
        case .incompatibleEntitlements: "The profile does not retain the app’s permissions."
        }
    }
}
