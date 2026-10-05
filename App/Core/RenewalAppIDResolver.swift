import Foundation

protocol RenewalAppIDRecord: Sendable {
    var identifier: String { get }
    var bundleIdentifier: String { get }
    var expirationDate: Date? { get }
}

enum RenewalAppIDError: Error, Equatable {
    case wrongApp, invalidResponse, alreadyRegistered, registrationUnavailable
}

enum RenewalAppIDResolver {
    /// The installed profile can remain valid after its portal registration is
    /// gone. Resolve that registration independently of the profile's expiry.
    static func resolve<Record: RenewalAppIDRecord>(
        bundleIdentifier: String,
        now: Date = .now,
        fetch: @Sendable () async throws -> [Record],
        register: @Sendable (String) async throws -> Record
    ) async throws -> Record {
        guard bundleIdentifier == RenewalProfile.rebuiltBundleIdentifier else {
            throw RenewalAppIDError.wrongApp
        }
        try Task.checkCancellation()
        let records = try await fetch()
        try Task.checkCancellation()
        if let existing = try matching(records, bundleIdentifier: bundleIdentifier, now: now) {
            return existing
        }

        do {
            let created = try await register(bundleIdentifier)
            try Task.checkCancellation()
            guard let validated = try matching([created], bundleIdentifier: bundleIdentifier, now: now) else {
                throw RenewalAppIDError.invalidResponse
            }
            return validated
        } catch RenewalAppIDError.alreadyRegistered {
            // Another provisioning client may have registered it after our
            // lookup. Re-read once; never invent another bundle ID or loop.
            try Task.checkCancellation()
            let refreshed = try await fetch()
            try Task.checkCancellation()
            guard let existing = try matching(refreshed, bundleIdentifier: bundleIdentifier, now: now) else {
                throw RenewalAppIDError.registrationUnavailable
            }
            return existing
        }
    }

    private static func matching<Record: RenewalAppIDRecord>(
        _ records: [Record], bundleIdentifier: String, now: Date
    ) throws -> Record? {
        let matches = records.filter { $0.bundleIdentifier == bundleIdentifier }
        guard matches.allSatisfy({ !$0.identifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }) else {
            throw RenewalAppIDError.invalidResponse
        }
        return matches.first { $0.expirationDate.map { $0 > now } ?? true }
    }
}
