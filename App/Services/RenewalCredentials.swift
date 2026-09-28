import Foundation
import SideSign

/// Account renewal state stays on this iPhone and outside app data exports.
struct RenewalCredentialState: Codable, Sendable {
    var anisetteIdentifier: UUID
    var anisetteProvisioning: Data?
    var email: String?
    var authSession: AuthSession?

    init() {
        anisetteIdentifier = UUID()
        anisetteProvisioning = nil
        email = nil
        authSession = nil
    }
}

enum RenewalCredentials {
    private static let item = BackgroundKeychainItem(
        service: "app.gps.reconstruction.renewal", account: "apple-developer-session")

    static func load() throws -> RenewalCredentialState? {
        do {
            guard let data = try item.load() else { return nil }
            return try JSONDecoder().decode(RenewalCredentialState.self, from: data)
        } catch {
            throw RenewalAccountError.secureStorageUnavailable
        }
    }

    static func save(_ state: RenewalCredentialState) throws {
        let data = try JSONEncoder().encode(state)
        do { try item.save(data) }
        catch { throw RenewalAccountError.secureStorageUnavailable }
    }

    static func delete() throws {
        do { try item.delete() }
        catch { throw RenewalAccountError.secureStorageUnavailable }
    }
}
