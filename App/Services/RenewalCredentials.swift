import Foundation
import Security
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
    private static let service = "app.gps.reconstruction.renewal"
    private static let account = "apple-developer-session"

    private static var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }

    static func load() throws -> RenewalCredentialState? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data,
              let state = try? JSONDecoder().decode(RenewalCredentialState.self, from: data) else {
            throw RenewalAccountError.secureStorageUnavailable
        }
        return state
    }

    static func save(_ state: RenewalCredentialState) throws {
        let data = try JSONEncoder().encode(state)
        let changed = SecItemUpdate(query as CFDictionary,
                                    [kSecValueData as String: data] as CFDictionary)
        if changed == errSecSuccess { return }
        guard changed == errSecItemNotFound else {
            throw RenewalAccountError.secureStorageUnavailable
        }
        var item = query
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else {
            throw RenewalAccountError.secureStorageUnavailable
        }
    }

    static func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw RenewalAccountError.secureStorageUnavailable
        }
    }
}
