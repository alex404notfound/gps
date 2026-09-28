import Foundation
import Security

/// Device-local secrets used by Shortcuts and background renewal. They remain
/// available while locked after the first unlock following a restart.
struct BackgroundKeychainItem: Sendable {
    let service: String
    let account: String
    private let client: any KeychainClient

    init(service: String, account: String, client: any KeychainClient = SystemKeychainClient()) {
        self.service = service
        self.account = account
        self.client = client
    }

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }

    func load() throws -> Data? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecReturnAttributes as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, item) = client.copyMatching(request)
        if status == errSecItemNotFound { return nil }
        try check(status)
        guard let item, let data = item[kSecValueData as String] as? Data else {
            throw KeychainStatusError(status: errSecDecode)
        }

        if item[kSecAttrAccessible as String] as? String != kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String {
            // Upgrade existing items on their first successful (unlocked) read.
            // Change only accessibility, preserving both the item and its data.
            try check(client.update(query, attributes: [
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            ]))
        }
        return data
    }

    func save(_ data: Data) throws {
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let status = client.update(query, attributes: attributes)
        if status == errSecItemNotFound {
            var item = query
            item.merge(attributes) { _, new in new }
            try check(client.add(item))
        } else {
            try check(status)
        }
    }

    func delete() throws {
        let status = client.delete(query)
        if status != errSecItemNotFound { try check(status) }
    }

    private func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw KeychainStatusError(status: status) }
    }
}

struct KeychainStatusError: Error {
    let status: OSStatus
}

protocol KeychainClient: Sendable {
    func copyMatching(_ query: [String: Any]) -> (OSStatus, [String: Any]?)
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus
    func add(_ attributes: [String: Any]) -> OSStatus
    func delete(_ query: [String: Any]) -> OSStatus
}

struct SystemKeychainClient: KeychainClient {
    func copyMatching(_ query: [String: Any]) -> (OSStatus, [String: Any]?) {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return (status, result as? [String: Any])
    }

    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        SecItemAdd(attributes as CFDictionary, nil)
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        SecItemDelete(query as CFDictionary)
    }
}
