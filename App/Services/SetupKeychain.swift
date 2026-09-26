import Foundation
import Security

struct SetupKeychain {
    private let service = (Bundle.main.bundleIdentifier ?? "app.gps.reconstruction") + ".setup"

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: "paired-device",
         kSecAttrSynchronizable as String: false]
    }

    func load() throws -> Data? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw GPSError.storage("Unlock this iPhone to read its saved setup.")
        }
        return data
    }

    func save(_ data: Data) throws {
        _ = try SetupConfiguration.decode(data)
        let values: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let updated = SecItemUpdate(query as CFDictionary, values as CFDictionary)
        if updated == errSecSuccess { return }
        guard updated == errSecItemNotFound else {
            throw GPSError.storage("The setup could not be saved securely. Unlock the iPhone and try again.")
        }
        var item = query
        item.merge(values) { _, new in new }
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else {
            throw GPSError.storage("The setup could not be saved securely.")
        }
    }
}
