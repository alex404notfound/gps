import Foundation
import Security
import Testing
@testable import GPSCore

/// Models iOS accessibility without putting credentials in the test host's
/// Keychain. Real lock-state enforcement still needs an iPhone smoke test.
private final class TestKeychain: KeychainClient, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: [String: Any]] = [:]
    private var unlocked = true
    private var hasUnlocked = true
    private var updateFailure: OSStatus?
    private var updates = 0

    var updateCount: Int { lock.withLock { updates } }

    func setLocked(_ locked: Bool, afterFirstUnlock: Bool = true) {
        lock.withLock {
            unlocked = !locked
            hasUnlocked = afterFirstUnlock || !locked
        }
    }

    func failUpdates(with status: OSStatus?) { lock.withLock { updateFailure = status } }

    func seed(service: String, account: String, data: Data) {
        lock.withLock {
            items[service + "/" + account] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
        }
    }

    private func key(_ query: [String: Any]) -> String {
        #expect(query[kSecClass as String] as? String == kSecClassGenericPassword as String)
        #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
        return (query[kSecAttrService as String] as! String) + "/" + (query[kSecAttrAccount as String] as! String)
    }

    private func accessible(_ item: [String: Any]) -> Bool {
        hasUnlocked && (unlocked || item[kSecAttrAccessible as String] as? String == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
    }

    func copyMatching(_ query: [String: Any]) -> (OSStatus, [String: Any]?) {
        lock.withLock {
            #expect(query[kSecReturnData as String] as? Bool == true)
            #expect(query[kSecReturnAttributes as String] as? Bool == true)
            guard let item = items[key(query)] else { return (errSecItemNotFound, nil) }
            guard accessible(item) else { return (errSecInteractionNotAllowed, nil) }
            return (errSecSuccess, item)
        }
    }

    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        lock.withLock {
            if let updateFailure { return updateFailure }
            let identity = key(query)
            guard var item = items[identity] else { return errSecItemNotFound }
            guard accessible(item) else { return errSecInteractionNotAllowed }
            item.merge(attributes) { _, new in new }
            items[identity] = item
            updates += 1
            return errSecSuccess
        }
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        lock.withLock {
            let identity = key(attributes)
            guard items[identity] == nil else { return errSecDuplicateItem }
            guard accessible(attributes) else { return errSecInteractionNotAllowed }
            items[identity] = attributes
            return errSecSuccess
        }
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        lock.withLock {
            items.removeValue(forKey: key(query)) == nil ? errSecItemNotFound : errSecSuccess
        }
    }
}

@Test func renewalItemsMigrateOnReadAndSurviveLockingWithoutLosingData() throws {
    let client = TestKeychain()
    let identities = [
        ("app.gps.reconstruction.setup", "paired-device"),
        ("app.gps.reconstruction.renewal", "apple-developer-session"),
        ("app.gps.reconstruction.renewal-state", "prepared-profile")
    ]
    for (service, account) in identities {
        let data = Data(account.utf8)
        client.seed(service: service, account: account, data: data)
        let item = BackgroundKeychainItem(service: service, account: account, client: client)
        #expect(try item.load() == data)
    }
    #expect(client.updateCount == identities.count)
    client.setLocked(true)
    for (service, account) in identities {
        let item = BackgroundKeychainItem(service: service, account: account, client: client)
        #expect(try item.load() == Data(account.utf8))
    }
    #expect(client.updateCount == identities.count)
}

@Test func backgroundKeychainCanSaveUpdateAndDeleteWhileLockedAfterFirstUnlock() throws {
    let client = TestKeychain()
    let item = BackgroundKeychainItem(service: "test", account: "refresh", client: client)
    client.setLocked(true)
    #expect(try item.load() == nil)
    try item.save(Data("prepared".utf8))
    #expect(try item.load() == Data("prepared".utf8))
    try item.save(Data("renewed".utf8))
    #expect(try item.load() == Data("renewed".utf8))
    try item.delete()
    #expect(try item.load() == nil)
    try item.delete()
}

@Test func legacyItemNeedsOneUnlockedReadAndFailedAccessPreservesIt() throws {
    let client = TestKeychain()
    let original = Data("existing session".utf8)
    client.seed(service: "test", account: "refresh", data: original)
    let item = BackgroundKeychainItem(service: "test", account: "refresh", client: client)
    client.setLocked(true)
    #expect(throws: KeychainStatusError.self) { try item.load() }
    #expect(throws: KeychainStatusError.self) { try item.save(Data("replacement".utf8)) }
    client.setLocked(false)
    #expect(try item.load() == original)
    client.setLocked(true)
    #expect(try item.load() == original)
}

@Test func migrationFailureIsReportedAndCanRetryWithoutReplacingTheSecret() throws {
    let client = TestKeychain()
    let original = Data("existing setup".utf8)
    client.seed(service: "test", account: "refresh", data: original)
    let item = BackgroundKeychainItem(service: "test", account: "refresh", client: client)
    client.failUpdates(with: errSecInteractionNotAllowed)
    #expect(throws: KeychainStatusError.self) { try item.load() }
    client.failUpdates(with: nil)
    #expect(try item.load() == original)
    client.setLocked(true)
    #expect(try item.load() == original)
}

@Test func backgroundKeychainStillRequiresFirstUnlockAfterRestart() throws {
    let client = TestKeychain()
    let item = BackgroundKeychainItem(service: "test", account: "refresh", client: client)
    let data = Data("renewal session".utf8)
    try item.save(data)
    client.setLocked(true, afterFirstUnlock: false)
    #expect(throws: KeychainStatusError.self) { try item.load() }
    client.setLocked(false)
    #expect(try item.load() == data)
    client.setLocked(true)
    #expect(try item.load() == data)
}

@Test func savingAnExistingItemAlsoMigratesItsAccessibility() throws {
    let client = TestKeychain()
    client.seed(service: "test", account: "refresh", data: Data("old".utf8))
    let item = BackgroundKeychainItem(service: "test", account: "refresh", client: client)
    let updated = Data("new session".utf8)
    try item.save(updated)
    client.setLocked(true)
    #expect(try item.load() == updated)
}
