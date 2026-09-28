import Foundation

struct SetupKeychain {
    private let item = BackgroundKeychainItem(
        service: (Bundle.main.bundleIdentifier ?? "app.gps.reconstruction") + ".setup",
        account: "paired-device")

    func load() throws -> Data? {
        do { return try item.load() }
        catch {
            throw GPSError.storage("The saved setup is unavailable. Open GPS once while unlocked after updating, and unlock once after each restart.")
        }
    }

    func save(_ data: Data) throws {
        _ = try SetupConfiguration.decode(data)
        do { try item.save(data) }
        catch {
            throw GPSError.storage("The setup could not be saved securely. Unlock the iPhone and try again.")
        }
    }
}
