import Foundation

/// One-off profile access through the same pinned device setup as the location
/// transport. Native calls block, so both operations run on a serial queue.
final class NativeProfileTransport: @unchecked Sendable {
    static let shared = NativeProfileTransport()

    private let queue = DispatchQueue(label: "app.gps.reconstruction.profiles", qos: .utility)

    private init() {}

    func install(profile: Data, configuration: SetupConfiguration) async throws {
        let setup = try configuration.encoded()
        try await perform {
            var error: UnsafeMutablePointer<CChar>?
            let status = setup.withUnsafeBytes { setupBytes in
                profile.withUnsafeBytes { profileBytes in
                    gps_native_install_profile(
                        setupBytes.bindMemory(to: UInt8.self).baseAddress,
                        setupBytes.count,
                        profileBytes.bindMemory(to: UInt8.self).baseAddress,
                        profileBytes.count,
                        &error
                    )
                }
            }
            try self.check(status, error: error)
        }
    }

    func profiles(configuration: SetupConfiguration) async throws -> [Data] {
        let setup = try configuration.encoded()
        return try await perform {
            var output: UnsafeMutablePointer<CChar>?
            var error: UnsafeMutablePointer<CChar>?
            let status = setup.withUnsafeBytes { bytes in
                gps_native_copy_profiles(
                    bytes.bindMemory(to: UInt8.self).baseAddress,
                    bytes.count,
                    &output,
                    &error
                )
            }
            defer { if let output { gps_native_error_free(output) } }
            try self.check(status, error: error)
            guard let output else {
                throw GPSError.transport("The iPhone returned no provisioning profiles response.")
            }
            let json = Data(String(cString: output).utf8)
            let encoded: [String]
            do { encoded = try JSONDecoder().decode([String].self, from: json) }
            catch { throw GPSError.transport("The iPhone returned malformed provisioning profiles.") }
            guard encoded.count <= 64 else {
                throw GPSError.transport("The iPhone returned too many provisioning profiles.")
            }
            return try encoded.map { value in
                guard let profile = Data(base64Encoded: value), profile.count <= 2 * 1024 * 1024 else {
                    throw GPSError.transport("The iPhone returned a malformed provisioning profile.")
                }
                return profile
            }
        }
    }

    private func perform<T: Sendable>(_ operation: @escaping @Sendable () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, Error>) in
            queue.async {
                do { continuation.resume(returning: try operation()) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    private func check(_ status: Int32, error: UnsafeMutablePointer<CChar>?) throws {
        defer { if let error { gps_native_error_free(error) } }
        guard status == 0 else {
            let message = error.map { String(cString: $0) } ?? "The iPhone could not complete profile management."
            throw GPSError.transport(message)
        }
    }
}
