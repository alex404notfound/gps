import Foundation

/// Rust owns the tunnel and DVT connection. This queue is the sole owner of its opaque handle.
final class NativeLocationTransport: LocationTransport, @unchecked Sendable {
    private let queue = DispatchQueue(label: "app.gps.reconstruction.native", qos: .userInitiated)
    private var session: OpaquePointer?

    func connect(configuration: SetupConfiguration) async throws {
        let data = try configuration.encoded()
        let assetsDirectory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("GPSDeveloperImage", isDirectory: true).path
        try await perform {
            self.closeSession()
            var created: OpaquePointer?
            var error: UnsafeMutablePointer<CChar>?
            let result = data.withUnsafeBytes { bytes in
                assetsDirectory.withCString { assetsPath in
                    gps_native_connect_with_assets(bytes.bindMemory(to: UInt8.self).baseAddress,
                                                   bytes.count, assetsPath, &created, &error)
                }
            }
            do { try self.check(result, error: error) }
            catch {
                if let created { gps_native_disconnect(created) }
                throw error
            }
            guard let created else { throw GPSError.transport("The location service returned no connection.") }
            self.session = created
        }
    }

    func setLocation(_ coordinate: Coordinate) async throws {
        _ = try coordinate.validated()
        try await perform {
            guard let session = self.session else { throw GPSError.notConnected }
            var error: UnsafeMutablePointer<CChar>?
            let result = gps_native_set(session, coordinate.latitude, coordinate.longitude, &error)
            try self.check(result, error: error)
        }
    }

    func resetLocation() async throws {
        try await perform {
            guard let session = self.session else { throw GPSError.notConnected }
            var error: UnsafeMutablePointer<CChar>?
            let result = gps_native_reset(session, &error)
            try self.check(result, error: error)
        }
    }

    func disconnect() async {
        await withCheckedContinuation { continuation in
            queue.async {
                self.closeSession()
                continuation.resume()
            }
        }
    }

    private func perform(_ operation: @escaping @Sendable () throws -> Void) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            queue.async {
                do { try operation(); continuation.resume() }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    private func check(_ status: Int32, error: UnsafeMutablePointer<CChar>?) throws {
        defer { if let error { gps_native_error_free(error) } }
        guard status == 0 else {
            let message = error.map { String(cString: $0) } ?? "The developer location service could not complete the request."
            throw GPSError.transport(message)
        }
    }

    private func closeSession() {
        if let session { gps_native_disconnect(session) }
        session = nil
    }
}
