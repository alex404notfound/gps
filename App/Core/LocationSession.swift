import Foundation

public protocol LocationTransport: Sendable {
    func connect(configuration: SetupConfiguration) async throws
    func setLocation(_ coordinate: Coordinate) async throws
    func resetLocation() async throws
    func disconnect() async
}

public struct SessionSnapshot: Equatable, Sendable {
    public var connection: ConnectionState = .notConfigured
    public var operation: OperationState = .idle
    /// Last command accepted during this app session; not a physical location readback.
    public var lastApplied: Coordinate?
    public var notice: String?
}

/// Serializes state changes. Set requires a reply; the reset protocol only confirms sending.
public actor LocationSession {
    private let transport: any LocationTransport
    private var state = SessionSnapshot()
    private var busy = false

    public init(transport: any LocationTransport) { self.transport = transport }
    public func snapshot() -> SessionSnapshot { state }

    public func connect(configuration: SetupConfiguration) async throws {
        guard !busy else { throw GPSError.busy }
        let checked = try configuration.validated()
        busy = true
        defer { busy = false }
        state.connection = .connecting
        state.operation = .idle
        state.notice = nil
        await transport.disconnect()
        do {
            try await transport.connect(configuration: checked)
            state.connection = .connected
            state.notice = "Connected to the developer location service."
        } catch {
            await transport.disconnect()
            state.connection = .failed(error.localizedDescription)
            state.notice = error.localizedDescription
            throw error
        }
    }

    public func apply(_ coordinate: Coordinate) async throws {
        guard !busy else { throw GPSError.busy }
        _ = try coordinate.validated()
        guard state.connection.isConnected else { throw GPSError.notConnected }
        busy = true
        defer { busy = false }
        state.operation = .applying
        state.notice = nil
        do {
            try await transport.setLocation(coordinate)
            state.lastApplied = coordinate
            state.operation = .idle
            state.notice = "Location command accepted. Check another app to verify its reported location."
        } catch {
            await operationFailed(error)
            throw error
        }
    }

    public func reset() async throws {
        guard !busy else { throw GPSError.busy }
        guard state.connection.isConnected else { throw GPSError.notConnected }
        busy = true
        defer { busy = false }
        state.operation = .resetting
        state.notice = nil
        do {
            try await transport.resetLocation()
            state.lastApplied = nil
            state.operation = .idle
            state.notice = "Reset command sent. Check Maps to verify your current location."
        } catch {
            await operationFailed(error)
            throw error
        }
    }

    public func disconnect() async throws {
        guard !busy else { throw GPSError.busy }
        busy = true
        defer { busy = false }
        await transport.disconnect()
        state.connection = .disconnected
        state.operation = .idle
        state.notice = "Disconnected. Disconnecting does not reset a previously applied location."
    }

    private func operationFailed(_ error: Error) async {
        // A transport error may occur after the device received a request. Its location is unknown.
        state.operation = .failed(error.localizedDescription)
        state.connection = .failed(error.localizedDescription)
        state.notice = "The command was not confirmed. Reconnect and reset to recover. \(error.localizedDescription)"
        await transport.disconnect()
    }
}
