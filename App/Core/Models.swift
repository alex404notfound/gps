import Foundation

public struct Coordinate: Codable, Hashable, Sendable {
    public var latitude: Double
    public var longitude: Double

    public init(latitude: Double, longitude: Double) {
        self.latitude = latitude
        self.longitude = longitude
    }

    public var isValid: Bool {
        latitude.isFinite && longitude.isFinite &&
        (-90...90).contains(latitude) && (-180...180).contains(longitude)
    }

    public var formatted: String {
        String(format: "%.5f, %.5f", locale: Locale(identifier: "en_US_POSIX"), latitude, longitude)
    }

    public func validated() throws -> Self {
        guard isValid else { throw GPSError.invalidCoordinate }
        return self
    }
}

public struct SavedPlace: Identifiable, Codable, Equatable, Sendable {
    public var id: UUID
    public var name: String
    public var coordinate: Coordinate
    public var savedAt: Date

    public init(id: UUID = UUID(), name: String, coordinate: Coordinate, savedAt: Date = .now) {
        self.id = id
        self.name = name
        self.coordinate = coordinate
        self.savedAt = savedAt
    }
}

public struct SearchResult: Identifiable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var subtitle: String
    public var coordinate: Coordinate

    public init(id: String, name: String, subtitle: String, coordinate: Coordinate) {
        self.id = id
        self.name = name
        self.subtitle = subtitle
        self.coordinate = coordinate
    }
}

public enum ConnectionState: Equatable, Sendable {
    case notConfigured, disconnected, connecting, connected, failed(String)

    public var title: String {
        switch self {
        case .notConfigured: "Setup needed"
        case .disconnected: "Disconnected"
        case .connecting: "Connecting…"
        case .connected: "Connected"
        case .failed: "Connection unavailable"
        }
    }

    public var isConnected: Bool { self == .connected }
}

public enum OperationState: Equatable, Sendable {
    case idle, applying, resetting, failed(String)

    public var isBusy: Bool { self == .applying || self == .resetting }
}

public enum GPSError: LocalizedError, Equatable, Sendable {
    case invalidCoordinate
    case setupRequired
    case invalidSetup(String)
    case notConnected
    case busy
    case transport(String)
    case storage(String)

    public var errorDescription: String? {
        switch self {
        case .invalidCoordinate: "Enter a latitude from −90 to 90 and a longitude from −180 to 180."
        case .setupRequired: "Import this iPhone’s setup file in App Access first."
        case .invalidSetup(let reason): "This setup file cannot be used. \(reason)"
        case .notConnected: "Connect to this iPhone in App Access before changing its location."
        case .busy: "Wait for the current operation to finish."
        case .transport(let message), .storage(let message): message
        }
    }
}
