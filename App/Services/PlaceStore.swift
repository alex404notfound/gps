import Foundation

struct PlaceCollection: Codable {
    var favorites: [SavedPlace] = []
    var recent: [SavedPlace] = []
}

struct PlaceStore {
    private var url: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("GPS", isDirectory: true)
            .appendingPathComponent("places.json")
    }

    func load() throws -> PlaceCollection {
        guard FileManager.default.fileExists(atPath: url.path) else { return PlaceCollection() }
        let data = try Data(contentsOf: url)
        guard data.count <= 1_048_576 else { throw GPSError.storage("Saved places could not be read.") }
        var collection = try JSONDecoder().decode(PlaceCollection.self, from: data)
        collection.favorites = collection.favorites.filter { $0.coordinate.isValid }
        collection.recent = Array(collection.recent.filter { $0.coordinate.isValid }.prefix(12))
        return collection
    }

    func save(_ collection: PlaceCollection) throws {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(collection)
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}
