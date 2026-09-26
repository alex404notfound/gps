import Foundation

enum ProvisioningStatus {
    /// Reads only the app's own embedded payload for an informational expiry date.
    /// This is not a CMS signature verifier and never authorizes a connection or location command.
    static func embeddedExpiration(bundle: Bundle = .main) -> Date? {
        guard let url = bundle.url(forResource: "embedded", withExtension: "mobileprovision"),
              let data = try? Data(contentsOf: url), data.count < 2_000_000,
              let start = data.range(of: Data("<?xml".utf8)),
              let end = data.range(of: Data("</plist>".utf8), in: start.lowerBound..<data.endIndex),
              let object = try? PropertyListSerialization.propertyList(
                from: data[start.lowerBound..<end.upperBound], options: [], format: nil),
              let profile = object as? [String: Any] else { return nil }
        return profile["ExpirationDate"] as? Date
    }
}
