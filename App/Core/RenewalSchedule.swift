import Foundation

enum RenewalSchedule {
    static let leadTime: TimeInterval = 72 * 3600
    static let retryInterval: TimeInterval = 12 * 3600

    /// A healthy profile needs no background checks before its renewal window.
    /// Due or unavailable profiles retain the existing bounded retry cadence.
    static func nextBackgroundRefresh(now: Date, expiration: Date?) -> Date {
        let retry = now.addingTimeInterval(retryInterval)
        guard let expiration else { return retry }
        return max(retry, expiration.addingTimeInterval(-leadTime))
    }
}
