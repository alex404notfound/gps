import Foundation
import Testing
@testable import GPSCore

private let appIDNow = Date(timeIntervalSince1970: 1_800_000_000)
private let gpsBundle = RenewalProfile.rebuiltBundleIdentifier

private struct TestAppID: RenewalAppIDRecord, Equatable {
    let identifier: String
    var bundleIdentifier = gpsBundle
    var expirationDate: Date? = appIDNow.addingTimeInterval(7 * 24 * 3600)
}

private enum PortalFailure: Error, Equatable {
    case unavailable, registrationLimit
}

private actor AppIDPortalStub {
    var fetchCount = 0
    var registeredBundles: [String] = []
    let snapshots: [[TestAppID]]
    let registration: Result<TestAppID, Error>
    let fetchError: PortalFailure?

    init(snapshots: [[TestAppID]], registration: Result<TestAppID, Error>, fetchError: PortalFailure? = nil) {
        self.snapshots = snapshots
        self.registration = registration
        self.fetchError = fetchError
    }

    func fetch() throws -> [TestAppID] {
        fetchCount += 1
        if let fetchError { throw fetchError }
        return snapshots[min(fetchCount - 1, snapshots.count - 1)]
    }

    func register(_ bundle: String) throws -> TestAppID {
        registeredBundles.append(bundle)
        return try registration.get()
    }
}

private func resolve(_ portal: AppIDPortalStub, bundle: String = gpsBundle) async throws -> TestAppID {
    try await RenewalAppIDResolver.resolve(
        bundleIdentifier: bundle, now: appIDNow,
        fetch: { try await portal.fetch() },
        register: { try await portal.register($0) })
}

@Test func renewalReusesTheExactExistingAppIDWithoutRegistration() async throws {
    let existing = TestAppID(identifier: "EXISTING", expirationDate: nil)
    let unrelated = TestAppID(identifier: "OTHER", bundleIdentifier: "app.gps.development")
    let portal = AppIDPortalStub(snapshots: [[unrelated, existing]], registration: .failure(PortalFailure.registrationLimit))
    #expect(try await resolve(portal) == existing)
    #expect(await portal.fetchCount == 1)
    #expect(await portal.registeredBundles.isEmpty)
}

@Test func missingAppIDIsRestoredUsingTheSameGPSBundleIdentifier() async throws {
    let created = TestAppID(identifier: "RESTORED")
    let unrelated = TestAppID(identifier: "OTHER", bundleIdentifier: "app.gps.development")
    let portal = AppIDPortalStub(snapshots: [[unrelated]], registration: .success(created))
    #expect(try await resolve(portal) == created)
    #expect(await portal.registeredBundles == [gpsBundle])
}

@Test func expiredRegistrationDoesNotPreventRestoringTheAppID() async throws {
    let expired = TestAppID(identifier: "EXPIRED", expirationDate: appIDNow)
    let restored = TestAppID(identifier: "RESTORED")
    let portal = AppIDPortalStub(snapshots: [[expired]], registration: .success(restored))
    #expect(try await resolve(portal) == restored)
    #expect(await portal.registeredBundles == [gpsBundle])
}

@Test func registrationConflictRefetchesTheSameAppOnce() async throws {
    let existing = TestAppID(identifier: "CREATED-ELSEWHERE")
    let portal = AppIDPortalStub(snapshots: [[], [existing]], registration: .failure(RenewalAppIDError.alreadyRegistered))
    #expect(try await resolve(portal) == existing)
    #expect(await portal.fetchCount == 2)
    #expect(await portal.registeredBundles == [gpsBundle])
}

@Test func unresolvedRegistrationConflictDoesNotLoopOrChangeBundleID() async {
    let portal = AppIDPortalStub(snapshots: [[]], registration: .failure(RenewalAppIDError.alreadyRegistered))
    await #expect(throws: RenewalAppIDError.registrationUnavailable) { try await resolve(portal) }
    #expect(await portal.fetchCount == 2)
    #expect(await portal.registeredBundles == [gpsBundle])
}

@Test func registrationLimitsArePreservedWithoutRepeatingRegistration() async {
    let portal = AppIDPortalStub(snapshots: [[]], registration: .failure(PortalFailure.registrationLimit))
    await #expect(throws: PortalFailure.registrationLimit) { try await resolve(portal) }
    #expect(await portal.fetchCount == 1)
    #expect(await portal.registeredBundles == [gpsBundle])
}

@Test func failedListingNeverTriggersRegistration() async {
    let portal = AppIDPortalStub(snapshots: [[]], registration: .success(TestAppID(identifier: "NEW")), fetchError: .unavailable)
    await #expect(throws: PortalFailure.unavailable) { try await resolve(portal) }
    #expect(await portal.registeredBundles.isEmpty)
}

@Test func malformedMatchingAppIDIsNotTreatedAsMissing() async {
    let portal = AppIDPortalStub(snapshots: [[TestAppID(identifier: "")]], registration: .success(TestAppID(identifier: "NEW")))
    await #expect(throws: RenewalAppIDError.invalidResponse) { try await resolve(portal) }
    #expect(await portal.registeredBundles.isEmpty)
}

@Test func registrationResponseMustMatchGPSAndRemainUsable() async {
    for invalid in [
        TestAppID(identifier: "OTHER", bundleIdentifier: "app.other"),
        TestAppID(identifier: ""),
        TestAppID(identifier: "EXPIRED", expirationDate: appIDNow.addingTimeInterval(-1))
    ] {
        let portal = AppIDPortalStub(snapshots: [[]], registration: .success(invalid))
        await #expect(throws: RenewalAppIDError.invalidResponse) { try await resolve(portal) }
    }
}

@Test func resolverCannotRegisterADifferentApplication() async {
    let portal = AppIDPortalStub(snapshots: [[]], registration: .success(TestAppID(identifier: "NEW")))
    await #expect(throws: RenewalAppIDError.wrongApp) { try await resolve(portal, bundle: "app.gps.development") }
    #expect(await portal.fetchCount == 0)
    #expect(await portal.registeredBundles.isEmpty)
}

@Test func cancellationAfterListingPreventsRegistration() async {
    let portal = AppIDPortalStub(snapshots: [[]], registration: .success(TestAppID(identifier: "NEW")))
    let task = Task {
        try await RenewalAppIDResolver.resolve(
            bundleIdentifier: gpsBundle, now: appIDNow,
            fetch: {
                let records = try await portal.fetch()
                withUnsafeCurrentTask { $0?.cancel() }
                return records
            }, register: { try await portal.register($0) })
    }
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(await portal.registeredBundles.isEmpty)
}
