import Foundation
import Testing
@testable import GPSCore

private let renewalNow = Date(timeIntervalSince1970: 1_800_000_000)
private let renewalDevice = "SYNTHETIC-DEVICE"
private let renewalTeam = "SYNTHETIC1"
private let renewalAppID = "SYNTHETIC1.app.gps.reconstruction"
private let renewalCertificates = [Data([0x30, 0x01]), Data([0x30, 0x02])]

private func profileFields(expiration: Date = renewalNow.addingTimeInterval(24 * 60 * 60)) -> [String: Any] {
    [
        "UUID": "00000000-0000-4000-8000-000000000001",
        "TeamIdentifier": [renewalTeam],
        "CreationDate": renewalNow.addingTimeInterval(-24 * 60 * 60),
        "ExpirationDate": expiration,
        "ProvisionedDevices": [renewalDevice],
        "DeveloperCertificates": renewalCertificates,
        "Entitlements": [
            "application-identifier": renewalAppID,
            "com.apple.developer.team-identifier": renewalTeam,
            "get-task-allow": true,
            "keychain-access-groups": ["SYNTHETIC1.*"],
            "synthetic.nested": ["permissions": ["read", "write"], "enabled": true]
        ] as [String: Any]
    ]
}

private func cmsFixture(_ fields: [String: Any]) throws -> Data {
    let xml = try PropertyListSerialization.data(fromPropertyList: fields, format: .xml, options: 0)
    return Data([0x30, 0x82, 0x01, 0x00]) + xml + Data([0x00, 0x01, 0xFF])
}

private func profile(_ fields: [String: Any]) throws -> RenewalProfile {
    try RenewalProfile(cmsData: cmsFixture(fields))
}

@Test func renewalProfileAcceptsConservativeExtensionAndDueWindow() throws {
    let reference = try profile(profileFields())
    var candidateFields = profileFields(expiration: renewalNow.addingTimeInterval(6 * 24 * 60 * 60))
    candidateFields["UUID"] = "00000000-0000-4000-8000-000000000002"
    candidateFields["DeveloperCertificates"] = renewalCertificates + [Data([0x30, 0x03])]
    var candidateEntitlements = try #require(candidateFields["Entitlements"] as? [String: Any])
    candidateEntitlements["synthetic.nested"] = ["permissions": ["write", "read", "admin"], "enabled": true]
    candidateEntitlements["synthetic.extra"] = "allowed"
    candidateFields["Entitlements"] = candidateEntitlements
    let candidate = try profile(candidateFields)

    #expect(reference.bundleIdentifier == RenewalProfile.rebuiltBundleIdentifier)
    #expect(reference.applicationIdentifier == renewalAppID)
    #expect(reference.deviceIDs == [renewalDevice])
    #expect(reference.developerCertificates == renewalCertificates)
    #expect(try candidate.validatedCandidate(reference: reference, deviceID: renewalDevice,
        now: renewalNow, minimumExpiration: reference.expiration) .uuid == candidate.uuid)
    #expect(!reference.isDue(now: renewalNow.addingTimeInterval(-3 * 24 * 60 * 60)))
    #expect(reference.isDue(now: renewalNow))
}

@Test func renewalProfileRejectsOtherTeamAndOriginalGPSBundle() throws {
    let reference = try profile(profileFields())
    var otherTeam = profileFields(expiration: renewalNow.addingTimeInterval(6 * 24 * 60 * 60))
    otherTeam["TeamIdentifier"] = ["OTHERTEAM1"]
    var teamEntitlements = try #require(otherTeam["Entitlements"] as? [String: Any])
    teamEntitlements["com.apple.developer.team-identifier"] = "OTHERTEAM1"
    teamEntitlements["application-identifier"] = "OTHERTEAM1.app.gps.reconstruction"
    otherTeam["Entitlements"] = teamEntitlements
    let otherTeamProfile = try profile(otherTeam)
    #expect(throws: RenewalProfileError.wrongApplication) {
        try otherTeamProfile.validatedCandidate(reference: reference, deviceID: renewalDevice, now: renewalNow)
    }

    var originalBundle = profileFields(expiration: renewalNow.addingTimeInterval(6 * 24 * 60 * 60))
    var originalEntitlements = try #require(originalBundle["Entitlements"] as? [String: Any])
    originalEntitlements["application-identifier"] = "SYNTHETIC1.app.gps.development"
    originalBundle["Entitlements"] = originalEntitlements
    #expect(throws: RenewalProfileError.wrongApplication) {
        try profile(originalBundle).validatedCandidate(reference: reference, deviceID: renewalDevice, now: renewalNow)
    }
}

@Test func renewalProfileRejectsOtherDeviceAndLostSigningCertificate() throws {
    let reference = try profile(profileFields())
    var missingDevice = profileFields(expiration: renewalNow.addingTimeInterval(6 * 24 * 60 * 60))
    missingDevice["ProvisionedDevices"] = ["OTHER-SYNTHETIC-DEVICE"]
    #expect(throws: RenewalProfileError.wrongDevice) {
        try profile(missingDevice).validatedCandidate(reference: reference, deviceID: renewalDevice, now: renewalNow)
    }
    var missingCertificate = profileFields(expiration: renewalNow.addingTimeInterval(6 * 24 * 60 * 60))
    missingCertificate["DeveloperCertificates"] = [renewalCertificates[0]]
    #expect(throws: RenewalProfileError.incompatibleCertificates) {
        try profile(missingCertificate).validatedCandidate(reference: reference, deviceID: renewalDevice, now: renewalNow)
    }
}

@Test func renewalProfileRequiresTypedEntitlementCoverageIncludingWildcardLiteral() throws {
    let reference = try profile(profileFields())
    var missingKeychain = profileFields(expiration: renewalNow.addingTimeInterval(6 * 24 * 60 * 60))
    var entitlements = try #require(missingKeychain["Entitlements"] as? [String: Any])
    entitlements.removeValue(forKey: "keychain-access-groups")
    missingKeychain["Entitlements"] = entitlements
    #expect(throws: RenewalProfileError.incompatibleEntitlements) {
        try profile(missingKeychain).validatedCandidate(reference: reference, deviceID: renewalDevice, now: renewalNow)
    }

    entitlements["keychain-access-groups"] = ["SYNTHETIC1.app.gps.reconstruction"]
    missingKeychain["Entitlements"] = entitlements
    #expect(throws: RenewalProfileError.incompatibleEntitlements) {
        try profile(missingKeychain).validatedCandidate(reference: reference, deviceID: renewalDevice, now: renewalNow)
    }

    entitlements["keychain-access-groups"] = ["SYNTHETIC1.*"]
    entitlements["synthetic.nested"] = ["permissions": ["read", "write"], "enabled": 1] as [String: Any]
    missingKeychain["Entitlements"] = entitlements
    #expect(throws: RenewalProfileError.incompatibleEntitlements) {
        try profile(missingKeychain).validatedCandidate(reference: reference, deviceID: renewalDevice, now: renewalNow)
    }
}

@Test func renewalProfileRequiresCurrentAndStrictlyLaterExpiration() throws {
    let reference = try profile(profileFields())
    #expect(throws: RenewalProfileError.notNewer) {
        try profile(profileFields()).validatedCandidate(reference: reference, deviceID: renewalDevice, now: renewalNow)
    }
    let newer = try profile(profileFields(expiration: renewalNow.addingTimeInterval(6 * 24 * 60 * 60)))
    #expect(throws: RenewalProfileError.notNewer) {
        try newer.validatedCandidate(reference: reference, deviceID: renewalDevice,
            now: renewalNow, minimumExpiration: newer.expiration)
    }
    var expiredReferenceFields = profileFields(expiration: renewalNow.addingTimeInterval(-2 * 24 * 60 * 60))
    expiredReferenceFields["CreationDate"] = renewalNow.addingTimeInterval(-3 * 24 * 60 * 60)
    let expiredReference = try profile(expiredReferenceFields)
    var expiredCandidateFields = profileFields(expiration: renewalNow.addingTimeInterval(-24 * 60 * 60))
    expiredCandidateFields["CreationDate"] = renewalNow.addingTimeInterval(-2 * 24 * 60 * 60)
    let expiredCandidate = try profile(expiredCandidateFields)
    #expect(throws: RenewalProfileError.notCurrentlyValid) {
        try expiredCandidate.validatedCandidate(reference: expiredReference, deviceID: renewalDevice, now: renewalNow)
    }
    var futureCreation = profileFields(expiration: renewalNow.addingTimeInterval(6 * 24 * 60 * 60))
    futureCreation["CreationDate"] = renewalNow.addingTimeInterval(60)
    #expect(throws: RenewalProfileError.notCurrentlyValid) {
        try profile(futureCreation).validatedCandidate(reference: reference, deviceID: renewalDevice, now: renewalNow)
    }
}

@Test func renewalProfileRejectsMalformedOversizedAndAmbiguousCMS() throws {
    #expect(throws: RenewalProfileError.invalidSize) {
        try RenewalProfile(cmsData: Data(repeating: 0, count: RenewalProfile.maximumCMSSize + 1))
    }
    #expect(throws: RenewalProfileError.malformed) {
        try RenewalProfile(cmsData: Data([0x30, 0x82, 0x01]))
    }
    let valid = try cmsFixture(profileFields())
    #expect(throws: RenewalProfileError.malformed) {
        try RenewalProfile(cmsData: valid + valid)
    }
    var missingCertificates = profileFields()
    missingCertificates.removeValue(forKey: "DeveloperCertificates")
    #expect(throws: RenewalProfileError.malformed) {
        try profile(missingCertificates)
    }
    var missingDevelopmentFlag = profileFields()
    var entitlements = try #require(missingDevelopmentFlag["Entitlements"] as? [String: Any])
    entitlements["get-task-allow"] = false
    missingDevelopmentFlag["Entitlements"] = entitlements
    #expect(throws: RenewalProfileError.malformed) {
        try profile(missingDevelopmentFlag)
    }
    #expect(!(RenewalProfileError.wrongDevice.errorDescription ?? "").contains(renewalDevice))
    #expect(!(RenewalProfileError.incompatibleCertificates.errorDescription ?? "").contains("30"))
}
