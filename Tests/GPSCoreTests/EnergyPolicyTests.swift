import Foundation
import Testing
@testable import GPSCore

@Test func locationSamplingAdaptsAcrossAnAppliedSession() throws {
    var policy = LocationMonitoringPolicy()
    #expect(policy.sampling == nil)
    policy.mode = .applied
    let foreground = try #require(policy.sampling)
    policy.isBackground = true
    let background = try #require(policy.sampling)
    #expect(background.accuracy == .threeKilometers)
    #expect(try #require(background.minimumMovement) > #require(foreground.minimumMovement))
    policy.isBackground = false
    #expect(policy.sampling == foreground)
    policy.isLowPowerMode = true
    #expect(policy.sampling == background)
    policy.isLowPowerMode = false
    #expect(policy.sampling == foreground)
}

@Test func resetVerificationKeepsFreshSamplingAcrossPowerAndSceneChanges() throws {
    var policy = LocationMonitoringPolicy()
    policy.mode = .resetVerification
    for background in [false, true] {
        for lowPower in [false, true] {
            policy.isBackground = background
            policy.isLowPowerMode = lowPower
            let sampling = try #require(policy.sampling)
            #expect(sampling.accuracy == .hundredMeters)
            #expect(sampling.minimumMovement == nil)
        }
    }
    policy.mode = .applied
    #expect(policy.sampling?.accuracy == .threeKilometers)
    policy.mode = .idle
    #expect(policy.sampling == nil)
}

@Test func powerAndSceneChangesCannotRestartStoppedLocationMonitoring() {
    var policy = LocationMonitoringPolicy()
    for background in [false, true] {
        for lowPower in [false, true] {
            policy.isBackground = background
            policy.isLowPowerMode = lowPower
            #expect(policy.sampling == nil)
        }
    }
}

@Test func healthySigningProfilesWaitUntilTheirRenewalWindow() {
    let now = Date(timeIntervalSince1970: 1_000_000)
    let expiration = now.addingTimeInterval(7 * 24 * 3600)
    let scheduled = RenewalSchedule.nextBackgroundRefresh(now: now, expiration: expiration)
    #expect(scheduled == expiration.addingTimeInterval(-RenewalSchedule.leadTime))
    // Opening the app again before that window must not bring the wake forward.
    #expect(RenewalSchedule.nextBackgroundRefresh(now: now.addingTimeInterval(3600),
                                                 expiration: expiration) == scheduled)
}

@Test func dueOrUnknownSigningProfilesKeepTheirRetryCadence() {
    let now = Date(timeIntervalSince1970: 1_000_000)
    for expiration in [nil, now.addingTimeInterval(-3600), now,
                       now.addingTimeInterval(RenewalSchedule.leadTime)] {
        #expect(RenewalSchedule.nextBackgroundRefresh(now: now, expiration: expiration)
                == now.addingTimeInterval(RenewalSchedule.retryInterval))
    }
}
