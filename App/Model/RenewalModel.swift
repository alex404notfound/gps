import Foundation
import Observation
import CryptoKit
import SideSign

@MainActor @Observable
final class RenewalModel {
    static let shared = RenewalModel()

    var enabled: Bool {
        didSet {
            UserDefaults.standard.set(enabled, forKey: "signingRefresh.enabled")
            if enabled { RenewalScheduler.schedule() }
            else { RenewalScheduler.cancel() }
        }
    }
    var isSignedIn = false
    var isBusy = false
    var status = "Sign in to renew GPS on this iPhone."
    var verifiedExpiration: Date?
    var verifiedAt: Date?
    var hasPreparedProfile = false
    var verificationRequest: TwoFactorRequest?
    var embeddedExpiration: Date? { try? referenceProfile().expiration }
    var expiration: Date? { verifiedExpiration ?? embeddedExpiration }
    var needsAutomaticRefresh: Bool { enabled && isDue }

    @ObservationIgnored private var verificationContinuation: CheckedContinuation<TwoFactorResponse, Never>?
    @ObservationIgnored private let pending = PendingRenewalStore()
    @ObservationIgnored private var lastAutomaticAttempt: Date?
    @ObservationIgnored private var lastOutcome = "not attempted"
    // A signed bundle cannot replace its embedded profile while this process is
    // running. Cache both success and failure so UI reads never repeat disk I/O.
    @ObservationIgnored private lazy var embeddedReference: Result<Data, Error> = Result {
        try Self.loadReferenceData()
    }
    @ObservationIgnored private lazy var embeddedReferenceProfile: Result<RenewalProfile, Error> = Result {
        try RenewalProfile(cmsData: referenceData())
    }

    private init() {
        enabled = UserDefaults.standard.bool(forKey: "signingRefresh.enabled")
        if let data = try? referenceData(),
           UserDefaults.standard.string(forKey: "signingRefresh.referenceHash") == Self.digest(data) {
            verifiedExpiration = UserDefaults.standard.object(forKey: "signingRefresh.expiration") as? Date
            verifiedAt = UserDefaults.standard.object(forKey: "signingRefresh.verifiedAt") as? Date
        }
    }

    func reload() async {
        // Reading also migrates legacy Keychain accessibility. Do this whenever
        // GPS opens, even if renewal is disabled or the profile is not due yet.
        isSignedIn = await RenewalAppleAccount.shared.hasSession
        hasPreparedProfile = (try? pending.load()) != nil
    }

    func signIn(email: String, password: String) async -> Bool {
        guard !isBusy else { return false }
        isBusy = true
        status = "Signing in with Apple…"
        defer { isBusy = false; verificationRequest = nil }
        do {
            try await RenewalAppleAccount.shared.signIn(email: email, password: password) { request in
                await self.waitForVerification(request)
            }
            try Task.checkCancellation()
            isSignedIn = true
            enabled = true
            status = "Signed in. Tap Refresh now to verify renewal on this iPhone."
            recordOutcome("signed in")
            await RenewalScheduler.requestNotifications()
            return true
        } catch {
            status = error.localizedDescription
            recordOutcome("sign-in failed")
            return false
        }
    }

    func answerVerification(_ response: TwoFactorResponse) {
        let continuation = verificationContinuation
        verificationContinuation = nil
        verificationRequest = nil
        continuation?.resume(returning: response)
    }

    private func waitForVerification(_ request: TwoFactorRequest) async -> TwoFactorResponse {
        if Task.isCancelled { return .cancel }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                verificationRequest = request
                verificationContinuation = continuation
            }
        } onCancel: {
            Task { @MainActor in self.answerVerification(.cancel) }
        }
    }

    func signOut() async {
        guard !isBusy else { return }
        enabled = false
        answerVerification(.cancel)
        do {
            try await RenewalAppleAccount.shared.signOut()
            try pending.clear()
            hasPreparedProfile = false
            isSignedIn = false
            status = "Signed out. The installed GPS profile remains in place."
            recordOutcome("signed out")
        } catch { status = error.localizedDescription }
    }

    func refresh(force: Bool = true) async throws -> String {
        guard !isBusy else { throw RenewalOperationError.busy }
        if !force && !isDue { return "GPS does not need refreshing yet." }
        isBusy = true
        defer { isBusy = false }
        do {
            let configuration = try configuration()
            try await prepare(configuration: configuration)
            try Task.checkCancellation()
            return try await install(configuration: configuration)
        } catch {
            status = error.localizedDescription
            recordOutcome("refresh failed")
            throw error
        }
    }

    /// Download while internet is available; installation can then run with cellular off.
    func prepareOnly(force: Bool = true) async throws -> String {
        guard !isBusy else { throw RenewalOperationError.busy }
        if !force && !isDue { return "GPS does not need refreshing yet." }
        isBusy = true
        defer { isBusy = false }
        do {
            try await prepare(configuration: configuration())
            status = "Profile ready. Keep LocalDevVPN on, turn cellular off if needed, then install the prepared refresh."
            return status
        } catch { status = error.localizedDescription; recordOutcome("prepare failed"); throw error }
    }

    func installPrepared() async throws -> String {
        guard !isBusy else { throw RenewalOperationError.busy }
        isBusy = true
        defer { isBusy = false }
        do { return try await install(configuration: configuration()) }
        catch { status = error.localizedDescription; recordOutcome("install failed"); throw error }
    }

    func runAutomatically(throttle: Bool) async -> Bool {
        guard enabled, isDue else { return true }
        guard !isBusy else { return false }
        if throttle, let lastAutomaticAttempt,
           Date.now.timeIntervalSince(lastAutomaticAttempt) < 6 * 3600 { return true }
        lastAutomaticAttempt = .now
        do {
            _ = try await refresh(force: false)
            return true
        } catch {
            if let expiration, expiration.timeIntervalSinceNow < 48 * 3600 {
                await RenewalScheduler.notifyFailure()
            }
            return false
        }
    }

    private var isDue: Bool {
        guard let expiration else { return true }
        return expiration.timeIntervalSinceNow <= RenewalSchedule.leadTime
    }

    private func prepare(configuration: SetupConfiguration) async throws {
        status = "Requesting a new GPS profile from Apple…"
        recordOutcome("prepare started")
        let referenceData = try referenceData()
        let reference = try referenceProfile()
        let data = try await RenewalAppleAccount.shared.fetchProfile(
            referenceData: referenceData, deviceID: configuration.device.identifier)
        try Task.checkCancellation()
        _ = try RenewalProfile(cmsData: data).validatedCandidate(
            reference: reference, deviceID: configuration.device.identifier, now: .now,
            minimumExpiration: verifiedExpiration)
        try pending.save(data)
        hasPreparedProfile = true
        recordOutcome("profile prepared")
    }

    private func install(configuration: SetupConfiguration) async throws -> String {
        guard let data = try pending.load() else { throw RenewalOperationError.noPreparedProfile }
        let referenceData = try referenceData()
        let profile = try RenewalProfile(cmsData: data).validatedCandidate(
            reference: referenceProfile(), deviceID: configuration.device.identifier,
            now: .now, minimumExpiration: verifiedExpiration)
        try Task.checkCancellation()
        status = "Installing and checking the GPS profile on this iPhone…"
        recordOutcome("install started")
        try await NativeProfileTransport.shared.install(profile: data, configuration: configuration)
        // Native reports success only after iOS accepts and returns the exact profile.
        verifiedExpiration = profile.expiration
        verifiedAt = .now
        UserDefaults.standard.set(Self.digest(referenceData), forKey: "signingRefresh.referenceHash")
        UserDefaults.standard.set(profile.expiration, forKey: "signingRefresh.expiration")
        UserDefaults.standard.set(verifiedAt, forKey: "signingRefresh.verifiedAt")
        // An optional Keychain cleanup cannot undo iOS's verified installation.
        try? pending.clear()
        hasPreparedProfile = (try? pending.load()) != nil
        status = "Refreshed. iOS confirmed the installed profile expires \(profile.expiration.formatted(date: .abbreviated, time: .shortened))."
        recordOutcome("installed and verified")
        RenewalScheduler.schedule()
        return status
    }

    private func referenceData() throws -> Data {
        try embeddedReference.get()
    }

    private static func loadReferenceData() throws -> Data {
        guard Bundle.main.bundleIdentifier == "app.gps.reconstruction",
              let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision") else {
            throw RenewalOperationError.noEmbeddedProfile
        }
        let data = try Data(contentsOf: url)
        guard data.count <= 2_000_000 else { throw RenewalOperationError.noEmbeddedProfile }
        return data
    }

    private func referenceProfile() throws -> RenewalProfile {
        try embeddedReferenceProfile.get()
    }

    private func configuration() throws -> SetupConfiguration {
        guard let data = try SetupKeychain().load() else { throw GPSError.setupRequired }
        return try SetupConfiguration.decode(data)
    }

    private static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func recordOutcome(_ outcome: String) {
        lastOutcome = outcome
        struct Diagnostic: Encodable {
            let recordedAt: Date
            let outcome: String
            let automaticEnabled: Bool
            let signedIn: Bool
            let prepared: Bool
            let verifiedExpiration: Date?
            let verifiedAt: Date?
        }
        let diagnostic = Diagnostic(recordedAt: .now, outcome: lastOutcome,
                                    automaticEnabled: enabled, signedIn: isSignedIn,
                                    prepared: hasPreparedProfile,
                                    verifiedExpiration: verifiedExpiration, verifiedAt: verifiedAt)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(diagnostic) else { return }
        let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("GPSRenewal", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        // Fixed outcomes and dates only; no account, profile, device, or error payloads.
        try? data.write(to: directory.appendingPathComponent("renewal-status.json"),
                        options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}

enum RenewalOperationError: LocalizedError {
    case busy, noPreparedProfile, noEmbeddedProfile, keychain, disabled
    var errorDescription: String? {
        switch self {
        case .busy: "A signing operation is already running."
        case .noPreparedProfile: "Prepare a refresh while connected to the internet first."
        case .noEmbeddedProfile: "This build has no usable GPS signing profile. Install a signed device build."
        case .keychain: "The prepared refresh is unavailable. Open GPS once while unlocked after updating, and unlock once after each restart."
        case .disabled: "Enable automatic refresh in GPS → App Access first."
        }
    }
}

private struct PendingRenewalStore {
    private let item = BackgroundKeychainItem(
        service: "app.gps.reconstruction.renewal-state", account: "prepared-profile")

    func load() throws -> Data? {
        do {
            guard let data = try item.load() else { return nil }
            guard data.count <= 2_000_000 else { throw RenewalOperationError.keychain }
            return data
        } catch { throw RenewalOperationError.keychain }
    }

    func save(_ data: Data) throws {
        do { try item.save(data) }
        catch { throw RenewalOperationError.keychain }
    }

    func clear() throws {
        do { try item.delete() }
        catch { throw RenewalOperationError.keychain }
    }
}
