import Foundation
import CryptoKit
import SideSign

enum RenewalAccountError: Error, LocalizedError, Sendable {
    case signInRequired
    case authenticationFailed
    case secureStorageUnavailable
    case localAnisetteUnavailable
    case portalUnavailable
    case wrongApp
    case wrongTeam
    case missingAppID
    case signingCertificateUnavailable
    case deviceNotProvisioned
    case profileUnchanged

    var errorDescription: String? {
        switch self {
        case .signInRequired:
            return "Sign in to the matching Apple development account to renew this app."
        case .authenticationFailed:
            return "Apple account sign-in did not complete. Check the account and verification code."
        case .secureStorageUnavailable:
            return "The saved renewal account is unavailable. Open GPS once while unlocked after updating, and unlock once after each restart."
        case .localAnisetteUnavailable:
            return "The on-device Apple sign-in support files are not ready."
        case .portalUnavailable:
            return "Apple's developer service did not complete the renewal. Try again later."
        case .wrongApp:
            return "The embedded profile does not belong to GPS Rebuilt."
        case .wrongTeam:
            return "The signed-in Apple account does not own this app's development team."
        case .missingAppID:
            return "This app's identifier is unavailable on the signed-in development team."
        case .signingCertificateUnavailable:
            return "The certificate that signed this app is unavailable for renewal."
        case .deviceNotProvisioned:
            return "Apple did not include this iPhone in the renewed profile."
        case .profileUnchanged:
            return "Apple returned a profile without a later expiration date."
        }
    }
}

private final class AppleRedirectGuard: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        guard let url = request.url,
              url.scheme?.lowercased() == "https",
              let host = url.host?.lowercased(),
              host == "apple.com" || host.hasSuffix(".apple.com") else {
            completionHandler(nil)
            return
        }
        completionHandler(request)
    }
}

/// Fetches only a new Xcode Team profile for this already installed app.
/// It does not create or revoke certificates, register devices, or change App IDs.
actor RenewalAppleAccount {
    static let shared = RenewalAppleAccount()

    private static let xcodeVersion = "27.0 (27A266a)"
    // Apple Music Android arm64 libraries from the verified Apple-signed APK.
    private static let adiSHA256 = [
        "libCoreADI.so": "9d5b557cf3faf88c34c394ab2cd7fc1a3b4acf3aed51f28cd0bc093858107c22",
        "libstoreservicescore.so": "bd335e6963ba5ae2f5babca613435ad56d2660a9aee37df35f876c458d105ce4"
    ]
    private let portal: DeveloperPortal
    private var sessionGeneration = 0

    private init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        let session = URLSession(configuration: configuration,
                                 delegate: AppleRedirectGuard(),
                                 delegateQueue: nil)
        portal = DeveloperPortal(session: session)
    }

    var hasSession: Bool {
        guard let state = try? RenewalCredentials.load(),
              let session = state.authSession?.session else { return false }
        return session.isValid
    }

    func signOut() throws {
        sessionGeneration += 1
        try RenewalCredentials.delete()
    }

    func signIn(
        email: String,
        password: String,
        verification: @escaping @Sendable (TwoFactorRequest) async throws -> TwoFactorResponse
    ) async throws {
        let trimmedEmail = email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedEmail.isEmpty, !password.isEmpty else {
            throw RenewalAccountError.authenticationFailed
        }
        sessionGeneration += 1
        let generation = sessionGeneration

        var state = try RenewalCredentials.load() ?? RenewalCredentialState()
        let (anisette, updatedState) = try await freshAnisette(for: state)
        guard generation == sessionGeneration else { throw CancellationError() }
        try Task.checkCancellation()
        state = updatedState
        try RenewalCredentials.save(state)

        let authenticated: AuthSession
        do {
            authenticated = try await portal.authenticate(
                appleID: trimmedEmail,
                password: password,
                anisetteData: anisette,
                xcodeVersion: Self.xcodeVersion,
                accountRepairHandler: { _, _ in .cancel },
                verificationHandler: verification
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw RenewalAccountError.authenticationFailed
        }

        guard generation == sessionGeneration else { throw CancellationError() }
        try Task.checkCancellation()
        state.email = trimmedEmail
        state.authSession = authenticated
        try RenewalCredentials.save(state)
    }

    /// Returns raw profile bytes. The caller validates them again before device installation.
    func fetchProfile(referenceData: Data, deviceID: String) async throws -> Data {
        let generation = sessionGeneration
        let reference: ProvisioningProfile
        do {
            reference = try ProvisioningProfile(data: referenceData)
        } catch {
            throw RenewalAccountError.wrongApp
        }
        guard reference.bundleIdentifier == Bundle.main.bundleIdentifier else {
            throw RenewalAccountError.wrongApp
        }
        guard !deviceID.isEmpty else { throw RenewalAccountError.deviceNotProvisioned }

        var state = try RenewalCredentials.load() ?? RenewalCredentialState()
        guard let saved = state.authSession, saved.session.isValid else {
            throw RenewalAccountError.signInRequired
        }
        let (anisette, updatedState) = try await freshAnisette(for: state)
        guard generation == sessionGeneration else { throw CancellationError() }
        try Task.checkCancellation()
        state = updatedState

        let old = saved.session
        let session = Session(
            dsid: old.dsid,
            authToken: old.authToken,
            anisetteData: anisette,
            xcodeVersion: old.xcodeVersion,
            machinePassword: old.machinePassword,
            creationDate: old.creationDate,
            expirationDate: old.expirationDate,
            timeToLive: old.timeToLive
        )
        state.authSession = AuthSession(account: saved.account, session: session)
        try RenewalCredentials.save(state)

        let account: Account
        do {
            account = try await portal.fetchAccount(session: session)
        } catch DeveloperPortalError.incorrectCredentials {
            throw RenewalAccountError.signInRequired
        } catch {
            throw RenewalAccountError.portalUnavailable
        }
        guard account.identifier == saved.account.identifier else {
            throw RenewalAccountError.signInRequired
        }

        let team: Team
        do {
            let teams = try await portal.fetchTeams(for: account, session: session)
            guard let matched = teams.first(where: { $0.identifier == reference.teamIdentifier }) else {
                throw RenewalAccountError.wrongTeam
            }
            team = matched
        } catch let error as RenewalAccountError {
            throw error
        } catch {
            throw RenewalAccountError.portalUnavailable
        }

        let referenceCertificates = Set(reference.certificates.compactMap(\.data))
        guard !referenceCertificates.isEmpty else {
            throw RenewalAccountError.signingCertificateUnavailable
        }
        do {
            let activeCertificates = try await portal.fetchCertificates(for: team, session: session)
            guard activeCertificates.contains(where: { cert in
                cert.data.map { referenceCertificates.contains($0) } ?? false
            }) else {
                throw RenewalAccountError.signingCertificateUnavailable
            }
        } catch let error as RenewalAccountError {
            throw error
        } catch {
            throw RenewalAccountError.portalUnavailable
        }

        let appID: AppID
        do {
            let appIDs = try await portal.fetchAppIDs(for: team, session: session)
            guard let matched = appIDs.first(where: { $0.bundleIdentifier == reference.bundleIdentifier }) else {
                throw RenewalAccountError.missingAppID
            }
            appID = matched
        } catch let error as RenewalAccountError {
            throw error
        } catch {
            throw RenewalAccountError.portalUnavailable
        }

        let renewed: ProvisioningProfile
        do {
            renewed = try await portal.downloadProvisioningProfile(
                for: appID, isTeamProfile: true, deviceType: .iPhone,
                team: team, session: session
            )
        } catch {
            throw RenewalAccountError.portalUnavailable
        }
        guard renewed.teamIdentifier == reference.teamIdentifier,
              renewed.bundleIdentifier == reference.bundleIdentifier else {
            throw RenewalAccountError.wrongApp
        }
        guard renewed.deviceIDs.contains(deviceID) else {
            throw RenewalAccountError.deviceNotProvisioned
        }
        guard renewed.certificates.contains(where: { cert in
            cert.data.map { referenceCertificates.contains($0) } ?? false
        }) else {
            throw RenewalAccountError.signingCertificateUnavailable
        }
        guard renewed.expirationDate > reference.expirationDate else {
            throw RenewalAccountError.profileUnchanged
        }
        guard generation == sessionGeneration else { throw CancellationError() }
        try Task.checkCancellation()
        return renewed.data
    }

    private func freshAnisette(
        for state: RenewalCredentialState
    ) async throws -> (AnisetteData, RenewalCredentialState) {
        guard let support = FileManager.default.urls(for: .applicationSupportDirectory,
                                                      in: .userDomainMask).first else {
            throw RenewalAccountError.localAnisetteUnavailable
        }
        let base = support.appendingPathComponent("GPSRenewal", isDirectory: true)
        let libs = base.appendingPathComponent("ADI", isDirectory: true)
        let provisioning = base.appendingPathComponent("provisioning", isDirectory: true)
        guard AnisetteDataManager.validateLibrariesExist(at: libs) else {
            throw RenewalAccountError.localAnisetteUnavailable
        }
        for (name, expectedHash) in Self.adiSHA256 {
            let file = libs.appendingPathComponent(name, isDirectory: false)
            guard let bytes = try? Data(contentsOf: file, options: .mappedIfSafe),
                  SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == expectedHash else {
                throw RenewalAccountError.localAnisetteUnavailable
            }
        }
        let manager = AnisetteDataManager(
            mode: .localODA(libsDir: libs, provisioningDir: provisioning),
            baseDirectory: base
        )
        do {
            let result = try await manager.fetchAnisetteData(
                identifier: state.anisetteIdentifier,
                existingAdiBlob: state.anisetteProvisioning
            )
            var updated = state
            if let newProvisioning = result.newAdiBlob {
                updated.anisetteProvisioning = newProvisioning
            }
            return (result.data, updated)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw RenewalAccountError.localAnisetteUnavailable
        }
    }
}
