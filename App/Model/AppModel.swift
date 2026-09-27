import Foundation
import MapKit
import Observation
import UIKit
import CryptoKit
import Network

@MainActor @Observable
final class AppModel {
    let renewal = RenewalModel.shared
    var selectedCoordinate: Coordinate?
    var selectedName = "Selected location"
    var searchQuery = ""
    var searchResults: [SearchResult] = []
    var isSearching = false
    var favorites: [SavedPlace] = []
    var recentPlaces: [SavedPlace] = []
    var connectionState: ConnectionState = .notConfigured {
        didSet { persistDiagnostics() }
    }
    var operationState: OperationState = .idle
    var lastAppliedCoordinate: Coordinate?
    var statusMessage: String? {
        didSet { persistDiagnostics() }
    }
    var setupSummary: String?
    var configuredHost: String?
    var profileExpiration: Date?
    var monitorStatus = "Location monitoring starts after Set."
    var monitorAccessNotice: String?
    var reportedSourceStatus: String?
    var resetReadbackStatus: String?
    var isCheckingCellularConnection = false
    var cellularConnectionCheck: String?
    var directConnectionCandidates: [String] = []
    var directConnectionResult: String?

    @ObservationIgnored private let session: LocationSession
    @ObservationIgnored private let monitor = LocationMonitor()
    @ObservationIgnored private let keychain = SetupKeychain()
    @ObservationIgnored private let places = PlaceStore()
    @ObservationIgnored private var configuration: SetupConfiguration?
    @ObservationIgnored private var activeSearch: MKLocalSearch?
    @ObservationIgnored private var searchGeneration = 0
    @ObservationIgnored private var actionInProgress = false
    @ObservationIgnored private var events: [String] = []
    @ObservationIgnored private var writingDiagnostics = false
    @ObservationIgnored private lazy var diagnosticsWriter = CoalescingFileWriter(url: diagnosticsURL) { [weak self] in
        Task { @MainActor [weak self] in
            guard let self, self.statusMessage == nil else { return }
            // Reporting a failed write must not schedule another failed write.
            self.writingDiagnostics = true
            self.statusMessage = "Diagnostics could not be saved for USB export."
            self.writingDiagnostics = false
        }
    }
    @ObservationIgnored private var pendingImportAttempted = false
    @ObservationIgnored private let pathMonitor = NWPathMonitor()
    @ObservationIgnored private var networkPathSummary = "System network path has not been reported yet."

    private var setupDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("GPSSetup", isDirectory: true)
    }

    private var pendingSetupURL: URL {
        setupDirectory.appendingPathComponent("pending-setup.json")
    }

    private var diagnosticsURL: URL {
        setupDirectory.appendingPathComponent("diagnostics.txt")
    }

    init(transport: any LocationTransport = NativeLocationTransport()) {
        session = LocationSession(transport: transport)
        monitor.onEvent = { [weak self] event in self?.handleMonitorEvent(event) }
        profileExpiration = ProvisioningStatus.embeddedExpiration()
        do {
            let stored = try places.load()
            favorites = stored.favorites
            recentPlaces = stored.recent
        } catch { statusMessage = "Saved places could not be loaded. \(error.localizedDescription)" }
        restoreSetup()
        record("App opened; previous device location is not assumed.")
        observeNetworkPath()
    }

    deinit { pathMonitor.cancel() }

    var diagnosticText: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown"
        return (["GPS Reconstruction \(version) (build \(build))", "iOS \(UIDevice.current.systemVersion)",
                 "Connection: \(connectionState.title)",
                 "Setup: \(configuration == nil ? "not imported" : "stored in Keychain")",
                 "Reported location has not been independently verified.", ""] + events).joined(separator: "\n")
    }

    func search() async {
        searchGeneration += 1
        let generation = searchGeneration
        activeSearch?.cancel()
        searchResults = []
        let query = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { isSearching = false; return }
        isSearching = true
        let request = MKLocalSearch.Request()
        request.naturalLanguageQuery = query
        if let selectedCoordinate {
            request.region = MKCoordinateRegion(
                center: CLLocationCoordinate2D(latitude: selectedCoordinate.latitude, longitude: selectedCoordinate.longitude),
                latitudinalMeters: 100_000, longitudinalMeters: 100_000)
        }
        let search = MKLocalSearch(request: request)
        activeSearch = search
        do {
            let response = try await search.start()
            guard generation == searchGeneration else { return }
            searchResults = response.mapItems.enumerated().compactMap { index, item in
                let point = item.placemark.coordinate
                let coordinate = Coordinate(latitude: point.latitude, longitude: point.longitude)
                guard coordinate.isValid else { return nil }
                return SearchResult(id: "\(index)-\(coordinate.formatted)", name: item.name ?? "Place",
                                    subtitle: item.placemark.title ?? coordinate.formatted, coordinate: coordinate)
            }
            statusMessage = searchResults.isEmpty ? "No places found. Try a city, address, or enter coordinates." : nil
        } catch {
            guard generation == searchGeneration else { return }
            if !Task.isCancelled { statusMessage = "Search unavailable. You can still enter coordinates." }
        }
        guard generation == searchGeneration else { return }
        activeSearch = nil
        isSearching = false
    }

    func select(_ result: SearchResult) { select(result.coordinate, name: result.name) }
    func select(_ place: SavedPlace) { select(place.coordinate, name: place.name) }
    func select(_ coordinate: Coordinate, name: String) {
        guard coordinate.isValid else { statusMessage = GPSError.invalidCoordinate.localizedDescription; return }
        selectedCoordinate = coordinate
        selectedName = name.isEmpty ? "Selected location" : name
        searchGeneration += 1
        activeSearch?.cancel()
        activeSearch = nil
        isSearching = false
        searchResults = []
        statusMessage = nil
    }

    func saveFavorite() {
        guard let selectedCoordinate, selectedCoordinate.isValid else { return }
        guard !favorites.contains(where: { $0.coordinate == selectedCoordinate }) else {
            statusMessage = "This location is already saved."
            return
        }
        favorites.append(SavedPlace(name: selectedName, coordinate: selectedCoordinate))
        if let detail = persistPlaces() {
            statusMessage = "Your places could not be saved. \(detail)"
        }
    }

    func deleteFavorite(_ id: UUID) {
        favorites.removeAll { $0.id == id }
        if let detail = persistPlaces() {
            statusMessage = "Your places could not be saved. \(detail)"
        }
    }

    func importSetup(from url: URL) async {
        guard !actionInProgress else { statusMessage = GPSError.busy.localizedDescription; return }
        actionInProgress = true
        defer { actionInProgress = false }
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        do {
            let imported = try validatedSetup(at: url)
            try await storeSetup(imported)
            statusMessage = "Setup saved securely. Turn on your local VPN, then connect."
            record("Imported setup with a pinned device identity.")
        } catch {
            statusMessage = error.localizedDescription
            record("Setup import failed. Existing setup was retained where available.")
        }
    }

    /// Imports only the known file copied into this app's own data container.
    /// Called at launch; it never connects or sends a location command.
    func importPendingSetupIfPresent() async {
        guard !pendingImportAttempted else { return }
        pendingImportAttempted = true
        let url = pendingSetupURL
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        guard !actionInProgress else { statusMessage = GPSError.busy.localizedDescription; return }
        actionInProgress = true
        defer { actionInProgress = false }

        do {
            let directoryValues = try setupDirectory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard directoryValues.isDirectory == true, directoryValues.isSymbolicLink != true else {
                throw GPSError.invalidSetup("The pending setup directory is not a regular app directory.")
            }
            let imported = try validatedSetup(at: url)
            try await storeSetup(imported)
        } catch {
            statusMessage = "Pending setup was not imported. The copied file remains in app storage. \(error.localizedDescription)"
            record("Pending setup import failed; copied file retained.")
            return
        }

        do {
            try FileManager.default.removeItem(at: url)
            statusMessage = "Setup imported securely. Turn on LocalDevVPN, then connect."
            record("Pending setup imported; copied credential file removed.")
        } catch {
            statusMessage = "Setup imported, but pending-setup.json could not be removed. Delete the copied file from this app's files before sharing a container backup."
            record("Pending setup file removal failed; copied credentials remain in app storage.")
        }
    }

    func updateConnectionAddress(_ input: String) async {
        guard !actionInProgress, connectionState != .connecting, !operationState.isBusy else {
            statusMessage = GPSError.busy.localizedDescription
            return
        }
        if configuration == nil { restoreSetup() }
        guard var updated = configuration else {
            statusMessage = GPSError.setupRequired.localizedDescription
            return
        }
        guard let host = privateIPv4Address(from: input) else {
            statusMessage = "Enter a private IPv4 address, such as 10.7.0.1. A /32 suffix is accepted."
            return
        }
        guard host != updated.transport.host else {
            statusMessage = "This Device IP is already saved."
            return
        }
        actionInProgress = true
        defer { actionInProgress = false }
        updated.transport.host = host
        do {
            try await storeSetup(updated)
            statusMessage = "Device IP saved. Turn on LocalDevVPN, then connect."
            record("Connection address updated; paired identity retained.")
        } catch {
            statusMessage = error.localizedDescription
            record("Connection address update failed; previous setup retained.")
        }
    }

    func connect(directHost: String? = nil) async {
        guard !actionInProgress else { statusMessage = GPSError.busy.localizedDescription; return }
        if configuration == nil { restoreSetup() }
        guard var configuration else { statusMessage = GPSError.setupRequired.localizedDescription; return }
        if let directHost {
            guard directHost == "127.0.0.1" || directHost == "::1" else {
                statusMessage = "Choose one of the direct on-device test addresses."
                return
            }
            configuration.transport.host = directHost
        }
        actionInProgress = true
        defer { actionInProgress = false }
        connectionState = .connecting
        statusMessage = nil
        if let directHost { directConnectionResult = "Connecting directly to \(directHost)…" }
        record("\(directHost == nil ? "Connect" : "Direct pairing test") requested. \(networkPathSummary)")
        var failure: Error?
        do {
            try await session.connect(configuration: configuration)
            if let directHost { directConnectionResult = "\(directHost): Connected to the developer location service." }
            record("Authenticated developer location service connected.")
        } catch {
            failure = error
            monitor.stop()
            if let directHost {
                directConnectionResult = "\(directHost): \(error.localizedDescription)"
                record("Direct pairing test \(directHost) failed: \(error.localizedDescription.prefix(600))")
            }
            record("Connection failed. No location command was sent.")
        }
        await updateSession(failure: failure)
    }

    func checkCellularConnection() async {
        guard !actionInProgress else { statusMessage = GPSError.busy.localizedDescription; return }
        guard !connectionState.isConnected else {
            cellularConnectionCheck = "Disconnect GPS before checking a fresh cellular connection."
            return
        }
        if configuration == nil { restoreSetup() }
        guard let configuration else { cellularConnectionCheck = GPSError.setupRequired.localizedDescription; return }
        actionInProgress = true
        isCheckingCellularConnection = true
        cellularConnectionCheck = "Checking the local developer ports…"
        directConnectionCandidates = []
        defer { actionInProgress = false; isCheckingCellularConnection = false }
        do {
            let result = try await LocalConnectionProbe.shared.check(configuration: configuration)
            cellularConnectionCheck = result.summary
            directConnectionCandidates = result.directConnectionCandidates
            record("Local connection check: \(result.summary)")
        } catch {
            cellularConnectionCheck = error.localizedDescription
            record("Local connection check did not finish. No pairing or location command was sent.")
        }
    }

    func disconnect() async {
        guard !actionInProgress else { statusMessage = GPSError.busy.localizedDescription; return }
        actionInProgress = true
        defer { actionInProgress = false }
        var failure: Error?
        do { try await session.disconnect(); record("Disconnected; no implicit reset requested.") }
        catch { failure = error }
        monitor.stop()
        await updateSession(failure: failure)
    }

    func apply() async {
        let startedAt = DispatchTime.now().uptimeNanoseconds
        guard !actionInProgress else { statusMessage = GPSError.busy.localizedDescription; return }
        guard let selectedCoordinate else { statusMessage = "Choose a location first."; return }
        actionInProgress = true
        defer { actionInProgress = false }
        operationState = .applying
        record("Apply action started.")
        resetReadbackStatus = nil
        reportedSourceStatus = nil
        monitor.beginAppliedSession()
        let name = selectedName
        await withBackgroundTime(name: "Apply location") {
            var failure: Error?
            var storageMessage: String?
            do {
                try await self.session.apply(selectedCoordinate)
                let elapsed = self.elapsedMilliseconds(since: startedAt)
                self.recentPlaces.removeAll { $0.coordinate == selectedCoordinate }
                self.recentPlaces.insert(SavedPlace(name: name, coordinate: selectedCoordinate), at: 0)
                self.recentPlaces = Array(self.recentPlaces.prefix(12))
                if let detail = self.persistPlaces() {
                    storageMessage = "Location request accepted, but recent places could not be saved. \(detail)"
                }
                self.record("Apply command accepted after \(elapsed) ms; no independent location readback.")
            } catch {
                failure = error
                self.monitor.stop()
                let elapsed = self.elapsedMilliseconds(since: startedAt)
                self.record(self.isSessionPrecondition(error)
                    ? "Apply request was not sent after \(elapsed) ms."
                    : "Apply command was not confirmed after \(elapsed) ms.")
            }
            await self.updateSession(failure: failure, storageMessage: storageMessage)
        }
    }

    func reset() async {
        let startedAt = DispatchTime.now().uptimeNanoseconds
        guard !actionInProgress else { statusMessage = GPSError.busy.localizedDescription; return }
        actionInProgress = true
        defer { actionInProgress = false }
        operationState = .resetting
        record("Reset action started.")
        await withBackgroundTime(name: "Reset location") {
            var failure: Error?
            do {
                try await self.session.reset()
                let elapsed = self.elapsedMilliseconds(since: startedAt)
                self.record("Reset command sent after \(elapsed) ms; no acknowledgement or independent location readback.")
                self.monitor.beginResetVerification()
            } catch {
                failure = error
                self.monitor.stop()
                let elapsed = self.elapsedMilliseconds(since: startedAt)
                self.record(self.isSessionPrecondition(error)
                    ? "Reset request was not sent after \(elapsed) ms."
                    : "Reset command was not confirmed after \(elapsed) ms.")
            }
            await self.updateSession(failure: failure)
            if failure == nil {
                self.statusMessage = "Reset command sent. Check Maps to verify your current location."
            }
        }
    }

    func refreshAfterForeground() {
        monitor.sceneBecameActive()
        // The signed bundle's embedded profile is immutable for this process.
        if configuration == nil { restoreSetup() }
        Task {
            await renewal.reload()
            _ = await renewal.runAutomatically(throttle: true)
        }
    }

    func recordSceneActive() {
        record("Scene became active; existing connection state has not been rechecked.")
    }

    func recordSceneBackground() {
        monitor.sceneEnteredBackground()
        record("Scene entered background.")
        Task {
            await withBackgroundTime(name: "Save diagnostics") {
                await self.diagnosticsWriter.flush()
            }
        }
    }

    func recordSceneInactive() {
        monitor.sceneBecameInactive()
    }

    private func elapsedMilliseconds(since startedAt: UInt64) -> UInt64 {
        (DispatchTime.now().uptimeNanoseconds &- startedAt) / 1_000_000
    }

    private func restoreSetup() {
        do {
            if let data = try keychain.load() {
                let loaded = try SetupConfiguration.decode(data)
                try validateIdentity(loaded)
                configuration = loaded
                setupSummary = loaded.device.name ?? "Paired iPhone"
                configuredHost = loaded.transport.host
                connectionState = .disconnected
            }
        } catch { statusMessage = error.localizedDescription }
    }

    private func validateIdentity(_ configuration: SetupConfiguration) throws {
        guard let privateBytes = Data(base64Encoded: configuration.pairing.privateKey),
              let publicBytes = Data(base64Encoded: configuration.pairing.publicKey),
              let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: privateBytes),
              key.publicKey.rawRepresentation == publicBytes else {
            throw GPSError.invalidSetup("The signing key does not match its public identity.")
        }
    }

    private func validatedSetup(at url: URL) throws -> SetupConfiguration {
        let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true,
              let size = values.fileSize, size > 0, size <= SetupConfiguration.maximumFileSize else {
            throw GPSError.invalidSetup("Choose a regular GPS setup JSON file smaller than 64 KB.")
        }
        let imported = try SetupConfiguration.decode(Data(contentsOf: url))
        try validateIdentity(imported)
        return imported
    }

    private func storeSetup(_ imported: SetupConfiguration) async throws {
        try validateIdentity(imported)
        let encoded = try imported.encoded()
        monitor.stop()
        try await session.disconnect()
        connectionState = .disconnected
        operationState = .idle
        try keychain.save(encoded)
        configuration = imported
        setupSummary = imported.device.name ?? "Paired iPhone"
        configuredHost = imported.transport.host
    }

    private func privateIPv4Address(from input: String) -> String? {
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasSuffix("/32") { text = String(text.dropLast(3)) }
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        let octets = parts.compactMap { part -> UInt8? in
            guard let value = UInt8(part), String(value) == part else { return nil }
            return value
        }
        guard octets.count == 4 else { return nil }
        let isPrivate = octets[0] == 10 ||
            (octets[0] == 172 && (16...31).contains(octets[1])) ||
            (octets[0] == 192 && octets[1] == 168)
        return isPrivate ? octets.map(String.init).joined(separator: ".") : nil
    }

    private func updateSession(failure: Error? = nil, storageMessage: String? = nil) async {
        let snapshot = await session.snapshot()
        connectionState = snapshot.connection
        operationState = snapshot.operation
        lastAppliedCoordinate = snapshot.lastApplied
        statusMessage = snapshot.notice
        if let failure {
            // A transport failure can leave the command's outcome unknown. Keep
            // that session notice; precondition failures never reached transport.
            let hasIndeterminateNotice: Bool
            if case .failed = snapshot.operation {
                hasIndeterminateNotice = !isSessionPrecondition(failure) && snapshot.notice != nil
            } else {
                hasIndeterminateNotice = false
            }
            if !hasIndeterminateNotice { statusMessage = failure.localizedDescription }
        }
        if failure == nil, let storageMessage { statusMessage = storageMessage }
    }

    private func handleMonitorEvent(_ event: LocationMonitor.Event) {
        switch event {
        case .permissionRequested:
            monitorStatus = "Allow Location access to keep this session active while using Maps."
            monitorAccessNotice = nil
            record("Location access requested for the user-started session.")
        case .permissionDenied:
            monitorStatus = "Location monitoring unavailable."
            monitorAccessNotice = "Location access is denied. Across-app monitoring needs When In Use access in Settings."
            record("Location access denied; across-app monitoring unavailable.")
        case .servicesUnavailable:
            monitorStatus = "Location monitoring unavailable."
            monitorAccessNotice = "Location Services are unavailable on this iPhone."
            record("Location Services unavailable; across-app monitoring unavailable.")
        case .waitingForForeground:
            monitorStatus = "Location monitoring will start when GPS is active."
            record("Location monitoring awaits foreground activation.")
        case .monitoringStarted(let backgroundEnabled):
            monitorStatus = backgroundEnabled
                ? "Monitoring iOS location reports across app switches."
                : "Monitoring while GPS is open; background location capability is unavailable."
            monitorAccessNotice = backgroundEnabled ? nil : "Background location capability is unavailable in this build."
            record(backgroundEnabled
                ? "Location monitoring started with background delivery."
                : "Location monitoring started without background delivery.")
        case .monitoringStopped:
            monitorStatus = "Location monitoring stopped."
            record("Location monitoring stopped.")
        case .sourceChanged(let source):
            switch source {
            case .simulated:
                reportedSourceStatus = "Last iOS sample: software-simulated."
                record("iOS sample source changed to software-simulated.")
            case .nonSimulated:
                reportedSourceStatus = "Last iOS sample: non-simulated."
                record("iOS sample source changed to non-simulated.")
            case .unknown:
                reportedSourceStatus = "Last iOS sample: source unavailable."
                record("iOS sample source became unavailable.")
            }
        case .resetAwaitingSample:
            resetReadbackStatus = "Reset sent; checking the location reported by iOS."
            record("Waiting for a fresh post-reset iOS sample.")
        case .freshNonSimulatedAfterReset(let milliseconds):
            resetReadbackStatus = "Reset checked: iOS is no longer reporting a simulated location."
            record("Fresh non-simulated post-reset sample after \(milliseconds) ms; physical location not verified.")
        case .resetTimedOut:
            resetReadbackStatus = "Reset was sent, but iOS hasn't supplied a fresh location to confirm it. Check Maps."
            record("Post-reset readback timed out without a fresh non-simulated sample.")
        case .resetVerificationUnavailable:
            resetReadbackStatus = "In-app reset readback is unavailable. Check Maps."
            record("Post-reset readback unavailable.")
        case .monitoringFailed:
            monitorStatus = "iOS location monitoring stopped after an error. Check Location access in Settings."
            monitorAccessNotice = "iOS could not continue location monitoring. Across-app monitoring is unavailable."
            record("Location monitoring stopped after a Core Location error.")
        }
    }

    private func isSessionPrecondition(_ error: Error) -> Bool {
        guard let error = error as? GPSError else { return false }
        switch error {
        case .busy, .notConnected, .invalidCoordinate, .setupRequired, .invalidSetup:
            return true
        case .transport, .storage:
            return false
        }
    }

    private func persistPlaces() -> String? {
        do {
            try places.save(PlaceCollection(favorites: favorites, recent: recentPlaces))
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    private func record(_ message: String) {
        // Only fixed messages; no coordinates, search queries, device IDs, or imported keys.
        events.append("\(Date.now.formatted(date: .omitted, time: .standard))  \(message)")
        if events.count > 80 { events.removeFirst(events.count - 80) }
        persistDiagnostics()
    }

    private func observeNetworkPath() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let state: String
            switch path.status {
            case .satisfied: state = "satisfied"
            case .unsatisfied: state = "unsatisfied"
            case .requiresConnection: state = "requires connection"
            @unknown default: state = "unknown"
            }
            let kinds: [(NWInterface.InterfaceType, String)] = [
                (.wifi, "Wi-Fi"), (.cellular, "cellular"), (.wiredEthernet, "wired"),
                (.loopback, "loopback"), (.other, "other")
            ]
            let used = kinds.compactMap { path.usesInterfaceType($0.0) ? $0.1 : nil }
            let available = kinds.compactMap { kind, label in
                path.availableInterfaces.contains { $0.type == kind } ? label : nil
            }
            // Interface classes only: never names, addresses, SSIDs, or device identifiers.
            // NWPathMonitor describes the system path, not the individual VPN socket route.
            let summary = "System path: \(state); uses \(used.isEmpty ? "none" : used.joined(separator: "/")); available \(available.isEmpty ? "none" : available.joined(separator: "/"))."
            Task { @MainActor [weak self] in
                guard let self, self.networkPathSummary != summary else { return }
                self.networkPathSummary = summary
                self.record(summary)
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "app.gps.reconstruction.network-diagnostics"))
    }

    private func persistDiagnostics() {
        guard !writingDiagnostics else { return }
        diagnosticsWriter.schedule(Data(diagnosticText.utf8))
    }

    private func withBackgroundTime(name: String, operation: () async -> Void) async {
        var identifier = UIBackgroundTaskIdentifier.invalid
        identifier = UIApplication.shared.beginBackgroundTask(withName: name) {
            if identifier != .invalid {
                UIApplication.shared.endBackgroundTask(identifier)
                identifier = .invalid
            }
        }
        await operation()
        if identifier != .invalid { UIApplication.shared.endBackgroundTask(identifier) }
    }
}
