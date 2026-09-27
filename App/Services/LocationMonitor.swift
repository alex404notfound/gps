import CoreLocation
import Foundation

/// Keeps Core Location active only for a user-started location session. Samples
/// are inspected in memory; coordinates are never retained or exported.
@MainActor
final class LocationMonitor: NSObject, @preconcurrency CLLocationManagerDelegate {
    enum Source: Equatable {
        case simulated, nonSimulated, unknown
    }

    enum Event {
        case permissionRequested
        case permissionDenied
        case servicesUnavailable
        case waitingForForeground
        case monitoringStarted(backgroundEnabled: Bool)
        case monitoringStopped
        case sourceChanged(Source)
        case resetAwaitingSample
        case freshNonSimulatedAfterReset(milliseconds: UInt64)
        case resetTimedOut
        case resetVerificationUnavailable
        case monitoringFailed
    }

    var onEvent: ((Event) -> Void)?

    private let manager = CLLocationManager()
    private var policy = LocationMonitoringPolicy()
    private var requested: Bool { policy.mode != .idle }
    private var updating = false
    private var sceneActive = true
    private var permissionPromptRequested = false
    private var lastSource: Source?
    private var resetSentAt: Date?
    private var resetStartedAt: UInt64?
    private var resetGeneration: UInt64 = 0
    private var resetTimeout: Task<Void, Never>?

    override init() {
        super.init()
        manager.delegate = self
        // Keep the session eligible for background delivery. Automatic pauses
        // end When In Use access; reduce sampling cost instead of pausing it.
        manager.pausesLocationUpdatesAutomatically = false
        manager.showsBackgroundLocationIndicator = true
        NotificationCenter.default.addObserver(self, selector: #selector(powerStateChanged),
                                               name: .NSProcessInfoPowerStateDidChange, object: nil)
    }

    deinit { NotificationCenter.default.removeObserver(self) }

    func beginAppliedSession() {
        cancelResetVerification()
        policy.mode = .applied
        updateSamplingPolicy()
        activateIfPermitted()
    }

    func beginResetVerification() {
        policy.mode = .resetVerification
        updateSamplingPolicy()
        activateIfPermitted()
        guard updating else {
            onEvent?(.resetVerificationUnavailable)
            stop()
            return
        }

        cancelResetVerification()
        resetSentAt = Date()
        resetStartedAt = DispatchTime.now().uptimeNanoseconds
        resetGeneration &+= 1
        let generation = resetGeneration
        onEvent?(.resetAwaitingSample)
        resetTimeout = Task { [weak self] in
            try? await Task.sleep(for: .seconds(15))
            guard !Task.isCancelled else { return }
            self?.timeOutReset(generation: generation)
        }
    }

    func sceneBecameActive() {
        sceneActive = true
        policy.isBackground = false
        updateSamplingPolicy()
        if requested && !updating { activateIfPermitted() }
    }

    func sceneEnteredBackground() {
        sceneActive = false
        policy.isBackground = true
        updateSamplingPolicy()
    }

    func sceneBecameInactive() {
        sceneActive = false
    }

    func stop() {
        let wasRequested = requested || updating
        policy.mode = .idle
        cancelResetVerification()
        lastSource = nil
        if updating {
            manager.stopUpdatingLocation()
            manager.allowsBackgroundLocationUpdates = false
            updating = false
        }
        if wasRequested { onEvent?(.monitoringStopped) }
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        guard requested else { return }
        if manager.authorizationStatus != .notDetermined { permissionPromptRequested = false }
        if manager.authorizationStatus == .denied || manager.authorizationStatus == .restricted {
            onEvent?(.permissionDenied)
            if resetSentAt != nil { onEvent?(.resetVerificationUnavailable) }
            stop()
            return
        }
        activateIfPermitted()
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard requested else { return }
        let observedAt = Date()
        for location in locations {
            let accuracy = location.horizontalAccuracy
            guard accuracy.isFinite, accuracy >= 0,
                  location.timestamp > observedAt.addingTimeInterval(-30),
                  location.timestamp <= observedAt.addingTimeInterval(2) else { continue }

            let source: Source
            switch location.sourceInformation?.isSimulatedBySoftware {
            case .some(true): source = .simulated
            case .some(false): source = .nonSimulated
            case .none: source = .unknown
            }
            if source != lastSource {
                lastSource = source
                onEvent?(.sourceChanged(source))
            }

            if let resetSentAt, let resetStartedAt,
               ResetReadback.isFreshNonSimulated(
                sampleTime: location.timestamp,
                horizontalAccuracy: accuracy,
                sourceIsSimulated: location.sourceInformation?.isSimulatedBySoftware,
                resetSentAt: resetSentAt,
                observedAt: observedAt
               ) {
                let elapsed = (DispatchTime.now().uptimeNanoseconds &- resetStartedAt) / 1_000_000
                onEvent?(.freshNonSimulatedAfterReset(milliseconds: elapsed))
                stop()
                return
            }
        }
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        if let locationError = error as? CLError, locationError.code == .locationUnknown { return }
        guard requested else { return }
        onEvent?(.monitoringFailed)
        if resetSentAt != nil { onEvent?(.resetVerificationUnavailable) }
        stop()
    }

    private func activateIfPermitted() {
        guard requested, !updating else { return }
        guard CLLocationManager.locationServicesEnabled() else {
            onEvent?(.servicesUnavailable)
            return
        }
        switch manager.authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse:
            guard sceneActive else {
                onEvent?(.waitingForForeground)
                return
            }
            // iOS terminates apps that set this flag without the Info.plist mode.
            let hasBackgroundMode = (Bundle.main.infoDictionary?["UIBackgroundModes"] as? [String])?.contains("location") == true
            manager.allowsBackgroundLocationUpdates = hasBackgroundMode
            manager.startUpdatingLocation()
            updating = true
            onEvent?(.monitoringStarted(backgroundEnabled: hasBackgroundMode))
        case .notDetermined:
            if !permissionPromptRequested && sceneActive {
                permissionPromptRequested = true
                manager.requestWhenInUseAuthorization()
                onEvent?(.permissionRequested)
            }
        case .restricted, .denied:
            onEvent?(.permissionDenied)
        @unknown default:
            onEvent?(.servicesUnavailable)
        }
    }

    @objc nonisolated private func powerStateChanged() {
        Task { @MainActor [weak self] in self?.updateSamplingPolicy() }
    }

    private func updateSamplingPolicy() {
        policy.isLowPowerMode = ProcessInfo.processInfo.isLowPowerModeEnabled
        guard let sampling = policy.sampling else { return }
        let accuracy: CLLocationAccuracy
        switch sampling.accuracy {
        case .hundredMeters: accuracy = kCLLocationAccuracyHundredMeters
        case .kilometer: accuracy = kCLLocationAccuracyKilometer
        case .threeKilometers: accuracy = kCLLocationAccuracyThreeKilometers
        }
        let distance = sampling.minimumMovement ?? kCLDistanceFilterNone
        if manager.desiredAccuracy != accuracy { manager.desiredAccuracy = accuracy }
        if manager.distanceFilter != distance { manager.distanceFilter = distance }
    }

    private func cancelResetVerification() {
        resetTimeout?.cancel()
        resetTimeout = nil
        resetSentAt = nil
        resetStartedAt = nil
    }

    private func timeOutReset(generation: UInt64) {
        guard generation == resetGeneration, resetSentAt != nil else { return }
        onEvent?(.resetTimedOut)
        stop()
    }
}
