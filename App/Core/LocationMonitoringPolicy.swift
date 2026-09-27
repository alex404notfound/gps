/// Sampling for source monitoring is deliberately coarse. Reset verification
/// temporarily requests a fresh, more accurate sample, even in Low Power Mode.
struct LocationMonitoringPolicy {
    enum Mode: Equatable { case idle, applied, resetVerification }
    enum Accuracy: Equatable { case hundredMeters, kilometer, threeKilometers }
    struct Sampling: Equatable {
        let accuracy: Accuracy
        /// nil requests every available sample during the bounded reset check.
        let minimumMovement: Double?
    }

    var mode: Mode = .idle
    var isBackground = false
    var isLowPowerMode = false

    var sampling: Sampling? {
        switch mode {
        case .idle:
            return nil
        case .resetVerification:
            return Sampling(accuracy: .hundredMeters, minimumMovement: nil)
        case .applied:
            if isBackground || isLowPowerMode {
                return Sampling(accuracy: .threeKilometers, minimumMovement: 1_000)
            }
            return Sampling(accuracy: .kilometer, minimumMovement: 100)
        }
    }
}
