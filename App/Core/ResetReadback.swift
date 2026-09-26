import Foundation

/// A post-reset Core Location sample is evidence about what iOS reported,
/// never proof of the phone's physical position.
public enum ResetReadback {
    public static func isFreshNonSimulated(
        sampleTime: Date,
        horizontalAccuracy: Double,
        sourceIsSimulated: Bool?,
        resetSentAt: Date,
        observedAt: Date
    ) -> Bool {
        guard sourceIsSimulated == false,
              horizontalAccuracy.isFinite,
              (0...1_000).contains(horizontalAccuracy),
              sampleTime > resetSentAt,
              sampleTime >= observedAt.addingTimeInterval(-5),
              sampleTime <= observedAt.addingTimeInterval(2) else { return false }
        return true
    }
}
