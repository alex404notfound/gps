import Foundation

/// Serializes file I/O off the main thread and keeps only the latest snapshot
/// during a burst of updates. Mutable state belongs exclusively to `queue`.
final class CoalescingFileWriter: @unchecked Sendable {
    private let queue = DispatchQueue(label: "app.gps.reconstruction.file-writer", qos: .utility)
    private let delay: DispatchTimeInterval
    private let write: @Sendable (Data) throws -> Void
    private let onFailure: @Sendable () -> Void
    private var pending: Data?
    private var lastWritten: Data?
    private var scheduled = false

    init(delay: DispatchTimeInterval = .milliseconds(200),
         write: @escaping @Sendable (Data) throws -> Void,
         onFailure: @escaping @Sendable () -> Void = {}) {
        self.delay = delay
        self.write = write
        self.onFailure = onFailure
    }

    convenience init(url: URL, onFailure: @escaping @Sendable () -> Void = {}) {
        self.init(write: { data in
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true)
            try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        }, onFailure: onFailure)
    }

    func schedule(_ data: Data) {
        queue.async {
            self.pending = data
            guard !self.scheduled else { return }
            self.scheduled = true
            self.queue.asyncAfter(deadline: .now() + self.delay) {
                self.scheduled = false
                self.writePending()
            }
        }
    }

    /// Waits for all previously submitted snapshots without blocking the caller.
    func flush() async {
        await withCheckedContinuation { continuation in
            queue.async {
                self.writePending()
                continuation.resume()
            }
        }
    }

    private func writePending() {
        guard let data = pending else { return }
        pending = nil
        guard data != lastWritten else { return }
        do {
            try write(data)
            lastWritten = data
        } catch {
            // A later submission of the same snapshot must be allowed to retry.
            onFailure()
        }
    }
}
