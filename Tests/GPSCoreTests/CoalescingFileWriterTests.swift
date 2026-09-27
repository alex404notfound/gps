import Foundation
import Testing
@testable import GPSCore

private final class WriteLog: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Data] = []
    private var failures = 0

    var snapshots: [Data] { lock.withLock { values } }
    var failureCount: Int { lock.withLock { failures } }

    func append(_ data: Data) { lock.withLock { values.append(data) } }
    func failed() { lock.withLock { failures += 1 } }
}

@Test func diagnosticSnapshotsAreWrittenWithoutAnExplicitFlush() {
    let completed = DispatchSemaphore(value: 0)
    let writer = CoalescingFileWriter(delay: .milliseconds(1), write: { data in
        #expect(data == Data("automatic".utf8))
        #expect(!Thread.isMainThread)
        completed.signal()
    })
    writer.schedule(Data("automatic".utf8))
    #expect(completed.wait(timeout: .now() + .seconds(2)) == .success)
}

@Test func diagnosticBurstsWriteOnlyTheLatestSnapshotOffTheMainThread() async {
    let log = WriteLog()
    let writer = CoalescingFileWriter(delay: .seconds(60), write: { data in
        #expect(!Thread.isMainThread)
        log.append(data)
    })
    for index in 0..<1_000 { writer.schedule(Data("event \(index)".utf8)) }
    await writer.flush()
    #expect(log.snapshots == [Data("event 999".utf8)])

    writer.schedule(Data("event 999".utf8))
    await writer.flush()
    #expect(log.snapshots.count == 1)

    writer.schedule(Data("new event".utf8))
    await writer.flush()
    #expect(log.snapshots.last == Data("new event".utf8))
    #expect(log.snapshots.count == 2)
}

@Test func failedDiagnosticWriteCanRetryTheSameSnapshot() async {
    struct WriteFailure: Error {}
    let log = WriteLog()
    let writer = CoalescingFileWriter(delay: .seconds(60), write: { data in
        log.append(data)
        if log.snapshots.count == 1 { throw WriteFailure() }
    }, onFailure: { log.failed() })
    let data = Data("retry me".utf8)
    writer.schedule(data)
    await writer.flush()
    #expect(log.failureCount == 1)
    writer.schedule(data)
    await writer.flush()
    writer.schedule(data)
    await writer.flush()
    #expect(log.snapshots == [data, data])
    #expect(log.failureCount == 1)
}

@Test func backgroundFlushPersistsTheLatestDiagnosticSnapshot() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("GPSSetup/diagnostics.txt")
    let writer = CoalescingFileWriter(url: url)
    writer.schedule(Data("foreground".utf8))
    writer.schedule(Data("background".utf8))
    await writer.flush()
    #expect(try Data(contentsOf: url) == Data("background".utf8))
}
