import Foundation
import Testing
@testable import GPSCore

@Test func resetReadbackRequiresFreshAccurateKnownSource() {
    let sentAt = Date(timeIntervalSince1970: 1_000)
    let observedAt = sentAt.addingTimeInterval(3)
    let fresh = sentAt.addingTimeInterval(1)
    #expect(ResetReadback.isFreshNonSimulated(sampleTime: fresh, horizontalAccuracy: 25,
        sourceIsSimulated: false, resetSentAt: sentAt, observedAt: observedAt))
    for source in [Optional<Bool>.none, .some(true)] {
        #expect(!ResetReadback.isFreshNonSimulated(sampleTime: fresh, horizontalAccuracy: 25,
            sourceIsSimulated: source, resetSentAt: sentAt, observedAt: observedAt))
    }
    for time in [sentAt.addingTimeInterval(-1), sentAt, observedAt.addingTimeInterval(3)] {
        #expect(!ResetReadback.isFreshNonSimulated(sampleTime: time, horizontalAccuracy: 25,
            sourceIsSimulated: false, resetSentAt: sentAt, observedAt: observedAt))
    }
    #expect(!ResetReadback.isFreshNonSimulated(sampleTime: fresh, horizontalAccuracy: 25,
        sourceIsSimulated: false, resetSentAt: sentAt, observedAt: sentAt.addingTimeInterval(10)))
    for accuracy in [-1, .infinity, 1_001] {
        #expect(!ResetReadback.isFreshNonSimulated(sampleTime: fresh, horizontalAccuracy: accuracy,
            sourceIsSimulated: false, resetSentAt: sentAt, observedAt: observedAt))
    }
}

@Test func coordinateBoundsAndNonfiniteValues() throws {
    for coordinate in [Coordinate(latitude: -90, longitude: -180), Coordinate(latitude: 90, longitude: 180),
                       Coordinate(latitude: 0, longitude: 0)] {
        #expect(try coordinate.validated() == coordinate)
    }
    for coordinate in [Coordinate(latitude: 90.001, longitude: 0), Coordinate(latitude: 0, longitude: -180.001),
                       Coordinate(latitude: .nan, longitude: 0), Coordinate(latitude: 0, longitude: .infinity)] {
        #expect(throws: GPSError.invalidCoordinate) { try coordinate.validated() }
    }
}

@Test func setupRejectsMissingPinMalformedIdentityAndRemoteDestination() throws {
    let valid = setupFixture()
    #expect(try SetupConfiguration.decode(valid.encoded()) == valid)
    var noPin = valid
    noPin.pairing.peerPublicKey = ""
    #expect(throws: GPSError.self) { try noPin.validated() }
    var missingPeer = valid
    missingPeer.pairing.peerIdentifier = ""
    #expect(throws: GPSError.self) { try missingPeer.validated() }
    var publicHost = valid
    publicHost.transport.host = "8.8.8.8"
    #expect(throws: GPSError.self) { try publicHost.validated() }
    publicHost.transport.host = "attacker.example"
    #expect(throws: GPSError.self) { try publicHost.validated() }
    #expect(throws: GPSError.self) { try SetupConfiguration.decode(Data(repeating: 32, count: 65_537)) }
    #expect(throws: GPSError.self) { try SetupConfiguration.decode(Data("{}".utf8)) }
    var unsupported = valid
    unsupported.version = 2
    #expect(throws: GPSError.self) { try unsupported.validated() }
}

@Test func disconnectedOrInvalidCommandsNeverReachTransport() async throws {
    let transport = TestTransport()
    let session = LocationSession(transport: transport)
    await #expect(throws: GPSError.notConnected) { try await session.apply(Coordinate(latitude: 1, longitude: 2)) }
    try await session.connect(configuration: setupFixture())
    await #expect(throws: GPSError.invalidCoordinate) { try await session.apply(Coordinate(latitude: 100, longitude: 0)) }
    let count = await transport.setCalls
    #expect(count == 0)
}

@Test func setupAcceptsOnlyWellFormedLocalAddressLiterals() throws {
    for host in ["10.7.1.1", "192.168.0.1", "172.16.0.2", "127.0.0.1", "::1", "fd00::1", "fe80::1"] {
        var setup = setupFixture()
        setup.transport.host = host
        #expect(try setup.validated() == setup)
    }
    for host in ["fd::::1", "fc:1", "fe80:invalid", "2001:4860:4860::8888", "10.7.1.1/32", "10.7.1.1\u{0000}.example", "010.0.0.1", "+10.0.0.1"] {
        var setup = setupFixture()
        setup.transport.host = host
        #expect(throws: GPSError.self) { try setup.validated() }
    }
}

@Test func optionalMinimizedLockdownRecordSurvivesRoundTripAndAddressChange() throws {
    let legacy = setupFixture()
    #expect(legacy.lockdown == nil)
    #expect(try SetupConfiguration.decode(legacy.encoded()).lockdown == nil)

    var setup = legacy
    setup.lockdown = .init(pairingRecord: try lockdownFixture())
    #expect(try SetupConfiguration.decode(setup.encoded()) == setup)
    let originalRecord = setup.lockdown?.pairingRecord
    setup.transport.host = "10.7.1.1"
    let edited = try SetupConfiguration.decode(setup.encoded())
    #expect(edited.transport.host == "10.7.1.1")
    #expect(edited.lockdown?.pairingRecord == originalRecord)
}

@Test func minimizedLockdownRecordRejectsWrongIdentityMissingFieldsAndExtraSecrets() throws {
    var setup = setupFixture()
    let invalidRecords = try [
        lockdownFixture { $0["UDID"] = "other-device" },
        lockdownFixture { $0.removeValue(forKey: "HostPrivateKey") },
        lockdownFixture { $0["DeviceCertificate"] = Data() },
        lockdownFixture { $0["HostID"] = "  " },
        lockdownFixture { $0["SystemBUID"] = "" },
        lockdownFixture { $0["RootPrivateKey"] = Data([1]) },
        lockdownFixture { $0.removeValue(forKey: "RootPrivateKey") },
        lockdownFixture { $0.removeValue(forKey: "WiFiMACAddress") },
        lockdownFixture { $0["EscrowBag"] = Data([1]) }
    ]
    for record in invalidRecords {
        setup.lockdown = .init(pairingRecord: record)
        #expect(throws: GPSError.self) { try setup.validated() }
    }
}

@Test func minimizedLockdownRecordRejectsMalformedAndOversizedData() throws {
    var setup = setupFixture()
    for record in ["not base64", Data([0xAA]).base64EncodedString(),
                   Data(repeating: 0xAA, count: 32_769).base64EncodedString()] {
        setup.lockdown = .init(pairingRecord: record)
        #expect(throws: GPSError.self) { try setup.validated() }
    }
}

@Test func failedApplyIsNeverReportedAsAccepted() async throws {
    let transport = TestTransport()
    let session = LocationSession(transport: transport)
    try await session.connect(configuration: setupFixture())
    await transport.failNextSet()
    await #expect(throws: GPSError.transport("Test connection interrupted")) {
        try await session.apply(Coordinate(latitude: 1, longitude: 2))
    }
    let snapshot = await session.snapshot()
    #expect(snapshot.lastApplied == nil)
    #expect(!snapshot.connection.isConnected)
    #expect(snapshot.notice?.contains("not confirmed") == true)
}

@Test func resetOnlyClearsAcceptedLocationAfterSuccessfulSend() async throws {
    let transport = TestTransport()
    let session = LocationSession(transport: transport)
    let coordinate = Coordinate(latitude: 1, longitude: 2)
    try await session.connect(configuration: setupFixture())
    try await session.apply(coordinate)
    await transport.failNextReset()
    await #expect(throws: GPSError.transport("Test reset interrupted")) { try await session.reset() }
    let failed = await session.snapshot()
    #expect(failed.lastApplied == coordinate)
    #expect(!failed.connection.isConnected)
    try await session.connect(configuration: setupFixture())
    try await session.reset()
    let succeeded = await session.snapshot()
    #expect(succeeded.lastApplied == nil)
    #expect(succeeded.connection.isConnected)
}

@Test func concurrentResetCannotOvertakePendingApply() async throws {
    let transport = TestTransport()
    let session = LocationSession(transport: transport)
    try await session.connect(configuration: setupFixture())
    await transport.holdNextSet()
    let coordinate = Coordinate(latitude: 10, longitude: 20)
    let apply = Task { try await session.apply(coordinate) }
    await transport.waitForHeldSet()
    let pending = await session.snapshot()
    #expect(pending.lastApplied == nil)
    #expect(pending.operation == .applying)
    await #expect(throws: GPSError.busy) { try await session.reset() }
    let resets = await transport.resetCalls
    #expect(resets == 0)
    await transport.releaseSet()
    try await apply.value
    let completed = await session.snapshot()
    #expect(completed.lastApplied == coordinate)
}

@Test func disconnectDoesNotPretendToResetDevice() async throws {
    let transport = TestTransport()
    let session = LocationSession(transport: transport)
    let coordinate = Coordinate(latitude: 1, longitude: 2)
    try await session.connect(configuration: setupFixture())
    try await session.apply(coordinate)
    try await session.disconnect()
    let state = await session.snapshot()
    #expect(state.lastApplied == coordinate)
    #expect(state.connection == .disconnected)
    let resets = await transport.resetCalls
    #expect(resets == 0)
}

private func setupFixture() -> SetupConfiguration {
    SetupConfiguration(createdAt: "2026-09-25T00:00:00Z",
        device: .init(identifier: "test-device", name: "Test iPhone"),
        transport: .init(host: "10.7.0.1", port: 49_152),
        pairing: .init(identifier: "test-host", privateKey: Data(repeating: 1, count: 32).base64EncodedString(),
                       publicKey: Data(repeating: 2, count: 32).base64EncodedString(),
                       peerIdentifier: "test-peer-account", peerPublicKey: Data(repeating: 3, count: 32).base64EncodedString()))
}

private func lockdownFixture(_ edit: (inout [String: Any]) -> Void = { _ in }) throws -> String {
    var record: [String: Any] = [
        "UDID": "test-device",
        "DeviceCertificate": Data([1]),
        "HostCertificate": Data([2]),
        "HostPrivateKey": Data([3]),
        "RootCertificate": Data([4]),
        "HostID": "test-host",
        "SystemBUID": "test-system",
        "RootPrivateKey": Data(),
        "WiFiMACAddress": ""
    ]
    edit(&record)
    return try PropertyListSerialization.data(fromPropertyList: record, format: .binary, options: 0)
        .base64EncodedString()
}

private actor TestTransport: LocationTransport {
    var setCalls = 0
    var resetCalls = 0
    private var rejectSet = false
    private var rejectReset = false
    private var shouldHold = false
    private var setContinuation: CheckedContinuation<Void, Never>?
    private var enteredContinuation: CheckedContinuation<Void, Never>?

    func connect(configuration: SetupConfiguration) async throws { }
    func disconnect() async { }
    func failNextSet() { rejectSet = true }
    func failNextReset() { rejectReset = true }
    func holdNextSet() { shouldHold = true }

    func setLocation(_ coordinate: Coordinate) async throws {
        setCalls += 1
        if rejectSet { rejectSet = false; throw GPSError.transport("Test connection interrupted") }
        if shouldHold {
            shouldHold = false
            await withCheckedContinuation { continuation in
                setContinuation = continuation
                enteredContinuation?.resume()
                enteredContinuation = nil
            }
        }
    }

    func resetLocation() async throws {
        resetCalls += 1
        if rejectReset { rejectReset = false; throw GPSError.transport("Test reset interrupted") }
    }

    func waitForHeldSet() async {
        if setContinuation != nil { return }
        await withCheckedContinuation { enteredContinuation = $0 }
    }

    func releaseSet() {
        setContinuation?.resume()
        setContinuation = nil
    }
}
