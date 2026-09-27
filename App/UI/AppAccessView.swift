import SwiftUI
import UniformTypeIdentifiers

struct AppAccessView: View {
    @Environment(AppModel.self) private var model

    @State private var isImporting = false
    @State private var importError: String?
    @State private var deviceIP = ""
    @State private var isSavingAddress = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    connectionCard
                    instructionsCard
                    setupCard
                    RenewalCard(model: model.renewal)
                    diagnosticsCard
                }
                .padding(.horizontal, 18)
                .padding(.top, 12)
                .padding(.bottom, 32)
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle("App Access")
            .navigationBarTitleDisplayMode(.large)
            .onChange(of: model.configuredHost, initial: true) { _, host in
                deviceIP = host ?? ""
            }
            .fileImporter(
                isPresented: $isImporting,
                allowedContentTypes: [.json]
            ) { result in
                switch result {
                case .success(let url):
                    importError = nil
                    Task { @MainActor in
                        await model.importSetup(from: url)
                    }
                case .failure(let error):
                    importError = error.localizedDescription
                }
            }
        }
    }

    private var connectionCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Connection", systemImage: "network")
                .font(.headline)

            HStack(alignment: .top, spacing: 12) {
                Image(systemName: connectionIcon)
                    .font(.title2)
                    .foregroundStyle(connectionColor)
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.connectionState.title)
                        .font(.headline)
                    Text(connectionDetail)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }

            if model.connectionState.isConnected {
                Button {
                    Task { await model.disconnect() }
                } label: {
                    Label("Disconnect", systemImage: "link.badge.minus")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
            } else {
                Button {
                    Task { await model.connect() }
                } label: {
                    Label(connectTitle, systemImage: "link")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(isConnecting || model.isCheckingCellularConnection)
            }

            if let statusMessage = model.statusMessage, !statusMessage.isEmpty {
                Text(statusMessage)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
    }

    private var setupCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("iPhone access", systemImage: "key.horizontal")
                .font(.headline)

            Text(model.setupSummary ?? "No GPS setup file imported.")
                .font(.subheadline)
                .foregroundStyle(model.setupSummary == nil ? .secondary : .primary)

            if model.setupSummary != nil {
                Text("Setup is saved securely on this iPhone and restored when GPS opens.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Button {
                isImporting = true
            } label: {
                Label(model.setupSummary == nil ? "Import GPS setup file" : "Replace setup from backup", systemImage: "square.and.arrow.down")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)

            if let importError {
                Label(importError, systemImage: "exclamationmark.circle")
                    .font(.footnote)
                    .foregroundStyle(.red)
            }

            if let host = model.configuredHost {
                Divider()

                Text("Device IP")
                    .font(.subheadline.weight(.semibold))
                Text("Current: \(host)")
                    .font(.subheadline.monospaced())
                    .foregroundStyle(.secondary)
                Text("Enter the Device IP shown by LocalDevVPN. You can paste an address ending in /32.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                TextField("Connection address", text: $deviceIP)
                    .keyboardType(.numbersAndPunctuation)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Device IP address")
                    .disabled(addressEditingDisabled)

                Button {
                    isSavingAddress = true
                    Task { @MainActor in
                        await model.updateConnectionAddress(deviceIP)
                        isSavingAddress = false
                    }
                } label: {
                    Label(isSavingAddress ? "Saving…" : "Save connection address", systemImage: "checkmark.circle")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(addressEditingDisabled)
            }

        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
    }

    private var diagnosticsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Diagnostics", systemImage: "waveform.path.ecg.rectangle")
                    .font(.headline)
                Spacer()
                if !model.diagnosticText.isEmpty {
                    ShareLink(item: model.diagnosticText) {
                        Label("Share", systemImage: "square.and.arrow.up")
                            .font(.subheadline)
                    }
                }
            }

            if model.diagnosticText.isEmpty {
                Text("Connection and command details will appear here.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else {
                Text(model.diagnosticText)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .background(Color(uiColor: .tertiarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12))
            }

        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
    }

    private var instructionsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Connect without Wi-Fi", systemImage: "antenna.radiowaves.left.and.right")
                .font(.headline)

            Text("The working cellular startup sequence for this iPhone:")
                .font(.subheadline).foregroundStyle(.secondary)
            instruction(1, "Keep LocalDevVPN on. Choose a saved place or enter coordinates before turning Cellular Data off.")
            instruction(2, "Turn Cellular Data off briefly, return to GPS, and tap Connect.")
            instruction(3, "In Location, tap Set location for your chosen place while data is still off.")
            instruction(4, "Turn Cellular Data back on. Keep the connection open; Set and Reset work in that session.")
            Text("Repeat after a disconnect or a lost session. Place search needs internet; saved places and coordinate entry work offline. On Wi-Fi, keep LocalDevVPN on and connect normally.")
                .font(.caption).foregroundStyle(.secondary)

            DisclosureGroup("Check a direct cellular connection") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Unplug USB and disconnect GPS. Leave Wi-Fi off and Cellular Data and LocalDevVPN on. This checks the VPN and direct on-device addresses; allow up to 30 seconds. It does not change location.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button(model.isCheckingCellularConnection ? "Checking…" : "Check cellular connection") {
                        Task { await model.checkCellularConnection() }
                    }
                    .disabled(model.isCheckingCellularConnection || isConnecting || model.connectionState.isConnected || model.operationState.isBusy)
                    if let result = model.cellularConnectionCheck {
                        ForEach(model.directConnectionCandidates, id: \.self) { host in
                            Button("Try direct connection (\(host))") {
                                Task { await model.connect(directHost: host) }
                            }
                            .disabled(model.isCheckingCellularConnection || isConnecting || model.connectionState.isConnected || model.operationState.isBusy)
                        }
                        if let directResult = model.directConnectionResult {
                            Text(directResult)
                                .font(.callout)
                                .textSelection(.enabled)
                            ShareLink(item: directResult) {
                                Label("Share direct connection result", systemImage: "square.and.arrow.up")
                            }
                        }
                        Text(result).font(.caption).textSelection(.enabled)
                        ShareLink(item: result) {
                            Label("Share check result", systemImage: "square.and.arrow.up")
                        }
                        .font(.caption)
                    }
                }
                .padding(.top, 8)
            }
            .font(.subheadline)
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
    }

    private func instruction(_ number: Int, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text("\(number)")
                .font(.caption.weight(.bold))
                .foregroundStyle(.tint)
                .frame(width: 22, height: 22)
                .background(Color.accentColor.opacity(0.12), in: Circle())
            Text(text)
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
    }

    private var isConnecting: Bool {
        if case .connecting = model.connectionState { return true }
        return false
    }

    private var addressEditingDisabled: Bool {
        isConnecting || model.operationState.isBusy || isSavingAddress || model.isCheckingCellularConnection
    }

    private var connectTitle: String {
        if isConnecting { return "Connecting…" }
        if case .failed = model.connectionState { return "Try again" }
        return "Connect"
    }

    private var connectionIcon: String {
        switch model.connectionState {
        case .connected: return "checkmark.circle.fill"
        case .connecting: return "arrow.triangle.2.circlepath.circle"
        case .failed: return "exclamationmark.circle.fill"
        case .notConfigured, .disconnected: return "link.circle"
        }
    }

    private var connectionColor: Color {
        switch model.connectionState {
        case .connected: return .green
        case .connecting: return .blue
        case .failed: return .red
        case .notConfigured, .disconnected: return .orange
        }
    }

    private var connectionDetail: String {
        switch model.connectionState {
        case .connected:
            return "Ready to set or reset the reported location."
        case .connecting:
            return "Connecting to the local service. After a restart, preparing developer tools can take a few minutes. Keep this app open."
        case .failed(let reason):
            return reason
        case .notConfigured:
            return "Import the GPS setup file, then connect."
        case .disconnected:
            return "Connect before applying or resetting a location."
        }
    }
}
