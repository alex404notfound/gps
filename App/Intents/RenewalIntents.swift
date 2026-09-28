import AppIntents

struct NeedsGPSRefreshIntent: AppIntent {
    static let title: LocalizedStringResource = "GPS signing refresh needed"
    static let description = IntentDescription("Return whether automatic GPS renewal is enabled and the current profile expires within three days. Use this before changing network settings in an automation.")
    static let openAppWhenRun = false
    static let authenticationPolicy: IntentAuthenticationPolicy = .alwaysAllowed

    @MainActor func perform() async -> some IntentResult & ReturnsValue<Bool> {
        .result(value: RenewalModel.shared.needsAutomaticRefresh)
    }
}

struct RefreshGPSAppIntent: AppIntent {
    static let title: LocalizedStringResource = "Refresh GPS signing"
    static let description = IntentDescription("Renew GPS before its seven-day profile expires. Requires Apple sign-in, internet access, and LocalDevVPN.")
    static let openAppWhenRun = false
    static let authenticationPolicy: IntentAuthenticationPolicy = .alwaysAllowed

    @MainActor func perform() async throws -> some IntentResult & ProvidesDialog {
        guard RenewalModel.shared.enabled else { throw RenewalOperationError.disabled }
        let result = try await RenewalModel.shared.refresh(force: false)
        return .result(dialog: "\(result)")
    }
}

struct PrepareGPSRefreshIntent: AppIntent {
    static let title: LocalizedStringResource = "Prepare GPS signing refresh"
    static let description = IntentDescription("Download GPS's new profile while internet access is available. Use Install prepared GPS refresh after switching cellular off if the local VPN needs it.")
    static let openAppWhenRun = false
    static let authenticationPolicy: IntentAuthenticationPolicy = .alwaysAllowed

    @MainActor func perform() async throws -> some IntentResult & ProvidesDialog {
        guard RenewalModel.shared.enabled else { throw RenewalOperationError.disabled }
        let result = try await RenewalModel.shared.prepareOnly()
        return .result(dialog: "\(result)")
    }
}

struct InstallGPSRefreshIntent: AppIntent {
    static let title: LocalizedStringResource = "Install prepared GPS refresh"
    static let description = IntentDescription("Install and verify the previously prepared GPS profile through LocalDevVPN. This step does not need internet access or change location.")
    static let openAppWhenRun = false
    static let authenticationPolicy: IntentAuthenticationPolicy = .alwaysAllowed

    @MainActor func perform() async -> some IntentResult & ReturnsValue<Bool> & ProvidesDialog {
        // Report operational failure as a value so the next Shortcut action can
        // restore Cellular Data. Throwing would abort that cleanup action.
        do {
            guard RenewalModel.shared.enabled else { throw RenewalOperationError.disabled }
            let result = try await RenewalModel.shared.installPrepared()
            return .result(value: true, dialog: "\(result)")
        } catch {
            return .result(value: false, dialog: "GPS refresh failed: \(error.localizedDescription)")
        }
    }
}

struct GPSRenewalShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: NeedsGPSRefreshIntent(), phrases: ["Check \(.applicationName) signing"],
                    shortTitle: "Refresh needed", systemImageName: "calendar.badge.clock")
        AppShortcut(intent: RefreshGPSAppIntent(), phrases: ["Refresh \(.applicationName) signing"],
                    shortTitle: "Refresh signing", systemImageName: "arrow.clockwise.circle")
        AppShortcut(intent: PrepareGPSRefreshIntent(), phrases: ["Prepare \(.applicationName) refresh"],
                    shortTitle: "Prepare refresh", systemImageName: "arrow.down.doc")
        AppShortcut(intent: InstallGPSRefreshIntent(), phrases: ["Install \(.applicationName) refresh"],
                    shortTitle: "Install refresh", systemImageName: "checkmark.shield")
    }
}
