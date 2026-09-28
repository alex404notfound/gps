import SwiftUI

@main
struct GPSApp: App {
    @State private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    init() {
        RenewalScheduler.register()
        RenewalScheduler.schedule()
        GPSRenewalShortcuts.updateAppShortcutParameters()
    }

    var body: some Scene {
        WindowGroup {
            TabView {
                LocationView()
                    .tabItem { Label("Location", systemImage: "location.fill") }
                    .tag(0)
                AppAccessView()
                    .tabItem { Label("App Access", systemImage: "key.horizontal") }
                    .tag(1)
            }
            .tint(.blue)
            .environment(model)
            .task {
                await model.importPendingSetupIfPresent()
                #if DEBUG
                if ProcessInfo.processInfo.arguments.contains("--restore-default-vpn-address") {
                    await model.updateConnectionAddress("10.7.0.1")
                }
                #endif
            }
            .onChange(of: scenePhase, initial: true) { _, phase in
                switch phase {
                case .active:
                    model.recordSceneActive()
                    model.refreshAfterForeground()
                case .background:
                    model.recordSceneBackground()
                case .inactive:
                    model.recordSceneInactive()
                default:
                    break
                }
            }
        }
    }
}
