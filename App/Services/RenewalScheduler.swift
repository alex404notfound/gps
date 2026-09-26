import BackgroundTasks
import UserNotifications

enum RenewalScheduler {
    static let identifier = "app.gps.reconstruction.signing-refresh"

    static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { task in
            let lifetime = RenewalBackgroundLifetime(task)
            lifetime.setExpirationHandler()
            let work = Task { @MainActor in
                let success = await RenewalModel.shared.runAutomatically(throttle: false)
                schedule()
                lifetime.complete(success: success && !Task.isCancelled)
            }
            lifetime.attach(work)
        }
    }

    static func schedule() {
        guard UserDefaults.standard.bool(forKey: "signingRefresh.enabled") else { return }
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 12 * 3600)
        // A daily Shortcut is the user-controlled trigger; iOS chooses BGTask delivery.
        try? BGTaskScheduler.shared.submit(request)
    }

    static func cancel() {
        BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: identifier)
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [identifier])
    }

    static func requestNotifications() async {
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
    }

    static func notifyFailure() async {
        let content = UNMutableNotificationContent()
        content.title = "GPS needs a signing refresh"
        content.body = "Open GPS → App Access before its profile expires. Check your Apple sign-in and LocalDevVPN."
        content.sound = .default
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
        try? await UNUserNotificationCenter.current().add(request)
    }
}

/// BGTask is an Objective-C callback handle. Protect cancellation and its single
/// completion while renewal work itself stays isolated to the main actor.
private final class RenewalBackgroundLifetime: @unchecked Sendable {
    private let task: BGTask
    private let lock = NSLock()
    private var work: Task<Void, Never>?
    private var expired = false
    private var finished = false

    init(_ task: BGTask) { self.task = task }

    func setExpirationHandler() {
        task.expirationHandler = { [weak self] in self?.expire() }
    }

    func attach(_ work: Task<Void, Never>) {
        lock.lock()
        self.work = work
        let shouldCancel = expired
        lock.unlock()
        if shouldCancel { work.cancel() }
    }

    private func expire() {
        lock.lock()
        expired = true
        let work = work
        lock.unlock()
        work?.cancel()
        complete(success: false)
    }

    func complete(success: Bool) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        work = nil
        lock.unlock()
        task.setTaskCompleted(success: success)
    }
}
