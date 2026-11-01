import AppKit
import Foundation
import UserNotifications
import Darwin

// Standalone USER tracker. No helper, PF, routing, kill-switch or privileged API.
final class TrackerMenu: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    private var item: NSStatusItem!
    private let detail = NSMenuItem(title: "Finding V2Box…", action: nil, keyEquivalent: "")
    private let mechanism = NSMenuItem(title: "Detection: starting", action: nil, keyEquivalent: "")
    private let pause = NSMenuItem(title: "Pause automatic reconnect", action: #selector(togglePause), keyEquivalent: "")
    private var paused = UserDefaults.standard.bool(forKey: "paused")
    private let observeOnly = CommandLine.arguments.contains("--observe-only")
    private var lastState: TrackerVPNState?
    private var lastWarning: TimeInterval = -60
    private var activity: NSObjectProtocol?
    private var wakeObserver: NSObjectProtocol?
    private lazy var tracker = NativeTracker(paused: paused, observeOnly: observeOnly) { [weak self] state, message, events in
        self?.update(state, message: message, events: events)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "VPN ?"
        let menu = NSMenu(); menu.autoenablesItems = false
        menu.addItem(NSMenuItem(title: "V2Box Reconnect Tracker — NOT a kill switch", action: nil, keyEquivalent: ""))
        menu.addItem(detail); menu.addItem(mechanism); menu.addItem(.separator())
        pause.target = self; pause.isEnabled = !observeOnly
        pause.title = paused ? "Resume automatic reconnect" : "Pause automatic reconnect"
        menu.addItem(pause)
        let quit = NSMenuItem(title: "Quit tracker (leaves VPN running)", action: #selector(quit), keyEquivalent: "q")
        quit.target = self; menu.addItem(quit)
        item.menu = menu
        let center = UNUserNotificationCenter.current(); center.delegate = self
        // Prevent App Nap from delaying the fallback while awake. This does NOT
        // prevent system sleep or claim to reconnect while hardware is asleep.
        activity = ProcessInfo.processInfo.beginActivity(options: .userInitiatedAllowingIdleSystemSleep,
                                                        reason: "Watch V2Box and reconnect promptly")
        tracker.start()
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didWakeNotification,
                                                                         object: nil, queue: .main) { [weak self] _ in
            self?.tracker.wake()
        }
        // Optional OS notification permission never gates monitoring/reconnection.
        if !observeOnly { center.requestAuthorization(options: [.alert, .sound]) { _, _ in } }
    }
    private func update(_ state: TrackerVPNState, message: String, events: Bool) {
        detail.title = message
        mechanism.title = events ? "Detection: native events + 500 ms fallback" : "Detection: 500 ms polling fallback"
        item.button?.title = state == .connected ? "VPN •" : (state == .disconnected ? "VPN DOWN" : "VPN !")
        item.button?.toolTip = message + " — tracker cannot prevent IP leaks"
        let now = ProcessInfo.processInfo.systemUptime
        if !observeOnly, state != .connected, lastState == .connected, now - lastWarning >= 10 {
            lastWarning = now
            let content = UNMutableNotificationContent()
            content.title = "V2Box connection lost"
            content.body = message + " This tracker does not block traffic."
            content.sound = .default
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "vpn-down", content: content, trigger: nil)) { _ in }
        }
        lastState = state
    }
    @objc private func togglePause() {
        paused.toggle(); UserDefaults.standard.set(paused, forKey: "paused")
        tracker.setPaused(paused)
        pause.title = paused ? "Resume automatic reconnect" : "Pause automatic reconnect"
    }
    @objc private func quit() {
        tracker.setPaused(true)
        if let activity { ProcessInfo.processInfo.endActivity(activity) }
        NSApp.terminate(nil)
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }
}

guard getuid() != 0, getuid() == geteuid() else { exit(1) }
let support = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/V2BoxReconnectTracker")
try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
let instanceLock = open(support.appendingPathComponent("instance.lock").path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0o600)
guard instanceLock >= 0, flock(instanceLock, LOCK_EX | LOCK_NB) == 0 else { exit(0) }
// Keep the descriptor open for the lifetime of this process: only one watcher.
let app = NSApplication.shared
let delegate = TrackerMenu()
app.delegate = delegate
app.run()
