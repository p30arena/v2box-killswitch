import Foundation
import SystemConfiguration
import Darwin

// Start-only user-session convenience. No subprocess, stop, PF or root API.
// Budget resets ONLY on an explicit new opt-in, never on Connected/status churn.
enum UserVPNStatus { case disconnected, connected, connecting, disconnecting, unknown }

struct StartOnlyReconnect {
    private(set) var attempts = 0
    private(set) var nextDue: TimeInterval = 0
    private var service: String?
    private var targetChanged = false
    private var lastTime: TimeInterval = 0
    private var transitionSince: TimeInterval?
    private(set) var message = "Auto-reconnect: waiting"

    mutating func step(now: TimeInterval, serviceID: String?, allowed: Bool, vpn: UserVPNStatus) -> Bool {
        guard now.isFinite, now >= lastTime else { message = "Auto-reconnect: paused — clock unavailable"; return false }
        lastTime = now
        guard allowed, let id = serviceID, id.count == 36, UUID(uuidString: id) != nil else {
            transitionSince = nil
            message = "Auto-reconnect: paused — protection not verified"; return false
        }
        let canonical = id.uppercased()
        if service == nil { service = canonical }
        guard service == canonical, !targetChanged else {
            targetChanged = true
            message = "Auto-reconnect: paused — VPN changed; toggle off/on"; return false
        }
        switch vpn {
        case .connected:
            transitionSince = nil
            message = "Auto-reconnect: watching (internet unverified)"; return false
        case .connecting, .disconnecting:
            if transitionSince == nil { transitionSince = now }
            message = now - transitionSince! >= 30
                ? "Auto-reconnect: paused — VPN transition stalled"
                : "Auto-reconnect: waiting for VPN"
            return false
        case .unknown:
            transitionSince = nil
            message = "Auto-reconnect: paused — VPN status unknown"; return false
        case .disconnected: transitionSince = nil
        }
        guard attempts < 5 else {
            message = "Auto-reconnect: paused — 5 attempts; toggle off/on"; return false
        }
        guard now >= nextDue else { message = "Auto-reconnect: waiting before retry"; return false }
        attempts += 1
        nextDue = now + [5.0, 10, 20, 40, 60][attempts - 1]
        message = "Auto-reconnect: start requested (\(attempts)/5)"
        return true
    }

    mutating func requestFailed() { message = "Auto-reconnect: start rejected (\(attempts)/5)" }
}

protocol UserVPNStarting {
    func status(_ service: String) -> UserVPNStatus
    func start(_ service: String) -> Bool
}

final class NativeUserVPN: UserVPNStarting {
    private func connection(_ service: String) -> SCNetworkConnection? {
        var uid: uid_t = 0, gid: gid_t = 0
        guard getuid() != 0, getuid() == geteuid(),
              SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) != nil, uid == geteuid(),
              service.count == 36, UUID(uuidString: service) != nil else { return nil }
        return SCNetworkConnectionCreateWithServiceID(nil, service as CFString, nil, nil)
    }
    func status(_ service: String) -> UserVPNStatus {
        guard let c = connection(service) else { return .unknown }
        switch SCNetworkConnectionGetStatus(c) {
        case .disconnected: return .disconnected
        case .connected: return .connected
        case .connecting: return .connecting
        case .disconnecting: return .disconnecting
        default: return .unknown
        }
    }
    func start(_ service: String) -> Bool {
        guard let c = connection(service), SCNetworkConnectionGetStatus(c) == .disconnected else { return false }
        // No options/profile override. Linger prevents quitting this app from
        // deliberately stopping an established VPN. TRUE means submitted, not usable.
        return SCNetworkConnectionStart(c, nil, true)
    }
}

final class AppAutoReconnect {
    private let queue = DispatchQueue(label: "org.v2boxkillswitch.user-connect")
    private let lock = NSLock()
    private let driver: UserVPNStarting
    private let publish: (String) -> Void
    private var enabled = false
    private var generation = 0
    private var observation = 0
    private var busy = false
    private var workerGeneration = -1
    private var policy = StartOnlyReconnect()

    init(driver: UserVPNStarting = NativeUserVPN(), publish: @escaping (String) -> Void) {
        self.driver = driver; self.publish = publish
    }
    func setEnabled(_ value: Bool) {
        lock.lock(); enabled = value; generation += 1; lock.unlock()
        publish(value ? "Auto-reconnect: waiting" : "Auto-reconnect: Off (this launch)")
    }
    private func current(_ version: Int, _ revision: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return enabled && generation == version && observation == revision
    }
    func observe(_ status: [String: String], receivedAt: TimeInterval = ProcessInfo.processInfo.systemUptime) {
        lock.lock()
        observation += 1 // Newer helper evidence revokes in-flight old decisions.
        let revision = observation
        guard enabled, !busy else { lock.unlock(); return }
        busy = true; let version = generation
        lock.unlock()
        queue.async { [self] in
            defer { lock.lock(); busy = false; lock.unlock() }
            guard current(version, revision) else { return }
            if workerGeneration != version { policy = StartOnlyReconnect(); workerGeneration = version }
            func fresh() -> Bool {
                let age = ProcessInfo.processInfo.systemUptime - receivedAt
                return age.isFinite && age >= 0 && age <= 3 && current(version, revision)
            }
            guard fresh() else { return }
            let allowed = status["state"] == "on" && status["policy_mode"] == "approved"
                && status["can_auto_connect"] == "true"
            let id = status["auto_connect_service_uuid"]
            let vpn: UserVPNStatus = allowed && id != nil ? driver.status(id!) : .unknown
            guard fresh() else { return }
            if policy.step(now: ProcessInfo.processInfo.systemUptime, serviceID: id, allowed: allowed, vpn: vpn),
               fresh(), let id {
                // This is not an atomic lease against a concurrent Disable.
                // A dispatched request may finish afterward; it cannot change PF.
                if !driver.start(id) { policy.requestFailed() }
            }
            let text = policy.message
            DispatchQueue.main.async { [self] in if current(version, revision) { publish(text) } }
        }
    }
}
