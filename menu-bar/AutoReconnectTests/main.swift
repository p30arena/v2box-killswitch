import Foundation

let id = "00000000-0000-0000-0000-000000000001"
let other = "00000000-0000-0000-0000-000000000002"
func allowed(_ policy: inout StartOnlyReconnect, _ time: Double, _ status: UserVPNStatus = .disconnected) -> Bool {
    return policy.step(now: time, serviceID: id, allowed: true, vpn: status)
}

// Pure model: no SystemConfiguration query or native start is invoked by tests.
var budget = StartOnlyReconnect()
for time in [0.0, 5, 15, 35, 75] { precondition(allowed(&budget, time)) }
precondition(!allowed(&budget, 1000) && budget.attempts == 5)
precondition(!allowed(&budget, 1001, .connected))
precondition(!allowed(&budget, 1002) && budget.attempts == 5) // Connected is NOT health/budget reset.
var backoff = StartOnlyReconnect()
precondition(allowed(&backoff, 10)); precondition(!allowed(&backoff, 14)); precondition(allowed(&backoff, 15))
var changed = StartOnlyReconnect()
precondition(allowed(&changed, 1))
precondition(!changed.step(now: 20, serviceID: other, allowed: true, vpn: .disconnected))
precondition(!allowed(&changed, 30)) // A target change latches until explicit re-opt-in.
var gate = StartOnlyReconnect()
precondition(!gate.step(now: 1, serviceID: id, allowed: false, vpn: .disconnected))
precondition(!gate.step(now: 2, serviceID: nil, allowed: true, vpn: .disconnected))
precondition(!gate.step(now: 3, serviceID: "not a UUID", allowed: true, vpn: .disconnected))
precondition(gate.attempts == 0)
for status: UserVPNStatus in [.connected, .connecting, .disconnecting, .unknown] {
    var policy = StartOnlyReconnect()
    precondition(!allowed(&policy, 1, status) && policy.attempts == 0)
}
var transition = StartOnlyReconnect()
precondition(!allowed(&transition, 1, .connecting)); precondition(!allowed(&transition, 32, .connecting))
precondition(transition.message.contains("stalled") && transition.attempts == 0)
var clock = StartOnlyReconnect()
precondition(allowed(&clock, 10)); precondition(!allowed(&clock, 9)); precondition(!allowed(&clock, .nan))
precondition(clock.attempts == 1)
var failed = StartOnlyReconnect()
precondition(allowed(&failed, 1)); failed.requestFailed(); precondition(failed.attempts == 1)

func pump(_ seconds: Double = 0.1) {
    let until = Date().addingTimeInterval(seconds)
    while Date() < until { RunLoop.current.run(until: Date().addingTimeInterval(0.005)) }
}
final class Driver: UserVPNStarting {
    private let lock = NSLock()
    private var reads = 0, starts = 0
    let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
    var blocking = false
    var counts: (Int, Int) { lock.lock(); defer { lock.unlock() }; return (reads, starts) }
    func status(_ service: String) -> UserVPNStatus {
        lock.lock(); reads += 1; lock.unlock()
        if blocking { entered.signal(); precondition(release.wait(timeout: .now() + 2) == .success) }
        return .disconnected
    }
    func start(_ service: String) -> Bool { lock.lock(); starts += 1; lock.unlock(); return true }
}
let status = ["state": "on", "policy_mode": "approved", "can_auto_connect": "true", "auto_connect_service_uuid": id]
let off = Driver(), manager = AppAutoReconnect(driver: off, publish: { _ in })
manager.observe(status); pump(); precondition(off.counts == (0, 0)) // Defaults Off.
manager.setEnabled(true); manager.observe(status); pump(); precondition(off.counts == (1, 1))
manager.observe(status); pump(); precondition(off.counts == (2, 1)) // No repeated start during backoff.
manager.setEnabled(false); manager.observe(status); pump(); precondition(off.counts == (2, 1))
let blocked = Driver(); blocked.blocking = true
let cancellation = AppAutoReconnect(driver: blocked, publish: { _ in })
cancellation.setEnabled(true); cancellation.observe(status)
precondition(blocked.entered.wait(timeout: .now() + 2) == .success)
let start = ProcessInfo.processInfo.systemUptime
cancellation.setEnabled(false) // Must not wait on the native worker queue.
precondition(ProcessInfo.processInfo.systemUptime - start < 0.1)
blocked.release.signal(); pump(); precondition(blocked.counts == (1, 0))
let revokedDriver = Driver(); revokedDriver.blocking = true
let revoked = AppAutoReconnect(driver: revokedDriver, publish: { _ in })
revoked.setEnabled(true); revoked.observe(status)
precondition(revokedDriver.entered.wait(timeout: .now() + 2) == .success)
revoked.observe([:]) // A newer failed helper response revokes older in-flight evidence.
revokedDriver.release.signal(); pump(); precondition(revokedDriver.counts == (1, 0))
let stale = Driver(), freshness = AppAutoReconnect(driver: stale, publish: { _ in })
freshness.setEnabled(true); freshness.observe(status, receivedAt: ProcessInfo.processInfo.systemUptime - 10)
pump(); precondition(stale.counts == (0, 0))
freshness.observe([:]); pump(); precondition(stale.counts == (0, 0))

let denied = try JSONSerialization.data(withJSONObject: ["can_enable": "false", "can_disable": "false"])
let permitted = try JSONSerialization.data(withJSONObject: ["can_enable": "true"])
precondition(HelperPreflight.allows(enabled: false, authorizationOnly: false, data: denied, message: nil))
precondition(HelperPreflight.allows(enabled: false, authorizationOnly: false, data: nil, message: "Backend unavailable"))
precondition(!HelperPreflight.allows(enabled: true, authorizationOnly: false, data: denied, message: nil))
precondition(HelperPreflight.allows(enabled: true, authorizationOnly: false, data: permitted, message: nil))
precondition(!HelperPreflight.allows(enabled: true, authorizationOnly: false, data: nil, message: "Backend unavailable"))
precondition(!HelperPreflight.allows(enabled: false, authorizationOnly: false, data: nil, message: nil))
precondition(HelperPreflight.allows(enabled: nil, authorizationOnly: true, data: nil, message: "Backend unavailable"))
print("Start-only policy, injected app coordination/cancellation and signed-reply preflight checks passed. No live VPN/PF operation.")
