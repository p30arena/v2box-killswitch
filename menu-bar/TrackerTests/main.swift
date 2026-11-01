import Foundation

var checks = 0
func check(_ condition: @autoclosure () -> Bool, _ label: String) {
    checks += 1
    guard condition() else { fatalError(label) }
}
var p = TrackerRetry()
check(p.sample(.disconnected, now: 100, enabled: true), "First disconnect requests Start immediately")
check(!p.sample(.disconnected, now: 100.1, enabled: true), "Duplicate event does not spam Start")
check(p.sample(.disconnected, now: 100.25, enabled: true), "Rapid retry after 250ms")
check(!p.sample(.disconnected, now: 100.5, enabled: true), "Second backoff respected")
check(p.sample(.disconnected, now: 100.75, enabled: true), "Second retry after 500ms")
for n in 1...1000 {
    check(p.sample(.disconnected, now: 200 + Double(n) * 5, enabled: true), "Retries do not exhaust")
}
let t = 6000.0
check(!p.sample(.connected, now: t, enabled: true), "Never starts a connected VPN")
check(p.sample(.disconnected, now: t + 0.1, enabled: true), "Fresh disconnect bypasses old failure cooldown")
check(!p.sample(.connecting, now: t + 1, enabled: true), "Does not restart connecting VPN")
check(!p.sample(.disconnecting, now: t + 2, enabled: true), "Waits for orderly disconnection")
check(!p.sample(.unknown, now: t + 3, enabled: true), "Unknown state is not permission to start")
check(!p.sample(.disconnected, now: t + 10, enabled: false), "Pause forbids Start")
p.resume()
check(p.sample(.disconnected, now: t + 10.1, enabled: true), "Resume does not wait for old cooldown")
check(!p.sample(.disconnected, now: .nan, enabled: true), "Reject nonfinite clock")
check(!p.sample(.disconnected, now: 0, enabled: true), "Reject backwards clock")
check(!p.sample(.connected, now: t + 20, enabled: true), "Status alone does not request Start")
check(!p.sample(.connected, now: t + 35, enabled: true), "Stable status resets rate")
check(p.attempts == 0, "No retry tier stuck after stable connection")
check(p.sample(.disconnected, now: t + 35.01, enabled: true), "Next outage starts immediately")
check(p.attempts == 1, "Next outage begins rapid retry tier")
print("Tracker policy: \(checks) checks passed; no VPN/PF/system changes")
