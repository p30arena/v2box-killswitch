import Foundation

var samples = 0
var sawKnownState = false
let tracker = NativeTracker(paused: false, observeOnly: true) { state, message, events in
    samples += 1
    sawKnownState = sawKnownState || state != .unknown
    if samples == 1 {
        print("Read-only native watcher: knownState=\(state != .unknown), eventSubscription=\(events)")
    }
    precondition(message.contains("observing only") || state == .unknown)
}
tracker.start()
RunLoop.main.run(until: Date(timeIntervalSinceNow: 3))
precondition(samples > 0 && sawKnownState, "Native service discovery/status observation did not succeed")
print("Read-only watcher passed: \(samples) observations. Start disabled; no VPN/PF changes.")
