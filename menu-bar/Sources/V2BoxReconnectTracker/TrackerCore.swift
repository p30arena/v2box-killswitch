import Foundation

enum TrackerVPNState { case disconnected, connecting, connected, disconnecting, unknown }

// Unattended START requests only. No retry exhaustion, PF, routes or stop action.
struct TrackerRetry {
    private(set) var attempts = 0
    private(set) var nextDue: TimeInterval = 0
    private var lastTime: TimeInterval = 0
    private var connectedSince: TimeInterval?
    private var lastStart: TimeInterval?

    mutating func sample(_ state: TrackerVPNState, now: TimeInterval, enabled: Bool) -> Bool {
        guard now.isFinite, now >= lastTime else { return false }
        lastTime = now
        guard enabled else { connectedSince = nil; return false }
        switch state {
        case .connected:
            // A new drop after Connected gets an immediate request, subject only
            // to a 250 ms anti-spin floor, not an old five-second failure delay.
            if let lastStart { nextDue = min(nextDue, lastStart + 0.25) }
            if connectedSince == nil { connectedSince = now }
            // Status stability resets the retry rate, NOT a claim of internet health.
            if now - connectedSince! >= 15 { attempts = 0; nextDue = 0 }
            return false
        case .connecting, .disconnecting, .unknown:
            connectedSince = nil
            return false
        case .disconnected: connectedSince = nil
        }
        guard now >= nextDue else { return false }
        let delays: [TimeInterval] = [0.25, 0.5, 1, 2, 5]
        let index = min(attempts, delays.count - 1)
        attempts = min(attempts + 1, Int.max - 1)
        lastStart = now
        nextDue = now + delays[index]
        return true
    }

    mutating func resume() { nextDue = 0 }
}
