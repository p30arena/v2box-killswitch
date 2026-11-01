import Foundation
import SystemConfiguration
import Darwin

struct TrackerService { let id: String; let name: String }

func discoverTrackerServices() -> [TrackerService] {
    // Fixed read-only query; no shell, profiles, root or caller command.
    let process = Process(), output = Pipe(), done = DispatchSemaphore(value: 0)
    process.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
    process.arguments = ["--nc", "list"]
    process.environment = ["PATH": "/usr/bin:/bin", "LC_ALL": "C"]
    process.standardInput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
    process.standardOutput = output
    process.terminationHandler = { _ in done.signal() }
    do { try process.run() } catch { return [] }
    guard done.wait(timeout: .now() + 2) == .success else { process.terminate(); return [] }
    let data = output.fileHandleForReading.readDataToEndOfFile()
    guard process.terminationStatus == 0, data.count < 65536,
          let text = String(data: data, encoding: .utf8),
          let regex = try? NSRegularExpression(pattern: #"(?m)^[^\n]*\s([0-9A-Fa-f-]{36})\s+VPN\s+\(hossin\.asaadi\.V2Box\)\s+"([^"\r\n]+)""#) else { return [] }
    return regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).compactMap { match in
        guard let a = Range(match.range(at: 1), in: text), let b = Range(match.range(at: 2), in: text),
              UUID(uuidString: String(text[a])) != nil else { return nil }
        return TrackerService(id: String(text[a]).uppercased(), name: String(text[b]))
    }
}

final class NativeTracker {
    private let queue = DispatchQueue(label: "org.v2boxkillswitch.tracker.events", qos: .userInitiated)
    private let lock = NSLock()
    private var paused: Bool
    private let observeOnly: Bool
    private var connection: SCNetworkConnection?
    private var service: TrackerService?
    private var timer: DispatchSourceTimer?
    private var retry = TrackerRetry()
    private var eventsAvailable = false
    private var lastDiscovery: TimeInterval = -10
    private let publish: (TrackerVPNState, String, Bool) -> Void

    init(paused: Bool, observeOnly: Bool = false, publish: @escaping (TrackerVPNState, String, Bool) -> Void) {
        self.paused = paused; self.observeOnly = observeOnly; self.publish = publish
    }
    func start() {
        queue.async { [self] in
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now(), repeating: .milliseconds(500), leeway: .milliseconds(20))
            timer.setEventHandler { [weak self] in self?.sample() }
            self.timer = timer; timer.resume()
        }
    }
    func wake() {
        queue.async { [self] in lastDiscovery = -10; retry.resume(); sample() }
    }
    func setPaused(_ value: Bool) {
        lock.lock(); paused = value; lock.unlock()
        queue.async { [self] in if !value { retry.resume() }; sample() }
    }
    private func permitted() -> Bool {
        lock.lock(); let enabled = !paused && !observeOnly; lock.unlock()
        var uid: uid_t = 0, gid: gid_t = 0
        return enabled && geteuid() != 0 && getuid() == geteuid()
            && SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) != nil && uid == geteuid()
    }
    private func attach() {
        let now = ProcessInfo.processInfo.systemUptime
        guard now - lastDiscovery >= 1 else { return }
        lastDiscovery = now
        let services = discoverTrackerServices()
        guard services.count == 1 else {
            emit(.unknown, services.isEmpty ? "V2Box service not found — retrying" : "Multiple V2Box services — cannot choose safely")
            return
        }
        var context = SCNetworkConnectionContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        guard let c = SCNetworkConnectionCreateWithServiceID(nil, services[0].id as CFString, { _, _, pointer in
            guard let pointer else { return }
            Unmanaged<NativeTracker>.fromOpaque(pointer).takeUnretainedValue().sample()
        }, &context) else { emit(.unknown, "Cannot watch V2Box — retrying"); return }
        service = services[0]; connection = c
        eventsAvailable = SCNetworkConnectionSetDispatchQueue(c, queue)
    }
    private func emit(_ state: TrackerVPNState, _ text: String) {
        let eventDriven = eventsAvailable
        DispatchQueue.main.async { [publish] in publish(state, text, eventDriven) }
    }
    private func sample() {
        guard let c = connection, service != nil else {
            attach()
            if connection != nil { sample() } // Do not wait for the first poll.
            return
        }
        let state: TrackerVPNState
        switch SCNetworkConnectionGetStatus(c) {
        case .connected: state = .connected
        case .disconnected: state = .disconnected
        case .connecting: state = .connecting
        case .disconnecting: state = .disconnecting
        default: state = .unknown
        }
        let now = ProcessInfo.processInfo.systemUptime
        let enabled = permitted()
        var suffix = observeOnly ? "observing only" : (enabled ? "automatic reconnect active" : "reconnect paused")
        if retry.sample(state, now: now, enabled: enabled), permitted(),
           SCNetworkConnectionGetStatus(c) == .disconnected {
            // Immediate async request, no confirmation/options/stop. Linger=true
            // means exiting this tracker must not deliberately disconnect V2Box.
            let accepted = SCNetworkConnectionStart(c, nil, true)
            suffix = accepted ? "Start submitted (\(retry.attempts)); internet unverified"
                              : "Start rejected; retrying automatically"
        }
        switch state {
        case .connected: emit(state, "Connected — internet/IP protection unverified; \(suffix)")
        case .disconnected: emit(state, "VPN DOWN — direct traffic may be exposed; \(suffix)")
        case .connecting: emit(state, "Connecting — direct traffic may be exposed; \(suffix)")
        case .disconnecting: emit(state, "Disconnecting — direct traffic may be exposed; \(suffix)")
        case .unknown:
            emit(state, "VPN status unknown — no privacy guarantee; \(suffix)")
            // A removed/recreated service must be rediscovered, not held forever.
            _ = SCNetworkConnectionSetDispatchQueue(c, nil)
            connection = nil; self.service = nil; eventsAvailable = false
        }
    }
}
