import Foundation
import Darwin

// Anonymous IN-PROCESS handoff only; no service registration or child execution.
final class Switch {
    private let lock = NSLock()
    private var enabled = true
    private var time: TimeInterval = 10
    private var count = 0
    func valid() -> Bool { lock.lock(); defer { lock.unlock() }; count += 1; return enabled }
    func revoke() { lock.lock(); enabled = false; lock.unlock() }
    func now() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return time }
    func expire() { lock.lock(); time = 100; lock.unlock() }
    func beforeStart() { lock.lock(); time = 0; lock.unlock() }
    var calls: Int { lock.lock(); defer { lock.unlock() }; return count }
}

func acquire(_ connection: NSXPCConnection, ticket: String) -> NSXPCListenerEndpoint? {
    let done = DispatchSemaphore(value: 0), lock = NSLock()
    var result: NSXPCListenerEndpoint?
    let proxy = connection.remoteObjectProxyWithErrorHandler { _ in done.signal() } as! RecoveryBootstrapProtocol
    proxy.acquire(ticket) { endpoint, _ in lock.lock(); result = endpoint; lock.unlock(); done.signal() }
    precondition(done.wait(timeout: .now() + 8) == .success, "Handoff acquire timed out")
    lock.lock(); defer { lock.unlock() }; return result
}

func confirm(_ connection: NSXPCConnection, ticket: String) -> Bool {
    let done = DispatchSemaphore(value: 0), lock = NSLock()
    var success = false
    let proxy = connection.remoteObjectProxyWithErrorHandler { _ in done.signal() } as! RecoveryPrivateProtocol
    proxy.confirm(ticket) { data, _ in
        let object = data.flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
        lock.lock()
        success = object?["phase"] as? String == "confirmed" && object?["can_execute"] as? Bool == false
            && object?["peer_pid"] as? Int == Int(getpid()) && object?["server_pid"] as? Int == Int(getpid())
        lock.unlock(); done.signal()
    }
    precondition(done.wait(timeout: .now() + 8) == .success, "Handoff confirm timed out")
    lock.lock(); defer { lock.unlock() }; return success
}

@available(macOS 13.0, *)
func check(_ pin: PeerPin, mode: String) throws {
    let ticket = String(repeating: "a", count: 32), state = Switch()
    let wrong = try PeerPin(String(repeating: "0", count: 40))
    let core = try RecoveryEndpointHandoff(ticket: ticket,
        callerUID: mode == "wrong_uid" ? (geteuid() == 1 ? 2 : 1) : geteuid(),
        callerPID: mode == "wrong_pid" ? getpid() + 1 : getpid(),
        pin: mode == "wrong_client_pin" ? wrong : pin, validateLaunch: { state.valid() }, now: { state.now() })
    let delegate = core.delegate()
    let listener = NSXPCListener.anonymous()
    listener.delegate = delegate; listener.resume()
    defer { listener.invalidate(); core.invalidate(); withExtendedLifetime(delegate) {} }
    if mode == "expired" { state.expire() }
    if mode == "clock_before_start" { state.beforeStart() }
    if mode == "revoked" { state.revoke() }
    let bootstrap = NSXPCConnection(listenerEndpoint: listener.endpoint)
    try pin.enforce(on: bootstrap)
    bootstrap.remoteObjectInterface = RecoveryEndpointHandoff.bootstrapInterface()
    bootstrap.resume()
    defer { bootstrap.invalidate() }
    let endpoint = acquire(bootstrap, ticket: mode == "wrong_ticket" ? String(repeating: "b", count: 32) : ticket)
    let accepted = ["good", "private_wrong_pin", "private_revoked", "private_expired", "private_clock_before_start", "private_wrong_ticket", "closed"].contains(mode)
    precondition((endpoint != nil) == accepted, "Unexpected endpoint issuance")
    if ["wrong_client_pin", "wrong_uid", "wrong_pid"].contains(mode) { precondition(state.calls == 0) }
    guard let endpoint else { return }
    // A transferred endpoint is not sufficient: independently pin this connection.
    let connection = NSXPCConnection(listenerEndpoint: endpoint)
    try (mode == "private_wrong_pin" ? wrong : pin).enforce(on: connection)
    connection.remoteObjectInterface = NSXPCInterface(with: RecoveryPrivateProtocol.self)
    connection.resume()
    defer { connection.invalidate() }
    if mode == "private_revoked" { state.revoke() }
    if mode == "private_expired" { state.expire() }
    if mode == "private_clock_before_start" { state.beforeStart() }
    if mode == "closed" { core.invalidate() }
    let result = confirm(connection, ticket: mode == "private_wrong_ticket" ? String(repeating: "b", count: 32) : ticket)
    precondition(result == (mode == "good"), "Private endpoint was not revalidated")
    if mode == "good" {
        precondition(!confirm(connection, ticket: ticket), "Confirmation replay accepted")
        precondition(acquire(bootstrap, ticket: ticket) == nil, "Endpoint replay accepted")
    }
}

if #available(macOS 13.0, *) {
    guard geteuid() != 0, CommandLine.arguments.count == 2 else { fatalError("Unprivileged fixture hash required") }
    let pin = try PeerPin(CommandLine.arguments[1])
    func invalid(ticket: String = String(repeating: "a", count: 32), uid: UInt32 = geteuid(),
                 pid: Int32 = getpid(), lifetime: TimeInterval = 5, time: TimeInterval = 10) {
        do {
            _ = try RecoveryEndpointHandoff(ticket: ticket, callerUID: uid, callerPID: pid, pin: pin,
                validateLaunch: { true }, lifetime: lifetime, now: { time })
            fatalError("Unsafe handoff context accepted")
        } catch {}
    }
    for ticket in ["", String(repeating: "a", count: 31), String(repeating: "a", count: 32) + "\n",
                   String(repeating: "A", count: 32), String(repeating: "g", count: 32), String(repeating: "é", count: 32)] {
        invalid(ticket: ticket)
    }
    invalid(uid: 0); invalid(uid: UInt32.max); invalid(pid: 0)
    for lifetime in [0.0, -1, 9, .infinity, .nan] { invalid(lifetime: lifetime) }
    for time in [-1.0, .infinity, .nan] { invalid(time: time) }
    let modes = ["good", "wrong_ticket", "wrong_client_pin", "wrong_uid", "wrong_pid", "expired", "revoked",
                 "clock_before_start", "private_wrong_pin", "private_revoked", "private_expired",
                 "private_clock_before_start", "private_wrong_ticket", "closed"]
    for mode in modes { try check(pin, mode: mode) }
    print("14 anonymous in-process endpoint suites and 17 context-schema checks passed. No cross-process service or execution activated.")
} else { fatalError("macOS 13+ required") }
