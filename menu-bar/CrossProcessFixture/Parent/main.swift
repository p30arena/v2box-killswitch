import Foundation
import Darwin

// Run ONLY after separate approval. Starts a temporary per-user bundled XPC
// diagnostic service, not a root helper/agent or the real recovery worker.
@available(macOS 13.0, *)
func run(_ config: FixtureConfig) throws {
    let deadline = DispatchTime.now() + 8
    let serverPin = try config.pin("service_hash")
    let connection = NSXPCConnection(serviceName: config.serviceName)
    try serverPin.enforce(on: connection)
    connection.remoteObjectInterface = RecoveryEndpointHandoff.bootstrapInterface()
    connection.resume()
    defer { connection.invalidate() }
    let acquired = DispatchSemaphore(value: 0), lock = NSLock()
    var endpoint: NSXPCListenerEndpoint?
    var serverPID: Int32 = 0
    var serverUID: UInt32 = UInt32.max
    let bootstrap = connection.remoteObjectProxyWithErrorHandler { _ in acquired.signal() } as! RecoveryBootstrapProtocol
    bootstrap.acquire(config.ticket) { value, _ in
        lock.lock()
        endpoint = value
        // Outgoing connection identity is consulted ONLY after a pinned reply.
        serverPID = connection.processIdentifier
        serverUID = connection.effectiveUserIdentifier
        lock.unlock(); acquired.signal()
    }
    guard acquired.wait(timeout: deadline) == .success else { throw FixtureFailure.unavailable }
    lock.lock(); let received = endpoint, pid = serverPID, uid = serverUID; lock.unlock()
    guard let received, pid > 0, pid != getpid(), uid == geteuid() else { throw FixtureFailure.unavailable }

    let privateConnection = NSXPCConnection(listenerEndpoint: received)
    try serverPin.enforce(on: privateConnection)
    privateConnection.remoteObjectInterface = NSXPCInterface(with: RecoveryPrivateProtocol.self)
    privateConnection.resume()
    defer { privateConnection.invalidate() }
    let confirmed = DispatchSemaphore(value: 0)
    var accepted = false
    let proxy = privateConnection.remoteObjectProxyWithErrorHandler { _ in confirmed.signal() } as! RecoveryPrivateProtocol
    proxy.confirm(config.ticket) { data, _ in
        let body = data.flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
        lock.lock()
        accepted = body?["phase"] as? String == "confirmed" && body?["can_execute"] as? Bool == false
            && body?["server_pid"] as? Int == Int(pid) && body?["peer_pid"] as? Int == Int(getpid())
            && body?["peer_uid"] as? Int == Int(geteuid())
            && privateConnection.processIdentifier == pid && privateConnection.effectiveUserIdentifier == uid
        lock.unlock(); confirmed.signal()
    }
    guard confirmed.wait(timeout: deadline) == .success else { throw FixtureFailure.unavailable }
    lock.lock(); let success = accepted; lock.unlock()
    guard success else { throw FixtureFailure.unavailable }
    let replay = DispatchSemaphore(value: 0)
    var rejected = false
    proxy.confirm(config.ticket) { data, issue in
        lock.lock(); rejected = data == nil && issue == "unavailable"; lock.unlock(); replay.signal()
    }
    guard replay.wait(timeout: deadline) == .success else { throw FixtureFailure.unavailable }
    lock.lock(); let replayRejected = rejected; lock.unlock()
    guard replayRejected else { throw FixtureFailure.unavailable }
}

if #available(macOS 13.0, *) {
    guard geteuid() != 0, Array(CommandLine.arguments.dropFirst()) == ["--run-read-only"] else {
        fputs("Fixture is build-only unless explicitly run with --run-read-only as a non-root user.\n", stderr)
        exit(1)
    }
    var config: FixtureConfig?
    do {
        var value = try FixtureConfig()
        try value.bindCurrentParent()
        config = value
        try run(value)
        value.result(true)
    } catch {
        config?.result(false)
        fputs("Read-only cross-process fixture failed; no protection/VPN operation exists.\n", stderr)
        exit(1)
    }
} else { exit(1) }
