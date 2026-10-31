import Foundation
import Darwin

// Unprivileged artifact fixtures and ANONYMOUS IN-PROCESS XPC only.
// No Root-parent positive test, production bridge, service registration or VPN.
// Test-only overload: production validate() has NO owner override.
extension WorkerArtifact {
    static func validate(_ url: URL, pin: PeerPin, expectedOwner: uid_t) throws {
        try validateFixture(url, pin: pin, expectedOwner: expectedOwner)
    }
}
func rejected(_ body: () throws -> Void) {
    do { try body(); fatalError("Unsafe worker artifact accepted") } catch {}
}

func fixtureACL(_ arguments: [String]) throws {
    let command = Process()
    command.executableURL = URL(fileURLWithPath: "/bin/chmod")
    command.arguments = arguments
    command.standardInput = FileHandle.nullDevice
    command.standardOutput = FileHandle.nullDevice
    command.standardError = FileHandle.nullDevice
    try command.run(); command.waitUntilExit()
    precondition(command.terminationStatus == 0, "Fixture ACL change failed")
}

@objc protocol SigningEchoProtocol {
    func ping(_ reply: @escaping (String) -> Void)
}

final class SigningEcho: NSObject, SigningEchoProtocol {
    private let lock = NSLock()
    private var count = 0
    func ping(_ reply: @escaping (String) -> Void) {
        lock.lock(); count += 1; lock.unlock()
        reply("signed-fixture")
    }
    var calls: Int { lock.lock(); defer { lock.unlock() }; return count }
}

@available(macOS 13.0, *)
final class SigningDelegate: NSObject, NSXPCListenerDelegate {
    let pin: PeerPin
    let role: RecoveryPeerRole
    let service = SigningEcho()
    init(_ pin: PeerPin, _ role: RecoveryPeerRole) { self.pin = pin; self.role = role }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        do {
            let peer = try RecoveryConnectionPeer(connection: connection, pin: pin, role: role)
            precondition(peer.effectiveUID == geteuid())
            precondition(peer.processIdentifier == getpid())
        } catch { return false }
        connection.exportedInterface = NSXPCInterface(with: SigningEchoProtocol.self)
        connection.exportedObject = service
        connection.resume()
        return true
    }
}

@available(macOS 13.0, *)
func peerCheck(serverPin: PeerPin, clientPin: PeerPin, role: RecoveryPeerRole,
               success expected: Bool, beforeDispatch: Bool = false) throws {
    let delegate = SigningDelegate(serverPin, role)
    let listener = NSXPCListener.anonymous()
    listener.delegate = delegate; listener.resume()
    defer { listener.invalidate() }
    let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
    try clientPin.enforce(on: connection)
    connection.remoteObjectInterface = NSXPCInterface(with: SigningEchoProtocol.self)
    let done = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var success = false
    connection.invalidationHandler = { done.signal() }
    connection.interruptionHandler = { done.signal() }
    connection.resume()
    defer { connection.invalidate() }
    let proxy = connection.remoteObjectProxyWithErrorHandler { _ in done.signal() } as! SigningEchoProtocol
    proxy.ping { value in
        lock.lock(); success = value == "signed-fixture"; lock.unlock(); done.signal()
    }
    precondition(done.wait(timeout: .now() + 8) == .success, "Anonymous signing check timed out")
    lock.lock(); let received = success; lock.unlock()
    precondition(received == expected)
    if beforeDispatch { precondition(delegate.service.calls == 0) }
    withExtendedLifetime(delegate) {}
}

if #available(macOS 13.0, *) {
    let args = CommandLine.arguments
    guard geteuid() != 0, args.count == 9 else { fatalError("Unprivileged fixture args required") }
    let worker = URL(fileURLWithPath: args[1])
    let workerPin = try PeerPin(args[2])
    let selfPin = try PeerPin(args[3])
    let plain = URL(fileURLWithPath: args[4])
    let plainPin = try PeerPin(args[5])
    let entitled = URL(fileURLWithPath: args[6])
    let entitledPin = try PeerPin(args[7])
    let directory = URL(fileURLWithPath: args[8])
    let wrong = try PeerPin(String(repeating: "0", count: 40))
    let uid = geteuid()

    try WorkerArtifact.validate(worker, pin: workerPin, expectedOwner: uid)
    rejected { try WorkerArtifact.validate(worker, pin: wrong, expectedOwner: uid) }
    // The user-writable source artifact MUST NOT pass production Root ownership.
    rejected { try WorkerArtifact.validate(worker, pin: workerPin) }
    rejected { try WorkerArtifact.validate(plain, pin: plainPin, expectedOwner: uid) }
    rejected { try WorkerArtifact.validate(entitled, pin: entitledPin, expectedOwner: uid) }

    let copy = directory.appendingPathComponent("copy")
    try FileManager.default.copyItem(at: worker, to: copy)
    try WorkerArtifact.validate(copy, pin: workerPin, expectedOwner: uid)
    chmod(copy.path, 0o775)
    rejected { try WorkerArtifact.validate(copy, pin: workerPin, expectedOwner: uid) }
    chmod(copy.path, 0o4755)
    rejected { try WorkerArtifact.validate(copy, pin: workerPin, expectedOwner: uid) }
    chmod(copy.path, 0o644)
    rejected { try WorkerArtifact.validate(copy, pin: workerPin, expectedOwner: uid) }
    chmod(copy.path, 0o755)
    try fixtureACL(["+a", "everyone allow write", copy.path])
    rejected { try WorkerArtifact.validate(copy, pin: workerPin, expectedOwner: uid) }
    try fixtureACL(["-N", copy.path])
    try fixtureACL(["+a", "everyone allow add_file", directory.path])
    rejected { try WorkerArtifact.validate(copy, pin: workerPin, expectedOwner: uid) }
    try fixtureACL(["-N", directory.path])
    let alias = directory.appendingPathComponent("alias")
    try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: copy)
    rejected { try WorkerArtifact.validate(alias, pin: workerPin, expectedOwner: uid) }
    try FileManager.default.removeItem(at: alias)
    try FileManager.default.linkItem(at: copy, to: alias)
    rejected { try WorkerArtifact.validate(copy, pin: workerPin, expectedOwner: uid) }
    try FileManager.default.removeItem(at: alias)
    chmod(directory.path, 0o777)
    rejected { try WorkerArtifact.validate(copy, pin: workerPin, expectedOwner: uid) }
    chmod(directory.path, 0o700)
    let output = try FileHandle(forUpdating: copy)
    try output.seek(toOffset: 4096)
    let old = try output.read(upToCount: 1)!
    try output.seek(toOffset: 4096)
    try output.write(contentsOf: Data([old[0] ^ 1]))
    try output.close()
    rejected { try WorkerArtifact.validate(copy, pin: workerPin, expectedOwner: uid) }

    try peerCheck(serverPin: selfPin, clientPin: selfPin, role: .userWorker(uid), success: true)
    try peerCheck(serverPin: wrong, clientPin: selfPin, role: .userWorker(uid), success: false, beforeDispatch: true)
    try peerCheck(serverPin: selfPin, clientPin: wrong, role: .userWorker(uid), success: false)
    try peerCheck(serverPin: selfPin, clientPin: selfPin, role: .userWorker(uid == 1 ? 2 : 1), success: false, beforeDispatch: true)
    try peerCheck(serverPin: selfPin, clientPin: selfPin, role: .userWorker(0), success: false, beforeDispatch: true)
    try peerCheck(serverPin: selfPin, clientPin: selfPin, role: .userWorker(UInt32.max), success: false, beforeDispatch: true)
    try peerCheck(serverPin: selfPin, clientPin: selfPin, role: .privilegedParent, success: false, beforeDispatch: true)
    print("15 artifact checks and 7 anonymous in-process signing/UID/PID role checks passed. No production bridge or privileged operation.")
} else { fatalError("macOS 13+ required") }
