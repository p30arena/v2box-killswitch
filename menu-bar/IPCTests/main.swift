import Foundation

// Anonymous, in-process test service only. No Mach-service registration,
// authorization prompts, root operations, PF, networking or GUI.
@objc protocol EchoProtocol {
    func ping(_ reply: @escaping (String) -> Void)
}

final class EchoService: NSObject, EchoProtocol {
    private let lock = NSLock()
    private var count = 0
    func ping(_ reply: @escaping (String) -> Void) {
        lock.lock(); count += 1; lock.unlock()
        reply("approved-test-peer")
    }
    var calls: Int {
        lock.lock(); defer { lock.unlock() }; return count
    }
}

@available(macOS 13.0, *)
final class EchoDelegate: NSObject, NSXPCListenerDelegate {
    let pin: PeerPin
    let service = EchoService()
    init(_ pin: PeerPin) { self.pin = pin }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        do { try pin.enforce(on: connection) } catch { return false }
        connection.exportedInterface = NSXPCInterface(with: EchoProtocol.self)
        connection.exportedObject = service
        connection.resume()
        return true
    }
}

@available(macOS 13.0, *)
func check(serverPin: PeerPin, clientPin: PeerPin, shouldSucceed: Bool, rejectBeforeDispatch: Bool = false) throws {
    let delegate = EchoDelegate(serverPin)
    let listener = NSXPCListener.anonymous()
    listener.delegate = delegate
    listener.resume()
    defer { listener.invalidate() }
    let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
    try clientPin.enforce(on: connection)
    connection.remoteObjectInterface = NSXPCInterface(with: EchoProtocol.self)
    let done = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var success = false
    connection.invalidationHandler = { done.signal() }
    connection.interruptionHandler = { done.signal() }
    connection.resume()
    defer { connection.invalidate() }
    let proxy = connection.remoteObjectProxyWithErrorHandler { _ in done.signal() } as! EchoProtocol
    proxy.ping { value in
        lock.lock(); success = value == "approved-test-peer"; lock.unlock()
        done.signal()
    }
    guard done.wait(timeout: .now() + 8) == .success else {
        fatalError("IPC identity test timed out")
    }
    lock.lock(); let received = success; lock.unlock()
    precondition(received == shouldSucceed, "Peer authentication did not behave as expected")
    if rejectBeforeDispatch {
        precondition(delegate.service.calls == 0, "Rejected client reached exported method")
    }
    withExtendedLifetime(delegate) {}
}

if #available(macOS 13.0, *) {
    guard CommandLine.arguments.count == 2 else { fatalError("Expected this test binary's CDHash") }
    let correct = try PeerPin(CommandLine.arguments[1])
    let wrong = try PeerPin(String(repeating: "0", count: 40))
    try check(serverPin: correct, clientPin: correct, shouldSucceed: true)
    try check(serverPin: wrong, clientPin: correct, shouldSucceed: false, rejectBeforeDispatch: true)
    // A client expecting the wrong server must reject it too.
    try check(serverPin: correct, clientPin: wrong, shouldSucceed: false)
    print("3 anonymous XPC identity tests passed. No privileged service or PF action.")
} else {
    print("Skipped: macOS 13+ required")
}
