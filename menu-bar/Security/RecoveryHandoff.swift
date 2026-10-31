import Foundation
import Darwin

// READ-ONLY rendezvous/capability handoff. No EXEC, lifecycle proof, PF or VPN API.
@objc protocol RecoveryBootstrapProtocol {
    func acquire(_ ticket: String, withReply reply: @escaping (NSXPCListenerEndpoint?, String?) -> Void)
}

@objc protocol RecoveryPrivateProtocol {
    func confirm(_ ticket: String, withReply reply: @escaping (Data?, String?) -> Void)
}

enum RecoveryHandoffError: Error { case invalidContext }

@available(macOS 13.0, *)
final class RecoveryEndpointHandoff {
    let pin: PeerPin
    let callerUID: UInt32
    let callerPID: Int32
    private let ticket: String
    private let validateLaunch: () -> Bool
    private let now: () -> TimeInterval
    private let started: TimeInterval
    private let deadline: TimeInterval
    private let lock = NSLock()
    private var issued = false
    private var consumed = false
    private var closed = false
    private var privateListener: NSXPCListener?
    private var privateDelegate: RecoveryHandoffDelegate?

    init(ticket: String, callerUID: UInt32, callerPID: Int32, pin: PeerPin,
         validateLaunch: @escaping () -> Bool, lifetime: TimeInterval = 5,
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) throws {
        let start = now()
        guard ticket.utf8.count == 32,
              ticket.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              callerUID > 0, callerUID != UInt32.max, callerPID > 0,
              start.isFinite, start >= 0, lifetime.isFinite, lifetime > 0, lifetime <= 8 else {
            throw RecoveryHandoffError.invalidContext
        }
        try pin.validate()
        self.ticket = ticket; self.callerUID = callerUID; self.callerPID = callerPID
        self.pin = pin; self.validateLaunch = validateLaunch; self.now = now
        started = start; deadline = start + lifetime
    }

    static func bootstrapInterface() -> NSXPCInterface {
        let interface = NSXPCInterface(with: RecoveryBootstrapProtocol.self)
        let classes = NSSet(object: NSXPCListenerEndpoint.self) as! Set<AnyHashable>
        interface.setClasses(classes, for: #selector(RecoveryBootstrapProtocol.acquire(_:withReply:)),
                             argumentIndex: 0, ofReply: true)
        return interface
    }

    func delegate(privateChannel: Bool = false) -> RecoveryHandoffDelegate {
        return RecoveryHandoffDelegate(core: self, privateChannel: privateChannel)
    }

    private func fresh() -> Bool {
        let time = now()
        return time.isFinite && time >= started && time < deadline
    }

    fileprivate func acquire(_ supplied: String, peer: RecoveryConnectionPeer,
                             reply: @escaping (NSXPCListenerEndpoint?, String?) -> Void) {
        // Called ONLY after Foundation dispatched a message through the pin.
        guard supplied == ticket, peer.effectiveUID == callerUID, peer.processIdentifier == callerPID,
              validateLaunch() else { reply(nil, "unavailable"); return }
        lock.lock()
        guard !closed, !issued, !consumed, fresh() else {
            lock.unlock(); reply(nil, "unavailable"); return
        }
        let listener = NSXPCListener.anonymous()
        let delegate = self.delegate(privateChannel: true)
        listener.delegate = delegate
        privateListener = listener; privateDelegate = delegate
        issued = true
        listener.resume()
        let endpoint = listener.endpoint
        lock.unlock()
        // NSXPC transfers the actual Mach capability. NEVER archive to pipe bytes.
        reply(endpoint, nil)
    }

    fileprivate func confirm(_ supplied: String, peer: RecoveryConnectionPeer,
                             reply: @escaping (Data?, String?) -> Void) {
        guard supplied == ticket, peer.effectiveUID == callerUID, peer.processIdentifier == callerPID,
              validateLaunch() else { reply(nil, "unavailable"); return }
        lock.lock()
        guard !closed, issued, !consumed, fresh() else {
            lock.unlock(); reply(nil, "unavailable"); return
        }
        consumed = true
        lock.unlock()
        let message: [String: Any] = [
            "phase": "confirmed", "server_pid": getpid(), "peer_pid": peer.processIdentifier,
            "peer_uid": peer.effectiveUID, "can_execute": false
        ]
        let data = try? JSONSerialization.data(withJSONObject: message, options: [.sortedKeys])
        reply(data, data == nil ? "unavailable" : nil)
    }

    func invalidate() {
        lock.lock(); closed = true
        let listener = privateListener
        privateListener = nil; privateDelegate = nil
        lock.unlock()
        listener?.invalidate()
    }

    deinit { privateListener?.invalidate() }
}

@available(macOS 13.0, *)
final class RecoveryHandoffDelegate: NSObject, NSXPCListenerDelegate {
    private weak var core: RecoveryEndpointHandoff?
    private let privateChannel: Bool
    init(core: RecoveryEndpointHandoff, privateChannel: Bool) {
        self.core = core; self.privateChannel = privateChannel
    }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard let core else { return false }
        let peer: RecoveryConnectionPeer
        do {
            peer = try RecoveryConnectionPeer(connection: connection, pin: core.pin, role: .userWorker(core.callerUID))
            guard peer.processIdentifier == core.callerPID else { return false }
        } catch { return false }
        // Acceptance only ARMS the pin. Exported methods perform no work until
        // Foundation has checked the incoming message. PID alone is not auth.
        if privateChannel {
            connection.exportedInterface = NSXPCInterface(with: RecoveryPrivateProtocol.self)
            connection.exportedObject = RecoveryPrivateFacade(core: core, peer: peer)
        } else {
            connection.exportedInterface = RecoveryEndpointHandoff.bootstrapInterface()
            connection.exportedObject = RecoveryBootstrapFacade(core: core, peer: peer)
        }
        connection.resume()
        return true
    }
}

@available(macOS 13.0, *)
private final class RecoveryBootstrapFacade: NSObject, RecoveryBootstrapProtocol {
    let core: RecoveryEndpointHandoff
    let peer: RecoveryConnectionPeer
    init(core: RecoveryEndpointHandoff, peer: RecoveryConnectionPeer) { self.core = core; self.peer = peer }
    func acquire(_ ticket: String, withReply reply: @escaping (NSXPCListenerEndpoint?, String?) -> Void) {
        core.acquire(ticket, peer: peer, reply: reply)
    }
}

@available(macOS 13.0, *)
private final class RecoveryPrivateFacade: NSObject, RecoveryPrivateProtocol {
    let core: RecoveryEndpointHandoff
    let peer: RecoveryConnectionPeer
    init(core: RecoveryEndpointHandoff, peer: RecoveryConnectionPeer) { self.core = core; self.peer = peer }
    func confirm(_ ticket: String, withReply reply: @escaping (Data?, String?) -> Void) {
        core.confirm(ticket, peer: peer, reply: reply)
    }
}
