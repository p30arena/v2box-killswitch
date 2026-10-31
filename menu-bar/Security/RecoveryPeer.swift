import Foundation

// Exclusive alternative to SessionPeer for an ACCEPTED listener connection.
// Instantiate ONCE before resume, using trusted local role/pin configuration.
// Do not read peer UID from an unestablished outgoing connection.
// Construction ARMS the signing policy; only Foundation-dispatched messages have
// passed it. Never grant/resume/clear state merely because this init returned.
enum RecoveryPeerRole {
    case privilegedParent
    case userWorker(UInt32)
}

enum RecoveryPeerError: Error { case invalidWorkerUID, wrongKernelIdentity }

struct RecoveryConnectionPeer {
    let effectiveUID: UInt32
    let processIdentifier: Int32 // Correlation only; never authority to signal.

    @available(macOS 13.0, *)
    init(connection: NSXPCConnection, pin: PeerPin, role: RecoveryPeerRole) throws {
        let expected: UInt32
        switch role {
        case .privilegedParent: expected = 0
        case .userWorker(let uid):
            guard uid > 0 && uid != UInt32.max else { throw RecoveryPeerError.invalidWorkerUID }
            expected = uid
        }
        let actual = connection.effectiveUserIdentifier
        let pid = connection.processIdentifier
        guard actual == expected, pid > 0 else { throw RecoveryPeerError.wrongKernelIdentity }
        try pin.enforce(on: connection) // Foundation checks EACH incoming message.
        effectiveUID = actual
        processIdentifier = pid
    }
}
