import Foundation
import Security

// Security utilities only. No listener, registration or privileged operations.
// macOS 13+ enforces these requirements on each NSXPCConnection message.
enum PeerSecurityError: Error {
    case invalidPin
    case invalidRequirement
    case malformedAuthorization
    case authorizationDenied(OSStatus)
    case verificationFailed(String, OSStatus)

    var safeDiagnostic: String {
        switch self {
        case .invalidPin: return "Invalid peer pin."
        case .invalidRequirement: return "Invalid peer signing requirement."
        case .malformedAuthorization: return "Authorization form has the wrong length."
        case .authorizationDenied(let status): return "Authorization request failed (OSStatus \(status))."
        case .verificationFailed(let stage, let status):
            return "Authorization verification failed at \(stage) (OSStatus \(status))."
        }
    }
}

struct PeerPin {
    let codeDirectoryHash: String

    init(_ hash: String) throws {
        // A local administrator may approve an exact signed build, including
        // an ad-hoc signed build. No Developer ID subscription is necessary to
        // construct this pin. Updates require explicit repinning.
        guard hash.range(of: "^[0-9a-fA-F]{40}$", options: .regularExpression) != nil else {
            throw PeerSecurityError.invalidPin
        }
        codeDirectoryHash = hash.lowercased()
    }

    var requirement: String { "cdhash H\"\(codeDirectoryHash)\"" }

    func validate() throws {
        var result: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &result) == errSecSuccess,
              result != nil else { throw PeerSecurityError.invalidRequirement }
    }

    @available(macOS 13.0, *)
    func enforce(on connection: NSXPCConnection) throws {
        try validate()
        // Must be called exactly once, before connection.resume(). Foundation
        // validates each new message; no PID lookup race or claimed bundle ID.
        connection.setCodeSigningRequirement(requirement)
    }
}

// Per-connection identity. UID comes from the kernel connection, never an RPC
// parameter. The requirement is enforced by Foundation before message dispatch.
struct SessionPeer {
    let effectiveUID: UInt32

    @available(macOS 13.0, *)
    init(connection: NSXPCConnection, pin: PeerPin) throws {
        let uid = connection.effectiveUserIdentifier
        guard uid != 0 else { throw SessionPeerError.rootPeerRejected }
        try pin.enforce(on: connection)
        effectiveUID = uid
    }

    func matchesConsoleUID(_ current: UInt32?) -> Bool {
        guard let current, current != 0 else { return false }
        return current == effectiveUID
    }
}

enum SessionPeerError: Error { case rootPeerRejected }

final class AuthorizationSession {
    private let reference: AuthorizationRef
    let externalData: Data

    init() throws {
        var ref: AuthorizationRef?
        let created = AuthorizationCreate(nil, nil, [], &ref)
        guard created == errAuthorizationSuccess, let ref else {
            throw PeerSecurityError.authorizationDenied(created)
        }
        let status = ManagementAuthorization.right.withCString { name -> OSStatus in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                return AuthorizationCopyRights(ref, &rights, nil,
                    [.interactionAllowed, .extendRights], nil)
            }
        }
        guard status == errAuthorizationSuccess else {
            AuthorizationFree(ref, [.destroyRights])
            throw PeerSecurityError.authorizationDenied(status)
        }
        var external = AuthorizationExternalForm()
        let externalized = AuthorizationMakeExternalForm(ref, &external)
        guard externalized == errAuthorizationSuccess else {
            AuthorizationFree(ref, [.destroyRights])
            throw PeerSecurityError.authorizationDenied(externalized)
        }
        reference = ref
        externalData = withUnsafeBytes(of: &external) { Data($0) }
    }

    deinit { AuthorizationFree(reference, [.destroyRights]) }
}

struct ManagementAuthorization {
    // Provision as our own authenticate-user/admin right, non-shared, timeout 60.
    // Do not delegate to authenticate-admin's zero-timeout rule or weaken it.
    static let right = "org.v2boxkillswitch.manage"

    static func verify(_ externalData: Data) throws {
        guard externalData.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw PeerSecurityError.malformedAuthorization
        }
        var external = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &external) { destination in
            externalData.copyBytes(to: destination)
        }
        var reference: AuthorizationRef?
        let created = AuthorizationCreateFromExternalForm(&external, &reference)
        guard created == errAuthorizationSuccess, let reference else {
            throw PeerSecurityError.verificationFailed("external-form reconstruction", created)
        }
        defer { AuthorizationFree(reference, []) }
        var verificationStage = "copy-rights"
        let checked = right.withCString { name -> OSStatus in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                // Re-evaluate the exact requested right on the externalized
                // authorization. ExtendRights is required after reconstruction;
                // InteractionAllowed is deliberately NOT set, so the helper
                // cannot prompt or grant a missing admin credential silently.
                var granted: UnsafeMutablePointer<AuthorizationRights>?
                let status = AuthorizationCopyRights(reference, &rights, nil, [.extendRights], &granted)
                guard status == errAuthorizationSuccess else { return status }
                guard let granted else {
                    verificationStage = "missing granted-rights result"
                    return errAuthorizationDenied
                }
                defer { AuthorizationFreeItemSet(granted) }
                guard granted.pointee.count == 1, let items = granted.pointee.items else {
                    verificationStage = "granted-right count \(granted.pointee.count)"
                    return errAuthorizationDenied
                }
                guard String(cString: items.pointee.name) == right else {
                    verificationStage = "granted-right name mismatch"
                    return errAuthorizationDenied
                }
                guard items.pointee.flags == 0 else {
                    verificationStage = "granted-right flags \(items.pointee.flags)"
                    return errAuthorizationDenied
                }
                return errAuthorizationSuccess
            }
        }
        guard checked == errAuthorizationSuccess else {
            throw PeerSecurityError.verificationFailed(verificationStage, checked)
        }
    }
}
