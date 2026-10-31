import Foundation
import Security

// Security utilities only. No listener, registration or privileged operations.
// macOS 13+ enforces these requirements on each NSXPCConnection message.
enum PeerSecurityError: Error {
    case invalidPin
    case invalidRequirement
    case malformedAuthorization
    case authorizationDenied(OSStatus)
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
                    [.interactionAllowed, .extendRights, .preAuthorize], nil)
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
    // The installer must define this right as authenticate-admin. Never replace
    // an existing rule automatically. No installer/right registration is shipped.
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
            throw PeerSecurityError.authorizationDenied(created)
        }
        defer { AuthorizationFree(reference, []) }
        let checked = right.withCString { name -> OSStatus in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                // No interaction or extension in the helper. The authenticated
                // UI must already have obtained the exact management right.
                var granted: UnsafeMutablePointer<AuthorizationRights>?
                let status = AuthorizationCopyRights(reference, &rights, nil, [], &granted)
                guard status == errAuthorizationSuccess else { return status }
                guard let granted else { return errAuthorizationDenied }
                defer { AuthorizationFreeItemSet(granted) }
                guard granted.pointee.count == 1, let items = granted.pointee.items,
                      String(cString: items.pointee.name) == right,
                      items.pointee.flags == 0 else { return errAuthorizationDenied }
                return errAuthorizationSuccess
            }
        }
        guard checked == errAuthorizationSuccess else {
            throw PeerSecurityError.authorizationDenied(checked)
        }
    }
}
