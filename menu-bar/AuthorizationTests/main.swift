import Foundation
import Security

// Explicit diagnostics only. No helper calls, listener, PF or root actions.
let arguments = Array(CommandLine.arguments.dropFirst())
if arguments == ["--unauthorized-form-only"] {
    var reference: AuthorizationRef?
    guard AuthorizationCreate(nil, nil, [], &reference) == errAuthorizationSuccess, let reference else { exit(1) }
    defer { AuthorizationFree(reference, [.destroyRights]) }
    var external = AuthorizationExternalForm()
    guard AuthorizationMakeExternalForm(reference, &external) == errAuthorizationSuccess else { exit(1) }
    let data = withUnsafeBytes(of: &external) { Data($0) }
    do {
        try ManagementAuthorization.verify(data)
        fputs("FAIL: an unauthorized form was accepted. No firewall operation requested.\n", stderr)
        exit(3)
    } catch {
        print("Unauthorized external form rejected without prompting. No firewall operation requested.")
    }
} else if arguments == ["--interactive-authorization-only"] {
    do {
        let session = try AuthorizationSession()
        try ManagementAuthorization.verify(session.externalData)
        withExtendedLifetime(session) {}
        print("Authorization-only local roundtrip verified. No firewall operation requested.")
    } catch let error as PeerSecurityError {
        fputs(error.safeDiagnostic + " No firewall operation requested.\n", stderr)
        exit(2)
    } catch {
        fputs("Authorization-only diagnostic failed. No firewall operation requested.\n", stderr)
        exit(2)
    }
} else {
    fputs("Requires --interactive-authorization-only or --unauthorized-form-only.\n", stderr)
    exit(1)
}
