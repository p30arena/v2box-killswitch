import Foundation
import Security
import Darwin

// Explicit provisioning utility, compiled but never invoked by build scripts.
// Does not modify PF, launchd, files, networking, or any unrelated auth right.
guard CommandLine.arguments == [CommandLine.arguments[0], "--register-management-right"], geteuid() == 0 else {
    fputs("Requires root and explicit --register-management-right. Nothing changed.\n", stderr)
    exit(1)
}
let name = "org.v2boxkillswitch.manage"
var existing: CFDictionary?
let found = AuthorizationRightGet(name, &existing)
if found == errAuthorizationSuccess {
    // Never silently overwrite a preexisting right, even one that looks similar.
    fputs("Right already exists; inspect it manually. Nothing changed.\n", stderr)
    exit(1)
}
guard found == errAuthorizationDenied else {
    fputs("Could not verify right absence. Nothing changed.\n", stderr)
    exit(1)
}
var authorization: AuthorizationRef?
guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess, let authorization else {
    exit(1)
}
defer { AuthorizationFree(authorization, []) }
let definition: [String: Any] = [
    "class": "rule", "rule": ["authenticate-admin"], "timeout": 60,
    "shared": false, "comment": "Authorize a V2Box Guard protection change"
]
let result = AuthorizationRightSet(authorization, name, definition as CFDictionary, nil, nil, nil)
guard result == errAuthorizationSuccess else {
    fputs("Management right registration failed.\n", stderr)
    exit(1)
}
print("Registered only org.v2boxkillswitch.manage. No networking changes.")
