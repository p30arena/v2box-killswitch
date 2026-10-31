import Foundation
import Security
import Darwin

// Explicit provisioning only; never run by builds. Changes only our custom right.
let register = CommandLine.arguments.dropFirst() == ["--register-management-right"]
let migrate = CommandLine.arguments.dropFirst() == ["--migrate-management-right"]
guard (register || migrate), geteuid() == 0 else {
    fputs("Requires root and an explicit management-right provisioning operation.\n", stderr)
    exit(1)
}
let name = "org.v2boxkillswitch.manage"
let comment = "Authorize a V2Box Guard protection change"
var existing: CFDictionary?
let found = AuthorizationRightGet(name, &existing)
if found == errAuthorizationSuccess {
    guard migrate, let old = existing as? [String: Any], old["comment"] as? String == comment else {
        fputs("Right already exists; refusing overwrite.\n", stderr); exit(1)
    }
    if old["class"] as? String == "user", old["group"] as? String == "admin",
       old["authenticate-user"] as? Bool == true, old["allow-root"] as? Bool == false,
       old["shared"] as? Bool == false, old["timeout"] as? Int == 60 {
        print("Management right already has the reviewed definition.")
        exit(0)
    }
    guard old["class"] as? String == "rule", old["rule"] as? [String] == ["authenticate-admin"] else {
        fputs("Existing definition is not the known legacy project right.\n", stderr); exit(1)
    }
    // Keep the original definition for this explicit migration, not a global DB.
    let backup = "/Library/Application Support/V2BoxGuard/management-right.before-migration.plist"
    guard !FileManager.default.fileExists(atPath: backup) else {
        fputs("Migration backup already exists; manual review required.\n", stderr); exit(1)
    }
    let data = try PropertyListSerialization.data(fromPropertyList: old, format: .xml, options: 0)
    guard FileManager.default.createFile(atPath: backup, contents: data,
                attributes: [.posixPermissions: 0o600, .ownerAccountID: 0, .groupOwnerAccountID: 0]) else { exit(1) }
} else {
    guard register, found == errAuthorizationDenied else {
        fputs("Could not verify the expected right state.\n", stderr); exit(1)
    }
}
var authorization: AuthorizationRef?
guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess, let authorization else { exit(1) }
defer { AuthorizationFree(authorization, []) }
// A self-contained right: authenticate-admin's zero-timeout delegated rule did
// not preserve the intended lifetime across an external-form transfer. Non-shared
// credentials and short lifetime; UI destroys rights after every request.
let definition: [String: Any] = [
    "class": "user", "group": "admin", "authenticate-user": true,
    "allow-root": false, "session-owner": false, "shared": false,
    "timeout": 60, "comment": comment
]
let result = AuthorizationRightSet(authorization, name, definition as CFDictionary, nil, nil, nil)
guard result == errAuthorizationSuccess else { fputs("Management right update failed.\n", stderr); exit(1) }
print("Provisioned only org.v2boxkillswitch.manage. No networking changes.")
