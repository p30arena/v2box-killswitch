import Foundation

// Call ONLY from a reply already validated by the pinned XPC connection.
// A capability flag is not authorization; the helper still checks the right.
enum HelperPreflight {
    static func allows(enabled: Bool?, authorizationOnly: Bool, data: Data?, message: String?) -> Bool {
        guard data != nil || message != nil else { return false }
        // Backend status failure must not veto explicit authorized Disable.
        if authorizationOnly || enabled == false { return true }
        guard enabled == true, message == nil, let data,
              let status = (try? JSONSerialization.jsonObject(with: data)) as? [String: String] else { return false }
        return status["can_enable"] == "true"
    }
}
