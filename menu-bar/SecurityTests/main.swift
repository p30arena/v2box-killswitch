import Foundation

// No connections, listener, authorization prompts, PF or service commands.
var checks = 0
func expectFailure(_ operation: () throws -> Void) {
    do { try operation(); fatalError("Expected rejection") }
    catch { checks += 1 }
}

for hash in ["", "abcd", String(repeating: "g", count: 40),
             String(repeating: "a", count: 40) + " or true", "../untrusted"] {
    expectFailure { _ = try PeerPin(hash) }
}
let pin = try PeerPin(String(repeating: "A", count: 40))
precondition(pin.codeDirectoryHash == String(repeating: "a", count: 40))
try pin.validate()
checks += 2
for size in [0, 1, 31, 33, 1024] {
    expectFailure { try ManagementAuthorization.verify(Data(repeating: 0, count: size)) }
}
print("\(checks) security-boundary checks passed; no service or firewall operations performed")
