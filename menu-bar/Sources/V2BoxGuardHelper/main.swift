import Foundation
import Security
import Darwin

// Development helper source. No automatic installation or launchd registration.
// Backend and pins must be installed by a reviewed installer before use.
let backendPath = "/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend"
let pinPath = "/Library/Application Support/V2BoxGuard/client-pin"

func trustedFile(_ path: String, executable: Bool) throws -> Data {
    // Deployment paths are constants. Reject writable/symlinked parents before
    // opening the final entry; unprivileged users cannot replace trusted parents.
    var parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
    while true {
        var directory = stat()
        guard lstat(parent, &directory) == 0, directory.st_uid == 0,
              directory.st_mode & S_IFMT == S_IFDIR,
              directory.st_mode & 0o022 == 0 else { throw GuardError.unavailable }
        if parent == "/" { break }
        parent = URL(fileURLWithPath: parent).deletingLastPathComponent().path
    }
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    guard fd >= 0 else { throw GuardError.unavailable }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_uid == 0,
          (info.st_mode & S_IFMT) == S_IFREG,
          (info.st_mode & 0o022) == 0, info.st_nlink == 1 else { throw GuardError.unavailable }
    if executable {
        guard info.st_mode & 0o111 != 0 else { throw GuardError.unavailable }
        return Data()
    }
    guard info.st_size > 0, info.st_size <= 128 else { throw GuardError.unavailable }
    var bytes = [UInt8](repeating: 0, count: 129)
    let count = read(fd, &bytes, bytes.count)
    guard count > 0, count <= 128 else { throw GuardError.unavailable }
    return Data(bytes.prefix(count))
}

enum GuardError: Error { case unavailable }

final class FixedBackend {
    func call(_ operation: String) throws -> Data {
        guard ["status", "enable", "disable", "refresh"].contains(operation) else { throw GuardError.unavailable }
        _ = try trustedFile(backendPath, executable: true)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: backendPath)
        process.arguments = [operation]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        process.currentDirectoryURL = URL(fileURLWithPath: "/")
        let output = Pipe()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }
        try process.run()
        guard done.wait(timeout: .now() + 10) == .success else {
            process.terminate()
            throw GuardError.unavailable // outcome unknown, never claim Off
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0, data.count <= 4096,
              let decoded = try? JSONSerialization.jsonObject(with: data),
              decoded is [String: String] else { throw GuardError.unavailable }
        return data
    }
}

final class GuardService: NSObject, GuardXPCProtocol {
    private let queue = DispatchQueue(label: "org.v2boxkillswitch.operations")
    private let backend = FixedBackend()
    private var timer: DispatchSourceTimer?

    override init() {
        super.init()
        // Backend refresh reads durable intent before doing any PF updates.
        // It cannot undo Disable; both operations use this same serial queue.
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 10, repeating: 10)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            _ = try? self.backend.call("refresh")
        }
        timer.resume()
        self.timer = timer
    }

    func status(_ reply: @escaping (Data?, String?) -> Void) {
        queue.async {
            do { reply(try self.backend.call("status"), nil) }
            catch { reply(nil, "Actual protection state unavailable.") }
        }
    }

    func setProtectionEnabled(_ enabled: Bool, authorization: Data,
                              reply: @escaping (Data?, String?) -> Void) {
        queue.async {
            do {
                try ManagementAuthorization.verify(authorization)
                reply(try self.backend.call(enabled ? "enable" : "disable"), nil)
            } catch {
                reply(nil, "Authorization or backend operation failed; protection state is unknown.")
            }
        }
    }

    func reconnectVPN(_ reply: @escaping (Data?, String?) -> Void) {
        // Must run through an authenticated user-session agent, not root's VPN
        // namespace. Do not start a GUI or accept service names from IPC.
        reply(nil, "User-session reconnect integration is not implemented.")
    }
}

@available(macOS 13.0, *)
final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    let pin: PeerPin
    let service = GuardService()
    init(pin: PeerPin) { self.pin = pin }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier != 0 else { return false }
        do { try pin.enforce(on: connection) }
        catch { return false }
        connection.exportedInterface = NSXPCInterface(with: GuardXPCProtocol.self)
        connection.exportedObject = service
        connection.resume()
        return true
    }
}

if #available(macOS 13.0, *) {
    guard CommandLine.arguments == [CommandLine.arguments[0], "--serve"], geteuid() == 0 else {
        fputs("Development helper: no installation. Requires reviewed root deployment and --serve.\n", stderr)
        exit(1)
    }
    do {
        let data = try trustedFile(pinPath, executable: false)
        guard let text = String(data: data, encoding: .utf8) else { throw GuardError.unavailable }
        let pin = try PeerPin(text.trimmingCharacters(in: .whitespacesAndNewlines))
        try pin.validate()
        let delegate = ListenerDelegate(pin: pin)
        let listener = NSXPCListener(machServiceName: "org.v2boxkillswitch.helper")
        listener.delegate = delegate
        listener.resume()
        withExtendedLifetime(delegate) { RunLoop.current.run() }
    } catch {
        fputs("Helper refused startup: trusted deployment prerequisites unavailable.\n", stderr)
        exit(1)
    }
} else {
    fputs("macOS 13 or later required.\n", stderr)
    exit(1)
}
