import Foundation
import Darwin
import SystemConfiguration

// READ-ONLY PROTOTYPE. No scutil/VPN executor exists in this binary.
// Not installed, registered or invoked by the app/helper. Read-only launchctl
// children verify bootstrap identity; both are reaped before emitting Ready.

func emit(_ phase: String, reason: String? = nil, ticket: String? = nil, uid: UInt32? = nil) {
    var message: [String: Any] = ["version": 1, "phase": phase, "can_execute": false]
    if let reason { message["reason"] = reason }
    if let ticket { message["ticket"] = ticket }
    if let uid { message["uid"] = uid }
    guard var data = try? JSONSerialization.data(withJSONObject: message, options: [.sortedKeys]) else { exit(2) }
    data.append(10)
    data.withUnsafeBytes { raw in
        var offset = 0
        while offset < raw.count {
            let written = Darwin.write(STDOUT_FILENO, raw.baseAddress!.advanced(by: offset), raw.count - offset)
            if written < 0 && errno == EINTR { continue }
            guard written > 0 else { _exit(3) }
            offset += written
        }
    }
}

func reject(_ reason: String, ticket: String? = nil) -> Never {
    emit("rejected", reason: reason, ticket: ticket)
    exit(2)
}

func uidArgument(_ value: String) -> UInt32? {
    guard value.range(of: "^[1-9][0-9]{0,9}$", options: .regularExpression) != nil,
          let uid = UInt32(value), uid != UInt32.max else { return nil }
    return uid
}

func launchctlIdentity(_ command: String) -> String? {
    guard ["manageruid", "managername"].contains(command) else { return nil }
    var descriptors: [Int32] = [-1, -1]
    guard pipe(&descriptors) == 0 else { return nil }
    defer { close(descriptors[0]) }
    var actions: posix_spawn_file_actions_t?
    guard posix_spawn_file_actions_init(&actions) == 0 else { close(descriptors[1]); return nil }
    defer { posix_spawn_file_actions_destroy(&actions) }
    var setup: Int32 = 0
    setup |= posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0)
    setup |= posix_spawn_file_actions_adddup2(&actions, descriptors[1], STDOUT_FILENO)
    setup |= posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0)
    setup |= posix_spawn_file_actions_addclose(&actions, descriptors[0])
    setup |= posix_spawn_file_actions_addclose(&actions, descriptors[1])
    guard setup == 0 else { close(descriptors[1]); return nil }
    var attributes: posix_spawnattr_t?
    guard posix_spawnattr_init(&attributes) == 0 else { close(descriptors[1]); return nil }
    defer { posix_spawnattr_destroy(&attributes) }
    guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else {
        close(descriptors[1]); return nil
    }
    let arguments: [UnsafeMutablePointer<CChar>?] = ["/bin/launchctl", command].map { text in text.withCString { strdup($0) } } + [nil]
    defer { for argument in arguments { if let argument { free(argument) } } }
    let environment: [UnsafeMutablePointer<CChar>?] = ["PATH=/usr/bin:/bin", "LC_ALL=C"].map { text in text.withCString { strdup($0) } } + [nil]
    defer { for item in environment { if let item { free(item) } } }
    var child: pid_t = 0
    let spawned = arguments.withUnsafeBufferPointer { argv in
        environment.withUnsafeBufferPointer { env in
            posix_spawn(&child, "/bin/launchctl", &actions, &attributes,
                        UnsafeMutablePointer(mutating: argv.baseAddress!), UnsafeMutablePointer(mutating: env.baseAddress!))
        }
    }
    close(descriptors[1])
    guard spawned == 0 else { return nil }
    let deadline = ProcessInfo.processInfo.systemUptime + 2
    var status: Int32 = 0
    while true {
        let result = waitpid(child, &status, WNOHANG)
        if result == child { break }
        if result < 0 {
            if errno == EINTR { continue }
            // Do not signal a PID after ECHILD or uncertain ownership.
            return nil
        }
        if ProcessInfo.processInfo.systemUptime >= deadline {
            // This exact child has NOT been reaped. SIGCHLD is default, so its
            // PID cannot be reused between waitpid(0) and this signal.
            _ = kill(child, SIGKILL)
            while waitpid(child, &status, 0) < 0 { if errno != EINTR { break } }
            return nil
        }
        usleep(10_000)
    }
    guard status == 0 else { return nil }
    let flags = fcntl(descriptors[0], F_GETFL)
    guard flags >= 0, fcntl(descriptors[0], F_SETFL, flags | O_NONBLOCK) == 0 else { return nil }
    var buffer = [UInt8](repeating: 0, count: 257)
    let count = read(descriptors[0], &buffer, buffer.count)
    guard count > 0 && count <= 256,
          let output = String(bytes: buffer.prefix(Int(count)), encoding: .utf8) else { return nil }
    return output.trimmingCharacters(in: .whitespacesAndNewlines)
}

func verifiedGroups(_ expected: UInt32) -> Bool {
    guard let account = getpwuid(expected), account.pointee.pw_uid == expected,
          let name = account.pointee.pw_name else { return false }
    let primary = account.pointee.pw_gid
    let username = String(cString: name) // Never serialized or used as an exec argument.
    guard getgid() == primary, getegid() == primary else { return false }
    var allowed = [Int32](repeating: 0, count: 1024)
    var allowedCount = Int32(allowed.count)
    let result = username.withCString { user in
        allowed.withUnsafeMutableBufferPointer { groups in
            getgrouplist(user, Int32(bitPattern: primary), groups.baseAddress, &allowedCount)
        }
    }
    guard result >= 0, allowedCount > 0, allowedCount <= allowed.count else { return false }
    var actual = [gid_t](repeating: 0, count: 1024)
    let actualCount = getgroups(Int32(actual.count), &actual)
    guard actualCount >= 0, actualCount <= actual.count else { return false }
    let allowedSet = Set(allowed.prefix(Int(allowedCount)).map { gid_t(bitPattern: $0) }).union([primary])
    let actualSet = Set(actual.prefix(Int(actualCount))).union([getgid(), getegid()])
    // Missing memberships do not add privilege; unexpected inherited groups do.
    return actualSet.isSubset(of: allowedSet)
}

func verifiedSession(_ expected: UInt32) -> Bool {
    guard getuid() == expected, geteuid() == expected, verifiedGroups(expected),
          let bootstrapUID = launchctlIdentity("manageruid"), uidArgument(bootstrapUID) == expected,
          launchctlIdentity("managername") == "Aqua" else { return false }
    var uid: uid_t = 0
    var gid: gid_t = 0
    guard SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) != nil, uid == expected else { return false }
    return true
}

enum Control { case line(String), closed, timeout, invalid }
func readControl() -> Control {
    let deadline = ProcessInfo.processInfo.systemUptime + 2
    var data = Data()
    while ProcessInfo.processInfo.systemUptime < deadline {
        var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN | POLLHUP), revents: 0)
        let ready = poll(&descriptor, 1, 50)
        if ready < 0 { if errno == EINTR { continue }; return .invalid }
        if ready == 0 { continue }
        if descriptor.revents & Int16(POLLERR | POLLNVAL) != 0 { return .invalid }
        var chunk = [UInt8](repeating: 0, count: 65)
        let count = read(STDIN_FILENO, &chunk, chunk.count)
        if count < 0 { if errno == EINTR { continue }; return .invalid }
        if count == 0 { return .closed }
        data.append(contentsOf: chunk.prefix(Int(count)))
        if data.count > 64 { return .invalid }
        if let newline = data.firstIndex(of: 10) {
            guard newline == data.index(before: data.endIndex),
                  ProcessInfo.processInfo.systemUptime < deadline,
                  let line = String(data: data.dropLast(), encoding: .ascii) else { return .invalid }
            return .line(line)
        }
    }
    return .timeout
}

// Administrator launchers may pass blocked signals. Do not inherit that mask
// into diagnostics. Own/reap every child ourselves; never permit auto-reaping.
var empty = sigset_t()
sigemptyset(&empty)
guard sigprocmask(SIG_SETMASK, &empty, nil) == 0 else { reject("signal_setup_failed") }
signal(SIGCHLD, SIG_DFL)
signal(SIGPIPE, SIG_IGN)
let args = CommandLine.arguments
if args.count == 3 && args[1] == "--probe-session" {
    guard let uid = uidArgument(args[2]) else { reject("invalid_uid") }
    guard verifiedSession(uid) else { reject("session_unverified") }
    emit("identity_verified", uid: uid)
    exit(0)
}
guard args.count == 6, args[1] == "--prepare",
      args[2].range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
      let uid = uidArgument(args[3]), ["start", "stop"].contains(args[4]),
      args[5].range(of: "^[A-Fa-f0-9]{8}(-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$", options: .regularExpression) != nil else {
    reject("invalid_request")
}
let ticket = args[2]
guard verifiedSession(uid) else { reject("session_unverified", ticket: ticket) }
emit("ready", ticket: ticket, uid: uid)
switch readControl() {
case .closed: emit("cancelled", reason: "parent_closed", ticket: ticket, uid: uid)
case .timeout: emit("cancelled", reason: "grant_timeout", ticket: ticket, uid: uid)
case .invalid: reject("invalid_control", ticket: ticket)
case .line(let line):
    if line == "CANCEL " + ticket {
        emit("cancelled", reason: "cancelled_by_parent", ticket: ticket, uid: uid)
    } else if line == "GRANT " + ticket {
        // Deliberately no native VPN command. A valid grant is NOT a claim that
        // recovery happened, nor a ready-to-deploy supervisor implementation.
        emit("execution_disabled", reason: "prototype_no_executor", ticket: ticket, uid: uid)
    } else { reject("invalid_control", ticket: ticket) }
}
