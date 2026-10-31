import Foundation
import Darwin

// Explicit diagnostic fixtures ONLY. No arbitrary argv, scutil, shell, or VPN.
enum ProbeFixture: String {
    case identity, wait
    var arguments: [String] {
        switch self {
        case .identity: return ["/usr/bin/id", "-u"]
        case .wait: return ["/bin/sleep", "10"]
        }
    }
}

private enum ChildControl { case none, cancel, closed, invalid }
private struct CancellationReader {
    var buffer = Data()
    mutating func poll(_ ticket: String) -> ChildControl {
        var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN | POLLHUP), revents: 0)
        let ready = Darwin.poll(&descriptor, 1, 0)
        if ready < 0 { return errno == EINTR ? .none : .invalid }
        if ready == 0 { return .none }
        if descriptor.revents & Int16(POLLERR | POLLNVAL) != 0 { return .invalid }
        var chunk = [UInt8](repeating: 0, count: 65)
        let count = read(STDIN_FILENO, &chunk, chunk.count)
        if count < 0 { return errno == EINTR ? .none : .invalid }
        if count == 0 { return .closed }
        buffer.append(contentsOf: chunk.prefix(Int(count)))
        guard buffer.count <= 64 else { return .invalid }
        guard let newline = buffer.firstIndex(of: 10) else { return .none }
        guard newline == buffer.index(before: buffer.endIndex),
              String(data: buffer.dropLast(), encoding: .ascii) == "CANCEL " + ticket else { return .invalid }
        return .cancel
    }
}

// The only PID used here comes directly from posix_spawn. Never accept a caller
// PID, signal a process group, or signal after reaping/uncertain ownership.
private final class OwnedProbeChild {
    let pid: pid_t
    let output: Int32
    private(set) var reaped = false
    private(set) var status: Int32 = 0
    private var ownershipUnknown = false

    init?(_ fixture: ProbeFixture) {
        var descriptors: [Int32] = [-1, -1]
        guard pipe(&descriptors) == 0 else { return nil }
        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            close(descriptors[0]); close(descriptors[1]); return nil
        }
        defer { posix_spawn_file_actions_destroy(&actions) }
        var setup: Int32 = 0
        setup |= posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0)
        setup |= posix_spawn_file_actions_adddup2(&actions, descriptors[1], STDOUT_FILENO)
        setup |= posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0)
        setup |= posix_spawn_file_actions_addclose(&actions, descriptors[0])
        setup |= posix_spawn_file_actions_addclose(&actions, descriptors[1])
        var attributes: posix_spawnattr_t?
        guard setup == 0, posix_spawnattr_init(&attributes) == 0 else {
            close(descriptors[0]); close(descriptors[1]); return nil
        }
        defer { posix_spawnattr_destroy(&attributes) }
        let flags = fcntl(descriptors[0], F_GETFL)
        guard flags >= 0, fcntl(descriptors[0], F_SETFL, flags | O_NONBLOCK) == 0,
              posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED)) == 0 else {
            close(descriptors[0]); close(descriptors[1]); return nil
        }
        let arguments = fixture.arguments.map { text in text.withCString { strdup($0) } }
        let environment = ["PATH=/usr/bin:/bin", "LC_ALL=C"].map { text in text.withCString { strdup($0) } }
        defer {
            for pointer in arguments + environment { if let pointer { free(pointer) } }
        }
        guard arguments.allSatisfy({ $0 != nil }), environment.allSatisfy({ $0 != nil }) else {
            close(descriptors[0]); close(descriptors[1]); return nil
        }
        let argv = arguments + [nil]
        let env = environment + [nil]
        var child: pid_t = 0
        let result = argv.withUnsafeBufferPointer { args in
            env.withUnsafeBufferPointer { vars in
                posix_spawn(&child, fixture.arguments[0], &actions, &attributes,
                            UnsafeMutablePointer(mutating: args.baseAddress!), UnsafeMutablePointer(mutating: vars.baseAddress!))
            }
        }
        close(descriptors[1])
        guard result == 0, child > 0 else { close(descriptors[0]); return nil }
        pid = child
        output = descriptors[0]
    }

    deinit { close(output) } // Never invent completion or signal from deinit.

    // true = reaped, false = still owned/unreaped, nil = unknown. ECHILD is NOT
    // termination proof; an uncertain PID must never be signalled later.
    func observe() -> Bool? {
        if ownershipUnknown { return nil }
        if reaped { return true }
        while true {
            let result = waitpid(pid, &status, WNOHANG)
            if result == pid { reaped = true; return true }
            if result == 0 { return false }
            if errno != EINTR { ownershipUnknown = true; return nil }
        }
    }

    func birth(_ uid: UInt32) -> (UInt64, UInt64)? {
        var info = proc_bsdinfo()
        let count = withUnsafeMutableBytes(of: &info) { buffer in
            proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, buffer.baseAddress, Int32(buffer.count))
        }
        guard count == MemoryLayout<proc_bsdinfo>.size, info.pbi_pid == UInt32(pid),
              info.pbi_ppid == UInt32(getpid()), info.pbi_uid == uid, info.pbi_ruid == uid,
              info.pbi_gid == getegid(), info.pbi_rgid == getgid(),
              info.pbi_start_tvsec > 0, info.pbi_start_tvusec < 1_000_000 else { return nil }
        return (info.pbi_start_tvsec, info.pbi_start_tvusec)
    }

    func resume() -> Bool {
        guard let finished = observe(), !finished else { return false }
        return kill(pid, SIGCONT) == 0 // Exact owned, still-unreaped child only.
    }

    func cancelAndReap() -> Bool {
        guard let finished = observe() else { return false }
        if finished { return true }
        // Default SIGCHLD + our sole wait ownership keeps this exact PID reserved,
        // even if it exits between observe(false) and kill. No PID lookup race.
        _ = kill(pid, SIGKILL)
        let deadline = ProcessInfo.processInfo.systemUptime + 1
        while ProcessInfo.processInfo.systemUptime < deadline {
            guard let finished = observe() else { return false }
            if finished { return true }
            usleep(10_000)
        }
        return false
    }

    var exitCode: Int? {
        guard reaped else { return nil }
        let signalNumber = status & 0x7f
        return signalNumber == 0 ? Int((status >> 8) & 0xff) : -Int(signalNumber)
    }

    func identityMatches(_ uid: UInt32) -> Bool {
        guard reaped, exitCode == 0 else { return false }
        var bytes = [UInt8](repeating: 0, count: 65)
        let count = read(output, &bytes, bytes.count)
        guard count > 0, count <= 64,
              let text = String(bytes: bytes.prefix(Int(count)), encoding: .ascii) else { return false }
        return text.trimmingCharacters(in: .whitespacesAndNewlines) == String(uid)
    }
}

func superviseProbe(_ fixture: ProbeFixture, ticket: String, uid: UInt32) -> Int32 {
    // Recheck at the diagnostic spawn boundary, not merely before Ready.
    guard verifiedSession(uid) else { reject("session_unverified", ticket: ticket) }
    guard let child = OwnedProbeChild(fixture) else { reject("probe_spawn_failed", ticket: ticket) }
    var reason: String? = nil
    let birth = child.birth(uid)
    if birth == nil { reason = "child_identity_unavailable" }
    // START_SUSPENDED prevents user-space execution (including dyld startup).
    // The fixture parent must explicitly permit EXEC after seeing this identity.
    // A future ROOT parent must durably record/validate the witness first; this
    // diagnostic handshake itself does NOT authenticate or persist that proof.
    if reason == nil && !emit("probe_staged", ticket: ticket, uid: uid, childPID: child.pid,
                             birthSeconds: birth?.0, birthMicroseconds: birth?.1) {
        reason = "parent_output_closed"
    }
    if reason == nil {
        switch readControl() {
        case .closed: reason = "parent_closed"
        case .timeout: reason = "execution_grant_timeout"
        case .invalid: reason = "invalid_control"
        case .line(let line):
            if line == "CANCEL " + ticket { reason = "cancelled_by_parent" }
            else if line != "EXEC " + ticket { reason = "invalid_control" }
            else if !verifiedSession(uid) { reason = "session_unverified" }
            else if !child.resume() { reason = "probe_resume_failed" }
            else if !emit("probe_started", ticket: ticket, uid: uid, childPID: child.pid,
                          birthSeconds: birth?.0, birthMicroseconds: birth?.1) { reason = "parent_output_closed" }
        }
    }
    var control = CancellationReader()
    let deadline = ProcessInfo.processInfo.systemUptime + 2
    var terminated = false
    while reason == nil {
        guard let finished = child.observe() else { reason = "child_state_unknown"; break }
        if finished { terminated = true; reason = "probe_exited"; break }
        if ProcessInfo.processInfo.systemUptime >= deadline { reason = "probe_timeout"; break }
        switch control.poll(ticket) {
        case .none: usleep(10_000)
        case .cancel: reason = "cancelled_by_parent"
        case .closed: reason = "parent_closed"
        case .invalid: reason = "invalid_control"
        }
    }
    if !terminated && reason != "child_state_unknown" { terminated = child.cancelAndReap() }
    if terminated && reason == "probe_exited" {
        if child.exitCode != 0 { reason = "probe_failed" }
        else if fixture == .identity && !child.identityMatches(uid) { reason = "probe_identity_mismatch" }
    }
    let sent = emit(terminated ? "probe_finished" : "supervision_unknown", reason: reason,
                    ticket: ticket, uid: uid, childPID: child.pid, terminated: terminated, exitCode: child.exitCode,
                    birthSeconds: birth?.0, birthMicroseconds: birth?.1)
    if !sent { return 3 }
    let expected = ["probe_exited", "cancelled_by_parent", "parent_closed", "probe_timeout", "execution_grant_timeout"]
    return terminated && expected.contains(reason ?? "") ? 0 : 2
}
