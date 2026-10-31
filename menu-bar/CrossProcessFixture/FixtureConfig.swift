import Foundation
import Darwin

// Test harness ONLY. User-owned fixture pins/config are NOT production trust.
enum FixtureFailure: Error { case unavailable }

struct FixtureConfig {
    let path: URL
    var values: [String: Any]

    init() throws {
        guard geteuid() != 0,
              let text = Bundle.main.object(forInfoDictionaryKey: "FixtureConfigPath") as? String,
              text.hasPrefix("/") else { throw FixtureFailure.unavailable }
        path = URL(fileURLWithPath: text)
        var info = stat()
        guard lstat(text, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == geteuid(), info.st_mode & 0o777 == 0o600, info.st_nlink == 1,
              info.st_size > 0, info.st_size <= 4096 else { throw FixtureFailure.unavailable }
        let data = try Data(contentsOf: path)
        guard data.count <= 4096, let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              (value["uid"] as? NSNumber)?.uint32Value == geteuid() else { throw FixtureFailure.unavailable }
        values = value
    }

    var ticket: String { values["ticket"] as? String ?? "" }
    var serviceName: String { values["service_name"] as? String ?? "" }
    var parentPID: Int32 { (values["parent_pid"] as? NSNumber)?.int32Value ?? 0 }
    var parentBirthSeconds: UInt64 { (values["parent_birth_seconds"] as? NSNumber)?.uint64Value ?? 0 }
    var parentBirthMicroseconds: UInt64 { (values["parent_birth_microseconds"] as? NSNumber)?.uint64Value ?? 0 }
    func pin(_ field: String) throws -> PeerPin { return try PeerPin(values[field] as? String ?? "") }

    mutating func bindCurrentParent() throws {
        guard let info = fixtureProcess(getpid()), info.pbi_uid == geteuid(), info.pbi_ruid == getuid() else {
            throw FixtureFailure.unavailable
        }
        values["parent_pid"] = getpid()
        values["parent_birth_seconds"] = info.pbi_start_tvsec
        values["parent_birth_microseconds"] = info.pbi_start_tvusec
        try JSONSerialization.data(withJSONObject: values, options: [.sortedKeys]).write(to: path, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
    }

    func parentStillMatches() -> Bool {
        guard parentPID > 0, let info = fixtureProcess(parentPID) else { return false }
        return info.pbi_uid == geteuid() && info.pbi_ruid == geteuid() && info.pbi_svuid == geteuid()
            && info.pbi_start_tvsec == parentBirthSeconds && info.pbi_start_tvusec == parentBirthMicroseconds
    }

    func result(_ passed: Bool) {
        let summary: [String: Any] = ["passed": passed, "read_only": true, "root_operations": false,
                                      "vpn_commands": false, "fixture": "cross_process_xpc_handoff"]
        if let data = try? JSONSerialization.data(withJSONObject: summary, options: [.sortedKeys]) {
            let url = path.deletingLastPathComponent().appendingPathComponent("result.json")
            try? data.write(to: url, options: [.atomic])
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            if let text = String(data: data, encoding: .utf8) { print(text) }
        }
    }
}

func fixtureProcess(_ pid: Int32) -> proc_bsdinfo? {
    guard pid > 0 else { return nil }
    var info = proc_bsdinfo()
    let count = withUnsafeMutableBytes(of: &info) { raw in
        proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, raw.baseAddress, Int32(raw.count))
    }
    guard count == MemoryLayout<proc_bsdinfo>.size, info.pbi_pid == UInt32(pid),
          info.pbi_start_tvsec > 0, info.pbi_start_tvusec < 1_000_000 else { return nil }
    return info
}
