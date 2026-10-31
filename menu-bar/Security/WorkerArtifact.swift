import Foundation
import Darwin
import Security

// Prelaunch artifact check only. NOT a process/connection authentication lease.
enum WorkerArtifactError: Error {
    case unsafePath, unsafeArtifact, changedArtifact, invalidSignature, unsafeSigningOptions
}

struct WorkerArtifact {
    private static func info(_ path: String) throws -> stat {
        var value = stat()
        guard path.withCString({ lstat($0, &value) }) == 0 else { throw WorkerArtifactError.unsafePath }
        return value
    }

    private static func restrictiveACL(_ path: String) throws {
        let before = try info(path)
        errno = 0
        guard let acl = path.withCString({ acl_get_link_np($0, ACL_TYPE_EXTENDED) }) else {
            let failure = errno
            // Darwin also returns ENOENT for an existing object with NO extended
            // ACL. Do not confuse it with disappearance: require unchanged lstat.
            guard failure == ENOENT, same(before, try info(path)) else {
                throw WorkerArtifactError.unsafePath
            }
            return
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard acl_valid(acl) == 0 else { throw WorkerArtifactError.unsafePath }
        var index = ACL_FIRST_ENTRY
        for _ in 0..<1024 {
            var entry: acl_entry_t?
            errno = 0
            let result = acl_get_entry(acl, index.rawValue, &entry)
            if result == -1 && errno == EINVAL { return } // End of a validated ACL.
            guard result == 0, let entry else { throw WorkerArtifactError.unsafePath }
            var tag = acl_tag_t(0)
            guard acl_get_tag_type(entry, &tag) == 0, tag == ACL_EXTENDED_DENY else {
                // Reject ALL allow ACLs, even apparently harmless ones. POSIX
                // 0755 alone does not exclude unprivileged ACL write/security grants.
                throw WorkerArtifactError.unsafePath
            }
            index = ACL_NEXT_ENTRY
        }
        throw WorkerArtifactError.unsafePath
    }

    private static func same(_ a: stat, _ b: stat) -> Bool {
        return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid
            && a.st_mode == b.st_mode && a.st_nlink == b.st_nlink && a.st_size == b.st_size
            && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec
            && a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }

    static func validate(_ url: URL, pin: PeerPin) throws {
        try validateOwned(url, pin: pin, expectedOwner: 0)
    }

    #if WORKER_ARTIFACT_FIXTURES
    static func validateFixture(_ url: URL, pin: PeerPin, expectedOwner: uid_t) throws {
        guard expectedOwner != 0, expectedOwner == geteuid() else { throw WorkerArtifactError.unsafeArtifact }
        try validateOwned(url, pin: pin, expectedOwner: expectedOwner)
    }
    #endif

    private static func validateOwned(_ url: URL, pin: PeerPin, expectedOwner: uid_t) throws {
        let path = url.path
        guard url.isFileURL, url.host == nil || url.host == "", path.hasPrefix("/"), !path.utf8.contains(0),
              path == url.standardizedFileURL.path, expectedOwner != UInt32.max else {
            throw WorkerArtifactError.unsafePath
        }
        // Production entry point fixes ownership to root, with no UID parameter.
        // The non-root fixture entry point exists only in the separate TEST build.
        var directory = url.deletingLastPathComponent()
        while true {
            let value = try info(directory.path)
            guard (value.st_mode & S_IFMT) == S_IFDIR,
                  [uid_t(0), expectedOwner].contains(value.st_uid), value.st_mode & 0o022 == 0,
                  expectedOwner != 0 || value.st_mode & 0o111 == 0o111 else {
                throw WorkerArtifactError.unsafePath
            }
            try restrictiveACL(directory.path)
            if directory.path == "/" { break }
            directory.deleteLastPathComponent()
        }
        let before = try info(path)
        guard (before.st_mode & S_IFMT) == S_IFREG, before.st_nlink == 1,
              before.st_uid == expectedOwner, before.st_mode & 0o022 == 0,
              before.st_mode & 0o6000 == 0, before.st_mode & 0o777 == 0o755 else {
            throw WorkerArtifactError.unsafeArtifact
        }
        try restrictiveACL(path)
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else {
            throw WorkerArtifactError.invalidSignature
        }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(pin.requirement as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw WorkerArtifactError.invalidSignature
        }
        var raw: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
              let signing = raw as? [String: Any],
              let flags = signing[kSecCodeInfoFlags as String] as? NSNumber,
              flags.uint32Value & 0x10000 != 0 else { // CS_RUNTIME, public codesign flag.
            throw WorkerArtifactError.unsafeSigningOptions
        }
        // This worker needs NO entitlements. Do not permit debug, JIT, DYLD,
        // disabled library validation or other exceptions via a permissive list.
        if let entitlements = signing[kSecCodeInfoEntitlementsDict as String] {
            guard let dictionary = entitlements as? [String: Any], dictionary.isEmpty else {
                throw WorkerArtifactError.unsafeSigningOptions
            }
        }
        guard same(before, try info(path)) else { throw WorkerArtifactError.changedArtifact }
        // Parent directories are protected from unprivileged replacement in the
        // ROOT-owner deployment. Rechecks do not make mutable fixture paths safe.
    }
}
