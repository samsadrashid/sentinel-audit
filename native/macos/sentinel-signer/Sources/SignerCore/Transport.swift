import Foundation

/// USB transport (protocol §6). Read-only intake into a private spool, and atomic exclusive output.
public enum AtomicFile {
    /// Write `bytes` to `url` via a temporary sibling (O_CREAT|O_EXCL|O_NOFOLLOW), fsync, rename, fsync dir.
    /// With `replace == false` an existing target is refused (never overwritten).
    public static func write(_ bytes: [UInt8], to url: URL, mode: mode_t, replace: Bool) throws {
        let dir = url.deletingLastPathComponent()
        let tmp = dir.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        if !replace, FileManager.default.fileExists(atPath: url.path) { throw Refusal(code: "output_exists") }
        let fd = open(tmp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard fd >= 0 else { throw Refusal(code: "output_unwritable") }
        let ok = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, bytes.count) } == bytes.count && fsync(fd) == 0
        close(fd)
        guard ok else { unlink(tmp.path); throw Refusal(code: "output_unwritable") }
        if !replace {
            // renamex_np with RENAME_EXCL: refuse if the target appeared meanwhile.
            guard renamex_np(tmp.path, url.path, UInt32(RENAME_EXCL)) == 0 else { unlink(tmp.path); throw Refusal(code: "output_exists") }
        } else {
            guard rename(tmp.path, url.path) == 0 else { unlink(tmp.path); throw Refusal(code: "output_unwritable") }
        }
        let dfd = open(dir.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        if dfd >= 0 { fsync(dfd); close(dfd) }
    }
}

public struct IntakeItem { public let requestId: String; public let bytes: [UInt8]; public let sha256: String }

public struct IntakeResult {
    public var items: [IntakeItem] = []
    public var ignored: [String] = []
    public var refused: [(String, String)] = []
    public var audit: [UInt8]?  // `trust-store-audit.json`, if present
}

public struct VolumeInfo: Equatable {
    public let fsType: String, flags: UInt32, encrypted: Bool
    public init(fsType: String, flags: UInt32, encrypted: Bool) { (self.fsType, self.flags, self.encrypted) = (fsType, flags, encrypted) }
}

public enum Transport {
    public static let maxRequestsPerIntake = 16
    public static let auditName = "trust-store-audit.json"

    public static func volumeInfo(_ url: URL) -> VolumeInfo? {
        var s = statfs()
        guard statfs(url.path, &s) == 0 else { return nil }
        let t = withUnsafePointer(to: s.f_fstypename) { $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) } }
        // Unknown encryption state counts as encrypted: fail closed, never prompt.
        let enc = (try? url.resourceValues(forKeys: [.volumeIsEncryptedKey]))?.volumeIsEncrypted ?? true
        return VolumeInfo(fsType: t, flags: s.f_flags, encrypted: enc)
    }

    /// Protocol R3.2, before any file access: APFS, not encrypted, and mounted nobrowse, noexec, nosuid,
    /// nodev; read-only for intake, read-write for output.
    public static func volumeProblem(_ i: VolumeInfo?, readOnly: Bool) -> String? {
        guard let i else { return "volume_unreadable" }
        guard i.fsType == "apfs" else { return "fs_not_apfs" }
        guard !i.encrypted else { return "fs_encrypted" }
        let need = UInt32(MNT_NOEXEC | MNT_NOSUID | MNT_NODEV | MNT_DONTBROWSE) | (readOnly ? UInt32(MNT_RDONLY) : 0)
        guard i.flags & need == need else { return "mount_flags" }
        if !readOnly, i.flags & UInt32(MNT_RDONLY) != 0 { return "volume_read_only" }
        return nil
    }

    public static let realCheck: (URL, Bool) -> String? = { volumeProblem(volumeInfo($0), readOnly: $1) }

    /// Open a directory component strictly: no symlink, must be a directory.
    public static func openDir(_ parent: Int32, _ name: String) throws -> Int32 {
        var st = stat()
        guard fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) == 0 else { throw Refusal(code: "missing_\(name)") }
        if (st.st_mode & S_IFMT) == S_IFLNK { throw Refusal(code: "symlinked_directory") }
        guard (st.st_mode & S_IFMT) == S_IFDIR else { throw Refusal(code: "not_a_directory") }
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Refusal(code: errno == ELOOP ? "symlinked_directory" : "missing_\(name)") }
        return fd
    }

    /// Protocol §6.2: O_RDONLY|O_NOFOLLOW|O_NONBLOCK; a regular single-link file within the limit; read
    /// at most limit + 1 bytes and require exactly st_size.
    public static func readStrict(_ dir: Int32, _ name: String, limit: Int) -> Result<[UInt8], Refusal> {
        let fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return .failure(Refusal(code: errno == ELOOP ? "symlink" : "unopenable")) }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return .failure(Refusal(code: "not_regular_file")) }
        guard st.st_nlink == 1 else { return .failure(Refusal(code: "hard_linked")) }
        guard st.st_size > 0, st.st_size <= limit else { return .failure(Refusal(code: "bad_size")) }
        let cap = limit + 1
        var buf = [UInt8](repeating: 0, count: cap)
        var got = 0
        while got < cap {
            let offset = got
            let r = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress! + offset, cap - offset) }
            if r <= 0 { break }
            got += r
        }
        guard got > 0, got <= limit, got == Int(st.st_size) else { return .failure(Refusal(code: "bad_size")) }
        return .success(Array(buf[0..<got]))
    }

    /// Protocol §6.2 and R3.1: walk only `<volume>/sentinel-v1/to-signer`, stage every accepted file, and
    /// move the staged set into the private spool only when the whole intake succeeded. Any error discards
    /// the staged set. Later processing reads only the spool copy.
    public static func intake(volume: URL, spool: URL, volumeCheck: (URL, Bool) -> String? = realCheck) throws -> IntakeResult {
        if let bad = volumeCheck(volume, true) { throw Refusal(code: bad) }
        let vfd = open(volume.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard vfd >= 0 else { throw Refusal(code: "volume_unreadable") }
        defer { close(vfd) }
        let root = try openDir(vfd, "sentinel-v1")
        defer { close(root) }
        let to = try openDir(root, "to-signer")
        defer { close(to) }
        guard let dirp = fdopendir(dup(to)) else { throw Refusal(code: "to_signer_unreadable") }
        defer { closedir(dirp) }
        var names: [String] = []
        while let ent = readdir(dirp) {
            let name = withUnsafePointer(to: ent.pointee.d_name) { $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) } }
            if name != "." && name != ".." { names.append(name) }
        }
        var result = IntakeResult()
        let pattern = try NSRegularExpression(pattern: "^req-([0-9a-f]{32})\\.json$")
        let candidates = names.sorted().filter { n in
            if pattern.firstMatch(in: n, range: NSRange(n.startIndex..., in: n)) != nil { return true }
            if n != auditName { result.ignored.append(n) }
            return false
        }
        if candidates.count > maxRequestsPerIntake { throw Refusal(code: "too_many_requests") }
        try FileManager.default.createDirectory(at: spool, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        for old in (try? FileManager.default.contentsOfDirectory(atPath: spool.path)) ?? [] where old.hasPrefix(".intake-") {
            try? FileManager.default.removeItem(at: spool.appendingPathComponent(old))  // an earlier interrupted intake
        }
        let stage = spool.appendingPathComponent(".intake-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: stage, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: stage) }
        for n in candidates {
            switch readStrict(to, n, limit: Policy.maxRequestBytes) {
            case let .failure(r): result.refused.append((n, r.code))
            case let .success(bytes):
                let rid = String(n.dropFirst(4).prefix(32))
                try AtomicFile.write(bytes, to: stage.appendingPathComponent("req-\(rid).json"), mode: 0o600, replace: false)
                result.items.append(IntakeItem(requestId: rid, bytes: bytes, sha256: sha256Hex(bytes)))
            }
        }
        if names.contains(auditName) {
            switch readStrict(to, auditName, limit: TrustAudit.maxBytes) {
            case let .failure(r): result.refused.append((auditName, r.code))
            case let .success(b): result.audit = b; try AtomicFile.write(b, to: stage.appendingPathComponent(auditName), mode: 0o600, replace: false)
            }
        }
        if let bad = volumeCheck(volume, true) { throw Refusal(code: bad) }  // the volume changed or vanished: discard
        for f in try FileManager.default.contentsOfDirectory(atPath: stage.path) {
            let dst = spool.appendingPathComponent(f)
            try? FileManager.default.removeItem(at: dst)
            try FileManager.default.moveItem(at: stage.appendingPathComponent(f), to: dst)
        }
        return result
    }

    /// Protocol §6.3: write a file under `from-signer/` exclusively; never overwrite or delete DM files.
    public static func writeOutput(volume: URL, name: String, body: [UInt8], volumeCheck: (URL, Bool) -> String? = realCheck) throws -> URL {
        guard body.count <= 2048 else { throw Refusal(code: "response_too_large") }
        if let bad = volumeCheck(volume, false) { throw Refusal(code: bad) }
        let vfd = open(volume.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard vfd >= 0 else { throw Refusal(code: "volume_unreadable") }
        defer { close(vfd) }
        var st = stat()
        if fstatat(vfd, "sentinel-v1", &st, AT_SYMLINK_NOFOLLOW) != 0 { _ = mkdirat(vfd, "sentinel-v1", 0o755) }  // a blank drive
        let root = try openDir(vfd, "sentinel-v1")
        close(root)
        let from = volume.appendingPathComponent("sentinel-v1/from-signer")
        if lstat(from.path, &st) == 0, (st.st_mode & S_IFMT) != S_IFDIR { throw Refusal(code: "symlinked_directory") }
        if !FileManager.default.fileExists(atPath: from.path) {
            try FileManager.default.createDirectory(at: from, withIntermediateDirectories: false)
        }
        let out = from.appendingPathComponent(name)
        try AtomicFile.write(body, to: out, mode: 0o644, replace: false)
        return out
    }

    public static func writeResponse(volume: URL, requestId: String, body: [UInt8], volumeCheck: (URL, Bool) -> String? = realCheck) throws -> URL {
        try writeOutput(volume: volume, name: "resp-\(requestId).json", body: body, volumeCheck: volumeCheck)
    }
}
