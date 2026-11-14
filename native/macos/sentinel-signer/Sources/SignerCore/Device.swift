import Foundation

/// The signing device's private state directory (0700) and every state-changing step, shared by the
/// signer CLI and the TEST-ONLY interop driver, so both exercise exactly the same logic.
public final class Device {
    public let dir: URL, spool: URL, outbox: URL, delivered: URL, versions: URL
    public var registry: Registry
    /// Protocol R3.2 volume checks. Only the TEST-ONLY interop driver replaces this.
    public var volumeCheck: (URL, Bool) -> String? = Transport.realCheck
    public let ledger: Ledger
    public let log: AuditLog
    var registryPath: URL { dir.appendingPathComponent("registry.json") }

    public init(dir: URL) throws {
        self.dir = dir
        (spool, outbox, delivered, versions) = (dir.appendingPathComponent("spool"), dir.appendingPathComponent("outbox"),
                                                dir.appendingPathComponent("delivered"), dir.appendingPathComponent("versions"))
        for d in [dir, spool, outbox, delivered, versions] {
            try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        let rp = dir.appendingPathComponent("registry.json")
        registry = try FileManager.default.contents(atPath: rp.path).map { try Registry.decode(Array($0)) } ?? Registry()
        ledger = try Ledger(path: dir.appendingPathComponent("ledger.json"))
        log = try AuditLog(path: dir.appendingPathComponent("log.jsonl"))
    }

    public func save() throws { try AtomicFile.write(registry.encode(), to: registryPath, mode: 0o600, replace: true) }

    /// SD-T55: the operator confirmed the clock against an independent source.
    public func clockChecked(now: Int64) throws {
        if let c = registry.clockCheckedAt, now < c { throw Refusal(code: "clock_regressed") }
        registry.clockCheckedAt = now
        try save()
        try log.append("clock_checked", [], now: now)
    }

    /// A new key the SD holds but the DM doesn't yet trust. It becomes active only by a committed key.rotate.
    public func addCandidate(_ k: RegistryKey, now: Int64) throws {
        guard registry.keys[k.keyId] == nil, k.status == "candidate" else { throw Refusal(code: "duplicate_key") }
        guard !k.operatorName.isEmpty, k.operatorName.count <= 128, k.operatorName.allSatisfy({ $0.isASCII && !$0.isNewline }),
              k.expiresAt > now else { throw Refusal(code: "bad_key_metadata") }
        registry.keys[k.keyId] = k
        try save()
        try log.append("registry_changed", [("key_id", .string(k.keyId)), ("change", .string("candidate_added")),
                                            ("role", .string(k.role)), ("fingerprint", .string(k.fingerprint))], now: now)
    }

    /// Validate one spooled request; refusals are logged and produce nothing (O-P1).
    public func validate(_ bytes: [UInt8], requestId: String, now: Int64) throws -> ValidatedRequest {
        do {
            return try validateRequest(bytes, fileRequestId: requestId, registry: registry, ledger: ledger, now: now)
        } catch let r as Refusal {
            try log.append("refused", [("request_id", .string(requestId)), ("reason", .string(r.code))], now: now)
            throw r
        }
    }

    /// After the presence check: sign (operator key) or assert (recovery key), self-check, record, queue.
    public func sign(_ v: ValidatedRequest, key: SigningKey?, authenticator: RecoveryAuthenticator?, now: Int64) throws -> [UInt8] {
        var body: [UInt8], counter: RecoveryCredential?
        if v.signerRole == "recovery" {
            guard let auth = authenticator, let k = registry.keys[v.keyId], let cred = k.recovery else { throw Refusal(code: "authenticator_missing") }
            let a = try auth.assert(challenge: Recovery.challenge(v.payload), credentialId: cred.credentialId)
            do { counter = try Recovery.verify(a, payload: v.payload, key: k) } catch let r as Refusal {
                if Recovery.suspectCodes.contains(r.code) { registry.keys[v.keyId]?.suspect = true; try save() }
                try log.append("refused", [("request_id", .string(v.requestId)), ("reason", .string(r.code))], now: now)
                throw r
            }
            body = Recovery.response(v, a)
        } else {
            guard let key else { throw Refusal(code: "key_missing") }
            body = try signResponse(v, key: key)
        }
        guard body.count <= 2048 else { throw Refusal(code: "response_too_large") }
        if let t = v.keyOpTarget {
            try registry.begin(PendingChange(requestId: v.requestId, payloadSHA256: v.payloadSHA256, action: v.action,
                                             expiresAt: v.expiresAt, target: t, signer: v.keyId, counter: counter))
        }
        try ledger.recordSigned(v)
        try save()
        try AtomicFile.write(body, to: outbox.appendingPathComponent("resp-\(v.requestId).json"), mode: 0o600, replace: false)
        try log.append("signed", [("request_id", .string(v.requestId)), ("payload_sha256", .string(v.payloadSHA256)),
                                  ("key_id", .string(v.keyId)), ("response_sha256", .string(sha256Hex(body)))], now: now)
        if let t = v.keyOpTarget {
            try log.append("registry_pending", [("action", .string(v.action)), ("target", .string(t))], now: now)
        }
        return body
    }

    /// Protocol §6.3 and R3.1: write queued responses; a failed write leaves it queued (`output_failed`),
    /// and a delivered response can be re-issued byte for byte, never re-signed (`output_reissued`).
    public func deliver(volume: URL, reissue: String? = nil, now: Int64) throws -> [String] {
        var done: [String] = []
        if let rid = reissue {
            guard hex32(rid), let bytes = FileManager.default.contents(atPath: delivered.appendingPathComponent("resp-\(rid).json").path)
            else { throw Refusal(code: "nothing_to_reissue") }
            _ = try Transport.writeResponse(volume: volume, requestId: rid, body: Array(bytes), volumeCheck: volumeCheck)
            try log.append("output_reissued", [("request_id", .string(rid)), ("response_sha256", .string(sha256Hex(Array(bytes))))], now: now)
            return [rid]
        }
        for f in try FileManager.default.contentsOfDirectory(atPath: outbox.path).filter({ $0.hasPrefix("resp-") }).sorted() {
            let rid = String(f.dropFirst(5).prefix(32))
            let src = outbox.appendingPathComponent(f), bytes = Array(try Data(contentsOf: src))
            do { _ = try Transport.writeResponse(volume: volume, requestId: rid, body: bytes, volumeCheck: volumeCheck) } catch let r as Refusal {
                try log.append("output_failed", [("request_id", .string(rid)), ("reason", .string(r.code))], now: now)
                continue
            }
            try FileManager.default.moveItem(at: src, to: delivered.appendingPathComponent(f))
            try log.append("output_written", [("request_id", .string(rid))], now: now)
            done.append(rid)
        }
        return done
    }

    // ── R3.1 registry state machine, driven only by the operator ──
    public func commitPending(now: Int64) throws {
        let p = try registry.commit()
        try save()
        try log.append("registry_changed", [("change", .string("committed")), ("action", .string(p.action)),
                                            ("key_id", .string(p.target)), ("payload_sha256", .string(p.payloadSHA256))], now: now)
    }

    public func abandonPending(now: Int64) throws {
        try registry.markAbandoning()
        try save()
        try log.append("registry_abandoning", [("key_id", .string(registry.pending?.target ?? ""))], now: now)
    }

    /// Resolve an abandon with a trust-store audit of the DM's `trust.json`.
    public func resolveAbandon(dmTrust: [UInt8], now: Int64) throws -> String {
        let report = try TrustAudit.compare(dmTrust, registry: registry)
        let outcome = try registry.resolveAbandon(now: now, changePresentOnDM: registry.changePresent(in: report.dmKeys))
        try save()
        try log.append("registry_changed", [("change", .string(outcome.lowercased())), ("dm_trust_sha256", .string(report.dmFingerprint))], now: now)
        return outcome
    }

    /// Intake into the spool with this device's volume check, logged (protocol §6.5).
    public func intake(volume: URL, now: Int64) throws -> IntakeResult {
        let res: IntakeResult
        do { res = try Transport.intake(volume: volume, spool: spool, volumeCheck: volumeCheck) } catch let r as Refusal {
            try log.append("intake_refused", [("reason", .string(r.code))], now: now)
            throw r
        }
        try log.append("intake", [
            ("files", .array(res.items.map { .object([("request_id", .string($0.requestId)), ("sha256", .string($0.sha256))]) })),
            ("ignored", .array(res.ignored.map { .string($0) })), ("refused", .array(res.refused.map { .string("\($0.0):\($0.1)") })),
            ("audit_sha256", res.audit.map { .string(sha256Hex($0)) } ?? .null),
        ], now: now)
        return res
    }

    /// The public-key file for the DM (`pub-<key_id>.json`), in the engine's key-file format.
    public func exportPublic(keyId: String, volume: URL, now: Int64) throws -> URL {
        guard let k = registry.keys[keyId] else { throw Refusal(code: "unknown_key") }
        let out = try Transport.writeOutput(volume: volume, name: "pub-\(keyId).json", body: KeyIdentity.publicExport(k), volumeCheck: volumeCheck)
        try log.append("output_written", [("file", .string(out.lastPathComponent))], now: now)
        return out
    }

    public func audit(dmTrust: [UInt8], now: Int64) throws -> AuditReport {
        let r = try TrustAudit.compare(dmTrust, registry: registry)
        try log.append("audit", [("match", .bool(r.match)), ("dm_trust_sha256", .string(r.dmFingerprint)),
                                 ("expected_fp", .string(registry.expectedFingerprint))], now: now)
        return r
    }

    // ── ceremony and recovery sessions (design round 2 §6, round 3 R3.3) ──
    public func ceremony(_ phase: String, facts: [(String, JSONValue)], now: Int64) throws -> String? {
        let marker = dir.appendingPathComponent("ceremony.json")
        if phase == "start" {
            guard !FileManager.default.fileExists(atPath: marker.path) else { throw Refusal(code: "ceremony_in_progress") }
            try log.append("ceremony_started", facts, now: now)
            try AtomicFile.write(Canonical.encode(.object([("head", .string(log.head)), ("seq", .int(log.seq))])), to: marker, mode: 0o600, replace: false)
            return nil
        }
        guard let m = FileManager.default.contents(atPath: marker.path), let v = try? Canonical.decode(Array(m)),
              let start = v["head"]?.string, let seq = v["seq"]?.int else { throw Refusal(code: "no_ceremony") }
        let h = sha256Hex(Array("sentinel/v1/ceremony".utf8) + [0] + Array("\(seq):\(start):\(log.seq):\(log.head)".utf8))
        try log.append("ceremony_ended", [("ceremony_hash", .string(h)), ("from_seq", .int(seq))], now: now)
        try FileManager.default.removeItem(at: marker)
        return h
    }

    public func recoverySession(start: Bool, now: Int64) throws -> String {
        if start {
            guard registry.recoverySession == nil else { throw Refusal(code: "recovery_in_progress") }
            registry.recoverySession = UUID().uuidString.lowercased()
            registry.replacementCommitted = false
        } else {
            guard registry.recoverySession != nil else { throw Refusal(code: "no_recovery_session") }
            guard registry.state == "IDLE" else { throw Refusal(code: "registry_pending") }
            registry.recoverySession = nil
        }
        try save()
        let id = registry.recoverySession ?? "ended"
        try log.append(start ? "recovery_started" : "recovery_ended", [("session", .string(id)), ("head", .string(log.head))], now: now)
        return start ? id : log.head
    }

    // ── D-46 checkpoints ──
    public func checkpointBody(device: String, now: Int64) -> JSONValue {
        Checkpoint.body(registry: registry, ledger: ledger.snapshot(), audit: (log.seq, log.head), device: device, now: now)
    }

    /// After signing, the operator re-types the hash written on paper; only then is the checkpoint anchored.
    public func recordCheckpoint(_ body: JSONValue, retypedHash: String, now: Int64) throws -> Bool {
        let h = Checkpoint.hash(body)
        let anchored = retypedHash == h
        if anchored { (registry.checkpointSequence, registry.lastCheckpoint) = (body["sequence"]?.int ?? 0, h); try save() }
        try log.append(anchored ? "checkpoint_anchored" : "checkpoint_unanchored", [("sha256", .string(h)), ("sequence", .int(body["sequence"]?.int ?? 0))], now: now)
        return anchored
    }

    public func restore(_ bytes: [UInt8], paperFingerprint: String, paperSequence: Int64, paperHash: String, older: [[UInt8]], now: Int64) throws {
        let (r, ledgerSnap) = try Checkpoint.restore(bytes, paperFingerprint: paperFingerprint, paperSequence: paperSequence,
                                                     paperHash: paperHash, older: older, current: registry)
        try ledger.restore(ledgerSnap)
        registry = r
        try save()
        try log.append("registry_changed", [("change", .string("restored")), ("checkpoint", .string(paperHash))], now: now)
    }

    // ── R3.4 signer installation ──
    public func install(record: [UInt8], binary: URL, now: Int64) throws -> String {
        let bin = Array(try Data(contentsOf: binary))
        let (commit, h, vr) = try Release.verify(record, registry: registry, binarySHA256: sha256Hex(bin), ledger: ledger, now: now)
        let dest = versions.appendingPathComponent(commit)
        try FileManager.default.createDirectory(at: dest, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let exe = dest.appendingPathComponent("sentinel-signer")
        if let have = FileManager.default.contents(atPath: exe.path) {
            guard sha256Hex(Array(have)) == sha256Hex(bin) else { throw Refusal(code: "kept_version_mismatch") }
        } else {
            try AtomicFile.write(bin, to: exe, mode: 0o755, replace: false)
        }
        try ledger.recordSigned(vr)
        try AtomicFile.write(Array("\(commit)\n".utf8), to: dir.appendingPathComponent("current"), mode: 0o600, replace: true)
        (registry.signerCommit, registry.signerBinary) = (commit, sha256Hex(bin))
        try save()
        try log.append("update_installed", [("commit", .string(commit)), ("binary_sha256", .string(sha256Hex(bin))),
                                            ("release_sha256", .string(h))], now: now)
        return commit
    }
}
