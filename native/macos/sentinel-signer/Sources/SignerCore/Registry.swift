import Foundation

/// The SD's own key registry (design round 2 §2.1, round 3 R3.1, D-45, D-46). It is authoritative: the SD
/// never imports registry state from the DM, and computes the DM trust fingerprint itself.
public enum Algo {
    public static let p256 = "ecdsa-p256-sha256"  // the engine's name for operator keys (D-47)
    public static let rpId = "sentinel-recovery.invalid"  // OD-2
    public static let coseES256: Int64 = -7
}

public struct RecoveryCredential: Equatable {
    public var credentialId: [UInt8]
    public var counterMode: String  // unset | zero | increasing (OD-3)
    public var lastCount: Int64
    public init(credentialId: [UInt8], counterMode: String = "unset", lastCount: Int64 = 0) {
        (self.credentialId, self.counterMode, self.lastCount) = (credentialId, counterMode, lastCount)
    }
}

public struct RegistryKey: Equatable {
    public let keyId: String
    public var role: String  // operator | recovery
    public var permittedActions: [String]  // sorted; the engine-visible D-45 set
    public let publicX963: [UInt8]
    public var operatorName: String
    public var expiresAt: Int64
    public var status: String  // candidate | active | revoked
    public var custody: String  // this-device | external-fido2 | other-device | lost
    public var suspect = false
    public var enrolledBy: String?
    public var revokedBy: String?
    public var recovery: RecoveryCredential?
    public var session: String?  // the recovery session a candidate was created in

    public init(keyId: String, role: String, publicX963: [UInt8], operatorName: String, expiresAt: Int64,
                status: String, custody: String, recovery: RecoveryCredential? = nil, session: String? = nil) {
        (self.keyId, self.role, self.publicX963, self.operatorName, self.expiresAt) = (keyId, role, publicX963, operatorName, expiresAt)
        (self.status, self.custody, self.recovery, self.session) = (status, custody, recovery, session)
        permittedActions = (role == "recovery" ? Policy.recoveryActions : Policy.operatorActions).sorted()
    }

    public var fingerprint: String { sha256Hex(publicX963) }

    /// Exactly the engine's `key_to_json` (src/sentinel/keys/operator.py), so fingerprints match.
    public var projection: JSONValue {
        var f: [(String, JSONValue)] = [
            ("algorithm", .string(Algo.p256)), ("expires_at", .int(expiresAt)), ("key_id", .string(keyId)),
            ("operator", .string(operatorName)), ("permitted_actions", .array(permittedActions.map { .string($0) })),
            ("public", .string(hex(publicX963))), ("role", .string(role)), ("status", .string(suspect ? "suspect" : status)),
        ]
        if let r = recovery {
            f += [("cose_alg", .int(Algo.coseES256)), ("counter_mode", .string(r.counterMode)),
                  ("credential_id_b64", .string(Data(r.credentialId).base64EncodedString())),
                  ("last_count", .int(r.lastCount)), ("rp_id", .string(Algo.rpId))]
        }
        return .object(f)
    }
}

public struct PendingChange: Equatable {
    public let requestId: String, payloadSHA256: String, action: String  // key.rotate | key.revoke
    public let expiresAt: Int64
    public let target: String, signer: String
    public let counter: RecoveryCredential?  // the recovery signer's counter state after this assertion
}

public struct Registry: Equatable {
    public var keys: [String: RegistryKey] = [:]
    public var state = "IDLE"  // IDLE | PENDING | ABANDONING (R3.1)
    public var pending: PendingChange?
    public var recoverySession: String?
    public var replacementCommitted = false  // a replacement operator key was committed in this session
    public var clockCheckedAt: Int64?
    public var checkpointSequence: Int64 = 0
    public var lastCheckpoint = "genesis"
    public var signerCommit = String(repeating: "0", count: 40)
    public var signerBinary = String(repeating: "0", count: 64)
    public init() {}

    public static let emptyFingerprint = sha256Hex(Canonical.encode(.object([("keys", .array([]))])))

    /// Keys the DM should hold: everything except un-enrolled candidates, sorted by key_id.
    public var enrolled: [RegistryKey] { keys.values.filter { $0.status != "candidate" }.sorted { $0.keyId < $1.keyId } }
    public var projection: JSONValue { .object([("keys", .array(enrolled.map { $0.projection }))]) }
    /// The expected DM trust fingerprint, from the committed registry only (R3.1).
    public var expectedFingerprint: String { sha256Hex(Canonical.encode(projection)) }
    public var activeOperators: [RegistryKey] { enrolled.filter { $0.role == "operator" && $0.status == "active" } }

    // ── R3.1 state machine. No transition happens automatically. ──
    public mutating func begin(_ p: PendingChange) throws {
        guard state == "IDLE", pending == nil else { throw Refusal(code: "registry_pending") }
        (state, pending) = ("PENDING", p)
    }

    /// The operator confirmed on the SD that the DM accepted the change.
    @discardableResult
    public mutating func commit() throws -> PendingChange {
        guard state == "PENDING", let p = pending else { throw Refusal(code: "nothing_pending") }
        apply(p)
        return p
    }

    /// The operator says the DM didn't apply it. Key operations stay refused until resolved.
    public mutating func markAbandoning() throws {
        guard state == "PENDING" else { throw Refusal(code: "nothing_pending") }
        state = "ABANDONING"
    }

    /// Only after `expires_at` has passed, and only on the evidence of a DM trust-store audit.
    public mutating func resolveAbandon(now: Int64, changePresentOnDM: Bool) throws -> String {
        guard state == "ABANDONING", let p = pending else { throw Refusal(code: "not_abandoning") }
        guard now > p.expiresAt else { throw Refusal(code: "not_expired") }
        if changePresentOnDM { apply(p); return "COMMITTED" }
        (state, pending) = ("IDLE", nil)
        return "ABANDONED"
    }

    mutating func apply(_ p: PendingChange) {
        if p.action == "key.rotate", var k = keys[p.target] {
            (k.status, k.enrolledBy) = ("active", p.payloadSHA256)
            if recoverySession != nil, k.session == recoverySession, k.role == "operator",
               keys[p.signer]?.role == "recovery" { replacementCommitted = true }
            keys[p.target] = k
        } else if p.action == "key.revoke", var k = keys[p.target] {
            (k.status, k.revokedBy) = ("revoked", p.payloadSHA256)
            keys[p.target] = k
        }
        if let c = p.counter { keys[p.signer]?.recovery = c }
        (state, pending) = ("IDLE", nil)
    }

    /// Whether a DM trust store already shows the pending change (used by the abandon procedure).
    public func changePresent(in dm: [String: JSONValue]) -> Bool {
        guard let p = pending, let k = dm[p.target] else { return false }
        return p.action == "key.rotate" ? k["status"]?.string == "active" : k["status"]?.string == "revoked"
    }

    // ── persistence (canonical JSON, 0600) ──
    public func encode() -> [UInt8] {
        let ks: [JSONValue] = keys.values.sorted { $0.keyId < $1.keyId }.map { k in
            var f: [(String, JSONValue)] = [("custody", .string(k.custody)), ("suspect", .bool(k.suspect))]
            f.append(("enrolled_by", k.enrolledBy.map { .string($0) } ?? .null))
            f.append(("revoked_by", k.revokedBy.map { .string($0) } ?? .null))
            f.append(("session", k.session.map { .string($0) } ?? .null))
            f.append(("status_raw", .string(k.status)))
            if case let .object(p) = k.projection { f += p.filter { $0.0 != "status" } }
            return .object(f)
        }
        let pend: JSONValue = pending.map { p in .object([
            ("action", .string(p.action)), ("expires_at", .int(p.expiresAt)), ("payload_sha256", .string(p.payloadSHA256)),
            ("request_id", .string(p.requestId)), ("signer", .string(p.signer)), ("target", .string(p.target)),
            ("counter", p.counter.map { .object([("counter_mode", .string($0.counterMode)), ("last_count", .int($0.lastCount))]) } ?? .null),
        ]) } ?? .null
        return Canonical.encode(.object([
            ("checkpoint_sequence", .int(checkpointSequence)), ("clock_checked_at", clockCheckedAt.map { .int($0) } ?? .null),
            ("format", .string("sentinel-signer/registry/2")), ("keys", .array(ks)), ("last_checkpoint", .string(lastCheckpoint)),
            ("pending", pend), ("recovery_session", recoverySession.map { .string($0) } ?? .null),
            ("replacement_committed", .bool(replacementCommitted)), ("signer_binary", .string(signerBinary)),
            ("signer_commit", .string(signerCommit)), ("state", .string(state)),
        ]))
    }

    public static func decode(_ bytes: [UInt8]) throws -> Registry {
        let v: JSONValue
        do { v = try Canonical.decode(bytes) } catch { throw Refusal(code: "registry_invalid") }
        guard v["format"]?.string == "sentinel-signer/registry/2", case let .array(ks)? = v["keys"] else { throw Refusal(code: "registry_invalid") }
        var r = Registry()
        for k in ks { let key = try decodeKey(k); r.keys[key.keyId] = key }
        r.state = v["state"]?.string ?? ""
        guard ["IDLE", "PENDING", "ABANDONING"].contains(r.state) else { throw Refusal(code: "registry_invalid") }
        if let p = v["pending"], p != .null {
            guard let rid = p["request_id"]?.string, let h = p["payload_sha256"]?.string, let a = p["action"]?.string,
                  let e = p["expires_at"]?.int, let t = p["target"]?.string, let s = p["signer"]?.string else { throw Refusal(code: "registry_invalid") }
            var c: RecoveryCredential?
            if let cv = p["counter"], cv != .null, let cred = r.keys[s]?.recovery {
                c = RecoveryCredential(credentialId: cred.credentialId, counterMode: cv["counter_mode"]?.string ?? "", lastCount: cv["last_count"]?.int ?? -1)
            }
            r.pending = PendingChange(requestId: rid, payloadSHA256: h, action: a, expiresAt: e, target: t, signer: s, counter: c)
        }
        guard (r.state == "IDLE") == (r.pending == nil) else { throw Refusal(code: "registry_invalid") }
        r.recoverySession = v["recovery_session"]?.string
        r.replacementCommitted = v["replacement_committed"] == .bool(true)
        r.clockCheckedAt = v["clock_checked_at"]?.int
        r.checkpointSequence = v["checkpoint_sequence"]?.int ?? 0
        r.lastCheckpoint = v["last_checkpoint"]?.string ?? "genesis"
        r.signerCommit = v["signer_commit"]?.string ?? r.signerCommit
        r.signerBinary = v["signer_binary"]?.string ?? r.signerBinary
        return r
    }

    static func decodeKey(_ k: JSONValue) throws -> RegistryKey {
        guard let id = k["key_id"]?.string, let role = k["role"]?.string, ["operator", "recovery"].contains(role),
              let pubHex = k["public"]?.string, let pub = unhex(pubHex), pub.count == 65, KeyIdentity.keyId(publicX963: pub) == id,
              let name = k["operator"]?.string, let exp = k["expires_at"]?.int, let st = k["status_raw"]?.string,
              ["candidate", "active", "revoked"].contains(st), let custody = k["custody"]?.string,
              case let .array(acts)? = k["permitted_actions"] else { throw Refusal(code: "registry_invalid") }
        var key = RegistryKey(keyId: id, role: role, publicX963: pub, operatorName: name, expiresAt: exp, status: st, custody: custody)
        key.permittedActions = acts.compactMap { $0.string }
        guard key.permittedActions == key.permittedActions.sorted(),
              Set(key.permittedActions).isSubset(of: role == "recovery" ? Policy.recoveryActions : Policy.operatorActions)
        else { throw Refusal(code: "registry_invalid") }
        key.suspect = k["suspect"] == .bool(true)
        key.enrolledBy = k["enrolled_by"]?.string
        key.revokedBy = k["revoked_by"]?.string
        key.session = k["session"]?.string
        if role == "recovery" {
            guard let b = k["credential_id_b64"]?.string, let cred = Data(base64Encoded: b), !cred.isEmpty,
                  let mode = k["counter_mode"]?.string, let n = k["last_count"]?.int else { throw Refusal(code: "registry_invalid") }
            key.recovery = RecoveryCredential(credentialId: Array(cred), counterMode: mode, lastCount: n)
        }
        return key
    }
}

/// The result of comparing a DM `trust.json` with the SD registry (design §2.4). Shown on the SD only.
public struct AuditReport: Equatable {
    public var match: Bool
    public var dmFingerprint: String
    public var onlyOnDM: [String] = [], onlyOnSD: [String] = [], different: [String] = []
    public var dmKeys: [String: JSONValue] = [:]
}

public enum TrustAudit {
    public static let maxBytes = 65_536

    /// Parse the DM's trust store as untrusted input and compare it with the registry's projection.
    public static func compare(_ dmBytes: [UInt8], registry: Registry) throws -> AuditReport {
        guard !dmBytes.isEmpty, dmBytes.count <= maxBytes else { throw Refusal(code: "audit_bad_size") }
        let v: JSONValue
        do { v = try Canonical.decode(dmBytes) } catch { throw Refusal(code: "audit_not_canonical") }
        guard v.keys == ["keys"], case let .array(entries)? = v["keys"] else { throw Refusal(code: "audit_bad_shape") }
        var dm: [String: JSONValue] = [:]
        for e in entries {
            guard let id = e["key_id"]?.string, dm[id] == nil else { throw Refusal(code: "audit_bad_shape") }
            dm[id] = e
        }
        let sd = Dictionary(uniqueKeysWithValues: registry.enrolled.map { ($0.keyId, $0.projection) })
        var r = AuditReport(match: false, dmFingerprint: sha256Hex(dmBytes), dmKeys: dm)
        r.onlyOnDM = dm.keys.filter { sd[$0] == nil }.sorted()
        r.onlyOnSD = sd.keys.filter { dm[$0] == nil }.sorted()
        for (id, mine) in sd.sorted(by: { $0.key < $1.key }) {
            guard let theirs = dm[id] else { continue }
            for f in Set(mine.keys).union(theirs.keys).sorted() where mine[f] != theirs[f] { r.different.append("\(id).\(f)") }
        }
        r.match = r.dmFingerprint == registry.expectedFingerprint && r.onlyOnDM.isEmpty && r.onlyOnSD.isEmpty && r.different.isEmpty
        return r
    }
}

public func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
public func unhex(_ s: String) -> [UInt8]? {
    guard s.count % 2 == 0, s.allSatisfy({ "0123456789abcdef".contains($0) }) else { return nil }
    var out = [UInt8](), it = s.makeIterator()
    while let a = it.next(), let b = it.next() { out.append(UInt8(String([a, b]), radix: 16)!) }
    return out
}
