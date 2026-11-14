import CryptoKit
import Foundation

public struct Refusal: Error, Equatable {
    public let code: String
    public init(code: String) { self.code = code }
}

public struct ValidatedRequest {
    public let requestId: String
    public let payload: JSONValue
    public let payloadBytes: [UInt8]
    public let payloadSHA256: String
    public let action: String
    public let keyId: String
    public let oneTime: Bool
    public let nonce: String
    public let expiresAt: Int64
    public let signerRole: String
    /// For key.rotate / key.revoke: the key added or revoked (becomes the pending registry change).
    public let keyOpTarget: String?
}

public enum Policy {
    public static let requestEnvelope = "sentinel/v1/sign-request"
    public static let maxRequestBytes = 16_384
    public static let clockSkew: Int64 = 300
    public static let actions: Set<String> = [
        "authorize_record", "revoke_record", "review.verify_no_evidence", "review.accept_risk",
        "suppress", "policy.change", "key.rotate", "key.revoke", "release.publish",
    ]
    public static let oneTime: Set<String> = ["revoke_record", "key.rotate", "key.revoke", "release.publish"]
    /// D-45 permission sets (D-74 adds `release.publish`, operator only). `signer.release` and
    /// `registry.checkpoint` are SD-internal operator actions: never in a DM request, never in the
    /// engine-visible permission list.
    public static let operatorActions = actions
    public static let recoveryActions: Set<String> = ["key.rotate", "key.revoke"]
    /// SD-T55: signing is blocked when the operator hasn't checked the clock in the last 30 days.
    public static let clockCheckMaxAge: Int64 = 30 * 86400
    static let hour: Int64 = 3600, day: Int64 = 86400
    /// The SD's own copy of the D-37 maximum lifetimes. It never comes from the request.
    public static let maxLifetime: [String: Int64] = [
        "authorize_record:local": 30 * day, "authorize_record:staging": 30 * day,
        "authorize_record:production": 24 * hour, "revoke_record": hour, "key.rotate": hour,
        "key.revoke": hour, "review.verify_no_evidence": 90 * day, "review.accept_risk": 90 * day,
        "suppress": 90 * day, "policy.change": 90 * day, "release.publish": hour,
    ]
    /// D-74: the product a `release.publish` may name, and the most artifacts one release lists.
    public static let releaseName = "sentinel-audit"
    public static let maxReleaseArtifacts = 16
    static let payloadKeys: Set<String> = [
        "action", "context", "expires_at", "issued_at", "key_id", "nonce", "rationale", "revision", "scope", "subject",
    ]
    static let requestKeys: Set<String> = ["envelope", "payload", "payload_sha256", "request_id"]
}

func hex64(_ s: String?) -> Bool { guard let s else { return false }; return s.count == 64 && s.allSatisfy { "0123456789abcdef".contains($0) } }
func hex32(_ s: String?) -> Bool { guard let s else { return false }; return s.count == 32 && s.allSatisfy { "0123456789abcdef".contains($0) } }
public func sha256Hex(_ b: [UInt8]) -> String { SHA256.hash(data: Data(b)).map { String(format: "%02x", $0) }.joined() }

/// Subject shapes per action (they mirror the engine's builders exactly; any extra field is refused).
func subjectOK(_ action: String, _ s: JSONValue) -> Bool {
    let keys = Set(s.keys)
    switch (action, s["type"]?.string) {
    case ("authorize_record", "authorization_record"), ("policy.change", "policy_file"),
         ("review.accept_risk", "suppression_entry"), ("suppress", "suppression_entry"):
        return keys == ["type", "sha256"] && hex64(s["sha256"]?.string)
    case ("revoke_record", "approval"):
        return keys == ["type", "sha256"] && hex64(s["sha256"]?.string)
    case ("revoke_record", "decision"):
        guard keys == ["type", "decision_id", "entry_sha256"], let d = s["decision_id"]?.string, !d.isEmpty, d.count <= 128 else { return false }
        let e = s["entry_sha256"]?.string
        return e == "none" || hex64(e)
    case ("review.verify_no_evidence", "finding"):
        return keys == ["type", "fingerprint"] && hex64(s["fingerprint"]?.string)
    case ("key.rotate", "operator_key"):
        return keys == ["type", "key_id", "public_sha256"] && validKeyId(s["key_id"]?.string) && hex64(s["public_sha256"]?.string)
    case ("key.revoke", "operator_key"):
        return keys == ["type", "key_id"] && validKeyId(s["key_id"]?.string)
    case ("release.publish", "release"):
        guard keys == ["type", "name", "version", "commit"], s["name"]?.string == Policy.releaseName,
              let v = s["version"]?.string, versionOK(v), let c = s["commit"]?.string else { return false }
        return c.count == 40 && c.allSatisfy { "0123456789abcdef".contains($0) }
    default:
        return false
    }
}

func asciiAlnum(_ c: Unicode.Scalar) -> Bool {
    (48...57).contains(c.value) || (65...90).contains(c.value) || (97...122).contains(c.value)
}

/// `^[0-9][0-9A-Za-z.+-]{0,63}$`, as the engine's schema.
func versionOK(_ v: String) -> Bool {
    let u = Array(v.unicodeScalars)
    guard (1...64).contains(u.count), (48...57).contains(u[0].value) else { return false }
    return u.allSatisfy { asciiAlnum($0) || ".+-".unicodeScalars.contains($0) }
}

/// `^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$`: a plain file name, never a path or a dotfile.
func artifactNameOK(_ n: String) -> Bool {
    let u = Array(n.unicodeScalars)
    guard (1...200).contains(u.count), asciiAlnum(u[0]) else { return false }
    return u.allSatisfy { asciiAlnum($0) || "._+-".unicodeScalars.contains($0) }
}

/// D-74: the exact `SHA256SUMS` bytes for a release scope. The SD recomputes them itself, so the hashes it
/// displays are exactly the ones the signature covers; any malformed, unsorted or duplicate entry is refused.
public func releaseSums(_ scope: JSONValue) throws -> [UInt8] {
    guard Set(scope.keys) == ["artifacts"], case let .array(items)? = scope["artifacts"],
          (1...Policy.maxReleaseArtifacts).contains(items.count) else { throw Refusal(code: "bad_release_scope") }
    var names: [String] = [], body = ""
    for a in items {
        guard Set(a.keys) == ["name", "sha256"], let n = a["name"]?.string, let h = a["sha256"]?.string,
              artifactNameOK(n), hex64(h) else { throw Refusal(code: "bad_release_scope") }
        names.append(n)
        body += "\(h)  \(n)\n"
    }
    guard names == names.sorted(), Set(names).count == names.count,
          !names.contains("SHA256SUMS"), !names.contains("SHA256SUMS.approval.json") else { throw Refusal(code: "bad_release_scope") }
    return Array(body.utf8)
}

func checkRelease(subject: JSONValue, scope: JSONValue, revision: String) throws {
    let sums = try releaseSums(scope)
    guard revision == "sums:\(sha256Hex(sums))" else { throw Refusal(code: "release_sums_mismatch") }
    guard let v = subject["version"]?.string, case let .array(items)? = scope["artifacts"],
          items.contains(where: { $0["name"]?.string == "sentinel_audit-\(v)-py3-none-any.whl" }) else {
        throw Refusal(code: "release_version_mismatch")
    }
}

func validKeyId(_ s: String?) -> Bool {
    guard let s, s.hasPrefix("p256:") else { return false }
    return hex32(String(s.dropFirst(5)))
}

func hasWildcard(_ v: JSONValue) -> Bool {
    switch v {
    case let .string(s): return s.contains("*") || s.contains("?")
    case let .array(a): return a.contains(where: hasWildcard)
    case let .object(kv): return kv.contains { hasWildcard($0.1) }
    default: return false
    }
}

/// Protocol v1 §4, steps 2–10, in order. Step 1 (intake) happens in `Transport`; step 11 is the display.
public func validateRequest(_ bytes: [UInt8], fileRequestId: String, registry: Registry, ledger: Ledger, now: Int64) throws -> ValidatedRequest {
    guard bytes.count <= Policy.maxRequestBytes, !bytes.isEmpty else { throw Refusal(code: "bad_size") }
    let req: JSONValue
    do { req = try Canonical.decode(bytes) } catch let e as CanonicalError { throw Refusal(code: "not_canonical:\(e.code)") }
    guard Set(req.keys) == Policy.requestKeys, req["envelope"]?.string == Policy.requestEnvelope else { throw Refusal(code: "bad_envelope") }
    guard let rid = req["request_id"]?.string, hex32(rid), rid == fileRequestId else { throw Refusal(code: "bad_request_id") }
    guard let payload = req["payload"], case .object = payload else { throw Refusal(code: "bad_payload") }
    let pbytes = Canonical.encode(payload)
    let phash = sha256Hex(pbytes)
    guard req["payload_sha256"]?.string == phash else { throw Refusal(code: "payload_hash_mismatch") }
    guard Set(payload.keys) == Policy.payloadKeys else { throw Refusal(code: "bad_payload_keys") }
    guard let action = payload["action"]?.string, Policy.actions.contains(action) else { throw Refusal(code: "unknown_action") }
    guard payload["context"]?.string == "sentinel/v1/approval/\(action)" else { throw Refusal(code: "wrong_context") }
    guard let keyId = payload["key_id"]?.string, let key = registry.keys[keyId] else { throw Refusal(code: "foreign_key") }
    let enrolment = key.status == "candidate"
    guard (key.status == "active" || enrolment), key.expiresAt > now else { throw Refusal(code: "key_inactive") }
    guard !key.suspect else { throw Refusal(code: "key_suspect") }
    guard key.permittedActions.contains(action) else { throw Refusal(code: "action_not_permitted") }
    guard let checked = registry.clockCheckedAt, checked <= now, now - checked <= Policy.clockCheckMaxAge else {
        throw Refusal(code: "clock_unchecked")
    }
    guard let issued = payload["issued_at"]?.int, let expires = payload["expires_at"]?.int else { throw Refusal(code: "bad_time") }
    guard abs(issued - now) <= Policy.clockSkew else { throw Refusal(code: "clock_skew") }
    guard issued < expires, expires > now else { throw Refusal(code: "bad_time") }
    guard let scope = payload["scope"], case .object = scope else { throw Refusal(code: "bad_scope") }
    let limit: Int64
    if action == "authorize_record" {
        var envs = Set<String>()
        if case let .array(assets)? = scope["assets"] {
            for a in assets { envs.insert(a["environment"]?.string ?? "?") }
        }
        if envs.isEmpty { envs = ["local"] }
        guard envs.isSubset(of: ["local", "staging", "production"]) else { throw Refusal(code: "bad_scope") }
        limit = envs.map { Policy.maxLifetime["authorize_record:\($0)"]! }.min()!
        if envs.contains("production"), hasWildcard(scope) { throw Refusal(code: "production_wildcard") }
    } else {
        limit = Policy.maxLifetime[action]!
    }
    guard expires - issued <= limit else { throw Refusal(code: "expiry_too_long") }
    guard let subject = payload["subject"], subjectOK(action, subject) else { throw Refusal(code: "bad_subject") }
    guard let revision = payload["revision"]?.string, !revision.isEmpty, revision.count <= 512 else { throw Refusal(code: "bad_revision") }
    var target: String?
    if action == "key.rotate" || action == "key.revoke" {
        target = try checkKeyOperation(action, subject: subject, revision: revision, signer: key, registry: registry)
    } else if enrolment {
        throw Refusal(code: "key_inactive")  // a candidate signs nothing but its own enrolment
    } else if action == "release.publish" {
        try checkRelease(subject: subject, scope: scope, revision: revision)
    }
    guard let rationale = payload["rationale"]?.string, !rationale.isEmpty, rationale.count <= 1000 else { throw Refusal(code: "bad_rationale") }
    guard let nonce = payload["nonce"]?.string, hex32(nonce) else { throw Refusal(code: "bad_nonce") }
    let oneTime = Policy.oneTime.contains(action)
    try ledger.check(requestId: rid, nonce: nonce, payloadSHA256: phash, oneTime: oneTime)
    return ValidatedRequest(requestId: rid, payload: payload, payloadBytes: pbytes, payloadSHA256: phash, action: action,
                            keyId: keyId, oneTime: oneTime, nonce: nonce, expiresAt: expires, signerRole: key.role, keyOpTarget: target)
}

/// Design round 2 §2.3 and protocol R3.5: key operations are checked against the SD's own registry.
/// Returns the key the operation adds or revokes.
func checkKeyOperation(_ action: String, subject: JSONValue, revision: String, signer: RegistryKey, registry: Registry) throws -> String {
    guard registry.state == "IDLE" else { throw Refusal(code: "registry_pending") }
    guard let target = subject["key_id"]?.string else { throw Refusal(code: "bad_subject") }
    if signer.status == "candidate" {
        // Enrolment: an empty registry, a self-signed key.rotate for this SD's own new operator key.
        guard action == "key.rotate", registry.enrolled.isEmpty, target == signer.keyId, signer.role == "operator",
              signer.custody == "this-device", revision == "trust:\(Registry.emptyFingerprint)" else { throw Refusal(code: "bad_enrolment") }
    } else {
        guard revision == "trust:\(registry.expectedFingerprint)" else { throw Refusal(code: "trust_mismatch") }
    }
    if action == "key.rotate" {
        guard let cand = registry.keys[target], cand.status == "candidate" else { throw Refusal(code: "unknown_candidate") }
        guard subject["public_sha256"]?.string == cand.fingerprint else { throw Refusal(code: "public_mismatch") }
        if signer.role == "recovery" {
            // R3.5 (a)-(c): only a replacement operator key generated on this SD in this recovery session.
            guard cand.role == "operator", cand.custody == "this-device", let s = registry.recoverySession, cand.session == s,
                  cand.permittedActions == Policy.operatorActions.sorted() else { throw Refusal(code: "recovery_candidate_refused") }
        }
    } else {
        guard let t = registry.keys[target], t.status == "active" else { throw Refusal(code: "unknown_target") }
        guard target != signer.keyId else { throw Refusal(code: "self_revocation") }
        if t.role == "operator", !registry.activeOperators.contains(where: { $0.keyId != target }) {
            throw Refusal(code: "last_operator_key")  // the engine refuses this too
        }
    }
    return target
}
