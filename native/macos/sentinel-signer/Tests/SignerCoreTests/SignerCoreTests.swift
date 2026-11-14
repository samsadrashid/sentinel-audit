import CryptoKit
import Foundation
import XCTest

@testable import SignerCore

struct SoftKey: SigningKey {
    let k = P256.Signing.PrivateKey()
    var publicX963: [UInt8] { Array(k.publicKey.x963Representation) }
    func sign(_ m: [UInt8]) throws -> [UInt8] { Array(try k.signature(for: Data(m)).derRepresentation) }
}

let now: Int64 = 1_800_000_000

func payload(action: String = "policy.change", keyId: String, issued: Int64 = now, life: Int64 = 3600,
             subject: JSONValue? = nil, revision: String = "policy-prev:none", nonce: String = String(repeating: "a", count: 32),
             scope: JSONValue = .object([])) -> JSONValue {
    .object([
        ("action", .string(action)), ("context", .string("sentinel/v1/approval/\(action)")),
        ("expires_at", .int(issued + life)), ("issued_at", .int(issued)), ("key_id", .string(keyId)),
        ("nonce", .string(nonce)), ("rationale", .string("test")), ("revision", .string(revision)), ("scope", scope),
        ("subject", subject ?? .object([("sha256", .string(String(repeating: "b", count: 64))), ("type", .string("policy_file"))])),
    ])
}

func request(_ p: JSONValue, rid: String = String(repeating: "c", count: 32), hash: String? = nil) -> [UInt8] {
    Canonical.encode(.object([
        ("envelope", .string("sentinel/v1/sign-request")), ("payload", p),
        ("payload_sha256", .string(hash ?? sha256Hex(Canonical.encode(p)))), ("request_id", .string(rid)),
    ]))
}

final class CanonicalTests: XCTestCase {
    func testRoundTripAndStrictness() throws {
        let ok = Array(#"{"a":[1,-2,true,null],"b":"x\"y\\z"}"#.utf8)
        XCTAssertEqual(Canonical.encode(try Canonical.decode(ok)), ok)
        let bad: [String: String] = [
            #"{"b":1,"a":2}"#: "not_canonical", #"{"a":1,"a":1}"#: "duplicate_key", #"{"a":1.5}"#: "float_not_allowed",
            #"{"a":1e3}"#: "float_not_allowed", #"{ "a":1}"#: "bad_key", #"{"a":"\n"}"#: "bad_escape",
            #"{"a":9007199254740993}"#: "integer_out_of_range", #"{"a":1}x"#: "trailing_bytes",
        ]
        for (s, code) in bad {
            XCTAssertThrowsError(try Canonical.decode(Array(s.utf8)), s) { XCTAssertEqual(($0 as? CanonicalError)?.code, code, s) }
        }
        XCTAssertThrowsError(try Canonical.decode(Array("{\"a\":\"é\"}".utf8)))  // non-ASCII
        XCTAssertThrowsError(try Canonical.decode(Array("{\"a\":\"\t\"}".utf8)))  // control character
    }
}

let noCheck: (URL, Bool) -> String? = { _, _ in nil }
let rid32 = String(repeating: "c", count: 32)

func rk(_ k: SoftKey, role: String = "operator", status: String = "active", custody: String = "this-device",
        session: String? = nil, cred: [UInt8]? = nil, exp: Int64 = now + 86400) -> RegistryKey {
    RegistryKey(keyId: KeyIdentity.keyId(publicX963: k.publicX963), role: role, publicX963: k.publicX963, operatorName: "owner",
                expiresAt: exp, status: status, custody: custody, recovery: cred.map { RecoveryCredential(credentialId: $0) }, session: session)
}

func registry(_ keys: [RegistryKey]) -> Registry {
    var r = Registry()
    for k in keys { r.keys[k.keyId] = k }
    r.clockCheckedAt = now
    return r
}

func keyPayload(_ action: String, signer: String, target: String, pub: String? = nil, revision: String, nonce: String = String(repeating: "5", count: 32)) -> JSONValue {
    var subj: [(String, JSONValue)] = [("key_id", .string(target)), ("type", .string("operator_key"))]
    if let pub { subj.append(("public_sha256", .string(pub))) }
    return payload(action: action, keyId: signer, life: 600, subject: .object(subj), revision: revision, nonce: nonce)
}

func validate(_ p: JSONValue, _ r: Registry, l: Ledger? = nil, rid: String = rid32) throws -> ValidatedRequest {
    try validateRequest(request(p, rid: rid), fileRequestId: rid, registry: r, ledger: l ?? (try Ledger(path: nil)), now: now)
}

func refused(_ code: String, _ f: () throws -> Any, file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertThrowsError(try f(), file: file, line: line) { XCTAssertEqual(($0 as? Refusal)?.code, code, file: file, line: line) }
}

final class ValidationTests: XCTestCase {
    var key: SoftKey!; var id: String!; var reg: Registry!
    override func setUp() {
        key = SoftKey(); id = KeyIdentity.keyId(publicX963: key.publicX963)
        reg = registry([rk(key)])
    }
    func refuse(_ bytes: [UInt8], _ code: String, rid: String = rid32, reg r: Registry? = nil, l: Ledger? = nil) throws {
        XCTAssertThrowsError(try validateRequest(bytes, fileRequestId: rid, registry: r ?? reg, ledger: l ?? (try Ledger(path: nil)), now: now)) {
            XCTAssertEqual(($0 as? Refusal)?.code, code)
        }
    }

    func testValidRequestAndSignatureVerifies() throws {
        let v = try validate(payload(keyId: id), reg)
        let resp = try Canonical.decode(try signResponse(v, key: key))
        let sig = try P256.Signing.ECDSASignature(derRepresentation: Data(base64Encoded: resp["signature_der_b64"]!.string!)!)
        XCTAssertTrue(key.k.publicKey.isValidSignature(sig, for: Data(v.payloadBytes)))
        XCTAssertEqual(Set(resp.keys), ["envelope", "key_id", "payload_sha256", "request_id", "signature_der_b64"])
        XCTAssertNil(v.keyOpTarget)
    }

    func testEveryRefusal() throws {
        try refuse(request(payload(keyId: id), hash: String(repeating: "0", count: 64)), "payload_hash_mismatch")
        try refuse(request(payload(keyId: id)), "bad_request_id", rid: String(repeating: "e", count: 32))
        try refuse(request(payload(action: "allowlist.change", keyId: id)), "unknown_action")
        try refuse(request(payload(action: "signer.release", keyId: id)), "unknown_action")  // SD-internal, never from the DM
        try refuse(request(payload(keyId: "p256:" + String(repeating: "f", count: 32))), "foreign_key")
        try refuse(request(payload(keyId: id, issued: now - 1000)), "clock_skew")
        try refuse(request(payload(keyId: id, life: 91 * 86400)), "expiry_too_long")
        try refuse(request(payload(keyId: id, subject: .object([("type", .string("policy_file")), ("sha256", .string("x"))]))), "bad_subject")
        try refuse(request(payload(keyId: id, subject: .object([("extra", .int(1)), ("sha256", .string(String(repeating: "b", count: 64))), ("type", .string("policy_file"))]))), "bad_subject")
        try refuse(request(payload(keyId: id, nonce: "short")), "bad_nonce")
        let other = SoftKey()
        var two = registry([rk(key), rk(other)])
        try refuse(request(keyPayload("key.revoke", signer: id, target: rk(other).keyId, revision: "trust:" + String(repeating: "9", count: 64))), "trust_mismatch", reg: two)
        two.keys[id]!.suspect = true
        try refuse(request(payload(keyId: id)), "key_suspect", reg: two)
        try refuse(request(payload(keyId: id)), "action_not_permitted", reg: registry([rk(key, role: "recovery", cred: [1])]))
        try refuse(request(payload(keyId: id)), "key_inactive", reg: registry([rk(key, status: "revoked")]))
        try refuse(request(payload(keyId: id)), "key_inactive", reg: registry([rk(key, exp: now - 1)]))
        let prod = JSONValue.object([("assets", .array([.object([("environment", .string("production")), ("id", .string("app-*"))])]))])
        try refuse(request(payload(action: "authorize_record", keyId: id,
                                   subject: .object([("sha256", .string(String(repeating: "b", count: 64))), ("type", .string("authorization_record"))]),
                                   revision: "record:x:1", scope: prod)), "production_wildcard")
        var extra = Array(request(payload(keyId: id)))
        extra.removeLast(); extra += Array(#","x":1}"#.utf8)
        try refuse(extra, "bad_envelope")
        var spaced = Array(request(payload(keyId: id)))
        spaced.insert(UInt8(ascii: " "), at: 1)
        try refuse(spaced, "not_canonical:bad_key")
    }

    func testClockMustHaveBeenCheckedRecently() throws {  // SD-T55
        var r = reg!
        r.clockCheckedAt = nil
        try refuse(request(payload(keyId: id)), "clock_unchecked", reg: r)
        r.clockCheckedAt = now - Policy.clockCheckMaxAge - 1
        try refuse(request(payload(keyId: id)), "clock_unchecked", reg: r)
        r.clockCheckedAt = now + 10  // the clock went backwards since the check
        try refuse(request(payload(keyId: id)), "clock_unchecked", reg: r)
    }

    func testReplayProtection() throws {
        let l = try Ledger(path: nil)
        try l.recordSigned(try validate(payload(keyId: id), reg, l: l))
        try refuse(request(payload(keyId: id)), "duplicate_request", l: l)
        let rebound = payload(keyId: id, revision: "policy-prev:other")
        try refuse(request(rebound, rid: String(repeating: "1", count: 32)), "nonce_rebound", rid: String(repeating: "1", count: 32), l: l)
        let b = SoftKey(), two = registry([rk(key), rk(b)])
        let once = keyPayload("key.revoke", signer: id, target: rk(b).keyId, revision: "trust:\(two.expectedFingerprint)", nonce: String(repeating: "2", count: 32))
        try l.recordSigned(try validate(once, two, l: l, rid: String(repeating: "3", count: 32)))
        try refuse(request(once, rid: String(repeating: "4", count: 32)), "nonce_reused", rid: String(repeating: "4", count: 32), reg: two, l: l)
    }

    func testDisplayShowsEveryFieldAndOnlyValidatedValues() throws {
        let v = try validate(payload(keyId: id), reg)
        let text = renderForApproval(v, deviceName: "SD").joined(separator: "\n")
        for k in ["action", "context", "expires_at", "issued_at", "key_id", "nonce", "rationale", "revision", "subject.sha256", "subject.type"] {
            XCTAssertTrue(text.contains("\n\(k) = "), k)
        }
        XCTAssertTrue(text.hasSuffix("Approve only if every line above is what you intend."))
    }
}

/// Design round 2 §2.3, protocol R3.5, D-45: key operations against the SD's own registry.
final class KeyOperationTests: XCTestCase {
    func testFirstEnrolmentIsSelfSignedIntoAnEmptyRegistry() throws {
        let a = SoftKey(), ka = rk(a, status: "candidate")
        let r = registry([ka])
        let v = try validate(keyPayload("key.rotate", signer: ka.keyId, target: ka.keyId, pub: ka.fingerprint, revision: "trust:\(Registry.emptyFingerprint)"), r)
        XCTAssertEqual(v.keyOpTarget, ka.keyId)
        refused("bad_enrolment") { try validate(keyPayload("key.rotate", signer: ka.keyId, target: ka.keyId, pub: ka.fingerprint, revision: "trust:" + String(repeating: "1", count: 64)), r) }
        refused("key_inactive") { try validate(payload(keyId: ka.keyId), r) }  // a candidate signs nothing else
        let other = rk(SoftKey())
        refused("bad_enrolment") { try validate(keyPayload("key.rotate", signer: ka.keyId, target: ka.keyId, pub: ka.fingerprint, revision: "trust:\(Registry.emptyFingerprint)"), registry([ka, other])) }
    }

    func testRotationNeedsAKeyThisDeviceHoldsAndTheComputedTrustState() throws {
        let a = rk(SoftKey()), b = rk(SoftKey(), status: "candidate")
        var r = registry([a, b])
        let fp = "trust:\(r.expectedFingerprint)"
        XCTAssertEqual(try validate(keyPayload("key.rotate", signer: a.keyId, target: b.keyId, pub: b.fingerprint, revision: fp), r).keyOpTarget, b.keyId)
        refused("public_mismatch") { try validate(keyPayload("key.rotate", signer: a.keyId, target: b.keyId, pub: String(repeating: "0", count: 64), revision: fp), r) }
        refused("unknown_candidate") { try validate(keyPayload("key.rotate", signer: a.keyId, target: "p256:" + String(repeating: "0", count: 32), pub: b.fingerprint, revision: fp), r) }
        // A rotation never re-adds an enrolled key: a revoked key must not come back (revocation reversal).
        var gone = rk(SoftKey(), status: "revoked")
        gone.revokedBy = String(repeating: "e", count: 64)
        var withRevoked = registry([a, gone])
        let fpr = "trust:\(withRevoked.expectedFingerprint)"
        refused("unknown_candidate") { try validate(keyPayload("key.rotate", signer: a.keyId, target: gone.keyId, pub: gone.fingerprint, revision: fpr), withRevoked) }
        refused("unknown_candidate") { try validate(keyPayload("key.rotate", signer: a.keyId, target: a.keyId, pub: a.fingerprint, revision: fpr), withRevoked) }
        withRevoked.state = "IDLE"
        try r.begin(PendingChange(requestId: rid32, payloadSHA256: "x", action: "key.rotate", expiresAt: now + 60, target: b.keyId, signer: a.keyId, counter: nil))
        refused("registry_pending") { try validate(keyPayload("key.rotate", signer: a.keyId, target: b.keyId, pub: b.fingerprint, revision: fp), r) }  // SD-T42
        XCTAssertNoThrow(try validate(payload(keyId: a.keyId), r))  // ordinary approvals stay possible while PENDING
    }

    func testRevocationRules() throws {
        let a = rk(SoftKey()), b = rk(SoftKey())
        let one = registry([a]), two = registry([a, b])
        refused("self_revocation") { try validate(keyPayload("key.revoke", signer: a.keyId, target: a.keyId, revision: "trust:\(two.expectedFingerprint)"), two) }
        refused("unknown_target") { try validate(keyPayload("key.revoke", signer: a.keyId, target: "p256:" + String(repeating: "0", count: 32), revision: "trust:\(two.expectedFingerprint)"), two) }
        XCTAssertNoThrow(try validate(keyPayload("key.revoke", signer: a.keyId, target: b.keyId, revision: "trust:\(two.expectedFingerprint)"), two))
        let rec = rk(SoftKey(), role: "recovery", custody: "external-fido2", cred: [9])
        let withRecovery = registry([a, rec])
        refused("last_operator_key") { try validate(keyPayload("key.revoke", signer: rec.keyId, target: a.keyId, revision: "trust:\(withRecovery.expectedFingerprint)"), withRecovery) }
        _ = one
    }

    func testRecoveryMayOnlyEnrolAReplacementGeneratedInThisSession() throws {  // SD-T32, SD-T33, SD-T49
        let a = rk(SoftKey(), custody: "lost"), rec = rk(SoftKey(), role: "recovery", custody: "external-fido2", cred: [7])
        var r = registry([a, rec])
        r.recoverySession = "s1"
        let fp = "trust:\(r.expectedFingerprint)"
        let inSession = rk(SoftKey(), status: "candidate", session: "s1"), stray = rk(SoftKey(), status: "candidate", session: nil)
        r.keys[inSession.keyId] = inSession
        r.keys[stray.keyId] = stray
        XCTAssertEqual(try validate(keyPayload("key.rotate", signer: rec.keyId, target: inSession.keyId, pub: inSession.fingerprint, revision: fp), r).signerRole, "recovery")
        refused("recovery_candidate_refused") { try validate(keyPayload("key.rotate", signer: rec.keyId, target: stray.keyId, pub: stray.fingerprint, revision: fp), r) }
        refused("action_not_permitted") { try validate(payload(keyId: rec.keyId), r) }
        refused("self_revocation") { try validate(keyPayload("key.revoke", signer: rec.keyId, target: rec.keyId, revision: fp), r) }
    }
}

final class RegistryTests: XCTestCase {
    func testProjectionIsTheEngineTrustStoreForm() throws {
        let k = rk(SoftKey())
        let r = registry([k, rk(SoftKey(), status: "candidate")])
        let entry = r.projection["keys"]!
        guard case let .array(items) = entry else { return XCTFail() }
        XCTAssertEqual(items.count, 1)  // candidates are not on the DM
        XCTAssertEqual(items[0].keys.sorted(), ["algorithm", "expires_at", "key_id", "operator", "permitted_actions", "public", "role", "status"])
        XCTAssertEqual(items[0]["algorithm"], .string("ecdsa-p256-sha256"))
        XCTAssertEqual(Registry.emptyFingerprint, sha256Hex(Array(#"{"keys":[]}"#.utf8)))
        let rec = rk(SoftKey(), role: "recovery", custody: "external-fido2", cred: [1, 2, 3])
        XCTAssertEqual(rec.projection.keys.sorted(), ["algorithm", "cose_alg", "counter_mode", "credential_id_b64", "expires_at", "key_id", "last_count",
                                                      "operator", "permitted_actions", "public", "role", "rp_id", "status"])
        XCTAssertEqual(rec.projection["permitted_actions"], .array([.string("key.revoke"), .string("key.rotate")]))
    }

    func testPersistenceRoundTripsEveryField() throws {
        var r = registry([rk(SoftKey()), rk(SoftKey(), role: "recovery", custody: "external-fido2", cred: [5, 6])])
        let c = rk(SoftKey(), status: "candidate", session: "s")
        r.keys[c.keyId] = c
        r.recoverySession = "s"
        try r.begin(PendingChange(requestId: rid32, payloadSHA256: String(repeating: "a", count: 64), action: "key.rotate", expiresAt: now, target: c.keyId, signer: r.activeOperators[0].keyId, counter: nil))
        XCTAssertEqual(try Registry.decode(r.encode()), r)
        refused("registry_invalid") { try Registry.decode(Array(#"{"format":"x","keys":[]}"#.utf8)) }
    }

    func testStateMachineHasNoAutomaticTransitions() throws {  // SD-T47
        let a = rk(SoftKey()), b = rk(SoftKey(), status: "candidate")
        var r = registry([a, b])
        let before = r.expectedFingerprint
        let p = PendingChange(requestId: rid32, payloadSHA256: String(repeating: "a", count: 64), action: "key.rotate", expiresAt: now + 100, target: b.keyId, signer: a.keyId, counter: nil)
        try r.begin(p)
        refused("registry_pending") { try r.begin(p) }
        XCTAssertEqual(r.expectedFingerprint, before)  // the expected fingerprint comes from the committed registry
        var abandoned = r
        try abandoned.markAbandoning()
        refused("not_expired") { try abandoned.resolveAbandon(now: now, changePresentOnDM: false) }
        var gone = abandoned
        XCTAssertEqual(try gone.resolveAbandon(now: now + 101, changePresentOnDM: false), "ABANDONED")
        XCTAssertEqual(gone.keys[b.keyId]?.status, "candidate")
        XCTAssertEqual(try abandoned.resolveAbandon(now: now + 101, changePresentOnDM: true), "COMMITTED")
        XCTAssertEqual(abandoned.keys[b.keyId]?.status, "active")
        refused("not_abandoning") { try r.resolveAbandon(now: now + 101, changePresentOnDM: false) }
        try r.commit()
        XCTAssertEqual(r.state, "IDLE")
        XCTAssertEqual(r.keys[b.keyId]?.enrolledBy, String(repeating: "a", count: 64))
        XCTAssertNotEqual(r.expectedFingerprint, before)
        refused("nothing_pending") { try r.commit() }
    }

    func testTrustStoreAuditDetectsSubstitution() throws {  // design §2.4, SD-T20, SD-T21
        let a = rk(SoftKey()), r = registry([a])
        let good = Canonical.encode(r.projection)
        XCTAssertTrue(try TrustAudit.compare(good, registry: r).match)
        let attacker = rk(SoftKey())
        let added = Canonical.encode(.object([("keys", .array([a.projection, attacker.projection].sorted { $0["key_id"]!.string! < $1["key_id"]!.string! }))]))
        XCTAssertEqual(try TrustAudit.compare(added, registry: r).onlyOnDM, [attacker.keyId])
        var revoked = a
        revoked.status = "revoked"
        var rr = registry([revoked])
        rr.clockCheckedAt = now
        let unrevoked = try TrustAudit.compare(good, registry: rr)
        XCTAssertFalse(unrevoked.match)
        XCTAssertEqual(unrevoked.different, ["\(a.keyId).status"])
        refused("audit_not_canonical") { try TrustAudit.compare(Array(#"{ "keys":[]}"#.utf8), registry: r) }
        refused("audit_bad_size") { try TrustAudit.compare([UInt8](repeating: 0x20, count: TrustAudit.maxBytes + 1), registry: r) }
        refused("audit_bad_shape") { try TrustAudit.compare(Array(#"{"keys":[],"x":1}"#.utf8), registry: r) }
    }
}

/// A software FIDO2 authenticator for the recovery tests (never in the product).
struct SoftAuthenticator: RecoveryAuthenticator {
    let k = P256.Signing.PrivateKey(), cred: [UInt8] = [1, 2, 3, 4]
    var count: UInt32 = 5, flags: UInt8 = 0x05, rp = "sentinel-recovery.invalid"
    var x963: [UInt8] { Array(k.publicKey.x963Representation) }
    var mutateClientData: (([UInt8]) -> [UInt8])? = nil
    func assert(challenge: [UInt8], credentialId: [UInt8]) throws -> Assertion {
        let ad = Array(SHA256.hash(data: Data(rp.utf8))) + [flags] + withUnsafeBytes(of: count.bigEndian, Array.init)
        let cd = (mutateClientData ?? { $0 })(Recovery.clientData(challenge))
        let sig = try k.signature(for: Data(ad + Array(SHA256.hash(data: Data(cd)))))
        return Assertion(authenticatorData: ad, clientDataJSON: cd, credentialId: credentialId, signature: Array(sig.derRepresentation))
    }
}

final class RecoveryTests: XCTestCase {
    func key(_ a: SoftAuthenticator, mode: String = "unset", last: Int64 = 0) -> RegistryKey {
        var r = RegistryKey(keyId: KeyIdentity.keyId(publicX963: a.x963), role: "recovery", publicX963: a.x963, operatorName: "owner",
                            expiresAt: now + 100, status: "active", custody: "external-fido2", recovery: RecoveryCredential(credentialId: a.cred, counterMode: mode, lastCount: last))
        r.status = "active"
        return r
    }

    func testStrictVerificationEveryRule() throws {  // final review §1.3, SD-T36
        let p = payload(action: "key.revoke", keyId: "p256:x", life: 600)
        let a = SoftAuthenticator()
        XCTAssertEqual(try Recovery.verify(try a.assert(challenge: Recovery.challenge(p), credentialId: a.cred), payload: p, key: key(a)).lastCount, 5)
        func bad(_ code: String, _ m: (inout SoftAuthenticator) -> Void, cred: [UInt8]? = nil, otherPayload: Bool = false) throws {
            var x = a
            m(&x)
            let asr = try x.assert(challenge: Recovery.challenge(otherPayload ? payload(keyId: "p256:y") : p), credentialId: cred ?? a.cred)
            refused(code) { try Recovery.verify(asr, payload: p, key: key(a)) }
        }
        try bad("bad_client_data") { $0.mutateClientData = { Array(String(decoding: $0, as: UTF8.self).replacingOccurrences(of: "}", with: #","topOrigin":"x"}"#).utf8) } }
        try bad("bad_client_data") { $0.mutateClientData = { Array(String(decoding: $0, as: UTF8.self).replacingOccurrences(of: "https://sentinel-recovery.invalid", with: "https://sentinel-recovery.invalid/").utf8) } }
        try bad("bad_client_data") { $0.mutateClientData = { Array(String(decoding: $0, as: UTF8.self).replacingOccurrences(of: "webauthn.get", with: "webauthn.create").utf8) } }
        try bad("bad_client_data", { _ in }, otherPayload: true)  // challenge for another payload (SD-T48)
        try bad("bad_rp_id") { $0.rp = "example.com" }
        try bad("presence_missing") { $0.flags = 0x04 }
        try bad("presence_missing") { $0.flags = 0x01 }
        try bad("bad_flags") { $0.flags = 0x45 }
        try bad("bad_flags") { $0.flags = 0x85 }
        try bad("wrong_credential", { _ in }, cred: [9])
        let good = try a.assert(challenge: Recovery.challenge(p), credentialId: a.cred)
        refused("bad_authenticator_data") { try Recovery.verify(Assertion(authenticatorData: good.authenticatorData + [0], clientDataJSON: good.clientDataJSON, credentialId: a.cred, signature: good.signature), payload: p, key: key(a)) }
        refused("bad_signature") { try Recovery.verify(Assertion(authenticatorData: good.authenticatorData, clientDataJSON: good.clientDataJSON, credentialId: a.cred, signature: try SoftAuthenticator().assert(challenge: Recovery.challenge(p), credentialId: a.cred).signature), payload: p, key: key(a)) }
        var op = key(a)
        op.role = "operator"
        refused("wrong_key_role") { try Recovery.verify(good, payload: p, key: op) }
    }

    func testCounterPolicy() throws {  // final review §2, SD-T51
        let c = RecoveryCredential(credentialId: [1])
        XCTAssertEqual(try Recovery.nextCounter(c, 0).counterMode, "zero")
        XCTAssertEqual(try Recovery.nextCounter(c, 7).counterMode, "increasing")
        let inc = RecoveryCredential(credentialId: [1], counterMode: "increasing", lastCount: 7)
        XCTAssertEqual(try Recovery.nextCounter(inc, 8).lastCount, 8)
        refused("counter_not_increasing") { try Recovery.nextCounter(inc, 7) }
        refused("counter_rollback") { try Recovery.nextCounter(inc, 0) }
        refused("counter_mode_changed") { try Recovery.nextCounter(RecoveryCredential(credentialId: [1], counterMode: "zero"), 1) }
        XCTAssertTrue(Recovery.suspectCodes.isSuperset(of: ["counter_rollback", "counter_mode_changed"]))
        XCTAssertFalse(Recovery.suspectCodes.contains("counter_not_increasing"))
    }

    func testChallengeAndClientDataMatchTheEngine() {
        // Engine (recovery.py): sha256(b"sentinel/v1/recovery-assertion\0" + canonical(payload)); base64url, no padding.
        let p = JSONValue.object([("a", .int(1))])
        XCTAssertEqual(Recovery.challenge(p), Array(SHA256.hash(data: Data(Array("sentinel/v1/recovery-assertion".utf8) + [0] + Array(#"{"a":1}"#.utf8)))))
        XCTAssertFalse(Recovery.b64url([0xfb, 0xff]).contains("="))
        XCTAssertEqual(Recovery.b64url([0xfb, 0xff]), "-_8")
    }

    func testAttestationParsingAcceptsOnlyES256() throws {
        let k = P256.Signing.PrivateKey(), x963 = Array(k.publicKey.x963Representation)
        func cbor(_ cose: [UInt8], rp: String = "sentinel-recovery.invalid") -> [UInt8] {
            let cred: [UInt8] = [0xaa, 0xbb]
            let ad = Array(SHA256.hash(data: Data(rp.utf8))) + [0x45, 0, 0, 0, 1] + [UInt8](repeating: 0, count: 16) + [0, 2] + cred + cose
            return [0xa1, 0x68] + Array("authData".utf8) + [0x58, UInt8(ad.count)] + ad
        }
        let good: [UInt8] = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20] + Array(x963[1...32]) + [0x22, 0x58, 0x20] + Array(x963[33...64])
        let (cid, x) = try Recovery.parseAttestation(cbor(good))
        XCTAssertEqual(cid, [0xaa, 0xbb])
        XCTAssertEqual(x, x963)
        var eddsa = good
        eddsa[4] = 0x27  // alg -8
        refused("attestation_not_es256") { try Recovery.parseAttestation(cbor(eddsa)) }
        refused("bad_attestation") { try Recovery.parseAttestation(cbor(good, rp: "example.com")) }
        refused("bad_cbor") { try Recovery.parseAttestation([0xa1, 0x7f]) }
    }
}

final class DeviceRecoveryTests: XCTestCase {
    func testACounterRollbackMarksTheRecoveryKeySuspectAndSignsNothing() throws {  // SD-T51
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("drec-\(UUID().uuidString)")
        let d = try Device(dir: dir)
        var auth = SoftAuthenticator()
        auth.count = 3
        let op = rk(SoftKey()), b = rk(SoftKey())
        var rec = RegistryKey(keyId: KeyIdentity.keyId(publicX963: auth.x963), role: "recovery", publicX963: auth.x963, operatorName: "owner",
                              expiresAt: now + 1000, status: "active", custody: "external-fido2",
                              recovery: RecoveryCredential(credentialId: auth.cred, counterMode: "increasing", lastCount: 9))
        rec.status = "active"
        d.registry = registry([op, b, rec])
        let v = try validate(keyPayload("key.revoke", signer: rec.keyId, target: b.keyId, revision: "trust:\(d.registry.expectedFingerprint)"), d.registry)
        refused("counter_rollback") { try d.sign(v, key: nil, authenticator: auth, now: now) }
        XCTAssertTrue(d.registry.keys[rec.keyId]!.suspect)
        XCTAssertEqual(d.registry.state, "IDLE")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: d.outbox.path), [])
        XCTAssertTrue(try Registry.decode(Array(try Data(contentsOf: dir.appendingPathComponent("registry.json")))).keys[rec.keyId]!.suspect)
        auth.count = 10
        refused("key_suspect") { try validate(keyPayload("key.revoke", signer: rec.keyId, target: b.keyId, revision: "trust:\(d.registry.expectedFingerprint)"), d.registry) }
    }

    func testAKeyOperationBecomesPendingOnlyAfterSigning() throws {
        let d = try Device(dir: URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dpend-\(UUID().uuidString)"))
        let k = SoftKey(), cand = rk(SoftKey(), status: "candidate")
        d.registry = registry([rk(k), cand])
        let v = try validate(keyPayload("key.rotate", signer: rk(k).keyId, target: cand.keyId, pub: cand.fingerprint, revision: "trust:\(d.registry.expectedFingerprint)"), d.registry)
        XCTAssertEqual(d.registry.state, "IDLE")
        _ = try d.sign(v, key: k, authenticator: nil, now: now)
        XCTAssertEqual(d.registry.state, "PENDING")
        XCTAssertEqual(d.registry.pending?.target, cand.keyId)
        XCTAssertEqual(d.registry.keys[cand.keyId]?.status, "candidate")  // applied only on commit
        try d.commitPending(now: now)
        XCTAssertEqual(d.registry.keys[cand.keyId]?.status, "active")
    }
}

final class CheckpointTests: XCTestCase {
    func setupDevice() throws -> (Device, SoftKey) {
        let d = try Device(dir: URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dev-\(UUID().uuidString)"))
        d.volumeCheck = noCheck
        let k = SoftKey()
        try d.clockChecked(now: now)
        try d.addCandidate(rk(k, status: "candidate"), now: now)
        d.registry.keys[rk(k).keyId]!.status = "active"
        try d.save()
        try d.ledger.recordSeen(requestId: String(repeating: "7", count: 32), expiresAt: now + 100)
        return (d, k)
    }

    func testSignedCheckpointRestoresOnlyWithTheExactPaperAnchor() throws {  // D-46, SD-T52, SD-T53
        let (d, k) = try setupDevice()
        let body1 = d.checkpointBody(device: "SD1", now: now), rec1 = try Checkpoint.sign(body1, key: k)
        XCTAssertTrue(try d.recordCheckpoint(body1, retypedHash: Checkpoint.hash(body1), now: now))
        let b2 = SoftKey()
        d.registry.keys[rk(b2).keyId] = rk(b2, status: "candidate")
        try d.registry.begin(PendingChange(requestId: rid32, payloadSHA256: String(repeating: "a", count: 64), action: "key.rotate", expiresAt: now + 60, target: rk(b2).keyId, signer: rk(k).keyId, counter: nil))
        let body2 = d.checkpointBody(device: "SD1", now: now + 1), rec2 = try Checkpoint.sign(body2, key: k), h2 = Checkpoint.hash(body2)
        XCTAssertEqual(body2["sequence"]?.int, 2)
        XCTAssertFalse(try d.recordCheckpoint(body2, retypedHash: String(repeating: "0", count: 64), now: now))  // unanchored
        let fresh = try Device(dir: URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("new-\(UUID().uuidString)"))
        let fp = rk(k).fingerprint
        refused("anchor_mismatch") { try fresh.restore(rec2, paperFingerprint: fp, paperSequence: 1, paperHash: h2, older: [rec1], now: now) }
        refused("anchor_mismatch") { try fresh.restore(rec2, paperFingerprint: fp, paperSequence: 2, paperHash: Checkpoint.hash(body1), older: [rec1], now: now) }
        refused("fingerprint_mismatch") { try fresh.restore(rec2, paperFingerprint: String(repeating: "f", count: 64), paperSequence: 2, paperHash: h2, older: [rec1], now: now) }
        var tampered = rec2
        if let i = tampered.firstIndex(of: UInt8(ascii: "S")) { tampered[i] = UInt8(ascii: "T") }  // "SD1" -> "TD1"
        refused("bad_signature") { try fresh.restore(tampered, paperFingerprint: fp, paperSequence: 2, paperHash: h2, older: [], now: now) }
        let stray = try Checkpoint.sign(d.checkpointBody(device: "SD9", now: now + 5), key: k)  // sequence 2, not on the chain
        refused("chain_broken") { try fresh.restore(rec2, paperFingerprint: fp, paperSequence: 2, paperHash: h2, older: [rec1, stray], now: now) }
        try fresh.restore(rec2, paperFingerprint: fp, paperSequence: 2, paperHash: h2, older: [rec1], now: now)
        XCTAssertEqual(fresh.registry.state, "PENDING")  // D-46 item 6
        XCTAssertEqual(fresh.registry.keys[rk(k).keyId]?.custody, "lost")
        refused("duplicate_request") { try fresh.ledger.check(requestId: String(repeating: "7", count: 32), nonce: String(repeating: "0", count: 32), payloadSHA256: "x", oneTime: false) }
        refused("registry_not_empty") { try fresh.restore(rec2, paperFingerprint: fp, paperSequence: 2, paperHash: h2, older: [rec1], now: now) }  // item 7
    }
}

final class ReleaseTests: XCTestCase {
    func testOnlyAnOperatorSignedSuccessorReleaseInstalls() throws {  // R3.4, R3.7, SD-T37..SD-T39, SD-T50
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("rel-\(UUID().uuidString)")
        let d = try Device(dir: root.appendingPathComponent("sd"))
        let k = SoftKey(), recoveryKey = SoftKey()
        d.registry = registry([rk(k), rk(recoveryKey, role: "recovery", custody: "external-fido2", cred: [1])])
        let tree = root.appendingPathComponent("tree")
        try FileManager.default.createDirectory(at: tree.appendingPathComponent(".build"), withIntermediateDirectories: true)
        try Data("main".utf8).write(to: tree.appendingPathComponent("main.swift"))
        try Data("ignored".utf8).write(to: tree.appendingPathComponent(".build/x"))
        let th = try Release.treeSHA256(tree)
        try Data("changed".utf8).write(to: tree.appendingPathComponent(".build/x"))
        XCTAssertEqual(try Release.treeSHA256(tree), th)  // build products don't count
        try Data("main2".utf8).write(to: tree.appendingPathComponent("main.swift"))
        XCTAssertNotEqual(try Release.treeSHA256(tree), th)
        try FileManager.default.createSymbolicLink(at: tree.appendingPathComponent("link"), withDestinationURL: tree.appendingPathComponent("main.swift"))
        refused("tree_special_file") { try Release.treeSHA256(tree) }
        let bin = root.appendingPathComponent("sentinel-signer")
        try Data("binary-v1".utf8).write(to: bin)
        let commit = String(repeating: "a", count: 40)
        func record(_ key: SoftKey, _ binary: String = sha256Hex(Array("binary-v1".utf8)), at t: Int64 = now, nonce: String = String(repeating: "1", count: 32)) throws -> [UInt8] {
            try Release.record(Release.payload(commit: commit, tree: th, binary: binary, toolchain: "swift 6", device: "SD",
                                               registry: d.registry, keyId: KeyIdentity.keyId(publicX963: key.publicX963), now: t, nonce: nonce), key: key)
        }
        refused("release_key_refused") { try d.install(record: try record(recoveryKey), binary: bin, now: now) }  // SD-T50
        refused("binary_mismatch") { try d.install(record: try record(k, String(repeating: "0", count: 64)), binary: bin, now: now) }
        refused("release_expired") { try d.install(record: try record(k, at: now - 7200), binary: bin, now: now) }
        // Deterministic forgeries (a byte flip in the base64 text could land on an invalid character and be
        // refused as malformed before the signature is ever checked): a corrupted signature, and a signed
        // field changed under a valid signature. Both must be refused by the signature check itself.
        func reencode(_ rec: [UInt8], sig: ((inout [UInt8]) -> Void)? = nil, toolchain: String? = nil) throws -> [UInt8] {
            let v = try Canonical.decode(rec)
            var der = Array(Data(base64Encoded: v["signature_der_b64"]!.string!)!)
            sig?(&der)
            var p = v["payload"]!
            if let t = toolchain, case let .object(kv) = p {
                var out: [(String, JSONValue)] = []
                for (name, value) in kv {
                    guard name == "subject", case let .object(sub) = value else { out.append((name, value)); continue }
                    out.append((name, .object(sub.map { field in field.0 == "toolchain" ? (field.0, .string(t)) : field })))
                }
                p = .object(out)
            }
            return Canonical.encode(.object([("payload", p), ("signature_der_b64", .string(Data(der).base64EncodedString()))]))
        }
        refused("bad_signature") { try d.install(record: try reencode(try record(k)) { $0[$0.count - 1] ^= 1 }, binary: bin, now: now) }
        refused("bad_signature") { try d.install(record: try reencode(try record(k), toolchain: "swift 7"), binary: bin, now: now) }
        let good = try record(k)
        XCTAssertEqual(try d.install(record: good, binary: bin, now: now), commit)
        XCTAssertEqual(d.registry.signerCommit, commit)
        XCTAssertEqual(try String(contentsOf: root.appendingPathComponent("sd/current"), encoding: .utf8), "\(commit)\n")
        refused("release_not_successor") { try d.install(record: good, binary: bin, now: now) }  // replay: no longer the successor
    }
}

final class TransportTests: XCTestCase {
    func volume() throws -> URL {
        let v = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("vol-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: v.appendingPathComponent("sentinel-v1/to-signer"), withIntermediateDirectories: true)
        return v
    }

    func testVolumeChecksBeforeAnyFileAccess() {  // R3.2, SD-T43, SD-T44, SD-T22
        let flags = UInt32(MNT_NOEXEC | MNT_NOSUID | MNT_NODEV | MNT_DONTBROWSE)
        XCTAssertNil(Transport.volumeProblem(VolumeInfo(fsType: "apfs", flags: flags | UInt32(MNT_RDONLY), encrypted: false), readOnly: true))
        XCTAssertNil(Transport.volumeProblem(VolumeInfo(fsType: "apfs", flags: flags, encrypted: false), readOnly: false))
        XCTAssertEqual(Transport.volumeProblem(VolumeInfo(fsType: "exfat", flags: flags | UInt32(MNT_RDONLY), encrypted: false), readOnly: true), "fs_not_apfs")
        XCTAssertEqual(Transport.volumeProblem(VolumeInfo(fsType: "msdos", flags: flags | UInt32(MNT_RDONLY), encrypted: false), readOnly: true), "fs_not_apfs")
        XCTAssertEqual(Transport.volumeProblem(VolumeInfo(fsType: "hfs", flags: flags | UInt32(MNT_RDONLY), encrypted: false), readOnly: true), "fs_not_apfs")
        XCTAssertEqual(Transport.volumeProblem(VolumeInfo(fsType: "apfs", flags: flags | UInt32(MNT_RDONLY), encrypted: true), readOnly: true), "fs_encrypted")
        XCTAssertEqual(Transport.volumeProblem(VolumeInfo(fsType: "apfs", flags: flags, encrypted: false), readOnly: true), "mount_flags")
        XCTAssertEqual(Transport.volumeProblem(VolumeInfo(fsType: "apfs", flags: UInt32(MNT_RDONLY | MNT_NOEXEC), encrypted: false), readOnly: true), "mount_flags")
        XCTAssertEqual(Transport.volumeProblem(VolumeInfo(fsType: "apfs", flags: flags | UInt32(MNT_RDONLY), encrypted: false), readOnly: false), "volume_read_only")
        XCTAssertEqual(Transport.volumeProblem(nil, readOnly: true), "volume_unreadable")
        // A plain temporary directory is not a properly mounted transfer volume: refused before any read.
        XCTAssertThrowsError(try Transport.intake(volume: URL(fileURLWithPath: NSTemporaryDirectory()), spool: URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("s-\(UUID().uuidString)")))
    }

    func testIntakeRefusesHazardsAndCopiesToSpool() throws {
        let v = try volume(); let to = v.appendingPathComponent("sentinel-v1/to-signer")
        let good = String(repeating: "a", count: 32)
        try Data("{}".utf8).write(to: to.appendingPathComponent("req-\(good).json"))
        try Data("x".utf8).write(to: v.appendingPathComponent("outside.json"))
        try FileManager.default.createSymbolicLink(at: to.appendingPathComponent("req-\(String(repeating: "b", count: 32)).json"), withDestinationURL: v.appendingPathComponent("outside.json"))
        try FileManager.default.linkItem(at: v.appendingPathComponent("outside.json"), to: to.appendingPathComponent("req-\(String(repeating: "d", count: 32)).json"))
        try Data(repeating: 0x7b, count: Policy.maxRequestBytes + 1).write(to: to.appendingPathComponent("req-\(String(repeating: "e", count: 32)).json"))
        mkfifo(to.appendingPathComponent("req-\(String(repeating: "f", count: 32)).json").path, 0o600)
        try Data("x".utf8).write(to: to.appendingPathComponent("._req-\(good).json"))
        try Data("x".utf8).write(to: to.appendingPathComponent(".req-\(good).json.tmp"))
        try Data("{}".utf8).write(to: to.appendingPathComponent(Transport.auditName))
        let spool = v.appendingPathComponent("spool")
        let r = try Transport.intake(volume: v, spool: spool, volumeCheck: noCheck)
        XCTAssertEqual(r.items.map { $0.requestId }, [good])
        XCTAssertEqual(Set(r.refused.map { $0.1 }), ["symlink", "hard_linked", "bad_size", "not_regular_file"])
        XCTAssertTrue(r.ignored.contains("._req-\(good).json") && r.ignored.contains(".req-\(good).json.tmp"))
        XCTAssertEqual(r.audit, Array("{}".utf8))
        XCTAssertEqual(try Data(contentsOf: spool.appendingPathComponent("req-\(good).json")), Data("{}".utf8))
    }

    func testAnInterruptedIntakeLeavesNothingInTheSpool() throws {  // R3.1, SD-T46
        let v = try volume(), spool = v.appendingPathComponent("spool")
        try Data("{}".utf8).write(to: v.appendingPathComponent("sentinel-v1/to-signer/req-\(String(repeating: "a", count: 32)).json"))
        var calls = 0
        XCTAssertThrowsError(try Transport.intake(volume: v, spool: spool, volumeCheck: { _, _ in calls += 1; return calls > 1 ? "volume_unreadable" : nil }))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: spool.path), [])
    }

    func testIntakeRefusesSymlinkedDirectoriesAndTooManyRequests() throws {
        let v = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("vol-\(UUID().uuidString)")
        let real = v.appendingPathComponent("real"); try FileManager.default.createDirectory(at: real.appendingPathComponent("to-signer"), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: v.appendingPathComponent("sentinel-v1"), withDestinationURL: real)
        refused("symlinked_directory") { try Transport.intake(volume: v, spool: v.appendingPathComponent("s"), volumeCheck: noCheck) }
        let w = try volume()
        for i in 0..<17 { try Data("{}".utf8).write(to: w.appendingPathComponent("sentinel-v1/to-signer/req-\(String(format: "%032x", i)).json")) }
        refused("too_many_requests") { try Transport.intake(volume: w, spool: w.appendingPathComponent("s"), volumeCheck: noCheck) }
    }

    func testOutputIsExclusiveAndNeverOverwrites() throws {
        let v = try volume(); let rid = String(repeating: "a", count: 32)
        _ = try Transport.writeResponse(volume: v, requestId: rid, body: Array("first".utf8), volumeCheck: noCheck)
        refused("output_exists") { try Transport.writeResponse(volume: v, requestId: rid, body: Array("second".utf8), volumeCheck: noCheck) }
        XCTAssertEqual(try String(contentsOf: v.appendingPathComponent("sentinel-v1/from-signer/resp-\(rid).json"), encoding: .utf8), "first")
        refused("response_too_large") { try Transport.writeResponse(volume: v, requestId: String(repeating: "b", count: 32), body: Array(repeating: 1, count: 2049), volumeCheck: noCheck) }
        refused("fs_not_apfs") { try Transport.writeResponse(volume: v, requestId: rid, body: [1], volumeCheck: { _, _ in "fs_not_apfs" }) }
    }

    func testFailedOutputStaysQueuedAndDeliveredOutputIsReissuedIdentically() throws {  // R3.1, SD-T46
        let v = try volume()
        let d = try Device(dir: v.appendingPathComponent("sd"))
        d.volumeCheck = noCheck
        let k = SoftKey()
        d.registry = registry([rk(k)])
        let vr = try validate(payload(keyId: rk(k).keyId), d.registry)
        let body = try d.sign(vr, key: k, authenticator: nil, now: now)
        let out = v.appendingPathComponent("sentinel-v1/from-signer/resp-\(rid32).json")
        try FileManager.default.createDirectory(at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("occupied".utf8).write(to: out)
        XCTAssertEqual(try d.deliver(volume: v, now: now), [])  // output_failed: still queued, never re-signed
        try FileManager.default.removeItem(at: out)
        XCTAssertEqual(try d.deliver(volume: v, now: now), [rid32])
        try FileManager.default.removeItem(at: out)  // e.g. the write was lost
        XCTAssertEqual(try d.deliver(volume: v, reissue: rid32, now: now), [rid32])
        XCTAssertEqual(Array(try Data(contentsOf: out)), body)
        let log = try String(contentsOf: v.appendingPathComponent("sd/log.jsonl"), encoding: .utf8)
        XCTAssertTrue(log.contains("output_failed") && log.contains("output_reissued"))
        XCTAssertEqual(log.components(separatedBy: "\"event\":\"signed\"").count - 1, 1)
    }

    func testCeremonyHashCoversTheLoggedSteps() throws {
        let d = try Device(dir: URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("cer-\(UUID().uuidString)"))
        XCTAssertNil(try d.ceremony("start", facts: [("device", .string("SD"))], now: now))
        refused("ceremony_in_progress") { try d.ceremony("start", facts: [], now: now) }
        try d.clockChecked(now: now)
        let h = try d.ceremony("end", facts: [], now: now)
        XCTAssertEqual(h?.count, 64)
        refused("no_ceremony") { try d.ceremony("end", facts: [], now: now) }
        refused("clock_regressed") { try d.clockChecked(now: now - 1) }
    }

    func testAuditLogIsHashChainedAndDetectsTampering() throws {
        let p = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("log-\(UUID().uuidString).jsonl")
        let log = try AuditLog(path: p)
        try log.append("intake", [("n", .int(1))], now: now)
        try log.append("signed", [("n", .int(2))], now: now)
        XCTAssertEqual(try AuditLog(path: p).seq, 2)
        var text = try String(contentsOf: p, encoding: .utf8)
        text = text.replacingOccurrences(of: "\"n\":1", with: "\"n\":9")
        try text.write(to: p, atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try AuditLog(path: p)) { XCTAssertEqual(($0 as? Refusal)?.code, "log_chain_broken") }
    }

    func testLedgerPersistsAcrossRestarts() throws {
        let p = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("ledger-\(UUID().uuidString).json")
        let l = try Ledger(path: p)
        try l.recordSeen(requestId: String(repeating: "a", count: 32), expiresAt: now)
        XCTAssertThrowsError(try Ledger(path: p).check(requestId: String(repeating: "a", count: 32), nonce: String(repeating: "0", count: 32), payloadSHA256: "x", oneTime: false))
        XCTAssertEqual(try Ledger(path: p).prune(now: now + Ledger.retention + 1), 1)
    }

    func testKeyIdMatchesTheEngineDerivation() {
        // The engine: "p256:" + sha256(b"ecdsa-p256-sha256\0" + x963)[:32]; checked against Python in the interop test.
        let raw = [UInt8](repeating: 4, count: 65)
        XCTAssertEqual(KeyIdentity.keyId(publicX963: raw), "p256:" + String(sha256Hex(Array("ecdsa-p256-sha256".utf8) + [0] + raw).prefix(32)))
    }
}

/// D-74: `release.publish`, signed on the SD. The SD recomputes the SHA256SUMS digest from the listed
/// artifacts itself; only operator keys may sign it.
final class ReleasePublishTests: XCTestCase {
    let commit = "0123456789abcdef0123456789abcdef01234567"
    var key: SoftKey!; var id: String!; var reg: Registry!
    override func setUp() {
        key = SoftKey(); id = KeyIdentity.keyId(publicX963: key.publicX963)
        reg = registry([rk(key)])
    }
    func arts(_ names: [String], hash: String = String(repeating: "d", count: 64)) -> JSONValue {
        .array(names.map { .object([("name", .string($0)), ("sha256", .string(hash))]) })
    }
    let names = ["sentinel-sbom.cdx.json", "sentinel_audit-1.2.3-py3-none-any.whl", "sentinel_audit-1.2.3.tar.gz"]
    func sums(_ names: [String], hash: String = String(repeating: "d", count: 64)) -> String {
        sha256Hex(Array(names.map { "\(hash)  \($0)\n" }.joined().utf8))
    }
    func rel(names n: [String]? = nil, scope: JSONValue? = nil, revision: String? = nil, version: String = "1.2.3",
             name: String = "sentinel-audit", commit c: String? = nil, keyId: String? = nil, life: Int64 = 3600,
             nonce: String = String(repeating: "7", count: 32)) -> JSONValue {
        let n = n ?? names
        let subject: JSONValue = .object([("commit", .string(c ?? commit)), ("name", .string(name)), ("type", .string("release")), ("version", .string(version))])
        return payload(action: "release.publish", keyId: keyId ?? id, life: life, subject: subject,
                       revision: revision ?? "sums:\(sums(n))", nonce: nonce, scope: scope ?? .object([("artifacts", arts(n))]))
    }

    func testAValidReleaseValidatesSignsAndShowsEveryHash() throws {
        let v = try validate(rel(), reg)
        XCTAssertTrue(v.oneTime)
        XCTAssertEqual(try releaseSums(v.payload["scope"]!), Array(names.map { "\(String(repeating: "d", count: 64))  \($0)\n" }.joined().utf8))
        let resp = try Canonical.decode(try signResponse(v, key: key))
        let sig = try P256.Signing.ECDSASignature(derRepresentation: Data(base64Encoded: resp["signature_der_b64"]!.string!)!)
        XCTAssertTrue(key.k.publicKey.isValidSignature(sig, for: Data(v.payloadBytes)))
        let text = renderForApproval(v, deviceName: "SD").joined(separator: "\n")
        XCTAssertTrue(text.contains("PUBLISH RELEASE sentinel-audit 1.2.3"))
        XCTAssertTrue(text.contains("COMMIT \(commit)"))
        XCTAssertTrue(text.contains("independent reproducible build"))
        for n in names { XCTAssertTrue(text.contains("\n  \(n)\n"), n) }
        XCTAssertTrue(text.contains("    dddddddd dddddddd dddddddd dddddddd dddddddd dddddddd dddddddd dddddddd"))
    }

    func testTheSumsDigestMustBeRecomputedFromTheListedArtifacts() throws {
        refused("release_sums_mismatch") { try validate(rel(revision: "sums:" + String(repeating: "0", count: 64)), reg) }
        // An artifact list that differs from what the digest covers is refused, whatever the DM claims.
        refused("release_sums_mismatch") { try validate(rel(scope: .object([("artifacts", arts(Array(names.dropLast())))])), reg) }
        refused("release_version_mismatch") { try validate(rel(version: "9.9.9"), reg) }
    }

    func testMalformedArtifactListsAreRefused() throws {
        let h = String(repeating: "d", count: 64)
        for bad: [String] in [[names[1], names[0]], [names[1], names[1]], ["dir/x", names[1]], [".hidden", names[1]],
                              ["SHA256SUMS", names[1]], ["SHA256SUMS.approval.json", names[1]], ["../x", names[1]], []] {
            refused("bad_release_scope") { try validate(rel(names: bad), reg) }
        }
        refused("bad_release_scope") { try validate(rel(names: (0..<17).map { "a\($0 + 10)" }), reg) }
        refused("bad_release_scope") { try validate(rel(scope: .object([("artifacts", self.arts(self.names)), ("x", .int(1))])), reg) }
        refused("bad_release_scope") { try validate(rel(scope: .object([("artifacts", self.arts(self.names, hash: String(repeating: "D", count: 64)))])), reg) }
        refused("bad_release_scope") {
            try validate(rel(scope: .object([("artifacts", .array([.object([("name", .string(self.names[1])), ("sha256", .string(h)), ("x", .int(1))])]))])), reg)
        }
    }

    func testSubjectAndLifetimeRules() throws {
        refused("bad_subject") { try validate(rel(name: "other"), reg) }
        refused("bad_subject") { try validate(rel(commit: "ABC"), reg) }
        refused("bad_subject") { try validate(rel(version: "1_2"), reg) }
        refused("expiry_too_long") { try validate(rel(life: 3601), reg) }
    }

    func testOnlyOperatorKeysWithThePermissionMaySign() throws {
        let a = SoftKey()
        let rec = rk(a, role: "recovery", custody: "external-fido2", cred: [1, 2, 3])
        let r = registry([rk(key), rec])
        refused("action_not_permitted") { try validate(rel(keyId: rec.keyId), r) }
        var old = rk(key)
        old.permittedActions = old.permittedActions.filter { $0 != "release.publish" }
        refused("action_not_permitted") { try validate(rel(), registry([old])) }
    }

    func testAReleaseNonceSignsOnce() throws {
        let l = try Ledger(path: nil)
        try l.recordSigned(try validate(rel(), reg, l: l))
        refused("nonce_reused") { try validate(self.rel(), self.reg, l: l, rid: String(repeating: "e", count: 32)) }
    }

    func testOperatorPermissionsMatchTheEngineExactly() {
        XCTAssertEqual(rk(SoftKey()).permittedActions, ["authorize_record", "key.revoke", "key.rotate", "policy.change", "release.publish",
                                                        "review.accept_risk", "review.verify_no_evidence", "revoke_record", "suppress"])
    }
}
