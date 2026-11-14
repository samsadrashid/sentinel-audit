// TEST-ONLY interop driver. It runs SignerCore's real Device logic (registry, state machine, validation,
// transport, checkpoints, releases) with DISPOSABLE SOFTWARE keys and a SOFTWARE FIDO2 authenticator, so
// the development Mac's engine can be tested against real signer output. It is not the signer: no Touch
// ID, no Secure Enclave, no display, no volume checks. It must never be built for or installed on a
// signing device; its private keys are plain files in the test directory.
//
//   signer-interop keygen -                                  (legacy: print a raw key and its X9.63 public)
//   signer-interop <cmd> DIR ...                             (see the switch below)
import CryptoKit
import Foundation
import SignerCore

struct SoftwareKey: SigningKey {
    let k: P256.Signing.PrivateKey
    var publicX963: [UInt8] { Array(k.publicKey.x963Representation) }
    func sign(_ m: [UInt8]) throws -> [UInt8] { Array(try k.signature(for: Data(m)).derRepresentation) }
}

/// A software stand-in for a FIDO2 security key: ES256, UP and UV set, a persistent counter.
final class SoftwareAuthenticator: RecoveryAuthenticator {
    let k: P256.Signing.PrivateKey, credentialId: [UInt8], counterFile: URL
    init(_ k: P256.Signing.PrivateKey, _ c: [UInt8], _ f: URL) { (self.k, credentialId, counterFile) = (k, c, f) }
    func assert(challenge: [UInt8], credentialId cid: [UInt8]) throws -> Assertion {
        guard cid == credentialId else { throw Refusal(code: "no_credential") }
        let mode = (try? String(contentsOf: counterFile)) ?? "1"
        let n = UInt32(mode.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        try "\(n == 0 ? 0 : n + 1)".write(to: counterFile, atomically: true, encoding: .utf8)
        let ad = Array(SHA256.hash(data: Data("sentinel-recovery.invalid".utf8))) + [0x05] + withUnsafeBytes(of: n.bigEndian, Array.init)
        let cd = Recovery.clientData(challenge)
        let sig = try k.signature(for: Data(ad + Array(SHA256.hash(data: Data(cd)))))
        return Assertion(authenticatorData: ad, clientDataJSON: cd, credentialId: credentialId, signature: Array(sig.derRepresentation))
    }
}

func out(_ s: String) { print(s) }
let a = CommandLine.arguments
guard a.count >= 3 else { FileHandle.standardError.write("usage: signer-interop <cmd> DIR ...\n".data(using: .utf8)!); exit(2) }
let now = Int64(Date().timeIntervalSince1970)
if a[1] == "keygen" {
    let k = P256.Signing.PrivateKey()
    out(hex(Array(k.rawRepresentation))); out(hex(Array(k.publicKey.x963Representation)))
    exit(0)
}
let dir = URL(fileURLWithPath: a[2])
let keys = dir.appendingPathComponent("test-keys")
try FileManager.default.createDirectory(at: keys, withIntermediateDirectories: true)
let d = try Device(dir: dir)
d.volumeCheck = { _, _ in nil }  // TEST-ONLY: temporary directories are not transfer volumes

func softKey(_ id: String) throws -> SoftwareKey {
    SoftwareKey(k: try P256.Signing.PrivateKey(rawRepresentation: unhex(try String(contentsOf: keys.appendingPathComponent("\(id).key")))!))
}
func softAuth(_ id: String) throws -> SoftwareAuthenticator {
    let parts = try String(contentsOf: keys.appendingPathComponent("\(id).fido")).split(separator: " ").map(String.init)
    return SoftwareAuthenticator(try P256.Signing.PrivateKey(rawRepresentation: unhex(parts[0])!), unhex(parts[1])!, keys.appendingPathComponent("\(id).counter"))
}
func firstOperator() throws -> SoftwareKey {
    guard let k = d.registry.activeOperators.first(where: { FileManager.default.fileExists(atPath: keys.appendingPathComponent("\($0.keyId).key").path) }) else { throw Refusal(code: "no_operator") }
    return try softKey(k.keyId)
}

do {
    switch a[1] {
    case "init": try d.clockChecked(now: now)
    case "create-key":  // DIR NAME EXPIRES
        let k = P256.Signing.PrivateKey(), x = Array(k.publicKey.x963Representation), id = KeyIdentity.keyId(publicX963: x)
        try hex(Array(k.rawRepresentation)).write(to: keys.appendingPathComponent("\(id).key"), atomically: true, encoding: .utf8)
        try d.addCandidate(RegistryKey(keyId: id, role: "operator", publicX963: x, operatorName: a[3], expiresAt: Int64(a[4])!,
                                       status: "candidate", custody: "this-device", session: d.registry.recoverySession), now: now)
        out(id)
    case "register-recovery":  // DIR NAME EXPIRES [first-counter]
        let k = P256.Signing.PrivateKey(), x = Array(k.publicKey.x963Representation), id = KeyIdentity.keyId(publicX963: x)
        let cred = (0..<16).map { _ in UInt8.random(in: 0...255) }
        try "\(hex(Array(k.rawRepresentation))) \(hex(cred))".write(to: keys.appendingPathComponent("\(id).fido"), atomically: true, encoding: .utf8)
        try (a.count > 5 ? a[5] : "1").write(to: keys.appendingPathComponent("\(id).counter"), atomically: true, encoding: .utf8)
        try d.addCandidate(RegistryKey(keyId: id, role: "recovery", publicX963: x, operatorName: a[3], expiresAt: Int64(a[4])!,
                                       status: "candidate", custody: "external-fido2", recovery: RecoveryCredential(credentialId: cred)), now: now)
        out(id)
    case "set-counter": try a[4].write(to: keys.appendingPathComponent("\(a[3]).counter"), atomically: true, encoding: .utf8)
    case "export-pub": out(try d.exportPublic(keyId: a[3], volume: URL(fileURLWithPath: a[4]), now: now).path)
    case "sign":  // DIR VOLUME: intake, validate, sign every request, deliver
        let vol = URL(fileURLWithPath: a[3])
        let res = try d.intake(volume: vol, now: now)
        for (n, why) in res.refused { out("refused-file \(n) \(why)") }
        for item in res.items {
            do {
                let v = try d.validate(item.bytes, requestId: item.requestId, now: now)
                if v.signerRole == "recovery" { _ = try d.sign(v, key: nil, authenticator: try softAuth(v.keyId), now: now) }
                else { _ = try d.sign(v, key: try softKey(v.keyId), authenticator: nil, now: now) }
                out("signed \(v.requestId)")
            } catch let r as Refusal { out("refused \(item.requestId) \(r.code)") }
            try? FileManager.default.removeItem(at: d.spool.appendingPathComponent("req-\(item.requestId).json"))
        }
        for rid in try d.deliver(volume: vol, now: now) { out("delivered \(rid)") }
    case "reissue": for rid in try d.deliver(volume: URL(fileURLWithPath: a[3]), reissue: a[4], now: now) { out("reissued \(rid)") }
    case "audit":  // DIR TRUSTFILE
        let r = try d.audit(dmTrust: Array(try Data(contentsOf: URL(fileURLWithPath: a[3]))), now: now)
        out(r.match ? "MATCH" : "MISMATCH dm=\(r.onlyOnDM) sd=\(r.onlyOnSD) diff=\(r.different)")
        if d.registry.pending != nil { out("present \(d.registry.changePresent(in: r.dmKeys))") }
    case "commit": try d.commitPending(now: now)
    case "abandon": try d.abandonPending(now: now)
    case "resolve": out(try d.resolveAbandon(dmTrust: Array(try Data(contentsOf: URL(fileURLWithPath: a[3]))), now: Int64(a[4]) ?? now))
    case "state": out("\(d.registry.state) \(d.registry.expectedFingerprint)")
    case "status": out(d.registry.keys[a[3]].map { "\($0.status) suspect=\($0.suspect) counter=\($0.recovery?.counterMode ?? "-"):\($0.recovery?.lastCount ?? -1)" } ?? "unknown")
    case "recovery": out(try d.recoverySession(start: a[3] == "start", now: now))
    case "ceremony": out(try d.ceremony(a[3], facts: [("device", .string("test"))], now: now) ?? "started")
    case "checkpoint":  // DIR OUTFILE [RETYPED]
        let body = d.checkpointBody(device: "test", now: now)
        try Data(try Checkpoint.sign(body, key: try firstOperator())).write(to: URL(fileURLWithPath: a[3]))
        let h = Checkpoint.hash(body)
        out("\(body["sequence"]?.int ?? 0) \(h) anchored=\(try d.recordCheckpoint(body, retypedHash: a.count > 4 ? a[4] : h, now: now))")
    case "restore":  // DIR FILE FINGERPRINT SEQUENCE HASH [OLDER...]
        let older = try a.dropFirst(7).map { Array(try Data(contentsOf: URL(fileURLWithPath: $0))) }
        try d.restore(Array(try Data(contentsOf: URL(fileURLWithPath: a[3]))), paperFingerprint: a[4], paperSequence: Int64(a[5])!,
                      paperHash: a[6], older: older, now: now)
        out("restored \(d.registry.expectedFingerprint)")
    case "fingerprint": out(d.registry.keys[a[3]]?.fingerprint ?? "")
    case "release-sign":  // DIR COMMIT TREE BINARY OUTFILE [KEYID]
        let key = a.count > 7 ? try softKey(a[7]) : try firstOperator()
        let p = Release.payload(commit: a[3], tree: try Release.treeSHA256(URL(fileURLWithPath: a[4])),
                                binary: sha256Hex(Array(try Data(contentsOf: URL(fileURLWithPath: a[5])))), toolchain: "test",
                                device: "test", registry: d.registry, keyId: KeyIdentity.keyId(publicX963: key.publicX963), now: now,
                                nonce: hex((0..<16).map { _ in UInt8.random(in: 0...255) }))
        try Data(try Release.record(p, key: key)).write(to: URL(fileURLWithPath: a[6]))
    case "release-install": out(try d.install(record: Array(try Data(contentsOf: URL(fileURLWithPath: a[3]))), binary: URL(fileURLWithPath: a[4]), now: now))
    default: exit(2)
    }
} catch let r as Refusal {
    out("error \(r.code)")
    exit(3)
}
