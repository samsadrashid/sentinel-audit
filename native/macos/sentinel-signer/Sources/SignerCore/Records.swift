import CryptoKit
import Foundation

func verifyDER(_ sig: [UInt8], _ message: [UInt8], x963: [UInt8]) -> Bool {
    guard let pub = try? P256.Signing.PublicKey(x963Representation: x963),
          let s = try? P256.Signing.ECDSASignature(derRepresentation: sig) else { return false }
    return pub.isValidSignature(s, for: Data(message))
}

func hexN(_ s: String?, _ n: Int) -> Bool { guard let s else { return false }; return s.count == n && unhex(s) != nil }

/// D-46 signed registry checkpoints (final review §3). Built and signed only on explicit operator
/// confirmation; restoration needs the paper anchor and never overrides a mismatch.
public enum Checkpoint {
    public static let context = "sentinel/v1/registry-checkpoint"

    public static func body(registry: Registry, ledger: JSONValue, audit: (Int64, String), device: String, now: Int64) -> JSONValue {
        .object([
            ("audit_head", .object([("hash", .string(audit.1)), ("seq", .int(audit.0))])), ("checkpoint", .string(context)),
            ("created_at", .int(now)), ("device", .string(device)), ("expected_dm_trust_fp", .string(registry.expectedFingerprint)),
            ("ledger", ledger), ("previous_checkpoint_sha256", .string(registry.lastCheckpoint)),
            ("registry", (try? Canonical.decode(registry.encode())) ?? .null),
            ("registry_revision", .string(sha256Hex(registry.encode()))), ("sequence", .int(registry.checkpointSequence + 1)),
            ("signer", .object([("binary_sha256", .string(registry.signerBinary)), ("commit", .string(registry.signerCommit))])),
        ])
    }

    public static func hash(_ body: JSONValue) -> String { sha256Hex(Canonical.encode(body)) }

    public static func sign(_ body: JSONValue, key: SigningKey) throws -> [UInt8] {
        let sig = try key.sign(Canonical.encode(body))
        return Canonical.encode(.object([("body", body), ("key_id", .string(KeyIdentity.keyId(publicX963: key.publicX963))),
                                         ("signature_der_b64", .string(Data(sig).base64EncodedString()))]))
    }

    static func open(_ bytes: [UInt8]) throws -> (body: JSONValue, signer: RegistryKey, registry: Registry) {
        guard bytes.count <= 4 << 20, let v = try? Canonical.decode(bytes), v.keys == ["body", "key_id", "signature_der_b64"],
              let body = v["body"], body["checkpoint"]?.string == context, let kid = v["key_id"]?.string,
              let reg = body["registry"], let r = try? Registry.decode(Canonical.encode(reg)),
              let sigB64 = v["signature_der_b64"]?.string, let sig = Data(base64Encoded: sigB64)
        else { throw Refusal(code: "checkpoint_malformed") }
        guard let k = r.keys[kid], k.role == "operator", k.status == "active" else { throw Refusal(code: "checkpoint_signer_refused") }
        guard verifyDER(Array(sig), Canonical.encode(body), x963: k.publicX963) else { throw Refusal(code: "bad_signature") }
        return (body, k, r)
    }

    /// D-46 items 4-7. `paperFingerprint`, `paperSequence` and `paperHash` are typed by the operator from the
    /// paper sheet. `older` are other checkpoint files on the drive. Returns the restored registry and ledger.
    public static func restore(_ bytes: [UInt8], paperFingerprint: String, paperSequence: Int64, paperHash: String,
                               older: [[UInt8]], current: Registry) throws -> (Registry, JSONValue) {
        guard current.keys.isEmpty, current.checkpointSequence == 0 else { throw Refusal(code: "registry_not_empty") }
        let (body, signer, reg) = try open(bytes)
        guard hash(body) == paperHash, body["sequence"]?.int == paperSequence else { throw Refusal(code: "anchor_mismatch") }
        guard signer.fingerprint == paperFingerprint else { throw Refusal(code: "fingerprint_mismatch") }
        guard reg.expectedFingerprint == body["expected_dm_trust_fp"]?.string,
              sha256Hex(reg.encode()) == body["registry_revision"]?.string else { throw Refusal(code: "checkpoint_inconsistent") }
        // The chain must reach every older checkpoint present on the drive.
        var byHash: [String: JSONValue] = [:]
        for o in older { if let (b, _, _) = try? open(o) { byHash[hash(b)] = b } else { throw Refusal(code: "chain_broken") } }
        var prev = body["previous_checkpoint_sha256"]?.string ?? "", seen = 0, seq = paperSequence
        while prev != "genesis", let b = byHash[prev] {  // older checkpoints may be absent from the drive
            guard b["sequence"]?.int == seq - 1 else { throw Refusal(code: "chain_broken") }
            (prev, seq, seen) = (b["previous_checkpoint_sha256"]?.string ?? "", seq - 1, seen + 1)
        }
        guard seen == byHash.count, prev != "genesis" || seq == 1 else { throw Refusal(code: "chain_broken") }
        var out = reg
        for (id, k) in out.keys where k.custody == "this-device" { out.keys[id]?.custody = "lost" }  // design §3.3 step 4
        (out.checkpointSequence, out.lastCheckpoint) = (paperSequence, paperHash)
        return (out, body["ledger"] ?? .null)
    }
}

/// R3.7 `signer.release` records and R3.4 installation. Built and signed entirely on the SD.
public enum Release {
    public static let action = "signer.release"
    static let zeroCommit = String(repeating: "0", count: 40)

    /// Deterministic hash of the reviewed signer tree: regular files only (a symlink is refused), build
    /// products excluded, `path NUL sha256 LF` lines in byte order.
    public static func treeSHA256(_ dir: URL) throws -> String {
        let skip: Set<String> = [".build", ".swiftpm", ".git"]
        var lines: [(String, String)] = []
        func walk(_ d: URL, _ rel: String) throws {
            for n in try FileManager.default.contentsOfDirectory(atPath: d.path).sorted() where !skip.contains(n) {
                let u = d.appendingPathComponent(n), r = rel.isEmpty ? n : "\(rel)/\(n)"
                var st = stat()
                guard lstat(u.path, &st) == 0 else { throw Refusal(code: "tree_unreadable") }
                switch st.st_mode & S_IFMT {
                case S_IFDIR: try walk(u, r)
                case S_IFREG: lines.append((r, sha256Hex(Array(try Data(contentsOf: u)))))
                default: throw Refusal(code: "tree_special_file")
                }
            }
        }
        try walk(dir, "")
        let text = lines.sorted { Array($0.0.utf8).lexicographicallyPrecedes(Array($1.0.utf8)) }.map { "\($0.0)\u{0}\($0.1)\n" }.joined()
        return sha256Hex(Array(text.utf8))
    }

    public static func payload(commit: String, tree: String, binary: String, toolchain: String, device: String,
                               registry: Registry, keyId: String, now: Int64, nonce: String) -> JSONValue {
        .object([
            ("action", .string(action)), ("context", .string("sentinel/v1/approval/\(action)")), ("expires_at", .int(now + 3600)),
            ("issued_at", .int(now)), ("key_id", .string(keyId)), ("nonce", .string(nonce)),
            ("rationale", .string("signer release \(commit)")), ("revision", .string("signer:\(registry.signerCommit)")),
            ("scope", .object([("device", .string(device))])),
            ("subject", .object([("binary_sha256", .string(binary)), ("commit", .string(commit)),
                                 ("previous_commit", .string(registry.signerCommit)), ("toolchain", .string(toolchain)),
                                 ("tree_sha256", .string(tree)), ("type", .string("signer_release"))])),
        ])
    }

    public static func record(_ p: JSONValue, key: SigningKey) throws -> [UInt8] {
        Canonical.encode(.object([("payload", p), ("signature_der_b64", .string(Data(try key.sign(Canonical.encode(p))).base64EncodedString()))]))
    }

    /// Refuses unless an active operator-role key in the SD registry signed exactly this binary, as the
    /// successor of the installed commit, within its lifetime, with an unused nonce. Returns (commit, payload hash).
    public static func verify(_ bytes: [UInt8], registry: Registry, binarySHA256: String, ledger: Ledger, now: Int64) throws -> (String, String, ValidatedRequest) {
        guard bytes.count <= 8192, let v = try? Canonical.decode(bytes), v.keys == ["payload", "signature_der_b64"],
              let p = v["payload"], Set(p.keys) == Policy.payloadKeys, p["action"]?.string == action,
              p["context"]?.string == "sentinel/v1/approval/\(action)", let s = p["subject"],
              Set(s.keys) == ["binary_sha256", "commit", "previous_commit", "toolchain", "tree_sha256", "type"],
              s["type"]?.string == "signer_release", hexN(s["commit"]?.string, 40), hexN(s["previous_commit"]?.string, 40),
              hexN(s["tree_sha256"]?.string, 64), hexN(s["binary_sha256"]?.string, 64), let commit = s["commit"]?.string,
              let issued = p["issued_at"]?.int, let expires = p["expires_at"]?.int, let nonce = p["nonce"]?.string, hex32(nonce),
              let kid = p["key_id"]?.string, let sigB64 = v["signature_der_b64"]?.string, let sig = Data(base64Encoded: sigB64)
        else { throw Refusal(code: "release_malformed") }
        guard let k = registry.keys[kid], k.role == "operator", k.status == "active", !k.suspect else { throw Refusal(code: "release_key_refused") }
        let pb = Canonical.encode(p)
        guard verifyDER(Array(sig), pb, x963: k.publicX963) else { throw Refusal(code: "bad_signature") }
        guard p["revision"]?.string == "signer:\(registry.signerCommit)", s["previous_commit"]?.string == registry.signerCommit
        else { throw Refusal(code: "release_not_successor") }
        guard issued <= now + Policy.clockSkew, expires > now, expires - issued <= 3600 else { throw Refusal(code: "release_expired") }
        guard s["binary_sha256"]?.string == binarySHA256 else { throw Refusal(code: "binary_mismatch") }
        let h = sha256Hex(pb)
        let vr = ValidatedRequest(requestId: String(h.prefix(32)), payload: p, payloadBytes: pb, payloadSHA256: h, action: action,
                                  keyId: kid, oneTime: true, nonce: nonce, expiresAt: expires, signerRole: "operator", keyOpTarget: nil)
        try ledger.check(requestId: vr.requestId, nonce: nonce, payloadSHA256: h, oneTime: true)
        return (commit, h, vr)
    }
}
