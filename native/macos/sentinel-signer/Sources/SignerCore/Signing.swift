import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// A P-256 signing key held by this device. Production uses `SecureEnclaveKey`; tests use a disposable
/// software key (only in the test target and the TEST-ONLY interop tool, never in the signer product).
public protocol SigningKey {
    var publicX963: [UInt8] { get }
    func sign(_ message: [UInt8]) throws -> [UInt8]  // DER-encoded ECDSA P-256/SHA-256
}

public enum KeyIdentity {
    /// Identical to the engine's `key_id_for("ecdsa-p256-sha256", raw)`.
    public static func keyId(publicX963: [UInt8]) -> String {
        "p256:" + String(sha256Hex(Array("ecdsa-p256-sha256".utf8) + [0] + publicX963).prefix(32))
    }

    /// The engine's key-file format (`sentinel key enrol|rotate --key`, operator-public-key schema):
    /// exactly {key_id, algorithm, public_hex}, plus the D-47 credential fields for a recovery key.
    public static func publicExport(_ k: RegistryKey) -> [UInt8] {
        var f: [(String, JSONValue)] = [("algorithm", .string(Algo.p256)), ("key_id", .string(k.keyId)), ("public_hex", .string(hex(k.publicX963)))]
        if let r = k.recovery {
            f += [("cose_alg", .int(Algo.coseES256)), ("credential_id_b64", .string(Data(r.credentialId).base64EncodedString())),
                  ("role", .string("recovery")), ("rp_id", .string(Algo.rpId))]
        }
        return Canonical.encode(.object(f))
    }
}

/// Build the sign response (protocol §3.2) for a validated request.
public func signResponse(_ r: ValidatedRequest, key: SigningKey) throws -> [UInt8] {
    guard KeyIdentity.keyId(publicX963: key.publicX963) == r.keyId else { throw Refusal(code: "key_mismatch") }
    let sig = try key.sign(r.payloadBytes)
    return Canonical.encode(.object([
        ("envelope", .string("sentinel/v1/sign-response")),
        ("key_id", .string(r.keyId)),
        ("payload_sha256", .string(r.payloadSHA256)),
        ("request_id", .string(r.requestId)),
        ("signature_der_b64", .string(Data(sig).base64EncodedString())),
    ]))
}

/// Secure Enclave P-256 key with `.biometryCurrentSet` (Touch ID only; a fingerprint-set change
/// invalidates it, SD-T02/SD-T03). Its data representation is an opaque, device-bound handle.
public struct SecureEnclaveKey: SigningKey {
    let key: SecureEnclave.P256.Signing.PrivateKey

    public static func create() throws -> (SecureEnclaveKey, Data) {
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &err)
        else { throw Refusal(code: "access_control_failed") }
        let k = try SecureEnclave.P256.Signing.PrivateKey(accessControl: ac)
        return (SecureEnclaveKey(key: k), k.dataRepresentation)
    }

    /// Load the key with a context that has already passed Touch ID for exactly this approval.
    public static func load(_ handle: Data, context: LAContext) throws -> SecureEnclaveKey {
        SecureEnclaveKey(key: try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: handle, authenticationContext: context))
    }

    public var publicX963: [UInt8] { Array(key.publicKey.x963Representation) }

    public func sign(_ message: [UInt8]) throws -> [UInt8] {
        Array(try key.signature(for: Data(message)).derRepresentation)
    }
}

/// Display text for a validated request (design §4). Built from fixed templates and validated values
/// only; no request-supplied label or instruction is ever shown, because none exists in the protocol.
public func renderForApproval(_ r: ValidatedRequest, deviceName: String, target: RegistryKey? = nil) -> [String] {
    var lines = [
        "Sentinel signing device: \(deviceName)",
        r.signerRole == "recovery" && r.action == "key.rotate" ? "Recovery: ENROL REPLACEMENT OPERATOR KEY"
            : "ACTION: \(r.action)\(r.oneTime ? "  (one-time)" : "")",
        "KEY: \(r.keyId)",
        "REQUEST: \(r.requestId)",
        "PAYLOAD SHA-256: \(r.payloadSHA256)",
    ]
    if let t = target {
        let fp = Array(t.fingerprint), groups = stride(from: 0, to: 64, by: 4).map { String(fp[$0..<$0 + 4]) }
        lines += ["", r.action == "key.rotate" ? "ADD KEY as \(t.role), permissions: \(t.permittedActions.joined(separator: ", "))"
                                               : "REVOKE KEY \(t.keyId) (\(t.role))",
                  "KEY FINGERPRINT (compare with your paper record or the key-creation step on this screen):"]
        lines += stride(from: 0, to: 16, by: 4).map { groups[$0..<$0 + 4].joined(separator: " ") }
    }
    if r.action == "release.publish", let sub = r.payload["subject"], case let .array(arts)? = r.payload["scope"]?["artifacts"] {
        // D-74: validation already recomputed the SHA256SUMS digest from exactly these entries.
        lines += ["", "PUBLISH RELEASE \(sub["name"]?.string ?? "?") \(sub["version"]?.string ?? "?")",
                  "COMMIT \(sub["commit"]?.string ?? "?")",
                  "SHA256SUMS \(r.payload["revision"]?.string ?? "?")",
                  "Compare EVERY hash below with the independent reproducible build (remote CI),",
                  "never with figures shown by the development Mac:"]
        for a in arts {
            let h = Array(a["sha256"]?.string ?? "")
            lines.append("  \(a["name"]?.string ?? "?")")
            lines.append("    " + stride(from: 0, to: h.count, by: 8).map { String(h[$0..<min($0 + 8, h.count)]) }.joined(separator: " "))
        }
    }
    lines += ["", "Every field that will be signed:"]
    func flat(_ prefix: String, _ v: JSONValue) {
        switch v {
        case let .object(kv):
            if kv.isEmpty { lines.append("\(prefix) = {}") }
            for (k, x) in kv.sorted(by: { $0.0 < $1.0 }) { flat(prefix.isEmpty ? k : "\(prefix).\(k)", x) }
        case let .array(a):
            if a.isEmpty { lines.append("\(prefix) = []") }
            for (i, x) in a.enumerated() { flat("\(prefix)[\(i)]", x) }
        case let .string(s): lines.append("\(prefix) = \"\(s)\"")
        case let .int(i): lines.append("\(prefix) = \(i)")
        case let .bool(b): lines.append("\(prefix) = \(b)")
        case .null: lines.append("\(prefix) = null")
        }
    }
    flat("", r.payload)
    lines.append("")
    lines.append("END OF PAYLOAD. Approve only if every line above is what you intend.")
    return lines
}
