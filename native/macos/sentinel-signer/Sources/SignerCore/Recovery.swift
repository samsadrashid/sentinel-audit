import CryptoKit
import Foundation

/// D-47 recovery assertions (protocol R3.4, final review §1.3 and §2). A recovery key signs only a WebAuthn
/// assertion whose challenge binds the exact payload. It is never treated as a plain ECDSA signature.
public struct Assertion: Equatable {
    public let authenticatorData: [UInt8], clientDataJSON: [UInt8], credentialId: [UInt8], signature: [UInt8]
    public init(authenticatorData: [UInt8], clientDataJSON: [UInt8], credentialId: [UInt8], signature: [UInt8]) {
        (self.authenticatorData, self.clientDataJSON, self.credentialId, self.signature) = (authenticatorData, clientDataJSON, credentialId, signature)
    }
}

/// The recovery authenticator (a FIDO2 security key). Production: AuthenticationServices on the SD
/// (SD-T35, unverified until that hardware test). Tests: a disposable software authenticator.
public protocol RecoveryAuthenticator {
    func assert(challenge: [UInt8], credentialId: [UInt8]) throws -> Assertion
}

public enum Recovery {
    static let prefix = Array("sentinel/v1/recovery-assertion".utf8) + [0]

    public static func challenge(_ payload: JSONValue) -> [UInt8] {
        Array(SHA256.hash(data: Data(prefix + Canonical.encode(payload))))
    }

    public static func b64url(_ b: [UInt8]) -> String {
        Data(b).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// The WebAuthn client-data serialisation (type, challenge, origin, crossOrigin), as a conforming
    /// client emits it. The SD self-check accepts only these exact bytes, with or without crossOrigin.
    public static func clientData(_ challenge: [UInt8], crossOrigin: Bool = true) -> [UInt8] {
        let base = #"{"type":"webauthn.get","challenge":"\#(b64url(challenge))","origin":"https://\#(Algo.rpId)""#
        return Array((base + (crossOrigin ? #","crossOrigin":false}"# : "}")).utf8)
    }

    /// The final review §2 counter policy. Returns the new counter state, or throws (and says whether the
    /// key must be marked suspect).
    public static func nextCounter(_ c: RecoveryCredential, _ n: Int64) throws -> RecoveryCredential {
        var out = c
        switch c.counterMode {
        case "unset": (out.counterMode, out.lastCount) = n == 0 ? ("zero", 0) : ("increasing", n)
        case "zero": if n != 0 { throw Refusal(code: "counter_mode_changed") }
        case "increasing":
            if n == c.lastCount { throw Refusal(code: "counter_not_increasing") }
            if n < c.lastCount { throw Refusal(code: "counter_rollback") }
            out.lastCount = n
        default: throw Refusal(code: "counter_mode_invalid")
        }
        return out
    }
    public static let suspectCodes: Set<String> = ["counter_rollback", "counter_mode_changed"]

    /// Every final-review §1.3 check, then the signature and the counter. Returns the new counter state.
    public static func verify(_ a: Assertion, payload: JSONValue, key: RegistryKey) throws -> RecoveryCredential {
        guard key.role == "recovery", let cred = key.recovery else { throw Refusal(code: "wrong_key_role") }
        let ch = challenge(payload)
        guard a.clientDataJSON == clientData(ch) || a.clientDataJSON == clientData(ch, crossOrigin: false) else {
            throw Refusal(code: "bad_client_data")
        }
        let ad = a.authenticatorData
        guard ad.count == 37 else { throw Refusal(code: "bad_authenticator_data") }
        guard Array(ad[0..<32]) == Array(SHA256.hash(data: Data(Algo.rpId.utf8))) else { throw Refusal(code: "bad_rp_id") }
        guard ad[32] & 0x01 != 0, ad[32] & 0x04 != 0 else { throw Refusal(code: "presence_missing") }
        guard ad[32] & 0xC0 == 0 else { throw Refusal(code: "bad_flags") }
        guard a.credentialId == cred.credentialId else { throw Refusal(code: "wrong_credential") }
        guard let pub = try? P256.Signing.PublicKey(x963Representation: key.publicX963),
              let sig = try? P256.Signing.ECDSASignature(derRepresentation: a.signature),
              pub.isValidSignature(sig, for: Data(ad + Array(SHA256.hash(data: Data(a.clientDataJSON))))) else {
            throw Refusal(code: "bad_signature")
        }
        let n = ad[33...36].reduce(Int64(0)) { $0 << 8 | Int64($1) }
        return try nextCounter(cred, n)
    }

    /// Protocol R3.4: the response carries a `webauthn` object instead of `signature_der_b64`.
    public static func response(_ r: ValidatedRequest, _ a: Assertion) -> [UInt8] {
        Canonical.encode(.object([
            ("envelope", .string("sentinel/v1/sign-response")), ("key_id", .string(r.keyId)),
            ("payload_sha256", .string(r.payloadSHA256)), ("request_id", .string(r.requestId)),
            ("webauthn", .object([
                ("authenticator_data_b64", .string(Data(a.authenticatorData).base64EncodedString())),
                ("client_data_json_b64", .string(Data(a.clientDataJSON).base64EncodedString())),
                ("credential_id_b64", .string(Data(a.credentialId).base64EncodedString())),
                ("signature_der_b64", .string(Data(a.signature).base64EncodedString())),
            ])),
        ]))
    }

    /// The COSE EC2 P-256 public key and credential ID from a WebAuthn registration's attestation object
    /// (a CBOR map with "authData"). Only ES256 (alg -7, crv 1) is accepted.
    public static func parseAttestation(_ att: [UInt8]) throws -> (credentialId: [UInt8], x963: [UInt8]) {
        var r = CBOR(b: att)
        guard case let .map(m) = try r.item(), case let .bytes(ad)? = m.first(where: { $0.0 == .text("authData") })?.1,
              ad.count > 55, ad[32] & 0x40 != 0, Array(ad[0..<32]) == Array(SHA256.hash(data: Data(Algo.rpId.utf8)))
        else { throw Refusal(code: "bad_attestation") }
        let n = Int(ad[53]) << 8 | Int(ad[54])
        guard ad.count >= 55 + n, n > 0, n <= 1023 else { throw Refusal(code: "bad_attestation") }
        var k = CBOR(b: Array(ad[(55 + n)...]))
        guard case let .map(cose) = try k.item() else { throw Refusal(code: "bad_attestation") }
        func get(_ key: Int64) -> CBOR.Item? { cose.first { $0.0 == .int(key) }?.1 }
        guard get(1) == .int(2), get(3) == .int(-7), get(-1) == .int(1), case let .bytes(x)? = get(-2), case let .bytes(y)? = get(-3),
              x.count == 32, y.count == 32, (try? P256.Signing.PublicKey(x963Representation: [4] + x + y)) != nil
        else { throw Refusal(code: "attestation_not_es256") }
        return (Array(ad[55..<(55 + n)]), [4] + x + y)
    }
}

/// A minimal CBOR reader for attestation objects: maps, arrays, byte and text strings, integers, simple
/// values. Indefinite lengths, tags and floats are refused.
struct CBOR {
    indirect enum Item: Equatable { case int(Int64), bytes([UInt8]), text(String), array([Item]), map([(Item, Item)]), simple(UInt8)
        static func == (a: Item, b: Item) -> Bool {
            switch (a, b) {
            case let (.int(x), .int(y)): return x == y
            case let (.bytes(x), .bytes(y)): return x == y
            case let (.text(x), .text(y)): return x == y
            case let (.array(x), .array(y)): return x == y
            case let (.map(x), .map(y)): return x.count == y.count && zip(x, y).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
            case let (.simple(x), .simple(y)): return x == y
            default: return false
            }
        }
    }
    let b: [UInt8]
    var i = 0, depth = 0

    mutating func byte() throws -> UInt8 { guard i < b.count else { throw Refusal(code: "bad_cbor") }; i += 1; return b[i - 1] }
    mutating func arg(_ info: UInt8) throws -> UInt64 {
        switch info {
        case 0..<24: return UInt64(info)
        case 24...27: return try (0..<(1 << (info - 24))).reduce(UInt64(0)) { acc, _ in acc << 8 | UInt64(try byte()) }
        default: throw Refusal(code: "bad_cbor")
        }
    }
    mutating func item() throws -> Item {
        depth += 1
        defer { depth -= 1 }
        guard depth < 16 else { throw Refusal(code: "bad_cbor") }
        let h = try byte(), major = h >> 5, n = try arg(h & 0x1f)
        let small = { (n: UInt64) throws -> Int in guard n <= 65_536 else { throw Refusal(code: "bad_cbor") }; return Int(n) }
        switch major {
        case 0: guard n <= UInt64(Int64.max) else { throw Refusal(code: "bad_cbor") }; return .int(Int64(n))
        case 1: guard n < UInt64(Int64.max) else { throw Refusal(code: "bad_cbor") }; return .int(-1 - Int64(n))
        case 2, 3:
            let len = try small(n)
            guard i + len <= b.count else { throw Refusal(code: "bad_cbor") }
            let s = Array(b[i..<(i + len)]); i += len
            if major == 2 { return .bytes(s) }
            guard let t = String(bytes: s, encoding: .utf8) else { throw Refusal(code: "bad_cbor") }
            return .text(t)
        case 4: return .array(try (0..<small(n)).map { _ in try item() })
        case 5: return .map(try (0..<small(n)).map { _ in (try item(), try item()) })
        case 7: guard n < 24 else { throw Refusal(code: "bad_cbor") }; return .simple(UInt8(n))
        default: throw Refusal(code: "bad_cbor")
        }
    }
}
