// sentinel-se-helper: minimal Secure Enclave P-256 operator-signing helper (D-38).
// Protocol: docs/m1/se-helper-contract.md. One command per process; exactly one JSON object on stdout.
//
// Security properties (see contract §2):
// - Keys are created inside the Secure Enclave with [.privateKeyUsage, .userPresence]. There is no
//   software key path anywhere in this file.
// - Every `sign` evaluates a fresh LAContext (reuse duration 0) before the key is used; nothing is
//   cached across invocations.
// - The helper hashes the stdin bytes itself and shows the FULL SHA-256 in the system prompt. It never
//   parses or reconstructs the payload and ignores any caller-supplied reason or digest.
// - Nothing except the single JSON result is written to stdout or stderr. Payload bytes are never logged.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

let maxMessageBytes = 65536
let maxHandleFileBytes = 8192  // base64 of at most 4096 handle bytes is 5464 chars
let maxHandleBytes = 4096
let algorithm = "ecdsa-p256-sha256"

// MARK: output

func emit(_ obj: [String: Any], exitCode: Int32) -> Never {
    let data = (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])) ?? Data()
    FileHandle.standardOutput.write(data)
    exit(exitCode)
}

let errorText: [String: String] = [
    "cancelled": "user presence prompt was cancelled",
    "timeout": "user presence prompt timed out",
    "auth_failed": "user presence authentication failed",
    "no_secure_enclave": "Secure Enclave unavailable",
    "key_unusable": "key handle unusable on this device",
    "not_interactive": "no interactive graphical session",
    "invalid_request": "invalid request",
]

func fail(_ code: String) -> Never {
    emit(["error": code, "message": errorText[code] ?? "error"], exitCode: code == "invalid_request" ? 2 : 1)
}

func hex(_ bytes: some Sequence<UInt8>) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func sentinelKeyId(_ x963: Data) -> String {
    var input = Data(algorithm.utf8)
    input.append(0)
    input.append(x963)
    return "p256:" + String(hex(SHA256.hash(data: input)).prefix(32))
}

// MARK: environment checks

func requireSecureEnclave() {
    if !SecureEnclave.isAvailable { fail("no_secure_enclave") }
}

func requireGraphicSession() {
    var sid = SecuritySessionId()
    var attrs = SessionAttributeBits()
    let status = SessionGetInfo(SecuritySessionId(bitPattern: -1), &sid, &attrs)  // callerSecuritySession
    if status != errSecSuccess || !attrs.contains(.sessionHasGraphicAccess) { fail("not_interactive") }
}

// MARK: strict input

func readStdin(limit: Int) -> Data {
    var buf = Data()
    let h = FileHandle.standardInput
    while true {
        let chunk = h.readData(ofLength: 16384)
        if chunk.isEmpty { break }
        buf.append(chunk)
        if buf.count > limit { fail("invalid_request") }
    }
    return buf
}

func readHandle(path: String) -> Data {
    guard path.hasPrefix("/"), let fh = FileHandle(forReadingAtPath: path) else { fail("invalid_request") }
    let raw = fh.readData(ofLength: maxHandleFileBytes + 1)
    try? fh.close()
    guard raw.count > 0, raw.count <= maxHandleFileBytes,
          let text = String(data: raw, encoding: .ascii),
          let handle = Data(base64Encoded: text),
          handle.base64EncodedString() == text,  // canonical base64 only, no whitespace
          handle.count > 0, handle.count <= maxHandleBytes
    else { fail("invalid_request") }
    return handle
}

func parseTimeout(_ s: String) -> Int {
    guard !s.isEmpty, s.count <= 3, s.allSatisfy({ $0 >= "0" && $0 <= "9" }), !s.hasPrefix("0"),
          let t = Int(s), t >= 1, t <= 300
    else { fail("invalid_request") }
    return t
}

// MARK: commands

func cmdStatus() -> Never {
    emit(["secure_enclave": SecureEnclave.isAvailable], exitCode: 0)
}

func cmdCreate() -> Never {
    requireSecureEnclave()
    var cfErr: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &cfErr)
    else { fail("no_secure_enclave") }
    guard let key = try? SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: ac)
    else { fail("no_secure_enclave") }
    let pub = key.publicKey.x963Representation
    guard pub.count == 65, pub.first == 0x04 else { fail("no_secure_enclave") }
    emit(["public_x963_hex": hex(pub), "handle_b64": key.dataRepresentation.base64EncodedString()], exitCode: 0)
}

final class AuthResult: @unchecked Sendable {
    var ok = false
    var error: Error?
}

func mapLAError(_ error: Error?) -> String {
    guard let la = error as? LAError else { return "auth_failed" }
    switch la.code {
    case .userCancel, .appCancel, .systemCancel, .userFallback: return "cancelled"
    case .notInteractive: return "not_interactive"
    default: return "auth_failed"
    }
}

func cmdSign(handlePath: String, timeoutArg: String) -> Never {
    // 1. Validate everything before any prompt.
    let timeout = parseTimeout(timeoutArg)
    let handle = readHandle(path: handlePath)
    let message = readStdin(limit: maxMessageBytes)
    if message.isEmpty { fail("invalid_request") }
    requireSecureEnclave()
    requireGraphicSession()

    // 2. Fresh context per invocation; no reuse of a previous unlock.
    let ctx = LAContext()
    ctx.touchIDAuthenticationAllowableReuseDuration = 0
    ctx.interactionNotAllowed = false

    guard let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: handle, authenticationContext: ctx)
    else { fail("key_unusable") }
    let pub = key.publicKey.x963Representation
    let keyId = sentinelKeyId(pub)

    // 3. The helper's own digest of the exact bytes it will sign; shown in full in the system prompt.
    let digest = hex(SHA256.hash(data: message))
    let reason = "approve a Sentinel operator action. Check this matches the payload SHA-256 shown in your terminal: \(digest)"

    let result = AuthResult()
    let done = DispatchSemaphore(value: 0)
    ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, err in
        result.ok = ok
        result.error = err
        done.signal()
    }
    if done.wait(timeout: .now() + .seconds(timeout)) == .timedOut {
        ctx.invalidate()
        fail("timeout")
    }
    if !result.ok { ctx.invalidate(); fail(mapLAError(result.error)) }

    // 4. Sign exactly the stdin bytes (CryptoKit hashes with SHA-256), then self-verify.
    guard let sig = try? key.signature(for: message) else { ctx.invalidate(); fail("key_unusable") }
    ctx.invalidate()
    guard key.publicKey.isValidSignature(sig, for: message) else { fail("key_unusable") }
    let der = sig.derRepresentation
    emit(["signature_der_b64": der.base64EncodedString(), "message_sha256": digest, "key_id": keyId], exitCode: 0)
}

// MARK: dispatch (exact argument shapes only)

let args = Array(CommandLine.arguments.dropFirst())
switch (args.first, args.count) {
case ("status", 1): cmdStatus()
case ("create", 1): cmdCreate()
case ("sign", 3): cmdSign(handlePath: args[1], timeoutArg: args[2])
default: fail("invalid_request")
}
