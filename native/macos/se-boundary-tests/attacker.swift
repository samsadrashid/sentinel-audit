// SE-H1 TEST ONLY. An independently built program (not the Sentinel helper, different code identity)
// that tries to use a copied Secure Enclave key handle. It signs bytes of ITS OWN choosing and shows
// ITS OWN dialog text. Usage: attacker <handle-b64-file> <mode: custom|default>
// Prints one JSON object. Never touches Sentinel state; the key must be a disposable test key.
import CryptoKit
import Foundation
import LocalAuthentication

func out(_ o: [String: Any]) -> Never {
    let d = try! JSONSerialization.data(withJSONObject: o, options: [.sortedKeys])
    FileHandle.standardOutput.write(d); FileHandle.standardOutput.write("\n".data(using: .utf8)!)
    exit(0)
}

let a = CommandLine.arguments
guard a.count == 3, let text = try? String(contentsOfFile: a[1], encoding: .utf8),
      let handle = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines))
else { out(["stage": "args", "error": "usage: attacker <handle-file> custom|default"]) }
let mode = a[2]
let message = "SE-H1 ATTACKER-CHOSEN PAYLOAD \(UUID().uuidString)".data(using: .utf8)!

let ctx = LAContext()
ctx.touchIDAuthenticationAllowableReuseDuration = 0
let key: SecureEnclave.P256.Signing.PrivateKey
do {
    key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: handle, authenticationContext: ctx)
} catch {
    out(["stage": "load_handle", "error": "\(error)", "loaded": false])
}
var auth: [String: Any] = ["mode": mode]
if mode == "custom" {
    // Attacker-chosen dialog text, impersonating a benign Sentinel approval.
    let reason = "approve a Sentinel operator action: suppress 1 low-severity test finding (ATTACKER TEXT, SE-H1)"
    let sem = DispatchSemaphore(value: 0)
    var ok = false; var err: Error?
    ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { o, e in ok = o; err = e; sem.signal() }
    _ = sem.wait(timeout: .now() + 120)
    auth["evaluate_ok"] = ok
    auth["evaluate_error"] = err.map { "\($0)" } ?? NSNull()
    if !ok { out(["stage": "authenticate", "loaded": true, "auth": auth, "signed": false]) }
}
do {
    let sig = try key.signature(for: message)
    out([
        "stage": "signed", "loaded": true, "auth": auth, "signed": true,
        "message_b64": message.base64EncodedString(),
        "signature_der_b64": sig.derRepresentation.base64EncodedString(),
        "public_x963_hex": key.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined(),
    ])
} catch {
    out(["stage": "sign", "loaded": true, "auth": auth, "signed": false, "error": "\(error)"])
}
