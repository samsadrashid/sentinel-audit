// sentinel-signer: the signing-device application (protocol v1; D-45..D-47, D-73).
//
// Runs ONLY on the dedicated signing Mac, in the standard `signer` account, which runs no development
// agents (design §0). Production signing stays disabled in Sentinel until this binary has been reviewed
// and built on that device, SD-T01..SD-T55 pass there, and the first-enrolment ceremony is recorded.
//
//   clock-check                                       confirm the clock against an independent source (SD-T55)
//   create-key --operator NAME --expires-at T         new Secure Enclave operator key (a candidate until committed)
//   register-recovery --operator NAME --expires-at T  new FIDO2 recovery credential (AuthenticationServices; SD-T35)
//   export-pub --key-id ID --volume V                 write pub-<id>.json for the DM (volume read-write)
//   intake --volume V                                 copy requests and any trust-store audit to the spool (READ-ONLY)
//   review                                            display, approve with Touch ID, sign (volume ejected)
//   deliver --volume V [--reissue REQUEST_ID]         write responses (volume read-write)
//   pending show|commit|abandon|resolve               the registry state machine (R3.1)
//   audit                                             compare the spooled DM trust.json with the registry (§2.4)
//   ceremony start|end   recovery start|end           ceremony and recovery sessions (§6, R3.3)
//   checkpoint write --volume CKPT | restore --volume CKPT    signed registry checkpoints (D-46)
//   release tree-hash DIR | sign --commit C --tree DIR --binary B --toolchain S | install --record R --binary B
import AppKit
import AuthenticationServices
import Foundation
import IOKit
import LocalAuthentication
import SignerCore

let base = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/sentinel-signer")
let keysDir = base.appendingPathComponent("keys")
let now = { Int64(Date().timeIntervalSince1970) }

func die(_ msg: String, _ code: Int32 = 1) -> Never {
    FileHandle.standardError.write("sentinel-signer: \(msg)\n".data(using: .utf8)!)
    exit(code)
}

func arg(_ name: String) -> String {
    let a = CommandLine.arguments
    guard let i = a.firstIndex(of: name), i + 1 < a.count else { die("missing \(name)", 2) }
    return a[i + 1]
}

func opt(_ name: String) -> String? { CommandLine.arguments.contains(name) ? arg(name) : nil }

func ask(_ prompt: String) -> String { print(prompt, terminator: " "); return readLine() ?? "" }
func confirm(_ prompt: String, word: String = "COMMIT") -> Bool { ask("\(prompt)\nType \(word) to confirm:") == word }

func deviceSerial() -> String {
    let svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
    defer { IOObjectRelease(svc) }
    let v = IORegistryEntryCreateCFProperty(svc, "IOPlatformSerialNumber" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue()
    return (v as? String) ?? "unknown"
}

func expiry() -> Int64 {
    guard let t = Int64(arg("--expires-at")), t > now() else { die("--expires-at must be a future unix time", 2) }
    return t
}

func operatorKey(_ d: Device, _ id: String, _ ctx: LAContext) throws -> SecureEnclaveKey {
    guard let h = FileManager.default.contents(atPath: keysDir.appendingPathComponent("\(id).handle").path) else { die("no Secure Enclave key handle for \(id)") }
    return try SecureEnclaveKey.load(h, context: ctx)
}

/// An active operator-role key whose Secure Enclave handle is on this device.
func localOperator(_ d: Device) -> RegistryKey {
    guard let k = d.registry.activeOperators.first(where: { $0.custody == "this-device" && FileManager.default.fileExists(atPath: keysDir.appendingPathComponent("\($0.keyId).handle").path) })
    else { die("no active operator key on this device") }
    return k
}

// ── approval window (design §4: full display, Approve only after the end is visible) ─────
final class ApprovalWindow: NSObject, NSWindowDelegate {
    let text: String
    var approved = false
    var approve: NSButton!
    var scroll: NSScrollView!

    init(text: String) { self.text = text }

    func run() -> Bool {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 900, height: 640), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        w.title = "Sentinel signing device: approve exactly this?"
        w.delegate = self
        scroll = NSScrollView(frame: NSRect(x: 20, y: 70, width: 860, height: 550))
        scroll.hasVerticalScroller = true
        scroll.autoresizingMask = [.width, .height]
        let tv = NSTextView(frame: scroll.bounds)
        tv.isEditable = false
        tv.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        tv.string = text
        scroll.documentView = tv
        scroll.contentView.postsBoundsChangedNotifications = true
        NotificationCenter.default.addObserver(self, selector: #selector(scrolled), name: NSView.boundsDidChangeNotification, object: scroll.contentView)
        approve = NSButton(title: "Approve with Touch ID", target: self, action: #selector(doApprove))
        approve.frame = NSRect(x: 680, y: 20, width: 200, height: 32)
        approve.isEnabled = false
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(doCancel))
        cancel.frame = NSRect(x: 560, y: 20, width: 110, height: 32)
        cancel.keyEquivalent = "\u{1b}"
        for v in [scroll!, approve!, cancel] { w.contentView?.addSubview(v) }
        w.center()
        w.makeKeyAndOrderFront(nil)
        app.activate(ignoringOtherApps: true)
        DispatchQueue.main.async { self.scrolled() }
        app.runModal(for: w)
        w.orderOut(nil)
        return approved
    }

    @objc func scrolled() {
        guard let doc = scroll.documentView else { return }
        if scroll.contentView.bounds.maxY >= doc.frame.height - 2 { approve.isEnabled = true }  // the end has been shown
    }
    @objc func doApprove() { approved = true; NSApplication.shared.stopModal() }
    @objc func doCancel() { approved = false; NSApplication.shared.stopModal() }
    func windowShouldClose(_ sender: NSWindow) -> Bool { doCancel(); return true }
}

/// Touch ID only: no passcode fallback; OD-6 60 s timeout.
func touchID(reason: String) -> LAContext? {
    let ctx = LAContext()
    ctx.localizedFallbackTitle = ""
    let sem = DispatchSemaphore(value: 0)
    var ok = false
    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { s, _ in ok = s; sem.signal() }
    if sem.wait(timeout: .now() + 60) == .timedOut { ctx.invalidate(); return nil }
    return ok ? ctx : nil
}

func approve(_ lines: [String], reason: String) -> LAContext? {
    guard ApprovalWindow(text: lines.joined(separator: "\n")).run() else { return nil }
    return touchID(reason: reason)
}

// ── FIDO2 recovery authenticator: AuthenticationServices (F-3). UNVERIFIED until SD-T35 on the SD. ──
final class SecurityKey: NSObject, RecoveryAuthenticator, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 420, height: 120), styleMask: [.titled], backing: .buffered, defer: false)
    var result: Result<ASAuthorization, Error>?
    let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: Algo.rpId)

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { window }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization a: ASAuthorization) { result = .success(a) }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError e: Error) { result = .failure(e) }

    func perform(_ req: ASAuthorizationRequest) throws -> ASAuthorizationCredential {
        NSApplication.shared.setActivationPolicy(.regular)
        window.title = "Sentinel recovery key: insert it, enter its PIN and touch it"
        window.center()
        window.makeKeyAndOrderFront(nil)
        defer { window.orderOut(nil) }
        let c = ASAuthorizationController(authorizationRequests: [req])
        (c.delegate, c.presentationContextProvider, result) = (self, self, nil)
        c.performRequests()
        let deadline = Date().addingTimeInterval(60)
        while result == nil, Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
        guard case let .success(a)? = result else { throw Refusal(code: "authenticator_failed") }  // includes the timeout
        return a.credential
    }

    func assert(challenge: [UInt8], credentialId: [UInt8]) throws -> Assertion {
        let req = provider.createCredentialAssertionRequest(challenge: Data(challenge))
        req.allowedCredentials = [ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: Data(credentialId), transports: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported)]
        req.userVerificationPreference = .required
        guard let a = try perform(req) as? ASAuthorizationSecurityKeyPublicKeyCredentialAssertion else { throw Refusal(code: "authenticator_failed") }
        return Assertion(authenticatorData: Array(a.rawAuthenticatorData), clientDataJSON: Array(a.rawClientDataJSON),
                         credentialId: Array(a.credentialID), signature: Array(a.signature))
    }

    func register(name: String) throws -> (credentialId: [UInt8], x963: [UInt8]) {
        var ch = [UInt8](repeating: 0, count: 32), uid = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &ch) == 0, SecRandomCopyBytes(kSecRandomDefault, 16, &uid) == 0 else { throw Refusal(code: "rng_failed") }
        let req = provider.createCredentialRegistrationRequest(challenge: Data(ch), displayName: name, name: name, userID: Data(uid))
        req.credentialParameters = [ASAuthorizationPublicKeyCredentialParameters(algorithm: .ES256)]
        req.userVerificationPreference = .required
        guard let r = try perform(req) as? ASAuthorizationSecurityKeyPublicKeyCredentialRegistration, let att = r.rawAttestationObject else { throw Refusal(code: "authenticator_failed") }
        let parsed = try Recovery.parseAttestation(Array(att))
        guard parsed.credentialId == Array(r.credentialID) else { throw Refusal(code: "bad_attestation") }
        return parsed
    }
}

func readFile(_ volume: URL, _ dir: String, _ name: String, limit: Int) throws -> [UInt8] {
    let vfd = open(volume.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard vfd >= 0 else { throw Refusal(code: "volume_unreadable") }
    defer { close(vfd) }
    let d = try Transport.openDir(vfd, dir)
    defer { close(d) }
    switch Transport.readStrict(d, name, limit: limit) {
    case let .success(b): return b
    case let .failure(r): throw r
    }
}

func review(_ d: Device) throws {
    try d.log.append("ledger_pruned", [("removed", .int(Int64(try d.ledger.prune(now: now()))))], now: now())
    let files = try FileManager.default.contentsOfDirectory(atPath: d.spool.path).filter { $0.hasPrefix("req-") && $0.hasSuffix(".json") }.sorted()
    for f in files {  // one at a time; there is no batch approval (SD-T29)
        let rid = String(f.dropFirst(4).prefix(32)), url = d.spool.appendingPathComponent(f)
        let bytes = Array(try Data(contentsOf: url))
        defer { try? FileManager.default.removeItem(at: url) }
        let v: ValidatedRequest
        do { v = try d.validate(bytes, requestId: rid, now: now()) } catch let r as Refusal { print("REFUSED \(rid): \(r.code)"); continue }
        try d.log.append("displayed", [("request_id", .string(rid)), ("payload_sha256", .string(v.payloadSHA256))], now: now())
        let lines = renderForApproval(v, deviceName: Host.current().localizedName ?? "signing device", target: v.keyOpTarget.flatMap { d.registry.keys[$0] })
        if v.signerRole == "recovery" {
            guard ApprovalWindow(text: lines.joined(separator: "\n")).run() else {
                try d.ledger.recordSeen(requestId: rid, expiresAt: v.expiresAt)
                try d.log.append("cancelled", [("request_id", .string(rid)), ("biometry_ok", .bool(false))], now: now())
                continue
            }
            do { _ = try d.sign(v, key: nil, authenticator: SecurityKey(), now: now()); print("Signed (recovery) \(rid)") } catch let r as Refusal { print("REFUSED \(rid): \(r.code)") }
            continue
        }
        guard let ctx = approve(lines, reason: "Approve the Sentinel operator action shown in the Sentinel signer window") else {
            try d.ledger.recordSeen(requestId: rid, expiresAt: v.expiresAt)
            try d.log.append("cancelled", [("request_id", .string(rid)), ("biometry_ok", .bool(false))], now: now())
            print("Cancelled \(rid)")
            continue
        }
        try d.log.append("approved", [("request_id", .string(rid)), ("biometry_ok", .bool(true))], now: now())
        _ = try d.sign(v, key: try operatorKey(d, v.keyId, ctx), authenticator: nil, now: now())
        print("Signed \(rid)\(v.keyOpTarget != nil ? "  (registry change PENDING: deliver, confirm the DM applied it, then `pending commit`)" : "")")
    }
}

func checkpoint(_ d: Device, write: Bool, volume: URL) throws {
    let dirName = "sentinel-ckpt"
    if write {
        if let bad = Transport.volumeProblem(Transport.volumeInfo(volume), readOnly: false) { die("checkpoint drive refused: \(bad)") }
        let body = d.checkpointBody(device: deviceSerial(), now: now()), h = Checkpoint.hash(body), seq = body["sequence"]?.int ?? 0
        let k = localOperator(d)
        let summary = ["REGISTRY CHECKPOINT \(seq)", "SHA-256: \(h)", "STATE: \(d.registry.state)", "KEYS:"]
            + d.registry.enrolled.map { "  \($0.keyId) \($0.role) \($0.status)\($0.suspect ? " SUSPECT" : "") \($0.permittedActions.joined(separator: ","))" }
            + ["AUDIT HEAD: \(d.log.seq) \(d.log.head)", "", "Write the sequence and the full hash on the paper sheet before approving."]
        guard let ctx = approve(summary, reason: "Sign registry checkpoint \(seq)") else { try d.log.append("checkpoint_declined", [], now: now()); die("not signed") }
        let rec = try Checkpoint.sign(body, key: try operatorKey(d, k.keyId, ctx))
        let dir = volume.appendingPathComponent(dirName)
        var st = stat()
        if lstat(dir.path, &st) == 0, (st.st_mode & S_IFMT) != S_IFDIR { die("\(dirName) is not a directory") }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try AtomicFile.write(rec, to: dir.appendingPathComponent("ckpt-\(seq)-\(h.prefix(32)).json"), mode: 0o644, replace: false)
        let anchored = try d.recordCheckpoint(body, retypedHash: ask("Re-type the full 64-hex hash from the paper sheet:"), now: now())
        print(anchored ? "Checkpoint \(seq) written and anchored." : "Hash mismatch: checkpoint \(seq) is UNANCHORED and can't be used for restoration.")
        return
    }
    if let bad = Transport.volumeProblem(Transport.volumeInfo(volume), readOnly: true) { die("checkpoint drive refused: \(bad)") }
    let fp = ask("Paper key fingerprint (64 hex):"), seqText = ask("Paper checkpoint sequence:"), h = ask("Paper checkpoint hash (64 hex):")
    guard let seq = Int64(seqText) else { die("bad sequence", 2) }
    let names = try FileManager.default.contentsOfDirectory(atPath: volume.appendingPathComponent(dirName).path).filter { $0.range(of: #"^ckpt-[0-9]+-[0-9a-f]{32}\.json$"#, options: .regularExpression) != nil }
    var chosen: [UInt8]?, older: [[UInt8]] = []
    for n in names {
        let b = try readFile(volume, dirName, n, limit: 4 << 20)
        if n == "ckpt-\(seq)-\(h.prefix(32)).json" { chosen = b } else if let s = Int64(n.split(separator: "-")[1]), s < seq { older.append(b) }
    }
    guard let chosen else { die("no checkpoint file matches the paper anchor") }
    try d.restore(chosen, paperFingerprint: fp, paperSequence: seq, paperHash: h, older: older, now: now())
    print("Restored checkpoint \(seq). Lost-device keys are marked custody=lost; run a recovery session (R3.3).")
}

func release(_ d: Device) throws {
    switch CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : "" {
    case "tree-hash": print(try Release.treeSHA256(URL(fileURLWithPath: CommandLine.arguments.count > 3 ? CommandLine.arguments[3] : ".")))
    case "sign":
        let commit = arg("--commit"), tree = try Release.treeSHA256(URL(fileURLWithPath: arg("--tree")))
        let bin = sha256Hex(Array(try Data(contentsOf: URL(fileURLWithPath: arg("--binary")))))
        guard commit.count == 40, commit.allSatisfy({ "0123456789abcdef".contains($0) }) else { die("--commit must be 40 hex", 2) }
        let k = localOperator(d)
        var nonce = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, 16, &nonce) == 0 else { die("rng failed") }
        let p = Release.payload(commit: commit, tree: tree, binary: bin, toolchain: arg("--toolchain"), device: deviceSerial(),
                                registry: d.registry, keyId: k.keyId, now: now(), nonce: hex(nonce))
        let lines = ["SIGNER RELEASE", "INSTALLED: \(d.registry.signerCommit)", "NEW COMMIT: \(commit)", "TREE SHA-256: \(tree)",
                     "BINARY SHA-256: \(bin)", "", "Approve only after reviewing the complete diff of the signer tree on this device."]
        guard let ctx = approve(lines, reason: "Approve signer release \(commit.prefix(12))") else { die("not signed") }
        let out = d.dir.appendingPathComponent("releases/\(commit).json")
        try FileManager.default.createDirectory(at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
        try AtomicFile.write(try Release.record(p, key: try operatorKey(d, k.keyId, ctx)), to: out, mode: 0o600, replace: false)
        print("Wrote \(out.path). Install with `release install --record \(out.path) --binary …` within 1 hour.")
    case "install":
        let commit = try d.install(record: Array(try Data(contentsOf: URL(fileURLWithPath: arg("--record")))), binary: URL(fileURLWithPath: arg("--binary")), now: now())
        print("Installed \(commit); `current` updated; the previous version is kept in versions/.")
    default: die("release tree-hash|sign|install", 2)
    }
}

// ── commands ─────────────────────────────────────────────────────────────
do {
    let d = try Device(dir: base)
    try FileManager.default.createDirectory(at: keysDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let cmd = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
    let sub = CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : ""
    switch cmd {
    case "clock-check":
        print("This device's clock (UTC): \(ISO8601DateFormatter().string(from: Date()))")
        guard confirm("Compare it with an independent time source.", word: "CORRECT") else { die("not confirmed") }
        try d.clockChecked(now: now())
    case "create-key":
        let name = arg("--operator"), exp = expiry()
        guard touchID(reason: "Create a Sentinel operator key in the Secure Enclave") != nil else { die("Touch ID failed") }
        let (key, handle) = try SecureEnclaveKey.create()
        let rk = RegistryKey(keyId: KeyIdentity.keyId(publicX963: key.publicX963), role: "operator", publicX963: key.publicX963,
                             operatorName: name, expiresAt: exp, status: "candidate", custody: "this-device", session: d.registry.recoverySession)
        print("New Secure Enclave key \(rk.keyId)\nPublic-key fingerprint (record on paper): \(rk.fingerprint)")
        guard confirm("Add it to the registry as a candidate (active only after a committed key.rotate)?") else { die("not added") }
        try AtomicFile.write(Array(handle), to: keysDir.appendingPathComponent("\(rk.keyId).handle"), mode: 0o600, replace: false)
        try d.addCandidate(rk, now: now())
    case "register-recovery":
        let name = arg("--operator"), exp = expiry()
        let securityKey = SecurityKey()
        let (cred, x963) = try securityKey.register(name: name)
        let rk = RegistryKey(keyId: KeyIdentity.keyId(publicX963: x963), role: "recovery", publicX963: x963, operatorName: name,
                             expiresAt: exp, status: "candidate", custody: "external-fido2", recovery: RecoveryCredential(credentialId: cred))
        print("New recovery credential \(rk.keyId)\nPublic-key fingerprint (record on paper): \(rk.fingerprint)")
        guard confirm("Add it to the registry as a candidate?") else { die("not added") }
        try d.addCandidate(rk, now: now())
    case "export-pub": print("Wrote \(try d.exportPublic(keyId: arg("--key-id"), volume: URL(fileURLWithPath: arg("--volume")), now: now()).path)")
    case "intake":
        let r = try d.intake(volume: URL(fileURLWithPath: arg("--volume")), now: now())
        print("Spooled \(r.items.count) request(s)\(r.audit != nil ? " and a trust-store audit" : ""); ignored \(r.ignored.count); refused \(r.refused.count). Eject the volume, then run `review`.")
    case "review": try review(d)
    case "deliver": for rid in try d.deliver(volume: URL(fileURLWithPath: arg("--volume")), reissue: opt("--reissue"), now: now()) { print("Delivered \(rid)") }
    case "audit":
        guard let b = FileManager.default.contents(atPath: d.spool.appendingPathComponent(Transport.auditName).path) else { die("no spooled trust-store audit; intake one first") }
        let r = try d.audit(dmTrust: Array(b), now: now())
        print(r.match ? "MATCH \(d.registry.expectedFingerprint)" : "MISMATCH\n only on DM: \(r.onlyOnDM)\n only on SD: \(r.onlyOnSD)\n different: \(r.different)")
        if d.registry.pending != nil { print("Pending change present on the DM: \(d.registry.changePresent(in: r.dmKeys))") }
    case "pending":
        switch sub {
        case "show": print(d.registry.state, d.registry.pending.map { "\($0.action) \($0.target) request \($0.requestId) expires \($0.expiresAt)" } ?? "")
        case "commit":
            guard let p = d.registry.pending, confirm("Confirm the DM accepted \(p.action) for \(p.target).") else { die("not committed") }
            try d.commitPending(now: now())
        case "abandon": guard confirm("The DM did not apply the pending change.", word: "ABANDON") else { die("not changed") }; try d.abandonPending(now: now())
        case "resolve":
            guard let b = FileManager.default.contents(atPath: d.spool.appendingPathComponent(Transport.auditName).path) else { die("intake a trust-store audit first") }
            print(try d.resolveAbandon(dmTrust: Array(b), now: now()))
        default: die("pending show|commit|abandon|resolve", 2)
        }
    case "ceremony":
        if sub == "start" {
            let facts: [(String, JSONValue)] = [("device", .string(deviceSerial())), ("macos", .string(ProcessInfo.processInfo.operatingSystemVersionString)),
                                                ("signer_commit", .string(d.registry.signerCommit)), ("signer_binary", .string(d.registry.signerBinary))]
            _ = try d.ceremony("start", facts: facts, now: now())
            print("Ceremony started on \(deviceSerial()). Record the date, time and serial on the sheet.")
        } else { print("Ceremony hash (write it on the sheet, then sign and date the sheet): \(try d.ceremony("end", facts: [], now: now()) ?? "")") }
    case "recovery":
        guard touchID(reason: "\(sub == "start" ? "Start" : "End") a Sentinel recovery session") != nil else { die("Touch ID failed") }
        print(try d.recoverySession(start: sub == "start", now: now()))
    case "checkpoint": try checkpoint(d, write: sub == "write", volume: URL(fileURLWithPath: arg("--volume")))
    case "release": try release(d)
    default: die("unknown command; see the header of main.swift", 2)
    }
} catch let r as Refusal {
    die(r.code)
} catch {
    die("\(error)")
}
