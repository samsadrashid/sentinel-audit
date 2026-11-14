import Foundation

/// SD device ledger (protocol §5): seen request IDs, nonce→payload bindings, used one-time nonces.
/// Entries are kept until 30 days after `expires_at`. Stored canonically, written atomically (0600).
public final class Ledger {
    public static let retention: Int64 = 30 * 86400
    struct Entry { var payload: String; var oneTime: Bool; var used: Bool; var expiresAt: Int64 }

    let path: URL?
    var requests: [String: Int64] = [:]  // request_id -> prune-after
    var nonces: [String: Entry] = [:]

    public init(path: URL?) throws {
        self.path = path
        guard let path, FileManager.default.fileExists(atPath: path.path) else { return }
        let v = try Canonical.decode(Array(try Data(contentsOf: path)))
        if case let .object(r)? = v["requests"] { for (k, x) in r { requests[k] = x.int ?? 0 } }
        if case let .object(n)? = v["nonces"] {
            for (k, x) in n {
                nonces[k] = Entry(payload: x["payload"]?.string ?? "", oneTime: x["one_time"] == .bool(true),
                                  used: x["used"] == .bool(true), expiresAt: x["expires_at"]?.int ?? 0)
            }
        }
    }

    public func check(requestId: String, nonce: String, payloadSHA256: String, oneTime: Bool) throws {
        if requests[requestId] != nil { throw Refusal(code: "duplicate_request") }
        if let e = nonces[nonce] {
            if e.payload != payloadSHA256 { throw Refusal(code: "nonce_rebound") }
            if e.oneTime || oneTime, e.used { throw Refusal(code: "nonce_reused") }
        }
    }

    /// Record a request as seen, whether it was then signed or cancelled; a request_id is consumed once.
    public func recordSeen(requestId: String, expiresAt: Int64) throws {
        requests[requestId] = expiresAt + Ledger.retention
        try save()
    }

    public func recordSigned(_ r: ValidatedRequest) throws {
        requests[r.requestId] = r.expiresAt + Ledger.retention
        nonces[r.nonce] = Entry(payload: r.payloadSHA256, oneTime: r.oneTime, used: true, expiresAt: r.expiresAt)
        try save()
    }

    @discardableResult
    public func prune(now: Int64) throws -> Int {
        let before = requests.count + nonces.count
        requests = requests.filter { $0.value > now }
        nonces = nonces.filter { $0.value.expiresAt + Ledger.retention > now }
        try save()
        return before - requests.count - nonces.count
    }

    /// Every unexpired entry, for a D-46 checkpoint (never pruned during a restore).
    public func snapshot() -> JSONValue { encoded() }

    /// D-46 item 6: restore replay protection exactly. Only into an empty ledger.
    public func restore(_ v: JSONValue) throws {
        guard requests.isEmpty, nonces.isEmpty, v.keys == ["nonces", "requests"] else { throw Refusal(code: "ledger_not_empty") }
        if case let .object(r)? = v["requests"] { for (k, x) in r { requests[k] = x.int ?? Int64.max } }
        if case let .object(n)? = v["nonces"] {
            for (k, x) in n {
                nonces[k] = Entry(payload: x["payload"]?.string ?? "", oneTime: x["one_time"] == .bool(true),
                                  used: x["used"] != .bool(false), expiresAt: x["expires_at"]?.int ?? Int64.max)
            }
        }
        try save()
    }

    func save() throws {
        guard let path else { return }
        try AtomicFile.write(Canonical.encode(encoded()), to: path, mode: 0o600, replace: true)
    }

    func encoded() -> JSONValue {
        JSONValue.object([
            ("nonces", .object(nonces.map { ($0.key, .object([
                ("expires_at", .int($0.value.expiresAt)), ("one_time", .bool($0.value.oneTime)),
                ("payload", .string($0.value.payload)), ("used", .bool($0.value.used)),
            ])) })),
            ("requests", .object(requests.map { ($0.key, .int($0.value)) })),
        ])
    }
}

/// Append-only, hash-chained SD log (protocol §6.5). Each line: {"event","prev","seq","t", ...fields}.
public final class AuditLog {
    let path: URL
    public private(set) var head: String
    public private(set) var seq: Int64

    public init(path: URL) throws {
        self.path = path
        (head, seq) = (String(repeating: "0", count: 64), 0)
        if let data = FileManager.default.contents(atPath: path.path) {
            for line in data.split(separator: UInt8(ascii: "\n")) {
                let v = try Canonical.decode(Array(line))
                guard v["prev"]?.string == head, v["seq"]?.int == seq + 1 else { throw Refusal(code: "log_chain_broken") }
                (head, seq) = (sha256Hex(Array(line)), seq + 1)
            }
        }
    }

    public func append(_ event: String, _ fields: [(String, JSONValue)], now: Int64) throws {
        let line = Canonical.encode(.object([("event", .string(event)), ("prev", .string(head)), ("seq", .int(seq + 1)), ("t", .int(now))] + fields))
        let fd = open(path.path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Refusal(code: "log_unwritable") }
        defer { close(fd) }
        let out = line + [UInt8(ascii: "\n")]
        guard out.withUnsafeBytes({ Darwin.write(fd, $0.baseAddress, out.count) }) == out.count, fsync(fd) == 0 else {
            throw Refusal(code: "log_unwritable")
        }
        (head, seq) = (sha256Hex(line), seq + 1)
    }
}
