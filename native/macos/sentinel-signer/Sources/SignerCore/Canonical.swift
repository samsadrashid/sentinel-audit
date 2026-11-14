import Foundation

/// A strictly canonical JSON value (signing protocol v1, §2).
public indirect enum JSONValue: Equatable {
    case object([(String, JSONValue)])
    case array([JSONValue])
    case string(String)
    case int(Int64)
    case bool(Bool)
    case null

    public static func == (a: JSONValue, b: JSONValue) -> Bool {
        switch (a, b) {
        case let (.object(x), .object(y)):
            return x.count == y.count && zip(x, y).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
        case let (.array(x), .array(y)): return x == y
        case let (.string(x), .string(y)): return x == y
        case let (.int(x), .int(y)): return x == y
        case let (.bool(x), .bool(y)): return x == y
        case (.null, .null): return true
        default: return false
        }
    }

    public subscript(key: String) -> JSONValue? {
        if case let .object(kv) = self { return kv.first { $0.0 == key }?.1 }
        return nil
    }

    public var string: String? { if case let .string(s) = self { return s }; return nil }
    public var int: Int64? { if case let .int(i) = self { return i }; return nil }
    public var keys: [String] { if case let .object(kv) = self { return kv.map { $0.0 } }; return [] }
}

public struct CanonicalError: Error, Equatable { public let code: String }

/// Strict parser: printable-ASCII strings with only `\"` and `\\` escapes, integers only (|n| < 2^53),
/// no whitespace, unique sorted keys. `decode(b)` succeeds only if `encode(decode(b)) == b`.
public enum Canonical {
    public static let maxDepth = 32
    static let limit: Int64 = 1 << 53

    public static func decode(_ bytes: [UInt8]) throws -> JSONValue {
        var p = Parser(b: bytes)
        let v = try p.value(depth: 0)
        guard p.i == bytes.count else { throw CanonicalError(code: "trailing_bytes") }
        guard encode(v) == bytes else { throw CanonicalError(code: "not_canonical") }
        return v
    }

    public static func encode(_ v: JSONValue) -> [UInt8] {
        var out: [UInt8] = []
        write(v, &out)
        return out
    }

    static func write(_ v: JSONValue, _ out: inout [UInt8]) {
        switch v {
        case let .object(kv):
            out.append(UInt8(ascii: "{"))
            for (n, (k, val)) in kv.sorted(by: { Array($0.0.utf8).lexicographicallyPrecedes(Array($1.0.utf8)) }).enumerated() {
                if n > 0 { out.append(UInt8(ascii: ",")) }
                writeString(k, &out)
                out.append(UInt8(ascii: ":"))
                write(val, &out)
            }
            out.append(UInt8(ascii: "}"))
        case let .array(a):
            out.append(UInt8(ascii: "["))
            for (n, x) in a.enumerated() {
                if n > 0 { out.append(UInt8(ascii: ",")) }
                write(x, &out)
            }
            out.append(UInt8(ascii: "]"))
        case let .string(s): writeString(s, &out)
        case let .int(i): out += Array(String(i).utf8)
        case let .bool(b): out += Array((b ? "true" : "false").utf8)
        case .null: out += Array("null".utf8)
        }
    }

    static func writeString(_ s: String, _ out: inout [UInt8]) {
        out.append(UInt8(ascii: "\""))
        for c in s.utf8 {
            if c == UInt8(ascii: "\"") || c == UInt8(ascii: "\\") { out.append(UInt8(ascii: "\\")) }
            out.append(c)
        }
        out.append(UInt8(ascii: "\""))
    }

    struct Parser {
        let b: [UInt8]
        var i = 0

        mutating func value(depth: Int) throws -> JSONValue {
            guard depth <= Canonical.maxDepth else { throw CanonicalError(code: "too_deep") }
            guard i < b.count else { throw CanonicalError(code: "truncated") }
            switch b[i] {
            case UInt8(ascii: "{"): return try object(depth: depth)
            case UInt8(ascii: "["): return try array(depth: depth)
            case UInt8(ascii: "\""): return .string(try string())
            case UInt8(ascii: "t"): try literal("true"); return .bool(true)
            case UInt8(ascii: "f"): try literal("false"); return .bool(false)
            case UInt8(ascii: "n"): try literal("null"); return .null
            case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"): return .int(try integer())
            default: throw CanonicalError(code: "unexpected_byte")
            }
        }

        mutating func literal(_ s: String) throws {
            let lit = Array(s.utf8)
            guard i + lit.count <= b.count, Array(b[i..<(i + lit.count)]) == lit else {
                throw CanonicalError(code: "bad_literal")
            }
            i += lit.count
        }

        mutating func integer() throws -> Int64 {
            let start = i
            if b[i] == UInt8(ascii: "-") { i += 1 }
            let digits = i
            while i < b.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(b[i]) { i += 1 }
            guard i > digits else { throw CanonicalError(code: "bad_number") }
            if i < b.count, [UInt8(ascii: "."), UInt8(ascii: "e"), UInt8(ascii: "E")].contains(b[i]) {
                throw CanonicalError(code: "float_not_allowed")
            }
            guard let s = String(bytes: b[start..<i], encoding: .ascii), let n = Int64(s),
                  n > -Canonical.limit, n < Canonical.limit
            else { throw CanonicalError(code: "integer_out_of_range") }
            return n
        }

        mutating func string() throws -> String {
            i += 1
            var out: [UInt8] = []
            while true {
                guard i < b.count else { throw CanonicalError(code: "truncated") }
                let c = b[i]
                if c == UInt8(ascii: "\"") { i += 1; break }
                if c == UInt8(ascii: "\\") {
                    guard i + 1 < b.count, b[i + 1] == UInt8(ascii: "\"") || b[i + 1] == UInt8(ascii: "\\") else {
                        throw CanonicalError(code: "bad_escape")
                    }
                    out.append(b[i + 1]); i += 2; continue
                }
                guard c >= 0x20, c <= 0x7E else { throw CanonicalError(code: "non_printable_ascii") }
                out.append(c); i += 1
            }
            return String(decoding: out, as: UTF8.self)
        }

        mutating func array(depth: Int) throws -> JSONValue {
            i += 1
            var out: [JSONValue] = []
            if i < b.count, b[i] == UInt8(ascii: "]") { i += 1; return .array(out) }
            while true {
                out.append(try value(depth: depth + 1))
                guard i < b.count else { throw CanonicalError(code: "truncated") }
                if b[i] == UInt8(ascii: ",") { i += 1; continue }
                if b[i] == UInt8(ascii: "]") { i += 1; return .array(out) }
                throw CanonicalError(code: "unexpected_byte")
            }
        }

        mutating func object(depth: Int) throws -> JSONValue {
            i += 1
            var out: [(String, JSONValue)] = []
            var seen = Set<String>()
            if i < b.count, b[i] == UInt8(ascii: "}") { i += 1; return .object(out) }
            while true {
                guard i < b.count, b[i] == UInt8(ascii: "\"") else { throw CanonicalError(code: "bad_key") }
                let k = try string()
                guard seen.insert(k).inserted else { throw CanonicalError(code: "duplicate_key") }
                guard i < b.count, b[i] == UInt8(ascii: ":") else { throw CanonicalError(code: "unexpected_byte") }
                i += 1
                out.append((k, try value(depth: depth + 1)))
                guard i < b.count else { throw CanonicalError(code: "truncated") }
                if b[i] == UInt8(ascii: ",") { i += 1; continue }
                if b[i] == UInt8(ascii: "}") { i += 1; return .object(out) }
                throw CanonicalError(code: "unexpected_byte")
            }
        }
    }
}
