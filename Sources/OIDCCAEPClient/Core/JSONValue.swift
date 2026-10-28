// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation

/// A JSON object: provider metadata, token responses, ID token claims, SET payloads.
public typealias JSONObject = [String: JSONValue]

/// Any JSON value. Claims, metadata and event payloads are open-ended, so the library keeps them as
/// `JSONValue` and offers typed accessors (``stringValue``, ``objectValue`` …) for the members it reads.
public enum JSONValue: Hashable, Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object(JSONObject)

    public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    public var boolValue: Bool? { if case .bool(let b) = self { return b }; return nil }
    public var doubleValue: Double? { if case .number(let n) = self { return n }; return nil }
    /// The number, when it is a whole number.
    public var intValue: Int? {
        guard case .number(let n) = self, n.isFinite, n.rounded() == n, abs(n) < 9.0e15 else { return nil }
        return Int(n)
    }
    public var arrayValue: [JSONValue]? { if case .array(let a) = self { return a }; return nil }
    public var objectValue: JSONObject? { if case .object(let o) = self { return o }; return nil }
    public var isNull: Bool { if case .null = self { return true }; return false }

    /// An array of strings (non-string members are skipped), or nil when this is not an array.
    public var stringArrayValue: [String]? { arrayValue?.compactMap(\.stringValue) }

    public subscript(key: String) -> JSONValue? { objectValue?[key] }
    public subscript(index: Int) -> JSONValue? {
        guard let a = arrayValue, a.indices.contains(index) else { return nil }
        return a[index]
    }

    /// Parses a JSON document.
    public static func parse(_ data: Data) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: data)
    }

    /// Parses a JSON document that must be an object.
    public static func parseObject(_ data: Data) throws -> JSONObject {
        guard let object = try parse(data).objectValue else {
            throw OIDCError.validation("Expected a JSON object")
        }
        return object
    }

    /// Compact (or pretty-printed) JSON text, with keys sorted.
    public func jsonString(pretty: Bool = false) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = pretty ? [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes] : [.sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(self) else { return "null" }
        return String(decoding: data, as: UTF8.self)
    }

    /// JSON data for this value.
    public func jsonData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
}

extension JSONValue: Codable {
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else if let n = try? c.decode(Double.self) { self = .number(n) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let a = try? c.decode([JSONValue].self) { self = .array(a) }
        else if let o = try? c.decode([String: JSONValue].self) { self = .object(o) }
        else { throw DecodingError.dataCorruptedError(in: c, debugDescription: "Not a JSON value") }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .number(let n):
            // Whole numbers are written without a fraction (`1`, not `1.0`): `exp`, `iat`, `expires_in`.
            if n.isFinite, n.rounded() == n, abs(n) < 9.0e15 { try c.encode(Int64(n)) } else { try c.encode(n) }
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }
}

extension JSONValue: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral, ExpressibleByFloatLiteral,
    ExpressibleByBooleanLiteral, ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral, ExpressibleByNilLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
    public init(integerLiteral value: Int) { self = .number(Double(value)) }
    public init(floatLiteral value: Double) { self = .number(value) }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { _, last in last }))
    }
    public init(nilLiteral: ()) { self = .null }
}

extension JSONValue {
    public init(_ value: String) { self = .string(value) }
    public init(_ value: Int) { self = .number(Double(value)) }
    public init(_ value: [String]) { self = .array(value.map(JSONValue.string)) }
}

extension Dictionary where Key == String, Value == JSONValue {
    /// Compact JSON text for the object, with keys sorted.
    public func jsonString(pretty: Bool = false) -> String { JSONValue.object(self).jsonString(pretty: pretty) }
    func string(_ key: String) -> String? { self[key]?.stringValue }
}
