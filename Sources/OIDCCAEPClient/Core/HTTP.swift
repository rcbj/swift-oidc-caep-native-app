// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// One HTTP request the library makes.
public struct HTTPRequest: Sendable {
    public var url: URL
    public var method: String
    /// Header names in lower case.
    public var headers: [String: String]
    public var body: Data?

    public init(url: URL, method: String = "GET", headers: [String: String] = [:], body: Data? = nil) {
        self.url = url
        self.method = method
        self.headers = Dictionary(headers.map { ($0.key.lowercased(), $0.value) }, uniquingKeysWith: { _, b in b })
        self.body = body
    }
}

/// One HTTP response.
public struct HTTPResponse: Sendable {
    public var url: URL
    public var status: Int
    /// Header names in lower case.
    public var headers: [String: String]
    public var body: Data

    public init(url: URL, status: Int, headers: [String: String] = [:], body: Data = Data()) {
        self.url = url
        self.status = status
        self.headers = Dictionary(headers.map { ($0.key.lowercased(), $0.value) }, uniquingKeysWith: { _, b in b })
        self.body = body
    }

    public var isOK: Bool { (200..<300).contains(status) }
    public func header(_ name: String) -> String? { headers[name.lowercased()] }
    public var text: String { String(decoding: body, as: UTF8.self) }
}

/// Sends the library's HTTP requests. The default is ``URLSessionTransport``; tests and apps with their own
/// networking stack can supply another (the counterpart of the JavaScript library's `fetch` option).
///
/// A transport must not follow redirects: an endpoint that redirects is answered as the redirect itself.
public protocol HTTPTransport: Sendable {
    func send(_ request: HTTPRequest, timeout: TimeInterval) async throws -> HTTPResponse
}

/// ``HTTPTransport`` over `URLSession`, with redirects refused, no cookies, and no caching.
public final class URLSessionTransport: NSObject, HTTPTransport, URLSessionTaskDelegate, @unchecked Sendable {
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()

    public override init() { super.init() }

    public func send(_ request: HTTPRequest, timeout: TimeInterval) async throws -> HTTPResponse {
        var r = URLRequest(url: request.url, timeoutInterval: timeout)
        r.httpMethod = request.method
        for (name, value) in request.headers { r.setValue(value, forHTTPHeaderField: name) }
        r.httpBody = request.body
        let (data, response): (Data, URLResponse) = try await withCheckedThrowingContinuation { continuation in
            let task = session.dataTask(with: r) { data, response, error in
                if let error { continuation.resume(throwing: error) }
                else if let response { continuation.resume(returning: (data ?? Data(), response)) }
                else { continuation.resume(throwing: URLError(.badServerResponse)) }
            }
            task.resume()
        }
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        var headers: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            if let k = key as? String { headers[k.lowercased()] = "\(value)" }
        }
        return HTTPResponse(url: http.url ?? request.url, status: http.statusCode, headers: headers, body: data)
    }

    // The library never follows a redirect (the JavaScript library's `redirect: 'manual'`).
    public func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                           newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

/// What every request the library makes shares: the transport and the timeout.
struct HTTPClient: Sendable {
    var transport: any HTTPTransport
    var timeout: TimeInterval

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        do {
            return try await transport.send(request, timeout: timeout)
        } catch {
            throw OIDCError(kind: .general, "HTTP request to \(request.url.absoluteString) failed: \(error.localizedDescription)",
                            code: "network_error", underlying: error)
        }
    }

    func get(_ url: URL, headers: [String: String] = ["accept": "application/json"]) async throws -> HTTPResponse {
        try await send(HTTPRequest(url: url, method: "GET", headers: headers))
    }
}

/// Reads a JSON body, turning OAuth error bodies and non-2xx responses into errors.
func readJSON(_ res: HTTPResponse, errorKind: OIDCError.Kind = .general) throws -> JSONValue? {
    let text = res.text
    var body: JSONValue?
    if !res.body.isEmpty {
        body = try? JSONValue.parse(res.body)
        if body == nil, res.isOK {
            throw OIDCError(kind: errorKind, "Expected JSON from \(res.url.absoluteString), got: \(text.prefix(200))", status: res.status)
        }
    }
    if !res.isOK {
        if let error = body?["error"]?.stringValue {
            throw OIDCError.oauth(error: error, description: body?["error_description"]?.stringValue,
                                  uri: body?["error_uri"]?.stringValue, status: res.status, response: body)
        }
        throw OIDCError(kind: errorKind, "HTTP \(res.status) from \(res.url.absoluteString)\(text.isEmpty ? "" : ": \(text.prefix(200))")",
                        code: "http_error", status: res.status, response: body ?? (text.isEmpty ? nil : .string(text)))
    }
    return body
}

/// Reads a JSON body that must be an object.
func readJSONObject(_ res: HTTPResponse, errorKind: OIDCError.Kind = .general) throws -> JSONObject {
    guard let object = try readJSON(res, errorKind: errorKind)?.objectValue else {
        throw OIDCError(kind: errorKind, "Expected a JSON object from \(res.url.absoluteString)", status: res.status)
    }
    return object
}

// MARK: - Form and query parameters

/// An ordered list of name/value pairs, encoded as `application/x-www-form-urlencoded` (the JavaScript
/// library's `URLSearchParams`). Names may repeat (`resource`).
public struct FormParameters: Sendable, Equatable, Sequence {
    public private(set) var items: [(name: String, value: String)] = []

    public init() {}
    public init(_ pairs: [(String, String)]) { items = pairs.map { (name: $0.0, value: $0.1) } }

    /// Parses `a=1&b=2` (a query string or form body). `+` is a space.
    public init(parsing string: String) {
        let s = string.hasPrefix("?") || string.hasPrefix("#") ? String(string.dropFirst()) : string
        for part in s.split(separator: "&", omittingEmptySubsequences: true) {
            let pieces = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let decode = { (x: Substring) in String(x).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? String(x) }
            items.append((name: decode(pieces[0]), value: pieces.count > 1 ? decode(pieces[1]) : ""))
        }
    }

    public func get(_ name: String) -> String? { items.first { $0.name == name }?.value }
    public func getAll(_ name: String) -> [String] { items.filter { $0.name == name }.map(\.value) }
    public func has(_ name: String) -> Bool { items.contains { $0.name == name } }
    public var names: [String] { var seen = Set<String>(); return items.map(\.name).filter { seen.insert($0).inserted } }

    /// Replaces every value of `name` with this one (or removes them, for nil).
    public mutating func set(_ name: String, _ value: String?) {
        guard let value else { items.removeAll { $0.name == name }; return }
        if let i = items.firstIndex(where: { $0.name == name }) {
            items[i].value = value
            items = items.enumerated().filter { $0.offset == i || $0.element.name != name }.map(\.element)
        } else {
            items.append((name: name, value: value))
        }
    }

    public mutating func append(_ name: String, _ value: String) { items.append((name: name, value: value)) }

    public var encoded: String {
        items.map { "\(Self.escape($0.name))=\(Self.escape($0.value))" }.joined(separator: "&")
    }

    public func makeIterator() -> IndexingIterator<[(name: String, value: String)]> { items.makeIterator() }

    public static func == (a: FormParameters, b: FormParameters) -> Bool {
        a.items.map(\.name) == b.items.map(\.name) && a.items.map(\.value) == b.items.map(\.value)
    }

    private static let unreserved: CharacterSet = {
        var set = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._*")
        set.insert(" ")
        return set
    }()

    static func escape(_ s: String) -> String {
        (s.addingPercentEncoding(withAllowedCharacters: unreserved) ?? s).replacingOccurrences(of: " ", with: "+")
    }
}

extension URL {
    /// This URL with `params` added to its query (existing parameters are kept).
    func appendingQuery(_ params: FormParameters) -> URL {
        guard !params.items.isEmpty, var components = URLComponents(url: self, resolvingAgainstBaseURL: false) else { return self }
        let existing = components.percentEncodedQuery.map { $0.isEmpty ? "" : $0 + "&" } ?? ""
        components.percentEncodedQuery = existing + params.encoded
        return components.url ?? self
    }
}
