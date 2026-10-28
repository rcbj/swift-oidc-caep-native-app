// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Crypto
import Foundation

/// base64url without padding (RFC 4648 §5), as JOSE uses it.
public enum Base64URL {
    public static func encode<D: DataProtocol>(_ data: D) -> String {
        Data(data).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decodes base64url. Padding, whitespace and the standard alphabet's `+` and `/` are refused.
    public static func decode(_ string: String) -> Data? {
        guard string.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else { return nil }
        var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = s.count % 4
        if remainder == 1 { return nil }
        if remainder > 0 { s += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: s)
    }
}

/// A cryptographically random base64url string (default 256 bits).
public func randomToken(bytes: Int = 32) -> String {
    var generator = SystemRandomNumberGenerator()
    return Base64URL.encode((0..<bytes).map { _ in UInt8.random(in: 0...255, using: &generator) })
}

func sha256(_ string: String) -> Data { Data(SHA256.hash(data: Data(string.utf8))) }

/// Compares two strings in time independent of where they differ, so a response's `state` cannot be
/// guessed byte by byte from timing. Both sides are hashed first so their lengths match.
func timingSafeEqual(_ a: String, _ b: String) -> Bool {
    let x = sha256(a), y = sha256(b)
    var diff: UInt8 = 0
    for (p, q) in zip(x, y) { diff |= p ^ q }
    return diff == 0
}

/// Loopback hosts, where plain http is acceptable (RFC 8252 §7.3, RFC 9700 §2.6).
func isLoopback(_ url: URL) -> Bool {
    guard var host = url.host?.lowercased() else { return false }
    if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
    if host == "localhost" || host.hasSuffix(".localhost") || host == "::1" { return true }
    let parts = host.split(separator: ".", omittingEmptySubsequences: false)
    return parts.count == 4 && parts[0] == "127" && parts.allSatisfy { p in p.count <= 3 && !p.isEmpty && p.allSatisfy(\.isNumber) && (Int(p) ?? 256) <= 255 }
}

/// https, or plain http to a loopback host. Anything unparseable is not secure.
func isSecureURL(_ value: String?) -> Bool {
    guard let value, let url = URL(string: value), let scheme = url.scheme?.lowercased(), url.host != nil else { return false }
    return scheme == "https" || (scheme == "http" && isLoopback(url))
}

/// A private-use URI scheme for a native app's redirect URI (RFC 8252 §7.1): a reverse domain name such as
/// `com.example.app`, so it contains a period, with no fragment.
func isPrivateUseRedirect(_ url: URL) -> Bool {
    guard let scheme = url.scheme?.lowercased(), scheme.contains("."), url.fragment == nil else { return false }
    return scheme.range(of: "^[a-z][a-z0-9+.-]*$", options: .regularExpression) != nil
}

/// Where a native app may receive a redirect: https, loopback http (RFC 8252 §7.3), or a private-use
/// scheme (RFC 8252 §7.1).
func isAcceptableRedirect(_ url: URL) -> Bool {
    isSecureURL(url.absoluteString) || isPrivateUseRedirect(url)
}

/// The origin (`scheme://host[:port]`) of a URL, with the default port left out, as the web defines it.
func originOf(_ url: URL) -> String? {
    guard let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased() else { return nil }
    let defaultPort = scheme == "https" ? 443 : scheme == "http" ? 80 : nil
    let hostPart = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
    if let port = url.port, port != defaultPort { return "\(scheme)://\(hostPart):\(port)" }
    return "\(scheme)://\(hostPart)"
}

func originOf(_ string: String) -> String? { URL(string: string).flatMap(originOf) }

func nowSeconds(_ now: Date) -> Int { Int(now.timeIntervalSince1970.rounded(.down)) }

// MARK: - Concurrency helpers

/// A value guarded by a lock, for state shared by synchronous and asynchronous code.
final class Locked<Value>: @unchecked Sendable {
    private var value: Value
    private let lock = NSLock()

    init(_ value: Value) { self.value = value }

    func withLock<R>(_ body: (inout Value) throws -> R) rethrows -> R {
        lock.lock()
        defer { lock.unlock() }
        return try body(&value)
    }

    var current: Value { withLock { $0 } }
}

/// An async mutex keyed by name: a refresh and a delete of one key's tokens never interleave, and two
/// refreshes never present the same rotating refresh token.
actor KeyedAsyncLock {
    private var held: Set<String> = []
    private var waiters: [String: [CheckedContinuation<Void, Never>]] = [:]

    func withLock<T: Sendable>(_ name: String, _ body: @Sendable () async throws -> T) async throws -> T {
        await acquire(name)
        do {
            let result = try await body()
            release(name)
            return result
        } catch {
            release(name)
            throw error
        }
    }

    private func acquire(_ name: String) async {
        if !held.contains(name) {
            held.insert(name)
            return
        }
        await withCheckedContinuation { waiters[name, default: []].append($0) }
    }

    private func release(_ name: String) {
        if var queue = waiters[name], !queue.isEmpty {
            let next = queue.removeFirst()
            waiters[name] = queue.isEmpty ? nil : queue
            next.resume()  // the lock passes straight to the next waiter
        } else {
            held.remove(name)
        }
    }
}

/// A subscription made with ``EventHub/subscribe(_:)``. Cancel it (or let it go) to stop receiving events.
public final class EventSubscription: @unchecked Sendable {
    private let onCancel: () -> Void
    private let cancelled = Locked(false)
    init(_ onCancel: @escaping () -> Void) { self.onCancel = onCancel }
    public func cancel() {
        let first = cancelled.withLock { c -> Bool in defer { c = true }; return !c }
        if first { onCancel() }
    }
    deinit { cancel() }
}

/// Delivers a component's events to any number of listeners, as callbacks or as `AsyncStream`s.
public final class EventHub<Event: Sendable>: @unchecked Sendable {
    private let listeners = Locked<[UUID: @Sendable (Event) -> Void]>([:])

    public init() {}

    /// Calls `listener` with every event until the returned subscription is cancelled or released.
    public func subscribe(_ listener: @escaping @Sendable (Event) -> Void) -> EventSubscription {
        let id = UUID()
        listeners.withLock { $0[id] = listener }
        return EventSubscription { [weak self] in self?.listeners.withLock { _ = $0.removeValue(forKey: id) } }
    }

    /// A stream of every event from now on. It ends when the consuming task is cancelled.
    public func stream() -> AsyncStream<Event> {
        AsyncStream { continuation in
            let id = UUID()
            listeners.withLock { $0[id] = { continuation.yield($0) } }
            continuation.onTermination = { [weak self] _ in self?.listeners.withLock { _ = $0.removeValue(forKey: id) } }
        }
    }

    func emit(_ event: Event) {
        for listener in listeners.withLock({ Array($0.values) }) { listener(event) }
    }
}

// MARK: - Logging

/// Where the library writes its few log lines (a received CAEP event, a warning about token storage, an
/// SSF error nobody handles). Replace ``OIDCLog/handler`` to route them elsewhere, or set it to a no-op.
public enum OIDCLog {
    public enum Level: String, Sendable { case info, warning, error }

    private static let _handler = Locked<@Sendable (Level, String) -> Void>({ level, message in
        let line = "[OIDCCAEPClient] \(message)\n"
        if level == .info { FileHandle.standardOutput.write(Data(line.utf8)) } else { FileHandle.standardError.write(Data(line.utf8)) }
    })

    public static var handler: @Sendable (Level, String) -> Void {
        get { _handler.current }
        set { _handler.withLock { $0 = newValue } }
    }

    static func log(_ level: Level, _ message: String) { handler(level, message) }
}
