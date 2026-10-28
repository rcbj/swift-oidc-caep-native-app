// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#if canImport(Glibc) || canImport(Darwin)
import Foundation
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

/// ``WebAuthenticator`` for a loopback redirect URI (RFC 8252 §7.3), such as `http://127.0.0.1:53682/callback`:
/// it listens on that port, opens the provider's page in the person's default browser, and returns when the
/// browser is redirected back to the port.
///
/// This is how a desktop app without `ASWebAuthenticationSession` signs in: on Linux (GNOME, KDE) it opens
/// the browser with `xdg-open`. It works on macOS too, with `open`.
public final class LoopbackWebAuthenticator: WebAuthenticator, @unchecked Sendable {
    /// How long to wait for the browser to come back (seconds).
    public let timeout: TimeInterval
    private let openBrowser: @Sendable (URL) throws -> Void
    /// The listener waiting on each port, in this process.
    private static let active = Locked<[Int: LoopbackListener]>([:])

    /// - Parameters:
    ///   - openBrowser: Opens a URL in the person's browser. Default: ``openInSystemBrowser(_:)``.
    public init(timeout: TimeInterval = 300, openBrowser: @escaping @Sendable (URL) throws -> Void = LoopbackWebAuthenticator.openInSystemBrowser) {
        self.timeout = timeout
        self.openBrowser = openBrowser
    }

    /// Opens `url` in the default browser: `xdg-open` on Linux, `open` on macOS.
    ///
    /// Inside an AppImage (`APPDIR` set), `LD_LIBRARY_PATH` points at the image's own libraries; it is left
    /// out of the browser's environment so the browser loads the system's.
    public static func openInSystemBrowser(_ url: URL) throws {
        let process = Process()
        #if os(macOS)
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        #else
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        #endif
        process.arguments = ["xdg-open", url.absoluteString]
        #if os(macOS)
        process.arguments = [url.absoluteString]
        #endif
        var environment = ProcessInfo.processInfo.environment
        if environment["APPDIR"] != nil {
            environment["LD_LIBRARY_PATH"] = environment["CAEP_ORIGINAL_LD_LIBRARY_PATH"]
            if environment["LD_LIBRARY_PATH"]?.isEmpty ?? true { environment["LD_LIBRARY_PATH"] = nil }
        }
        process.environment = environment
        try process.run()
    }

    public func authenticate(url: URL, callback: URL) async throws -> URL {
        guard callback.scheme?.lowercased() == "http", isLoopback(callback), let port = callback.port else {
            throw OIDCError.usage("LoopbackWebAuthenticator needs a loopback redirect URI with a port, such as http://127.0.0.1:53682/callback, not \(callback.absoluteString)")
        }
        // A sign-in that never came back (the provider showed an error and never redirected, the tab was
        // closed) still holds the port until it times out. A new one on the same port replaces it: the old one
        // ends as cancelled, and its socket is closed before this one binds.
        let replaced = Self.active.withLock { $0.removeValue(forKey: port) }
        replaced?.cancel()
        let listener = try LoopbackListener.bindRetrying(host: callback.host ?? "127.0.0.1", port: port, retryFor: replaced == nil ? 0 : 2)
        Self.active.withLock { $0[port] = listener }
        do {
            try openBrowser(url)
        } catch {
            listener.close()
            throw OIDCError(kind: .general, "Could not open the browser: \(error.localizedDescription)", code: "web_authentication_failed", underlying: error)
        }
        let path = callback.path.isEmpty ? "/" : callback.path
        let deadline = Date().addingTimeInterval(timeout)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
                Thread.detachNewThread {
                    defer {
                        listener.close()
                        Self.active.withLock { if $0[port] === listener { $0[port] = nil } }
                    }
                    do {
                        let query = try listener.waitForRequest(path: path, deadline: deadline)
                        var c = URLComponents(url: callback, resolvingAgainstBaseURL: false)!
                        c.percentEncodedQuery = query.isEmpty ? nil : query
                        continuation.resume(returning: c.url ?? callback)
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            listener.cancel()
        }
    }
}

/// One listening socket on a loopback address.
private final class LoopbackListener: @unchecked Sendable {
    private let fd: Int32
    private let cancelled = Locked(false)
    private let closed = Locked(false)

    init(host: String, port: Int) throws {
        let ipv6 = host.contains(":")
        #if canImport(Glibc)
        let stream = Int32(SOCK_STREAM.rawValue)
        #else
        let stream = SOCK_STREAM
        #endif
        fd = socket(ipv6 ? AF_INET6 : AF_INET, stream, 0)
        guard fd >= 0 else { throw Self.error("socket") }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var result: Int32
        if ipv6 {
            var addr = sockaddr_in6()
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = in_port_t(UInt16(port)).bigEndian
            addr.sin6_addr = in6addr_loopback
            result = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        } else {
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = in_port_t(UInt16(port)).bigEndian
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")
            result = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        guard result == 0, listen(fd, 8) == 0 else {
            let e = Self.error("listening on port \(port)")
            _ = closeSocket(fd)
            throw e
        }
    }

    /// Stops waiting, and frees the port: shutdown() wakes the thread polling the socket, which then closes it.
    func cancel() {
        cancelled.withLock { $0 = true }
        if !closed.current { _ = shutdown(fd, Int32(SHUT_RDWR)) }
    }

    /// Binds, retrying for up to `retryFor` seconds while the port is still held by a listener being replaced.
    static func bindRetrying(host: String, port: Int, retryFor: TimeInterval) throws -> LoopbackListener {
        let deadline = Date().addingTimeInterval(retryFor)
        while true {
            do { return try LoopbackListener(host: host, port: port) } catch {
                guard Date() < deadline else { throw error }
                usleep(50_000)
            }
        }
    }

    func close() {
        let first = closed.withLock { c -> Bool in defer { c = true }; return !c }
        if first { _ = closeSocket(fd) }
    }

    /// Answers requests until one arrives for `path`, and returns its query string.
    func waitForRequest(path: String, deadline: Date) throws -> String {
        while true {
            if cancelled.current { throw OIDCError(kind: .general, "The sign-in was cancelled", code: OIDCError.userCancelledCode) }
            if Date() > deadline { throw OIDCError(kind: .general, "The browser did not come back within the time allowed", code: "web_authentication_failed") }
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, 250) > 0 else { continue }
            let client = accept(fd, nil, nil)
            guard client >= 0 else { continue }
            defer { _ = closeSocket(client) }
            guard let target = Self.readRequestTarget(client) else { continue }
            let parts = target.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.first.map(String.init) == path else {
                Self.respond(client, status: "404 Not Found", body: "Not found.")
                continue
            }
            Self.respond(client, status: "200 OK", body: "Signed in. You can close this window and return to the app.")
            return parts.count > 1 ? String(parts[1]) : ""
        }
    }

    /// The request target of an HTTP/1.x GET (`/callback?code=…`).
    private static func readRequestTarget(_ client: Int32) -> String? {
        var data = [UInt8]()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while data.count < 65_536 {
            let n = recv(client, &buffer, buffer.count, 0)
            if n <= 0 { break }
            data += buffer[0..<n]
            if data.count >= 4, String(decoding: data.suffix(4), as: UTF8.self) == "\r\n\r\n" { break }
            if String(decoding: data, as: UTF8.self).contains("\r\n\r\n") { break }
        }
        let line = String(decoding: data, as: UTF8.self).split(separator: "\r\n", maxSplits: 1).first ?? ""
        let fields = line.split(separator: " ")
        guard fields.count == 3, fields[0] == "GET", fields[2].hasPrefix("HTTP/1.") else { return nil }
        return String(fields[1])
    }

    private static func respond(_ client: Int32, status: String, body: String) {
        let html = "<!doctype html><meta charset=utf-8><title>\(body)</title><p style=\"font:16px sans-serif;margin:3em\">\(body)</p>"
        let response = "HTTP/1.1 \(status)\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(html.utf8.count)\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n\(html)"
        _ = response.withCString { send(client, $0, strlen($0), 0) }
    }

    private static func error(_ what: String) -> OIDCError {
        OIDCError(kind: .general, "Loopback redirect listener failed (\(what)): \(String(cString: strerror(errno)))", code: "web_authentication_failed")
    }
}

private func closeSocket(_ fd: Int32) -> Int32 {
    #if canImport(Glibc)
    return Glibc.close(fd)
    #else
    return Darwin.close(fd)
    #endif
}
#endif
