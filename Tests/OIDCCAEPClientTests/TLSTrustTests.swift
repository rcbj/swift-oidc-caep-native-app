// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation
import XCTest
@testable import OIDCCAEPClient

final class TLSTrustTests: XCTestCase {
    /// A throwaway self-signed certificate (CN=test root), DER.
    static let der = Data(base64Encoded: "MIIBfzCCASWgAwIBAgIUfXyPZp9cB8mXjlHPkMJIr0JjBrUwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJdGVzdCByb290MCAXDTI2MDEwMTAwMDAwMFoYDzIxMjYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAl0ZXN0IHJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ7mXkF0z0Oe0rP3m8m8n0gk6Kp3o3XK6a7m3h1qkq4w8cBf1qYz0vKX3y9zYqQyB0bQ2F1q0s3K7c7R0Kj3wKoo1MwUTAdBgNVHQ4EFgQUAAAAAAAAAAAAAAAAAAAAAAAAAAAwHwYDVR0jBBgwFoAUAAAAAAAAAAAAAAAAAAAAAAAAAAAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1+0CIA==")!

    var pem: String {
        "-----BEGIN CERTIFICATE-----\n\(Self.der.base64EncodedString(options: .lineLength64Characters))\n-----END CERTIFICATE-----\n"
    }

    func testPEMChainsAndDER() throws {
        let chain = try TLSTrust(pemOrDER: [Data((pem + "junk between\n" + pem).utf8), Self.der])
        XCTAssertEqual(chain.certificates.count, 3, "every certificate of a chain is kept, and DER is accepted")
        XCTAssertEqual(chain.certificates[0], Self.der)
        XCTAssertTrue(chain.includeSystemRoots)
        XCTAssertThrowsError(try TLSTrust(pemOrDER: [Data("not a certificate".utf8)]))
        XCTAssertThrowsError(try TLSTrust(pemOrDER: [Data("-----BEGIN CERTIFICATE-----\nAAAA".utf8)]))
    }

    func testConfigurationReadsTrustedCertificates() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try Data(pem.utf8).write(to: dir.appendingPathComponent("root.pem"))
        let base: [String: Any] = ["MetadataURL": "https://op.example.test/.well-known/openid-configuration", "ClientID": "c",
                                   "RedirectURI": "net.example.app:/cb"]
        var d = base
        d["TrustedCertificates"] = ["root.pem", pem]
        d["TrustSystemRoots"] = false
        let c = try OIDCAppConfiguration(dictionary: d, baseURL: dir)
        XCTAssertEqual(c.tlsTrust?.certificates.count, 2, "a relative path, and inline PEM")
        XCTAssertEqual(c.tlsTrust?.includeSystemRoots, false)
        XCTAssertFalse(c.insecureSkipTLSVerification)
        XCTAssertNil(try OIDCAppConfiguration(dictionary: base).tlsTrust)
        d["TrustedCertificates"] = ["missing.pem"]
        XCTAssertThrowsError(try OIDCAppConfiguration(dictionary: d, baseURL: dir))
        var insecure = base
        insecure["InsecureSkipTLSVerification"] = true
        XCTAssertTrue(try OIDCAppConfiguration(dictionary: insecure).insecureSkipTLSVerification)
    }
}

final class LoopbackWebAuthenticatorTests: XCTestCase {
    func testReturnsTheRedirectTheBrowserMakes() async throws {
        let port = Int.random(in: 41_000...48_000)
        let callback = URL(string: "http://127.0.0.1:\(port)/callback")!
        // The "browser": once the page is opened, it is sent to an unrelated path, then to the redirect URI.
        let auth = LoopbackWebAuthenticator(timeout: 10) { _ in
            Task {
                let transport = URLSessionTransport()
                let other = try await transport.send(HTTPRequest(url: URL(string: "http://127.0.0.1:\(port)/favicon.ico")!), timeout: 5)
                XCTAssertEqual(other.status, 404)
                _ = try await transport.send(HTTPRequest(url: URL(string: "http://127.0.0.1:\(port)/callback?code=abc&state=xyz&iss=https%3A%2F%2Fop")!), timeout: 5)
            }
        }
        let result = try await auth.authenticate(url: URL(string: "https://op.example.test/authorize")!, callback: callback)
        let p = OIDCClient.responseParameters(result)
        XCTAssertEqual(p.get("code"), "abc")
        XCTAssertEqual(p.get("state"), "xyz")
        XCTAssertEqual(p.get("iss"), "https://op")
        XCTAssertEqual(result.path, "/callback")
    }

    func testRefusesANonLoopbackRedirect() async {
        let auth = LoopbackWebAuthenticator { _ in }
        await XCTAssertThrowsCode("invalid_argument") {
            try await auth.authenticate(url: URL(string: "https://op.example.test/authorize")!, callback: URL(string: "net.example.app:/cb")!)
        }
    }
}
