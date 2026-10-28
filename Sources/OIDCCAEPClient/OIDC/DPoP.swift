// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Crypto
import Foundation

/// DPoP proof algorithms this library can create, in preference order.
public let dpopAlgorithms: [String] = ["ES256", "ES384", "ES512"]

/// Where a DPoP key pair is kept between launches.
///
/// - ``MemoryKeyStore``: a software key in memory (a new key every launch).
/// - ``KeychainKeyStore``: a software key whose private bytes are kept in the Keychain.
/// - ``SecureEnclaveKeyStore``: a P-256 key generated in the Secure Enclave. Its private key can never be
///   read out, by this app or anything else, so a stolen access or refresh token is useless elsewhere —
///   the counterpart of the browser's non-extractable WebCrypto key.
public protocol DPoPKeyStore: Sendable {
    /// The key kept for `alg`, if any.
    func load(alg: String) async throws -> (any JWSSigner)?
    /// Creates a key for `alg`, keeps it (replacing any other), and returns it.
    func create(alg: String) async throws -> any JWSSigner
    /// Forgets the key.
    func delete() async throws
    /// The algorithms this store can create keys for, in preference order.
    var supportedAlgorithms: [String] { get }
    /// Whether the private key can be read out of the store (a software key) or not (Secure Enclave).
    var isExtractable: Bool { get }
}

/// A software key in memory: a new one after every launch.
public actor MemoryKeyStore: DPoPKeyStore {
    private var signer: (any JWSSigner)?
    public init() {}
    public func load(alg: String) -> (any JWSSigner)? { signer?.alg == alg ? signer : nil }
    public func create(alg: String) throws -> any JWSSigner {
        let s = try SoftwareECSigner(alg: alg)
        signer = s
        return s
    }
    public func delete() { signer = nil }
    public nonisolated var supportedAlgorithms: [String] { dpopAlgorithms }
    public nonisolated var isExtractable: Bool { true }
}

/// A DPoP key pair (RFC 9449) and the proofs made with it.
///
/// Keep the same key for the lifetime of the tokens it binds: a refresh token bound to a key is useless
/// with any other.
public struct DPoPKey: Sendable {
    public let signer: any JWSSigner
    public var alg: String { signer.alg }
    public var publicJWK: JSONObject { signer.publicJWK }
    /// RFC 7638 SHA-256 thumbprint of the public key (the `jkt`).
    public let thumbprint: String

    public init(signer: any JWSSigner) {
        self.signer = signer
        thumbprint = jwkThumbprint(signer.publicJWK)
    }

    /// Loads the key held in `store` for `alg`, or creates one there.
    public static func loadOrCreate(store: any DPoPKeyStore, alg: String = "ES256") async throws -> DPoPKey {
        if let held = try await store.load(alg: alg) { return DPoPKey(signer: held) }
        return DPoPKey(signer: try await store.create(alg: alg))
    }

    /// A DPoP proof JWT (RFC 9449 §4.2) for one request.
    public func proof(method: String, url: URL, nonce: String? = nil, accessToken: String? = nil, now: Date = Date()) throws -> String {
        var claims: JSONObject = [
            "htm": .string(method.uppercased()),
            "htu": .string(htuOf(url)),
            "jti": .string(UUID().uuidString.lowercased()),
            "iat": JSONValue(nowSeconds(now)),
        ]
        if let nonce { claims["nonce"] = .string(nonce) }
        if let accessToken { claims["ath"] = .string(Base64URL.encode(sha256(accessToken))) }
        return try signJWS(header: ["typ": "dpop+jwt", "jwk": .object(publicJWK)], claims: claims, signer: signer)
    }
}

/// The `htu` of a request: its URL without query and fragment (RFC 9449 §4.2).
public func htuOf(_ url: URL) -> String {
    guard var c = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return url.absoluteString }
    c.query = nil
    c.fragment = nil
    c.scheme = c.scheme?.lowercased()
    c.host = c.host?.lowercased()
    if (c.scheme == "https" && c.port == 443) || (c.scheme == "http" && c.port == 80) { c.port = nil }
    if c.path.isEmpty { c.path = "/" }
    return c.string ?? url.absoluteString
}

/// Remembers the most recent `DPoP-Nonce` each server origin handed out (RFC 9449 §8, §9).
final class DPoPNonceCache: Sendable {
    private let nonces = Locked<[String: String]>([:])

    func get(_ url: URL) -> String? { originOf(url).flatMap { o in nonces.withLock { $0[o] } } }

    /// Records the nonce a response carries, if any, and returns it.
    @discardableResult
    func update(_ url: URL, _ response: HTTPResponse) -> String? {
        guard let nonce = response.header("dpop-nonce"), !nonce.isEmpty, let o = originOf(url) else { return nil }
        nonces.withLock { $0[o] = nonce }
        return nonce
    }
}

/// Whether a resource server's 401 asks for a (new) DPoP nonce (RFC 9449 §9).
func wantsDPoPNonce(_ response: HTTPResponse) -> Bool {
    guard response.status == 401 else { return false }
    let www = response.header("www-authenticate") ?? ""
    return www.range(of: "\\bdpop\\b", options: [.regularExpression, .caseInsensitive]) != nil
        && www.contains("error=\"use_dpop_nonce\"") && response.header("dpop-nonce") != nil
}
