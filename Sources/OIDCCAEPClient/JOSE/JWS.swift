// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Crypto
import _CryptoExtras
import Foundation

/// Asymmetric JWS algorithms this library can verify. A public client has no secret, so HS* (MACed with a
/// client secret) is not among them.
public let asymmetricJWSAlgorithms: [String] = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"]

/// ID token algorithms this library can verify.
public let supportedIDTokenAlgorithms: [String] = asymmetricJWSAlgorithms

/// Why a JWS or JWT was not accepted, in the terms of the `jose` library the JavaScript client uses, so
/// that a SET's error can be classified the same way (a bad token, or a check that may pass later).
enum JOSEError: Error, CustomStringConvertible {
    case invalid(String)                 // JWSInvalid / JWTInvalid: malformed
    case notSupported(String)            // JOSENotSupported: e.g. an unknown `crit`
    case algNotAllowed(String)           // JOSEAlgNotAllowed
    case signatureFailed                 // JWSSignatureVerificationFailed
    case claimFailed(claim: String, String)  // JWTClaimValidationFailed
    case expired(claim: String, String)  // JWTExpired
    case noMatchingKey                   // JWKSNoMatchingKey: may pass after the JWKS is fetched again
    case jwksUnavailable(String)         // the JWKS could not be fetched or read: may pass later

    var description: String {
        switch self {
        case .invalid(let m), .notSupported(let m), .algNotAllowed(let m), .jwksUnavailable(let m): return m
        case .signatureFailed: return "signature verification failed"
        case .claimFailed(_, let m), .expired(_, let m): return m
        case .noMatchingKey: return "no applicable key found in the JSON Web Key Set"
        }
    }

    /// The token itself is bad; anything else may pass on a later attempt.
    var isDefinite: Bool {
        switch self {
        case .noMatchingKey, .jwksUnavailable: return false
        default: return true
        }
    }
}

/// A compact JWS, split and decoded (signature not yet verified).
struct CompactJWS {
    let header: JSONObject
    let payload: Data
    let signingInput: Data
    let signature: Data

    init(_ token: String) throws {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw JOSEError.invalid("Invalid Compact JWS") }
        guard let h = Base64URL.decode(String(parts[0])), let header = try? JSONValue.parseObject(h) else {
            throw JOSEError.invalid("Invalid JWS Protected Header")
        }
        guard let payload = Base64URL.decode(String(parts[1])), let signature = Base64URL.decode(String(parts[2])) else {
            throw JOSEError.invalid("Invalid Compact JWS encoding")
        }
        self.header = header
        self.payload = payload
        self.signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        self.signature = signature
    }

    var alg: String? { header.string("alg") }
}

/// Decodes a JWS's protected header without verifying anything.
public func decodeProtectedHeader(_ token: String) throws -> JSONObject {
    do { return try CompactJWS(token).header } catch { throw OIDCError.validation("Not a valid compact JWS") }
}

/// Decodes a JWT's payload without verifying anything. For display only: never trust what it returns.
public func decodeUnverifiedJWTPayload(_ token: String) -> JSONObject? {
    let parts = token.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3, let data = Base64URL.decode(String(parts[1])) else { return nil }
    return try? JSONValue.parseObject(data)
}

// MARK: - Keys

/// A public key from a JWK (RFC 7517), ready to verify signatures.
enum VerificationKey {
    case rsa(_RSA.Signing.PublicKey)
    case p256(P256.Signing.PublicKey)
    case p384(P384.Signing.PublicKey)
    case p521(P521.Signing.PublicKey)
    case ed25519(Curve25519.Signing.PublicKey)

    init(jwk: JSONObject) throws {
        func bytes(_ name: String) throws -> Data {
            guard let s = jwk.string(name), let d = Base64URL.decode(s), !d.isEmpty else { throw JOSEError.invalid("JWK member \(name) is missing or invalid") }
            return d
        }
        switch jwk.string("kty") {
        case "RSA":
            do { self = .rsa(try _RSA.Signing.PublicKey(n: try bytes("n"), e: try bytes("e"))) } catch let e as JOSEError { throw e } catch {
                throw JOSEError.invalid("Unusable RSA key (RSA keys must be at least 2048 bits)")
            }
        case "EC":
            let x = try bytes("x"), y = try bytes("y")
            let raw = x + y
            do {
                switch jwk.string("crv") {
                case "P-256": self = .p256(try P256.Signing.PublicKey(rawRepresentation: raw))
                case "P-384": self = .p384(try P384.Signing.PublicKey(rawRepresentation: raw))
                case "P-521": self = .p521(try P521.Signing.PublicKey(rawRepresentation: raw))
                default: throw JOSEError.notSupported("Unsupported EC curve \(jwk.string("crv") ?? "(none)")")
                }
            } catch let e as JOSEError { throw e } catch { throw JOSEError.invalid("Invalid EC public key") }
        case "OKP":
            guard jwk.string("crv") == "Ed25519" else { throw JOSEError.notSupported("Unsupported OKP curve \(jwk.string("crv") ?? "(none)")") }
            do { self = .ed25519(try Curve25519.Signing.PublicKey(rawRepresentation: try bytes("x"))) } catch let e as JOSEError { throw e } catch {
                throw JOSEError.invalid("Invalid Ed25519 public key")
            }
        default:
            throw JOSEError.notSupported("Unsupported key type \(jwk.string("kty") ?? "(none)")")
        }
    }

    /// Verifies `signature` over `input` with algorithm `alg`. A key of the wrong type for `alg` fails.
    func verify(alg: String, signature: Data, input: Data) -> Bool {
        switch (self, alg) {
        case (.rsa(let key), "RS256"): return rsa(key, signature, SHA256.hash(data: input), .insecurePKCS1v1_5)
        case (.rsa(let key), "RS384"): return rsa(key, signature, SHA384.hash(data: input), .insecurePKCS1v1_5)
        case (.rsa(let key), "RS512"): return rsa(key, signature, SHA512.hash(data: input), .insecurePKCS1v1_5)
        case (.rsa(let key), "PS256"): return rsa(key, signature, SHA256.hash(data: input), .PSS)
        case (.rsa(let key), "PS384"): return rsa(key, signature, SHA384.hash(data: input), .PSS)
        case (.rsa(let key), "PS512"): return rsa(key, signature, SHA512.hash(data: input), .PSS)
        case (.p256(let key), "ES256"):
            guard signature.count == 64, let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
            return key.isValidSignature(sig, for: SHA256.hash(data: input))
        case (.p384(let key), "ES384"):
            guard signature.count == 96, let sig = try? P384.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
            return key.isValidSignature(sig, for: SHA384.hash(data: input))
        case (.p521(let key), "ES512"):
            guard signature.count == 132, let sig = try? P521.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
            return key.isValidSignature(sig, for: SHA512.hash(data: input))
        case (.ed25519(let key), "EdDSA"), (.ed25519(let key), "Ed25519"):
            return key.isValidSignature(signature, for: input)
        default:
            return false
        }
    }

    private func rsa<D: Digest>(_ key: _RSA.Signing.PublicKey, _ signature: Data, _ digest: D, _ padding: _RSA.Signing.Padding) -> Bool {
        key.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: signature), for: digest, padding: padding)
    }
}

/// Whether a JWK can be used to verify a signature made with `alg` (its `kty`, `crv`, `use`, `alg` and `key_ops`).
func jwk(_ jwk: JSONObject, isUsableFor alg: String) -> Bool {
    if let use = jwk.string("use"), use != "sig" { return false }
    if let ops = jwk["key_ops"]?.stringArrayValue, !ops.contains("verify") { return false }
    if let a = jwk.string("alg"), a != alg { return false }
    let kty = jwk.string("kty"), crv = jwk.string("crv")
    switch alg {
    case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512": return kty == "RSA"
    case "ES256": return kty == "EC" && crv == "P-256"
    case "ES384": return kty == "EC" && crv == "P-384"
    case "ES512": return kty == "EC" && crv == "P-521"
    case "EdDSA", "Ed25519": return kty == "OKP" && crv == "Ed25519"
    default: return false
    }
}

/// RFC 7638 JWK SHA-256 thumbprint of a public key.
public func jwkThumbprint(_ jwk: JSONObject) -> String {
    let members: [String]
    switch jwk.string("kty") {
    case "EC": members = ["crv", "kty", "x", "y"]
    case "RSA": members = ["e", "kty", "n"]
    case "OKP": members = ["crv", "kty", "x"]
    default: members = []
    }
    let json = "{" + members.map { "\"\($0)\":\"\(jwk.string($0) ?? "")\"" }.joined(separator: ",") + "}"
    return Base64URL.encode(Data(SHA256.hash(data: Data(json.utf8))))
}

// MARK: - Key sets

/// A JSON Web Key Set fetched from a `jwks_uri`, cached, and fetched again when a token names a key it
/// does not hold (a rotation), at most once per cooldown — the behaviour of `jose`'s `createRemoteJWKSet`.
actor RemoteJWKSet {
    let url: URL
    private let http: HTTPClient
    private let cooldown: TimeInterval
    private let cacheMaxAge: TimeInterval
    private let now: @Sendable () -> Date
    private var keys: [JSONObject]?
    private var fetchedAt: Date?
    private var inflight: Task<[JSONObject], Error>?

    init(url: URL, http: HTTPClient, cooldown: TimeInterval = 30, cacheMaxAge: TimeInterval = 600, now: @escaping @Sendable () -> Date) {
        self.url = url
        self.http = http
        self.cooldown = cooldown
        self.cacheMaxAge = cacheMaxAge
        self.now = now
    }

    /// The keys that may have signed a token with this header.
    func candidates(for header: JSONObject) async throws -> [JSONObject] {
        guard let alg = header.string("alg") else { throw JOSEError.invalid("JWS header has no alg") }
        let kid = header.string("kid")
        func matching(_ keys: [JSONObject]) -> [JSONObject] {
            keys.filter { (kid == nil || $0.string("kid") == kid) && jwk($0, isUsableFor: alg) }
        }
        let fresh = fetchedAt.map { now().timeIntervalSince($0) < cacheMaxAge } ?? false
        if keys == nil || !fresh { _ = try await reload() }
        var found = matching(keys ?? [])
        if found.isEmpty, let at = fetchedAt, now().timeIntervalSince(at) >= cooldown {
            found = matching(try await reload())
        }
        if found.isEmpty { throw JOSEError.noMatchingKey }
        return found
    }

    private func reload() async throws -> [JSONObject] {
        if let inflight { return try await inflight.value }
        let task = Task { [http, url] () throws -> [JSONObject] in
            let res: HTTPResponse
            do { res = try await http.get(url, headers: ["accept": "application/json, application/jwk-set+json"]) } catch {
                throw JOSEError.jwksUnavailable("Could not fetch the JWKS at \(url.absoluteString): \(error.localizedDescription)")
            }
            guard res.isOK, let doc = try? JSONValue.parseObject(res.body), let list = doc["keys"]?.arrayValue else {
                throw JOSEError.jwksUnavailable("The JWKS at \(url.absoluteString) is not a JSON Web Key Set (HTTP \(res.status))")
            }
            return list.compactMap(\.objectValue)
        }
        inflight = task
        defer { inflight = nil }
        let fetched = try await task.value
        keys = fetched
        fetchedAt = now()
        return fetched
    }
}

// MARK: - Verifying JWTs

struct JWTVerifyOptions {
    var algorithms: [String]
    var issuer: String?
    /// The token's `aud` must contain one of these.
    var audience: [String]?
    var clockTolerance: TimeInterval = 0
    /// Refuse a token whose `iat` is older than this (seconds).
    var maxTokenAge: TimeInterval?
    var requiredClaims: [String] = []
    var now: Date
}

/// Verifies a compact JWS JWT's signature against `keys` and its registered claims, the way `jose`'s
/// `jwtVerify` does. Returns the protected header and the claims.
func verifyJWT(_ token: String, keys: RemoteJWKSet, options o: JWTVerifyOptions) async throws -> (header: JSONObject, claims: JSONObject) {
    let jws = try CompactJWS(token)
    guard let alg = jws.alg else { throw JOSEError.invalid("JWS header has no alg") }
    guard o.algorithms.contains(alg) else { throw JOSEError.algNotAllowed("\"alg\" (Algorithm) Header Parameter value not allowed") }
    if jws.header["crit"] != nil { throw JOSEError.notSupported("Extension Header Parameter in crit is not recognized") }
    if jws.header["b64"] != nil { throw JOSEError.notSupported("b64 is not supported") }

    let candidates = try await keys.candidates(for: jws.header)
    var verified = false
    for jwk in candidates {
        guard let key = try? VerificationKey(jwk: jwk) else { continue }
        if key.verify(alg: alg, signature: jws.signature, input: jws.signingInput) { verified = true; break }
    }
    guard verified else { throw JOSEError.signatureFailed }

    guard let claims = try? JSONValue.parseObject(jws.payload) else { throw JOSEError.invalid("JWT Claims Set must be a top-level JSON object") }
    try validateClaims(claims, options: o)
    return (jws.header, claims)
}

func validateClaims(_ claims: JSONObject, options o: JWTVerifyOptions) throws {
    for name in o.requiredClaims where claims[name] == nil {
        throw JOSEError.claimFailed(claim: name, "missing required \"\(name)\" claim")
    }
    if let issuer = o.issuer, claims.string("iss") != issuer {
        throw JOSEError.claimFailed(claim: "iss", "unexpected \"iss\" claim value")
    }
    if let audience = o.audience {
        let aud: [String] = claims["aud"]?.stringValue.map { [$0] } ?? claims["aud"]?.stringArrayValue ?? []
        if !aud.contains(where: audience.contains) { throw JOSEError.claimFailed(claim: "aud", "unexpected \"aud\" claim value") }
    }
    let now = o.now.timeIntervalSince1970.rounded(.down)
    let tol = o.clockTolerance
    if let iat = claims["iat"], iat.doubleValue == nil { throw JOSEError.claimFailed(claim: "iat", "\"iat\" claim must be a number") }
    if let nbf = claims["nbf"] {
        guard let v = nbf.doubleValue else { throw JOSEError.claimFailed(claim: "nbf", "\"nbf\" claim must be a number") }
        if v > now + tol { throw JOSEError.claimFailed(claim: "nbf", "\"nbf\" claim timestamp check failed") }
    }
    if let exp = claims["exp"] {
        guard let v = exp.doubleValue else { throw JOSEError.claimFailed(claim: "exp", "\"exp\" claim must be a number") }
        if v <= now - tol { throw JOSEError.expired(claim: "exp", "\"exp\" claim timestamp check failed") }
    }
    if let max = o.maxTokenAge {
        guard let iat = claims["iat"]?.doubleValue else { throw JOSEError.claimFailed(claim: "iat", "missing required \"iat\" claim") }
        let age = now - iat
        if age - tol > max { throw JOSEError.expired(claim: "iat", "\"iat\" claim timestamp check failed (too far in the past)") }
        if age < 0 - tol { throw JOSEError.claimFailed(claim: "iat", "\"iat\" claim timestamp check failed (it should be in the past)") }
    }
}

// MARK: - Signing (DPoP proofs)

/// Creates compact JWS tokens with a private key (DPoP proofs, and test fixtures).
public protocol JWSSigner: Sendable {
    /// The JWS `alg` this key signs with.
    var alg: String { get }
    /// The public key, as a JWK (no private members).
    var publicJWK: JSONObject { get }
    /// The JWS signature over `data` (for ECDSA, `r || s`).
    func sign(_ data: Data) throws -> Data
}

/// Signs `claims` as a compact JWS with `signer`, under `header` (its `alg` is set from the signer).
public func signJWS(header: JSONObject, claims: JSONObject, signer: any JWSSigner) throws -> String {
    var h = header
    h["alg"] = .string(signer.alg)
    let input = Base64URL.encode(try JSONValue.object(h).jsonData()) + "." + Base64URL.encode(try JSONValue.object(claims).jsonData())
    return input + "." + Base64URL.encode(try signer.sign(Data(input.utf8)))
}

/// An ES256 / ES384 / ES512 signer with a software key (CryptoKit / swift-crypto).
public struct SoftwareECSigner: JWSSigner {
    enum Key: @unchecked Sendable {
        case p256(P256.Signing.PrivateKey), p384(P384.Signing.PrivateKey), p521(P521.Signing.PrivateKey)
    }
    let key: Key
    public let alg: String

    /// A new key for `alg` (ES256, ES384 or ES512).
    public init(alg: String = "ES256") throws {
        switch alg {
        case "ES256": key = .p256(P256.Signing.PrivateKey())
        case "ES384": key = .p384(P384.Signing.PrivateKey())
        case "ES512": key = .p521(P521.Signing.PrivateKey())
        default: throw OIDCError.usage("Unsupported EC algorithm \(alg)")
        }
        self.alg = alg
    }

    /// A key restored from its raw private representation (``rawPrivateKey``).
    public init(alg: String, rawPrivateKey: Data) throws {
        switch alg {
        case "ES256": key = .p256(try P256.Signing.PrivateKey(rawRepresentation: rawPrivateKey))
        case "ES384": key = .p384(try P384.Signing.PrivateKey(rawRepresentation: rawPrivateKey))
        case "ES512": key = .p521(try P521.Signing.PrivateKey(rawRepresentation: rawPrivateKey))
        default: throw OIDCError.usage("Unsupported EC algorithm \(alg)")
        }
        self.alg = alg
    }

    /// The private key's raw bytes, for a store that keeps it (``KeychainKeyStore``).
    public var rawPrivateKey: Data {
        switch key {
        case .p256(let k): return k.rawRepresentation
        case .p384(let k): return k.rawRepresentation
        case .p521(let k): return k.rawRepresentation
        }
    }

    public var publicJWK: JSONObject {
        let (crv, raw): (String, Data)
        switch key {
        case .p256(let k): (crv, raw) = ("P-256", k.publicKey.rawRepresentation)
        case .p384(let k): (crv, raw) = ("P-384", k.publicKey.rawRepresentation)
        case .p521(let k): (crv, raw) = ("P-521", k.publicKey.rawRepresentation)
        }
        let half = raw.count / 2
        return ["kty": "EC", "crv": .string(crv), "x": .string(Base64URL.encode(raw.prefix(half))), "y": .string(Base64URL.encode(raw.suffix(half)))]
    }

    public func sign(_ data: Data) throws -> Data {
        switch key {
        case .p256(let k): return try k.signature(for: SHA256.hash(data: data)).rawRepresentation
        case .p384(let k): return try k.signature(for: SHA384.hash(data: data)).rawRepresentation
        case .p521(let k): return try k.signature(for: SHA512.hash(data: data)).rawRepresentation
        }
    }
}
