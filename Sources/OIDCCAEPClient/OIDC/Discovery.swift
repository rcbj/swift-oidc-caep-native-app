// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation

/// An OpenID Provider metadata document (OpenID Connect Discovery 1.0 §3), with typed accessors for the
/// members this library reads. ``raw`` holds every member.
public struct ProviderMetadata: Sendable, Equatable {
    public let raw: JSONObject

    public init(_ raw: JSONObject) { self.raw = raw }

    public subscript(key: String) -> JSONValue? { raw[key] }

    public var issuer: String { raw.string("issuer") ?? "" }
    public var authorizationEndpoint: String? { raw.string("authorization_endpoint") }
    public var tokenEndpoint: String? { raw.string("token_endpoint") }
    public var jwksURI: String? { raw.string("jwks_uri") }
    public var userinfoEndpoint: String? { raw.string("userinfo_endpoint") }
    public var endSessionEndpoint: String? { raw.string("end_session_endpoint") }
    public var revocationEndpoint: String? { raw.string("revocation_endpoint") }
    public var pushedAuthorizationRequestEndpoint: String? { raw.string("pushed_authorization_request_endpoint") }
    public var registrationEndpoint: String? { raw.string("registration_endpoint") }
    public var requirePushedAuthorizationRequests: Bool { raw["require_pushed_authorization_requests"]?.boolValue == true }
    public var authorizationResponseIssParameterSupported: Bool { raw["authorization_response_iss_parameter_supported"]?.boolValue == true }
    public var scopesSupported: [String]? { raw["scopes_supported"]?.stringArrayValue }
    public var idTokenSigningAlgValuesSupported: [String] { raw["id_token_signing_alg_values_supported"]?.stringArrayValue ?? [] }
    public var codeChallengeMethodsSupported: [String]? { raw["code_challenge_methods_supported"]?.stringArrayValue }
    public var tokenEndpointAuthMethodsSupported: [String]? { raw["token_endpoint_auth_methods_supported"]?.stringArrayValue }
    public var dpopSigningAlgValuesSupported: [String]? { raw["dpop_signing_alg_values_supported"]?.stringArrayValue }
}

/// The OpenID Connect Discovery 1.0 §4 URL: the well-known suffix appended to the issuer.
public func oidcDiscoveryURL(issuer: String) -> String {
    var s = issuer
    while s.hasSuffix("/") { s.removeLast() }
    return s + "/.well-known/openid-configuration"
}

/// RFC 8414 §3-style well-known URLs: the suffix inserted between host and path, then (when different)
/// appended OIDC-style, in preference order.
public func wellKnownURLs(issuer: String, suffix: String) -> [String] {
    guard let url = URL(string: issuer), let origin = originOf(url) else { return [] }
    var path = url.path
    while path.hasSuffix("/") { path.removeLast() }
    let inserted = "\(origin)/.well-known/\(suffix)\(path)"
    let appended = "\(origin)\(path)/.well-known/\(suffix)"
    return inserted == appended ? [inserted] : [inserted, appended]
}

private actor MetadataCache {
    static let shared = MetadataCache()
    private var entries: [String: (metadata: JSONObject, expiresAt: Date)] = [:]
    func get(_ key: String, now: Date) -> JSONObject? {
        guard let hit = entries[key], hit.expiresAt > now else { return nil }
        return hit.metadata
    }
    func set(_ key: String, _ metadata: JSONObject, expiresAt: Date) { entries[key] = (metadata, expiresAt) }
    func clear() { entries.removeAll() }
}

/// Clears the in-process metadata cache (mostly useful in tests).
public func clearDiscoveryCache() async { await MetadataCache.shared.clear() }

/// Fetches metadata from the first URL that answers 2xx and checks that its `issuer` matches exactly.
func fetchMetadata(urls: [String], expectedIssuer: String, http: HTTPClient, cacheTTL: TimeInterval, now: Date) async throws -> JSONObject {
    let cacheKey = urls.joined(separator: "|")
    if let hit = await MetadataCache.shared.get(cacheKey, now: now) { return hit }
    for (i, string) in urls.enumerated() {
        guard let url = URL(string: string) else { throw OIDCError.validation("Invalid metadata URL \(string)") }
        let res = try await http.get(url)
        if res.status == 404, i < urls.count - 1 { continue }
        guard let metadata = try readJSON(res)?.objectValue else { throw OIDCError.validation("Metadata at \(string) is not a JSON object") }
        // Discovery §4.3 / RFC 8414 §3.3: issuer MUST be identical to the one used to build the URL.
        guard metadata.string("issuer") == expectedIssuer else {
            throw OIDCError.validation("Issuer mismatch in \(string): expected \"\(expectedIssuer)\", got \"\(metadata.string("issuer") ?? "")\"", code: "issuer_mismatch")
        }
        await MetadataCache.shared.set(cacheKey, metadata, expiresAt: now.addingTimeInterval(cacheTTL))
        return metadata
    }
    throw OIDCError.validation("No metadata found for \(expectedIssuer)")
}

private let requiredOPMetadata = ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "response_types_supported",
                                  "subject_types_supported", "id_token_signing_alg_values_supported"]

/// Validates an OpenID Provider metadata document (OIDC Discovery 1.0 §3) for use by a code-flow RP.
/// When `expectedIssuer` is given, `issuer` must match it exactly (§4.3).
@discardableResult
public func validateOpenIDProviderMetadata(_ metadata: JSONObject, expectedIssuer: String? = nil) throws -> ProviderMetadata {
    let missing = requiredOPMetadata.filter { metadata[$0] == nil }
    if !missing.isEmpty {
        throw OIDCError.validation("OpenID Provider metadata is missing required fields: \(missing.joined(separator: ", "))")
    }
    if let expectedIssuer, metadata.string("issuer") != expectedIssuer {
        throw OIDCError.validation("Issuer mismatch: expected \"\(expectedIssuer)\", got \"\(metadata.string("issuer") ?? "")\"", code: "issuer_mismatch")
    }
    for key in ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "end_session_endpoint", "revocation_endpoint"] {
        guard let value = metadata[key] else { continue }
        guard let s = value.stringValue, let url = URL(string: s), url.scheme != nil, url.host != nil else {
            throw OIDCError.validation("OpenID Provider metadata \(key) is not a valid URL")
        }
        if key == "issuer", url.query != nil || url.fragment != nil {
            throw OIDCError.validation("issuer must not contain a query or fragment")
        }
    }
    guard metadata["response_types_supported"]?.stringArrayValue?.contains("code") == true else {
        throw OIDCError.validation("OpenID Provider does not support response_type=code")
    }
    guard metadata["id_token_signing_alg_values_supported"]?.arrayValue != nil else {
        throw OIDCError.validation("id_token_signing_alg_values_supported must be an array")
    }
    return ProviderMetadata(metadata)
}

/// Retrieves and validates OpenID Provider metadata from `<issuer>/.well-known/openid-configuration`.
public func discoverOpenIDProvider(issuer: String, transport: any HTTPTransport = URLSessionTransport(),
                                   timeout: TimeInterval = 10, cacheTTL: TimeInterval = 3600) async throws -> ProviderMetadata {
    let http = HTTPClient(transport: transport, timeout: timeout)
    let metadata = try await fetchMetadata(urls: [oidcDiscoveryURL(issuer: issuer)], expectedIssuer: issuer, http: http, cacheTTL: cacheTTL, now: Date())
    return try validateOpenIDProviderMetadata(metadata, expectedIssuer: issuer)
}

/// Retrieves and validates OpenID Provider metadata from its metadata URL
/// (`https://idp.example.com/.well-known/openid-configuration`), the form an app's configuration holds.
///
/// The document's `issuer` must be the one the URL was built from (Discovery §4.3), in either the OpenID
/// form (`<issuer>/.well-known/openid-configuration`) or the RFC 8414 form (well-known part inserted after
/// the host).
public func discoverOpenIDProvider(metadataURL: URL, transport: any HTTPTransport = URLSessionTransport(),
                                   timeout: TimeInterval = 10, cacheTTL: TimeInterval = 3600) async throws -> ProviderMetadata {
    let http = HTTPClient(transport: transport, timeout: timeout)
    let now = Date()
    let key = metadataURL.absoluteString
    var metadata = await MetadataCache.shared.get(key, now: now)
    if metadata == nil {
        let res = try await http.get(metadataURL)
        guard let doc = try readJSON(res)?.objectValue else { throw OIDCError.validation("Metadata at \(key) is not a JSON object") }
        metadata = doc
    }
    guard let metadata, let issuer = metadata.string("issuer") else {
        throw OIDCError.validation("OpenID Provider metadata is missing required fields: issuer")
    }
    let forms = [oidcDiscoveryURL(issuer: issuer)] + wellKnownURLs(issuer: issuer, suffix: "openid-configuration")
    guard forms.contains(key) else {
        throw OIDCError.validation("The metadata at \(key) names the issuer \"\(issuer)\", whose metadata is not at that URL", code: "issuer_mismatch")
    }
    let validated = try validateOpenIDProviderMetadata(metadata, expectedIssuer: issuer)
    await MetadataCache.shared.set(key, metadata, expiresAt: now.addingTimeInterval(cacheTTL))
    return validated
}

/// Retrieves SSF 1.0 transmitter metadata from `/.well-known/ssf-configuration` (RFC 8414-style path
/// insertion first, then the appended form).
public func discoverSSFTransmitter(issuer: String, transport: any HTTPTransport = URLSessionTransport(),
                                   timeout: TimeInterval = 10, cacheTTL: TimeInterval = 3600) async throws -> JSONObject {
    let http = HTTPClient(transport: transport, timeout: timeout)
    let metadata = try await fetchMetadata(urls: wellKnownURLs(issuer: issuer, suffix: "ssf-configuration"), expectedIssuer: issuer,
                                           http: http, cacheTTL: cacheTTL, now: Date())
    guard metadata.string("jwks_uri") != nil else { throw OIDCError.validation("SSF transmitter metadata has no jwks_uri") }
    return metadata
}
