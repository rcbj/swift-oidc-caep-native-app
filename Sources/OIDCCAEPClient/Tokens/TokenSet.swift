// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation

/// The tokens one token endpoint response issued, with the claims of the ID token this client validated.
///
/// Stored as the token response's own JSON (snake_case), plus `expires_at`, `issued_at` and `claims`.
public struct TokenSet: Sendable, Equatable, Codable {
    public var accessToken: String
    /// `Bearer` or `DPoP`.
    public var tokenType: String
    public var refreshToken: String?
    public var idToken: String?
    public var scope: String?
    /// Epoch seconds when the access token expires.
    public var expiresAt: Int?
    /// Epoch seconds when the tokens were issued.
    public var issuedAt: Int?
    /// The validated ID token's claims. Only claims this client validated: an ID token is never decoded
    /// here unverified, because code that trusts `claims` (UserInfo's `sub` check, account keys) must not
    /// be handed claims nobody checked.
    public var claims: JSONObject?
    /// Every other member of the token response.
    public var additional: JSONObject

    private static let known: Set<String> = ["access_token", "token_type", "refresh_token", "id_token", "scope", "expires_in", "expires_at", "issued_at", "claims"]

    public init(accessToken: String, tokenType: String = "Bearer", refreshToken: String? = nil, idToken: String? = nil, scope: String? = nil,
                expiresAt: Int? = nil, issuedAt: Int? = nil, claims: JSONObject? = nil, additional: JSONObject = [:]) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.scope = scope
        self.expiresAt = expiresAt
        self.issuedAt = issuedAt
        self.claims = claims
        self.additional = additional
    }

    /// From a token endpoint response. `expires_in` becomes `expires_at`; the response cannot set
    /// `expires_at`, `issued_at` or `claims`.
    init(response: JSONObject, claims: JSONObject?, now: Date) {
        accessToken = response.string("access_token") ?? ""
        tokenType = response.string("token_type") ?? "Bearer"
        refreshToken = response.string("refresh_token")
        idToken = response.string("id_token")
        scope = response.string("scope")
        if let expiresIn = response["expires_in"].flatMap({ $0.doubleValue ?? $0.stringValue.flatMap(Double.init) }) {
            issuedAt = nowSeconds(now)
            expiresAt = nowSeconds(now) + Int(expiresIn)
        }
        self.claims = claims
        additional = response.filter { !Self.known.contains($0.key) }
    }

    /// The tokens are bound to a DPoP key (`token_type` DPoP).
    public var isDPoPBound: Bool { tokenType.caseInsensitiveCompare("DPoP") == .orderedSame }

    /// Seconds until the access token expires.
    public func expiresIn(now: Date = Date()) -> Int? {
        expiresAt.map { max(0, $0 - nowSeconds(now)) }
    }

    /// Skew to apply for early renewal, capped at half the token lifetime so that short-lived tokens are not
    /// considered expired the moment they are issued.
    public func effectiveSkew(_ skew: TimeInterval) -> TimeInterval {
        guard let issuedAt, let expiresAt else { return skew }
        return min(skew, Double(expiresAt - issuedAt) / 2)
    }

    /// Whether the access token has expired, or will within `skew` seconds (see ``effectiveSkew(_:)``).
    public func isExpired(skew: TimeInterval = 0, now: Date = Date()) -> Bool {
        guard let expiresAt else { return false }
        return Double(expiresAt) - effectiveSkew(skew) <= Double(nowSeconds(now))
    }

    /// The token set as stored: the response's members, `expires_at`, `issued_at` and `claims`.
    public var json: JSONObject {
        var o = additional
        o["access_token"] = .string(accessToken)
        o["token_type"] = .string(tokenType)
        if let refreshToken { o["refresh_token"] = .string(refreshToken) }
        if let idToken { o["id_token"] = .string(idToken) }
        if let scope { o["scope"] = .string(scope) }
        if let expiresAt { o["expires_at"] = JSONValue(expiresAt) }
        if let issuedAt { o["issued_at"] = JSONValue(issuedAt) }
        if let claims { o["claims"] = .object(claims) }
        return o
    }

    /// A token set as stored (``json``).
    public init(json o: JSONObject) throws {
        guard let access = o.string("access_token") else { throw OIDCError.validation("Stored tokens have no access_token") }
        self.init(accessToken: access, tokenType: o.string("token_type") ?? "Bearer", refreshToken: o.string("refresh_token"),
                  idToken: o.string("id_token"), scope: o.string("scope"), expiresAt: o["expires_at"]?.intValue,
                  issuedAt: o["issued_at"]?.intValue, claims: o["claims"]?.objectValue,
                  additional: o.filter { !Self.known.contains($0.key) })
    }

    public init(from decoder: Decoder) throws {
        let object = try JSONValue(from: decoder)
        guard let o = object.objectValue else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Not an object")) }
        try self.init(json: o)
    }

    public func encode(to encoder: Encoder) throws { try JSONValue.object(json).encode(to: encoder) }
}
