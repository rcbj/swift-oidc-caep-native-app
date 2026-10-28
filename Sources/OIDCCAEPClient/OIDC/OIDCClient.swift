// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Crypto
import Foundation

/// Pushed Authorization Requests (RFC 9126).
public enum PARMode: String, Sendable, Codable {
    /// Used when the provider advertises a PAR endpoint (and required when it sets
    /// `require_pushed_authorization_requests`).
    case auto
    /// Always; fails when the provider has no PAR endpoint.
    case always
    /// Never; fails when the provider requires PAR.
    case never
}

/// DPoP (RFC 9449) settings.
public struct DPoPOptions: Sendable {
    /// Where the key is kept. Default: memory (a new key every launch).
    public var keyStore: any DPoPKeyStore
    /// The proof algorithm. Default: the first of the store's algorithms the provider accepts.
    public var alg: String?
    /// A key to use as is, instead of one from `keyStore`.
    public var key: DPoPKey?

    public init(keyStore: any DPoPKeyStore = MemoryKeyStore(), alg: String? = nil, key: DPoPKey? = nil) {
        self.keyStore = keyStore
        self.alg = alg
        self.key = key
    }
}

/// How an ``OIDCClient`` behaves. Only `clientID` is required; every default is the safe one.
public struct OIDCClientOptions: Sendable {
    /// A PUBLIC client (`token_endpoint_auth_method` none). There is no client secret.
    public var clientID: String
    /// Where the provider returns the authorization response. For a native app (RFC 8252): a private-use
    /// scheme such as `com.example.app:/callback`, or loopback `http://127.0.0.1:port/…` (which needs an
    /// app-supplied ``WebAuthenticator`` listening on that port; ``SystemWebAuthenticator`` cannot receive it).
    public var redirectURI: URL?
    public var postLogoutRedirectURI: URL?
    /// Default `openid profile email`, plus `offline_access` when the provider supports it.
    public var scope: String?
    /// RFC 8707 resource indicators: audience-restrict the tokens.
    public var resource: [String]
    /// The ID token `alg` this client accepts (one only). Default RS256.
    public var idTokenSignedResponseAlg: String
    public var par: PARMode
    /// DPoP (RFC 9449). Off when nil.
    public var dpop: DPoPOptions?
    /// With DPoP on, refuse a token response whose `token_type` is Bearer. Default: true when `dpop` is set.
    /// A refresh of DPoP-bound tokens never accepts Bearer, whatever this says.
    public var requireDPoP: Bool?
    /// The only `alg` a signed UserInfo response may use. Default: any asymmetric algorithm.
    public var userinfoSignedResponseAlg: String?
    /// Where state, nonce and the PKCE verifier wait for the callback.
    public var transactionStore: any TransactionStore
    /// How long an authorization request stays redeemable (seconds).
    public var transactionTTL: TimeInterval
    /// Refuse ID tokens whose `iat` is older than this (seconds; 0 for no limit).
    public var maxIDTokenAge: TimeInterval
    /// When `acr_values` were requested, require the ID token's `acr` to be one of them.
    public var enforceACR: Bool
    /// Require `auth_time` in every ID token.
    public var requireAuthTime: Bool
    /// Allow non-TLS endpoints other than loopback. Never in production.
    public var allowInsecureRequests: Bool
    /// Allowed clock skew (seconds).
    public var clockTolerance: TimeInterval
    /// Per-request timeout (seconds).
    public var httpTimeout: TimeInterval
    /// How long discovered metadata is cached (seconds).
    public var discoveryCacheTTL: TimeInterval
    public var transport: any HTTPTransport
    /// The clock (for tests).
    public var now: @Sendable () -> Date

    public init(clientID: String, redirectURI: URL? = nil, postLogoutRedirectURI: URL? = nil, scope: String? = nil,
                resource: [String] = [], idTokenSignedResponseAlg: String = "RS256", par: PARMode = .auto,
                dpop: DPoPOptions? = nil, requireDPoP: Bool? = nil, userinfoSignedResponseAlg: String? = nil,
                transactionStore: any TransactionStore = MemoryTransactionStore(), transactionTTL: TimeInterval = 600,
                maxIDTokenAge: TimeInterval = 600, enforceACR: Bool = true, requireAuthTime: Bool = false,
                allowInsecureRequests: Bool = false, clockTolerance: TimeInterval = 30, httpTimeout: TimeInterval = 10,
                discoveryCacheTTL: TimeInterval = 3600, transport: any HTTPTransport = URLSessionTransport(),
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.postLogoutRedirectURI = postLogoutRedirectURI
        self.scope = scope
        self.resource = resource
        self.idTokenSignedResponseAlg = idTokenSignedResponseAlg
        self.par = par
        self.dpop = dpop
        self.requireDPoP = requireDPoP
        self.userinfoSignedResponseAlg = userinfoSignedResponseAlg
        self.transactionStore = transactionStore
        self.transactionTTL = transactionTTL
        self.maxIDTokenAge = maxIDTokenAge
        self.enforceACR = enforceACR
        self.requireAuthTime = requireAuthTime
        self.allowInsecureRequests = allowInsecureRequests
        self.clockTolerance = clockTolerance
        self.httpTimeout = httpTimeout
        self.discoveryCacheTTL = discoveryCacheTTL
        self.transport = transport
        self.now = now
    }
}

/// Options for one authorization request.
public struct AuthorizationRequestOptions: Sendable {
    public var scope: String?
    public var redirectURI: URL?
    /// `none`, `login`, `consent`, `select_account` (space-separated for several).
    public var prompt: String?
    public var maxAge: Int?
    public var loginHint: String?
    /// A previously issued ID token naming the account (and session) meant.
    public var idTokenHint: String?
    /// Space-separated; with `enforceACR`, the ID token's `acr` must be one of these.
    public var acrValues: String?
    /// The callback refuses an ID token about anybody else (`account_mismatch`): when a request names an
    /// account, a sign-in as another person must not be taken for it.
    public var expectedSub: String?
    /// Kept with the transaction and handed back by ``OIDCClient/completeAuthorization(callbackURL:)``
    /// (and on an OAuth error as ``OIDCError/context``).
    public var context: JSONValue?
    /// Further parameters (`claims`, `ui_locales` …). They may not replace the ones the client sets.
    public var extraParameters: [String: String]

    public init(scope: String? = nil, redirectURI: URL? = nil, prompt: String? = nil, maxAge: Int? = nil, loginHint: String? = nil,
                idTokenHint: String? = nil, acrValues: String? = nil, expectedSub: String? = nil, context: JSONValue? = nil,
                extraParameters: [String: String] = [:]) {
        self.scope = scope
        self.redirectURI = redirectURI
        self.prompt = prompt
        self.maxAge = maxAge
        self.loginHint = loginHint
        self.idTokenHint = idTokenHint
        self.acrValues = acrValues
        self.expectedSub = expectedSub
        self.context = context
        self.extraParameters = extraParameters
    }
}

/// An authorization request, ready to open in the system browser.
public struct AuthorizationRequest: Sendable {
    public let url: URL
    public let state: String
}

/// A completed sign-in.
public struct AuthorizationResult: Sendable {
    public let tokenSet: TokenSet
    public let context: JSONValue?
}

/// An RP-Initiated Logout request.
public struct EndSessionRequest: Sendable {
    public let url: URL
    public let state: String
}

/// Which protections are in effect, for display and audit.
public struct SecurityFeatures: Sendable {
    public let pkce: String
    public let state: String
    public let nonce: Bool
    public let issuerIdentification: String
    public let par: Bool
    /// The DPoP algorithm and key thumbprint, when DPoP is on.
    public let dpop: (alg: String, jkt: String, extractable: Bool)?
    public let resourceIndicators: [String]
    public let tlsEnforced: Bool
    public let idToken: String
}

/// Authorization request parameters `extraParameters` may not set: the client sets them, and the callback relies on them.
private let reservedAuthorizationParameters: Set<String> = ["response_type", "response_mode", "client_id", "redirect_uri", "state",
    "nonce", "code_challenge", "code_challenge_method", "dpop_jkt", "request", "request_uri", "resource"]

/// JWT `typ` values that mark a token as something other than an ID token. Presenting one of them as an
/// ID token is token confusion (RFC 8725 §3.11), so it is refused even when its signature verifies.
private let notIDTokenTypes: Set<String> = ["at+jwt", "application/at+jwt", "logout+jwt", "secevent+jwt", "dpop+jwt",
    "token-introspection+jwt", "software-statement+jwt", "jwt-bearer"]

/// Parameters that must never arrive at a code-flow redirect URI (tokens in the front channel).
private let frontChannelTokens = ["access_token", "id_token", "refresh_token", "token_type"]

/// Endpoints whose URLs must use TLS.
private let tlsEndpoints = ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint",
    "revocation_endpoint", "end_session_endpoint", "pushed_authorization_request_endpoint", "registration_endpoint"]

/// OpenID Connect Relying Party for a PUBLIC client (a native app): Authorization Code + PKCE, with the
/// protections RFC 9700 (OAuth 2.0 Security Best Current Practice), RFC 8252 (OAuth 2.0 for Native Apps)
/// and OpenID Connect call for. It holds no client secret and supports no confidential-client authentication.
///
/// Create one with ``discover(metadataURL:options:)``, ``discover(issuer:options:)`` or
/// ``fromMetadata(_:options:)``.
public final class OIDCClient: Sendable {
    public let metadata: ProviderMetadata
    public let options: OIDCClientOptions
    /// The DPoP key, when DPoP is on.
    public let dpopKey: DPoPKey?
    /// Whether authorization requests are pushed (PAR).
    public let usesPAR: Bool
    /// The scope requested when a request names none.
    public let scope: String
    /// Every token set the token endpoint issues (sign-in and refresh).
    public let tokenEvents = EventHub<TokenSet>()

    let http: HTTPClient
    let jwks: RemoteJWKSet
    private let dpopExtractable: Bool
    // RFC 9449 §8 and §9: the authorization server's nonce and a resource server's are separate, even when
    // both are on one origin (UserInfo at the OP), so each has its own cache.
    private let asNonces = DPoPNonceCache()
    private let rsNonces = DPoPNonceCache()
    private let usedStates = Locked<[String: Date]>([:])

    public var issuer: String { metadata.issuer }
    public var clientID: String { options.clientID }
    var now: Date { options.now() }

    // MARK: Creating a client

    /// Loads the provider's metadata from its metadata URL (`…/.well-known/openid-configuration`) and creates a client.
    public static func discover(metadataURL: URL, options: OIDCClientOptions) async throws -> OIDCClient {
        let metadata = try await discoverOpenIDProvider(metadataURL: metadataURL, transport: options.transport,
                                                        timeout: options.httpTimeout, cacheTTL: options.discoveryCacheTTL)
        return try await OIDCClient(metadata: metadata, options: options)
    }

    /// Loads the provider's metadata from `<issuer>/.well-known/openid-configuration` and creates a client.
    public static func discover(issuer: String, options: OIDCClientOptions) async throws -> OIDCClient {
        let metadata = try await discoverOpenIDProvider(issuer: issuer, transport: options.transport,
                                                        timeout: options.httpTimeout, cacheTTL: options.discoveryCacheTTL)
        return try await OIDCClient(metadata: metadata, options: options)
    }

    /// Creates a client from a provider metadata document already in hand (validated as if discovered).
    public static func fromMetadata(_ metadata: JSONObject, options: OIDCClientOptions) async throws -> OIDCClient {
        try await OIDCClient(metadata: try validateOpenIDProviderMetadata(metadata), options: options)
    }

    private init(metadata m: ProviderMetadata, options o: OIDCClientOptions) async throws {
        guard !o.clientID.isEmpty else { throw OIDCError.usage("clientID is required") }
        // TLS for every endpoint and redirect URI (RFC 9700 §2.6, OIDC Core §16.17), loopback excepted. A
        // native app's redirect URI may also be a private-use scheme (RFC 8252 §7.1).
        if !o.allowInsecureRequests {
            for key in tlsEndpoints {
                if let value = m[key]?.stringValue, !isSecureURL(value) {
                    throw OIDCError.validation("\(key) must use https: \(value)", code: "insecure_endpoint")
                }
            }
        }
        for (name, uri) in [("redirectURI", o.redirectURI), ("postLogoutRedirectURI", o.postLogoutRedirectURI)] {
            if let uri, !o.allowInsecureRequests, !isAcceptableRedirect(uri) {
                throw OIDCError.validation("\(name) must use https, loopback http, or a private-use scheme such as com.example.app:/callback: \(uri.absoluteString)",
                                           code: "insecure_redirect_uri")
            }
        }
        // PKCE downgrade protection (RFC 9700 §2.1.1): refuse an OP that says it does not do S256.
        if let methods = m.codeChallengeMethodsSupported, !methods.contains("S256") {
            throw OIDCError.validation("The OP does not support PKCE with S256", code: "pkce_not_supported")
        }
        // A public client authenticates with "none" only.
        if let methods = m.tokenEndpointAuthMethodsSupported, !methods.contains("none") {
            throw OIDCError.validation("The OP does not accept public clients (token_endpoint_auth_method \"none\")", code: "public_client_not_supported")
        }
        guard supportedIDTokenAlgorithms.contains(o.idTokenSignedResponseAlg) else {
            throw OIDCError.validation("ID token alg \(o.idTokenSignedResponseAlg) cannot be verified by this library (supported: \(supportedIDTokenAlgorithms.joined(separator: ", ")))")
        }
        guard m.idTokenSigningAlgValuesSupported.contains(o.idTokenSignedResponseAlg) else {
            throw OIDCError.validation("OP does not support ID token alg \(o.idTokenSignedResponseAlg)")
        }

        // PAR (RFC 9126).
        let parEndpoint = m.pushedAuthorizationRequestEndpoint
        if m.requirePushedAuthorizationRequests, parEndpoint == nil {
            throw OIDCError.validation("The OP requires PAR but advertises no pushed_authorization_request_endpoint")
        }
        if o.par == .always, parEndpoint == nil { throw OIDCError.validation("par is .always but the OP has no pushed_authorization_request_endpoint") }
        if o.par == .never, m.requirePushedAuthorizationRequests { throw OIDCError.validation("The OP requires PAR (require_pushed_authorization_requests)") }
        usesPAR = parEndpoint != nil && (o.par != .never || m.requirePushedAuthorizationRequests)

        // DPoP (RFC 9449).
        if let d = o.dpop {
            if let key = d.key {
                dpopKey = key
                dpopExtractable = true
            } else {
                let offered = m.dpopSigningAlgValuesSupported
                let creatable = d.keyStore.supportedAlgorithms
                guard let alg = d.alg ?? (offered.map { list in creatable.first(where: list.contains) } ?? creatable.first) else {
                    throw OIDCError.validation("The OP accepts no DPoP algorithm this key store creates (\(creatable.joined(separator: ", ")))", code: "dpop_not_supported")
                }
                dpopKey = try await DPoPKey.loadOrCreate(store: d.keyStore, alg: alg)
                dpopExtractable = d.keyStore.isExtractable
            }
        } else {
            dpopKey = nil
            dpopExtractable = false
        }

        guard let jwksString = m.jwksURI, let jwksURL = URL(string: jwksString) else { throw OIDCError.validation("jwks_uri is not a URL") }
        let http = HTTPClient(transport: o.transport, timeout: o.httpTimeout)
        self.http = http
        jwks = RemoteJWKSet(url: jwksURL, http: http, now: o.now)
        scope = o.scope ?? "openid profile email" + ((m.scopesSupported?.contains("offline_access") ?? false) ? " offline_access" : "")
        metadata = m
        options = o
        await o.transactionStore.sweep(createdBefore: o.now().addingTimeInterval(-o.transactionTTL))
    }

    /// Which security features are active, for display and audit.
    public var securityFeatures: SecurityFeatures {
        SecurityFeatures(
            pkce: "S256",
            state: "random 256-bit, single use, expiring, issuer-bound, constant-time compared",
            nonce: true,
            issuerIdentification: metadata.authorizationResponseIssParameterSupported ? "required (RFC 9207)" : "checked when present (RFC 9207)",
            par: usesPAR,
            dpop: dpopKey.map { ($0.alg, $0.thumbprint, dpopExtractable) },
            resourceIndicators: options.resource,
            tlsEnforced: !options.allowInsecureRequests,
            idToken: "alg \(options.idTokenSignedResponseAlg), typ checked, iat ≤ \(Int(options.maxIDTokenAge))s, at_hash, acr \(options.enforceACR ? "enforced" : "not enforced")")
    }

    // MARK: Authorization request

    /// Starts an Authorization Code + PKCE (S256) sign-in. The transaction (state, nonce, code verifier) is
    /// kept in the transaction store under its `state`, and ``completeAuthorization(callbackURL:)`` consumes it.
    /// Uses PAR when enabled, and binds the authorization code to the DPoP key (`dpop_jkt`).
    ///
    /// Open the returned URL in the system browser (``WebAuthenticator``), or use ``authorize(using:_:)``,
    /// which does both steps.
    public func createAuthorizationRequest(_ opts: AuthorizationRequestOptions = .init()) async throws -> AuthorizationRequest {
        guard let redirectURI = opts.redirectURI ?? options.redirectURI else { throw OIDCError.usage("redirectURI is required") }
        if !options.allowInsecureRequests, !isAcceptableRedirect(redirectURI) {
            throw OIDCError.validation("redirectURI must use https, loopback http, or a private-use scheme: \(redirectURI.absoluteString)", code: "insecure_redirect_uri")
        }
        let reserved = opts.extraParameters.keys.filter(reservedAuthorizationParameters.contains).sorted()
        if !reserved.isEmpty { throw OIDCError.usage("extraParameters may not set \(reserved.joined(separator: ", ")): the client sets them itself") }

        let state = randomToken()
        let nonce = randomToken()
        let codeVerifier = generateCodeVerifier()
        let scope = opts.scope ?? self.scope
        var prompt = opts.prompt
        // offline_access requires prompt=consent per OIDC Core §11 unless the caller chose otherwise.
        if prompt == nil, scope.split(separator: " ").contains("offline_access") { prompt = "consent" }

        var query = FormParameters()
        query.append("response_type", "code")
        query.append("client_id", options.clientID)
        query.append("redirect_uri", redirectURI.absoluteString)
        query.append("scope", scope)
        query.append("state", state)
        query.append("nonce", nonce)
        query.append("code_challenge", codeChallengeS256(codeVerifier))
        query.append("code_challenge_method", "S256")
        if let prompt { query.append("prompt", prompt) }
        if let maxAge = opts.maxAge { query.append("max_age", String(maxAge)) }
        if let v = opts.loginHint { query.append("login_hint", v) }
        if let v = opts.idTokenHint { query.append("id_token_hint", v) }
        if let v = opts.acrValues { query.append("acr_values", v) }
        for (k, v) in opts.extraParameters.sorted(by: { $0.key < $1.key }) { query.set(k, v) }
        if let jkt = dpopKey?.thumbprint { query.append("dpop_jkt", jkt) }
        for r in options.resource { query.append("resource", r) }

        guard let authorizationEndpoint = metadata.authorizationEndpoint.flatMap(URL.init(string:)) else {
            throw OIDCError.validation("authorization_endpoint is not a URL")
        }
        let url: URL
        if usesPAR, let parEndpoint = metadata.pushedAuthorizationRequestEndpoint.flatMap(URL.init(string:)) {
            let par = try await postForm(parEndpoint, query)
            guard let requestURI = par.string("request_uri") else {
                throw OIDCError.validation("PAR response has no request_uri", code: "invalid_par_response")
            }
            url = authorizationEndpoint.appendingQuery(FormParameters([("client_id", options.clientID), ("request_uri", requestURI)]))
        } else {
            url = authorizationEndpoint.appendingQuery(query)
        }

        let transaction = AuthorizationTransaction(state: state, nonce: nonce, codeVerifier: codeVerifier, redirectURI: redirectURI.absoluteString,
                                                   maxAge: opts.maxAge, acrValues: opts.acrValues, expectedSub: opts.expectedSub, context: opts.context,
                                                   issuer: metadata.issuer, clientID: options.clientID, createdAt: now.timeIntervalSince1970)
        await options.transactionStore.set(state, try JSONEncoder().encode(transaction))
        return AuthorizationRequest(url: url, state: state)
    }

    /// Completes the sign-in from the redirect URL: consumes the stored transaction for the returned `state`
    /// (single use), checks it, redeems the code with the PKCE verifier (and a DPoP proof) and validates the
    /// ID token. An error the OP returned (e.g. `login_required` to a `prompt=none` request) is thrown as an
    /// ``OIDCError`` of kind `.oauth` carrying the request's context.
    public func completeAuthorization(callbackURL: URL) async throws -> AuthorizationResult {
        try await completeAuthorization(parameters: Self.responseParameters(callbackURL))
    }

    /// ``completeAuthorization(callbackURL:)`` with the response's parameters.
    public func completeAuthorization(parameters p: FormParameters) async throws -> AuthorizationResult {
        // Front-channel token injection: a code-flow redirect never carries tokens (RFC 9700 §4.5, §2.1.2).
        let injected = frontChannelTokens.filter(p.has)
        if !injected.isEmpty {
            throw OIDCError.validation("Authorization response carries \(injected.joined(separator: ", ")); tokens never arrive in the front channel", code: "front_channel_token")
        }
        // Parameter pollution: every response parameter appears at most once (RFC 6749 §3.1).
        for name in p.names where p.getAll(name).count > 1 {
            throw OIDCError.validation("Authorization response repeats \"\(name)\"", code: "duplicate_parameter")
        }

        // STATE: look up and REMOVE the transaction (single use), then check it thoroughly.
        guard let returned = p.get("state"), !returned.isEmpty else {
            throw OIDCError.validation("state missing from authorization response", code: "state_missing")
        }
        guard let data = await options.transactionStore.take(returned),
              let transaction = try? JSONDecoder().decode(AuthorizationTransaction.self, from: data) else {
            let reused = usedStates.withLock { $0[returned] != nil }
            throw OIDCError.validation(reused ? "This authorization response was already used (state replayed)"
                                       : "No sign-in in progress for this state (unknown, already used, or from another app instance)",
                                       code: reused ? "state_reused" : "state_mismatch")
        }
        rememberState(returned)
        guard timingSafeEqual(returned, transaction.state) else { throw OIDCError.validation("state mismatch", code: "state_mismatch") }
        if now.timeIntervalSince1970 - transaction.createdAt > options.transactionTTL {
            throw OIDCError.validation("The sign-in took longer than \(Int(options.transactionTTL))s; start again", code: "transaction_expired")
        }
        // The transaction belongs to this OP and this client (mix-up defence when several are configured).
        guard transaction.issuer == metadata.issuer, transaction.clientID == options.clientID else {
            throw OIDCError.validation("This sign-in was started with a different identity provider or client", code: "issuer_mismatch")
        }

        // RFC 9207 issuer identification.
        if let iss = p.get("iss"), iss != metadata.issuer {
            throw OIDCError.validation("iss mismatch in authorization response: \(iss)", code: "issuer_mismatch")
        }
        if p.get("iss") == nil, metadata.authorizationResponseIssParameterSupported {
            throw OIDCError.validation("iss missing from authorization response", code: "issuer_missing")
        }
        if let error = p.get("error"), !error.isEmpty {
            var e = OIDCError.oauth(error: error, description: p.get("error_description"), uri: p.get("error_uri"))
            e.context = transaction.context
            throw e
        }
        guard let code = p.get("code"), !code.isEmpty else { throw OIDCError.validation("code missing from authorization response", code: "code_missing") }

        var body = FormParameters()
        body.append("grant_type", "authorization_code")
        body.append("code", code)
        body.append("redirect_uri", transaction.redirectURI)
        body.append("code_verifier", transaction.codeVerifier)
        for r in options.resource { body.append("resource", r) }
        let tokens = try await tokenRequest(body)
        guard let idToken = tokens.string("id_token") else { throw OIDCError.validation("Token response did not include an id_token", code: "id_token_missing") }

        let claims = try await validateIDToken(idToken, nonce: transaction.nonce, maxAge: transaction.maxAge,
                                               acrValues: transaction.acrValues, accessToken: tokens.string("access_token"))
        // The request named an account; a sign-in as somebody else is not that account.
        if let expected = transaction.expectedSub, claims.string("sub") != expected {
            await revokeQuietly(accessToken: tokens.string("access_token"), refreshToken: tokens.string("refresh_token"))
            throw OIDCError.validation("The identity provider signed in a different account from the one requested", code: "account_mismatch",
                                       response: ["expected": .string(expected), "sub": claims["sub"] ?? .null])
        }
        let tokenSet = TokenSet(response: tokens, claims: claims, now: now)
        tokenEvents.emit(tokenSet)
        return AuthorizationResult(tokenSet: tokenSet, context: transaction.context)
    }

    private func rememberState(_ state: String) {
        let at = now
        let cutoff = at.addingTimeInterval(-options.transactionTTL)
        usedStates.withLock { used in
            used[state] = at
            if used.count > 1000 || used.values.contains(where: { $0 < cutoff }) {
                used = used.filter { $0.value >= cutoff }
                while used.count > 1000, let oldest = used.min(by: { $0.value < $1.value }) { used[oldest.key] = nil }
            }
        }
    }

    /// The parameters of an authorization response: the query, plus any fragment, so that tokens injected
    /// in a fragment are caught.
    static func responseParameters(_ url: URL) -> FormParameters {
        var all = FormParameters()
        if let c = URLComponents(url: url, resolvingAgainstBaseURL: false) {
            for item in FormParameters(parsing: c.percentEncodedQuery ?? "") { all.append(item.name, item.value) }
            if let fragment = c.percentEncodedFragment, !fragment.isEmpty {
                for item in FormParameters(parsing: fragment) { all.append(item.name, item.value) }
            }
        }
        return all
    }

    // MARK: Refresh

    /// Refresh Token grant (OIDC Core §12). Keeps the previous refresh token when the OP doesn't rotate it,
    /// validates any new ID token against the previous claims (§12.2), and sends a DPoP proof with the same
    /// key when the tokens are DPoP-bound.
    public func refresh(_ previous: TokenSet, scope: String? = nil) async throws -> TokenSet {
        try await refresh(refreshToken: previous.refreshToken, previous: previous, previousClaims: previous.claims, scope: scope)
    }

    /// Refresh with a bare refresh token. Without `previousClaims` (the claims of the ID token from the
    /// original sign-in), a response that carries an ID token is refused.
    public func refresh(refreshToken: String, previousClaims: JSONObject? = nil, scope: String? = nil) async throws -> TokenSet {
        try await refresh(refreshToken: refreshToken, previous: nil, previousClaims: previousClaims, scope: scope)
    }

    private func refresh(refreshToken: String?, previous: TokenSet?, previousClaims: JSONObject?, scope: String?) async throws -> TokenSet {
        guard let refreshToken, !refreshToken.isEmpty else { throw OIDCError(kind: .general, "No refresh_token available", code: "no_refresh_token") }
        var body = FormParameters()
        body.append("grant_type", "refresh_token")
        body.append("refresh_token", refreshToken)
        if let scope { body.append("scope", scope) }
        for r in options.resource { body.append("resource", r) }

        var tokens = try await tokenRequest(body)
        let tokenType = tokens.string("token_type") ?? ""
        // A DPoP-bound grant must stay bound: a Bearer reply to it is a downgrade (RFC 9449 §5).
        if previous?.isDPoPBound == true, tokenType.caseInsensitiveCompare("DPoP") != .orderedSame {
            throw OIDCError.validation("Refresh of DPoP-bound tokens returned token_type \(tokenType)", code: "dpop_downgrade")
        }
        var claims = previousClaims
        if let idToken = tokens.string("id_token") {
            guard let previousClaims else {
                throw OIDCError.validation("The refresh returned an ID token, and there are no previous ID token claims to check it against (OIDC Core §12.2); pass a TokenSet or previousClaims",
                                           code: "invalid_id_token")
            }
            claims = try await validateIDToken(idToken, accessToken: tokens.string("access_token"), previousClaims: previousClaims)
        }
        if tokens["refresh_token"] == nil { tokens["refresh_token"] = .string(refreshToken) }
        if tokens["id_token"] == nil, let id = previous?.idToken { tokens["id_token"] = .string(id) }
        let tokenSet = TokenSet(response: tokens, claims: claims, now: now)
        tokenEvents.emit(tokenSet)
        return tokenSet
    }

    // MARK: Calling protected resources (UserInfo, SSF, APIs)

    /// The `authorization` (and `dpop`) headers for a request to a resource server. A DPoP-bound token gets
    /// a fresh proof bound to this method, URL and token.
    public func resourceHeaders(accessToken: String, tokenType: String = "Bearer", method: String = "GET", url: URL,
                                nonce: String? = nil) throws -> [String: String] {
        if tokenType.caseInsensitiveCompare("DPoP") == .orderedSame {
            guard let dpopKey else { throw OIDCError(kind: .general, "A DPoP-bound token needs the DPoP key it was issued to", code: "dpop_key_missing") }
            return [
                "authorization": "DPoP \(accessToken)",
                "dpop": try dpopKey.proof(method: method, url: url, nonce: nonce ?? rsNonces.get(url), accessToken: accessToken, now: now),
            ]
        }
        return ["authorization": "Bearer \(accessToken)"]
    }

    /// ``resourceHeaders(accessToken:tokenType:method:url:nonce:)`` for a token set.
    public func resourceHeaders(for tokenSet: TokenSet, method: String = "GET", url: URL, nonce: String? = nil) throws -> [String: String] {
        try resourceHeaders(accessToken: tokenSet.accessToken, tokenType: tokenSet.tokenType, method: method, url: url, nonce: nonce)
    }

    /// Sends a request to a protected resource with an access token, retrying once when the resource
    /// server asks for a DPoP nonce (RFC 9449 §9).
    public func fetchResource(_ tokenSet: TokenSet, url: URL, method: String = "GET", headers: [String: String] = [:], body: Data? = nil) async throws -> HTTPResponse {
        func send(_ nonce: String?) async throws -> HTTPResponse {
            var h = headers
            for (k, v) in try resourceHeaders(for: tokenSet, method: method, url: url, nonce: nonce) { h[k] = v }
            return try await http.send(HTTPRequest(url: url, method: method, headers: h, body: body))
        }
        var res = try await send(nil)
        let nonce = rsNonces.update(url, res)
        if wantsDPoPNonce(res) {
            res = try await send(nonce)
            rsNonces.update(url, res)
        }
        return res
    }

    /// Calls the UserInfo endpoint (OIDC Core §5.3). The response must be about the person the ID token is
    /// about (§5.3.2): its `sub` is checked against `expectedSub`, or else the token set's ID token `sub`.
    public func userinfo(_ tokenSet: TokenSet, expectedSub: String? = nil) async throws -> JSONObject {
        guard let expected = expectedSub ?? tokenSet.claims?.string("sub") else {
            throw OIDCError.validation("UserInfo needs the ID token sub to check the response against (OIDC Core §5.3.2): pass a TokenSet with an ID token, or expectedSub",
                                       code: "sub_mismatch")
        }
        guard let endpoint = metadata.userinfoEndpoint.flatMap(URL.init(string:)) else { throw OIDCError(kind: .general, "OP has no userinfo_endpoint") }
        let res = try await fetchResource(tokenSet, url: endpoint, headers: ["accept": "application/json, application/jwt"])
        if res.status == 401 {
            let www = res.header("www-authenticate") ?? ""
            let error = www.range(of: "error=\"([^\"]+)\"", options: .regularExpression).map { String(www[$0].dropFirst(7).dropLast()) } ?? "invalid_token"
            throw OIDCError.oauth(error: error, description: www, status: 401)
        }
        let claims: JSONObject
        if (res.header("content-type") ?? "").contains("application/jwt") {
            do {
                claims = try await verifyJWT(res.text.trimmingCharacters(in: .whitespacesAndNewlines), keys: jwks, options: JWTVerifyOptions(
                    algorithms: options.userinfoSignedResponseAlg.map { [$0] } ?? asymmetricJWSAlgorithms,
                    issuer: metadata.issuer, audience: [options.clientID], clockTolerance: options.clockTolerance, now: now)).claims
            } catch let e as JOSEError {
                throw OIDCError.validation("UserInfo response validation failed: \(e)", code: "invalid_userinfo")
            }
        } else {
            guard let object = try readJSON(res)?.objectValue else {
                throw OIDCError.validation("UserInfo response is not a JSON object", code: "invalid_userinfo")
            }
            claims = object
        }
        guard claims.string("sub") == expected else { throw OIDCError.validation("UserInfo sub does not match ID token sub", code: "sub_mismatch") }
        return claims
    }

    /// Token revocation (RFC 7009), as a public client. Returns false when the OP has no revocation endpoint.
    @discardableResult
    public func revoke(_ token: String, hint: String? = nil) async throws -> Bool {
        guard let endpoint = metadata.revocationEndpoint.flatMap(URL.init(string:)), !token.isEmpty else { return false }
        var body = FormParameters()
        body.append("token", token)
        body.append("client_id", options.clientID)
        if let hint { body.append("token_type_hint", hint) }
        let res = try await http.send(HTTPRequest(url: endpoint, method: "POST",
                                                  headers: ["content-type": "application/x-www-form-urlencoded", "accept": "application/json"],
                                                  body: Data(body.encoded.utf8)))
        if !res.isOK { _ = try readJSON(res) }
        return true
    }

    /// Revokes a token set's refresh and access tokens, ignoring failures.
    func revokeQuietly(accessToken: String?, refreshToken: String?) async {
        async let r: Void = { if let refreshToken { _ = try? await self.revoke(refreshToken, hint: "refresh_token") } }()
        async let a: Void = { if let accessToken { _ = try? await self.revoke(accessToken, hint: "access_token") } }()
        _ = await (r, a)
    }

    // MARK: Logout

    /// Builds an RP-Initiated Logout 1.0 request with a fresh `state`, kept for
    /// ``completeEndSession(callbackURL:)``. Returns nil when the OP has no end_session_endpoint.
    /// `context` is kept with the state and handed back when the logout completes.
    public func createEndSessionRequest(idTokenHint: String? = nil, postLogoutRedirectURI: URL? = nil, logoutHint: String? = nil,
                                        context: JSONValue? = nil) async throws -> EndSessionRequest? {
        guard let endpoint = metadata.endSessionEndpoint.flatMap(URL.init(string:)) else { return nil }
        let state = randomToken()
        let redirect = postLogoutRedirectURI ?? options.postLogoutRedirectURI
        if let redirect, !options.allowInsecureRequests, !isAcceptableRedirect(redirect) {
            throw OIDCError.validation("postLogoutRedirectURI must use https, loopback http, or a private-use scheme: \(redirect.absoluteString)", code: "insecure_redirect_uri")
        }
        var params = FormParameters()
        if let idTokenHint, !idTokenHint.isEmpty { params.append("id_token_hint", idTokenHint) }
        if let redirect { params.append("post_logout_redirect_uri", redirect.absoluteString) }
        params.append("client_id", options.clientID)
        if let logoutHint, !logoutHint.isEmpty { params.append("logout_hint", logoutHint) }
        if redirect != nil {
            params.append("state", state)
            let held = LogoutTransaction(state: state, context: context, createdAt: now.timeIntervalSince1970)
            await options.transactionStore.set("logout:\(state)", try JSONEncoder().encode(held))
        }
        return EndSessionRequest(url: endpoint.appendingQuery(params), state: state)
    }

    /// Checks the `state` the OP returned to the post-logout redirect URI, and returns the context the
    /// logout request was created with. Throws when the state is missing, unknown, reused or expired.
    @discardableResult
    public func completeEndSession(callbackURL: URL) async throws -> JSONValue? {
        guard let returned = Self.responseParameters(callbackURL).get("state"), !returned.isEmpty else {
            throw OIDCError.validation("state missing from logout response", code: "state_missing")
        }
        guard let data = await options.transactionStore.take("logout:\(returned)"),
              let held = try? JSONDecoder().decode(LogoutTransaction.self, from: data), timingSafeEqual(returned, held.state) else {
            throw OIDCError.validation("Unknown or already-used logout state", code: "state_mismatch")
        }
        if now.timeIntervalSince1970 - held.createdAt > options.transactionTTL {
            throw OIDCError.validation("The logout took too long", code: "transaction_expired")
        }
        return held.context
    }

    // MARK: ID token validation (OIDC Core §3.1.3.7, §12.2; RFC 8725)

    /// Validates an ID token and returns its claims.
    public func validateIDToken(_ idToken: String, nonce: String? = nil, maxAge: Int? = nil, acrValues: String? = nil,
                                accessToken: String? = nil, previousClaims: JSONObject? = nil) async throws -> JSONObject {
        let expectedAlg = options.idTokenSignedResponseAlg
        let header: JSONObject
        do { header = try CompactJWS(idToken).header } catch {
            throw OIDCError.validation("ID token is not a valid JWS", code: "invalid_id_token")
        }
        guard header.string("alg") == expectedAlg else {
            throw OIDCError.validation("Unexpected ID token alg \(header.string("alg") ?? "(none)"); expected \(expectedAlg)", code: "invalid_id_token")
        }
        if let typ = header["typ"], notIDTokenTypes.contains((typ.stringValue ?? typ.jsonString()).lowercased()) {
            throw OIDCError.validation("A \"\(typ.stringValue ?? typ.jsonString())\" token is not an ID token", code: "invalid_id_token")
        }
        if header["crit"] != nil {
            throw OIDCError.validation("ID token has critical header parameters this client does not understand", code: "invalid_id_token")
        }

        let claims: JSONObject
        do {
            claims = try await verifyJWT(idToken, keys: jwks, options: JWTVerifyOptions(
                algorithms: [expectedAlg], issuer: metadata.issuer, audience: [options.clientID], clockTolerance: options.clockTolerance,
                maxTokenAge: options.maxIDTokenAge > 0 ? options.maxIDTokenAge : nil, requiredClaims: ["iss", "sub", "aud", "exp", "iat"], now: now)).claims
        } catch let e as JOSEError {
            throw OIDCError.validation("ID token validation failed: \(e)", code: "invalid_id_token")
        }

        let aud: [JSONValue] = claims["aud"]?.arrayValue ?? [claims["aud"] ?? .null]
        if aud.count > 1, claims["azp"] == nil { throw OIDCError.validation("ID token has multiple audiences but no azp", code: "invalid_id_token") }
        if let azp = claims["azp"], azp.stringValue != options.clientID { throw OIDCError.validation("ID token azp does not match client_id", code: "invalid_id_token") }
        if let nonce, !timingSafeEqual(claims.string("nonce") ?? "", nonce) {
            throw OIDCError.validation("ID token nonce mismatch", code: "nonce_mismatch")
        }
        if maxAge != nil || options.requireAuthTime, claims["auth_time"]?.doubleValue == nil {
            throw OIDCError.validation("ID token has no auth_time", code: "invalid_id_token")
        }
        if let maxAge, let authTime = claims["auth_time"]?.doubleValue,
           authTime + Double(maxAge) + options.clockTolerance < Double(nowSeconds(now)) {
            throw OIDCError.validation("auth_time is older than max_age; re-authentication required", code: "max_age_exceeded")
        }
        if let acrValues, !acrValues.isEmpty, options.enforceACR {
            let wanted = acrValues.split(separator: " ").map(String.init)
            if !wanted.contains(claims.string("acr") ?? "\u{0}") {
                throw OIDCError.validation("ID token acr \"\(claims.string("acr") ?? "(none)")\" is not one of the requested acr_values (\(acrValues))", code: "acr_mismatch")
            }
        }
        if let accessToken, let atHash = claims["at_hash"], atHash.stringValue != tokenHash(accessToken, alg: expectedAlg) {
            throw OIDCError.validation("ID token at_hash does not match access token", code: "invalid_id_token")
        }
        if let previous = previousClaims {
            // OIDC Core §12.2: iss, sub and azp the same (azp absent if it was absent), aud the same.
            for claim in ["iss", "sub", "azp"] where claims[claim] != previous[claim] {
                throw OIDCError.validation("Refreshed ID token \(claim) changed", code: "invalid_id_token")
            }
            func audOf(_ v: JSONValue?) -> [String] {
                Array(Set(v?.stringValue.map { [$0] } ?? v?.stringArrayValue ?? [])).sorted()
            }
            if audOf(claims["aud"]) != audOf(previous["aud"]) {
                throw OIDCError.validation("Refreshed ID token aud changed", code: "invalid_id_token")
            }
            // §12.2 lets a refreshed ID token leave auth_time out; one it carries must be the original time.
            if let was = previous["auth_time"], let is_ = claims["auth_time"], was != is_ {
                throw OIDCError.validation("Refreshed ID token auth_time changed", code: "invalid_id_token")
            }
        }
        return claims
    }

    // MARK: Internals

    /// POSTs a form to an authorization-server endpoint as this public client, with a DPoP proof when
    /// enabled, retrying once when the AS demands a DPoP nonce (RFC 9449 §8).
    func postForm(_ endpoint: URL, _ form: FormParameters) async throws -> JSONObject {
        var form = form
        form.set("client_id", options.clientID)
        let body = Data(form.encoded.utf8)
        func send(_ nonce: String?) async throws -> HTTPResponse {
            var headers = ["content-type": "application/x-www-form-urlencoded", "accept": "application/json"]
            if let dpopKey { headers["dpop"] = try dpopKey.proof(method: "POST", url: endpoint, nonce: nonce ?? asNonces.get(endpoint), now: now) }
            return try await http.send(HTTPRequest(url: endpoint, method: "POST", headers: headers, body: body))
        }
        var res = try await send(nil)
        let nonce = asNonces.update(endpoint, res)
        if dpopKey != nil, res.status == 400, nonce != nil,
           res.text.range(of: "\"error\"\\s*:\\s*\"use_dpop_nonce\"", options: .regularExpression) != nil {
            res = try await send(nonce)
            asNonces.update(endpoint, res)
        }
        guard let object = try readJSON(res)?.objectValue else {
            throw OIDCError.validation("Expected a JSON object from \(endpoint.absoluteString)")
        }
        return object
    }

    private func tokenRequest(_ form: FormParameters) async throws -> JSONObject {
        guard let endpoint = metadata.tokenEndpoint.flatMap(URL.init(string:)) else { throw OIDCError.validation("token_endpoint is not a URL") }
        var tokens = try await postForm(endpoint, form)
        guard tokens.string("access_token")?.isEmpty == false else {
            throw OIDCError.validation("Token response missing access_token", code: "invalid_token_response")
        }
        let type = tokens.string("token_type") ?? ""
        let isDPoP = type.caseInsensitiveCompare("DPoP") == .orderedSame
        guard isDPoP || type.caseInsensitiveCompare("Bearer") == .orderedSame else {
            throw OIDCError.validation("Unsupported token_type \(type)", code: "invalid_token_response")
        }
        if isDPoP, dpopKey == nil { throw OIDCError.validation("The OP issued a DPoP-bound token but DPoP is not enabled", code: "invalid_token_response") }
        if dpopKey != nil, options.requireDPoP ?? true, !isDPoP {
            throw OIDCError.validation("DPoP is required, and the OP issued token_type \(type)", code: "dpop_downgrade")
        }
        if let e = tokens["expires_in"] {
            let n = e.doubleValue ?? e.stringValue.flatMap(Double.init)
            guard let n, n.isFinite, n >= 0 else { throw OIDCError.validation("Invalid expires_in \(e.jsonString())", code: "invalid_token_response") }
        }
        // expires_at, issued_at and claims are this client's own fields, computed from what it validated.
        for key in ["expires_at", "issued_at", "claims"] { tokens[key] = nil }
        return tokens
    }
}

/// at_hash: left-most half of the hash of the ASCII value, base64url encoded (OIDC Core §3.1.3.6).
func tokenHash(_ value: String, alg: String) -> String {
    let data = Data(value.utf8)
    let digest: Data
    switch alg == "EdDSA" || alg == "Ed25519" ? "512" : String(alg.suffix(3)) {
    case "384": digest = Data(SHA384.hash(data: data))
    case "512": digest = Data(SHA512.hash(data: data))
    default: digest = Data(SHA256.hash(data: data))
    }
    return Base64URL.encode(digest.prefix(digest.count / 2))
}

// MARK: - PKCE

/// RFC 7636 §4.1: 43–128 characters; 32 random bytes are 43 base64url characters.
public func generateCodeVerifier() -> String { randomToken(bytes: 32) }

/// RFC 7636 §4.2 S256 transformation.
public func codeChallengeS256(_ verifier: String) -> String { Base64URL.encode(sha256(verifier)) }
