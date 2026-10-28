// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// A strict in-memory OpenID Provider and SSF transmitter, injected as the library's HTTPTransport. It
// enforces public clients, PKCE, PAR, and DPoP (proof signature, htm/htu/ath, key binding, nonces), and
// keeps a poll stream of SETs with acknowledgements.

import Crypto
import _CryptoExtras
import Foundation
@testable import OIDCCAEPClient

let ISSUER = "https://op.example.test"
let CLIENT_ID = "native-demo"
let REDIRECT = URL(string: "net.example.app:/callback")!
let POST_LOGOUT = URL(string: "net.example.app:/logged-out")!

struct IssuedCode {
    var clientID: String, redirectURI: String, challenge: String, nonce: String?, jkt: String?, scope: String, sub: String
}

struct Grant { var sub: String; var jkt: String?; var scope: String; var sid: String }

actor StubOP: HTTPTransport {
    // Settings a test may change.
    var idTokenAlg = "ES256"
    var signer: any JWSSigner = try! SoftwareECSigner(alg: "ES256")
    var rsaKey: _RSA.Signing.PrivateKey?
    var metadataOverrides: JSONObject = [:]
    var metadataRemovals: Set<String> = []
    var sub = "user-1"
    var email = "alice@example.test"
    var emailVerified = true
    var sid = "sid-1"
    var expiresIn = 300
    var issueRefreshTokens = true
    var rotateRefreshTokens = true
    var forceTokenType: String?
    var requireDPoPNonce = false
    var dpopNonce = "nonce-1"
    var authorizeError: String?
    var mutateIDToken: (@Sendable (inout JSONObject) -> Void)?
    var refreshIDToken = true
    var userinfoSub: String?
    var tokenDelay: UInt64 = 0

    // What happened.
    private(set) var tokenRequests = 0
    private(set) var refreshRequests = 0
    private(set) var revoked: [String] = []
    private(set) var parRequests: [FormParameters] = []
    private(set) var lastAuthorizeParams = FormParameters()
    private(set) var acks: [String] = []
    private(set) var setErrs: JSONObject = [:]
    private(set) var subjectsAdded: [JSONObject] = []
    private(set) var streamDeletes = 0

    private var codes: [String: IssuedCode] = [:]
    private var parRequestsByURI: [String: FormParameters] = [:]
    private var refreshTokens: [String: Grant] = [:]
    private var accessTokens: [String: Grant] = [:]
    private var streams: [String: JSONObject] = [:]
    private var queued: [(jti: String, token: String)] = []

    // SSF
    var ssfSigner: any JWSSigner = try! SoftwareECSigner(alg: "ES256")
    let ssfKid = "ssf-1"

    func configure(_ body: (isolated StubOP) -> Void) { body(self) }
    func setMutator(_ m: (@Sendable (inout JSONObject) -> Void)?) { mutateIDToken = m }

    func useRSA(alg: String) throws {
        rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        idTokenAlg = alg
    }

    var metadata: JSONObject {
        var m: JSONObject = [
            "issuer": .string(ISSUER),
            "authorization_endpoint": .string("\(ISSUER)/authorize"),
            "token_endpoint": .string("\(ISSUER)/token"),
            "jwks_uri": .string("\(ISSUER)/jwks"),
            "userinfo_endpoint": .string("\(ISSUER)/userinfo"),
            "revocation_endpoint": .string("\(ISSUER)/revoke"),
            "end_session_endpoint": .string("\(ISSUER)/logout"),
            "pushed_authorization_request_endpoint": .string("\(ISSUER)/par"),
            "registration_endpoint": .string("\(ISSUER)/register"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "PS256", "ES256"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
            "authorization_response_iss_parameter_supported": true,
        ]
        m.merge(metadataOverrides) { _, b in b }
        for k in metadataRemovals { m[k] = nil }
        return m
    }

    var jwks: JSONObject {
        var keys: [JSONValue] = []
        if let rsaKey {
            let der = rsaKey.publicKey.derRepresentation
            let (n, e) = rsaComponents(der)
            keys.append(["kty": "RSA", "kid": "rsa-1", "n": .string(Base64URL.encode(n)), "e": .string(Base64URL.encode(e))])
        }
        var ec = signer.publicJWK
        ec["kid"] = "ec-1"
        keys.append(.object(ec))
        return ["keys": .array(keys)]
    }

    // MARK: Signing

    func signIDToken(_ claims: JSONObject) throws -> String {
        if let rsaKey, idTokenAlg.hasPrefix("RS") || idTokenAlg.hasPrefix("PS") {
            let header: JSONObject = ["alg": .string(idTokenAlg), "kid": "rsa-1", "typ": "JWT"]
            let input = Base64URL.encode(try JSONValue.object(header).jsonData()) + "." + Base64URL.encode(try JSONValue.object(claims).jsonData())
            let digest = SHA256.hash(data: Data(input.utf8))
            let sig = try rsaKey.signature(for: digest, padding: idTokenAlg.hasPrefix("PS") ? .PSS : .insecurePKCS1v1_5)
            return input + "." + Base64URL.encode(sig.rawRepresentation)
        }
        return try signJWS(header: ["kid": "ec-1", "typ": "JWT"], claims: claims, signer: signer)
    }

    func makeSET(type: String, payload: JSONObject = [:], subId: JSONObject? = nil, aud: String = CLIENT_ID, iat: Int? = nil,
                 jti: String = UUID().uuidString, typ: String = "secevent+jwt", signer: (any JWSSigner)? = nil, extraEvents: JSONObject = [:]) throws -> String {
        var claims: JSONObject = ["iss": .string(ISSUER), "aud": .string(aud), "iat": JSONValue(iat ?? Int(Date().timeIntervalSince1970)), "jti": .string(jti)]
        var events: JSONObject = [type: .object(payload)]
        events.merge(extraEvents) { _, b in b }
        claims["events"] = .object(events)
        if let subId { claims["sub_id"] = .object(subId) }
        return try signJWS(header: ["kid": .string(ssfKid), "typ": .string(typ)], claims: claims, signer: signer ?? ssfSigner)
    }

    @discardableResult
    func queueSET(type: String, payload: JSONObject = [:], subId: JSONObject? = nil, jti: String = UUID().uuidString, token: String? = nil) throws -> String {
        let t = try token ?? makeSET(type: type, payload: payload, subId: subId, jti: jti)
        queued.append((jti, t))
        return jti
    }

    var queuedCount: Int { queued.count }

    // MARK: The browser's part

    /// What the browser does: follows the authorization request and returns the redirect it ends at.
    func authorize(_ url: URL) throws -> URL {
        var p = OIDCClient.responseParameters(url)
        if let uri = p.get("request_uri") {
            guard let pushed = parRequestsByURI.removeValue(forKey: uri) else { throw StubError("unknown request_uri") }
            guard pushed.get("client_id") == p.get("client_id") else { throw StubError("client_id differs from PAR") }
            p = pushed
        }
        lastAuthorizeParams = p
        guard p.get("response_type") == "code", p.get("code_challenge_method") == "S256", let challenge = p.get("code_challenge"),
              let redirect = p.get("redirect_uri"), let clientID = p.get("client_id") else { throw StubError("bad authorization request") }
        var out = FormParameters()
        if let authorizeError {
            out.append("error", authorizeError)
        } else {
            let code = randomToken()
            codes[code] = IssuedCode(clientID: clientID, redirectURI: redirect, challenge: challenge, nonce: p.get("nonce"), jkt: p.get("dpop_jkt"),
                                     scope: p.get("scope") ?? "openid", sub: sub)
            out.append("code", code)
        }
        if let state = p.get("state") { out.append("state", state) }
        out.append("iss", ISSUER)
        return URL(string: redirect + "?" + out.encoded)!
    }

    // MARK: HTTP

    func send(_ request: HTTPRequest, timeout: TimeInterval) async throws -> HTTPResponse {
        let url = request.url
        let path = url.path
        func json(_ v: JSONValue, _ status: Int = 200, _ headers: [String: String] = [:]) throws -> HTTPResponse {
            var h = headers
            h["content-type"] = "application/json"
            return HTTPResponse(url: url, status: status, headers: h, body: try v.jsonData())
        }
        func oauthError(_ error: String, _ status: Int = 400, _ headers: [String: String] = [:]) throws -> HTTPResponse {
            try json(["error": .string(error)], status, headers)
        }
        let form = FormParameters(parsing: String(decoding: request.body ?? Data(), as: UTF8.self))
        let body = request.body.flatMap { try? JSONValue.parseObject($0) } ?? [:]

        switch (request.method, path) {
        case ("GET", "/.well-known/openid-configuration"): return try json(.object(metadata))
        case ("GET", "/jwks"): return try json(.object(jwks))
        case ("GET", "/.well-known/ssf-configuration"):
            return try json([
                "issuer": .string(ISSUER), "jwks_uri": .string("\(ISSUER)/ssf/jwks"),
                "configuration_endpoint": .string("\(ISSUER)/ssf/streams"), "status_endpoint": .string("\(ISSUER)/ssf/status"),
                "add_subject_endpoint": .string("\(ISSUER)/ssf/subjects:add"), "remove_subject_endpoint": .string("\(ISSUER)/ssf/subjects:remove"),
                "verification_endpoint": .string("\(ISSUER)/ssf/verify"), "delivery_methods_supported": .array([.string(Delivery.poll)]),
            ])
        case ("GET", "/ssf/jwks"):
            var k = ssfSigner.publicJWK
            k["kid"] = .string(ssfKid)
            return try json(["keys": [.object(k)]])
        case ("POST", "/par"):
            guard form.get("client_id") == CLIENT_ID else { return try oauthError("invalid_client", 401) }
            if let failure = try checkDPoP(request, htm: "POST", accessToken: nil) { return failure }
            parRequests.append(form)
            let uri = "urn:ietf:params:oauth:request_uri:\(randomToken())"
            parRequestsByURI[uri] = form
            return try json(["request_uri": .string(uri), "expires_in": 60], 201)
        case ("POST", "/token"):
            tokenRequests += 1
            if tokenDelay > 0 { try await Task.sleep(nanoseconds: tokenDelay) }
            guard form.get("client_id") == CLIENT_ID else { return try oauthError("invalid_client", 401) }
            if let failure = try checkDPoP(request, htm: "POST", accessToken: nil) { return failure }
            let jkt = try request.headers["dpop"].map { try proofJkt($0) }
            switch form.get("grant_type") {
            case "authorization_code":
                guard let code = form.get("code"), let issued = codes.removeValue(forKey: code) else { return try oauthError("invalid_grant") }
                guard issued.redirectURI == form.get("redirect_uri"), let verifier = form.get("code_verifier"),
                      codeChallengeS256(verifier) == issued.challenge else { return try oauthError("invalid_grant") }
                if let bound = issued.jkt, bound != jkt { return try oauthError("invalid_dpop_proof") }
                return try json(.object(issueTokens(sub: issued.sub, nonce: issued.nonce, jkt: jkt, scope: issued.scope, withIDToken: true)))
            case "refresh_token":
                refreshRequests += 1
                guard let rt = form.get("refresh_token"), let grant = refreshTokens[rt] else { return try oauthError("invalid_grant") }
                if grant.jkt != nil, grant.jkt != jkt { return try oauthError("invalid_dpop_proof") }
                if rotateRefreshTokens { refreshTokens[rt] = nil }
                var out = try issueTokens(sub: grant.sub, nonce: nil, jkt: grant.jkt, scope: grant.scope, withIDToken: refreshIDToken)
                if !rotateRefreshTokens { out["refresh_token"] = nil }
                return try json(.object(out))
            default:
                return try oauthError("unsupported_grant_type")
            }
        case ("GET", "/userinfo"):
            guard let (token, grant) = try authorizedGrant(request) else {
                return HTTPResponse(url: url, status: 401, headers: ["www-authenticate": "DPoP error=\"invalid_token\""])
            }
            _ = token
            return try json(["sub": .string(userinfoSub ?? grant.sub), "email": .string(email), "name": "Alice Example"])
        case ("POST", "/revoke"):
            if let t = form.get("token") { revoked.append(t); refreshTokens[t] = nil; accessTokens[t] = nil }
            return HTTPResponse(url: url, status: 200)
        case ("POST", "/register"):
            var reg = body
            reg["client_id"] = .string(CLIENT_ID)
            return try json(.object(reg), 201)
        case ("POST", "/ssf/streams"):
            guard try authorizedGrant(request) != nil else { return try oauthError("invalid_token", 401) }
            let id = "stream-\(streams.count + 1)"
            var s = body
            s["stream_id"] = .string(id)
            s["aud"] = .string(CLIENT_ID)
            s["delivery"] = ["method": .string(Delivery.poll), "endpoint_url": .string("\(ISSUER)/ssf/poll/\(id)")]
            streams[id] = s
            return try json(.object(s), 201)
        case ("GET", "/ssf/streams"):
            guard try authorizedGrant(request) != nil else { return try oauthError("invalid_token", 401) }
            if let id = FormParameters(parsing: url.query ?? "").get("stream_id") {
                guard let s = streams[id] else { return try oauthError("not_found", 404) }
                return try json(.object(s))
            }
            return try json(.array(streams.values.map(JSONValue.object)))
        case ("PATCH", "/ssf/streams"):
            guard let id = body.string("stream_id"), var s = streams[id] else { return try oauthError("not_found", 404) }
            s.merge(body) { _, b in b }
            streams[id] = s
            return try json(.object(s))
        case ("DELETE", "/ssf/streams"):
            streamDeletes += 1
            streams[FormParameters(parsing: url.query ?? "").get("stream_id") ?? ""] = nil
            return HTTPResponse(url: url, status: 204)
        case ("POST", "/ssf/subjects:add"):
            if let s = body["subject"]?.objectValue { subjectsAdded.append(s) }
            return HTTPResponse(url: url, status: 200)
        case ("POST", "/ssf/verify"):
            let state = body.string("state") ?? ""
            let t = try makeSET(type: SSF.verification, payload: ["state": .string(state)], subId: Subject.opaque(body.string("stream_id") ?? ""))
            queued.append((UUID().uuidString, t))
            return HTTPResponse(url: url, status: 204)
        default:
            if request.method == "POST", path.hasPrefix("/ssf/poll/") {
                guard try authorizedGrant(request) != nil else { return try oauthError("invalid_token", 401) }
                let ack = body["ack"]?.stringArrayValue ?? []
                acks += ack
                for (k, v) in body["setErrs"]?.objectValue ?? [:] { setErrs[k] = v }
                queued.removeAll { ack.contains($0.jti) || body["setErrs"]?.objectValue?[$0.jti] != nil }
                let max = body["maxEvents"]?.intValue ?? 25
                let batch = queued.prefix(max)
                var sets: JSONObject = [:]
                for q in batch { sets[q.jti] = .string(q.token) }
                return try json(["sets": .object(sets), "moreAvailable": .bool(queued.count > batch.count)])
            }
            return HTTPResponse(url: url, status: 404)
        }
    }

    private func issueTokens(sub: String, nonce: String?, jkt: String?, scope: String, withIDToken: Bool) throws -> JSONObject {
        let access = randomToken()
        let grant = Grant(sub: sub, jkt: jkt, scope: scope, sid: sid)
        accessTokens[access] = grant
        var out: JSONObject = ["access_token": .string(access), "token_type": .string(forceTokenType ?? (jkt != nil ? "DPoP" : "Bearer")),
                               "expires_in": JSONValue(expiresIn), "scope": .string(scope)]
        if issueRefreshTokens {
            let rt = randomToken()
            refreshTokens[rt] = grant
            out["refresh_token"] = .string(rt)
        }
        if withIDToken {
            let now = Int(Date().timeIntervalSince1970)
            var claims: JSONObject = ["iss": .string(ISSUER), "sub": .string(sub), "aud": .string(CLIENT_ID), "iat": JSONValue(now),
                                      "exp": JSONValue(now + 300), "auth_time": JSONValue(1_700_000_000), "sid": .string(sid),
                                      "email": .string(email), "email_verified": .bool(emailVerified), "preferred_username": "alice",
                                      "at_hash": .string(tokenHash(access, alg: idTokenAlg))]
            if let nonce { claims["nonce"] = .string(nonce) }
            mutateIDToken?(&claims)
            out["id_token"] = .string(try signIDToken(claims))
        }
        return out
    }

    /// The grant behind the request's access token, with its DPoP proof checked when it is DPoP-bound.
    private func authorizedGrant(_ request: HTTPRequest) throws -> (String, Grant)? {
        let auth = request.headers["authorization"] ?? ""
        let parts = auth.split(separator: " ", maxSplits: 1).map(String.init)
        guard parts.count == 2, let grant = accessTokens[parts[1]] else { return nil }
        if let jkt = grant.jkt {
            guard parts[0] == "DPoP", let proof = request.headers["dpop"], try proofJkt(proof) == jkt else { return nil }
            let claims = try verifyProof(proof, htm: request.method, url: request.url)
            guard claims.string("ath") == Base64URL.encode(sha256(parts[1])) else { return nil }
        } else if parts[0] != "Bearer" { return nil }
        return (parts[1], grant)
    }

    private func checkDPoP(_ request: HTTPRequest, htm: String, accessToken: String?) throws -> HTTPResponse? {
        guard let proof = request.headers["dpop"] else { return nil }
        let claims = try verifyProof(proof, htm: htm, url: request.url)
        if requireDPoPNonce, claims.string("nonce") != dpopNonce {
            return HTTPResponse(url: request.url, status: 400, headers: ["dpop-nonce": dpopNonce, "content-type": "application/json"],
                                body: Data(#"{"error":"use_dpop_nonce"}"#.utf8))
        }
        return nil
    }

    private func verifyProof(_ proof: String, htm: String, url: URL) throws -> JSONObject {
        let jws = try CompactJWS(proof)
        guard jws.header.string("typ") == "dpop+jwt", let jwk = jws.header["jwk"]?.objectValue else { throw StubError("bad proof header") }
        let key = try VerificationKey(jwk: jwk)
        guard key.verify(alg: jws.alg ?? "", signature: jws.signature, input: jws.signingInput) else { throw StubError("bad proof signature") }
        let claims = try JSONValue.parseObject(jws.payload)
        guard claims.string("htm") == htm, claims.string("htu") == htuOf(url), claims.string("jti") != nil else { throw StubError("bad proof claims") }
        return claims
    }

    private func proofJkt(_ proof: String) throws -> String {
        guard let jwk = try CompactJWS(proof).header["jwk"]?.objectValue else { throw StubError("no jwk") }
        return jwkThumbprint(jwk)
    }
}

struct StubError: Error, CustomStringConvertible {
    let description: String
    init(_ d: String) { description = d }
}

/// The modulus and exponent of a DER SubjectPublicKeyInfo RSA key (enough ASN.1 for the test keys).
func rsaComponents(_ spki: Data) -> (Data, Data) {
    var bytes = [UInt8](spki)
    func readLength(_ i: inout Int) -> Int {
        let first = Int(bytes[i]); i += 1
        if first < 0x80 { return first }
        var len = 0
        for _ in 0..<(first & 0x7f) { len = len << 8 | Int(bytes[i]); i += 1 }
        return len
    }
    func readInteger(_ i: inout Int) -> Data {
        precondition(bytes[i] == 0x02); i += 1
        let len = readLength(&i)
        var v = Data(bytes[i..<(i + len)]); i += len
        while v.first == 0 && v.count > 1 { v.removeFirst() }
        return v
    }
    // SPKI: SEQ { SEQ { alg }, BIT STRING { SEQ { n, e } } }
    var i = 0
    i += 1; _ = readLength(&i)                 // outer SEQ
    i += 1; let algLen = readLength(&i); i += algLen
    i += 1; _ = readLength(&i); i += 1         // BIT STRING, unused-bits byte
    i += 1; _ = readLength(&i)                 // inner SEQ
    let n = readInteger(&i)
    let e = readInteger(&i)
    bytes = []
    return (n, e)
}

/// A WebAuthenticator that plays the browser against the stub.
struct StubBrowser: WebAuthenticator {
    let op: StubOP
    func authenticate(url: URL, callback: URL) async throws -> URL {
        if url.path == "/logout" {
            let p = OIDCClient.responseParameters(url)
            var out = FormParameters()
            if let s = p.get("state") { out.append("state", s) }
            return URL(string: (p.get("post_logout_redirect_uri") ?? callback.absoluteString) + "?" + out.encoded)!
        }
        return try await op.authorize(url)
    }
}

func makeClient(_ op: StubOP, dpop: Bool = true, configure: (inout OIDCClientOptions) -> Void = { _ in }) async throws -> OIDCClient {
    await clearDiscoveryCache()
    var o = OIDCClientOptions(clientID: CLIENT_ID, redirectURI: REDIRECT, postLogoutRedirectURI: POST_LOGOUT,
                              idTokenSignedResponseAlg: await op.idTokenAlg, dpop: dpop ? DPoPOptions() : nil, transport: op)
    configure(&o)
    return try await OIDCClient.discover(metadataURL: URL(string: "\(ISSUER)/.well-known/openid-configuration")!, options: o)
}
