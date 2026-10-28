// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation
import XCTest
@testable import OIDCCAEPClient

func XCTAssertThrowsCode<T>(_ code: String, _ body: () async throws -> T, file: StaticString = #filePath, line: UInt = #line) async {
    do {
        _ = try await body()
        XCTFail("expected \(code), got success", file: file, line: line)
    } catch let e as OIDCError {
        XCTAssertEqual(e.code, code, "\(e.message)", file: file, line: line)
    } catch {
        XCTFail("expected OIDCError \(code), got \(error)", file: file, line: line)
    }
}

final class OIDCClientTests: XCTestCase {
    func signIn(_ client: OIDCClient, _ op: StubOP, _ opts: AuthorizationRequestOptions = .init()) async throws -> TokenSet {
        try await client.authorize(using: StubBrowser(op: op), opts).tokenSet
    }

    // MARK: Discovery and setup

    func testDiscoversFromMetadataURLAndSignsInWithPARAndDPoP() async throws {
        let op = StubOP()
        let client = try await makeClient(op)
        XCTAssertTrue(client.usesPAR)
        XCTAssertNotNil(client.dpopKey)
        XCTAssertEqual(client.scope, "openid profile email offline_access")
        let ts = try await signIn(client, op)
        XCTAssertEqual(ts.tokenType, "DPoP")
        XCTAssertEqual(ts.claims?.string("sub"), "user-1")
        XCTAssertNotNil(ts.refreshToken)
        let pushed = await op.parRequests
        XCTAssertEqual(pushed.count, 1)
        XCTAssertEqual(pushed[0].get("dpop_jkt"), client.dpopKey?.thumbprint)
        XCTAssertEqual(pushed[0].get("code_challenge_method"), "S256")
        XCTAssertEqual(pushed[0].get("prompt"), "consent", "offline_access asks for consent (OIDC Core §11)")
    }

    func testMetadataURLMustNameItsIssuer() async throws {
        let op = StubOP()
        await op.configure { $0.metadataOverrides = ["issuer": "https://other.example.test"] }
        await XCTAssertThrowsCode("issuer_mismatch") { try await makeClient(op) }
    }

    func testRefusesOPWithoutS256OrPublicClients() async throws {
        let op = StubOP()
        await op.configure { $0.metadataOverrides = ["code_challenge_methods_supported": ["plain"]] }
        await XCTAssertThrowsCode("pkce_not_supported") { try await makeClient(op) }
        await op.configure { $0.metadataOverrides = ["token_endpoint_auth_methods_supported": ["client_secret_basic"]] }
        await XCTAssertThrowsCode("public_client_not_supported") { try await makeClient(op) }
    }

    func testRefusesInsecureEndpointsAndRedirects() async throws {
        let op = StubOP()
        await op.configure { $0.metadataOverrides = ["token_endpoint": "http://op.example.test/token"] }
        await XCTAssertThrowsCode("insecure_endpoint") { try await makeClient(op) }
        await op.configure { $0.metadataOverrides = [:] }
        await XCTAssertThrowsCode("insecure_redirect_uri") { try await makeClient(op) { $0.redirectURI = URL(string: "http://example.test/cb") } }
        await XCTAssertThrowsCode("insecure_redirect_uri") { try await makeClient(op) { $0.redirectURI = URL(string: "myapp:/cb") } }
        _ = try await makeClient(op) { $0.redirectURI = URL(string: "http://127.0.0.1:8123/cb") }
    }

    func testAppConfigurationFromPropertyList() throws {
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>MetadataURL</key><string>https://op.example.test/.well-known/openid-configuration</string>
          <key>ClientID</key><string>native-demo</string>
          <key>Scopes</key><array><string>openid</string><string>email</string><string>ssf.read</string></array>
          <key>RedirectURI</key><string>net.example.app:/callback</string>
          <key>PAR</key><string>always</string>
          <key>DPoP</key><false/>
        </dict></plist>
        """
        let c = try OIDCAppConfiguration(propertyList: Data(plist.utf8))
        XCTAssertEqual(c.clientID, "native-demo")
        XCTAssertEqual(c.scope, "openid email ssf.read")
        XCTAssertEqual(c.par, .always)
        XCTAssertFalse(c.dpop)
        XCTAssertNil(c.clientOptions().dpop)
        XCTAssertThrowsError(try OIDCAppConfiguration(dictionary: ["MetadataURL": "https://op.example.test/", "ClientID": "x", "RedirectURI": "a.b:/c"]))
        XCTAssertThrowsError(try OIDCAppConfiguration(dictionary: ["MetadataURL": "https://op.example.test/.well-known/openid-configuration", "RedirectURI": "a.b:/c"]))
    }

    // MARK: The authorization response

    func testStateIsSingleUse() async throws {
        let op = StubOP()
        let client = try await makeClient(op)
        let request = try await client.createAuthorizationRequest()
        let callback = try await op.authorize(request.url)
        _ = try await client.completeAuthorization(callbackURL: callback)
        await XCTAssertThrowsCode("state_reused") { try await client.completeAuthorization(callbackURL: callback) }
    }

    func testUnknownMissingAndExpiredState() async throws {
        let op = StubOP()
        await XCTAssertThrowsCode("state_mismatch") {
            let client = try await makeClient(op)
            return try await client.completeAuthorization(callbackURL: URL(string: "net.example.app:/callback?code=x&state=nope&iss=\(ISSUER)")!)
        }
        let client = try await makeClient(op)
        await XCTAssertThrowsCode("state_missing") { try await client.completeAuthorization(callbackURL: URL(string: "net.example.app:/callback?code=x")!) }

        let clock = Locked(Date())
        let late = try await makeClient(op) { o in o.now = { clock.current } }
        let request = try await late.createAuthorizationRequest()
        let callback = try await op.authorize(request.url)
        clock.withLock { $0 = $0.addingTimeInterval(601) }
        await XCTAssertThrowsCode("transaction_expired") { try await late.completeAuthorization(callbackURL: callback) }
    }

    func testFrontChannelTokensAndRepeatedParametersAreRefused() async throws {
        let op = StubOP()
        let client = try await makeClient(op)
        let request = try await client.createAuthorizationRequest()
        let callback = try await op.authorize(request.url)
        await XCTAssertThrowsCode("front_channel_token") { try await client.completeAuthorization(callbackURL: URL(string: callback.absoluteString + "#access_token=x")!) }
        await XCTAssertThrowsCode("duplicate_parameter") { try await client.completeAuthorization(callbackURL: URL(string: callback.absoluteString + "&code=again")!) }
    }

    func testRFC9207IssuerIsRequiredAndChecked() async throws {
        let op = StubOP()
        let client = try await makeClient(op)
        let request = try await client.createAuthorizationRequest()
        let callback = try await op.authorize(request.url)
        let p = OIDCClient.responseParameters(callback)
        var wrong = FormParameters()
        for item in p { wrong.append(item.name, item.name == "iss" ? "https://evil.example" : item.value) }
        await XCTAssertThrowsCode("issuer_mismatch") { try await client.completeAuthorization(parameters: wrong) }

        let request2 = try await client.createAuthorizationRequest()
        var missing = FormParameters()
        for item in OIDCClient.responseParameters(try await op.authorize(request2.url)) where item.name != "iss" { missing.append(item.name, item.value) }
        await XCTAssertThrowsCode("issuer_missing") { try await client.completeAuthorization(parameters: missing) }
    }

    func testOAuthErrorCarriesContext() async throws {
        let op = StubOP()
        await op.configure { $0.authorizeError = "login_required" }
        let client = try await makeClient(op)
        do {
            _ = try await client.authorize(using: StubBrowser(op: op), AuthorizationRequestOptions(prompt: "none", context: ["intent": "resume"]))
            XCTFail("expected an error")
        } catch let e as OIDCError {
            XCTAssertEqual(e.kind, .oauth)
            XCTAssertEqual(e.oauthError, "login_required")
            XCTAssertEqual(e.context?["intent"], "resume")
            XCTAssertTrue(needsInteraction(e))
        }
    }

    func testExtraParametersCannotReplaceReservedOnes() async throws {
        let client = try await makeClient(StubOP())
        await XCTAssertThrowsCode("invalid_argument") { try await client.createAuthorizationRequest(.init(extraParameters: ["state": "x"])) }
    }

    func testWithoutPARTheRequestIsInTheURL() async throws {
        let op = StubOP()
        let client = try await makeClient(op) { $0.par = .never }
        let request = try await client.createAuthorizationRequest(.init(loginHint: "alice"))
        let p = OIDCClient.responseParameters(request.url)
        XCTAssertEqual(p.get("login_hint"), "alice")
        XCTAssertEqual(p.get("client_id"), CLIENT_ID)
        XCTAssertNil(p.get("request_uri"))
        _ = try await client.completeAuthorization(callbackURL: try await op.authorize(request.url))
    }

    // MARK: ID token

    func testIDTokenChecks() async throws {
        let cases: [(String, @Sendable (inout JSONObject) -> Void)] = [
            ("nonce_mismatch", { $0["nonce"] = "other" }),
            ("invalid_id_token", { $0["aud"] = "someone-else" }),
            ("invalid_id_token", { $0["iss"] = "https://evil.example" }),
            ("invalid_id_token", { $0["exp"] = JSONValue(Int(Date().timeIntervalSince1970) - 3600) }),
            ("invalid_id_token", { $0["iat"] = JSONValue(Int(Date().timeIntervalSince1970) - 3600) }),
            ("invalid_id_token", { $0["aud"] = [.string(CLIENT_ID), "other"] }),
            ("invalid_id_token", { $0["azp"] = "other" }),
            ("invalid_id_token", { $0["at_hash"] = "AAAA" }),
        ]
        for (code, mutate) in cases {
            let op = StubOP()
            await op.setMutator(mutate)
            let client = try await makeClient(op)
            await XCTAssertThrowsCode(code) { try await self.signIn(client, op) }
        }
    }

    func testIDTokenSignedByAnotherKeyIsRefused() async throws {
        let op = StubOP()
        let client = try await makeClient(op)
        let bad = try SoftwareECSigner(alg: "ES256")
        let token = try signJWS(header: ["kid": "ec-1"], claims: ["iss": .string(ISSUER), "sub": "x", "aud": .string(CLIENT_ID),
                                                               "iat": JSONValue(Int(Date().timeIntervalSince1970)), "exp": JSONValue(Int(Date().timeIntervalSince1970) + 60)], signer: bad)
        await XCTAssertThrowsCode("invalid_id_token") { try await client.validateIDToken(token) }
    }

    func testRSAIDTokens() async throws {
        for alg in ["RS256", "PS256"] {
            let op = StubOP()
            try await op.useRSA(alg: alg)
            let client = try await makeClient(op)
            let ts = try await signIn(client, op)
            XCTAssertEqual(ts.claims?.string("sub"), "user-1", alg)
        }
    }

    func testUnexpectedAlgAndTypAreRefused() async throws {
        let op = StubOP()
        let client = try await makeClient(op) { $0.idTokenSignedResponseAlg = "RS256" }
        await XCTAssertThrowsCode("invalid_id_token") { try await self.signIn(client, op) }
        let ec = try await makeClient(op)
        let now = Int(Date().timeIntervalSince1970)
        let at = try signJWS(header: ["kid": "ec-1", "typ": "at+jwt"], claims: ["iss": .string(ISSUER), "sub": "x", "aud": .string(CLIENT_ID),
                                                                             "iat": JSONValue(now), "exp": JSONValue(now + 60)], signer: await op.signer)
        await XCTAssertThrowsCode("invalid_id_token") { try await ec.validateIDToken(at) }
    }

    func testACRIsEnforcedAndExpectedSubChecked() async throws {
        let op = StubOP()
        let client = try await makeClient(op)
        await XCTAssertThrowsCode("acr_mismatch") { try await self.signIn(client, op, .init(acrValues: "urn:mfa")) }
        await XCTAssertThrowsCode("account_mismatch") { try await self.signIn(client, op, .init(expectedSub: "user-2")) }
        let revoked = await op.revoked
        XCTAssertEqual(revoked.count, 2, "the other person's tokens are revoked")
    }

    // MARK: DPoP and tokens

    func testDPoPDowngradeIsRefused() async throws {
        let op = StubOP()
        await op.configure { $0.forceTokenType = "Bearer" }
        let client = try await makeClient(op)
        await XCTAssertThrowsCode("dpop_downgrade") { try await self.signIn(client, op) }
    }

    func testDPoPNonceIsRetried() async throws {
        let op = StubOP()
        await op.configure { $0.requireDPoPNonce = true }
        let client = try await makeClient(op)
        let ts = try await signIn(client, op)
        XCTAssertEqual(ts.tokenType, "DPoP")
    }

    func testBearerWithoutDPoP() async throws {
        let op = StubOP()
        let client = try await makeClient(op, dpop: false)
        let ts = try await signIn(client, op)
        XCTAssertEqual(ts.tokenType, "Bearer")
        XCTAssertEqual(try client.resourceHeaders(for: ts, url: URL(string: "https://api.example.test/x")!)["authorization"], "Bearer \(ts.accessToken)")
    }

    func testRefreshRotatesAndChecksTheIDToken() async throws {
        let op = StubOP()
        let client = try await makeClient(op)
        let first = try await signIn(client, op)
        let second = try await client.refresh(first)
        XCTAssertNotEqual(second.refreshToken, first.refreshToken)
        XCTAssertEqual(second.claims?.string("sub"), "user-1")
        await op.setMutator { $0["sub"] = "someone-else" }
        await XCTAssertThrowsCode("invalid_id_token") { try await client.refresh(second) }
        await XCTAssertThrowsCode("invalid_grant") { try await client.refresh(first) }
    }

    func testRefreshKeepsANonRotatedRefreshToken() async throws {
        let op = StubOP()
        await op.configure { $0.rotateRefreshTokens = false }
        await op.configure { $0.refreshIDToken = false }
        let client = try await makeClient(op)
        let first = try await signIn(client, op)
        let second = try await client.refresh(first)
        XCTAssertEqual(second.refreshToken, first.refreshToken)
        XCTAssertEqual(second.idToken, first.idToken)
        XCTAssertEqual(second.claims, first.claims)
    }

    func testUserInfoChecksSub() async throws {
        let op = StubOP()
        let client = try await makeClient(op)
        let ts = try await signIn(client, op)
        let info = try await client.userinfo(ts)
        XCTAssertEqual(info.string("email"), "alice@example.test")
        await op.configure { $0.userinfoSub = "other" }
        await XCTAssertThrowsCode("sub_mismatch") { try await client.userinfo(ts) }
    }

    func testLogoutStateIsCheckedOnce() async throws {
        let op = StubOP()
        let client = try await makeClient(op)
        let ts = try await signIn(client, op)
        let request = try await client.createEndSessionRequest(idTokenHint: ts.idToken, context: ["key": "k"])
        XCTAssertNotNil(request)
        let p = OIDCClient.responseParameters(request!.url)
        XCTAssertEqual(p.get("post_logout_redirect_uri"), POST_LOGOUT.absoluteString)
        let callback = URL(string: "\(POST_LOGOUT.absoluteString)?state=\(p.get("state")!)")!
        let context = try await client.completeEndSession(callbackURL: callback)
        XCTAssertEqual(context?["key"], "k")
        await XCTAssertThrowsCode("state_mismatch") { try await client.completeEndSession(callbackURL: callback) }
        let v1 = try await client.endSession(using: StubBrowser(op: op), request: try await client.createEndSessionRequest())
        XCTAssertTrue(v1)
    }

    func testDynamicRegistrationIsPublic() async throws {
        let op = StubOP()
        let (client, registration) = try await OIDCClient.register(
            metadata: await op.metadata, clientMetadata: ["redirect_uris": [.string(REDIRECT.absoluteString)], "id_token_signed_response_alg": "ES256"],
            options: OIDCClientOptions(clientID: "", dpop: DPoPOptions(), transport: op))
        XCTAssertEqual(client.clientID, CLIENT_ID)
        XCTAssertEqual(registration.string("token_endpoint_auth_method"), "none")
        XCTAssertEqual(registration["dpop_bound_access_tokens"], true)
        XCTAssertEqual(client.options.redirectURI, REDIRECT)
    }

    // MARK: Primitives

    func testPKCEAndThumbprint() {
        // RFC 7636 Appendix B.
        XCTAssertEqual(codeChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        // RFC 7638 §3.1.
        let jwk: JSONObject = ["kty": "RSA", "e": "AQAB", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"]
        XCTAssertEqual(jwkThumbprint(jwk), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
        XCTAssertEqual(htuOf(URL(string: "HTTPS://Api.Example.test:443/a/b?x=1#f")!), "https://api.example.test/a/b")
    }

    func testFormParametersRoundTrip() {
        var f = FormParameters()
        f.append("a", "x y&z=é")
        f.append("r", "1")
        f.append("r", "2")
        let parsed = FormParameters(parsing: f.encoded)
        XCTAssertEqual(parsed.get("a"), "x y&z=é")
        XCTAssertEqual(parsed.getAll("r"), ["1", "2"])
        f.set("r", "3")
        XCTAssertEqual(f.getAll("r"), ["3"])
    }
}
