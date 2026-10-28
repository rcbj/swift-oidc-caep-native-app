// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation
import XCTest
@testable import OIDCCAEPClient

final class TokenManagerTests: XCTestCase {
    func testRefreshesAreMergedAndExpiredTokensRefreshed() async throws {
        let op = StubOP()
        await op.configure { $0.tokenDelay = 50_000_000 }
        let client = try await makeClient(op)
        let ts = try await client.authorize(using: StubBrowser(op: op)).tokenSet
        let tokens = TokenManager(client: client, store: MemoryTokenStore(), autoRefresh: false)
        try await tokens.set("k", ts)
        async let a = tokens.refresh("k")
        async let b = tokens.refresh("k")
        let (x, y) = try await (a, b)
        XCTAssertEqual(x.accessToken, y.accessToken)
        let refreshes = await op.refreshRequests
        XCTAssertEqual(refreshes, 1)

        var expired = x
        expired.expiresAt = Int(Date().timeIntervalSince1970) - 1
        try await tokens.set("k", expired)
        let fresh = try await tokens.getTokenSet("k")
        XCTAssertNotEqual(fresh.accessToken, x.accessToken)
    }

    func testInvalidGrantDropsTheTokens() async throws {
        let op = StubOP()
        let client = try await makeClient(op)
        var ts = try await client.authorize(using: StubBrowser(op: op)).tokenSet
        ts.refreshToken = "unknown"
        let tokens = TokenManager(client: client, store: MemoryTokenStore(), autoRefresh: false)
        try await tokens.set("k", ts)
        await XCTAssertThrowsCode("invalid_grant") { try await tokens.refresh("k") }
        let left = try await tokens.get("k")
        XCTAssertNil(left)
    }

    func testDeleteRevokes() async throws {
        let op = StubOP()
        let client = try await makeClient(op)
        let ts = try await client.authorize(using: StubBrowser(op: op)).tokenSet
        let tokens = TokenManager(client: client, store: MemoryTokenStore())
        try await tokens.set("k", ts)
        try await tokens.delete("k", revoke: true)
        let revoked = await op.revoked
        XCTAssertEqual(Set(revoked), Set([ts.accessToken, ts.refreshToken!]))
    }

    func testBackgroundRefreshFires() async throws {
        let op = StubOP()
        await op.configure { $0.expiresIn = 2 }
        let client = try await makeClient(op)
        let ts = try await client.authorize(using: StubBrowser(op: op)).tokenSet
        let tokens = TokenManager(client: client, store: MemoryTokenStore(), refreshSkew: 60, minRefreshDelay: 0.1)
        let refreshed = expectation(description: "refreshed")
        let sub = tokens.events.subscribe { if case .refreshed = $0 { refreshed.fulfill() } }
        try await tokens.set("k", ts)
        await fulfillment(of: [refreshed], timeout: 5)
        sub.cancel()
        await tokens.close()
    }

    func testTokenSetRoundTripsThroughJSON() throws {
        let ts = TokenSet(accessToken: "a", tokenType: "DPoP", refreshToken: "r", idToken: "i", scope: "openid", expiresAt: 10, issuedAt: 5,
                          claims: ["sub": "s"], additional: ["x": 1])
        let decoded = try JSONDecoder().decode(TokenSet.self, from: try JSONEncoder().encode(ts))
        XCTAssertEqual(decoded, ts)
        XCTAssertEqual(ts.effectiveSkew(60), 2.5)
    }
}

final class AccountManagerTests: XCTestCase {
    func makeAccounts(_ op: StubOP, store: any TokenStore = MemoryTokenStore(), hooks: (inout AccountManagerOptions) -> Void = { _ in }) async throws -> AccountManager {
        let client = try await makeClient(op)
        var o = AccountManagerOptions(store: store)
        hooks(&o)
        return try await AccountManager(client: client, options: o).restore()
    }

    func testSignInAddsAndActivates() async throws {
        let op = StubOP()
        let accounts = try await makeAccounts(op)
        let result = try await accounts.signIn(using: StubBrowser(op: op))
        XCTAssertTrue(result.added)
        XCTAssertEqual(result.intent, "sign-in")
        let active = await accounts.active
        XCTAssertEqual(active?.key, accountKey(iss: ISSUER, sub: "user-1"))
        XCTAssertEqual(active?.status, .signedIn)
        XCTAssertEqual(active?.email, "alice@example.test")
        let ts = try await accounts.getTokenSet()
        XCTAssertEqual(ts.claims?.string("sub"), "user-1")
    }

    func testOnlyTheActiveAccountsTokensAreReachableAndSwitchingWorks() async throws {
        let op = StubOP()
        let activated = Locked<[String]>([])
        let accounts = try await makeAccounts(op) { o in
            o.onActivate = { account, access in
                _ = try await access.getTokenSet()
                activated.withLock { $0.append(account.sub) }
            }
        }
        let alice = try await accounts.signIn(using: StubBrowser(op: op)).account
        await op.configure { $0.sub = "user-2" }
        let bob = try await accounts.addAccount(using: StubBrowser(op: op)).account
        let activeKey = await accounts.activeKey
        XCTAssertEqual(activeKey, bob.key)
        let v1 = await op.lastAuthorizeParams.get("prompt")
        XCTAssertEqual(v1, "login")
        try await accounts.activate(alice.key)
        let ts = try await accounts.getTokenSet()
        XCTAssertEqual(ts.claims?.string("sub"), "user-1")
        XCTAssertEqual(activated.current, ["user-1", "user-2", "user-1"])
        let list = await accounts.list()
        XCTAssertEqual(list.map(\.sub), ["user-1", "user-2"])
    }

    func testResumeNamesTheAccountAndRefusesAnybodyElse() async throws {
        let op = StubOP()
        let accounts = try await makeAccounts(op)
        let alice = try await accounts.signIn(using: StubBrowser(op: op)).account
        await op.configure { $0.sub = "user-2" }
        do {
            _ = try await accounts.resume(alice.key, using: StubBrowser(op: op))
            XCTFail("expected account_mismatch")
        } catch let e as OIDCError {
            XCTAssertEqual(e.code, "account_mismatch")
        }
        let p = await op.lastAuthorizeParams
        XCTAssertEqual(p.get("prompt"), "none")
        XCTAssertEqual(p.get("login_hint"), "alice")
        XCTAssertNotNil(p.get("id_token_hint"))

        await op.configure { $0.authorizeError = "login_required" }
        do {
            _ = try await accounts.resume(alice.key, using: StubBrowser(op: op))
            XCTFail("expected login_required")
        } catch let e as OIDCError {
            XCTAssertTrue(needsInteraction(e))
            XCTAssertEqual(e.account?.key, alice.key)
        }
    }

    func testSignOutRevokesAndHandsOverToAnotherAccount() async throws {
        let op = StubOP()
        let left = Locked<[String]>([])
        let accounts = try await makeAccounts(op) { o in o.onLeave = { a, _ in left.withLock { $0.append(a.sub) } } }
        let alice = try await accounts.signIn(using: StubBrowser(op: op)).account
        await op.configure { $0.sub = "user-2" }
        let bob = try await accounts.addAccount(using: StubBrowser(op: op)).account
        let logout = try await accounts.signOut(bob.key)
        XCTAssertNotNil(OIDCClient.responseParameters(logout!.url).get("id_token_hint"))
        let active = await accounts.activeKey
        XCTAssertEqual(active, alice.key)
        let v2 = await accounts.get(bob.key)?.status
        XCTAssertEqual(v2, .signedOut)
        XCTAssertEqual(left.current, ["user-2"])
        let v3 = await op.revoked.count
        XCTAssertEqual(v3, 2)
        try await accounts.signOut(using: StubBrowser(op: op))
        let v4 = await accounts.activeKey
        XCTAssertNil(v4)
        try await accounts.forget(bob.key)
        let v5 = await accounts.list().count
        XCTAssertEqual(v5, 1)
    }

    func testEndAndSubjectMatching() async throws {
        let op = StubOP()
        let accounts = try await makeAccounts(op)
        let alice = try await accounts.signIn(using: StubBrowser(op: op)).account
        let found = await accounts.accountsForSubject(Subject.complex(["user": .object(Subject.issSub(ISSUER, "user-1")), "session": .object(Subject.opaque("sid-1"))]))
        XCTAssertEqual(found.map(\.key), [alice.key])
        let other = await accounts.accountsForSubject(Subject.complex(["user": .object(Subject.issSub(ISSUER, "user-1")), "session": .object(Subject.opaque("sid-9"))]))
        XCTAssertTrue(other.isEmpty)
        try await accounts.end(alice.key, reason: "revoked")
        let a = await accounts.get(alice.key)
        XCTAssertEqual(a?.status, .ended)
        XCTAssertEqual(a?.endedReason, "revoked")
        await XCTAssertThrowsCode("not_active") { try await accounts.getTokenSet() }
    }

    func testRestoresAccountsFromThePersistentStore() async throws {
        let op = StubOP()
        let store = MemoryTokenStore()
        let first = try await makeAccounts(op, store: store)
        let alice = try await first.signIn(using: StubBrowser(op: op)).account
        await first.close()
        let second = try await makeAccounts(op, store: store)
        let v6 = await second.activeKey
        XCTAssertEqual(v6, alice.key)
        let v7 = await second.list().map(\.key)
        XCTAssertEqual(v7, [alice.key])
    }

    func testTheCallersContextIsKept() async throws {
        let op = StubOP()
        let accounts = try await makeAccounts(op)
        let request = try await accounts.signIn(AuthorizationRequestOptions(context: ["screen": "settings"]))
        let result = try await accounts.client.completeAuthorization(callbackURL: try await op.authorize(request.url))
        XCTAssertEqual(result.context?["screen"], "settings")
        XCTAssertEqual(result.context?["intent"], "sign-in")
    }

    func testTooManyAccounts() async throws {
        let op = StubOP()
        let accounts = try await makeAccounts(op) { $0.maxAccounts = 1 }
        _ = try await accounts.signIn(using: StubBrowser(op: op))
        await op.configure { $0.sub = "user-2" }
        await XCTAssertThrowsCode("too_many_accounts") { try await accounts.addAccount(using: StubBrowser(op: op)) }
    }

    func testSubjectMatchingRules() {
        let id = SubjectIdentity(iss: ISSUER, sub: "s", sid: "sid", email: "A@x.test", emailVerified: true, phoneNumber: "+1", phoneNumberVerified: false)
        XCTAssertTrue(subjectMatches(Subject.issSub(ISSUER, "s"), id))
        XCTAssertFalse(subjectMatches(Subject.issSub("https://other", "s"), id))
        XCTAssertTrue(subjectMatches(Subject.email("a@X.test"), id))
        XCTAssertFalse(subjectMatches(Subject.phone("+1"), id), "an unverified phone number names nobody")
        XCTAssertTrue(subjectMatches(Subject.opaque("s"), id))
        XCTAssertTrue(subjectMatches(Subject.aliases([Subject.opaque("no"), Subject.account("acct:A@x.test")]), id))
        XCTAssertFalse(subjectMatches(Subject.complex(["device": .object(Subject.opaque("d"))]), id))
    }
}
