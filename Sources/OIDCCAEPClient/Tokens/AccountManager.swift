// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation

/// ID token claims an account record keeps, for display and for naming the account to the OP. No tokens.
let profileClaims = ["iss", "sub", "sid", "name", "given_name", "family_name", "preferred_username", "email",
                     "email_verified", "phone_number", "phone_number_verified", "picture", "acr", "amr", "auth_time"]

/// One person signed in through this client in this app. Holds no token.
public struct Account: Codable, Sendable, Equatable, Identifiable {
    public enum Status: String, Codable, Sendable {
        /// Its tokens are in the cache.
        case signedIn = "signed-in"
        /// Not signed out, but its cached tokens could not be used (e.g. expired with no refresh token);
        /// ``AccountManager/resume(_:_:)`` asks the OP for new ones without a screen while its session there lasts.
        case tokensMissing = "tokens-missing"
        case signedOut = "signed-out"
        /// Ended by the OP, a security event or a refused refresh; see ``endedReason``.
        case ended
    }

    /// Stable id derived from `iss` and `sub` (``accountKey(iss:sub:)``).
    public let key: String
    public internal(set) var status: Status
    public internal(set) var endedReason: String?
    public internal(set) var addedAt: Date
    public internal(set) var lastUsedAt: Date
    /// When the status last left `signed-in`.
    public internal(set) var changedAt: Date?
    /// The profile claims of its latest validated ID token (``profileClaims``).
    public internal(set) var claims: JSONObject

    public var id: String { key }
    public var iss: String { claims.string("iss") ?? "" }
    public var sub: String { claims.string("sub") ?? "" }
    /// The OP session (OpenID Connect Front-/Back-Channel Logout `sid`).
    public var sid: String? { claims.string("sid") }
    public var name: String? { claims.string("name") }
    public var email: String? { claims.string("email") }
    public var preferredUsername: String? { claims.string("preferred_username") }

    /// What ``subjectMatches(_:_:)`` compares a security event's subject with.
    public var identity: SubjectIdentity {
        SubjectIdentity(iss: iss, sub: sub, sid: sid, email: email, emailVerified: claims["email_verified"]?.boolValue == true,
                        phoneNumber: claims.string("phone_number"), phoneNumberVerified: claims["phone_number_verified"]?.boolValue == true)
    }
}

/// Reaches one account's tokens from inside a hook (and, for `onActivate`, for as long as it stays active).
public struct AccountAccess: Sendable {
    let fetch: @Sendable (Bool) async throws -> TokenSet
    public func getTokenSet(forceRefresh: Bool = false) async throws -> TokenSet { try await fetch(forceRefresh) }
}

public struct AccountManagerOptions: Sendable {
    /// The account list and each account's tokens. Default: ``defaultTokenStore()`` — the Keychain on Apple
    /// platforms (encrypted at rest, kept across launches), memory elsewhere. A persistent store without DPoP
    /// logs a warning, since a refresh token at rest is best bound to a key (RFC 9700 §2.2.2).
    public var store: any TokenStore
    /// The key the account list is stored under (and, with `active:` before it, the active account).
    public var storeKey: String
    public var refreshSkew: TimeInterval
    /// Past it, the account that left longest ago is forgotten; when every place is held by a signed-in
    /// account, a further sign-in is refused (`too_many_accounts`).
    public var maxAccounts: Int
    /// How long a signed-out account stays listed (days).
    public var rememberSignedOutDays: Double
    /// What names an account to the OP in `login_hint`. Default: `preferred_username`, else `email`.
    public var loginHint: @Sendable (Account) -> String?
    /// Runs when an account is about to become the active account, after its tokens are refreshed if due
    /// and before `.activated` is emitted — e.g. to poll its CAEP stream and act on the signals queued while
    /// it was dormant. Throwing aborts the activation.
    public var onActivate: (@Sendable (Account, AccountAccess) async throws -> Void)?
    /// Runs when an account stops being the active account (e.g. to stop polling its stream).
    public var onDeactivate: (@Sendable (Account) async -> Void)?
    /// Runs before an account's tokens are deleted by ``AccountManager/signOut(_:revoke:endSession:postLogoutRedirectURI:)``
    /// or ``AccountManager/end(_:reason:)`` (e.g. to delete its CAEP stream while its tokens still work).
    public var onLeave: (@Sendable (Account, AccountAccess) async -> Void)?

    public init(store: any TokenStore = defaultTokenStore(), storeKey: String = "accounts", refreshSkew: TimeInterval = 60,
                maxAccounts: Int = 10, rememberSignedOutDays: Double = 30,
                loginHint: @escaping @Sendable (Account) -> String? = { $0.preferredUsername ?? $0.email },
                onActivate: (@Sendable (Account, AccountAccess) async throws -> Void)? = nil,
                onDeactivate: (@Sendable (Account) async -> Void)? = nil,
                onLeave: (@Sendable (Account, AccountAccess) async -> Void)? = nil) {
        self.store = store
        self.storeKey = storeKey
        self.refreshSkew = refreshSkew
        self.maxAccounts = maxAccounts
        self.rememberSignedOutDays = rememberSignedOutDays
        self.loginHint = loginHint
        self.onActivate = onActivate
        self.onDeactivate = onDeactivate
        self.onLeave = onLeave
    }
}

/// What a completed sign-in did.
public struct SignInResult: Sendable {
    public let account: Account
    public let tokenSet: TokenSet
    /// `sign-in`, `choose`, `add`, `resume` or `reauth`.
    public let intent: String
    /// The account is new to this app (rather than signed in again).
    public let added: Bool
}

/// Every account signed in through one client in this app, with ONE active account — for an OP that keeps
/// several signed-in accounts per browser (e.g. iya-sts `authn.multipleAccounts`).
///
/// - **One cache.** Each account's tokens are kept until it is signed out or its session ends, so any signed-in
///   account can be made active with no trip to the OP.
/// - **One active account.** Only its tokens are reachable (``getTokenSet(forceRefresh:)``), and only its
///   tokens are refreshed in the background. The others are dormant: stored, not used, not refreshed.
///   ``activate(_:)`` refreshes a dormant account's tokens if they are due and runs `onActivate` before it
///   becomes active.
///
/// Signing in: ``signIn(_:)`` lets the OP decide (its account picker when several are signed in there);
/// ``chooseAccount(_:)`` always shows the picker (`prompt=select_account`); ``addAccount(_:)`` is a fresh
/// sign-in (`prompt=login`). ``resume(_:_:)`` and ``reauthenticate(_:_:)`` name the account and refuse anybody
/// else. ``signOut(_:revoke:endSession:postLogoutRedirectURI:)`` revokes that account's tokens and names its
/// ID token at logout, so the OP ends that account's session only.
///
/// Use one `AccountManager` per store.
public actor AccountManager {
    public enum Event: Sendable {
        case added(Account)
        case updated(Account)
        /// The active account changed (to nil: none is active).
        case activated(Account?, previous: Account?)
        /// The active account's tokens were refreshed.
        case refreshed(Account)
        case signedOut(Account)
        case ended(Account, reason: String?)
        case forgotten(Account)
        case activationError(Account?, OIDCError)
        /// After any of the above.
        case change
    }

    public nonisolated let events = EventHub<Event>()
    public nonisolated let client: OIDCClient
    public nonisolated let tokens: TokenManager
    let options: AccountManagerOptions

    private var accounts: [String: Account] = [:]
    private var activeKeyValue: String?
    private var activating: String?
    private var subscription: EventSubscription?
    private var restored = false
    private let persistLock = KeyedAsyncLock()

    public init(client: OIDCClient, options: AccountManagerOptions = .init()) {
        self.client = client
        self.options = options
        tokens = TokenManager(client: client, store: options.store, refreshSkew: options.refreshSkew)
        if options.store.isPersistent, client.dpopKey == nil {
            OIDCLog.log(.warning, "AccountManager: tokens are kept in persistent storage without DPoP. Anything that can read the store can use them anywhere; turn on DPoP or use MemoryTokenStore.")
        }
    }

    private var now: Date { client.options.now() }

    /// Loads the account list and reactivates the account that was active (refreshing its tokens if due and
    /// running `onActivate`). A failed reactivation leaves no active account and is emitted as `.activationError`.
    @discardableResult
    public func restore() async throws -> AccountManager {
        if subscription == nil {
            subscription = tokens.events.subscribe { [weak self] event in
                guard let self else { return }
                Task { await self.handleTokenEvent(event) }
            }
        }
        if !restored {
            restored = true
            if let saved = try await options.store.getJSON(options.storeKey), let list = saved["accounts"] {
                let decoded = (try? JSONDecoder().decode([Account].self, from: try list.jsonData())) ?? []
                accounts = Dictionary(decoded.map { ($0.key, $0) }, uniquingKeysWith: { _, b in b })
            }
            let forgetBefore = now.addingTimeInterval(-options.rememberSignedOutDays * 86_400)
            accounts = accounts.filter { !($0.value.status == .signedOut && ($0.value.changedAt ?? .distantPast) < forgetBefore) }
            try await persist()
        }
        if let data = try await options.store.get(activeStoreKey), let remembered = String(data: data, encoding: .utf8), accounts[remembered] != nil {
            do { try await activateInternal(remembered) } catch {
                events.emit(.activationError(get(remembered), .wrap(error)))
            }
        }
        return self
    }

    /// Every account in this app, in the order added.
    public func list() -> [Account] { accounts.values.sorted { $0.addedAt < $1.addedAt } }
    public func get(_ key: String) -> Account? { accounts[key] }
    /// The active account (whatever its status).
    public var active: Account? { activeKeyValue.flatMap { accounts[$0] } }
    public var activeKey: String? { activeKeyValue }

    /// The identity ``subjectMatches(_:_:)`` compares a security event's subject with.
    public func identity(_ key: String) -> SubjectIdentity? { accounts[key]?.identity }

    /// The accounts a security event's subject (`sub_id`) is about. A subject naming a session (an SSF
    /// complex subject with `session`) matches only the account signed in with that session.
    public func accountsForSubject(_ subId: JSONObject) -> [Account] {
        list().filter { subjectMatches(subId, $0.identity) }
    }

    // MARK: The active account's tokens: the only ones reachable

    /// The active account's tokens, refreshed first when (nearly) expired. A dormant account's tokens cannot
    /// be reached: activate the account first.
    public func getTokenSet(forceRefresh: Bool = false) async throws -> TokenSet {
        try await tokensFor(activeKeyValue, forceRefresh: forceRefresh)
    }

    /// Refreshes the active account's tokens now.
    @discardableResult
    public func refresh() async throws -> TokenSet { try await getTokenSet(forceRefresh: true) }

    private func tokensFor(_ key: String?, forceRefresh: Bool) async throws -> TokenSet {
        guard let key, key == activeKeyValue || key == activating else {
            throw OIDCError(kind: .general, "Only the active account's tokens can be used; activate the account first", code: "not_active")
        }
        guard accounts[key]?.status == .signedIn else { throw OIDCError(kind: .general, "The active account is not signed in", code: "no_tokens") }
        return try await tokens.getTokenSet(key, forceRefresh: forceRefresh)
    }

    private func access(_ key: String) -> AccountAccess {
        AccountAccess { [weak self] force in
            guard let self else { throw OIDCError(kind: .general, "The account manager is gone", code: "no_tokens") }
            return try await self.tokensFor(key, forceRefresh: force)
        }
    }

    // MARK: Signing in (building the requests)

    /// A sign-in that leaves the choice to the OP: with several accounts signed in there, it shows its
    /// account picker; with one, it answers as that account.
    public func signIn(_ opts: AuthorizationRequestOptions = .init()) async throws -> AuthorizationRequest {
        var o = opts
        o.context = Self.context(opts.context, ["intent": "sign-in"])
        return try await client.createAuthorizationRequest(o)
    }

    /// A sign-in that always shows the OP's account picker (`prompt=select_account`).
    public func chooseAccount(_ opts: AuthorizationRequestOptions = .init()) async throws -> AuthorizationRequest {
        var o = opts
        o.prompt = "select_account"
        o.context = Self.context(opts.context, ["intent": "choose"])
        return try await client.createAuthorizationRequest(o)
    }

    /// A fresh sign-in (`prompt=login`), never the OP's picker: whoever signs in is added as an account.
    public func addAccount(_ opts: AuthorizationRequestOptions = .init()) async throws -> AuthorizationRequest {
        var o = opts
        o.prompt = "login"
        o.context = Self.context(opts.context, ["intent": "add"])
        return try await client.createAuthorizationRequest(o)
    }

    /// Asks the OP for this account's tokens again without showing a screen (`prompt=none`, naming the
    /// account with `login_hint` and, where cached, `id_token_hint`). Fails with an error for which
    /// ``needsInteraction(_:)`` is true when the account's session at the OP has ended; reauthenticate then.
    public func resume(_ key: String, _ opts: AuthorizationRequestOptions = .init()) async throws -> AuthorizationRequest {
        var o = opts
        if o.prompt == nil { o.prompt = "none" }
        return try await accountRequest(key, intent: "resume", o)
    }

    /// Signs this account's person in again at the OP (`prompt=login` by default), e.g. for step-up with
    /// `acrValues`/`maxAge`. A sign-in as anybody else is refused at the callback (`account_mismatch`).
    public func reauthenticate(_ key: String, _ opts: AuthorizationRequestOptions = .init()) async throws -> AuthorizationRequest {
        var o = opts
        if o.prompt == nil { o.prompt = "login" }
        return try await accountRequest(key, intent: "reauth", o)
    }

    private func accountRequest(_ key: String, intent: String, _ opts: AuthorizationRequestOptions) async throws -> AuthorizationRequest {
        let a = try mustGet(key)
        let cached = try? await tokens.get(key)
        var o = opts
        if o.loginHint == nil { o.loginHint = options.loginHint(a) }
        if o.idTokenHint == nil { o.idTokenHint = cached?.idToken }
        o.expectedSub = a.sub
        o.context = Self.context(opts.context, ["intent": .string(intent), "key": .string(key)])
        return try await client.createAuthorizationRequest(o)
    }

    /// Completes any of the requests above from the redirect. The account signed in is added to the cache
    /// (or, when already listed, signed in again) and becomes the active account.
    ///
    /// An error the OP returned is thrown with ``OIDCError/context`` (`{ intent, key? }`) and, for
    /// `resume`/`reauth`, ``OIDCError/account``.
    @discardableResult
    public func handleCallback(_ callbackURL: URL) async throws -> SignInResult {
        let result: AuthorizationResult
        do {
            result = try await client.completeAuthorization(callbackURL: callbackURL)
        } catch var e as OIDCError {
            if let key = e.context?["key"]?.stringValue { e.account = accounts[key] }
            throw e
        }
        let tokenSet = result.tokenSet
        let claims = tokenSet.claims ?? [:]
        let key = accountKey(iss: claims.string("iss") ?? "", sub: claims.string("sub") ?? "")
        var account = accounts[key]
        let added = account == nil
        if added {
            try await makeRoom(tokenSet)
            account = Account(key: key, status: .signedIn, addedAt: now, lastUsedAt: now, claims: [:])
        }
        account!.claims = claims.filter { profileClaims.contains($0.key) }
        account!.status = .signedIn
        account!.lastUsedAt = now
        account!.endedReason = nil
        account!.changedAt = nil
        accounts[key] = account
        try await tokens.set(key, tokenSet, schedule: false)
        try await persist()
        events.emit(added ? .added(account!) : .updated(account!))
        try await activateInternal(key)
        return SignInResult(account: accounts[key] ?? account!, tokenSet: tokenSet, intent: result.context?["intent"]?.stringValue ?? "sign-in", added: added)
    }

    // MARK: Activating

    /// Makes a listed account the active account; the previous one becomes dormant. Nothing is sent to the
    /// OP unless the account's tokens are due for a refresh. An account that is not `signed-in` becomes active
    /// too, with no tokens; resume or reauthenticate it.
    ///
    /// When the refresh or `onActivate` fails, the previously active account is reactivated and the error thrown.
    @discardableResult
    public func activate(_ key: String) async throws -> Account? {
        _ = try mustGet(key)
        let previous = activeKeyValue
        do {
            try await activateInternal(key)
        } catch {
            if let previous, previous != key, activeKeyValue != previous { try? await activateInternal(previous) }
            throw error
        }
        return active
    }

    private func activateInternal(_ key: String) async throws {
        let previous = activeKeyValue
        if let previous, previous != key { await deactivate() }
        _ = try mustGet(key)
        if accounts[key]?.status == .signedIn {
            var ts = try await tokens.get(key)
            if let t = ts, t.isExpired(skew: options.refreshSkew, now: now) {
                ts = t.refreshToken != nil ? try await tokens.refresh(key) : nil
            }
            if ts == nil {
                _ = try? await tokens.delete(key)
                setStatus(key, .tokensMissing)
                try await persist()
            } else if let onActivate = options.onActivate, let account = accounts[key] {
                activating = key
                defer { activating = nil }
                try await onActivate(account, access(key))
                // A signal acted on during onActivate may have ended the account: its status says so.
            }
        }
        activeKeyValue = key
        try await options.store.set(activeStoreKey, Data(key.utf8))
        if accounts[key]?.status == .signedIn {
            accounts[key]?.lastUsedAt = now
            try await persist()
            await tokens.schedule(key)
        }
        if previous != key { events.emit(.activated(accounts[key], previous: previous.flatMap { accounts[$0] })) }
        events.emit(.change)
    }

    private func deactivate() async {
        guard let key = activeKeyValue else { return }
        await tokens.unschedule(key)
        activeKeyValue = nil
        try? await options.store.delete(activeStoreKey)
        if let a = accounts[key], let hook = options.onDeactivate { await hook(a) }
    }

    // MARK: Signing out, ending, forgetting

    /// Signs one account out of this app: `onLeave` runs, its tokens are revoked (with `revoke`) and removed
    /// from the cache, and it stays listed as `signed-out`. When it was the active account, the most recently
    /// added signed-in account becomes active. Returns an RP-Initiated Logout request naming that account's ID
    /// token, so the OP ends that account's session only (or nil: no end_session_endpoint, or `endSession: false`).
    @discardableResult
    public func signOut(_ key: String? = nil, revoke: Bool = true, endSession: Bool = true, postLogoutRedirectURI: URL? = nil) async throws -> EndSessionRequest? {
        guard let key = key ?? activeKeyValue else { throw OIDCError(kind: .general, "No account to sign out", code: "no_account") }
        let (account, idToken) = try await leave(key, status: .signedOut, revoke: revoke, reason: nil)
        await afterLeaving(key)
        events.emit(.signedOut(account))
        events.emit(.change)
        guard endSession else { return nil }
        return try await client.createEndSessionRequest(idTokenHint: idToken, postLogoutRedirectURI: postLogoutRedirectURI,
                                                        logoutHint: idToken == nil ? options.loginHint(account) : nil, context: ["key": .string(key)])
    }

    /// Signs every account out of this app. Returns one logout request that names nobody, so an OP holding
    /// several accounts asks the person which to end (or all of them).
    @discardableResult
    public func signOutAll(revoke: Bool = true, endSession: Bool = true, postLogoutRedirectURI: URL? = nil) async throws -> EndSessionRequest? {
        let previous = active
        for a in list() where a.status == .signedIn || a.status == .tokensMissing {
            let (account, _) = try await leave(a.key, status: .signedOut, revoke: revoke, reason: nil)
            events.emit(.signedOut(account))
        }
        if activeKeyValue != nil { await deactivate() }
        if let previous { events.emit(.activated(nil, previous: accounts[previous.key])) }
        events.emit(.change)
        guard endSession else { return nil }
        return try await client.createEndSessionRequest(postLogoutRedirectURI: postLogoutRedirectURI, context: ["all": true])
    }

    /// Ends an account's session in this app because the OP or a security event says it has ended:
    /// `onLeave` runs, its tokens are removed from the cache (not revoked: the OP already knows), and it stays
    /// listed as `ended` with the reason. When it was the active account, the most recently added signed-in
    /// account becomes active. Does nothing for an account that is not signed in.
    @discardableResult
    public func end(_ key: String, reason: String? = nil) async throws -> Account? {
        guard let a = accounts[key], a.status == .signedIn || a.status == .tokensMissing else { return accounts[key] }
        let (account, _) = try await leave(key, status: .ended, revoke: false, reason: reason)
        // During its onActivate the account is not active yet; activation sees the status when the hook returns.
        if activating != key { await afterLeaving(key) }
        events.emit(.ended(account, reason: reason))
        events.emit(.change)
        return accounts[key]
    }

    /// Removes an account that is not signed in from the list. A signed-in account must be signed out first.
    public func forget(_ key: String) async throws {
        let a = try mustGet(key)
        if a.status == .signedIn { throw OIDCError(kind: .general, "Sign the account out before forgetting it", code: "account_signed_in") }
        accounts[key] = nil
        try await persist()
        _ = try? await tokens.delete(key)
        if activeKeyValue == key {
            activeKeyValue = nil
            try? await options.store.delete(activeStoreKey)
            events.emit(.activated(nil, previous: a))
        }
        events.emit(.forgotten(a))
        events.emit(.change)
    }

    /// Cancels refresh timers (call on shutdown).
    public func close() async {
        await tokens.close()
        subscription?.cancel()
        subscription = nil
    }

    // MARK: Internals

    private var activeStoreKey: String { "active:\(options.storeKey)" }

    /// The request's context: the manager's `intent` (and `key`), added to an object the caller passed, or
    /// kept beside any other value as `app`.
    private static func context(_ given: JSONValue?, _ ours: JSONObject) -> JSONValue {
        guard let given else { return .object(ours) }
        if var object = given.objectValue {
            object.merge(ours) { _, mine in mine }
            return .object(object)
        }
        return .object(ours.merging(["app": given]) { a, _ in a })
    }

    private func mustGet(_ key: String) throws -> Account {
        guard let a = accounts[key] else { throw OIDCError(kind: .general, "No account \(key)", code: "no_account") }
        return a
    }

    /// Runs onLeave, drops the tokens and records the new status.
    private func leave(_ key: String, status: Account.Status, revoke: Bool, reason: String?) async throws -> (Account, String?) {
        let a = try mustGet(key)
        let cached = try? await tokens.get(key)
        if cached != nil, let onLeave = options.onLeave {
            let tokens = self.tokens
            await onLeave(a, AccountAccess { force in try await tokens.getTokenSet(key, forceRefresh: force) })
        }
        _ = try? await tokens.delete(key, revoke: revoke)
        setStatus(key, status)
        if let reason { accounts[key]?.endedReason = reason }
        try await persist()
        var result = accounts[key] ?? a
        result.status = status
        return (result, cached?.idToken)
    }

    /// When the account that left was the active one, the most recently added signed-in account takes over.
    private func afterLeaving(_ key: String) async {
        guard activeKeyValue == key else { return }
        await deactivate()
        if let next = accounts.values.filter({ $0.status == .signedIn }).max(by: { $0.addedAt < $1.addedAt }) {
            do { try await activateInternal(next.key) } catch { events.emit(.activationError(accounts[next.key], .wrap(error))) }
        } else {
            events.emit(.activated(nil, previous: accounts[key]))
        }
    }

    private func setStatus(_ key: String, _ status: Account.Status) {
        guard accounts[key] != nil else { return }
        accounts[key]?.status = status
        accounts[key]?.changedAt = now
        if status != .ended { accounts[key]?.endedReason = nil }
    }

    /// Before adding an account at the limit: forget the account that left longest ago, or refuse.
    private func makeRoom(_ tokenSet: TokenSet) async throws {
        guard accounts.count >= options.maxAccounts else { return }
        let droppable = accounts.values.filter { $0.status != .signedIn }.sorted { ($0.changedAt ?? $0.lastUsedAt) < ($1.changedAt ?? $1.lastUsedAt) }
        guard let oldest = droppable.first else {
            let client = self.client
            Task { await client.revokeQuietly(accessToken: tokenSet.accessToken, refreshToken: tokenSet.refreshToken) }
            throw OIDCError(kind: .general, "\(options.maxAccounts) accounts are signed in already; sign one out first", code: "too_many_accounts")
        }
        accounts[oldest.key] = nil
        _ = try? await tokens.delete(oldest.key)
        events.emit(.forgotten(oldest))
    }

    private func handleTokenEvent(_ event: TokenManager.Event) async {
        switch event {
        case .refreshed(let key, let ts):
            guard let claims = ts.claims, accounts[key] != nil else { return }
            for (k, v) in claims where profileClaims.contains(k) { accounts[key]?.claims[k] = v }
            try? await persist()
            if key == activeKeyValue, let a = accounts[key] { events.emit(.refreshed(a)) }
            events.emit(.change)
        case .expired(let key):
            _ = try? await end(key, reason: "Its tokens could not be renewed.")
        default:
            break
        }
    }

    /// Writes the account list. The snapshot is taken under the lock, so the last write is the latest list.
    private func persist() async throws {
        try await persistLock.withLock("accounts") {
            let snapshot = await self.list()
            let data = try JSONEncoder().encode(snapshot)
            try await self.options.store.setJSON(self.options.storeKey, ["accounts": try JSONValue.parse(data)])
        }
    }
}

/// The account key for an `iss` and `sub`: stable, opaque, and safe in a storage key or a URL.
public func accountKey(iss: String, sub: String) -> String {
    "acct-" + Base64URL.encode(sha256("\(iss)\n\(sub)")).prefix(22)
}
