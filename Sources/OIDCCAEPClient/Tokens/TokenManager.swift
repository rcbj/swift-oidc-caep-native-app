// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation

extension OIDCError {
    /// Any error as an ``OIDCError`` (kept as is when it already is one).
    static func wrap(_ error: Error) -> OIDCError {
        error as? OIDCError ?? OIDCError(kind: .general, error.localizedDescription, underlying: error)
    }
}

/// Caches token sets per key and keeps them fresh. By default they are cached in the Keychain on Apple
/// platforms and in memory elsewhere (``defaultTokenStore(service:)``).
///
/// - ``getTokenSet(_:forceRefresh:)`` always returns tokens valid for at least `refreshSkew`, refreshing on demand.
/// - With `autoRefresh` (the default), a timer refreshes each key's tokens `refreshSkew` before they expire.
/// - Concurrent refreshes of one key are merged into one token-endpoint call, and a refresh and a delete of
///   one key never interleave, so a rotating refresh token is never presented twice and revoked tokens are
///   never written back.
/// - ``set(_:_:schedule:)`` with `schedule: false`, and ``unschedule(_:)``, keep a key's tokens without
///   refreshing them.
public actor TokenManager {
    public enum Event: Sendable {
        /// New tokens obtained with the refresh token.
        case refreshed(key: String, tokenSet: TokenSet)
        /// A refresh failed (the tokens are dropped when the grant is invalid).
        case refreshError(key: String, error: OIDCError)
        /// The key's tokens could not be renewed and were removed.
        case expired(key: String)
        /// The key's tokens were deleted with ``delete(_:revoke:)``.
        case removed(key: String)
    }

    public nonisolated let events = EventHub<Event>()
    public nonisolated let client: OIDCClient
    let store: any TokenStore
    let refreshSkew: TimeInterval
    let autoRefresh: Bool
    let minRefreshDelay: TimeInterval
    let retryDelay: TimeInterval

    private var timers: [String: (id: UUID, task: Task<Void, Never>)] = [:]
    private var wanted: Set<String> = []
    private var inflight: [String: Task<TokenSet, Error>] = [:]
    private let locks = KeyedAsyncLock()

    public init(client: OIDCClient, store: any TokenStore = defaultTokenStore(), refreshSkew: TimeInterval = 60, autoRefresh: Bool = true,
                minRefreshDelay: TimeInterval = 1, retryDelay: TimeInterval = 5) {
        self.client = client
        self.store = store
        self.refreshSkew = refreshSkew
        self.autoRefresh = autoRefresh
        self.minRefreshDelay = minRefreshDelay
        self.retryDelay = retryDelay
    }

    private var now: Date { client.options.now() }

    /// Stores tokens for a key and (unless `schedule` is false) schedules their proactive refresh.
    @discardableResult
    public func set(_ key: String, _ tokenSet: TokenSet, schedule: Bool = true) async throws -> TokenSet {
        try await store.setJSON(key, tokenSet.json)
        if schedule { wanted.insert(key) } else { unschedule(key) }
        scheduleTimer(key, tokenSet)
        return tokenSet
    }

    /// Schedules the proactive refresh of the tokens already stored for `key`.
    public func schedule(_ key: String) async {
        wanted.insert(key)
        if let ts = try? await get(key) { scheduleTimer(key, ts) }
    }

    /// Stops refreshing `key`'s tokens in the background; they stay stored.
    public func unschedule(_ key: String) {
        wanted.remove(key)
        timers.removeValue(forKey: key)?.task.cancel()
    }

    /// The cached tokens (possibly expired) for `key`.
    public func get(_ key: String) async throws -> TokenSet? {
        guard let json = try await store.getJSON(key) else { return nil }
        return try? TokenSet(json: json)
    }

    /// A usable access token for `key`, refreshing first if it is expired or about to expire. Prefer
    /// ``getTokenSet(_:forceRefresh:)`` when the token may be DPoP-bound: its `tokenType` decides the header.
    public func getAccessToken(_ key: String, forceRefresh: Bool = false) async throws -> String {
        try await getTokenSet(key, forceRefresh: forceRefresh).accessToken
    }

    /// The cached token set for `key`, refreshed first if the access token is (nearly) expired.
    public func getTokenSet(_ key: String, forceRefresh: Bool = false) async throws -> TokenSet {
        guard var ts = try await get(key) else { throw OIDCError(kind: .general, "No tokens cached for \(key)", code: "no_tokens") }
        if forceRefresh || ts.isExpired(skew: refreshSkew, now: now) {
            if ts.refreshToken != nil {
                ts = try await refresh(key)
            } else if ts.isExpired(now: now) {
                await drop(key, .expired(key: key))
                throw OIDCError(kind: .general, "Access token expired and no refresh_token is available", code: "token_expired")
            }
        }
        return ts
    }

    /// Refreshes the tokens for `key` now. Concurrent calls share one request.
    @discardableResult
    public func refresh(_ key: String) async throws -> TokenSet {
        if let running = inflight[key] { return try await running.value }
        // Cleared by the task itself, before its awaiters resume: a refresh asked for after this one finished
        // is a new refresh.
        let task = Task { () throws -> TokenSet in
            defer { self.inflight[key] = nil }
            return try await self.performRefresh(key)
        }
        inflight[key] = task
        return try await task.value
    }

    private func performRefresh(_ key: String) async throws -> TokenSet {
        guard let before = try await get(key) else { throw OIDCError(kind: .general, "No tokens cached for \(key)", code: "no_tokens") }
        do {
            return try await locks.withLock(Self.lockName(key)) { try await self.refreshHoldingLock(key, before: before) }
        } catch {
            let e = OIDCError.wrap(error)
            events.emit(.refreshError(key: key, error: e))
            if e.kind == .oauth, e.code == "invalid_grant" || e.code == "invalid_client" { await drop(key, .expired(key: key)) }
            throw e
        }
    }

    private func refreshHoldingLock(_ key: String, before: TokenSet) async throws -> TokenSet {
        guard let current = try await get(key) else { throw OIDCError(kind: .general, "Tokens for \(key) were removed", code: "no_tokens") }
        // Another refresh may have finished while this one waited for the lock.
        if current.accessToken != before.accessToken, !current.isExpired(skew: refreshSkew, now: now) {
            scheduleTimer(key, current)
            return current
        }
        let next = try await client.refresh(current)
        // The key may have been deleted while the request was in flight. Its new tokens are revoked rather
        // than left valid at the OP.
        if try await store.get(key) == nil {
            await client.revokeQuietly(accessToken: next.accessToken, refreshToken: next.refreshToken)
            throw OIDCError(kind: .general, "Tokens for \(key) were removed during refresh", code: "no_tokens")
        }
        try await set(key, next, schedule: wanted.contains(key))
        events.emit(.refreshed(key: key, tokenSet: next))
        return next
    }

    /// Removes the tokens for `key`, optionally revoking them at the OP (RFC 7009). A refresh in flight
    /// finishes first, so it cannot write its tokens back after they were removed (e.g. on a CAEP
    /// session-revoked).
    @discardableResult
    public func delete(_ key: String, revoke: Bool = false) async throws -> TokenSet? {
        let held = try await locks.withLock(Self.lockName(key)) { () -> TokenSet? in
            let held = try await self.get(key)
            await self.drop(key, .removed(key: key))
            return held
        }
        if revoke, let held { await client.revokeQuietly(accessToken: held.accessToken, refreshToken: held.refreshToken) }
        return held
    }

    /// Cancels every refresh timer (call on shutdown).
    public func close() {
        for t in timers.values { t.task.cancel() }
        timers.removeAll()
        wanted.removeAll()
    }

    private func drop(_ key: String, _ event: Event) async {
        unschedule(key)
        try? await store.delete(key)
        events.emit(event)
    }

    private func scheduleTimer(_ key: String, _ ts: TokenSet) {
        timers.removeValue(forKey: key)?.task.cancel()
        guard autoRefresh, wanted.contains(key), let expiresAt = ts.expiresAt, ts.refreshToken != nil else { return }
        let due = Double(expiresAt) - ts.effectiveSkew(refreshSkew) - now.timeIntervalSince1970
        startTimer(key, delay: max(minRefreshDelay, due))
    }

    private func startTimer(_ key: String, delay: TimeInterval) {
        let id = UUID()
        let task = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(min(delay, 86_400 * 30) * 1_000_000_000))
            if Task.isCancelled { return }
            await self?.timerFired(key, id: id)
        }
        timers[key] = (id, task)
    }

    private func timerFired(_ key: String, id: UUID) async {
        guard timers[key]?.id == id else { return }
        timers[key] = nil
        do { _ = try await refresh(key) } catch { await retry(key) }
    }

    /// After a transient background-refresh failure (already reported as `.refreshError`), try again later.
    private func retry(_ key: String) async {
        guard let ts = try? await get(key), timers[key] == nil, wanted.contains(key) else { return }
        if ts.isExpired(now: now) {
            await drop(key, .expired(key: key))
            return
        }
        startTimer(key, delay: retryDelay)
    }

    private static func lockName(_ key: String) -> String { "refresh:\(key)" }
}
