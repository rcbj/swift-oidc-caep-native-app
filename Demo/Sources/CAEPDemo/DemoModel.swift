// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The demo's state and behaviour. The OIDC client runs in this app as a public client: Authorization Code +
// PKCE in the system browser, state/nonce, PAR, DPoP with the key in the Secure Enclave (or the Keychain),
// RFC 9207, tokens cached in the Keychain with auto-refresh, and a CAEP (Shared Signals) stream polled with
// the active account's access token.
//
// Several accounts can be signed in at once. The library caches every account's tokens, and the app has ONE
// active account: only its tokens are used and refreshed, and only its stream is polled. Switching makes
// another cached account active; its stream first catches up on the signals queued while it was dormant.

import Foundation
import Observation
import OIDCCAEPClient

struct LogEntry: Identifiable, Codable, Equatable {
    var id = UUID()
    var at = Date()
    var account: String
    var name: String
    var type: String?
    var jti: String?
    var subject: String?
    var payload: String?
    var action: String
}

struct Notice: Identifiable, Equatable {
    enum Level { case info, warn, danger }
    let id = UUID()
    var level: Level
    var text: String
}

/// Per account: refresh count, step-up requirement, notices from its signals.
struct AccountState {
    var refreshCount = 0
    var lastRefresh: Date?
    var stepUp: String?
    var notices: [Notice] = []
}

enum StreamStatus: Equatable {
    case disabled, waitingForUser, connecting, connected, unavailable, noStream, error
}

struct StreamState: Equatable {
    var status: StreamStatus = .waitingForUser
    var transmitter: String?
    var note: String?
    var error: String?
    var streamStatus: String?
    var streamID: String?
    var audience: String?
    var write = false
}

@MainActor
@Observable
final class DemoModel {
    // Configuration and library objects.
    private(set) var config: OIDCAppConfiguration?
    private(set) var client: OIDCClient?
    private(set) var accounts: AccountManager?
    private var subscription: EventSubscription?
    private let authenticator: any WebAuthenticator
    private var transport: (any HTTPTransport)?

    // What the views show.
    private(set) var accountList: [Account] = []
    private(set) var active: Account?
    private(set) var currentTokens: TokenSet?
    private(set) var signInTokens: (key: String, tokenSet: TokenSet)?
    private(set) var perAccount: [String: AccountState] = [:]
    var notices: [Notice] = []
    var error: String?
    var attention: (key: String, text: String)?
    private(set) var busy: String?
    private(set) var ended: [String: String] = [:]
    var userinfoOutput: String?
    private(set) var dpopStoreDescription = "memory"

    // CAEP: the one stream this app polls, the active account's.
    private(set) var caepKey: String?
    private var receiver: SSFReceiver?
    private(set) var stream = StreamState()
    private(set) var log: [LogEntry] = []
    var selectedEvents: Set<String>

    private let defaults = UserDefaults.standard
    private static let streamsKey = "caep-demo.stream-ids"
    private static let eventsKey = "caep-demo.caep-events"
    private static let labelsKey = "caep-demo.labels"
    private static let logKey = "caep-demo.event-log"

    init() {
        let saved = UserDefaults.standard.stringArray(forKey: Self.eventsKey)
        selectedEvents = Set(saved ?? CAEP.all)
        log = (UserDefaults.standard.data(forKey: Self.logKey)).flatMap { try? JSONDecoder().decode([LogEntry].self, from: $0) } ?? []
        // macOS: ASWebAuthenticationSession and a private-use scheme redirect. Linux: the default browser
        // (xdg-open) and a loopback redirect (RFC 8252 §7.3).
        #if os(macOS)
        authenticator = SystemWebAuthenticator()
        #else
        authenticator = LoopbackWebAuthenticator()
        #endif
    }

    var signedIn: Account? { active?.status == .signedIn ? active : nil }
    func state(_ key: String) -> AccountState { perAccount[key] ?? AccountState() }

    // MARK: - Configuration → client

    func start() async {
        do {
            let cfg = try Self.loadConfiguration()
            config = cfg
            stream.status = cfg.caepEnabled ? .waitingForUser : .disabled
            // The DPoP key and the tokens go to the platform's secure storage when it has one (macOS: Secure
            // Enclave or Keychain), and stay in memory otherwise (Linux).
            #if os(macOS)
            let keyStore: any DPoPKeyStore = await preferredDPoPKeyStore(service: "net.rcbj.caepdemo.dpop")
            dpopStoreDescription = keyStore is SecureEnclaveKeyStore ? "Secure Enclave (non-extractable)" : "Keychain (software key)"
            #else
            let keyStore: any DPoPKeyStore = MemoryKeyStore()
            dpopStoreDescription = "memory (a new key each launch)"
            #endif
            let transport = cfg.makeTransport()
            self.transport = transport
            let client = try await cfg.makeClient(dpopKeyStore: keyStore, transport: transport)
            self.client = client

            // The hooks tie the app's one CAEP stream to its active account.
            let options = AccountManagerOptions(
                store: defaultTokenStore(service: "net.rcbj.caepdemo.tokens"),
                storeKey: "accounts:\(client.issuer):\(client.clientID)",
                onActivate: { [weak self] account, access in
                    await self?.rememberProfile(account, access)
                    await self?.startCaep(account, access)
                },
                onDeactivate: { [weak self] account in await self?.stopCaep(account.key) },
                onLeave: { [weak self] account, access in await self?.deleteStream(account, access) })
            let accounts = AccountManager(client: client, options: options)
            self.accounts = accounts
            subscription = accounts.events.subscribe { [weak self] event in
                Task { @MainActor in await self?.handle(event) }
            }
            try await accounts.restore()
            await reload()
        } catch {
            self.error = "Could not load the OIDC configuration or reach the identity provider: \(describe(error))"
        }
    }

    /// The configuration, from the first of:
    /// - `OIDC_CONFIG=/path/to/file.plist`;
    /// - Linux: `~/.config/caep-demo/OIDCConfiguration.plist`, to point the demo at another provider without rebuilding;
    /// - the app bundle (macOS, built with scripts/build-app.sh);
    /// - the package's resources: `OIDCConfiguration.plist` on macOS, `OIDCConfiguration-Linux.plist` (a loopback
    ///   redirect URI) on Linux.
    private static func loadConfiguration() throws -> OIDCAppConfiguration {
        let environment = ProcessInfo.processInfo.environment
        if let path = environment["OIDC_CONFIG"], !path.isEmpty {
            return try OIDCAppConfiguration.load(contentsOf: URL(fileURLWithPath: path))
        }
        #if os(macOS)
        let resource = OIDCAppConfiguration.defaultResourceName
        #else
        let resource = "OIDCConfiguration-Linux"
        let home = environment["XDG_CONFIG_HOME"].map { URL(fileURLWithPath: $0) }
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config")
        let user = home.appendingPathComponent("caep-demo/OIDCConfiguration.plist")
        if FileManager.default.fileExists(atPath: user.path) { return try OIDCAppConfiguration.load(contentsOf: user) }
        #endif
        if Bundle.main.url(forResource: resource, withExtension: "plist") != nil {
            return try OIDCAppConfiguration.load(bundle: .main, resource: resource)
        }
        return try OIDCAppConfiguration.load(bundle: .module, resource: resource)
    }

    private func reload() async {
        guard let accounts else { return }
        accountList = await accounts.list()
        active = await accounts.active
        if let key = active?.key, active?.status == .signedIn {
            currentTokens = try? await accounts.tokens.get(key)
        } else {
            currentTokens = nil
        }
    }

    private func handle(_ event: AccountManager.Event) async {
        switch event {
        case .refreshed(let a):
            perAccount[a.key, default: AccountState()].refreshCount += 1
            perAccount[a.key, default: AccountState()].lastRefresh = Date()
        case .signedOut(let a), .forgotten(let a):
            // A signed-out or forgotten account's signals leave the app with it.
            clearLog(a.key)
        case .ended(let a, let reason):
            ended[a.key] = reason ?? "The session ended."
        case .activated(let a, _):
            if a?.key != signInTokens?.key { signInTokens = nil }
            attention = nil
        case .activationError(let a, let e):
            error = "Could not make \(label(a)) active: \(describe(e))"
        case .change:
            // The active account may have been ended by a signal.
            if let key = caepKey, let status = await accounts?.get(key)?.status, status != .signedIn { await stopCaep(key) }
        case .added, .updated:
            break
        }
        await reload()
    }

    // MARK: - Sign-in, switching, sign-out

    private var acr: AuthorizationRequestOptions { AuthorizationRequestOptions(acrValues: config?.acrValues) }

    /// login: do not continue whoever is already signed in at the IdP. consent: offline_access is ignored
    /// unless the request asks for it (OIDC Core §11).
    func signIn() async {
        var o = acr
        o.prompt = "login consent"
        await go("sign-in") { try await $0.signIn(using: $1, o) }
    }

    func addAccount() async {
        let o = acr
        await go("sign-in") { try await $0.addAccount(using: $1, o) }
    }

    func resume(_ key: String) async {
        let o = acr
        await go("silent sign-in") { try await $0.resume(key, using: $1, o) }
    }

    func reauthenticate(_ key: String) async {
        let o = acr
        await go("sign-in") { try await $0.reauthenticate(key, using: $1, o) }
    }

    private func go(_ what: String, _ run: (AccountManager, any WebAuthenticator) async throws -> SignInResult) async {
        guard let accounts else { return }
        error = nil
        do {
            let result = try await run(accounts, authenticator)
            let account = result.account
            perAccount[account.key] = nil
            ended[account.key] = nil
            if await accounts.activeKey == account.key { signInTokens = (account.key, result.tokenSet) }
            notices.insert(Notice(level: .info, text: result.added
                ? "\(label(account)) added. Your other accounts stay signed in, dormant until you switch to them."
                : "Signed in as \(label(account))."), at: 0)
        } catch let e as OIDCError where e.isUserCancellation {
            // The person closed the browser window.
        } catch let e as OIDCError {
            if needsInteraction(e), let account = e.account {
                attention = (account.key, "The identity provider could not sign \(label(account)) in without asking (\(e.code ?? "")): their session there has ended.")
            } else if e.oauthError == "account_selection_required" {
                error = "Several accounts are signed in at the identity provider and the request did not say which; choose one."
            } else if e.code == "account_mismatch" {
                error = "You signed in as somebody else at the identity provider, not the account this app asked for. Nothing was changed."
            } else {
                error = "The \(what) failed: \(describe(e))"
            }
        } catch {
            self.error = "The \(what) failed: \(describe(error))"
        }
        await reload()
    }

    /// Makes another cached account the active account. Its stream catches up first.
    func activate(_ key: String) async {
        guard let accounts else { return }
        busy = "Switching to \(label(accountList.first(where: { $0.key == key }))): checking the signals queued for this account…"
        do { try await accounts.activate(key) } catch {
            self.error = "Could not switch to \(label(accountList.first(where: { $0.key == key }))): \(describe(error))"
        }
        busy = nil
        await reload()
    }

    /// Signs one account out of this app and at the IdP (its session only); the others stay signed in.
    func signOut(_ key: String? = nil) async {
        guard let accounts else { return }
        do { try await accounts.signOut(key, using: authenticator) } catch let e as OIDCError where e.isUserCancellation {
        } catch {
            self.error = "Sign-out failed: \(describe(error))"
        }
        await reload()
    }

    func signOutAll() async {
        guard let accounts else { return }
        do { try await accounts.signOutAll(using: authenticator) } catch let e as OIDCError where e.isUserCancellation {
        } catch {
            self.error = "Sign-out failed: \(describe(error))"
        }
        await reload()
    }

    // MARK: - Token cache actions

    func callUserInfo() async {
        guard let accounts, let client, let me = signedIn else { return }
        do {
            let info = try await client.userinfo(try await accounts.getTokenSet(), expectedSub: me.sub)
            userinfoOutput = info.jsonString(pretty: true)
        } catch {
            userinfoOutput = "UserInfo failed: \(describe(error))"
        }
        await reload()
    }

    func forceRefresh() async {
        guard let accounts else { return }
        do { try await accounts.refresh() } catch { self.error = "Refresh failed: \(describe(error))" }
        await reload()
    }

    // MARK: - CAEP: the app polls ONE stream, the active account's, authorised by its (DPoP-bound) access token.
    // A stream belongs to the principal that created it. With only ssf.read this client lists, gets and polls
    // the account's stream; ssf.manage is what creates, changes and deletes one. A dormant account's stream
    // keeps queueing events, and activating the account catches up on them before its tokens are used.

    private var transmitterIssuer: String { config?.ssfTransmitterIssuer ?? client?.issuer ?? "" }

    private var streamIDs: [String: String] {
        get { defaults.dictionary(forKey: Self.streamsKey) as? [String: String] ?? [:] }
        set { defaults.set(newValue, forKey: Self.streamsKey) }
    }

    /// The scopes the transmitter enforces: those in the access token, which may be narrower than requested.
    private func scopes(_ ts: TokenSet) -> [String] {
        let fromToken = decodeUnverifiedJWTPayload(ts.accessToken)?["scope"]?.stringValue ?? ""
        let list = (fromToken.isEmpty ? ts.scope ?? "" : fromToken).split(separator: " ").map(String.init)
        return list
    }

    /// Reads the display name and username. Profile claims are at UserInfo, not always in the ID token.
    private func rememberProfile(_ account: Account, _ access: AccountAccess) async {
        guard let client, let ts = try? await access.getTokenSet() else { return }
        let info = (try? await client.userinfo(ts, expectedSub: account.sub)) ?? [:]
        let full = [info.string("given_name"), info.string("family_name")].compactMap { $0 }.joined(separator: " ")
        let name = [full, info.string("name") ?? "", account.name ?? ""].first { !$0.isEmpty } ?? ""
        let accessClaims = decodeUnverifiedJWTPayload(ts.accessToken) ?? [:]
        let username = [info.string("preferred_username"), accessClaims["username"]?.stringValue, account.preferredUsername]
            .compactMap { $0 }.first { !$0.isEmpty } ?? ""
        guard !name.isEmpty || !username.isEmpty else { return }
        var labels = defaults.dictionary(forKey: Self.labelsKey) as? [String: [String]] ?? [:]
        labels[account.key] = [name, username]
        defaults.set(labels, forKey: Self.labelsKey)
    }

    /// onActivate: read the account's stream and act on what it queued while dormant.
    private func startCaep(_ account: Account, _ access: AccountAccess) async {
        guard config?.caepEnabled == true else { return }
        let key = account.key
        caepKey = key
        receiver = nil
        stream = StreamState(status: .connecting, transmitter: transmitterIssuer)
        do {
            let scopes = scopes(try await access.getTokenSet())
            guard scopes.contains("ssf.read") || scopes.contains("ssf.manage") else {
                note(key, .unavailable, "This sign-in was not issued ssf.read, so the app is not reading a stream.")
                return
            }
            let write = scopes.contains("ssf.manage")
            var r: SSFReceiver?
            if let held = streamIDs[key] {
                let attempt = makeReceiver(account, access, streamID: held)
                do {
                    try await attempt.start(catchUp: true)
                    r = attempt
                } catch {
                    await attempt.stop()
                    // The remembered stream is gone. Without ssf.manage, do not create a replacement.
                    r = write ? try await startNew(account, access) : try await adoptListed(account, access)
                }
            } else {
                r = write ? try await startNew(account, access) : try await adoptListed(account, access)
            }
            guard let r else {
                note(key, .noStream, "No stream for this account. This client reads with ssf.read and does not create one.")
                return
            }
            // A signal received while catching up ended the account, or another account was activated meanwhile.
            let status = await accounts?.get(key)?.status
            if caepKey != key || status != .signedIn {
                await r.stop()
                return
            }
            receiver = r
            let s = await r.stream ?? [:]
            if let id = s.string("stream_id") { streamIDs[key] = id }
            if write {
                do { try await syncEvents(r) } catch {
                    record(LogEntry(account: key, name: "subscription", action: "Could not update the stream's event types: \(describe(error))"))
                }
                if await r.metadata?["add_subject_endpoint"] != nil {
                    do { try await r.addSubject(Subject.issSub(account.iss, account.sub)) } catch {
                        record(LogEntry(account: key, name: "subject", action: "Could not add the subject: \(describe(error))"))
                    }
                }
            }
            await refreshStreamState(r, write: write)
            if write { Task { _ = try? await r.requestVerification(timeout: 30) } }
        } catch {
            // Shown on the stream card; the account is still activated so the person is not locked out by an
            // unreachable transmitter.
            if caepKey == key {
                stream = StreamState(status: .error, transmitter: transmitterIssuer, error: "Could not catch up: \(describe(error))")
            }
        }
    }

    private func startNew(_ account: Account, _ access: AccountAccess) async throws -> SSFReceiver {
        let r = makeReceiver(account, access, streamID: nil)
        try await r.start(catchUp: true)
        return r
    }

    /// Lists this account's streams and polls the first one. Does not create a stream.
    private func adoptListed(_ account: Account, _ access: AccountAccess) async throws -> SSFReceiver? {
        let probe = makeReceiver(account, access, streamID: nil)
        try await probe.discover()
        guard let id = try await probe.listStreams().compactMap({ $0.string("stream_id") }).first else { return nil }
        let r = makeReceiver(account, access, streamID: id)
        try await r.start(catchUp: true)
        return r
    }

    private func refreshStreamState(_ r: SSFReceiver, write: Bool) async {
        let s = await r.stream ?? [:]
        let aud = s["aud"].map { $0.stringValue ?? ($0.stringArrayValue ?? []).joined(separator: ", ") }
        stream = StreamState(status: .connected, transmitter: transmitterIssuer, streamStatus: s.string("status") ?? "enabled",
                             streamID: s.string("stream_id"), audience: aud, write: write)
    }

    private func note(_ key: String, _ status: StreamStatus, _ text: String) {
        guard caepKey == key else { return }
        stream = StreamState(status: status, transmitter: transmitterIssuer, note: text)
    }

    /// onDeactivate: stop polling; the stream stays at the transmitter and keeps queueing events.
    private func stopCaep(_ key: String) async {
        guard caepKey == key else { return }
        let r = receiver
        caepKey = nil
        receiver = nil
        stream = StreamState(status: config?.caepEnabled == true ? .waitingForUser : .disabled)
        await r?.stop()
    }

    /// onLeave: the account is signed out or ended. Delete its stream only when the token can write.
    private func deleteStream(_ account: Account, _ access: AccountAccess) async {
        await stopCaep(account.key)
        guard let id = streamIDs[account.key], config?.caepEnabled == true,
              let ts = try? await access.getTokenSet(), scopes(ts).contains("ssf.manage") else { return }
        streamIDs[account.key] = nil
        let r = makeReceiver(account, access, streamID: id)
        do {
            try await r.discover()
            await r.setStream(["stream_id": .string(id)])
            try await r.deleteStream()
        } catch {
            // Left at the transmitter, which removes a poll stream nobody polls (iya-sts: after
            // ssf.personStreamInactivityTimeoutS, a day by default).
        }
    }

    private func makeReceiver(_ account: Account, _ access: AccountAccess, streamID: String?) -> SSFReceiver {
        let client = self.client!
        let r = SSFReceiver(SSFReceiverConfiguration(
            transmitterIssuer: transmitterIssuer,
            // Every management and poll call carries THIS account's access token, with a DPoP proof when bound.
            authorization: .oidc(client) { try await access.getTokenSet() },
            eventsRequested: CAEP.all.filter(selectedEvents.contains),
            streamID: streamID,
            description: "swift-oidc-caep-native-app demo (\(label(account)))",
            pollInterval: 5,
            transport: transport ?? URLSessionTransport()))
        installHandlers(r, key: account.key, access: access)
        return r
    }

    /// Asks the transmitter for the selected event types when the stream asks for others. Needs ssf.manage.
    private func syncEvents(_ r: SSFReceiver) async throws {
        let want = CAEP.all.filter(selectedEvents.contains)
        let have = await r.stream?["events_requested"]?.stringArrayValue ?? []
        guard Set(want) != Set(have) else { return }
        try await r.updateStream(["events_requested": JSONValue(want)])
    }

    // MARK: - CAEP buttons

    func updateSubscription() async {
        defaults.set(Array(selectedEvents), forKey: Self.eventsKey)
        guard let r = receiver else { return }
        do {
            try await syncEvents(r)
            await refreshStreamState(r, write: stream.write)
        } catch {
            stream.error = "Could not update the subscription: \(describe(error))"
        }
    }

    func requestVerification() async {
        guard let r = receiver else { return }
        do {
            let evt = try await r.requestVerification(timeout: 30)
            stream.error = nil
            _ = evt
        } catch {
            stream.error = "Verification failed: \(describe(error))"
        }
    }

    func reconnect() async {
        guard let accounts, let key = caepKey ?? signedIn?.key else { return }
        await stopCaep(key)
        // Re-running the activation reconnects the stream (and catches up).
        do { try await accounts.activate(key) } catch { self.error = "Could not reconnect: \(describe(error))" }
        await reload()
    }

    // MARK: - Event policies: only events about this account (or its stream) are acted on.

    private func installHandlers(_ r: SSFReceiver, key: String, access: AccountAccess) {
        r.onSessionRevoked { [weak self] evt in
            await self?.handle(key, evt) { m in
                try await m.end(key, evt.reasonUser?["en"] ?? "The session was revoked by the identity provider.")
                return "Session ended; its cached tokens discarded. Other accounts are unaffected."
            }
        }
        .onTokenClaimsChange { [weak self] evt in
            await self?.handle(key, evt) { _ in
                _ = try await access.getTokenSet(forceRefresh: true)
                let claims = evt.payload["claims"]?.objectValue?.keys.sorted().joined(separator: ", ") ?? ""
                return "Refreshed tokens for new claims (\(claims.isEmpty ? "unspecified" : claims))."
            }
        }
        .onCredentialChange { [weak self] evt in
            await self?.handle(key, evt) { m in
                let type = evt.payload.string("credential_type") ?? "credential"
                let change = evt.payload.string("change_type")
                if change == "revoke" || change == "delete" {
                    try await m.end(key, "The \(type) was \(change!)d; sign in again.")
                    return "Credential \(change!)d: session ended."
                }
                m.perAccount[key, default: AccountState()].notices.insert(
                    Notice(level: .info, text: "The \(type) was \(change.map { "\($0)d" } ?? "changed") at the identity provider."), at: 0)
                return "User notified; session kept."
            }
        }
        .onAssuranceLevelChange { [weak self] evt in
            await self?.handle(key, evt) { m in
                let current = evt.payload.string("current_level") ?? "?", previous = evt.payload.string("previous_level") ?? "?"
                let down = evt.payload.string("change_direction") == "decrease"
                m.perAccount[key, default: AccountState()].stepUp = down ? "Assurance dropped from \(previous) to \(current)." : nil
                return down ? "Step-up authentication required." : "Step-up requirement cleared."
            }
        }
        .onDeviceComplianceChange { [weak self] evt in
            await self?.handle(key, evt) { m in
                guard evt.payload.string("current_status") == "not-compliant" else { return "Device compliant: no action." }
                try await m.end(key, "The device is no longer compliant with security policy.")
                return "Device not compliant: session ended."
            }
        }
        .onRiskLevelChange { [weak self] evt in
            await self?.handle(key, evt) { m in
                let level = evt.payload.string("current_level") ?? "?"
                let why = evt.payload.string("risk_reason") ?? "no reason given"
                if level == "HIGH" {
                    try await m.end(key, "High risk detected (\(why)).")
                    return "Risk HIGH: session ended."
                }
                m.perAccount[key, default: AccountState()].stepUp = level == "MEDIUM" ? "Risk raised to MEDIUM (\(why))." : nil
                return "Risk \(level): \(level == "MEDIUM" ? "step-up required" : "step-up cleared")."
            }
        }
        .onSessionEstablished { [weak self] evt in
            await self?.handle(key, evt) { _ in "Informational: new session at the IdP (acr=\(evt.payload.string("acr") ?? "n/a"))." }
        }
        .onSessionPresented { [weak self] evt in
            await self?.handle(key, evt) { _ in "Informational: session presented to another service." }
        }
        .onVerification { [weak self] evt in
            await self?.handle(key, evt) { _ in "Stream verified (state=\(evt.payload.string("state") ?? "none"))." }
        }
        .onStreamUpdated { [weak self] evt in
            await self?.handle(key, evt) { m in
                if m.caepKey == key { m.stream.streamStatus = evt.payload.string("status") }
                return "Transmitter set the stream to \"\(evt.payload.string("status") ?? "?")\"."
            }
        }
        .onUnhandledEvent { [weak self] evt in
            await self?.handle(key, evt) { _ in "No handler for \(evt.type)." }
        }
        .onError { [weak self] err, ctx in
            guard ctx.phase == .poll else { return }
            Task { @MainActor in
                guard let self, self.caepKey == key else { return }
                self.stream.error = "Last poll failed at \(Date().formatted(date: .omitted, time: .standard)): \(self.describe(err))"
            }
        }
    }

    /// Runs one event's policy when the event is about this account (or its stream), and logs what was done.
    private func handle(_ key: String, _ evt: SecurityEvent, _ policy: @MainActor (DemoModel) async throws -> String) async {
        // Poll delivery is at-least-once.
        if log.contains(where: { $0.jti == evt.jti && $0.account == key }) { return }
        let identity = await accounts?.identity(key)
        let mine = subjectMatches(evt.subject, identity)
        let streamID = caepKey == key ? stream.streamID ?? streamIDs[key] : nil
        let aboutStream = evt.subject == nil || (evt.subject?.string("format") == "opaque" && evt.subject?.string("id") == streamID)
        var action: String
        do {
            action = mine || aboutStream ? try await policy(self) : "Not about this account (or another of its sessions); ignored."
        } catch {
            action = "Handler failed: \(describe(error))"
        }
        if await accounts?.activeKey != key { action += " (caught up on activation)" }
        record(LogEntry(account: key, name: evt.name, type: evt.type, jti: evt.jti, subject: evt.subject.map { $0.jsonString(pretty: true) },
                        payload: evt.payload.jsonString(pretty: true), action: action))
        await reload()
    }

    private func end(_ key: String, _ reason: String) async throws {
        try await accounts?.end(key, reason: reason)
    }

    // MARK: - Event log

    /// The active account's entries, newest first.
    var activeLog: [LogEntry] { log.filter { $0.account == active?.key } }

    private func record(_ entry: LogEntry) {
        log.insert(entry, at: 0)
        if log.count > 300 { log.removeLast(log.count - 300) }
        saveLog()
    }

    func clearLog(_ key: String? = nil) {
        let key = key ?? active?.key
        log.removeAll { $0.account == key }
        saveLog()
    }

    private func saveLog() { defaults.set(try? JSONEncoder().encode(log), forKey: Self.logKey) }

    // MARK: - Labels

    /// `Display name (username)`, from UserInfo when it was read; the ID token's subject is not a name.
    func label(_ a: Account?) -> String {
        guard let a else { return "—" }
        let saved = (defaults.dictionary(forKey: Self.labelsKey) as? [String: [String]])?[a.key] ?? []
        let display = (saved.first.flatMap { $0.isEmpty ? nil : $0 } ?? a.name ?? "").trimmingCharacters(in: .whitespaces)
        let username = (saved.dropFirst().first.flatMap { $0.isEmpty ? nil : $0 } ?? a.preferredUsername ?? "").trimmingCharacters(in: .whitespaces)
        if !display.isEmpty, !username.isEmpty, display != username { return "\(display) (\(username))" }
        return [display, username, a.email ?? "", a.sub].first { !$0.isEmpty } ?? "—"
    }

    nonisolated func describe(_ error: Error) -> String {
        guard let e = error as? OIDCError else { return error.localizedDescription }
        var text = e.message
        if let status = e.status, !text.contains(String(status)) { text += " (HTTP \(status))" }
        if let response = e.response, case .object = response, !text.contains(response.jsonString()) { text += " \(response.jsonString())" }
        return String(text.prefix(600))
    }
}

extension SSFReceiver {
    /// Points the receiver at a known stream id without fetching it (to delete it).
    func setStream(_ s: JSONObject) { stream = s }
}
