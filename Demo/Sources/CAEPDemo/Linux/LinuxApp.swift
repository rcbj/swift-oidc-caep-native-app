// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// The Linux front end: GTK 4 through SwiftCrossUI, for GNOME and KDE desktops. It shows the same model
// (DemoModel.swift) as the macOS SwiftUI front end, in the same layout: a top bar with the account menu,
// banners, and two tabs, Identity and CAEP events.
#if os(Linux)
import Foundation
import GtkBackend
import OIDCCAEPClient
import SwiftCrossUI

/// The one model the window shows.
@MainActor
enum Shared {
    static let model = DemoModel()
}

@main
struct CAEPDemoLinuxApp: App {
    typealias Backend = GtkBackend

    /// `--version` prints the version and exits, without opening a window (the AppImage's smoke test).
    init() {
        // A light theme, whatever the desktop's: the demo's colours below are chosen for it.
        // GTK_THEME set in the environment wins.
        if ProcessInfo.processInfo.environment["GTK_THEME"] == nil { setenv("GTK_THEME", "Adwaita", 1) }
        if CommandLine.arguments.contains("--version") {
            print("CAEP Demo \(demoVersion) (OIDCCAEPClient, GTK)")
            exit(0)
        }
    }

    var body: some Scene {
        WindowGroup("CAEP Demo") {
            DemoWindow()
        }
        .defaultSize(width: 900, height: 760)
    }
}

let demoVersion = "0.1"

/// The window's colours: a pale page, white bordered cards with tinted title bars, field names in blue.
enum Palette {
    static let page = Color(red: 0.94, green: 0.95, blue: 0.97)
    static let card = Color(red: 1, green: 1, blue: 1)
    static let border = Color(red: 0.72, green: 0.75, blue: 0.80)
    static let cardTitle = Color(red: 0.86, green: 0.90, blue: 0.97)
    static let titleText = Color(red: 0.08, green: 0.20, blue: 0.42)
    static let field = Color(red: 0.12, green: 0.32, blue: 0.62)
    static let value = Color(red: 0.10, green: 0.10, blue: 0.12)
    static let muted = Color(red: 0.38, green: 0.40, blue: 0.45)
    static let code = Color(red: 0.96, green: 0.97, blue: 0.98)
    static let ok = Color(red: 0.10, green: 0.50, blue: 0.20)
    static let warn = Color(red: 0.70, green: 0.40, blue: 0.00)
    static let bad = Color(red: 0.75, green: 0.12, blue: 0.12)
    static let infoFill = Color(red: 0.90, green: 0.94, blue: 1.00)
    static let warnFill = Color(red: 1.00, green: 0.95, blue: 0.86)
    static let badFill = Color(red: 1.00, green: 0.91, blue: 0.91)
}

extension View {
    /// The view on a filled, bordered, rounded box.
    func boxed(fill: Color, stroke: Color = Palette.border, radius: Double = 8) -> some View {
        background {
            RoundedRectangle(cornerRadius: radius).fill(fill)
            RoundedRectangle(cornerRadius: radius).stroke(stroke)
        }
    }
}

/// The window. SwiftCrossUI redraws on its own state, not on Swift Observation, so `tick` is bumped every
/// second (the token countdowns need that anyway) and after every action; each redraw reads the model afresh.
struct DemoWindow: View {
    @State var tick = 0
    @State var tab = "identity"
    @State var started = false
    @State var tokenView = "signIn"
    /// Per token ("access", "id"): "encoded" or "decoded".
    @State var tokenFormats: [String: String] = [:]

    var model: DemoModel { Shared.model }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("").frame(width: 0, height: 0).padding(tick < 0 ? 1 : 0)  // reads tick, so every tick redraws
            topBar
            banners
            HStack(spacing: 6) {
                Toggle("Identity", isOn: tabBinding("identity")).toggleStyle(.button)
                Toggle("CAEP events", isOn: tabBinding("caep")).toggleStyle(.button)
                Spacer()
                Text(tab == "identity" ? "Sign-in, session and tokens" : "The active account's CAEP stream and events")
                    .foregroundColor(Palette.muted)
            }
            .padding(6)
            .boxed(fill: Palette.cardTitle)
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if tab == "identity" { identity } else { caepTab }
                }
                .padding(12)
            }
            .boxed(fill: Palette.page)
        }
        .padding(12)
        .background(Palette.page)
        .onAppear {
            guard !started else { return }
            started = true
            Task { @MainActor in await model.start(); tick += 1 }
            Task { @MainActor in
                while true {
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                    tick += 1
                }
            }
        }
    }

    private func tabBinding(_ name: String) -> Binding<Bool> {
        Binding(get: { tab == name }, set: { if $0 { tab = name } })
    }

    /// Runs an action of the model, then redraws.
    private func run(_ action: @escaping @MainActor () async -> Void) {
        Task { @MainActor in
            await action()
            tick += 1
        }
    }

    // MARK: - Top bar and account menu

    @ViewBuilder var topBar: some View {
        HStack(spacing: 10) {
            Text("◆ CAEP Demo").font(.title3).bold().foregroundColor(Palette.titleText)
            Text("OIDCCAEPClient · native public client (GTK)").font(.caption).foregroundColor(Palette.muted)
            Spacer()
            accountMenu
        }
        .padding(8)
        .boxed(fill: Palette.card)
    }

    @ViewBuilder var accountMenu: some View {
        if model.client != nil {
            if model.accountList.isEmpty {
                Button("Sign in") { run { await model.signIn() } }
            } else {
                Menu(model.active.map { menuLabel($0) } ?? "Choose an account") {
                    ForEach(choices(), id: \.key) { a in
                        Button(a.status == .signedIn ? "Switch to \(menuLabel(a))" : "\(menuLabel(a)) — \(statusName(a.status)): sign in again") {
                            if a.status == .signedIn { run { await model.activate(a.key) } } else { run { await model.reauthenticate(a.key) } }
                        }
                    }
                    Divider()
                    Button("Sign in with another account") { run { await model.addAccount() } }
                    Divider()
                    if let cur = model.active, cur.status == .signedIn {
                        Button("Sign out \(menuLabel(cur))") { run { await model.signOut() } }
                    }
                    Button("Sign out of all accounts") { run { await model.signOutAll() } }
                }
            }
        }
    }

    /// The other accounts, and the active one while it has no session (choosing it signs it in).
    private func choices() -> [Account] {
        let cur = model.active
        let others = model.accountList.filter { $0.key != cur?.key }
        if let cur, cur.status != .signedIn { return [cur] + others }
        return others
    }

    private func menuLabel(_ a: Account) -> String {
        let full = model.label(a)
        return full.count > 64 ? String(full.prefix(63)) + "…" : full
    }

    // MARK: - Banners

    @ViewBuilder var banners: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let busy = model.busy { banner(busy, .blue) }
            if let error = model.error {
                HStack {
                    banner(error, .red)
                    Button("Dismiss") { model.error = nil; tick += 1 }
                }
            }
            if let attention = model.attention {
                HStack {
                    banner(attention.text, .orange)
                    Button("Sign in again") { run { await model.reauthenticate(attention.key) } }
                }
            }
            if let me = model.signedIn, let stepUp = model.state(me.key).stepUp {
                HStack {
                    banner("\(stepUp) Sign in again to restore access.", .orange)
                    Button("Step up") { run { await model.reauthenticate(me.key) } }
                }
            }
            if let me = model.signedIn {
                ForEach(model.state(me.key).notices, id: \.id) { n in banner(n.text, .blue) }
            }
            if let me = model.active, me.status == .ended, let reason = model.ended[me.key] ?? me.endedReason {
                banner("\(model.label(me))'s session was ended: \(reason)", .red)
            }
            ForEach(Array(model.notices.prefix(3)), id: \.id) { n in banner(n.text, .blue) }
        }
    }

    private func banner(_ text: String, _ color: Color) -> some View {
        let (fill, ink): (Color, Color) = color == .red ? (Palette.badFill, Palette.bad)
            : color == .orange ? (Palette.warnFill, Palette.warn) : (Palette.infoFill, Palette.titleText)
        return Text(text).foregroundColor(ink).textSelectionEnabled()
            .padding(8)
            .frame(maxWidth: Double.infinity, alignment: .leading)
            .boxed(fill: fill, stroke: ink)
    }

    // MARK: - Identity tab

    @ViewBuilder var identity: some View {
        VStack(alignment: .leading, spacing: 12) {
            card(heroTitle) { hero }
            card("Protections in effect") { protections }
            card(model.signedIn.map { "Session · \(model.label($0))" } ?? "Session") { session }
            card("Token cache") { tokenCache }
            card("Tokens") { tokens }
        }
    }

    private func card<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(title).font(.headline).foregroundColor(Palette.titleText)
                .padding(8)
                .frame(maxWidth: Double.infinity, alignment: .leading)
                .background(Palette.cardTitle)
            VStack(alignment: .leading, spacing: 8) { content() }
                .padding(10)
                .frame(maxWidth: Double.infinity, alignment: .leading)
        }
        .boxed(fill: Palette.card)
    }

    /// One field: its name (blue, bold) and its value (dark, wrapping, selectable).
    private func field(_ name: String, _ value: String) -> some View {
        HStack(spacing: 12) {
            Text(name).bold().foregroundColor(Palette.field).frame(width: 190, alignment: .leading)
            Text(value).foregroundColor(Palette.value).textSelectionEnabled()
                .frame(maxWidth: Double.infinity, alignment: .leading)
        }
    }

    /// Long text (tokens, JSON) in a bordered box that scrolls.
    private func scrollBox(_ text: String, height: Int = 160) -> some View {
        ScrollView {
            Text(text).font(.caption).fontDesign(.monospaced).foregroundColor(Palette.value).textSelectionEnabled()
                .padding(8)
                .frame(maxWidth: Double.infinity, alignment: .leading)
        }
        .frame(height: height)
        .boxed(fill: Palette.code, radius: 4)
    }

    private func note(_ text: String) -> some View {
        Text(text).foregroundColor(Palette.muted)
    }

    private var heroTitle: String {
        guard model.client != nil else { return "Identity provider" }
        guard let cur = model.active else { return model.accountList.isEmpty ? "Sign in" : "Choose an account" }
        switch cur.status {
        case .signedIn: return "Signed in as \(model.label(cur))"
        case .tokensMissing: return "Continue as \(model.label(cur))"
        case .ended: return "\(model.label(cur))'s session was ended"
        case .signedOut: return "\(model.label(cur)) is signed out"
        }
    }

    @ViewBuilder var hero: some View {
        if model.client == nil {
            note(model.error == nil ? "Loading the OIDC configuration." : "The identity provider could not be reached.")
        } else {
            Text(heroText).foregroundColor(Palette.value)
            HStack {
                if let cur = model.active, cur.status == .tokensMissing {
                    Button("Continue as \(model.label(cur))") { run { await model.resume(cur.key) } }
                } else if let cur = model.active, cur.status == .signedOut || cur.status == .ended {
                    Button("Sign in again as \(model.label(cur))") { run { await model.reauthenticate(cur.key) } }
                }
                if model.accountList.isEmpty {
                    Button("Sign in") { run { await model.signIn() } }
                } else {
                    Button("Sign in with another account") { run { await model.addAccount() } }
                }
            }
        }
    }

    private var heroText: String {
        guard let cur = model.active else {
            if model.accountList.contains(where: { $0.status == .signedIn }) { return "These accounts are signed in. Pick one from the account menu. No password is needed." }
            return "Sign in through your identity provider, in your browser. This app keeps the session and the tokens. CAEP events are on the other tab."
        }
        switch cur.status {
        case .signedIn: return "The session, token cache, and tokens for this account are below."
        case .tokensMissing: return "The cached tokens have expired and cannot be refreshed. New ones can be fetched without a password while the session at the identity provider lasts."
        case .ended, .signedOut:
            let reason = cur.status == .ended ? (cur.endedReason.map { "\($0) " } ?? "") : ""
            return "\(reason)Sign in again as \(model.label(cur)), switch to another account, or sign in with another account."
        }
    }

    @ViewBuilder var protections: some View {
        if let client = model.client {
            let f = client.securityFeatures
            ForEach(protectionItems(f), id: \.0) { item in field("✔ \(item.0)", item.1) }
        } else {
            note("The identity provider has not been reached yet.")
        }
    }

    private func protectionItems(_ f: SecurityFeatures) -> [(String, String)] {
        [
            ("Public client", "no client secret; token_endpoint_auth_method none"),
            ("System browser", "sign-in in your default browser (xdg-open); the app never sees the password"),
            ("Redirect URI", "loopback \(model.config?.redirectURI.absoluteString ?? "") (RFC 8252 §7.3), listened on only during a sign-in"),
            ("PKCE", f.pkce),
            ("state", f.state),
            ("nonce", "random, checked against the ID token"),
            ("Issuer identification", f.issuerIdentification),
            ("Pushed Authorization Requests", f.par ? "on: the request never passes through the browser URL" : "off"),
            ("DPoP", f.dpop.map { "on (\($0.alg), \(model.dpopStoreDescription), jkt \($0.jkt.prefix(12))…)" } ?? "off: bearer tokens"),
            ("ID token", f.idToken),
            ("TLS", model.config?.insecureSkipTLSVerification == true ? "VERIFICATION OFF (InsecureSkipTLSVerification)"
                : model.config?.tlsTrust != nil ? "required; extra trusted certificates configured" : "required (loopback excepted)"),
            ("Token cache", "memory: Linux has no secure storage this library uses, so a restart means signing in again"),
            ("One active account", "only its tokens are reachable, refreshed and used to poll; the others stay dormant"),
            ("Resource indicators", f.resourceIndicators.isEmpty ? "none" : f.resourceIndicators.joined(separator: ", ")),
        ]
    }

    @ViewBuilder var session: some View {
        if let me = model.signedIn {
            let stepUp = model.state(me.key).stepUp
            Text(stepUp != nil ? "● Step-up required" : "● Active").bold().foregroundColor(stepUp != nil ? Palette.warn : Palette.ok)
            let claims = model.currentTokens?.claims ?? me.claims
            ForEach(sessionRows(claims), id: \.0) { row in field(row.0, row.1) }
        } else {
            note("No one is signed in.")
        }
    }

    private func sessionRows(_ claims: JSONObject) -> [(String, String)] {
        ["sub", "name", "email", "preferred_username", "acr", "amr", "sid", "iss", "auth_time"].compactMap { k in
            guard let v = claims[k] else { return nil }
            if k == "auth_time", let t = v.doubleValue { return (k, Date(timeIntervalSince1970: t).formatted(date: .abbreviated, time: .standard)) }
            return (k, v.stringValue ?? v.jsonString())
        }
    }

    @ViewBuilder var tokenCache: some View {
        let me = model.signedIn
        let ts = model.currentTokens
        let now = Date()
        ProgressView(value: fraction(ts, now)).frame(maxWidth: 400)
        HStack(spacing: 30) {
            stat(ts?.expiresIn(now: now).map(duration) ?? "—", "access token expires in")
            stat(autoRefresh(ts, now), "auto-refresh in")
            stat(me.flatMap { model.state($0.key).lastRefresh?.formatted(date: .omitted, time: .standard) } ?? "—", "last refresh")
            stat(me.map { "\(model.state($0.key).refreshCount)" } ?? "—", "refreshes")
        }
        HStack {
            Button("Call UserInfo") { run { await model.callUserInfo() } }.frame(minWidth: 130).disabled(me == nil)
            Button("Force refresh") { run { await model.forceRefresh() } }.frame(minWidth: 130).disabled(me == nil)
        }
        if let out = model.userinfoOutput {
            Text("UserInfo response").bold().foregroundColor(Palette.field)
            scrollBox(out, height: 140)
        }
    }

    private func fraction(_ ts: TokenSet?, _ now: Date) -> Double {
        guard let ts, let exp = ts.expiresAt, let iat = ts.issuedAt, exp > iat else { return 0 }
        return max(0, min(1, (Double(exp) - now.timeIntervalSince1970) / Double(exp - iat)))
    }

    private func autoRefresh(_ ts: TokenSet?, _ now: Date) -> String {
        guard let ts, let exp = ts.expiresAt, ts.refreshToken != nil else { return "—" }
        return duration(max(0, Int(Double(exp) - ts.effectiveSkew(60) - now.timeIntervalSince1970)))
    }

    private func duration(_ seconds: Int) -> String { seconds >= 60 ? "\(seconds / 60)m \(seconds % 60)s" : "\(seconds)s" }

    private func stat(_ value: String, _ caption: String) -> some View {
        VStack(alignment: .leading) {
            Text(value).font(.title3).bold().foregroundColor(Palette.value)
            Text(caption).font(.caption).foregroundColor(Palette.field)
        }
        .padding(8)
        .boxed(fill: Palette.code, radius: 6)
    }

    @ViewBuilder var tokens: some View {
        HStack(spacing: 6) {
            Toggle("At sign-in", isOn: Binding(get: { tokenView == "signIn" }, set: { if $0 { tokenView = "signIn" } })).toggleStyle(.button)
            Toggle("Current", isOn: Binding(get: { tokenView == "current" }, set: { if $0 { tokenView = "current" } })).toggleStyle(.button)
        }
        let ts: TokenSet? = tokenView == "current" ? model.currentTokens
            : (model.signInTokens?.key == model.signedIn?.key ? model.signInTokens?.tokenSet : nil)
        if let ts {
            tokenSection("access", "Access token (\(ts.tokenType))", ts.accessToken)
            if let id = ts.idToken { tokenSection("id", "ID token", id) }
            if let rt = ts.refreshToken { tokenSection("refresh", "Refresh token", rt) }
        } else {
            note(tokenView == "current" ? "No tokens until someone is signed in." : "The tokens from this session's last sign-in appear here.")
        }
    }

    /// One token, in its own bordered box. A JWT gets two tabs: the encoded token as received, and its header
    /// and payload decoded. Anything else (a refresh token, an opaque access token) is shown as it is.
    @ViewBuilder
    private func tokenSection(_ kind: String, _ title: String, _ token: String) -> some View {
        let header = try? decodeProtectedHeader(token)
        let payload = decodeUnverifiedJWTPayload(token)
        let format = tokenFormats[kind] ?? "encoded"
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Text(title).bold().foregroundColor(Palette.titleText)
                Spacer()
                if header != nil, payload != nil {
                    Toggle("Encoded JWT", isOn: formatBinding(kind, "encoded")).toggleStyle(.button)
                    Toggle("Decoded JWT (Header + Payload)", isOn: formatBinding(kind, "decoded")).toggleStyle(.button)
                }
            }
            if let header, let payload {
                if format == "decoded" {
                    Text("Header").bold().foregroundColor(Palette.field)
                    scrollBox(header.jsonString(pretty: true), height: 110)
                    Text("Payload").bold().foregroundColor(Palette.field)
                    scrollBox(payload.jsonString(pretty: true), height: 220)
                    note("Decoded for display. The library validated the signature and claims when the token was issued.")
                } else {
                    scrollBox(token, height: 120)
                }
            } else {
                scrollBox(token, height: 60)
                note(kind == "refresh" ? "An opaque token: there is nothing to decode." : "Not a JWT: there is nothing to decode.")
            }
        }
        .padding(8)
        .boxed(fill: Palette.code, radius: 6)
    }

    private func formatBinding(_ kind: String, _ format: String) -> Binding<Bool> {
        Binding(get: { (tokenFormats[kind] ?? "encoded") == format },
                set: { if $0 { tokenFormats[kind] = format } })
    }

    // MARK: - CAEP events tab

    @ViewBuilder var caepTab: some View {
        let me = model.signedIn
        let st = me != nil && model.caepKey == me?.key ? model.stream
            : StreamState(status: model.config?.caepEnabled == false ? .disabled : model.busy != nil ? .connecting : .waitingForUser)
        VStack(alignment: .leading, spacing: 12) {
            card(me.map { "CAEP stream · \(model.label($0))" } ?? "CAEP stream") {
                Text("● \(st.status == .connected ? st.streamStatus ?? "enabled" : streamName(st.status))").bold()
                    .foregroundColor(st.status == .connected ? Palette.ok : st.status == .error ? Palette.bad : Palette.warn)
                ForEach(streamRows(st), id: \.0) { row in field(row.0, row.1) }
                Text("Event types this stream asks for").bold().foregroundColor(Palette.field)
                ForEach(CAEP.all, id: \.self) { uri in
                    Toggle(eventName(uri), isOn: Binding(
                        get: { model.selectedEvents.contains(uri) },
                        set: { on in if on { model.selectedEvents.insert(uri) } else { model.selectedEvents.remove(uri) }; tick += 1 }))
                        .toggleStyle(.checkbox)
                }
                HStack {
                    Button("Update subscription") { run { await model.updateSubscription() } }.disabled(st.status != .connected || !st.write)
                    Button("Request verification event") { run { await model.requestVerification() } }.disabled(st.status != .connected || !st.write)
                    Button("Reconnect stream") { run { await model.reconnect() } }.disabled(me == nil)
                }
                if !st.write { note("Updating the subscription and verification need ssf.manage.") }
                if let error = st.error { banner(error, .red) }
            }
            card("Event log") {
                HStack {
                    Text(model.stream.status == .connected ? "● polling" : "○ not polling").bold()
                        .foregroundColor(model.stream.status == .connected ? Palette.ok : Palette.muted)
                    Button("Clear") { model.clearLog(); tick += 1 }
                }
                let entries = model.activeLog
                if entries.isEmpty {
                    note("No CAEP events yet. Sign in, then trigger an event at your identity provider (for example, revoke your session).")
                }
                ForEach(entries, id: \.id) { e in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(e.name).bold().foregroundColor(Palette.titleText)
                            Spacer()
                            Text(e.at.formatted(date: .omitted, time: .standard)).foregroundColor(Palette.muted)
                        }
                        field("action", e.action)
                        if let subject = e.subject { Text("subject").bold().foregroundColor(Palette.field); scrollBox(subject, height: 90) }
                        if let payload = e.payload { Text("payload").bold().foregroundColor(Palette.field); scrollBox(payload, height: 110) }
                    }
                    .padding(8)
                    .boxed(fill: Palette.code, radius: 6)
                }
            }
        }
    }

    private func streamRows(_ st: StreamState) -> [(String, String)] {
        var r: [(String, String)] = [("transmitter", st.transmitter ?? model.config?.ssfTransmitterIssuer ?? model.client?.issuer ?? "—")]
        if let id = st.streamID { r += [("stream_id", id), ("delivery", "poll (RFC 8936)"), ("SET audience", st.audience ?? "—")] }
        if st.status == .waitingForUser { r.append(("note", "Sign in. The app reads the active account's stream when its access token carries ssf.read.")) }
        if let note = st.note { r.append(("note", note)) }
        if model.accountList.count > 1 { r.append(("other accounts", "dormant: their streams keep queueing, and are caught up when the account is activated")) }
        return r
    }

    private func streamName(_ s: StreamStatus) -> String {
        switch s {
        case .disabled: return "disabled"
        case .waitingForUser: return "waiting-for-user"
        case .connecting: return "connecting"
        case .connected: return "enabled"
        case .unavailable: return "unavailable"
        case .noStream: return "no-stream"
        case .error: return "error"
        }
    }

    private func statusName(_ s: Account.Status) -> String {
        switch s {
        case .signedIn: return "signed in"
        case .tokensMissing: return "tokens expired"
        case .signedOut: return "signed out"
        case .ended: return "session ended"
        }
    }
}
#endif
