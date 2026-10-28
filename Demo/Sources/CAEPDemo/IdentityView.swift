// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// The macOS front end (SwiftUI). The Linux one is in Linux/.
#if os(macOS)

import OIDCCAEPClient
import SwiftUI

struct IdentityView: View {
    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                HeroCard()
                SecurityCard()
                SessionCard()
                TokenCacheCard()
                TokensCard()
            }
            .padding(.vertical)
        }
    }
}

struct HeroCard: View {
    @Environment(DemoModel.self) private var model

    var body: some View {
        let cur = model.active
        let list = model.accountList
        Card(title: title(cur, list)) {
            Text("OpenID Connect").font(.caption.smallCaps()).foregroundStyle(.secondary)
            Text(text(cur, list)).foregroundStyle(.secondary)
            HStack {
                if let cur, cur.status == .tokensMissing {
                    Button("Continue as \(model.label(cur))") { Task { await model.resume(cur.key) } }.buttonStyle(.borderedProminent)
                } else if let cur, cur.status == .signedOut || cur.status == .ended {
                    Button("Sign in again as \(model.label(cur))") { Task { await model.reauthenticate(cur.key) } }.buttonStyle(.borderedProminent)
                }
                if model.client != nil {
                    if list.isEmpty {
                        Button("Sign in") { Task { await model.signIn() } }.buttonStyle(.borderedProminent)
                    } else {
                        Button("Sign in with another account") { Task { await model.addAccount() } }
                    }
                }
            }
        }
    }

    private func title(_ cur: Account?, _ list: [Account]) -> String {
        guard model.client != nil else { return "Identity provider" }
        guard let cur else {
            if list.contains(where: { $0.status == .signedIn }) { return "Choose an account" }
            return list.isEmpty ? "Sign in" : "Choose an account"
        }
        switch cur.status {
        case .signedIn: return "Signed in as \(model.label(cur))"
        case .tokensMissing: return "Continue as \(model.label(cur))"
        case .ended: return "\(model.label(cur))'s session was ended"
        case .signedOut: return "\(model.label(cur)) is signed out"
        }
    }

    private func text(_ cur: Account?, _ list: [Account]) -> String {
        guard model.client != nil else { return model.error == nil ? "Loading the OIDC configuration." : "The identity provider could not be reached." }
        guard let cur else {
            if list.contains(where: { $0.status == .signedIn }) { return "These accounts are signed in. Pick one from the menu under your name. No password is needed." }
            if !list.isEmpty { return "None of the accounts is signed in. Sign in again as one of them from the menu, or sign in with another account." }
            return "Sign in through your identity provider, in your browser. This app keeps the session and the tokens. CAEP events are on the other tab."
        }
        switch cur.status {
        case .signedIn: return "The session, token cache, and tokens for this account are below."
        case .tokensMissing: return "The tokens cached for this account have expired and cannot be refreshed. New ones can be fetched without a password while its session at the identity provider lasts."
        case .ended, .signedOut:
            let reason = cur.status == .ended ? (cur.endedReason.map { "\($0) " } ?? "") : ""
            return "\(reason)Sign in again as \(model.label(cur)), switch to another account, or sign in with another account."
        }
    }
}

struct SecurityCard: View {
    @Environment(DemoModel.self) private var model

    var body: some View {
        Card(title: "Protections in effect") {
            if let client = model.client {
                let f = client.securityFeatures
                ForEach(Array(items(f).enumerated()), id: \.offset) { _, item in
                    HStack(alignment: .firstTextBaseline) {
                        Image(systemName: "checkmark.shield").foregroundStyle(.green)
                        Text(item.0).bold()
                        Text(item.1).foregroundStyle(.secondary)
                    }
                    .font(.callout)
                }
            } else {
                Text("The identity provider has not been reached yet.").foregroundStyle(.secondary)
            }
        }
    }

    private func items(_ f: SecurityFeatures) -> [(String, String)] {
        [
            ("Public client", "no client secret; token_endpoint_auth_method none"),
            ("System browser", "sign-in in ASWebAuthenticationSession (RFC 8252); the app never sees the password"),
            ("Redirect URI", "private-use scheme \(model.config?.redirectURI.scheme ?? "")"),
            ("PKCE", f.pkce),
            ("state", f.state),
            ("nonce", "random, checked against the ID token"),
            ("Issuer identification", f.issuerIdentification),
            ("Pushed Authorization Requests", f.par ? "on: the request never passes through the browser URL" : "off"),
            ("DPoP", f.dpop.map { "on (\($0.alg), \(model.dpopStoreDescription), jkt \($0.jkt.prefix(12))…)" } ?? "off: bearer tokens"),
            ("ID token", f.idToken),
            ("TLS", f.tlsEnforced ? "required for the IdP (loopback excepted)" : "not enforced"),
            ("Token cache", "the Keychain (encrypted at rest), refreshed before expiry"),
            ("One active account", "only its tokens are reachable, refreshed and used to poll; the others stay dormant until activated, and their queued signals are acted on first"),
            ("Several accounts", "a sign-in naming an account refuses anybody else; sign-out names the account's ID token so only its IdP session ends"),
            ("Resource indicators", f.resourceIndicators.isEmpty ? "none" : f.resourceIndicators.joined(separator: ", ")),
        ]
    }
}

struct SessionCard: View {
    @Environment(DemoModel.self) private var model

    var body: some View {
        let me = model.signedIn
        let stepUp = me.flatMap { model.state($0.key).stepUp }
        Card(title: me.map { "Session · \(model.label($0))" } ?? "Session") {
            Pill(text: me == nil ? "Signed out" : stepUp != nil ? "Step-up required" : "Active",
                 color: me == nil ? .secondary : stepUp != nil ? .orange : .green)
        } content: {
            if let me {
                let claims = model.currentTokens?.claims ?? me.claims
                let shown = ["sub", "name", "email", "preferred_username", "acr", "amr", "sid", "iss", "auth_time"]
                KeyValues(rows: shown.compactMap { k in
                    guard let v = claims[k] else { return nil }
                    if k == "auth_time", let t = v.doubleValue { return (k, Date(timeIntervalSince1970: t).formatted(date: .abbreviated, time: .standard)) }
                    return (k, v.stringValue ?? v.jsonString())
                })
            } else {
                Text("No one is signed in.").foregroundStyle(.secondary)
            }
        }
    }
}

struct TokenCacheCard: View {
    @Environment(DemoModel.self) private var model

    var body: some View {
        let me = model.signedIn
        let s = me.map { model.state($0.key) }
        Card(title: "Token cache") {
            if let s { Text("\(s.refreshCount) refreshes").font(.caption).foregroundStyle(.secondary) }
        } content: {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                let ts = model.currentTokens
                let now = context.date
                VStack(alignment: .leading, spacing: 10) {
                    ProgressView(value: fraction(ts, now))
                        .tint(fraction(ts, now) < 0.2 ? .orange : .accentColor)
                    HStack(spacing: 30) {
                        stat(ts?.expiresIn(now: now).map(duration) ?? "—", "access token expires in")
                        stat(autoRefresh(ts, now), "auto-refresh in")
                        stat(s?.lastRefresh.map { $0.formatted(date: .omitted, time: .standard) } ?? "—", "last refresh")
                    }
                }
            }
            HStack {
                Button("Call UserInfo") { Task { await model.callUserInfo() } }.disabled(me == nil)
                Button("Force refresh") { Task { await model.forceRefresh() } }.disabled(me == nil)
            }
            if let out = model.userinfoOutput {
                ScrollView(.horizontal) {
                    Text(out).font(.caption.monospaced()).textSelection(.enabled).padding(6)
                }
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
            }
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
            Text(value).font(.title3.monospacedDigit().bold())
            Text(caption).font(.caption).foregroundStyle(.secondary)
        }
    }
}

struct TokensCard: View {
    @Environment(DemoModel.self) private var model
    @State private var which = "signIn"

    var body: some View {
        Card(title: "Tokens") {
            Picker("Which tokens", selection: $which) {
                Text("At sign-in").tag("signIn")
                Text("Current").tag("current")
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 260)
            let ts: TokenSet? = which == "current" ? model.currentTokens
                : (model.signInTokens?.key == model.signedIn?.key ? model.signInTokens?.tokenSet : nil)
            if let ts {
                TokenView(title: "Access token (\(ts.tokenType))", token: ts.accessToken)
                if let id = ts.idToken { TokenView(title: "ID token", token: id) }
                if let rt = ts.refreshToken { TokenView(title: "Refresh token", token: rt, opaqueNote: "An opaque token: there is nothing to decode.") }
            } else {
                Text(which == "current" ? "No tokens until someone is signed in." : "The tokens from this session's last sign-in appear here.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }
}

/// One token. A JWT gets two tabs: the encoded token as received, and its header and payload decoded.
struct TokenView: View {
    let title: String
    let token: String
    var opaqueNote = "Not a JWT: there is nothing to decode."
    @State private var format = "encoded"

    var body: some View {
        DisclosureGroup {
            VStack(alignment: .leading, spacing: 6) {
                if let header = try? decodeProtectedHeader(token), let payload = decodeUnverifiedJWTPayload(token) {
                    Picker("Format", selection: $format) {
                        Text("Encoded JWT").tag("encoded")
                        Text("Decoded JWT (Header + Payload)").tag("decoded")
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    if format == "decoded" {
                        Text("Header").font(.caption.bold())
                        codeBox(header.jsonString(pretty: true))
                        Text("Payload").font(.caption.bold())
                        codeBox(payload.jsonString(pretty: true))
                        Text("Decoded for display. The library validated the signature and claims when the token was issued.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        codeBox(token)
                    }
                } else {
                    codeBox(token)
                    Text(opaqueNote).font(.caption).foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text(title).font(.callout.bold())
        }
    }

    private func codeBox(_ text: String) -> some View {
        ScrollView {
            Text(text).font(.caption.monospaced()).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
        }
        .frame(maxHeight: 200)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
    }
}
#endif
