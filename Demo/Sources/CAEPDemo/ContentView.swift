// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import OIDCCAEPClient
import SwiftUI

struct ContentView: View {
    @Environment(DemoModel.self) private var model
    @AppStorage("caep-demo.page-tab") private var tab = "identity"

    var body: some View {
        VStack(spacing: 0) {
            TopBar()
            Banners()
            TabView(selection: $tab) {
                IdentityView()
                    .tabItem { Text("Identity") }
                    .tag("identity")
                CAEPView()
                    .tabItem { Text("CAEP events") }
                    .tag("caep")
            }
            .padding([.horizontal, .bottom])
        }
    }
}

// MARK: - Top bar and account menu

struct TopBar: View {
    @Environment(DemoModel.self) private var model

    var body: some View {
        HStack(spacing: 10) {
            Text("◆").foregroundStyle(.tint)
            Text("CAEP Demo").font(.headline)
            Text("OIDCCAEPClient · native public client").font(.caption).foregroundStyle(.secondary)
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(.quaternary, in: Capsule())
            Spacer()
            AccountMenu()
        }
        .padding(.horizontal)
        .padding(.vertical, 10)
        .background(.bar)
    }
}

struct AccountMenu: View {
    @Environment(DemoModel.self) private var model

    var body: some View {
        if model.client == nil {
            EmptyView()
        } else if model.accountList.isEmpty {
            Button("Sign in") { Task { await model.signIn() } }.buttonStyle(.borderedProminent)
        } else {
            let current = model.active
            let others = model.accountList.filter { $0.key != current?.key }
            // The active account is listed too while it has no session, so that choosing it signs it in.
            let choices = current.map { $0.status != .signedIn ? [$0] + others : others } ?? others
            Menu {
                Section("Switch account") {
                    if choices.isEmpty { Text("No other account yet.") }
                    ForEach(choices) { a in
                        Button {
                            // An account with no session can only come back through a sign-in that names it.
                            Task {
                                if a.status == .signedIn { await model.activate(a.key) } else { await model.reauthenticate(a.key) }
                            }
                        } label: {
                            Text(a.status == .signedIn ? menuLabel(a) : "\(menuLabel(a)) — \(statusText(a.status))")
                        }
                    }
                }
                Divider()
                Button("Sign in with another account") { Task { await model.addAccount() } }
                Text("Switching changes the active account only. The account you leave stays signed in, dormant, and switching back needs no password.")
                Divider()
                if let current, current.status == .signedIn {
                    Button("Sign out \(menuLabel(current))") { Task { await model.signOut() } }
                }
                Button("Sign out of all accounts") { Task { await model.signOutAll() } }
            } label: {
                HStack(spacing: 6) {
                    Avatar(text: model.label(current))
                    Text(current.map(menuLabel) ?? "Choose an account").lineLimit(1)
                }
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .help(current.map { model.label($0) } ?? "")
        }
    }

    /// Labels of up to 64 characters; a longer one is cut, ending in "…".
    private func menuLabel(_ a: Account) -> String {
        let full = model.label(a)
        return full.count > 64 ? String(full.prefix(63)) + "…" : full
    }
}

struct Avatar: View {
    let text: String
    var body: some View {
        Text(String(text.first ?? "?").uppercased())
            .font(.caption.bold())
            .frame(width: 22, height: 22)
            .background(Color.accentColor.opacity(0.2), in: Circle())
    }
}

func statusText(_ s: Account.Status) -> String {
    switch s {
    case .signedIn: return "Signed in"
    case .tokensMissing: return "Tokens expired"
    case .signedOut: return "Signed out"
    case .ended: return "Session ended"
    }
}

// MARK: - Banners

struct Banners: View {
    @Environment(DemoModel.self) private var model

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 6) {
            if let busy = model.busy { Banner(level: .info, text: busy) }
            if let error = model.error { Banner(level: .danger, text: error) { model.error = nil } }
            if let attention = model.attention {
                Banner(level: .warn, text: attention.text, action: ("Sign in again", { Task { await model.reauthenticate(attention.key) } })) { model.attention = nil }
            }
            if let me = model.signedIn {
                let s = model.state(me.key)
                if let stepUp = s.stepUp {
                    Banner(level: .warn, text: "\(stepUp) Sign in again to restore access.",
                           action: ("Step up", { Task { await model.reauthenticate(me.key) } }))
                }
                ForEach(s.notices) { n in Banner(level: n.level, text: n.text) }
            }
            if let me = model.active, me.status == .ended, let reason = model.ended[me.key] ?? me.endedReason {
                Banner(level: .danger, text: "\(model.label(me))'s session was ended: \(reason)")
            }
            ForEach(model.notices.prefix(3)) { n in
                Banner(level: n.level, text: n.text) { model.notices.removeAll { $0.id == n.id } }
            }
        }
        .padding(.horizontal)
        .padding(.top, 6)
    }
}

struct Banner: View {
    let level: Notice.Level
    let text: String
    var action: (String, () -> Void)?
    var dismiss: (() -> Void)?

    init(level: Notice.Level, text: String, action: (String, () -> Void)? = nil, dismiss: (() -> Void)? = nil) {
        self.level = level
        self.text = text
        self.action = action
        self.dismiss = dismiss
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: level == .danger ? "exclamationmark.octagon" : level == .warn ? "exclamationmark.triangle" : "info.circle")
            Text(text).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
            if let action { Button(action.0, action: action.1) }
            if let dismiss { Button { dismiss() } label: { Image(systemName: "xmark") }.buttonStyle(.borderless) }
        }
        .font(.callout)
        .padding(8)
        .background(color.opacity(0.15), in: RoundedRectangle(cornerRadius: 6))
    }

    private var color: Color { level == .danger ? .red : level == .warn ? .orange : .blue }
}

// MARK: - Shared pieces

struct Card<Content: View, Accessory: View>: View {
    let title: String
    @ViewBuilder var accessory: () -> Accessory
    @ViewBuilder var content: () -> Content

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) { content() }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
        } label: {
            HStack {
                Text(title).font(.headline)
                Spacer()
                accessory()
            }
        }
    }
}

extension Card where Accessory == EmptyView {
    init(title: String, @ViewBuilder content: @escaping () -> Content) {
        self.init(title: title, accessory: { EmptyView() }, content: content)
    }
}

struct Pill: View {
    let text: String
    var color: Color = .secondary
    var body: some View {
        Text(text).font(.caption.weight(.semibold))
            .padding(.horizontal, 8).padding(.vertical, 2)
            .foregroundStyle(color)
            .background(color.opacity(0.15), in: Capsule())
    }
}

struct KeyValues: View {
    let rows: [(String, String)]
    var body: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 4) {
            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                GridRow {
                    Text(row.0).foregroundStyle(.secondary).font(.callout.monospaced())
                    Text(row.1).textSelection(.enabled).font(.callout)
                }
            }
        }
    }
}
