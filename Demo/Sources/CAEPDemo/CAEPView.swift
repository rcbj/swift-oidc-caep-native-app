// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import OIDCCAEPClient
import SwiftUI

struct CAEPView: View {
    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                StreamCard()
                EventLogCard()
            }
            .padding(.vertical)
        }
    }
}

struct StreamCard: View {
    @Environment(DemoModel.self) private var model

    var body: some View {
        @Bindable var model = model
        let me = model.signedIn
        let st = me != nil && model.caepKey == me?.key ? model.stream
            : StreamState(status: model.config?.caepEnabled == false ? .disabled : model.busy != nil ? .connecting : .waitingForUser)
        let status = st.status == .connected ? st.streamStatus ?? "enabled" : name(st.status)
        Card(title: me.map { "CAEP stream · \(model.label($0))" } ?? "CAEP stream") {
            Pill(text: status, color: status == "enabled" ? .green : st.status == .error ? .red : .orange)
        } content: {
            KeyValues(rows: rows(st))
            Text("Event types this stream asks for").font(.callout.bold())
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), alignment: .leading)], alignment: .leading) {
                ForEach(CAEP.all, id: \.self) { uri in
                    Toggle(eventName(uri), isOn: Binding(
                        get: { model.selectedEvents.contains(uri) },
                        set: { on in if on { model.selectedEvents.insert(uri) } else { model.selectedEvents.remove(uri) } }))
                }
            }
            HStack {
                Button("Update subscription") { Task { await model.updateSubscription() } }
                    .disabled(st.status != .connected || !st.write)
                Text(st.write ? "" : "Needs ssf.manage.").font(.caption).foregroundStyle(.secondary)
            }
            if let error = st.error { Text(error).foregroundStyle(.red).font(.callout).textSelection(.enabled) }
            HStack {
                Button("Request verification event") { Task { await model.requestVerification() } }.disabled(st.status != .connected || !st.write)
                Button("Reconnect stream") { Task { await model.reconnect() } }.disabled(me == nil)
            }
        }
    }

    private func rows(_ st: StreamState) -> [(String, String)] {
        var r: [(String, String)] = [("transmitter", st.transmitter ?? model.config?.ssfTransmitterIssuer ?? model.client?.issuer ?? "—")]
        if let id = st.streamID {
            r += [("stream_id", id), ("delivery", "poll (RFC 8936)"), ("SET audience", st.audience ?? "—")]
        }
        if st.status == .waitingForUser { r.append(("note", "Sign in. The app reads the active account's stream when its access token carries ssf.read.")) }
        if let note = st.note { r.append(("note", note)) }
        if model.accountList.count > 1 {
            r.append(("other accounts", "dormant: their streams keep queueing at the transmitter, and are caught up when the account is activated"))
        }
        return r
    }

    private func name(_ s: StreamStatus) -> String {
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
}

struct EventLogCard: View {
    @Environment(DemoModel.self) private var model

    var body: some View {
        Card(title: "Event log") {
            HStack {
                if model.stream.status == .connected {
                    Label("polling", systemImage: "dot.radiowaves.left.and.right").font(.caption).foregroundStyle(.green)
                }
                Button("Clear") { model.clearLog() }
            }
        } content: {
            let entries = model.activeLog
            if entries.isEmpty {
                Text("No CAEP events yet. Sign in, then trigger an event at your identity provider (for example, revoke your session).")
                    .foregroundStyle(.secondary)
            }
            ForEach(entries) { e in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(e.name).font(.callout.monospaced().bold())
                        Spacer()
                        Text(e.at.formatted(date: .omitted, time: .standard)).font(.caption).foregroundStyle(.secondary)
                    }
                    Text(e.action).font(.callout)
                    if e.subject != nil || e.payload != nil {
                        DisclosureGroup("Subject & payload") {
                            Text([e.subject.map { "subject: \($0)" }, e.payload.map { "payload: \($0)" }].compactMap { $0 }.joined(separator: "\n"))
                                .font(.caption.monospaced()).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .font(.caption)
                    }
                }
                .padding(.vertical, 4)
                Divider()
            }
        }
    }
}
