// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation
import XCTest
@testable import OIDCCAEPClient

/// The library against a real iya-sts: sign in, then two CAEP signals through its SSF receiver.
///
/// Skipped unless `IYA_STS_LIVE_PLIST` names an `OIDCConfiguration.plist`. `scripts/live_iya_sts.py` starts a
/// fresh iya-sts, registers the client, writes that plist (its `TrustedCertificates` is the root of the chain
/// iya-sts publishes at `GET /tls/server-certificate`) and runs this test in the `swift:6.1-noble` container.
///
/// Everything is the library's own: ``OIDCAppConfiguration`` and its TLS trust, ``OIDCClient`` (PAR, PKCE,
/// DPoP), ``AccountManager``, ``LoopbackWebAuthenticator`` listening on the plist's loopback redirect URI, and
/// ``SSFReceiver``. Only the browser is replaced: ``IyaSTSBrowser`` walks iya-sts's sign-in screens over HTTP
/// (the JSON calls its static pages make) and then requests the loopback redirect, as a browser would.
///
/// The test plays the operator too: it emits credential-change and then session-revoked with
/// `POST /admin-api/caep/emit`. The first must arrive with the account still signed in; the second must end it.
final class LiveIyaSTSTests: XCTestCase {
    func testSignInAndTwoCAEPSignals() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let plistPath = env["IYA_STS_LIVE_PLIST"], !plistPath.isEmpty else {
            throw XCTSkip("IYA_STS_LIVE_PLIST is not set; scripts/live_iya_sts.py runs this test against a fresh iya-sts")
        }
        let username = env["IYA_STS_LIVE_USERNAME"] ?? "caep-demo-user"
        let password = env["CAEP_DEMO_USER_PASSWORD"] ?? "unused-in-development-mode"
        guard let adminSecret = env["STS_ADMIN_API_CLIENT_SECRET"] ?? env["ADMIN_API_CLIENT_SECRET"], !adminSecret.isEmpty else {
            throw OIDCError.usage("STS_ADMIN_API_CLIENT_SECRET is required to emit the signals")
        }

        let plistURL = URL(fileURLWithPath: plistPath)
        let config = try OIDCAppConfiguration.load(contentsOf: plistURL)
        XCTAssertFalse(config.insecureSkipTLSVerification, "the live test trusts iya-sts through TrustedCertificates only")
        let trust = try XCTUnwrap(config.tlsTrust, "the plist must name iya-sts's root in TrustedCertificates")
        XCTAssertFalse(trust.includeSystemRoots)
        let origin = try XCTUnwrap(Self.origin(of: config.metadataURL))

        // The library: its own transport (Linux: curl with a CA bundle holding TrustedCertificates only).
        let transport = config.makeTransport()
        let client = try await config.makeClient(dpopKeyStore: MemoryKeyStore(), transport: transport)
        let accounts = try await AccountManager(client: client, options: AccountManagerOptions(store: MemoryTokenStore())).restore()

        // The browser, substituted: it trusts the same root (a browser would have it in its own store).
        let anchors = FileManager.default.temporaryDirectory.appendingPathComponent("live-anchors-\(UUID().uuidString).pem")
        try Data(trust.pem.utf8).write(to: anchors)
        let browser = try IyaSTSBrowser(origin: origin, caFile: anchors, username: username, password: password)
        defer { browser.close(); try? FileManager.default.removeItem(at: anchors) }

        let authenticator = LoopbackWebAuthenticator(timeout: 120) { url in browser.open(url) }
        let signIn = try await accounts.signIn(using: authenticator)
        if let failure = browser.failure { XCTFail("the browser walk failed: \(failure)") }
        let key = signIn.account.key
        XCTAssertEqual(signIn.account.status, .signedIn)
        let tokens = try await accounts.getTokenSet()
        XCTAssertTrue(tokens.isDPoPBound, "the access token is DPoP-bound")
        if let scope = tokens.scope {
            let granted = Set(scope.split(separator: " ").map(String.init))
            XCTAssertTrue(granted.contains("ssf.read") && granted.contains("ssf.manage"), "granted scopes: \(granted.sorted())")
        }

        // The library's CAEP receiver, polling this account's stream every second with its DPoP-bound token.
        let received = Locked<[SecurityEvent]>([])
        let endedBySubject = Locked<Bool?>(nil)
        let receiver = SSFReceiver(SSFReceiverConfiguration(
            transmitterIssuer: config.ssfTransmitterIssuer ?? client.issuer,
            authorization: .oidc(client) { try await accounts.getTokenSet() },
            eventsRequested: [CAEP.credentialChange, CAEP.sessionRevoked],
            description: "swift-oidc-caep-native-app live test",
            pollInterval: 1,
            transport: transport,
            onEventReceived: nil))
        receiver
            .onCredentialChange { event in received.withLock { $0.append(event) } }
            .onSessionRevoked { event in
                // The account the signal names (its iss/sub, or its session) is ended. When the subject
                // names nothing this app holds, this app's one account is (the WS-Federation demos' rule).
                let named = await accounts.accountsForSubject(event.subject ?? [:]).map(\.key)
                endedBySubject.withLock { $0 = !named.isEmpty }
                for one in named.isEmpty ? [key] : named {
                    try await accounts.end(one, reason: event.reasonUser?["en"] ?? "The session was revoked by the identity provider.")
                }
                received.withLock { $0.append(event) }
            }
        try await receiver.start(catchUp: true)
        if await receiver.metadata?["add_subject_endpoint"] != nil {
            try await receiver.addSubject(Subject.issSub(signIn.account.iss, signIn.account.sub))
        }

        let operatorAPI = AdminAPI(browser: browser, origin: origin, secret: adminSecret)
        let sessionID = try await operatorAPI.sessionID(for: username)

        try await operatorAPI.emit(sessionID: sessionID, type: "credential-change")
        let afterFirst = try await Self.wait("credential-change") {
            received.current.contains { $0.type == CAEP.credentialChange }
        }
        XCTAssertTrue(afterFirst)
        let statusAfterFirst = await accounts.get(key)?.status
        XCTAssertEqual(statusAfterFirst, .signedIn, "credential-change (an update) keeps the session")

        try await operatorAPI.emit(sessionID: sessionID, type: "session-revoked")
        let afterSecond = try await Self.wait("session-revoked") {
            received.current.contains { $0.type == CAEP.sessionRevoked }
        }
        XCTAssertTrue(afterSecond)
        let statusAfterSecond = await accounts.get(key)?.status
        XCTAssertEqual(statusAfterSecond, .ended, "session-revoked ends the account")
        await receiver.stop()

        let events: [[String: String]] = received.current.map { ["type": $0.type, "jti": $0.jti] }
        let result: [String: Any] = [
            "ok": statusAfterFirst == .signedIn && statusAfterSecond == .ended && events.count == 2,
            "subject": signIn.account.sub,
            "issuer": client.issuer,
            "tokenType": tokens.tokenType,
            "signedInAfterCredentialChange": statusAfterFirst == .signedIn,
            "signedInAfterSessionRevoked": statusAfterSecond == .signedIn,
            "accountStatus": statusAfterSecond?.rawValue ?? "missing",
            "sessionRevokedMatchedSubject": endedBySubject.current ?? false,
            "events": events,
        ]
        let line = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        print("LIVE-RESULT " + String(decoding: line, as: UTF8.self))
    }

    static func origin(of url: URL) -> String? {
        guard let scheme = url.scheme, let host = url.host else { return nil }
        return url.port.map { "\(scheme)://\(host):\($0)" } ?? "\(scheme)://\(host)"
    }

    /// Waits up to 30 seconds for `condition`.
    static func wait(_ what: String, _ condition: @Sendable () async -> Bool) async throws -> Bool {
        let deadline = Date().addingTimeInterval(30)
        while Date() < deadline {
            if await condition() { return true }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        XCTFail("timed out waiting for \(what)")
        return false
    }
}

/// The browser the live test substitutes: curl with a cookie jar, walking iya-sts's static sign-in screens
/// through the JSON API they call (`/authn-api`), and finally requesting the redirect it is sent to, which is
/// the library's loopback listener.
final class IyaSTSBrowser: @unchecked Sendable {
    struct Response {
        var status: Int
        var headers: [String: [String]]
        var body: Data
        func header(_ name: String) -> String? { headers[name.lowercased()]?.last }
        var json: [String: Any] { (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:] }
        var text: String { String(decoding: body.prefix(500), as: UTF8.self) }
    }

    let origin: String
    let caFile: URL
    let username: String
    let password: String
    private let dir: URL
    private let failureBox = Locked<String?>(nil)
    var failure: String? { failureBox.current }

    init(origin: String, caFile: URL, username: String, password: String) throws {
        self.origin = origin
        self.caFile = caFile
        self.username = username
        self.password = password
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("live-browser-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }

    func close() { try? FileManager.default.removeItem(at: dir) }

    /// ``LoopbackWebAuthenticator``'s `openBrowser`: the listener is already bound, so the walk runs on its own
    /// thread and ends by requesting the loopback redirect.
    func open(_ url: URL) {
        Thread.detachNewThread { [self] in
            do { try walk(url) } catch { failureBox.withLock { $0 = "\(error)" } }
        }
    }

    private func walk(_ start: URL) throws {
        var url = start
        for _ in 0..<24 {
            guard let next = try step(url) else { return }
            url = next
        }
        throw OIDCError.usage("the sign-in did not finish; last URL \(url.absoluteString)")
    }

    /// One page. Returns the next URL, or nil once the loopback redirect was delivered.
    private func step(_ url: URL) throws -> URL? {
        let res = try request("GET", url, headers: ["accept": "text/html,application/json"])
        if (300..<400).contains(res.status), let location = res.header("location") {
            return URL(string: location, relativeTo: url)?.absoluteURL
        }
        guard url.absoluteString.hasPrefix(origin) else {
            // Not iya-sts: the loopback redirect, answered by the library's listener.
            guard res.status == 200 else { throw OIDCError.usage("the redirect to \(url.absoluteString) answered \(res.status)") }
            return nil
        }
        let path = url.path
        let query = FormParameters(parsing: url.query ?? "")
        func pending(_ name: String) -> String { query.get(name).flatMap { $0.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) } ?? "" }
        if path.hasPrefix("/authn/login") {
            let id = pending("authn")
            let csrf = try view("/authn-api/pending/\(id)")
            return try act(url, "/authn-api/pending/\(id)/password", ["username": username, "password": password], csrf)
        }
        if path.hasPrefix("/oauth2/consent") {
            let id = pending("consent")
            let csrf = try view("/authn-api/consent/\(id)")
            return try act(url, "/authn-api/consent/\(id)", ["action": "allow"], csrf)
        }
        if path.hasPrefix("/authn/mfa-setup") || path.hasPrefix("/authn/post-login") {
            return try skip(url)
        }
        throw OIDCError.usage("the sign-in stopped at \(res.status) \(url.absoluteString): \(res.text)")
    }

    /// A screen's view from its API, for the CSRF token its form sends.
    private func view(_ apiPath: String) throws -> String {
        let res = try request("GET", URL(string: origin + apiPath)!, headers: ["accept": "application/json"])
        guard let csrf = res.json["csrf"] as? String, !csrf.isEmpty else {
            throw OIDCError.usage("\(apiPath) answered \(res.status) without a csrf token: \(res.text)")
        }
        return csrf
    }

    private func act(_ page: URL, _ apiPath: String, _ body: [String: Any], _ csrf: String) throws -> URL? {
        let res = try request("POST", URL(string: origin + apiPath)!, headers: [
            "accept": "application/json", "content-type": "application/json", "origin": origin, "x-csrf-token": csrf,
        ], body: try JSONSerialization.data(withJSONObject: body))
        if (300..<400).contains(res.status), let location = res.header("location") {
            return URL(string: location, relativeTo: page)?.absoluteURL
        }
        let json = res.json
        if let location = json["location"] as? String, let next = URL(string: location, relativeTo: URL(string: origin + "/")!)?.absoluteURL {
            if json["next"] as? String == "mfa", json["step"] as? String == "enrol" { return try skip(next) }
            return next
        }
        throw OIDCError.usage("\(apiPath) answered \(res.status) without a location: \(res.text)")
    }

    /// Skips an optional second-factor enrolment or post-login step; a required one stops the walk.
    private func skip(_ url: URL) throws -> URL? {
        let query = FormParameters(parsing: url.query ?? "")
        let id = query.get("mfa") ?? query.get("authn") ?? url.pathComponents.last ?? ""
        let postLogin = url.path.hasPrefix("/authn/post-login")
        let res = try request("GET", URL(string: "\(origin)/authn-api/mfa/\(id)?page=\(postLogin ? "post-login" : "setup")")!,
                              headers: ["accept": "application/json"])
        guard let csrf = res.json["csrf"] as? String else { throw OIDCError.usage("the MFA view answered \(res.status): \(res.text)") }
        let setup = (res.json["view"] as? [String: Any])?["setup"] as? [String: Any]
        guard postLogin || setup?["optional"] as? Bool == true else { throw OIDCError.usage("a required step is in the way at \(url.absoluteString)") }
        return try act(url, "/authn-api/mfa/\(id)/\(postLogin ? "post-login/skip" : "skip")", [:], csrf)
    }

    /// One request with curl: the cookie jar, the anchors, no redirects followed. Headers and the body go
    /// through files, never the command line.
    func request(_ method: String, _ url: URL, headers: [String: String] = [:], body: Data? = nil) throws -> Response {
        let id = UUID().uuidString
        let headerFile = dir.appendingPathComponent("\(id).request-headers")
        let dumped = dir.appendingPathComponent("\(id).response-headers")
        let output = dir.appendingPathComponent("\(id).body")
        let bodyFile = dir.appendingPathComponent("\(id).request-body")
        defer { for f in [headerFile, dumped, output, bodyFile] { try? FileManager.default.removeItem(at: f) } }
        let lines = headers.map { "\($0.key): \($0.value)" } + ["Expect:"]
        FileManager.default.createFile(atPath: headerFile.path, contents: Data(lines.joined(separator: "\n").utf8), attributes: [.posixPermissions: 0o600])
        var args = ["curl", "--silent", "--show-error", "--http1.1", "--max-time", "30", "--cacert", caFile.path,
                    "--cookie", dir.appendingPathComponent("jar").path, "--cookie-jar", dir.appendingPathComponent("jar").path,
                    "--request", method, "--header", "@\(headerFile.path)", "--dump-header", dumped.path,
                    "--output", output.path, "--write-out", "%{http_code}"]
        if let body {
            FileManager.default.createFile(atPath: bodyFile.path, contents: body, attributes: [.posixPermissions: 0o600])
            args += ["--data-binary", "@\(bodyFile.path)"]
        }
        args.append(url.absoluteString)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = args
        let stdout = Pipe(), stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        let code = String(decoding: stdout.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let errorText = String(decoding: stderr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        guard process.terminationStatus == 0, let status = Int(code.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw OIDCError.usage("curl \(method) \(url.absoluteString): \(errorText)")
        }
        let raw = (try? String(contentsOf: dumped, encoding: .utf8)) ?? ""
        let block = raw.components(separatedBy: "\r\n\r\n").filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }.last ?? ""
        var parsed: [String: [String]] = [:]
        for line in block.components(separatedBy: "\r\n").dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            parsed[line[..<colon].lowercased(), default: []].append(line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces))
        }
        return Response(status: status, headers: parsed, body: (try? Data(contentsOf: output)) ?? Data())
    }
}

/// The operator's side: iya-sts's management API, with the seeded `sts-api-client`.
struct AdminAPI {
    let browser: IyaSTSBrowser
    let origin: String
    let secret: String

    private func token() throws -> String {
        let form = FormParameters([("grant_type", "client_credentials"), ("scope", "admin:read admin:write"),
                                   ("resource", origin + "/admin-api")])
        let basic = Data("sts-api-client:\(secret)".utf8).base64EncodedString()
        let res = try browser.request("POST", URL(string: origin + "/oauth2/token")!, headers: [
            "content-type": "application/x-www-form-urlencoded", "accept": "application/json", "authorization": "Basic \(basic)",
        ], body: Data(form.encoded.utf8))
        guard res.status == 200, let token = res.json["access_token"] as? String else {
            throw OIDCError.usage("the admin token request answered \(res.status)")
        }
        return token
    }

    private func call(_ method: String, _ path: String, _ body: [String: Any]? = nil) throws -> IyaSTSBrowser.Response {
        var headers = ["accept": "application/json", "authorization": "Bearer \(try token())"]
        if body != nil { headers["content-type"] = "application/json" }
        return try browser.request(method, URL(string: origin + path)!, headers: headers,
                                   body: try body.map { try JSONSerialization.data(withJSONObject: $0) })
    }

    /// The sign-on session iya-sts's CAEP page lists for `username`.
    func sessionID(for username: String) async throws -> String {
        let deadline = Date().addingTimeInterval(20)
        var last = ""
        while Date() < deadline {
            let res = try call("GET", "/admin-api/caep")
            last = res.text
            for row in res.json["sessions"] as? [[String: Any]] ?? [] {
                if row["username"] as? String == username, row["state"] as? String != "revoked", let id = row["sessionId"] as? String {
                    return id
                }
            }
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
        throw OIDCError.usage("no CAEP session for \(username): \(last)")
    }

    func emit(sessionID: String, type: String) async throws {
        let res = try call("POST", "/admin-api/caep/emit", ["session_id": sessionID, "type": type, "initiating_entity": "admin"])
        let message = res.json["message"] as? String ?? ""
        guard res.status == 200, res.json["ok"] as? Bool != false, !message.contains("Nothing was sent") else {
            throw OIDCError.usage("emitting \(type) answered \(res.status): \(res.text)")
        }
        print("emitted \(type): \(message)")
    }
}
