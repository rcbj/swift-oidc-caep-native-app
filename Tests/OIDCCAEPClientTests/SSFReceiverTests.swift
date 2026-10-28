// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation
import XCTest
@testable import OIDCCAEPClient

final class SSFReceiverTests: XCTestCase {
    /// A signed-in client and a receiver authorized by its (DPoP-bound) token.
    func setUp(_ op: StubOP, configure: (inout SSFReceiverConfiguration) -> Void = { _ in }) async throws -> (SSFReceiver, TokenSet) {
        let client = try await makeClient(op)
        let ts = try await client.authorize(using: StubBrowser(op: op)).tokenSet
        var c = SSFReceiverConfiguration(transmitterIssuer: ISSUER, authorization: .oidc(client) { ts }, pollInterval: 3600,
                                         transport: op, onEventReceived: nil)
        configure(&c)
        return (SSFReceiver(c), ts)
    }

    func testOneHandlerPerEventAndAcknowledgement() async throws {
        let op = StubOP()
        let (receiver, _) = try await setUp(op)
        let seen = Locked<[String]>([])
        receiver
            .onSessionRevoked { e in seen.withLock { $0.append("revoked:\(e.reasonUser?["en"] ?? "")") } }
            .onCredentialChange { e in seen.withLock { $0.append("credential:\(e.payload.string("change_type") ?? "")") } }
            .onAnyEvent { e in seen.withLock { $0.append("any:\(e.name)") } }
        let j1 = try await op.queueSET(type: CAEP.sessionRevoked, payload: ["reason_user": ["en": "bye"]], subId: Subject.issSub(ISSUER, "user-1"))
        let j2 = try await op.queueSET(type: CAEP.credentialChange, payload: ["change_type": "revoke"])
        try await receiver.start(catchUp: true)
        XCTAssertEqual(Set(seen.current), Set(["revoked:bye", "any:session-revoked", "credential:revoke", "any:credential-change"]))
        await receiver.stop()
        let acks = await op.acks
        XCTAssertEqual(Set(acks), Set([j1, j2]))
        let v1 = await op.queuedCount
        XCTAssertEqual(v1, 0)
    }

    func testAThrowingHandlerLeavesTheSETForRedelivery() async throws {
        let op = StubOP()
        let (receiver, _) = try await setUp(op) { $0.maxDeliveryAttempts = 2 }
        let calls = Locked(0)
        let errors = Locked<[String]>([])
        receiver
            .onSessionRevoked { _ in calls.withLock { $0 += 1 }; throw StubError("not now") }
            .onError { e, ctx in errors.withLock { $0.append("\(ctx.phase.rawValue):\(e.code ?? "")") } }
        let jti = try await op.queueSET(type: CAEP.sessionRevoked)
        try await receiver.start(catchUp: false)
        try await receiver.poll()
        XCTAssertEqual(calls.current, 1)
        let v2 = await op.acks.contains(jti)
        XCTAssertFalse(v2)
        try await receiver.poll()   // redelivered; the second failure gives up and acknowledges
        try await receiver.poll()
        XCTAssertEqual(calls.current, 2)
        let v3 = await op.acks.contains(jti)
        XCTAssertTrue(v3)
        XCTAssertTrue(errors.current.contains("handler:handler_failed"))
        await receiver.stop()
    }

    func testInvalidSETsAreReportedAndReplaysDropped() async throws {
        let op = StubOP()
        let (receiver, _) = try await setUp(op)
        let seen = Locked(0)
        receiver.onSessionRevoked { _ in seen.withLock { $0 += 1 } }
        receiver.onError { _, _ in }
        try await receiver.start()
        let other = try SoftwareECSigner(alg: "ES256")
        let forged = try await op.makeSET(type: CAEP.sessionRevoked, jti: "forged", signer: other)
        try await op.queueSET(type: "", jti: "forged", token: forged)
        let wrongAud = try await op.makeSET(type: CAEP.sessionRevoked, aud: "someone-else", jti: "aud")
        try await op.queueSET(type: "", jti: "aud", token: wrongAud)
        let wrongTyp = try await op.makeSET(type: CAEP.sessionRevoked, jti: "typ", typ: "JWT")
        try await op.queueSET(type: "", jti: "typ", token: wrongTyp)
        let two = try await op.makeSET(type: CAEP.sessionRevoked, jti: "two", extraEvents: [CAEP.credentialChange: [:]])
        try await op.queueSET(type: "", jti: "two", token: two)
        try await receiver.poll()
        try await receiver.poll()
        await receiver.stop()       // sends the setErrs still owed
        let errs = await op.setErrs
        XCTAssertEqual(errs["forged"]?["err"], "invalid_key")
        XCTAssertEqual(errs["aud"]?["err"], "invalid_audience")
        XCTAssertEqual(errs["typ"]?["err"], "invalid_request")
        XCTAssertEqual(errs["two"]?["err"], "invalid_request")
        XCTAssertEqual(seen.current, 0)

        let good = try await op.makeSET(type: CAEP.sessionRevoked, jti: "once")
        let first = try await receiver.receiveSet(good)
        let replay = try await receiver.receiveSet(good)
        XCTAssertEqual(first.count, 1)
        XCTAssertTrue(replay.isEmpty)
        XCTAssertEqual(seen.current, 1)
    }

    func testVerificationAndSubjects() async throws {
        let op = StubOP()
        let (receiver, _) = try await setUp(op)
        try await receiver.start()
        try await receiver.addSubject(Subject.issSub(ISSUER, "user-1"))
        let v4 = await op.subjectsAdded.first?.string("sub")
        XCTAssertEqual(v4, "user-1")
        let event = try await receiver.requestVerification(timeout: 5)
        XCTAssertEqual(event.type, SSF.verification)
        await receiver.stop(deleteStream: true)
        let v5 = await op.streamDeletes
        XCTAssertEqual(v5, 1)
    }

    func testAHandlerCanStopItsOwnReceiver() async throws {
        let op = StubOP()
        let (receiver, _) = try await setUp(op)
        let jti = try await op.queueSET(type: CAEP.sessionRevoked)
        // As an app does when a signal ends the account: the handler stops (and forgets) the receiver.
        receiver.onSessionRevoked { _ in await receiver.stop() }
        let started = Task { try await receiver.start(catchUp: true) }
        let finished = await withTaskGroup(of: Bool.self) { group in
            group.addTask { _ = try? await started.value; return true }
            group.addTask { try? await Task.sleep(nanoseconds: 5_000_000_000); return false }
            let first = await group.next()!
            group.cancelAll()
            return first
        }
        XCTAssertTrue(finished, "stop() inside a handler must not wait for the poll running that handler")
        let acks = await op.acks
        XCTAssertTrue(acks.contains(jti), "the handled SET is still acknowledged")
    }

    func testPollEndpointMustBeAtTheTransmitter() async throws {
        let op = StubOP()
        let (receiver, _) = try await setUp(op)
        try await receiver.start()
        await receiver.setStreamForTest(["stream_id": "s", "aud": .string(CLIENT_ID), "delivery": ["endpoint_url": "https://evil.example/poll"]])
        await XCTAssertThrowsCode("untrusted_endpoint") { try await receiver.poll() }
        await receiver.stop()
    }
}

extension SSFReceiver {
    func setStreamForTest(_ s: JSONObject) { stream = s }
}
