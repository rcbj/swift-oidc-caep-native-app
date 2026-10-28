// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation

/// What every security event handler receives.
public struct SecurityEvent: Sendable, Equatable {
    /// Event type URI.
    public let type: String
    /// Short name, e.g. `session-revoked`.
    public let name: String
    /// The event-specific object from the SET's `events` claim.
    public let payload: JSONObject
    /// RFC 9493 subject identifier (`sub_id`, or the legacy `subject` inside the event).
    public let subject: JSONObject?
    /// CAEP `event_timestamp` (seconds), falling back to the SET's `toe`, then `iat`.
    public let eventTimestamp: Double?
    /// `admin`, `user`, `policy` or `system`.
    public let initiatingEntity: String?
    public let reasonAdmin: [String: String]?
    public let reasonUser: [String: String]?
    public let jti: String
    public let iss: String
    public let aud: JSONValue?
    public let iat: Double
    public let txn: String?
    /// Every validated SET claim.
    public let set: JSONObject
    /// The SET as received (compact JWS).
    public let raw: String

    init(type: String, payload: JSONObject, set: JSONObject, raw: String) {
        self.type = type
        name = eventName(type)
        self.payload = payload
        subject = set["sub_id"]?.objectValue ?? payload["subject"]?.objectValue
        eventTimestamp = payload["event_timestamp"]?.doubleValue ?? set["toe"]?.doubleValue ?? set["iat"]?.doubleValue
        initiatingEntity = payload.string("initiating_entity")
        func strings(_ v: JSONValue?) -> [String: String]? { v?.objectValue?.compactMapValues(\.stringValue) }
        reasonAdmin = strings(payload["reason_admin"])
        reasonUser = strings(payload["reason_user"])
        jti = set.string("jti") ?? ""
        iss = set.string("iss") ?? ""
        aud = set["aud"]
        iat = set["iat"]?.doubleValue ?? 0
        txn = set.string("txn")
        self.set = set
        self.raw = raw
    }
}

/// A handler for one kind of event. Throwing leaves the SET for the transmitter to send again.
public typealias SecurityEventHandler = @Sendable (SecurityEvent) async throws -> Void

/// Where an error reported to ``SSFReceiver/onError(_:)`` came from.
public struct SSFErrorContext: Sendable {
    public enum Phase: String, Sendable {
        /// Polling, or validating a polled SET.
        case poll
        /// A handler threw.
        case handler
        /// `onEventReceived` threw.
        case hook
        /// Sending the last acknowledgements, or deleting the stream, failed.
        case stop
    }
    public let phase: Phase
    /// The SET concerned, when there is one.
    public var jti: String?
    /// The event whose handler threw.
    public var event: SecurityEvent?
    /// The SET was left for the transmitter to send again.
    public var willRetry: Bool = false
}

public typealias SSFErrorHandler = @Sendable (OIDCError, SSFErrorContext) -> Void

/// One request to the transmitter, for ``SSFAuthorization/headers(_:)``.
public struct SSFRequestInfo: Sendable {
    public let method: String
    public let url: URL
    /// A DPoP nonce the transmitter asked for.
    public let nonce: String?
}

/// How the receiver authorizes its calls to the transmitter (stream management and polling).
public enum SSFAuthorization: Sendable {
    /// A bearer token, fetched for each request.
    case bearer(@Sendable () async throws -> String)
    /// The `authorization` (and `dpop`) headers for one request.
    case headers(@Sendable (SSFRequestInfo) async throws -> [String: String])

    /// The signed-in person's access token, with a DPoP proof when it is bound — the usual choice.
    public static func oidc(_ client: OIDCClient, tokenSet: @escaping @Sendable () async throws -> TokenSet) -> SSFAuthorization {
        .headers { request in
            try client.resourceHeaders(for: try await tokenSet(), method: request.method, url: request.url, nonce: request.nonce)
        }
    }
}

/// The default `onEventReceived` hook: one log line per accepted event, naming the event and its `jti`
/// only. The payload and subject can carry personal data (email, phone, session id, IP address), so they
/// are left out. Call it from your own hook to keep the line.
public let logEventReceived: SecurityEventHandler = { event in
    OIDCLog.log(.info, "CAEP event received: \(event.name) (jti \(event.jti))")
}

public struct SSFReceiverConfiguration: Sendable {
    /// The SSF transmitter's issuer; its metadata is read from `/.well-known/ssf-configuration`.
    /// Delivery is RFC 8936 POLL. (SETs obtained any other way can still be given to ``SSFReceiver/receiveSet(_:)``.)
    public var transmitterIssuer: String
    public var authorization: SSFAuthorization?
    /// Expected SET `aud`. Default: the `aud` in the stream configuration.
    public var audience: [String]?
    /// Default: every CAEP event type.
    public var eventsRequested: [String]
    /// Use an existing stream instead of creating one.
    public var streamID: String?
    public var description: String
    /// Seconds between polls.
    public var pollInterval: TimeInterval
    /// Max SETs per poll.
    public var maxEvents: Int
    public var clockTolerance: TimeInterval
    /// Refuse SETs whose `iat` is older than this (seconds). Default 0: no limit. A polled SET waits at the
    /// transmitter until it is read, so an age limit would throw away the signals a stopped receiver catches
    /// up on. A replay is caught by its `jti` whatever its age.
    public var maxSetAge: TimeInterval
    /// How many times a SET whose handlers throw is left for the transmitter to send again before it is
    /// acknowledged anyway (`onError` gets `handler_failed`).
    public var maxDeliveryAttempts: Int
    /// Allow non-TLS SSF URLs other than loopback.
    public var allowInsecureRequests: Bool
    /// Origins besides the transmitter's issuer and configuration_endpoint that the stream's poll
    /// `endpoint_url` may be at. The poll request carries the person's access token, so it is refused anywhere else.
    public var trustedPollOrigins: [String]
    /// Require the `typ: secevent+jwt` header (SSF §4.1.9).
    public var requireTyp: Bool
    /// Replay-protection window size.
    public var jtiCacheSize: Int
    public var httpTimeout: TimeInterval
    public var transport: any HTTPTransport
    /// Your logic for every accepted event: called once per event, before the typed handlers, and awaited.
    /// Default ``logEventReceived``. Nil turns it off. A throw goes to `onError` with phase `hook`, and the
    /// typed handlers still run.
    public var onEventReceived: SecurityEventHandler?
    public var now: @Sendable () -> Date

    public init(transmitterIssuer: String, authorization: SSFAuthorization? = nil, audience: [String]? = nil,
                eventsRequested: [String] = CAEP.all, streamID: String? = nil, description: String = "swift-oidc-caep-native-app receiver",
                pollInterval: TimeInterval = 5, maxEvents: Int = 25, clockTolerance: TimeInterval = 60, maxSetAge: TimeInterval = 0,
                maxDeliveryAttempts: Int = 5, allowInsecureRequests: Bool = false, trustedPollOrigins: [String] = [],
                requireTyp: Bool = true, jtiCacheSize: Int = 10_000, httpTimeout: TimeInterval = 10,
                transport: any HTTPTransport = URLSessionTransport(), onEventReceived: SecurityEventHandler? = logEventReceived,
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.transmitterIssuer = transmitterIssuer
        self.authorization = authorization
        self.audience = audience
        self.eventsRequested = eventsRequested
        self.streamID = streamID
        self.description = description
        self.pollInterval = pollInterval
        self.maxEvents = maxEvents
        self.clockTolerance = clockTolerance
        self.maxSetAge = maxSetAge
        self.maxDeliveryAttempts = maxDeliveryAttempts
        self.allowInsecureRequests = allowInsecureRequests
        self.trustedPollOrigins = trustedPollOrigins
        self.requireTyp = requireTyp
        self.jtiCacheSize = jtiCacheSize
        self.httpTimeout = httpTimeout
        self.transport = transport
        self.onEventReceived = onEventReceived
        self.now = now
    }
}

/// The handlers registered on a receiver. Registration is synchronous, so handlers can be chained.
private final class HandlerRegistry: @unchecked Sendable {
    struct State {
        var byType: [String: [SecurityEventHandler]] = [:]
        var any: [SecurityEventHandler] = []
        var unhandled: [SecurityEventHandler] = []
        var errors: [SSFErrorHandler] = []
    }
    let state = Locked(State())
}

/// SSF transmitter metadata members that are URLs, all of which must use TLS.
private let ssfURLMembers = ["jwks_uri", "configuration_endpoint", "status_endpoint", "add_subject_endpoint", "remove_subject_endpoint", "verification_endpoint"]

/// An OpenID Shared Signals Framework 1.0 receiver with one handler per CAEP event, polling its stream
/// (RFC 8936).
///
/// ```swift
/// let receiver = SSFReceiver(SSFReceiverConfiguration(
///     transmitterIssuer: client.issuer,
///     authorization: .oidc(client) { try await accounts.getTokenSet() }))
/// receiver
///     .onSessionRevoked { event in /* sign the user out */ }
///     .onCredentialChange { event in /* event.payload["change_type"] */ }
/// try await receiver.start()
/// ```
///
/// Any other event type (e.g. RISC) can be handled with ``onEvent(_:_:)``.
public actor SSFReceiver {
    /// Transmitter metadata, once discovered.
    public private(set) var metadata: JSONObject?
    /// The current stream configuration.
    public var stream: JSONObject?

    public nonisolated let configuration: SSFReceiverConfiguration
    private nonisolated let handlers = HandlerRegistry()
    private let http: HTTPClient
    private var jwks: RemoteJWKSet?
    private var seenJtis: [String: Int] = [:]
    private var seenOrder: [String] = []
    private var pendingVerifications: [String: VerificationWaiter] = [:]
    private var loopTask: Task<Void, Never>?
    private var polling = false
    private var pollInFlight: Task<PollResult, Error>?
    private var pollAgain = false
    private var inFlight: Set<String> = []
    private var pendingAcks: [String] = []
    private var pendingErrs: [String: JSONValue] = [:]
    private var attempts: [String: Int] = [:]
    /// Handlers are running (a poll is dispatching SETs).
    private var dispatchDepth = 0
    /// stop() was called from inside a handler: the poll finishing now sends the last acknowledgements.
    private var flushWhenPollEnds = false

    public struct PollResult: Sendable {
        public let received: Int
        public let moreAvailable: Bool
    }

    public init(_ configuration: SSFReceiverConfiguration) {
        self.configuration = configuration
        http = HTTPClient(transport: configuration.transport, timeout: configuration.httpTimeout)
    }

    private var now: Date { configuration.now() }

    // MARK: Handler registration — one per CAEP event, plus generic hooks

    /// CAEP session-revoked: the session(s) for the subject were revoked; end local sessions.
    @discardableResult public nonisolated func onSessionRevoked(_ h: @escaping SecurityEventHandler) -> SSFReceiver { onEvent(CAEP.sessionRevoked, h) }
    /// CAEP token-claims-change: claims in previously issued tokens changed (`payload["claims"]`).
    @discardableResult public nonisolated func onTokenClaimsChange(_ h: @escaping SecurityEventHandler) -> SSFReceiver { onEvent(CAEP.tokenClaimsChange, h) }
    /// CAEP credential-change: a credential was created, revoked, updated or deleted (`credential_type`, `change_type`).
    @discardableResult public nonisolated func onCredentialChange(_ h: @escaping SecurityEventHandler) -> SSFReceiver { onEvent(CAEP.credentialChange, h) }
    /// CAEP assurance-level-change (`current_level`, `previous_level`, `change_direction`).
    @discardableResult public nonisolated func onAssuranceLevelChange(_ h: @escaping SecurityEventHandler) -> SSFReceiver { onEvent(CAEP.assuranceLevelChange, h) }
    /// CAEP device-compliance-change (`current_status`: `compliant` or `not-compliant`).
    @discardableResult public nonisolated func onDeviceComplianceChange(_ h: @escaping SecurityEventHandler) -> SSFReceiver { onEvent(CAEP.deviceComplianceChange, h) }
    /// CAEP session-established (`acr`, `amr`, `fp_ua`, `ext_id`).
    @discardableResult public nonisolated func onSessionEstablished(_ h: @escaping SecurityEventHandler) -> SSFReceiver { onEvent(CAEP.sessionEstablished, h) }
    /// CAEP session-presented (`fp_ua`, `ext_id`).
    @discardableResult public nonisolated func onSessionPresented(_ h: @escaping SecurityEventHandler) -> SSFReceiver { onEvent(CAEP.sessionPresented, h) }
    /// CAEP risk-level-change (`principal`, `current_level`, `previous_level`, `risk_reason`).
    @discardableResult public nonisolated func onRiskLevelChange(_ h: @escaping SecurityEventHandler) -> SSFReceiver { onEvent(CAEP.riskLevelChange, h) }
    /// SSF verification event (`state`).
    @discardableResult public nonisolated func onVerification(_ h: @escaping SecurityEventHandler) -> SSFReceiver { onEvent(SSF.verification, h) }
    /// SSF stream-updated event (`status`, `reason`).
    @discardableResult public nonisolated func onStreamUpdated(_ h: @escaping SecurityEventHandler) -> SSFReceiver { onEvent(SSF.streamUpdated, h) }

    /// A handler for any event type URI (CAEP, RISC, or your own).
    @discardableResult
    public nonisolated func onEvent(_ eventType: String, _ handler: @escaping SecurityEventHandler) -> SSFReceiver {
        handlers.state.withLock { $0.byType[eventType, default: []].append(handler) }
        return self
    }

    /// Called for every accepted event, after its type's handlers.
    @discardableResult
    public nonisolated func onAnyEvent(_ handler: @escaping SecurityEventHandler) -> SSFReceiver {
        handlers.state.withLock { $0.any.append(handler) }
        return self
    }

    /// Called for events no type-specific handler is registered for.
    @discardableResult
    public nonisolated func onUnhandledEvent(_ handler: @escaping SecurityEventHandler) -> SSFReceiver {
        handlers.state.withLock { $0.unhandled.append(handler) }
        return self
    }

    /// Called when a SET is rejected, a handler throws, or polling fails. Without one, errors are logged
    /// (``OIDCLog``), so a lost signal always leaves a trace.
    @discardableResult
    public nonisolated func onError(_ handler: @escaping SSFErrorHandler) -> SSFReceiver {
        handlers.state.withLock { $0.errors.append(handler) }
        return self
    }

    /// Removes every handler registered for `eventType`.
    @discardableResult
    public nonisolated func removeHandlers(for eventType: String) -> SSFReceiver {
        handlers.state.withLock { $0.byType[eventType] = nil }
        return self
    }

    // MARK: Lifecycle

    /// Loads the transmitter's metadata from its well-known SSF configuration endpoint.
    @discardableResult
    public func discover() async throws -> JSONObject {
        let c = configuration
        // TLS for every SSF URL (RFC 9700 §2.6), loopback excepted: they receive the person's access token,
        // and the JWKS is what every SET is trusted by.
        if !c.allowInsecureRequests, !isSecureURL(c.transmitterIssuer) {
            throw OIDCError.ssf("transmitterIssuer must use https: \(c.transmitterIssuer)", code: "insecure_endpoint")
        }
        let m = try await discoverSSFTransmitter(issuer: c.transmitterIssuer, transport: c.transport, timeout: c.httpTimeout)
        if !c.allowInsecureRequests {
            for key in ssfURLMembers {
                if let value = m.string(key), !isSecureURL(value) { throw OIDCError.ssf("SSF metadata \(key) must use https: \(value)", code: "insecure_endpoint") }
            }
        }
        guard let jwksURL = m.string("jwks_uri").flatMap(URL.init(string:)) else { throw OIDCError.ssf("SSF metadata jwks_uri is not a URL") }
        if let supported = m["delivery_methods_supported"]?.stringArrayValue, !supported.contains(Delivery.poll) {
            throw OIDCError.ssf("Transmitter does not support poll delivery (\(Delivery.poll))")
        }
        metadata = m
        jwks = RemoteJWKSet(url: jwksURL, http: http, now: c.now)
        return m
    }

    /// Discovers the transmitter, creates (or reuses) a stream, and starts polling. If the transmitter already
    /// has a stream for this receiver (HTTP 409), that stream is reused and re-pointed at this receiver's
    /// delivery settings.
    ///
    /// With `catchUp`, the SETs already queued on the stream are polled and dispatched before this returns,
    /// so that a session revoked while the receiver was stopped is acted on before the session is used.
    @discardableResult
    public func start(catchUp: Bool = false) async throws -> JSONObject {
        if metadata == nil { try await discover() }
        if let id = configuration.streamID {
            stream = try await getStream(id)
        } else if metadata?["configuration_endpoint"] != nil {
            do {
                stream = try await createStream()
            } catch let e as OIDCError where e.status == 409 {
                let existing = try await listStreams()
                guard let first = existing.first else { throw e }
                stream = first
                stream = try await updateStream(["delivery": deliveryRequest, "events_requested": JSONValue(configuration.eventsRequested)])
            }
        } else {
            throw OIDCError.ssf("Transmitter has no configuration_endpoint and no streamID was supplied")
        }
        var more = catchUp
        // A handler may end the account and delete the stream while catching up: then there is nothing to poll.
        while more, stream != nil { more = try await poll().moreAvailable }
        guard stream != nil else { return [:] }
        polling = true
        pollNow()
        return stream ?? [:]
    }

    /// Stops polling, sends the acknowledgements still owed, and optionally deletes the stream at the transmitter.
    public func stop(deleteStream: Bool = false) async {
        polling = false
        loopTask?.cancel()
        loopTask = nil
        // A poll still running may finish handling SETs; their acknowledgements go in the flush below.
        // Called from inside a handler (which runs within a poll), waiting for that poll would never end: the
        // poll sends the last acknowledgements when it finishes instead.
        if dispatchDepth > 0, pollInFlight != nil {
            flushWhenPollEnds = true
            return
        }
        if let running = pollInFlight { _ = try? await running.value }
        await flushAcks()
        if deleteStream, stream?.string("stream_id") != nil {
            do { try await self.deleteStream() } catch { emitError(.wrap(error), SSFErrorContext(phase: .stop)) }
        }
    }

    // MARK: Stream management API (SSF 1.0 §8.1)

    /// Creates a stream with this receiver's delivery settings and requested events.
    @discardableResult
    public func createStream(_ extra: JSONObject = [:]) async throws -> JSONObject {
        var body: JSONObject = ["delivery": deliveryRequest, "events_requested": JSONValue(configuration.eventsRequested),
                                "description": .string(configuration.description)]
        body.merge(extra) { _, b in b }
        stream = try await mgmt("POST", try endpoint("configuration_endpoint"), body)?.objectValue
        return stream ?? [:]
    }

    /// Every stream the transmitter has for this receiver.
    public func listStreams() async throws -> [JSONObject] {
        let result = try await mgmt("GET", try endpoint("configuration_endpoint"))
        if let list = result?.arrayValue { return list.compactMap(\.objectValue) }
        return result?.objectValue.map { [$0] } ?? []
    }

    @discardableResult
    public func getStream(_ streamID: String? = nil) async throws -> JSONObject {
        guard let id = streamID ?? stream?.string("stream_id") else { throw OIDCError.ssf("No stream; call start() or createStream() first") }
        stream = try await mgmt("GET", try endpoint("configuration_endpoint").appendingQuery(FormParameters([("stream_id", id)])))?.objectValue
        return stream ?? [:]
    }

    /// PATCH the stream configuration.
    @discardableResult
    public func updateStream(_ changes: JSONObject) async throws -> JSONObject {
        var body = changes
        body["stream_id"] = .string(try streamID())
        stream = try await mgmt("PATCH", try endpoint("configuration_endpoint"), body)?.objectValue
        return stream ?? [:]
    }

    /// PUT (replace) the stream configuration.
    @discardableResult
    public func replaceStream(_ configuration: JSONObject) async throws -> JSONObject {
        var body = configuration
        body["stream_id"] = .string(try streamID())
        stream = try await mgmt("PUT", try endpoint("configuration_endpoint"), body)?.objectValue
        return stream ?? [:]
    }

    public func deleteStream() async throws {
        let url = try endpoint("configuration_endpoint").appendingQuery(FormParameters([("stream_id", try streamID())]))
        _ = try await mgmt("DELETE", url)
        stream = nil
    }

    /// The stream's status: `{ stream_id, status: enabled|paused|disabled, reason? }`.
    public func getStatus() async throws -> JSONObject {
        let url = try endpoint("status_endpoint").appendingQuery(FormParameters([("stream_id", try streamID())]))
        return try await mgmt("GET", url)?.objectValue ?? [:]
    }

    /// Sets the stream's status (`enabled`, `paused` or `disabled`).
    @discardableResult
    public func updateStatus(_ status: String, reason: String? = nil) async throws -> JSONObject {
        var body: JSONObject = ["stream_id": .string(try streamID()), "status": .string(status)]
        if let reason { body["reason"] = .string(reason) }
        return try await mgmt("POST", try endpoint("status_endpoint"), body)?.objectValue ?? [:]
    }

    /// Asks the transmitter to include events about a subject in this stream (e.g. `Subject.issSub(iss, sub)`).
    public func addSubject(_ subject: JSONObject, verified: Bool? = nil) async throws {
        var body: JSONObject = ["stream_id": .string(try streamID()), "subject": .object(subject)]
        if let verified { body["verified"] = .bool(verified) }
        _ = try await mgmt("POST", try endpoint("add_subject_endpoint"), body)
    }

    public func removeSubject(_ subject: JSONObject) async throws {
        _ = try await mgmt("POST", try endpoint("remove_subject_endpoint"), ["stream_id": .string(try streamID()), "subject": .object(subject)])
    }

    /// Requests a verification event (SSF §8.1.4) and returns it once received.
    @discardableResult
    public func requestVerification(timeout: TimeInterval = 15, state: String = randomToken(bytes: 16)) async throws -> SecurityEvent {
        let waiter = VerificationWaiter()
        pendingVerifications[state] = waiter
        do {
            _ = try await mgmt("POST", try endpoint("verification_endpoint"), ["stream_id": .string(try streamID()), "state": .string(state)])
        } catch {
            pendingVerifications[state] = nil
            throw error
        }
        pollNow()
        defer { pendingVerifications[state] = nil }
        return try await waiter.wait(timeout: timeout)
    }

    // MARK: Delivery

    /// Validates a SET and runs its handlers. Use this for SETs received through your own transport.
    /// Returns the dispatched events (empty for a replayed `jti`).
    @discardableResult
    public func receiveSet(_ token: String) async throws -> [SecurityEvent] {
        let events = try await validateSet(token)
        _ = await dispatchAll(events)
        return events
    }

    /// Validates a SET (RFC 8417 / SSF 1.0 §4) without dispatching it. A replayed `jti` returns an empty array.
    public func validateSet(_ token: String) async throws -> [SecurityEvent] {
        if jwks == nil { try await discover() }
        guard let jwks, let metadata else { throw OIDCError.ssf("Receiver not initialised; call discover() or start()") }
        let c = configuration
        guard token.split(separator: ".", omittingEmptySubsequences: false).count == 3 else {
            throw OIDCError.set("Body is not a compact-serialised JWS", code: "invalid_request")
        }
        let header: JSONObject
        do { header = try CompactJWS(token).header } catch { throw OIDCError.set("Malformed JWS header", code: "invalid_request", underlying: error) }
        let alg = header.string("alg") ?? ""
        guard asymmetricJWSAlgorithms.contains(alg) else {
            throw OIDCError.set("SET is signed with \"\(alg)\", which this receiver cannot verify (supported: \(asymmetricJWSAlgorithms.joined(separator: ", ")))", code: "invalid_key")
        }
        if c.requireTyp {
            var typ = header.string("typ")?.lowercased() ?? ""
            if typ.hasPrefix("application/") { typ.removeFirst("application/".count) }
            guard typ == "secevent+jwt" else { throw OIDCError.set("Unexpected typ \"\(header.string("typ") ?? "")\"; expected secevent+jwt", code: "invalid_request") }
        }
        // Fail closed: SSF 1.0 requires the transmitter to supply the stream's `aud`, so a missing one is not
        // a reason to accept SETs addressed to anybody.
        let audience = c.audience ?? stream?["aud"].flatMap { $0.stringValue.map { [$0] } ?? $0.stringArrayValue }
        guard let audience, !audience.isEmpty else {
            throw OIDCError.set("No expected SET audience: the stream configuration has no \"aud\" and no audience option was set", code: "invalid_audience")
        }
        let claims: JSONObject
        do {
            claims = try await verifyJWT(token, keys: jwks, options: JWTVerifyOptions(
                algorithms: asymmetricJWSAlgorithms, issuer: metadata.string("issuer"), audience: audience, clockTolerance: c.clockTolerance,
                maxTokenAge: c.maxSetAge > 0 ? c.maxSetAge : nil, requiredClaims: ["iss", "jti", "iat", "events"], now: now)).claims
        } catch let e as JOSEError {
            throw Self.mapJOSEError(e)
        }
        guard let iat = claims["iat"]?.doubleValue, iat <= now.timeIntervalSince1970 + c.clockTolerance else {
            throw OIDCError.set("SET iat is missing or in the future", code: "invalid_request")
        }
        guard let events = claims["events"]?.objectValue else { throw OIDCError.set("SET \"events\" claim must be an object", code: "invalid_request") }
        // SSF 1.0 §4.1.8: the events claim contains exactly one event.
        guard events.count == 1, let (type, payload) = events.first else {
            throw OIDCError.set("SET \"events\" claim must contain exactly one event, not \(events.count)", code: "invalid_request")
        }
        // A stream event (verification, stream-updated) is about a stream, named by an opaque sub_id. One that
        // names another stream, or something else, is not about this one.
        if type == SSF.verification || type == SSF.streamUpdated, let subId = claims["sub_id"] {
            let ours = stream?.string("stream_id") ?? c.streamID
            if subId["format"]?.stringValue != "opaque" || (ours != nil && subId["id"]?.stringValue != ours) {
                throw OIDCError.set("\(eventName(type)) event is not about this stream", code: "invalid_request")
            }
        }
        guard let jti = claims.string("jti") else { throw OIDCError.set("SET jti must be a string", code: "invalid_request") }
        if seenJtis[jti] != nil { return [] }
        rememberJti(jti)
        return [SecurityEvent(type: type, payload: payload.objectValue ?? [:], set: claims, raw: token)]
    }

    /// Polls now (when polling). During a poll, another follows right after it.
    public func pollNow() {
        guard polling else { return }
        if pollInFlight != nil {
            pollAgain = true
            return
        }
        scheduleLoop(0)
    }

    /// Performs one RFC 8936 poll request, acknowledging the SETs already handled. Polls never overlap: a
    /// call during a poll shares it.
    @discardableResult
    public func poll() async throws -> PollResult {
        if let running = pollInFlight { return try await running.value }
        // The slot is cleared by the task itself, before anyone awaiting it resumes, so a call made right after
        // a poll finishes starts a new poll rather than joining the finished one.
        let task = Task { () throws -> PollResult in
            defer { self.pollInFlight = nil }
            return try await self.pollOnce()
        }
        pollInFlight = task
        return try await task.value
    }

    private func pollOnce() async throws -> PollResult {
        let endpoint = try pollEndpoint()
        let ack = pendingAcks
        pendingAcks = []
        let setErrs = pendingErrs
        pendingErrs = [:]
        var body: JSONObject = ["maxEvents": JSONValue(configuration.maxEvents), "returnImmediately": true, "ack": JSONValue(ack)]
        if !setErrs.isEmpty { body["setErrs"] = .object(setErrs) }
        let result: JSONValue?
        do {
            result = try await mgmt("POST", endpoint, body)
        } catch {
            // Put the acknowledgements back so they're sent with the next poll.
            pendingAcks.insert(contentsOf: ack, at: 0)
            pendingErrs.merge(setErrs) { current, _ in current }
            throw error
        }
        // The `sets` object has no order; SETs are handled oldest first.
        let sets = (result?["sets"]?.objectValue ?? [:]).compactMap { jti, token in token.stringValue.map { (jti, $0) } }
            .sorted { a, b in
                let ia = decodeUnverifiedJWTPayload(a.1)?["iat"]?.doubleValue ?? 0, ib = decodeUnverifiedJWTPayload(b.1)?["iat"]?.doubleValue ?? 0
                return ia == ib ? a.0 < b.0 : ia < ib
            }
        for (jti, token) in sets {
            guard polling || !flushWhenPollEnds else { break }
            await receivePolled(jti, token)
        }
        if flushWhenPollEnds {
            flushWhenPollEnds = false
            await flushAcks()
        }
        return PollResult(received: sets.count, moreAvailable: result?["moreAvailable"]?.boolValue == true)
    }

    /// One polled SET. RFC 8936 §2.4: an acknowledged SET, and one reported in `setErrs`, are never sent again.
    /// So a SET is acknowledged only once its handlers ran without throwing, and reported only when it is
    /// definitely invalid. One whose handlers threw is left for the transmitter to send again, up to
    /// `maxDeliveryAttempts` times; one that could not be checked for a reason that may pass is left until it can.
    private func receivePolled(_ jti: String, _ token: String) async {
        // Being handled right now: neither acknowledged nor reported, so the transmitter keeps it until done.
        guard !inFlight.contains(jti) else { return }
        inFlight.insert(jti)
        defer { inFlight.remove(jti) }

        let events: [SecurityEvent]
        do {
            events = try await validateSet(token)
        } catch {
            let e = OIDCError.wrap(error)
            if e.retryable {
                emitError(e, SSFErrorContext(phase: .poll, jti: jti, willRetry: true))
                return
            }
            attempts[jti] = nil
            pendingErrs[jti] = ["err": .string(e.kind == .setValidation ? (e.code ?? "invalid_request") : "invalid_request"), "description": .string(e.message)]
            emitError(e, SSFErrorContext(phase: .poll, jti: jti))
            return
        }
        let handled = await dispatchAll(events)
        if !handled, attempt(jti) < configuration.maxDeliveryAttempts {
            // Let the redelivery through the replay check: it is the same SET, not handled yet.
            for evt in events { forgetJti(evt.jti) }
            return
        }
        if !handled {
            emitError(OIDCError.ssf("Gave up on SET \(jti) after \(configuration.maxDeliveryAttempts) attempts; its handlers kept throwing", code: "handler_failed"),
                      SSFErrorContext(phase: .handler, jti: jti))
        }
        attempts[jti] = nil
        if !pendingAcks.contains(jti) { pendingAcks.append(jti) }
    }

    private func attempt(_ jti: String) -> Int {
        let n = (attempts[jti] ?? 0) + 1
        attempts[jti] = n
        if attempts.count > configuration.jtiCacheSize, let k = attempts.keys.first(where: { $0 != jti }) { attempts[k] = nil }
        return n
    }

    /// The poll endpoint, which receives the person's access token on every request. It comes from the
    /// stream configuration, not the transmitter's metadata, so it must use TLS and share an origin with the
    /// transmitter's own endpoints: a stream re-pointed elsewhere must not be handed the token.
    private func pollEndpoint() throws -> URL {
        guard let s = stream?["delivery"]?["endpoint_url"]?.stringValue, let endpoint = URL(string: s) else {
            throw OIDCError.ssf("Stream has no poll endpoint_url")
        }
        if !configuration.allowInsecureRequests, !isSecureURL(s) {
            throw OIDCError.ssf("Poll endpoint_url must use https: \(s)", code: "insecure_endpoint")
        }
        let trusted = ([metadata?.string("issuer"), metadata?.string("configuration_endpoint")].compactMap { $0 } + configuration.trustedPollOrigins).compactMap(originOf)
        guard let origin = originOf(endpoint), trusted.contains(origin) else {
            throw OIDCError.ssf("Poll endpoint_url \(s) is not at the transmitter's origin (\(trusted.joined(separator: ", "))); not sending the access token there",
                                code: "untrusted_endpoint")
        }
        return endpoint
    }

    /// Sends the acknowledgements and errors still owed, so a stopped receiver is not sent them again.
    private func flushAcks() async {
        guard !pendingAcks.isEmpty || !pendingErrs.isEmpty, stream?["delivery"]?["endpoint_url"] != nil, metadata != nil else { return }
        let ack = pendingAcks
        pendingAcks = []
        let setErrs = pendingErrs
        pendingErrs = [:]
        do {
            var body: JSONObject = ["maxEvents": 0, "returnImmediately": true, "ack": JSONValue(ack)]
            if !setErrs.isEmpty { body["setErrs"] = .object(setErrs) }
            _ = try await mgmt("POST", try pollEndpoint(), body)
        } catch {
            pendingAcks.insert(contentsOf: ack, at: 0)
            pendingErrs.merge(setErrs) { current, _ in current }
            emitError(.wrap(error), SSFErrorContext(phase: .stop))
        }
    }

    // MARK: Internals

    private var deliveryRequest: JSONValue { ["method": .string(Delivery.poll)] }

    private func scheduleLoop(_ delay: TimeInterval) {
        loopTask?.cancel()
        loopTask = Task { [weak self] in
            if delay > 0 { try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            if Task.isCancelled { return }
            await self?.pollLoop()
        }
    }

    private func pollLoop() async {
        guard polling else { return }
        loopTask = nil
        pollAgain = false
        var delay = configuration.pollInterval
        do {
            if try await poll().moreAvailable { delay = 0 }
        } catch {
            emitError(.wrap(error), SSFErrorContext(phase: .poll))
        }
        if pollAgain { delay = 0 }
        if polling, loopTask == nil { scheduleLoop(delay) }
    }

    /// False when a handler threw.
    private func dispatchAll(_ events: [SecurityEvent]) async -> Bool {
        dispatchDepth += 1
        defer { dispatchDepth -= 1 }
        var ok = true
        for evt in events { ok = await dispatch(evt) && ok }
        return ok
    }

    private func dispatch(_ evt: SecurityEvent) async -> Bool {
        if evt.type == SSF.verification, let state = evt.payload.string("state") {
            pendingVerifications.removeValue(forKey: state)?.resolve(evt)
        }
        // validateSet() refused a stream event that names another stream; one with no sub_id is the stream's.
        if evt.type == SSF.streamUpdated, stream != nil, let status = evt.payload["status"] { stream?["status"] = status }
        if let hook = configuration.onEventReceived {
            do { try await hook(evt) } catch { emitError(.wrap(error), SSFErrorContext(phase: .hook, event: evt)) }
        }
        let registered = handlers.state.current
        let specific = registered.byType[evt.type] ?? []
        var ok = true
        for h in (specific.isEmpty ? registered.unhandled : specific) + registered.any {
            do { try await h(evt) } catch {
                ok = false
                emitError(.wrap(error), SSFErrorContext(phase: .handler, event: evt))
            }
        }
        return ok
    }

    private func emitError(_ error: OIDCError, _ context: SSFErrorContext) {
        let registered = handlers.state.current.errors
        // Never silent: a security event that could not be handled must leave a trace.
        guard !registered.isEmpty else {
            OIDCLog.log(.error, "\(context.phase.rawValue): \(error.message)")
            return
        }
        for h in registered { h(error, context) }
    }

    private func rememberJti(_ jti: String) {
        seenJtis[jti] = 1
        seenOrder.append(jti)
        while seenOrder.count > configuration.jtiCacheSize {
            seenJtis[seenOrder.removeFirst()] = nil
        }
    }

    private func forgetJti(_ jti: String) {
        seenJtis[jti] = nil
        seenOrder.removeAll { $0 == jti }
    }

    private func endpoint(_ name: String) throws -> URL {
        guard let metadata else { throw OIDCError.ssf("Receiver not initialised; call discover() or start()") }
        guard let s = metadata.string(name), let url = URL(string: s) else { throw OIDCError.ssf("Transmitter does not advertise \(name)") }
        return url
    }

    private func streamID() throws -> String {
        guard let id = stream?.string("stream_id") ?? configuration.streamID else { throw OIDCError.ssf("No stream; call start() or createStream() first") }
        return id
    }

    private func mgmt(_ method: String, _ url: URL, _ body: JSONObject? = nil) async throws -> JSONValue? {
        let data = try body.map { try JSONValue.object($0).jsonData() }
        func send(_ nonce: String?) async throws -> HTTPResponse {
            var headers = ["accept": "application/json"]
            switch configuration.authorization {
            case .headers(let make):
                for (k, v) in try await make(SSFRequestInfo(method: method, url: url, nonce: nonce)) { headers[k.lowercased()] = v }
            case .bearer(let token):
                headers["authorization"] = "Bearer \(try await token())"
            case nil:
                break
            }
            if data != nil { headers["content-type"] = "application/json" }
            return try await http.send(HTTPRequest(url: url, method: method, headers: headers, body: data))
        }
        var res = try await send(nil)
        // A resource server may demand a DPoP nonce (RFC 9449 §9): retry once with it.
        if case .headers = configuration.authorization, wantsDPoPNonce(res) {
            res = try await send(res.header("dpop-nonce"))
        }
        do {
            return try readJSON(res, errorKind: .ssf)
        } catch var e as OIDCError where e.kind == .oauth {
            e.kind = .ssf
            throw e
        }
    }

    /// A JOSE failure as a SET error: a bad token (reported to the transmitter), or a check that may pass later.
    private static func mapJOSEError(_ e: JOSEError) -> OIDCError {
        switch e {
        case .noMatchingKey:
            var err = OIDCError.set(e.description, code: "invalid_key")
            err.retryable = true
            return err
        case .jwksUnavailable:
            var err = OIDCError.set(e.description, code: "invalid_request")
            err.retryable = true
            return err
        case .expired(claim: "iat", _):
            return OIDCError.set("SET is too old: \(e.description)", code: "invalid_request")
        case .claimFailed(claim: "iat", _):
            return OIDCError.set("SET iat is not acceptable: \(e.description)", code: "invalid_request")
        case .claimFailed(claim: "iss", _):
            return OIDCError.set(e.description, code: "invalid_issuer")
        case .claimFailed(claim: "aud", _):
            return OIDCError.set(e.description, code: "invalid_audience")
        case .signatureFailed, .algNotAllowed:
            return OIDCError.set(e.description, code: "invalid_key")
        default:
            return OIDCError.set(e.description, code: "invalid_request")
        }
    }
}

/// Waits for one verification event, or a timeout.
private final class VerificationWaiter: @unchecked Sendable {
    private enum State { case waiting(CheckedContinuation<SecurityEvent, Error>?), done(Result<SecurityEvent, OIDCError>) }
    private let state = Locked<State>(.waiting(nil))

    func resolve(_ event: SecurityEvent) { finish(.success(event)) }

    func wait(timeout: TimeInterval) async throws -> SecurityEvent {
        let timer = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            if !Task.isCancelled {
                self?.finish(.failure(OIDCError.ssf("Verification event not received within \(Int(timeout * 1000))ms", code: "verification_timeout")))
            }
        }
        defer { timer.cancel() }
        return try await withCheckedThrowingContinuation { continuation in
            let ready: Result<SecurityEvent, OIDCError>? = state.withLock { s in
                if case .done(let r) = s { return r }
                s = .waiting(continuation)
                return nil
            }
            if let ready { continuation.resume(with: ready) }
        }
    }

    private func finish(_ result: Result<SecurityEvent, OIDCError>) {
        let waiting: CheckedContinuation<SecurityEvent, Error>?? = state.withLock { s in
            guard case .waiting(let c) = s else { return .none }
            s = .done(result)
            return .some(c)
        }
        if case .some(.some(let c)) = waiting { c.resume(with: result.mapError { $0 as Error }) }
    }
}
