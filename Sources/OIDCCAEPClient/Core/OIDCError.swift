// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation

/// Every error this library throws.
///
/// `kind` says which family it belongs to, and `code` is a stable, machine-readable reason
/// (`state_mismatch`, `invalid_id_token`, `dpop_downgrade`, an OAuth `error` …). Match on those, not on the
/// message.
public struct OIDCError: Error, LocalizedError, CustomStringConvertible, Sendable {
    public enum Kind: String, Sendable {
        /// A failure of the library or the network (`network_error`, `no_tokens`, `not_active` …).
        case general
        /// The authorization server answered with an OAuth 2.0 error (RFC 6749 §5.2, §4.1.2.1).
        /// `code` is the `error` value; ``errorDescription`` and ``errorURI`` hold the rest.
        case oauth
        /// A response from the provider failed validation (bad ID token, state mismatch, metadata mismatch …).
        case validation
        /// A Security Event Token could not be accepted. `code` is an RFC 8935 §2.3 error code.
        case setValidation
        /// A Shared Signals Framework management API call failed.
        case ssf
    }

    public var kind: Kind
    public var message: String
    public var code: String?
    /// The HTTP status, when the error came from an HTTP response.
    public var status: Int?
    /// The response body (or a description of it), when there was one.
    public var response: JSONValue?
    /// OAuth `error_description`.
    public var oauthErrorDescription: String?
    /// OAuth `error_uri`.
    public var errorURI: String?
    /// The `context` the authorization or logout request was created with (see
    /// ``OIDCClient/createAuthorizationRequest(_:)``).
    public var context: JSONValue?
    /// The account a `resume` or `reauth` request was about (``AccountManager``).
    public var account: Account?
    /// The SET may pass on a later attempt (a JWKS that could not be fetched, a key it does not hold yet).
    public var retryable: Bool = false
    /// A description of the underlying error, if any.
    public var underlying: String?

    public init(kind: Kind = .general, _ message: String, code: String? = nil, status: Int? = nil,
                response: JSONValue? = nil, underlying: Error? = nil) {
        self.kind = kind
        self.message = message
        self.code = code
        self.status = status
        self.response = response
        self.underlying = underlying.map { String(describing: $0) }
    }

    /// The OAuth `error` value, for an error of kind `.oauth`.
    public var oauthError: String? { kind == .oauth ? code : nil }

    public var errorDescription: String? { message }
    public var description: String { message }

    static func validation(_ message: String, code: String? = nil, response: JSONValue? = nil) -> OIDCError {
        OIDCError(kind: .validation, message, code: code, response: response)
    }

    static func ssf(_ message: String, code: String? = nil, status: Int? = nil) -> OIDCError {
        OIDCError(kind: .ssf, message, code: code, status: status)
    }

    static func set(_ message: String, code: String = "invalid_request", underlying: Error? = nil) -> OIDCError {
        OIDCError(kind: .setValidation, message, code: code, underlying: underlying)
    }

    static func oauth(error: String, description: String? = nil, uri: String? = nil, status: Int? = nil,
                      response: JSONValue? = nil) -> OIDCError {
        var e = OIDCError(kind: .oauth, description.map { "\(error): \($0)" } ?? error, code: error, status: status, response: response)
        e.oauthErrorDescription = description
        e.errorURI = uri
        return e
    }

    /// A programming error: an option or argument this library cannot use.
    static func usage(_ message: String) -> OIDCError {
        OIDCError(kind: .general, message, code: "invalid_argument")
    }
}

/// Errors the OP answers a `prompt=none` request with when it would have to show the person a screen
/// (OpenID Connect Core §3.1.2.6). `account_selection_required` is what an OP holding several signed-in
/// accounts answers when nothing in the request says which one.
public let interactionRequiredErrors: Set<String> = ["login_required", "interaction_required", "account_selection_required", "consent_required"]

/// True when `error` is an OAuth error that a request showing the sign-in screen (no `prompt=none`) would get past.
public func needsInteraction(_ error: Error) -> Bool {
    guard let e = error as? OIDCError, e.kind == .oauth, let code = e.code else { return false }
    return interactionRequiredErrors.contains(code)
}
