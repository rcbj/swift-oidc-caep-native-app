// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation

/// Shows the provider's pages in the system browser and returns the redirect URL it ends at.
///
/// RFC 8252 §8.12: a native app signs people in through an external user agent (the system browser), never
/// an embedded web view, so the app never sees the password and the person's browser session is shared.
/// On Apple platforms, ``SystemWebAuthenticator`` does this with `ASWebAuthenticationSession`.
public protocol WebAuthenticator: Sendable {
    /// Opens `url` and returns the URL the browser is redirected to on `callback`.
    func authenticate(url: URL, callback: URL) async throws -> URL
}

extension OIDCError {
    /// The person closed the sign-in (or logout) window.
    public static let userCancelledCode = "user_cancelled"

    public var isUserCancellation: Bool { code == Self.userCancelledCode }
}

extension OIDCClient {
    /// Signs a person in through the system browser: creates the request, shows it with `authenticator`,
    /// and completes the sign-in from the redirect.
    public func authorize(using authenticator: any WebAuthenticator, _ opts: AuthorizationRequestOptions = .init()) async throws -> AuthorizationResult {
        let request = try await createAuthorizationRequest(opts)
        guard let redirect = opts.redirectURI ?? options.redirectURI else { throw OIDCError.usage("redirectURI is required") }
        let callback = try await authenticator.authenticate(url: request.url, callback: redirect)
        return try await completeAuthorization(callbackURL: callback)
    }

    /// RP-Initiated Logout through the system browser, checking the `state` it returns with. Returns false,
    /// without opening the browser, when there is nothing to complete: the provider has no end_session_endpoint,
    /// or the request has no post-logout redirect URI (the browser window could not close by itself).
    @discardableResult
    public func endSession(using authenticator: any WebAuthenticator, request: EndSessionRequest?) async throws -> Bool {
        guard let request,
              let redirect = Self.responseParameters(request.url).get("post_logout_redirect_uri").flatMap(URL.init(string:)) else { return false }
        let callback = try await authenticator.authenticate(url: request.url, callback: redirect)
        try await completeEndSession(callbackURL: callback)
        return true
    }
}

extension AccountManager {
    /// ``signIn(_:)`` through the system browser, then ``handleCallback(_:)``.
    @discardableResult
    public func signIn(using authenticator: any WebAuthenticator, _ opts: AuthorizationRequestOptions = .init()) async throws -> SignInResult {
        try await run(authenticator, opts, try await signIn(opts))
    }

    /// ``chooseAccount(_:)`` through the system browser.
    @discardableResult
    public func chooseAccount(using authenticator: any WebAuthenticator, _ opts: AuthorizationRequestOptions = .init()) async throws -> SignInResult {
        try await run(authenticator, opts, try await chooseAccount(opts))
    }

    /// ``addAccount(_:)`` through the system browser.
    @discardableResult
    public func addAccount(using authenticator: any WebAuthenticator, _ opts: AuthorizationRequestOptions = .init()) async throws -> SignInResult {
        try await run(authenticator, opts, try await addAccount(opts))
    }

    /// ``resume(_:_:)`` through the system browser.
    @discardableResult
    public func resume(_ key: String, using authenticator: any WebAuthenticator, _ opts: AuthorizationRequestOptions = .init()) async throws -> SignInResult {
        try await run(authenticator, opts, try await resume(key, opts))
    }

    /// ``reauthenticate(_:_:)`` through the system browser.
    @discardableResult
    public func reauthenticate(_ key: String, using authenticator: any WebAuthenticator, _ opts: AuthorizationRequestOptions = .init()) async throws -> SignInResult {
        try await run(authenticator, opts, try await reauthenticate(key, opts))
    }

    /// ``signOut(_:revoke:endSession:postLogoutRedirectURI:)``, then the provider's logout in the system
    /// browser. The account is signed out of the app even if the browser step is cancelled.
    public func signOut(_ key: String? = nil, using authenticator: any WebAuthenticator, revoke: Bool = true) async throws {
        let request = try await signOut(key, revoke: revoke, endSession: true)
        try await client.endSession(using: authenticator, request: request)
    }

    /// ``signOutAll(revoke:endSession:postLogoutRedirectURI:)``, then the provider's logout in the system browser.
    public func signOutAll(using authenticator: any WebAuthenticator, revoke: Bool = true) async throws {
        let request = try await signOutAll(revoke: revoke, endSession: true)
        try await client.endSession(using: authenticator, request: request)
    }

    private func run(_ authenticator: any WebAuthenticator, _ opts: AuthorizationRequestOptions, _ request: AuthorizationRequest) async throws -> SignInResult {
        guard let redirect = opts.redirectURI ?? client.options.redirectURI else { throw OIDCError.usage("redirectURI is required") }
        let callback = try await authenticator.authenticate(url: request.url, callback: redirect)
        return try await handleCallback(callback)
    }
}
