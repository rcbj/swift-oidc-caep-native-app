// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#if canImport(AuthenticationServices)
import AuthenticationServices
import Foundation
#if canImport(AppKit)
import AppKit
#endif

/// ``WebAuthenticator`` with `ASWebAuthenticationSession`: the provider's pages open in the person's
/// default browser (sharing its sign-in session), and the session ends when the browser is redirected to
/// the app's redirect URI.
///
/// The redirect URI must be a private-use scheme (`com.example.app:/callback`, RFC 8252 §7.1), or, on
/// macOS 14.4 and later, an https URL on a domain the app claims with an associated domain.
public final class SystemWebAuthenticator: NSObject, WebAuthenticator, @unchecked Sendable {
    /// Ask the browser not to share cookies with this sign-in. Off by default: sharing the browser's session
    /// is what lets several accounts, single sign-on and `prompt=none` work.
    public let prefersEphemeralWebBrowserSession: Bool
    private let anchor: (@MainActor @Sendable () -> ASPresentationAnchor?)?

    /// - Parameters:
    ///   - anchor: The window the browser sheet belongs to. Default: the key window.
    public init(prefersEphemeralWebBrowserSession: Bool = false, anchor: (@MainActor @Sendable () -> ASPresentationAnchor?)? = nil) {
        self.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
        self.anchor = anchor
        super.init()
    }

    public func authenticate(url: URL, callback: URL) async throws -> URL {
        guard let scheme = callback.scheme?.lowercased() else { throw OIDCError.usage("The redirect URI has no scheme: \(callback.absoluteString)") }
        if scheme == "http" {
            throw OIDCError.usage("ASWebAuthenticationSession cannot receive a loopback http redirect; use a private-use scheme such as com.example.app:/callback")
        }
        let box = SessionBox()
        return try await withTaskCancellationHandler {
            try await start(url: url, callback: callback, scheme: scheme, box: box)
        } onCancel: {
            Task { @MainActor in box.session?.cancel() }
        }
    }

    @MainActor
    private func start(url: URL, callback: URL, scheme: String, box: SessionBox) async throws -> URL {
        let provider = AnchorProvider(anchor: anchor?() ?? Self.defaultAnchor())
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
            let completion: (URL?, Error?) -> Void = { result, error in
                box.session = nil
                if let result {
                    continuation.resume(returning: result)
                } else if let e = error as? ASWebAuthenticationSessionError, e.code == .canceledLogin {
                    continuation.resume(throwing: OIDCError(kind: .general, "The sign-in window was closed", code: OIDCError.userCancelledCode))
                } else {
                    continuation.resume(throwing: OIDCError(kind: .general, "The browser sign-in failed: \(error?.localizedDescription ?? "no redirect")",
                                                            code: "web_authentication_failed", underlying: error))
                }
            }
            let session: ASWebAuthenticationSession
            if scheme == "https" {
                guard #available(macOS 14.4, iOS 17.4, *), let host = callback.host else {
                    continuation.resume(throwing: OIDCError.usage("An https redirect URI needs macOS 14.4 or later and an associated domain; use a private-use scheme"))
                    return
                }
                session = ASWebAuthenticationSession(url: url, callback: .https(host: host, path: callback.path), completionHandler: completion)
            } else {
                session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: completion)
            }
            session.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
            session.presentationContextProvider = provider
            box.session = session
            box.provider = provider
            if !session.start() {
                box.session = nil
                continuation.resume(throwing: OIDCError(kind: .general, "The browser sign-in could not start", code: "web_authentication_failed"))
            }
        }
    }

    @MainActor
    private static func defaultAnchor() -> ASPresentationAnchor {
        #if canImport(AppKit)
        return NSApplication.shared.keyWindow ?? NSApplication.shared.mainWindow ?? NSApplication.shared.windows.first ?? ASPresentationAnchor()
        #else
        return ASPresentationAnchor()
        #endif
    }
}

/// Keeps the session (and its anchor provider) alive until it completes.
private final class SessionBox: @unchecked Sendable {
    var session: ASWebAuthenticationSession?
    var provider: AnchorProvider?
}

private final class AnchorProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
    let anchor: ASPresentationAnchor
    init(anchor: ASPresentationAnchor) { self.anchor = anchor }
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { anchor }
}
#endif

#if canImport(AuthenticationServices)
extension OIDCAppConfiguration {
    /// A ``SystemWebAuthenticator`` with this configuration's `PrefersEphemeralWebBrowserSession`.
    public func makeAuthenticator() -> SystemWebAuthenticator {
        SystemWebAuthenticator(prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession)
    }
}
#endif
