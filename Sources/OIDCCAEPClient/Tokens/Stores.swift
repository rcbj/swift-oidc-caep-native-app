// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation

/// Where tokens (and an ``AccountManager``'s account list) are kept: opaque values by key.
///
/// ``MemoryTokenStore`` keeps nothing past the process. ``KeychainTokenStore`` (Apple platforms) keeps the
/// values in the Keychain, so a relaunch keeps every signed-in account.
public protocol TokenStore: Sendable {
    func get(_ key: String) async throws -> Data?
    func set(_ key: String, _ value: Data) async throws
    func delete(_ key: String) async throws
    /// Whether values outlive the process. A persistent store without DPoP logs a warning.
    var isPersistent: Bool { get }
}

extension TokenStore {
    public var isPersistent: Bool { true }

    func getJSON(_ key: String) async throws -> JSONObject? {
        guard let data = try await get(key) else { return nil }
        return try? JSONValue.parseObject(data)
    }

    func setJSON(_ key: String, _ value: JSONObject) async throws {
        try await set(key, try JSONValue.object(value).jsonData())
    }
}

/// Where tokens are cached unless an app says otherwise: the platform's secure storage when it has one
/// (the Keychain, ``KeychainTokenStore``, on macOS and iOS), and memory (``MemoryTokenStore``) otherwise.
public func defaultTokenStore(service: String = defaultKeychainService("tokens")) -> any TokenStore {
    #if canImport(Security)
    return KeychainTokenStore(service: service)
    #else
    return MemoryTokenStore()
    #endif
}

/// A Keychain service name of this app's own: `<bundle id>.oidc-<purpose>` (or `oidc-caep-client.<purpose>`
/// for a binary without a bundle id), so two apps using the library never share items.
public func defaultKeychainService(_ purpose: String) -> String {
    Bundle.main.bundleIdentifier.map { "\($0).oidc-\(purpose)" } ?? "oidc-caep-client.\(purpose)"
}

/// Tokens in memory only: nothing persists, so a relaunch means signing in again (or resuming silently
/// with `prompt=none` while the provider's session lasts).
public actor MemoryTokenStore: TokenStore {
    private var values: [String: Data] = [:]
    public init() {}
    public func get(_ key: String) -> Data? { values[key] }
    public func set(_ key: String, _ value: Data) { values[key] = value }
    public func delete(_ key: String) { values[key] = nil }
    public var keys: [String] { Array(values.keys) }
    public nonisolated var isPersistent: Bool { false }
}

/// One authorization request in progress: what the callback needs to check the response and redeem the code.
public struct AuthorizationTransaction: Codable, Sendable, Equatable {
    public var state: String
    public var nonce: String
    public var codeVerifier: String
    public var redirectURI: String
    public var maxAge: Int?
    public var acrValues: String?
    public var expectedSub: String?
    public var context: JSONValue?
    public var issuer: String
    public var clientID: String
    /// When the request was created (seconds since 1970).
    public var createdAt: TimeInterval
}

/// A logout request in progress (RP-Initiated Logout), kept to check the `state` it returns with.
public struct LogoutTransaction: Codable, Sendable, Equatable {
    public var state: String
    public var context: JSONValue?
    public var createdAt: TimeInterval
}

/// Authorization and logout transactions between the request and its callback, keyed by `state`. `take`
/// removes the entry as it reads it, so each transaction (and therefore each response) is used once.
///
/// A native app receives the callback in the same process that made the request, so the default,
/// ``MemoryTransactionStore``, is enough.
public protocol TransactionStore: Sendable {
    func set(_ id: String, _ value: Data) async
    /// Reads and removes a transaction.
    func take(_ id: String) async -> Data?
    /// Removes transactions created before `cutoff` (abandoned sign-ins).
    func sweep(createdBefore cutoff: Date) async
}

/// Transactions in memory.
public actor MemoryTransactionStore: TransactionStore {
    private var values: [String: (data: Data, at: Date)] = [:]
    public init() {}
    public func set(_ id: String, _ value: Data) { values[id] = (value, Date()) }
    public func take(_ id: String) -> Data? {
        guard !id.isEmpty else { return nil }
        return values.removeValue(forKey: id)?.data
    }
    public func sweep(createdBefore cutoff: Date) {
        values = values.filter { $0.value.at >= cutoff }
    }
}
