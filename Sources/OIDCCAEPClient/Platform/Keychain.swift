// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#if canImport(Security)
import Foundation
import Security

/// Generic-password items of one Keychain service.
struct KeychainItems: Sendable {
    let service: String
    let accessGroup: String?
    let useDataProtectionKeychain: Bool

    private func query(_ account: String) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        if useDataProtectionKeychain { q[kSecUseDataProtectionKeychain as String] = true }
        return q
    }

    func get(_ account: String) throws -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try check(status, "read")
        return result as? Data
    }

    func set(_ account: String, _ value: Data) throws {
        var attributes: [String: Any] = [kSecValueData as String: value]
        if useDataProtectionKeychain { attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly }
        let status = SecItemUpdate(query(account) as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var add = query(account)
            for (k, v) in attributes { add[k] = v }
            try check(SecItemAdd(add as CFDictionary, nil), "write")
        } else {
            try check(status, "write")
        }
    }

    func delete(_ account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        if status != errSecItemNotFound { try check(status, "delete") }
    }

    private func check(_ status: OSStatus, _ action: String) throws {
        guard status != errSecSuccess else { return }
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        throw OIDCError(kind: .general, "Keychain \(action) failed: \(message)", code: "keychain_error")
    }
}

/// Tokens (and an ``AccountManager``'s account list) in the Keychain, as generic-password items of one
/// service. They survive relaunches, so every signed-in account stays signed in.
///
/// Pair it with DPoP (ideally ``SecureEnclaveKeyStore``): a DPoP-bound refresh token is useless without the
/// key it is bound to.
public actor KeychainTokenStore: TokenStore {
    private let items: KeychainItems

    /// - Parameters:
    ///   - service: The Keychain service the items are stored under.
    ///   - accessGroup: A Keychain access group shared with other apps of the same team.
    ///   - useDataProtectionKeychain: Use the data protection keychain (needs a signed app with a
    ///     `keychain-access-groups` entitlement on macOS). Default: the login keychain.
    public init(service: String = defaultKeychainService("tokens"), accessGroup: String? = nil, useDataProtectionKeychain: Bool = false) {
        items = KeychainItems(service: service, accessGroup: accessGroup, useDataProtectionKeychain: useDataProtectionKeychain)
    }

    public func get(_ key: String) throws -> Data? { try items.get(key) }
    public func set(_ key: String, _ value: Data) throws { try items.set(key, value) }
    public func delete(_ key: String) throws { try items.delete(key) }
    public nonisolated var isPersistent: Bool { true }
}

/// A software DPoP key whose private bytes are kept in the Keychain. Use it where the Secure Enclave is
/// unavailable; ``SecureEnclaveKeyStore`` keeps a key nothing can read out.
public actor KeychainKeyStore: DPoPKeyStore {
    private let items: KeychainItems
    private let account: String

    public init(service: String = defaultKeychainService("dpop"), account: String = "dpop-key", accessGroup: String? = nil, useDataProtectionKeychain: Bool = false) {
        items = KeychainItems(service: service, accessGroup: accessGroup, useDataProtectionKeychain: useDataProtectionKeychain)
        self.account = account
    }

    public func load(alg: String) throws -> (any JWSSigner)? {
        guard let data = try items.get(account), let saved = try? JSONValue.parseObject(data), saved.string("alg") == alg,
              let raw = saved.string("key").flatMap(Base64URL.decode) else { return nil }
        return try SoftwareECSigner(alg: alg, rawPrivateKey: raw)
    }

    public func create(alg: String) throws -> any JWSSigner {
        let signer = try SoftwareECSigner(alg: alg)
        let saved: JSONObject = ["alg": .string(alg), "key": .string(Base64URL.encode(signer.rawPrivateKey))]
        try items.set(account, try JSONValue.object(saved).jsonData())
        return signer
    }

    public func delete() throws { try items.delete(account) }
    public nonisolated var supportedAlgorithms: [String] { dpopAlgorithms }
    public nonisolated var isExtractable: Bool { true }
}
#endif
