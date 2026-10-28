// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#if canImport(CryptoKit) && canImport(Security)
import CryptoKit
import Foundation

/// A DPoP key generated in the Secure Enclave (ES256 only). The private key never leaves the Enclave: the
/// app can ask it to sign, but nothing — not the app, not malware running as the user — can read it out,
/// so stolen access and refresh tokens are useless on any other device. This is the native counterpart of
/// the browser library's non-extractable WebCrypto key.
///
/// What is kept in the Keychain is the key's `dataRepresentation`: a handle that only this device's
/// Secure Enclave can use.
public actor SecureEnclaveKeyStore: DPoPKeyStore {
    private let items: KeychainItems
    private let account: String

    /// Whether this Mac has a Secure Enclave (Apple silicon, or a T2 chip).
    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    public init(service: String = defaultKeychainService("dpop"), account: String = "dpop-key-secure-enclave", accessGroup: String? = nil,
                useDataProtectionKeychain: Bool = false) {
        items = KeychainItems(service: service, accessGroup: accessGroup, useDataProtectionKeychain: useDataProtectionKeychain)
        self.account = account
    }

    public func load(alg: String) throws -> (any JWSSigner)? {
        guard alg == "ES256", let data = try items.get(account) else { return nil }
        guard let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data) else { return nil }
        return SecureEnclaveSigner(key: key)
    }

    public func create(alg: String) throws -> any JWSSigner {
        guard alg == "ES256" else { throw OIDCError.usage("The Secure Enclave holds P-256 keys only (ES256), not \(alg)") }
        guard SecureEnclave.isAvailable else { throw OIDCError(kind: .general, "This device has no Secure Enclave", code: "secure_enclave_unavailable") }
        let key: SecureEnclave.P256.Signing.PrivateKey
        do { key = try SecureEnclave.P256.Signing.PrivateKey() } catch {
            throw OIDCError(kind: .general, "The Secure Enclave could not create a key: \(error.localizedDescription)", code: "secure_enclave_unavailable", underlying: error)
        }
        try items.set(account, key.dataRepresentation)
        return SecureEnclaveSigner(key: key)
    }

    public func delete() throws { try items.delete(account) }
    public nonisolated var supportedAlgorithms: [String] { ["ES256"] }
    public nonisolated var isExtractable: Bool { false }
}

struct SecureEnclaveSigner: JWSSigner, @unchecked Sendable {
    let key: SecureEnclave.P256.Signing.PrivateKey
    var alg: String { "ES256" }

    var publicJWK: JSONObject {
        let raw = key.publicKey.rawRepresentation
        return ["kty": "EC", "crv": "P-256", "x": .string(Base64URL.encode(raw.prefix(32))), "y": .string(Base64URL.encode(raw.suffix(32)))]
    }

    func sign(_ data: Data) throws -> Data {
        try key.signature(for: SHA256.hash(data: data)).rawRepresentation
    }
}

/// The best place for a DPoP key on this Mac: the Secure Enclave when it can create keys, else the Keychain.
public func preferredDPoPKeyStore(service: String = defaultKeychainService("dpop")) async -> any DPoPKeyStore {
    let enclave = SecureEnclaveKeyStore(service: service)
    if SecureEnclaveKeyStore.isAvailable {
        if (try? await enclave.load(alg: "ES256")) != nil { return enclave }
        // Creating a key can fail for an unsigned build; then a Keychain-held software key is used.
        if (try? await enclave.create(alg: "ES256")) != nil { return enclave }
    }
    return KeychainKeyStore(service: service)
}
#endif
