// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation

/// An app's OpenID Connect settings, read from a property list — the usual place a macOS or iOS app keeps
/// configuration that ships with it (as `GoogleService-Info.plist` or MSAL's `Info.plist` keys do).
///
/// Put the settings in **`OIDCConfiguration.plist`** in the app bundle, or in a dictionary under the
/// **`OIDCConfiguration`** key of the app's `Info.plist`:
///
/// ```xml
/// <dict>
///   <key>MetadataURL</key>   <string>https://idp.example.com/.well-known/openid-configuration</string>
///   <key>ClientID</key>      <string>my-native-app</string>
///   <key>Scopes</key>        <array><string>openid</string><string>profile</string><string>email</string></array>
///   <key>RedirectURI</key>   <string>com.example.myapp:/oauth2/callback</string>
/// </dict>
/// ```
///
/// | Key | Type | Required | Meaning |
/// |---|---|---|---|
/// | `MetadataURL` | string | yes | The provider's metadata (discovery) URL |
/// | `ClientID` | string | yes | The public client's `client_id` |
/// | `Scopes` | array or space-separated string | no | Default `openid profile email` (+ `offline_access` when offered) |
/// | `RedirectURI` | string | yes | Private-use scheme (`com.example.app:/callback`) or loopback |
/// | `PostLogoutRedirectURI` | string | no | Where the provider returns after logout |
/// | `Resource` | array or string | no | RFC 8707 resource indicators |
/// | `DPoP` | bool | no | Bind tokens to a key (default `true`) |
/// | `PAR` | string | no | `auto` (default), `always` or `never` |
/// | `IDTokenSignedResponseAlg` | string | no | Default `RS256` |
/// | `ACRValues` | string | no | Requested `acr_values` |
/// | `PrefersEphemeralWebBrowserSession` | bool | no | No shared browser cookies at sign-in (default `false`) |
/// | `SSFTransmitterIssuer` | string | no | CAEP transmitter, if not the provider's issuer |
/// | `CAEPEnabled` | bool | no | Receive CAEP events (default `true`) |
public struct OIDCAppConfiguration: Sendable, Equatable {
    public var metadataURL: URL
    public var clientID: String
    public var scopes: [String]
    public var redirectURI: URL
    public var postLogoutRedirectURI: URL?
    public var resource: [String]
    public var dpop: Bool
    public var par: PARMode
    public var idTokenSignedResponseAlg: String?
    public var acrValues: String?
    public var prefersEphemeralWebBrowserSession: Bool
    public var ssfTransmitterIssuer: String?
    public var caepEnabled: Bool

    /// The scope string (`openid profile email`), or nil for the client's default.
    public var scope: String? { scopes.isEmpty ? nil : scopes.joined(separator: " ") }

    /// The name of the file ``load(bundle:resource:)`` looks for, and of the `Info.plist` key.
    public static let defaultResourceName = "OIDCConfiguration"

    public init(metadataURL: URL, clientID: String, scopes: [String] = [], redirectURI: URL, postLogoutRedirectURI: URL? = nil,
                resource: [String] = [], dpop: Bool = true, par: PARMode = .auto, idTokenSignedResponseAlg: String? = nil,
                acrValues: String? = nil, prefersEphemeralWebBrowserSession: Bool = false, ssfTransmitterIssuer: String? = nil,
                caepEnabled: Bool = true) {
        self.metadataURL = metadataURL
        self.clientID = clientID
        self.scopes = scopes
        self.redirectURI = redirectURI
        self.postLogoutRedirectURI = postLogoutRedirectURI
        self.resource = resource
        self.dpop = dpop
        self.par = par
        self.idTokenSignedResponseAlg = idTokenSignedResponseAlg
        self.acrValues = acrValues
        self.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
        self.ssfTransmitterIssuer = ssfTransmitterIssuer
        self.caepEnabled = caepEnabled
    }

    /// Reads `<resource>.plist` from `bundle`, or else the `<resource>` dictionary in its `Info.plist`.
    public static func load(bundle: Bundle = .main, resource: String = defaultResourceName) throws -> OIDCAppConfiguration {
        if let url = bundle.url(forResource: resource, withExtension: "plist") {
            return try load(contentsOf: url)
        }
        if let dict = bundle.object(forInfoDictionaryKey: resource) as? [String: Any] {
            return try OIDCAppConfiguration(dictionary: dict)
        }
        throw OIDCError.usage("No \(resource).plist in \(bundle.bundleURL.lastPathComponent), and no \(resource) key in its Info.plist")
    }

    /// Reads a property list file (XML or binary).
    public static func load(contentsOf url: URL) throws -> OIDCAppConfiguration {
        try OIDCAppConfiguration(propertyList: try Data(contentsOf: url), source: url.lastPathComponent)
    }

    /// Parses property list data.
    public init(propertyList data: Data, source: String = "the configuration") throws {
        guard let dict = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            throw OIDCError.usage("\(source) is not a dictionary")
        }
        try self.init(dictionary: dict)
    }

    /// From a dictionary with the keys in the table above.
    public init(dictionary d: [String: Any]) throws {
        func string(_ key: String) -> String? {
            (d[key] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        }
        func list(_ key: String) -> [String] {
            if let a = d[key] as? [Any] { return a.compactMap { ($0 as? String)?.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }
            return string(key)?.split(whereSeparator: \.isWhitespace).map(String.init) ?? []
        }
        func url(_ key: String, required: Bool) throws -> URL? {
            guard let s = string(key) else {
                if required { throw OIDCError.usage("The OIDC configuration has no \(key)") }
                return nil
            }
            guard let u = URL(string: s), u.scheme != nil else { throw OIDCError.usage("The OIDC configuration's \(key) is not a URL: \(s)") }
            return u
        }
        guard let metadataURL = try url("MetadataURL", required: true), let redirectURI = try url("RedirectURI", required: true) else {
            throw OIDCError.usage("The OIDC configuration is incomplete")
        }
        guard metadataURL.path.contains("/.well-known/") else {
            throw OIDCError.usage("MetadataURL must be the provider's metadata URL (…/.well-known/openid-configuration), not \(metadataURL.absoluteString)")
        }
        guard let clientID = string("ClientID") else { throw OIDCError.usage("The OIDC configuration has no ClientID") }
        let par = try string("PAR").map { value -> PARMode in
            guard let mode = PARMode(rawValue: value.lowercased()) else { throw OIDCError.usage("PAR must be auto, always or never, not \(value)") }
            return mode
        }
        self.init(metadataURL: metadataURL, clientID: clientID, scopes: list("Scopes"), redirectURI: redirectURI,
                  postLogoutRedirectURI: try url("PostLogoutRedirectURI", required: false), resource: list("Resource"),
                  dpop: d["DPoP"] as? Bool ?? true, par: par ?? .auto, idTokenSignedResponseAlg: string("IDTokenSignedResponseAlg"),
                  acrValues: string("ACRValues"), prefersEphemeralWebBrowserSession: d["PrefersEphemeralWebBrowserSession"] as? Bool ?? false,
                  ssfTransmitterIssuer: string("SSFTransmitterIssuer"), caepEnabled: d["CAEPEnabled"] as? Bool ?? true)
    }

    /// Client options from this configuration. Pass the DPoP key store to use (e.g. ``SecureEnclaveKeyStore``);
    /// it is ignored when `DPoP` is false.
    public func clientOptions(dpopKeyStore: any DPoPKeyStore = MemoryKeyStore(), transport: any HTTPTransport = URLSessionTransport()) -> OIDCClientOptions {
        OIDCClientOptions(clientID: clientID, redirectURI: redirectURI, postLogoutRedirectURI: postLogoutRedirectURI, scope: scope,
                          resource: resource, idTokenSignedResponseAlg: idTokenSignedResponseAlg ?? "RS256", par: par,
                          dpop: dpop ? DPoPOptions(keyStore: dpopKeyStore) : nil, transport: transport)
    }

    /// Discovers the provider and creates a client.
    public func makeClient(dpopKeyStore: any DPoPKeyStore = MemoryKeyStore(), transport: any HTTPTransport = URLSessionTransport()) async throws -> OIDCClient {
        var options = clientOptions(dpopKeyStore: dpopKeyStore, transport: transport)
        if idTokenSignedResponseAlg == nil {
            // Pick an algorithm the provider uses: RS256 when offered, else the first this library verifies.
            let metadata = try await discoverOpenIDProvider(metadataURL: metadataURL, transport: transport)
            let algs = metadata.idTokenSigningAlgValuesSupported
            options.idTokenSignedResponseAlg = algs.contains("RS256") ? "RS256" : algs.first(where: supportedIDTokenAlgorithms.contains) ?? "RS256"
        }
        return try await OIDCClient.discover(metadataURL: metadataURL, options: options)
    }
}

extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
