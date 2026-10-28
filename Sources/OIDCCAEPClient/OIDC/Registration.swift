// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation

/// Client metadata values the server must honour exactly as requested; if it registers something else
/// (OIDC Dynamic Client Registration 1.0 §3.2 allows substitution) the registration is rejected.
private let mustMatch = ["id_token_signed_response_alg", "token_endpoint_auth_method"]

/// OpenID Connect Dynamic Client Registration 1.0 / RFC 7591 / RFC 7592, for a public client.
public enum ClientRegistration {
    /// Registers a client. `clientMetadata` needs `redirect_uris`. Returns the Client Information Response.
    public static func register(metadata: ProviderMetadata, clientMetadata: JSONObject, initialAccessToken: String? = nil,
                                allowInsecureRequests: Bool = false, transport: any HTTPTransport = URLSessionTransport(),
                                timeout: TimeInterval = 10) async throws -> JSONObject {
        guard let endpoint = metadata.registrationEndpoint else {
            throw OIDCError(kind: .general, "OpenID Provider does not advertise a registration_endpoint", code: "registration_not_supported")
        }
        // The request may carry an initial access token, and the answer is this client's identity.
        if !allowInsecureRequests, !isSecureURL(endpoint) {
            throw OIDCError.validation("registration_endpoint must use https: \(endpoint)", code: "insecure_endpoint")
        }
        guard let uris = clientMetadata["redirect_uris"]?.stringArrayValue, !uris.isEmpty else {
            throw OIDCError.usage("clientMetadata.redirect_uris is required")
        }
        if let alg = clientMetadata.string("id_token_signed_response_alg") {
            guard supportedIDTokenAlgorithms.contains(alg) else {
                throw OIDCError.validation("Refusing to register id_token_signed_response_alg \(alg): this library cannot verify it")
            }
            if !metadata.idTokenSigningAlgValuesSupported.isEmpty, !metadata.idTokenSigningAlgValuesSupported.contains(alg) {
                throw OIDCError.validation("OpenID Provider does not support id_token_signed_response_alg \(alg)")
            }
        }
        var headers = ["content-type": "application/json", "accept": "application/json"]
        if let initialAccessToken { headers["authorization"] = "Bearer \(initialAccessToken)" }
        let http = HTTPClient(transport: transport, timeout: timeout)
        guard let url = URL(string: endpoint) else { throw OIDCError.validation("registration_endpoint is not a URL") }
        let res = try await http.send(HTTPRequest(url: url, method: "POST", headers: headers, body: try JSONValue.object(clientMetadata).jsonData()))
        let registration = try readJSONObject(res)
        guard registration.string("client_id") != nil else {
            throw OIDCError.validation("Registration response is missing client_id", response: .object(registration))
        }
        for key in mustMatch {
            if let wanted = clientMetadata[key], let got = registration[key], wanted != got {
                throw OIDCError.validation("The OP registered \(key)=\(got.stringValue ?? got.jsonString()) instead of the requested \(wanted.stringValue ?? wanted.jsonString())",
                                           code: "registration_mismatch", response: .object(registration))
            }
        }
        return registration
    }

    /// Reads the current registration (OIDC DCR §4 / RFC 7592 §2.1).
    public static func read(_ registration: JSONObject, allowInsecureRequests: Bool = false,
                            transport: any HTTPTransport = URLSessionTransport(), timeout: TimeInterval = 10) async throws -> JSONObject {
        let (uri, token) = try managementCredentials(registration, allowInsecureRequests)
        let res = try await HTTPClient(transport: transport, timeout: timeout).get(uri, headers: ["authorization": "Bearer \(token)", "accept": "application/json"])
        return try readJSONObject(res)
    }

    /// Deletes a registration (RFC 7592 §2.3).
    public static func delete(_ registration: JSONObject, allowInsecureRequests: Bool = false,
                              transport: any HTTPTransport = URLSessionTransport(), timeout: TimeInterval = 10) async throws {
        let (uri, token) = try managementCredentials(registration, allowInsecureRequests)
        let res = try await HTTPClient(transport: transport, timeout: timeout).send(HTTPRequest(url: uri, method: "DELETE", headers: ["authorization": "Bearer \(token)"]))
        if !res.isOK { _ = try readJSON(res) }
    }

    // The registration access token goes to registration_client_uri, so that must use TLS (RFC 7592 §5).
    private static func managementCredentials(_ registration: JSONObject, _ allowInsecureRequests: Bool) throws -> (URL, String) {
        guard let uri = registration.string("registration_client_uri"), let token = registration.string("registration_access_token"), let url = URL(string: uri) else {
            throw OIDCError(kind: .general, "Registration has no registration_client_uri / registration_access_token", code: "registration_not_manageable")
        }
        if !allowInsecureRequests, !isSecureURL(uri) {
            throw OIDCError.validation("registration_client_uri must use https: \(uri)", code: "insecure_endpoint")
        }
        return (url, token)
    }
}

extension OIDCClient {
    /// Registers a new PUBLIC client (OpenID Connect Dynamic Client Registration 1.0) and returns a client
    /// configured from the registration. `token_endpoint_auth_method` is always `none`. `options.clientID`
    /// is replaced by the registered one.
    public static func register(metadata: JSONObject, clientMetadata: JSONObject, initialAccessToken: String? = nil,
                                options: OIDCClientOptions) async throws -> (client: OIDCClient, registration: JSONObject) {
        let provider = try validateOpenIDProviderMetadata(metadata)
        var request = clientMetadata
        request["token_endpoint_auth_method"] = "none"
        if options.dpop != nil, request["dpop_bound_access_tokens"] == nil { request["dpop_bound_access_tokens"] = true }
        let registration = try await ClientRegistration.register(metadata: provider, clientMetadata: request, initialAccessToken: initialAccessToken,
                                                                 allowInsecureRequests: options.allowInsecureRequests, transport: options.transport,
                                                                 timeout: options.httpTimeout)
        if registration["client_secret"] != nil {
            // A confidential registration is not what was asked for, and this client would ignore the secret.
            throw OIDCError.validation("The OP registered a confidential client (it issued a client_secret); only public clients are supported",
                                       code: "registration_mismatch", response: .object(registration))
        }
        var o = options
        o.clientID = registration.string("client_id") ?? ""
        if o.redirectURI == nil {
            o.redirectURI = (registration["redirect_uris"]?.stringArrayValue?.first ?? request["redirect_uris"]?.stringArrayValue?.first).flatMap(URL.init(string:))
        }
        if o.postLogoutRedirectURI == nil {
            o.postLogoutRedirectURI = (registration["post_logout_redirect_uris"]?.stringArrayValue?.first
                                       ?? request["post_logout_redirect_uris"]?.stringArrayValue?.first).flatMap(URL.init(string:))
        }
        o.idTokenSignedResponseAlg = registration.string("id_token_signed_response_alg") ?? request.string("id_token_signed_response_alg") ?? "RS256"
        return (try await fromMetadata(metadata, options: o), registration)
    }
}
