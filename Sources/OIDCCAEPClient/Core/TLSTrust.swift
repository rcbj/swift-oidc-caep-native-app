// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

import Foundation
#if canImport(Security)
import Security
#endif

/// Extra certificates to trust for the provider's TLS connections: a private CA's root (a trust anchor), or a
/// full chain (leaf, intermediates and root). Every certificate given counts as a trust anchor, so a chain may
/// be given whole or in part. The host name is still checked.
///
/// Use it for an identity provider whose certificate is issued by a private CA (a self-signed test iya-sts),
/// instead of turning verification off with `InsecureSkipTLSVerification`.
public struct TLSTrust: Sendable, Equatable {
    /// The certificates, DER encoded.
    public let certificates: [Data]
    /// Whether the system's trusted roots still count. With `false`, only ``certificates`` are trusted.
    public let includeSystemRoots: Bool

    public init(certificates: [Data], includeSystemRoots: Bool = true) {
        self.certificates = certificates
        self.includeSystemRoots = includeSystemRoots
    }

    /// From PEM text (one or more `CERTIFICATE` blocks) or DER data, each entry a file's contents.
    public init(pemOrDER entries: [Data], includeSystemRoots: Bool = true) throws {
        var certs: [Data] = []
        for entry in entries {
            let text = String(decoding: entry, as: UTF8.self)
            if text.contains("-----BEGIN CERTIFICATE-----") {
                certs += try Self.parsePEM(text)
            } else if entry.first == 0x30 {
                certs.append(entry)  // DER: a SEQUENCE
            } else {
                throw OIDCError.usage("A trusted certificate is neither PEM nor DER")
            }
        }
        guard !certs.isEmpty else { throw OIDCError.usage("No certificates were found in the trusted certificates given") }
        self.init(certificates: certs, includeSystemRoots: includeSystemRoots)
    }

    /// Reads certificates from files: PEM (possibly several, e.g. a whole chain) or DER.
    public init(files: [URL], includeSystemRoots: Bool = true) throws {
        let entries = try files.map { url -> Data in
            do { return try Data(contentsOf: url) } catch {
                throw OIDCError.usage("Could not read the trusted certificate file \(url.path): \(error.localizedDescription)")
            }
        }
        try self.init(pemOrDER: entries, includeSystemRoots: includeSystemRoots)
    }

    static func parsePEM(_ text: String) throws -> [Data] {
        var out: [Data] = []
        var rest = Substring(text)
        while let begin = rest.range(of: "-----BEGIN CERTIFICATE-----") {
            guard let end = rest.range(of: "-----END CERTIFICATE-----", range: begin.upperBound..<rest.endIndex) else {
                throw OIDCError.usage("A PEM certificate has no END line")
            }
            let body = rest[begin.upperBound..<end.lowerBound].filter { !$0.isWhitespace }
            guard let der = Data(base64Encoded: String(body)) else { throw OIDCError.usage("A PEM certificate is not valid base64") }
            out.append(der)
            rest = rest[end.upperBound...]
        }
        return out
    }

    /// The certificates as PEM text (for a CA bundle file).
    var pem: String {
        certificates.map { der in
            let b64 = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
            return "-----BEGIN CERTIFICATE-----\n\(b64)\n-----END CERTIFICATE-----\n"
        }.joined()
    }

    #if canImport(Security)
    /// Evaluates a server trust with these anchors (and the system roots when allowed).
    func evaluate(_ trust: SecTrust) -> Bool {
        let anchors = certificates.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, !includeSystemRoots) == errSecSuccess else { return false }
        var error: CFError?
        return SecTrustEvaluateWithError(trust, &error)
    }
    #endif

    #if !canImport(Darwin)
    /// A CA bundle file (readable by this user only) with these certificates, plus the system's roots when
    /// allowed, for curl. Written once per trust configuration.
    func caBundleFile() throws -> URL {
        let key = Base64URL.encode(Data(sha256(pem + (includeSystemRoots ? "+system" : "")).prefix(12)))
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("oidc-caep-trust-\(getuid())-\(key).pem")
        if FileManager.default.fileExists(atPath: url.path) { return url }
        var bundle = ""
        if includeSystemRoots {
            for path in ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem"] {
                if let system = try? String(contentsOfFile: path, encoding: .utf8) { bundle = system + "\n"; break }
            }
        }
        bundle += pem
        let tmp = url.appendingPathExtension("\(UUID().uuidString)")
        guard FileManager.default.createFile(atPath: tmp.path, contents: Data(bundle.utf8), attributes: [.posixPermissions: 0o600]) else {
            throw OIDCError(kind: .general, "Could not write the trusted CA bundle", code: "tls_trust_error")
        }
        _ = try? FileManager.default.replaceItemAt(url, withItemAt: tmp)
        if !FileManager.default.fileExists(atPath: url.path) { try FileManager.default.moveItem(at: tmp, to: url) }
        return url
    }
    #endif
}
