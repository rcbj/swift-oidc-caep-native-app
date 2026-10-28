// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

/// Builders for RFC 9493 Subject Identifiers, as carried in a SET's `sub_id` claim and sent to
/// ``SSFReceiver/addSubject(_:verified:)``.
public enum Subject {
    public static func issSub(_ iss: String, _ sub: String) -> JSONObject { ["format": "iss_sub", "iss": .string(iss), "sub": .string(sub)] }
    public static func email(_ email: String) -> JSONObject { ["format": "email", "email": .string(email)] }
    public static func phone(_ phoneNumber: String) -> JSONObject { ["format": "phone_number", "phone_number": .string(phoneNumber)] }
    public static func opaque(_ id: String) -> JSONObject { ["format": "opaque", "id": .string(id)] }
    public static func account(_ uri: String) -> JSONObject { ["format": "account", "uri": .string(uri)] }
    public static func uri(_ uri: String) -> JSONObject { ["format": "uri", "uri": .string(uri)] }
    public static func did(_ url: String) -> JSONObject { ["format": "did", "url": .string(url)] }
    public static func aliases(_ identifiers: [JSONObject]) -> JSONObject { ["format": "aliases", "identifiers": .array(identifiers.map(JSONValue.object))] }
    /// An SSF complex subject, e.g. `Subject.complex(["user": .object(Subject.issSub(iss, sub)), "session": .object(Subject.opaque(sid))])`.
    public static func complex(_ members: JSONObject) -> JSONObject { members.merging(["format": "complex"]) { _, b in b } }
}

/// What a security event's subject is compared with: one identity, from validated ID token claims.
public struct SubjectIdentity: Sendable, Equatable {
    public var iss: String?
    public var sub: String?
    /// The OP session id.
    public var sid: String?
    public var email: String?
    public var emailVerified: Bool
    public var phoneNumber: String?
    public var phoneNumberVerified: Bool
    /// Opaque ids for the other complex-subject members: `device`, `application`, `tenant`, `org_unit`, `group`.
    public var other: [String: String]

    public init(iss: String? = nil, sub: String? = nil, sid: String? = nil, email: String? = nil, emailVerified: Bool = false,
                phoneNumber: String? = nil, phoneNumberVerified: Bool = false, other: [String: String] = [:]) {
        self.iss = iss
        self.sub = sub
        self.sid = sid
        self.email = email
        self.emailVerified = emailVerified
        self.phoneNumber = phoneNumber
        self.phoneNumberVerified = phoneNumberVerified
        self.other = other
    }
}

private let complexMembers = ["user", "session", "device", "application", "tenant", "org_unit", "group"]

/// Whether a subject identifier refers to a known identity.
///
/// - An email or phone number identifies somebody only when the OP said it was verified
///   (`email_verified` / `phone_number_verified`): OIDC Core §5.7 makes neither a stable or unique
///   identifier, and an unverified one may be anybody's.
/// - A top-level opaque id is compared with `sub`. A session is named inside a complex subject.
/// - In a complex subject every member must match, and the members this identity can't be checked against
///   count as a non-match: an event about one session matches only an identity holding that `sid`.
public func subjectMatches(_ subId: JSONObject?, _ identity: SubjectIdentity?) -> Bool {
    guard let subId, let identity else { return false }
    switch subId.string("format") {
    case "iss_sub":
        guard let sub = subId.string("sub"), let mine = identity.sub, !mine.isEmpty, sub == mine else { return false }
        return identity.iss == nil || identity.iss == "" || subId.string("iss") == identity.iss
    case "email":
        guard identity.emailVerified, let mine = identity.email, let theirs = subId.string("email") else { return false }
        return theirs.lowercased() == mine.lowercased()
    case "phone_number":
        guard identity.phoneNumberVerified, let theirs = subId.string("phone_number") else { return false }
        return theirs == identity.phoneNumber
    case "opaque":
        return opaqueIs(subId, identity.sub)
    case "account":
        guard identity.emailVerified, let mine = identity.email else { return false }
        return subId.string("uri") == "acct:\(mine)"
    case "aliases":
        return (subId["identifiers"]?.arrayValue ?? []).contains { subjectMatches($0.objectValue, identity) }
    case "complex":
        let members = complexMembers.filter { subId[$0] != nil && subId[$0] != .null }
        guard !members.isEmpty else { return false }
        return members.allSatisfy { member in
            let value = subId[member]?.objectValue
            switch member {
            case "user": return subjectMatches(value, identity)
            case "session": return opaqueIs(value, identity.sid)
            default: return opaqueIs(value, identity.other[member])
            }
        }
    default:
        return false
    }
}

/// An opaque identifier naming exactly `id`: both must be non-empty strings.
private func opaqueIs(_ value: JSONObject?, _ id: String?) -> Bool {
    guard let value, value.string("format") == "opaque", let v = value.string("id"), !v.isEmpty, let id, !id.isEmpty else { return false }
    return v == id
}
