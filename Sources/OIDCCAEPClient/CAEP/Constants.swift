// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

private let caepBase = "https://schemas.openid.net/secevent/caep/event-type/"
private let ssfBase = "https://schemas.openid.net/secevent/ssf/event-type/"
private let riscBase = "https://schemas.openid.net/secevent/risc/event-type/"

/// OpenID CAEP 1.0 event types.
public enum CAEP {
    public static let sessionRevoked = caepBase + "session-revoked"
    public static let tokenClaimsChange = caepBase + "token-claims-change"
    public static let credentialChange = caepBase + "credential-change"
    public static let assuranceLevelChange = caepBase + "assurance-level-change"
    public static let deviceComplianceChange = caepBase + "device-compliance-change"
    public static let sessionEstablished = caepBase + "session-established"
    public static let sessionPresented = caepBase + "session-presented"
    public static let riskLevelChange = caepBase + "risk-level-change"

    /// Every CAEP 1.0 event type.
    public static let all = [sessionRevoked, tokenClaimsChange, credentialChange, assuranceLevelChange, deviceComplianceChange,
                             sessionEstablished, sessionPresented, riskLevelChange]
}

/// OpenID Shared Signals Framework 1.0 stream-control event types.
public enum SSF {
    public static let verification = ssfBase + "verification"
    public static let streamUpdated = ssfBase + "stream-updated"
}

/// OpenID RISC 1.0 event types (receivable through ``SSFReceiver/onEvent(_:_:)``).
public enum RISC {
    public static let accountCredentialChangeRequired = riscBase + "account-credential-change-required"
    public static let accountPurged = riscBase + "account-purged"
    public static let accountDisabled = riscBase + "account-disabled"
    public static let accountEnabled = riscBase + "account-enabled"
    public static let identifierChanged = riscBase + "identifier-changed"
    public static let identifierRecycled = riscBase + "identifier-recycled"
    public static let credentialCompromise = riscBase + "credential-compromise"
    public static let optIn = riscBase + "opt-in"
    public static let optOutInitiated = riscBase + "opt-out-initiated"
    public static let optOutCancelled = riscBase + "opt-out-cancelled"
    public static let optOutEffective = riscBase + "opt-out-effective"
    public static let recoveryActivated = riscBase + "recovery-activated"
    public static let recoveryInformationChanged = riscBase + "recovery-information-changed"
}

/// SSF delivery methods.
public enum Delivery {
    public static let push = "urn:ietf:rfc:8935"
    public static let poll = "urn:ietf:rfc:8936"
}

/// The short name (`session-revoked`) of an event type URI.
public func eventName(_ uri: String) -> String {
    uri.split(separator: "/", omittingEmptySubsequences: false).last.map(String.init) ?? uri
}
