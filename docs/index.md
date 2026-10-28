---
title: swift-oidc-caep-native-app
---

# swift-oidc-caep-native-app

An OpenID Connect client library for **native macOS apps**, written in Swift. It runs in the app as a **public client**, with no client secret. It is the Swift port of the JavaScript library [oidc-caep-client](https://rcbj.github.io/oidc-caep-client/), with the browser's parts replaced by their native counterparts. It covers:

- **Signing in:** Authorization Code with PKCE, PAR, DPoP-bound tokens, RFC 9207 mix-up defence, and full ID token validation. The sign-in page opens in the system browser through `ASWebAuthenticationSession` (RFC 8252), never in an embedded web view.
- **Tokens:** caching them in the Keychain and refreshing them before they expire. Where the platform has no secure storage, they are cached in memory.
- **DPoP keys:** generated in the Secure Enclave when the Mac has one, so the private key can never be read out. Otherwise the key is kept in the Keychain.
- **Several accounts:** several people signed in to one app, with one active account.
- **CAEP:** subscribing to the identity provider's Shared Signals stream, with one handler per CAEP event and a hook for your own logic.

The library product is `OIDCCAEPClient`. It needs macOS 13 or later and Swift 5.9 or later, and its only dependency is Apple's [swift-crypto](https://github.com/apple/swift-crypto). It also builds and runs its tests on Linux, without the Keychain, Secure Enclave and browser parts.

## Install

The package is installed with Swift Package Manager.

**In `Package.swift`**, add the package and the product:

```swift
dependencies: [
    .package(url: "https://github.com/rcbj/swift-oidc-caep-native-app.git", from: "0.1.0"),
],
targets: [
    .executableTarget(
        name: "MyApp",
        dependencies: [
            .product(name: "OIDCCAEPClient", package: "swift-oidc-caep-native-app"),
        ]
    ),
]
```

**In Xcode**, choose **File → Add Package Dependencies…**, enter `https://github.com/rcbj/swift-oidc-caep-native-app.git`, and add the `OIDCCAEPClient` library to your app target.

While the repository is private, Xcode and `swift package resolve` need GitHub credentials that can read it: an account added in Xcode's Settings → Accounts, or a git credential helper.

## Where to read

- **[Building a native macOS app](native-app-guide.md)**, the walkthrough:
  - registering the app at the identity provider, with a private-use redirect URI;
  - the `OIDCConfiguration.plist` file;
  - signing in, and where tokens and keys are kept;
  - calling your APIs;
  - receiving CAEP events;
  - signing out, errors, sandboxed apps and troubleshooting.
- **[API reference](reference.md):** the security features, every option and its default, the methods and events, and the CAEP event table.
- **[API reference (DocC)](api/documentation/oidccaepclient/)**, generated from the source for every public type and function.
- **[Running the demo](demo.md):** a complete SwiftUI app built this way, with several accounts, a CAEP event log and an event-type picker, and how to register it on iya-sts.
- **[Development](development.md):** tests, CI, branches and the layout of the repository.

## Quick look

```swift
import OIDCCAEPClient

// OIDCConfiguration.plist in the app bundle: MetadataURL, ClientID, Scopes, RedirectURI, …
let configuration = try OIDCAppConfiguration.load()
let client = try await configuration.makeClient(dpopKeyStore: await preferredDPoPKeyStore())
let accounts = try await AccountManager(client: client).restore()   // tokens in the Keychain

// Sign in in the system browser.
let signedIn = try await accounts.signIn(using: SystemWebAuthenticator())
let key = signedIn.account.key
let identity = signedIn.account.identity

// React to security events about the signed-in person.
let caep = SSFReceiver(SSFReceiverConfiguration(
    transmitterIssuer: client.issuer,
    authorization: .oidc(client) { try await accounts.getTokenSet() },
    // Runs for every event, before the handlers below. The default, logEventReceived, logs the
    // event's name and jti; replace it with your own logic, or pass nil to turn it off.
    onEventReceived: { event in
        try await logEventReceived(event)
        await audit.record(event.name, event.subject)
    }))

// One handler per event type. Register your own to decide what each event does.
caep
    .onSessionRevoked { event in
        guard subjectMatches(event.subject, identity) else { return }
        try await accounts.end(key, reason: "Your session was ended.")
    }
    .onTokenClaimsChange { _ in try await accounts.refresh() }
    .onCredentialChange { event in
        if let change = event.payload["change_type"]?.stringValue, ["revoke", "delete"].contains(change) {
            try await accounts.end(key, reason: "Sign in again.")
        }
    }
    .onAssuranceLevelChange { event in
        if event.payload["change_direction"]?.stringValue == "decrease" { await requireStepUp() }
    }
    .onDeviceComplianceChange { event in
        if event.payload["current_status"]?.stringValue == "not-compliant" {
            try await accounts.end(key, reason: "This device no longer meets policy.")
        }
    }
    .onRiskLevelChange { event in
        if event.payload["current_level"]?.stringValue == "HIGH" {
            try await accounts.end(key, reason: "Unusual activity was detected.")
        }
    }
    .onError { error, context in print("CAEP", context.phase.rawValue, error.code ?? "", error.message) }

try await caep.start(catchUp: true)
```

`audit` and `requireStepUp()` stand for your app's own code. Registering a handler for an event type adds to what runs; `removeHandlers(for: CAEP.sessionRevoked)` removes them again. `onEvent(_:_:)` handles any other type, such as the RISC events in `RISC`. The [guide](native-app-guide.md#9-receive-caep-events) wires a receiver to the active account and suggests a reaction for each event, and the [reference](reference.md#caep-one-handler-per-event) lists every handler and its payload fields.

MIT licensed. © 2026 Iya CyberSecurity Solutions, LLC.
