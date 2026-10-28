# ``OIDCCAEPClient``

An OpenID Connect public client for native macOS apps, with a Shared Signals receiver that has one handler per CAEP event.

## Overview

`OIDCCAEPClient` signs people in with Authorization Code + PKCE through the system browser (`ASWebAuthenticationSession`, RFC 8252), with PAR, DPoP-bound tokens and full ID token validation. It caches tokens in the Keychain and refreshes them before they expire, keeps the DPoP key in the Secure Enclave when the Mac has one, and lets several people stay signed in to one app with one active account. ``SSFReceiver`` subscribes to the identity provider's Shared Signals stream and hands each validated CAEP event to its handler.

It is the Swift port of the JavaScript library oidc-caep-client. The client is public: it has no client secret.

```swift
let configuration = try OIDCAppConfiguration.load()
let client = try await configuration.makeClient(dpopKeyStore: await preferredDPoPKeyStore())
let accounts = try await AccountManager(client: client).restore()
let signedIn = try await accounts.signIn(using: SystemWebAuthenticator())
```

The integration guide, the reference with every option's default, and the demo are on the documentation site: <https://rcbj.github.io/swift-oidc-caep-native-app/>.

## Topics

### Configuring the client

- ``OIDCAppConfiguration``
- ``OIDCClient``
- ``OIDCClientOptions``
- ``DPoPOptions``
- ``PARMode``
- ``ProviderMetadata``
- ``SecurityFeatures``

### Signing in and out

- ``WebAuthenticator``
- ``SystemWebAuthenticator``
- ``AuthorizationRequestOptions``
- ``AuthorizationRequest``
- ``AuthorizationResult``
- ``EndSessionRequest``
- ``ClientRegistration``

### Accounts and tokens

- ``AccountManager``
- ``AccountManagerOptions``
- ``Account``
- ``AccountAccess``
- ``SignInResult``
- ``TokenManager``
- ``TokenSet``
- ``accountKey(iss:sub:)``

### Where tokens are kept

- ``TokenStore``
- ``defaultTokenStore(service:)``
- ``KeychainTokenStore``
- ``MemoryTokenStore``
- ``TransactionStore``
- ``MemoryTransactionStore``

### DPoP keys

- ``DPoPKeyStore``
- ``preferredDPoPKeyStore(service:)``
- ``SecureEnclaveKeyStore``
- ``KeychainKeyStore``
- ``MemoryKeyStore``
- ``DPoPKey``

### Receiving CAEP events

- ``SSFReceiver``
- ``SSFReceiverConfiguration``
- ``SSFAuthorization``
- ``SecurityEvent``
- ``SecurityEventHandler``
- ``logEventReceived``
- ``SSFErrorContext``
- ``SSFErrorHandler``

### Subjects and event types

- ``Subject``
- ``SubjectIdentity``
- ``subjectMatches(_:_:)``
- ``CAEP``
- ``SSF``
- ``RISC``
- ``Delivery``
- ``eventName(_:)``

### Errors and logging

- ``OIDCError``
- ``needsInteraction(_:)``
- ``interactionRequiredErrors``
- ``OIDCLog``

### Networking and JSON

- ``HTTPTransport``
- ``URLSessionTransport``
- ``HTTPRequest``
- ``HTTPResponse``
- ``JSONValue``
- ``JSONObject``
- ``EventHub``
- ``EventSubscription``
