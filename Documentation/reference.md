# OIDCCAEPClient reference

An OpenID Connect client library for **native macOS apps**, in Swift, configured from the provider's metadata document. It runs as a **public client**: no client secret, and `token_endpoint_auth_method: none`. It covers:

- signing users in through the system browser;
- caching tokens in the Keychain and refreshing them before they expire;
- subscribing to **CAEP** events through the OpenID Shared Signals Framework, with **one handler per CAEP event**.

It is the Swift port of the JavaScript library [oidc-caep-client](https://rcbj.github.io/oidc-caep-client/), and keeps its names where Swift allows. It needs macOS 13 or later and Swift 5.9 or later. Its only dependency is Apple's [swift-crypto](https://github.com/apple/swift-crypto), which is CryptoKit on Apple platforms. The core also builds on Linux, without the Keychain, Secure Enclave and browser parts.

**New to the library?** [Building a native macOS app](native-app-guide.md) walks through it step by step: registering the app, the configuration file, sign-in, storage, calling APIs, CAEP events, sign-out and sandboxing. This page is the reference. The [DocC reference](https://rcbj.github.io/swift-oidc-caep-native-app/api/documentation/oidccaepclient/) documents every public symbol.

## Installing

Add the package with Swift Package Manager:

```swift
dependencies: [
    .package(url: "https://github.com/rcbj/swift-oidc-caep-native-app.git", from: "0.1.0"),
],
```

and the product to your target:

```swift
.product(name: "OIDCCAEPClient", package: "swift-oidc-caep-native-app")
```

In Xcode: **File → Add Package Dependencies…**, the same URL, and the **OIDCCAEPClient** library for your app target.

**Versions** are semantic-version tags. `from: "0.1.0"` takes every later version below 1.0.0; while the version is 0.x a minor version may change the API, so `.upToNextMinor(from: "0.1.0")` stays on 0.1. For a reproducible build, commit `Package.resolved`.

## Security features

These follow RFC 9700 (the OAuth 2.0 Security Best Current Practice), RFC 8252 (OAuth 2.0 for Native Apps) and OpenID Connect Core.

| Protection | What the library does |
|---|---|
| **System browser** | `SystemWebAuthenticator` shows the provider's pages with `ASWebAuthenticationSession`, in the person's default browser (RFC 8252 §8.12). The app never sees the password, and there is no embedded web view. The browser's session is shared, so single sign-on, `prompt=none` and several accounts work; `prefersEphemeralWebBrowserSession` turns that off. Closing the window is `user_cancelled`. |
| **Redirect URIs** | A private-use scheme in reverse-domain form (`com.example.app:/callback`, RFC 8252 §7.1): the scheme must contain a period and the URI no fragment. `https` and loopback `http` are also accepted. `SystemWebAuthenticator` takes a private-use scheme, or `https` with an associated domain on macOS 14.4 and later; it refuses loopback, which `ASWebAuthenticationSession` cannot receive. The redirect only reaches the session that started the sign-in. |
| **Authorization Code + PKCE** | Uses only `response_type=code`, with PKCE `S256`. It refuses an OP whose metadata doesn't offer S256 (downgrade protection), or doesn't accept public clients (`none`). |
| **`state`** | A new random 256-bit value per request, kept with the transaction in memory (`MemoryTransactionStore`). On return, `state` is **required** and compared in constant time, and the transaction is **single use** (a replayed response is refused: `state_reused`). It **expires** after `transactionTTL` (default 10 minutes) and is **bound to the issuer and client** that started it. It is checked *before* an error response is reported. |
| **`nonce`** | A new random 256-bit value per request, compared in constant time with the ID token's `nonce`. |
| **Mix-up defence** | RFC 9207: the `iss` response parameter must match, and is required when the OP advertises it. Transactions are bound to their issuer. |
| **Authorization response hygiene** | Refuses tokens in the front channel (`access_token`, `id_token` and so on, including in the fragment) and repeated parameters. |
| **PAR** (RFC 9126) | The authorization request is pushed to the OP, so only `client_id` and `request_uri` pass through the browser. Used automatically when advertised (`par: .auto`), and required when the OP sets `require_pushed_authorization_requests`. |
| **DPoP** (RFC 9449) | Access and refresh tokens are bound to a key. `SecureEnclaveKeyStore` generates it in the **Secure Enclave**: the app can ask it to sign but nothing can read it out, so stolen tokens are useless on any other device. `preferredDPoPKeyStore()` uses it when available and falls back to `KeychainKeyStore`. The authorization code is bound too (`dpop_jkt`). Proofs are sent to the token endpoint, UserInfo, the SSF endpoints and your own APIs (`fetchResource`). Server nonces are handled (one retry on `use_dpop_nonce`). With DPoP on, a `Bearer` token response is refused (`requireDPoP`, default on), and a DPoP-bound grant is never refreshed into a Bearer one. |
| **ID token validation** | Covers everything in OIDC Core §3.1.3.7: signature against the JWKS with the expected `alg` only, `iss`, `aud`, `azp`, `exp`, `iat` (no older than `maxIDTokenAge`), `nonce`, `at_hash`, `max_age`/`auth_time`, and the refresh rules in §12.2. It also refuses other JWT types presented as ID tokens (`typ` `at+jwt`, `logout+jwt` and so on), unknown `crit` headers, and an `acr` outside the requested `acr_values` (`enforceACR`). |
| **TLS** | Every OP endpoint, every SSF transmitter URL (including the JWKS and the stream's poll endpoint), the registration endpoint and `registration_client_uri` must use `https`. Loopback `http` is allowed for local development. |
| **HTTP** | `URLSessionTransport` uses an ephemeral session with no cookies and no cache, and never follows a redirect. |
| **Audience-restricted tokens** | RFC 8707 resource indicators (`resource`) on the authorization, token and refresh requests. |
| **Refresh tokens** | Rotation is handled. Concurrent refreshes of one key are merged into one request, so rotation stays safe. With DPoP, refresh tokens are sender-constrained, as RFC 9700 §2.2.2 recommends for public clients. A refreshed ID token must keep the original `iss`, `sub`, `aud` and `azp` (OIDC Core §12.2). A deletion waits for a refresh in flight, so revoked tokens are never written back. |
| **Logout** | RP-Initiated Logout with its own single-use, expiring `state`, checked on return (`completeEndSession`, or `endSession(using:request:)` in the browser). `TokenManager.delete(_:revoke: true)` and `AccountManager.signOut` revoke the tokens (RFC 7009); `createEndSessionRequest` alone does not. |
| **Token storage** | Tokens are cached in the platform's secure storage when it has one, otherwise in memory: `defaultTokenStore()` is `KeychainTokenStore` on Apple platforms (the login keychain by default; with `useDataProtectionKeychain`, the data protection keychain and `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`), and `MemoryTokenStore` elsewhere. A token set's `claims` come only from a validated ID token; a stored record without them is never filled in by decoding the ID token. `AccountManager` logs a warning when tokens go to persistent storage without DPoP. |
| **UserInfo** | The response `sub` must equal the ID token's: `expectedSub`, or by default the token set's ID token `sub` (OIDC Core §5.3.2). A signed UserInfo response is verified with an asymmetric algorithm (`userinfoSignedResponseAlg` pins one). |

**Not included:**

- Confidential-client authentication: client secrets, `private_key_jwt`, mTLS. This library is a public client only.
- JAR/JARM (signed request objects and responses).
- Back- and front-channel logout, which need a server endpoint.
- CAEP push delivery, which an app without a public endpoint can't receive.
- A loopback redirect listener. `OIDCClient` accepts loopback redirect URIs, but receiving one needs your own `WebAuthenticator`.
- An embedded web view, on purpose.
- A sign-in that survives a relaunch: transactions are in memory, so the redirect must come back to the process that started the sign-in.

## Signing in

```swift
import OIDCCAEPClient

let configuration = try OIDCAppConfiguration.load()       // OIDCConfiguration.plist in the app bundle
let client = try await configuration.makeClient(dpopKeyStore: await preferredDPoPKeyStore())
let tokens = TokenManager(client: client)                 // the Keychain, auto-refreshing
let authenticator = SystemWebAuthenticator()

// 1. Sign in through the system browser: request (PKCE, PAR), browser, callback, validation.
let result = try await client.authorize(using: authenticator)
try await tokens.set("user", result.tokenSet)

// 2. Call APIs. The token is fresh, and carries a DPoP proof when bound.
let response = try await client.fetchResource(try await tokens.getTokenSet("user"),
                                              url: URL(string: "https://api.example.com/me")!)

// 3. Sign out: revoke, then the provider's logout in the browser, with its state checked.
let tokenSet = try await tokens.getTokenSet("user")
let logout = try await client.createEndSessionRequest(idTokenHint: tokenSet.idToken)
try await tokens.delete("user", revoke: true)
try await client.endSession(using: authenticator, request: logout)
```

Without a browser step, the same flow is `createAuthorizationRequest(_:)`, which returns the URL to open, and `completeAuthorization(callbackURL:)`, which returns `AuthorizationResult { tokenSet, context }`. Logout is `createEndSessionRequest(…)` and `completeEndSession(callbackURL:)`.

### OIDCConfiguration.plist

`OIDCAppConfiguration.load(bundle:resource:)` reads `OIDCConfiguration.plist` from the bundle (default `Bundle.main`), or else an `OIDCConfiguration` dictionary in its `Info.plist`. `load(contentsOf:)`, `init(propertyList:source:)` and `init(dictionary:)` read it from elsewhere.

| Key | Type | Default | Applied by |
|---|---|---|---|
| `MetadataURL` | string, required, contains `/.well-known/` | — | `makeClient` |
| `ClientID` | string, required | — | `makeClient` |
| `Scopes` | array, or space-separated string | the client's: `openid profile email` (+ `offline_access`) | `makeClient` |
| `RedirectURI` | string, required | — | `makeClient` |
| `PostLogoutRedirectURI` | string | — | `makeClient` |
| `Resource` | array or string | — | `makeClient` |
| `DPoP` | bool | `true` | `makeClient` |
| `PAR` | `auto`, `always`, `never` | `auto` | `makeClient` |
| `IDTokenSignedResponseAlg` | string | `RS256` if offered, else the first offered that the library verifies | `makeClient` |
| `ACRValues` | string | — | your code: `AuthorizationRequestOptions(acrValues:)` |
| `PrefersEphemeralWebBrowserSession` | bool | `false` | `makeAuthenticator()` |
| `SSFTransmitterIssuer` | string | — (the provider's issuer) | your code: `SSFReceiverConfiguration(transmitterIssuer:)` |
| `CAEPEnabled` | bool | `true` | your code |
| `TrustedCertificates` | array | — | `makeTransport()`: extra trust anchors or chains (`TLSTrust`) |
| `TrustSystemRoots` | bool | `true` | `makeTransport()` |
| `InsecureSkipTLSVerification` | bool | `false` | `makeTransport()`: certificate verification off. Local test providers only |

`makeClient(dpopKeyStore:transport:)` discovers the provider and creates the client; `clientOptions(dpopKeyStore:transport:)` returns the `OIDCClientOptions` without discovering. With no `dpopKeyStore`, `makeClient` keeps the DPoP key in secure storage (`preferredDPoPKeyStore()`: the Secure Enclave, else the Keychain; memory where neither exists). `makeAuthenticator()` returns a `SystemWebAuthenticator` with `PrefersEphemeralWebBrowserSession` applied.

### Dynamic Client Registration

```swift
let (client, registration) = try await OIDCClient.register(
    metadata: metadataJSON,
    clientMetadata: [
        "redirect_uris": ["com.example.myapp:/callback"],
        "id_token_signed_response_alg": "ES256",
    ],
    initialAccessToken: initialAccessToken,
    options: OIDCClientOptions(clientID: "", dpop: DPoPOptions(keyStore: await preferredDPoPKeyStore())))
```

The registration always requests `token_endpoint_auth_method: none` (and `dpop_bound_access_tokens` with DPoP on). It fails if the OP issues a client secret, or registers a different ID token `alg` than requested (`registration_mismatch`). `ClientRegistration.read(_:)` and `ClientRegistration.delete(_:)` implement RFC 7592.

## Several accounts in one app

Some OPs keep several people signed in in one browser and let each request say which one it is for. iya-sts does this with `authn.multipleAccounts`, which is on by default. `AccountManager` is the app's side of that, and it follows two rules:

- **One token cache.** Every signed-in account's tokens are cached until that account is signed out or its session ends. The cache is in the Keychain by default (`defaultTokenStore()`), so a relaunch doesn't lose any account, and any cached account can be made active without a password.
- **One active account.** Only the active account's tokens can be reached: `getTokenSet()` takes no account. Only its tokens are refreshed in the background. The other accounts are **dormant**: their tokens stay stored, but they aren't refreshed or used. The active account is remembered in the store across launches.

```swift
let accounts = AccountManager(client: client, options: AccountManagerOptions(
    // Runs before an account becomes active, with that account's tokens: catch up on its signals.
    onActivate: { account, access in /* e.g. receiver.start(catchUp: true) */ },
    onDeactivate: { account in /* stop polling its stream */ },
    onLeave: { account, access in /* signed out or ended: delete its stream */ }))
try await accounts.restore()                                 // reactivates the account active at the last launch

try await accounts.signIn(using: authenticator)               // the OP decides (its picker if several are signed in)
try await accounts.chooseAccount(using: authenticator)        // prompt=select_account: always the OP's picker
try await accounts.addAccount(using: authenticator)           // prompt=login: a fresh sign-in, added as an account

try await accounts.activate(otherKey)                         // the previous account goes dormant
let tokenSet = try await accounts.getTokenSet()               // the ACTIVE account's, refreshed when due

try await accounts.signOut(key, using: authenticator)         // revokes; id_token_hint ends that sid only
```

Every `using:` method has a form without it that returns the `AuthorizationRequest` (or `EndSessionRequest`) for your own browser step, completed with `handleCallback(_:)`.

- **Activating** a dormant account refreshes its tokens first if they are due, then runs `onActivate`, and only then makes the account active. If a signal handled during `onActivate` ends the account, it becomes active with status `.ended` and its tokens are never handed out. If the refresh or the hook fails, the previously active account is reactivated and the error thrown.
- **A request that names an account only accepts that account.** `resume(key, using:)` asks without a screen (`prompt=none`); `reauthenticate(key, using:)` uses `prompt=login`. Both send `login_hint` and the cached `id_token_hint`. If the OP signs in somebody else, the callback refuses with `account_mismatch` and revokes the tokens it got. `AuthorizationRequestOptions(expectedSub:)` gives the same check to any request.
- **`prompt=none` failures say which account they were for.** With several accounts signed in and nothing naming one, the OP answers `account_selection_required` (OpenID Connect Core §3.1.2.6). `needsInteraction(_:)` covers it, along with `login_required`, `interaction_required` and `consent_required`. For `resume` and `reauth`, `error.account` is set.
- **Signing out one account leaves the others signed in.** Its logout request names its ID token, so the OP ends that session only. If it was the active account, the most recently added signed-in account becomes active. `signOutAll(using:)` sends one logout request that names nobody, so the OP asks which accounts to end. `signOut(using:)` signs the account out of the app even when the browser step is cancelled.
- **Security events reach the account they are about.** `accountsForSubject(_:)` matches by `iss`/`sub`, a **verified** `email` or phone number (`email_verified` / `phone_number_verified` in the ID token), and `sid`. An SSF complex subject that names a session matches only the account holding that session; an account whose ID token has no `sid` doesn't match it. `end(_:reason:)` drops the account's cached tokens; it stays listed as `.ended`.
- **Statuses:** `.signedIn`, `.tokensMissing` (the cached tokens expired and can't be refreshed; `resume` gets new ones while the OP session lasts), `.signedOut` and `.ended`. Past `maxAccounts` (default 10), the account that left longest ago is forgotten. If every account is signed in, a new sign-in is refused (`too_many_accounts`).
- **Streams are per person.** iya-sts gives a stream created with a person's token to that person, and sends it only events about them. So each account keeps its own stream. The app polls only its active account's stream. A dormant account's stream keeps queueing at the transmitter, and `start(catchUp: true)` in `onActivate` acts on what it queued before the account is used.
- **Hooks and `stop()`.** A handler that calls `end(_:reason:)` runs `onLeave` and `onDeactivate` before it returns, and `SSFReceiver.stop()` waits for the poll that is running the handler. Don't await `stop()` in those hooks; start it in a `Task`. The [guide](native-app-guide.md#wire-a-receiver-to-the-active-account) shows the pattern.

Pair the Keychain cache with DPoP. A DPoP-bound refresh token is useless without its key, and a Secure Enclave key can't be copied. Cached tokens last until the account is signed out, its session ends, or its refresh is refused; quitting the app doesn't clear them.

## CAEP: one handler per event

```swift
let receiver = SSFReceiver(SSFReceiverConfiguration(
    transmitterIssuer: client.issuer,                         // reads /.well-known/ssf-configuration
    // The signed-in user's token authorizes the stream, with a DPoP proof when bound:
    authorization: .oidc(client) { try await accounts.getTokenSet() }))

receiver
    .onSessionRevoked { event in /* sign the user out */ }
    .onTokenClaimsChange { event in /* event.payload["claims"]: refresh tokens */ }
    .onCredentialChange { event in /* event.payload["credential_type"], ["change_type"] */ }
    .onAssuranceLevelChange { event in /* ["current_level"], ["change_direction"] */ }
    .onDeviceComplianceChange { event in /* ["current_status"] */ }
    .onSessionEstablished { event in /* ["acr"], ["amr"], ["fp_ua"] */ }
    .onSessionPresented { event in /* ["fp_ua"], ["ext_id"] */ }
    .onRiskLevelChange { event in /* ["current_level"], ["risk_reason"] */ }
    .onError { error, context in print(context.phase, error) }

try await receiver.start()                                    // discover, create the stream, start polling
// receiver.start(catchUp: true) first acts on the SETs already queued (e.g. while the account was dormant)
try await receiver.addSubject(Subject.issSub(account.iss, account.sub))   // events about this user only
```

Delivery is **poll** (RFC 8936). To authorize with a static bearer token instead, pass `authorization: .bearer { token }`; `.headers { request in … }` builds the headers for each request yourself.

| CAEP event | Method | Constant | Notable `payload` fields |
|---|---|---|---|
| session-revoked | `onSessionRevoked` | `CAEP.sessionRevoked` | — |
| token-claims-change | `onTokenClaimsChange` | `CAEP.tokenClaimsChange` | `claims` |
| credential-change | `onCredentialChange` | `CAEP.credentialChange` | `credential_type`, `change_type`, `friendly_name` |
| assurance-level-change | `onAssuranceLevelChange` | `CAEP.assuranceLevelChange` | `namespace`, `current_level`, `previous_level`, `change_direction` |
| device-compliance-change | `onDeviceComplianceChange` | `CAEP.deviceComplianceChange` | `previous_status`, `current_status` |
| session-established | `onSessionEstablished` | `CAEP.sessionEstablished` | `fp_ua`, `acr`, `amr`, `ext_id` |
| session-presented | `onSessionPresented` | `CAEP.sessionPresented` | `fp_ua`, `ext_id` |
| risk-level-change | `onRiskLevelChange` | `CAEP.riskLevelChange` | `principal`, `current_level`, `previous_level`, `risk_reason` |
| SSF verification | `onVerification` | `SSF.verification` | `state` |
| SSF stream-updated | `onStreamUpdated` | `SSF.streamUpdated` | `status`, `reason` |

`payload` is a `JSONObject` (`[String: JSONValue]`): read a field with `event.payload["change_type"]?.stringValue`.

**Your own logic for every event.** `onEventReceived` in the configuration is called once for each accepted event, before the typed handlers, and is awaited. By default it is `logEventReceived`, which logs `[OIDCCAEPClient] CAEP event received: <name> (jti …)` through `OIDCLog`. It leaves the payload and subject out, because they can carry personal data. Replace it with your own closure, call `try await logEventReceived(event)` from yours to keep the line, or pass `nil` to turn it off. If it throws, `onError` gets the error with phase `.hook`, and the typed handlers still run.

```swift
let receiver = SSFReceiver(SSFReceiverConfiguration(
    transmitterIssuer: client.issuer,
    authorization: .oidc(client) { try await accounts.getTokenSet() },
    onEventReceived: { event in
        try await logEventReceived(event)
        await audit.record(event.name, event.subject, event.payload)   // your logic
    }))
```

The receiver also has these generic hooks. Each returns the receiver, so they chain:

- `onEvent(_:_:)` handles any event type URI, for example the RISC events in `RISC`.
- `onAnyEvent(_:)` runs for every event, after its type's handlers.
- `onUnhandledEvent(_:)` runs for events that have no specific handler.
- `onError(_:)` runs on errors, with an `SSFErrorContext` (`phase` `.poll`, `.handler`, `.hook` or `.stop`; `jti`, `event`, `willRetry`).
- `removeHandlers(for:)` removes every handler of a type.

Every handler receives a `SecurityEvent`: `type`, `name`, `payload`, `subject`, `eventTimestamp`, `initiatingEntity`, `reasonAdmin`, `reasonUser`, `jti`, `iss`, `aud`, `iat`, `txn`, `set` and `raw`. Use `subjectMatches(event.subject, account.identity)` to tell whether an event is about your user; `SubjectIdentity(iss:sub:sid:email:emailVerified:…)` builds an identity by hand. An email or phone number counts only when verified, and a session-scoped subject matches only the identity holding that `sid`.

**SET validation.** Every SET must meet all of the following, or it is rejected:

- It is a compact JWS with `typ` `secevent+jwt` (`requireTyp`), signed with an asymmetric algorithm.
- Its signature verifies against the transmitter's JWKS.
- `iss` matches the transmitter.
- `aud` matches the stream's `aud` (or the `audience` option). If neither exists, the check fails closed.
- `jti`, `iat` and `events` are present, and `events` holds exactly one event (SSF 1.0).
- `iat` is not in the future. There is no age limit by default: a polled SET waits at the transmitter until it is read, so catching up after a stop must not throw old signals away. Set `maxSetAge` to impose one.
- A verification or stream-updated event names this stream (an opaque `sub_id`), if it names anything.

In addition, a replayed `jti` is dropped (`jtiCacheSize` remembers the last 10,000).

**Acknowledgement (RFC 8936).** An acknowledged SET, and one reported back as an error, is never sent again, so the receiver is careful with both:

- A SET is acknowledged only after its handlers ran without throwing. If one throws, the SET is left for the transmitter to send again, up to `maxDeliveryAttempts` times (default 5). After that it is acknowledged and `onError` gets `handler_failed`. Make handlers idempotent.
- Only a definitely invalid SET is reported as an error (bad signature, issuer, audience, `typ`, claims). One that couldn't be checked for a reason that may pass is left for redelivery for as long as that lasts, and never reported: a network error fetching the JWKS, or a key the cached JWKS doesn't hold yet.
- Polls never overlap: `poll()` during a poll shares it, and `pollNow()` during a poll asks for another right after it. A SET whose handlers are still running is never acknowledged by another poll.
- `stop()` sends the acknowledgements still owed. It waits for a poll in progress first.
- The poll endpoint must use TLS and share an origin with the transmitter (`trustedPollOrigins` adds others), because every poll carries the person's access token.
- Errors go to `onError`; without one, they are logged through `OIDCLog`, so a lost signal always leaves a trace.

SETs that arrive some other way can be handed to `receiveSet(_:)`, which validates and dispatches them, or `validateSet(_:)`, which only validates.

## API summary

**`OIDCAppConfiguration`**: `load(bundle:resource:)`, `load(contentsOf:)`, `init(propertyList:source:)`, `init(dictionary:)`, `makeClient(dpopKeyStore:transport:)`, `clientOptions(dpopKeyStore:transport:)`, `scope`.

**`OIDCClient`**:

- `discover(metadataURL:options:)`, `discover(issuer:options:)`, `fromMetadata(_:options:)`, `register(metadata:clientMetadata:initialAccessToken:options:)`
- `authorize(using:_:)` → `AuthorizationResult`; or `createAuthorizationRequest(_:)` → `AuthorizationRequest { url, state }` and `completeAuthorization(callbackURL:)` → `AuthorizationResult { tokenSet, context }`
- `refresh(_:scope:)`, `refresh(refreshToken:previousClaims:scope:)`
- `resourceHeaders(for:method:url:nonce:)`, `resourceHeaders(accessToken:tokenType:method:url:nonce:)`, `fetchResource(_:url:method:headers:body:)` → `HTTPResponse`
- `userinfo(_:expectedSub:)`, `revoke(_:hint:)`
- `createEndSessionRequest(idTokenHint:postLogoutRedirectURI:logoutHint:context:)`, `completeEndSession(callbackURL:)` → context, `endSession(using:request:)`
- `validateIDToken(_:nonce:maxAge:acrValues:accessToken:previousClaims:)`
- `metadata`, `issuer`, `clientID`, `scope`, `usesPAR`, `dpopKey`, `tokenEvents`, `securityFeatures` (a summary of the protections in effect)

**`AuthorizationRequestOptions`**: `scope`, `redirectURI`, `prompt`, `maxAge`, `loginHint`, `idTokenHint`, `acrValues`, `expectedSub`, `context`, `extraParameters` (which may not replace the parameters the client sets).

These are the `OIDCClientOptions`:

| Option | Default |
|---|---|
| `clientID` | required |
| `redirectURI`, `postLogoutRedirectURI` | `nil` |
| `scope` | `openid profile email` + `offline_access` if supported |
| `resource` | `[]` |
| `idTokenSignedResponseAlg` | `"RS256"` |
| `par` | `.auto` |
| `dpop` | `nil` (off); `DPoPOptions(keyStore:alg:key:)`, whose `keyStore` defaults to `MemoryKeyStore()` |
| `requireDPoP` | `nil`: true when `dpop` is set |
| `userinfoSignedResponseAlg` | `nil`: any asymmetric algorithm |
| `transactionStore` | `MemoryTransactionStore()` |
| `transactionTTL` | 600 s |
| `maxIDTokenAge` | 600 s (0: no limit) |
| `enforceACR` | `true` |
| `requireAuthTime` | `false` |
| `allowInsecureRequests` | `false` |
| `clockTolerance` | 30 s |
| `httpTimeout` | 10 s |
| `discoveryCacheTTL` | 3600 s |
| `transport` | `URLSessionTransport()` |
| `now` | `{ Date() }` |

**`SystemWebAuthenticator(prefersEphemeralWebBrowserSession: false, anchor: nil)`**, a `WebAuthenticator`: `authenticate(url:callback:)`. `anchor` returns the window to present over; the default is the key window.

**`TokenManager(client:store:refreshSkew:autoRefresh:minRefreshDelay:retryDelay:)`**:

| Option | Default |
|---|---|
| `store` | `defaultTokenStore()` |
| `refreshSkew` | 60 s (capped at half the token's lifetime) |
| `autoRefresh` | `true` |
| `minRefreshDelay` | 1 s |
| `retryDelay` | 5 s |

- `set(_:_:schedule:)`, `get(_:)`, `getTokenSet(_:forceRefresh:)`, `getAccessToken(_:forceRefresh:)`, `refresh(_:)`, `schedule(_:)`, `unschedule(_:)`, `delete(_:revoke:)`, `close()`
- `events`: `.refreshed(key:tokenSet:)`, `.refreshError(key:error:)`, `.expired(key:)`, `.removed(key:)`

**`AccountManager(client:options:)`**:

- `restore()`, `list()`, `get(_:)`, `active`, `activeKey`, `identity(_:)`, `accountsForSubject(_:)`
- `signIn`, `chooseAccount`, `addAccount`, `resume(_:)`, `reauthenticate(_:)`, each with a `using:` form; `handleCallback(_:)` → `SignInResult { account, tokenSet, intent, added }`
- `activate(_:)`, `getTokenSet(forceRefresh:)` and `refresh()` (the active account's only), `signOut(_:revoke:endSession:postLogoutRedirectURI:)`, `signOut(_:using:revoke:)`, `signOutAll(revoke:endSession:postLogoutRedirectURI:)`, `signOutAll(using:revoke:)`, `end(_:reason:)`, `forget(_:)`, `close()`
- `client`, `tokens` (its `TokenManager`), `events`: `.added`, `.updated`, `.activated(_:previous:)`, `.refreshed`, `.signedOut`, `.ended(_:reason:)`, `.forgotten`, `.activationError`, `.change`
- Also: `needsInteraction(_:)`, `interactionRequiredErrors`, `accountKey(iss:sub:)`

| `AccountManagerOptions` | Default |
|---|---|
| `store` | `defaultTokenStore()` |
| `storeKey` | `"accounts"` (the active account is kept under `active:accounts`) |
| `refreshSkew` | 60 s |
| `maxAccounts` | 10 |
| `rememberSignedOutDays` | 30 |
| `loginHint` | `preferred_username`, else `email` |
| `onActivate`, `onDeactivate`, `onLeave` | `nil` |

**`Account`**: `key`, `status`, `endedReason`, `addedAt`, `lastUsedAt`, `changedAt`, `claims` (profile claims only, no tokens), `iss`, `sub`, `sid`, `name`, `email`, `preferredUsername`, `identity`.

**`TokenSet`**: `accessToken`, `tokenType`, `refreshToken`, `idToken`, `scope`, `expiresAt`, `issuedAt`, `claims`, `additional`, `isDPoPBound`, `expiresIn(now:)`, `isExpired(skew:now:)`, `json`.

**`SSFReceiver(_:)`**:

- Handlers: `onSessionRevoked`, `onTokenClaimsChange`, `onCredentialChange`, `onAssuranceLevelChange`, `onDeviceComplianceChange`, `onSessionEstablished`, `onSessionPresented`, `onRiskLevelChange`, `onVerification`, `onStreamUpdated`, `onEvent(_:_:)`, `onAnyEvent`, `onUnhandledEvent`, `onError`, `removeHandlers(for:)`
- Lifecycle: `discover()`, `start(catchUp:)`, `stop(deleteStream:)`, `poll()`, `pollNow()`
- Streams (SSF 1.0 §8.1): `createStream(_:)`, `listStreams()`, `getStream(_:)`, `updateStream(_:)`, `replaceStream(_:)`, `deleteStream()`, `getStatus()`, `updateStatus(_:reason:)`, `addSubject(_:verified:)`, `removeSubject(_:)`, `requestVerification(timeout:state:)`
- Delivery: `receiveSet(_:)`, `validateSet(_:)`
- `metadata`, `stream`, `configuration`

| `SSFReceiverConfiguration` | Default |
|---|---|
| `transmitterIssuer` | required |
| `authorization` | `nil`; `.oidc(client) { tokenSet }`, `.bearer { token }` or `.headers { request in … }` |
| `audience` | the stream's `aud` |
| `eventsRequested` | `CAEP.all` |
| `streamID` | `nil`: create or reuse a stream |
| `description` | `"swift-oidc-caep-native-app receiver"` |
| `pollInterval` | 5 s |
| `maxEvents` | 25 |
| `clockTolerance` | 60 s |
| `maxSetAge` | 0 (no limit) |
| `maxDeliveryAttempts` | 5 |
| `allowInsecureRequests` | `false` |
| `trustedPollOrigins` | `[]` |
| `requireTyp` | `true` |
| `jtiCacheSize` | 10000 |
| `httpTimeout` | 10 s |
| `transport` | `URLSessionTransport()` |
| `onEventReceived` | `logEventReceived` |
| `now` | `{ Date() }` |

**Subjects and constants:** `Subject.issSub`, `.email`, `.phone`, `.opaque`, `.account`, `.uri`, `.did`, `.aliases`, `.complex`; `SubjectIdentity`, `subjectMatches(_:_:)`; `CAEP.*` and `CAEP.all`, `SSF.*`, `RISC.*`, `Delivery.push` / `.poll`, `eventName(_:)`.

**Stores:**

| Store | Kind | Notes |
|---|---|---|
| `KeychainTokenStore(service:accessGroup:useDataProtectionKeychain:)` | tokens | Default on Apple platforms. Service `defaultKeychainService("tokens")` (`<bundle id>.oidc-tokens`), login keychain. |
| `MemoryTokenStore()` | tokens | Default where there is no Keychain. Nothing persists. |
| `defaultTokenStore(service:)` | tokens | The Keychain on Apple platforms, else memory. |
| `SecureEnclaveKeyStore(service:account:accessGroup:useDataProtectionKeychain:)` | DPoP key | ES256, non-extractable. `SecureEnclaveKeyStore.isAvailable`. |
| `KeychainKeyStore(service:account:accessGroup:useDataProtectionKeychain:)` | DPoP key | ES256/384/512 software key, private bytes in the Keychain. |
| `MemoryKeyStore()` | DPoP key | A new key every launch. |
| `preferredDPoPKeyStore(service:)` | DPoP key | The Secure Enclave when it can create a key, else the Keychain. |
| `MemoryTransactionStore()` | sign-ins in progress | The default. |

Your own stores implement `TokenStore`, `DPoPKeyStore` or `TransactionStore`; your own networking implements `HTTPTransport`.

**Errors:** `OIDCError` with `kind` (`.general`, `.oauth`, `.validation`, `.setValidation`, `.ssf`), `code`, `message`, `status`, `response`, `oauthError`, `oauthErrorDescription`, `errorURI`, `context`, `account`, `retryable`, `isUserCancellation`. The [guide](native-app-guide.md#11-errors) lists the codes.

**Logging:** `OIDCLog.handler` receives the library's few log lines (`.info`, `.warning`, `.error`): a received CAEP event, a warning about token storage, an SSF error nobody handles. The default writes them to standard output and standard error.

## Tests

```sh
swift test                                                                  # on macOS
docker run --rm -v "$PWD":/pkg -w /pkg swift:6.1-noble swift test           # on Linux
```

The tests run against a strict in-memory OpenID Provider and SSF transmitter, injected as the library's `HTTPTransport`.

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC.
