# Building a native macOS app with OIDCCAEPClient

This guide shows how to add OpenID Connect sign-in and CAEP to a native macOS app with the `OIDCCAEPClient` library from this package. By the end, your app signs people in through the system browser, keeps their tokens in the Keychain and fresh, calls your APIs with sender-constrained tokens, and reacts within seconds when the identity provider reports a change about a signed-in user through CAEP.

The app is a **public client**: it has no client secret, because anything shipped in an app can be read out of it. Sign-in happens in the person's browser through `ASWebAuthenticationSession`, as RFC 8252 (OAuth 2.0 for Native Apps) requires. The app never sees the password, and never shows the provider's pages in an embedded web view.

The [API reference](reference.md) lists every option, method and event. This guide is the walkthrough. It explains which pieces to use, in what order, and why. The demo in this repository ([`Demo/`](../Demo)) is a working SwiftUI app built this way.

**Who this is for.** macOS apps written in Swift, with SwiftUI or AppKit. The package targets macOS 13 and later.

## Contents

1. [How the pieces fit together](#1-how-the-pieces-fit-together)
2. [Add the package](#2-add-the-package)
3. [Register the app at the identity provider](#3-register-the-app-at-the-identity-provider)
4. [Create OIDCConfiguration.plist](#4-create-oidcconfigurationplist)
5. [Create the client](#5-create-the-client)
6. [Where tokens and keys are kept](#6-where-tokens-and-keys-are-kept)
7. [Sign in](#7-sign-in)
8. [Call your APIs](#8-call-your-apis)
9. [Receive CAEP events](#9-receive-caep-events)
10. [Sign out](#10-sign-out)
11. [Errors](#11-errors)
12. [Sandboxed and signed apps](#12-sandboxed-and-signed-apps)
13. [Security checklist](#13-security-checklist)
14. [Troubleshooting](#14-troubleshooting)

## 1. How the pieces fit together

| Piece | What it does |
|---|---|
| `OIDCAppConfiguration` | Reads the app's settings from `OIDCConfiguration.plist` and creates the client. |
| `OIDCClient` | Sign-in (Authorization Code + PKCE, PAR, DPoP), ID token validation, refresh, UserInfo, sign-out. |
| `SystemWebAuthenticator` | Shows the provider's pages in the system browser with `ASWebAuthenticationSession`, and returns the redirect. |
| `TokenManager` | Caches one person's tokens and refreshes them before they expire. |
| `AccountManager` | Several people signed in to one app, with one active account. Use it instead of `TokenManager` when you need that; it also suits a single account. |
| `SSFReceiver` | Subscribes to the identity provider's Shared Signals stream, polls it, validates each event and hands it to your handlers. |
| Stores | Where tokens and the DPoP key are kept: the Keychain, the Secure Enclave, or memory. |

```
 Your macOS app                                           Identity provider
 ──────────────                                           ─────────────────
 SystemWebAuthenticator ── system browser: sign-in ─────▶ authorization endpoint
        ▲                                                       │
        └──── redirect to com.example.myapp:/callback ◀─────────┘
 OIDCClient ──── PAR, token, UserInfo (DPoP proofs) ────▶ OpenID Connect endpoints
 AccountManager / TokenManager (Keychain cache, refresh)
 SSFReceiver ──── create / read stream, poll ───────────▶ SSF transmitter
      ▲                                                       │
      └──────────── signed security events (SETs) ◀───────────┘
 your handlers: end the session, refresh tokens, ask for step-up, ...
 your APIs ◀──── fetchResource(): access token + DPoP proof
```

The identity provider is usually both the OpenID provider and the SSF transmitter. The receiver authenticates to the transmitter with the **signed-in person's own access token**, so it can only see that person's stream. An app has no public endpoint for the transmitter to push to, so delivery is always **poll** (RFC 8936).

## 2. Add the package

**With Xcode:** choose **File → Add Package Dependencies…**, enter `https://github.com/rcbj/swift-oidc-caep-native-app.git`, choose a version rule (for example *Up to Next Minor Version* from `0.1.0`), and add the **OIDCCAEPClient** library to your app target.

**With `Package.swift`:**

```swift
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/rcbj/swift-oidc-caep-native-app.git", from: "0.1.0"),
    ],
    targets: [
        .executableTarget(
            name: "MyApp",
            dependencies: [.product(name: "OIDCCAEPClient", package: "swift-oidc-caep-native-app")],
            resources: [.process("Resources")]   // OIDCConfiguration.plist, see step 4
        ),
    ]
)
```

`from: "0.1.0"` accepts every later version below 1.0.0. While the version is 0.x, a new minor version may change the API; use `.upToNextMinor(from: "0.1.0")` to stay on 0.1. The package needs macOS 13 or later and Swift 5.9 or later. Its only dependency is [swift-crypto](https://github.com/apple/swift-crypto), which is CryptoKit on Apple platforms.

## 3. Register the app at the identity provider

Register your app as a **public client**:

| Setting | Value |
|---|---|
| Client type | public, `token_endpoint_auth_method: none` |
| Grant types | `authorization_code`, `refresh_token` |
| Response type | `code` |
| Redirect URI | a private-use scheme, e.g. `com.example.myapp:/callback` |
| Post-logout redirect URI | e.g. `com.example.myapp:/logged-out` |
| Allowed scopes | `openid profile email`, `offline_access` for refresh tokens, and the CAEP scopes below |

**The redirect URI.** RFC 8252 §7.1 gives a native app a **private-use URI scheme** named after a domain you control, in reverse order: `example.com` becomes `com.example`, and a scheme such as `com.example.myapp`. The redirect URI is that scheme, a colon, and **one** slash: `com.example.myapp:/callback`. The library refuses a scheme without a period, since a single word such as `myapp` could belong to any app. You don't need to declare the scheme in `Info.plist` (`CFBundleURLTypes`): `ASWebAuthenticationSession` catches the redirect itself, and only for the session it started.

Other redirect URIs:

- **`https`** on a domain the app claims with an associated domain works with `SystemWebAuthenticator` on macOS 14.4 and later.
- **Loopback** (`http://127.0.0.1:port/…`, RFC 8252 §7.3) is accepted by `OIDCClient`, but `ASWebAuthenticationSession` cannot receive it, so `SystemWebAuthenticator` refuses it. Using it means writing your own `WebAuthenticator` with a local listener.

**No CORS.** Unlike a browser app, a native app's requests are not subject to CORS, so the provider needs no web origin for it.

**TLS.** Every provider endpoint must be `https`. Loopback `http` (`localhost`, `127.0.0.1`) is allowed for development. The Mac must trust the provider's certificate: `URLSession` and the browser both check it. With a self-signed development certificate, add it to the keychain and mark it trusted, or use a local CA such as mkcert.

**CAEP scopes.** These are the CAEP Interoperability Profile's names:

| Scope | Lets the receiver |
|---|---|
| `ssf.read` | read its stream and its status, and poll for events |
| `ssf.manage` | everything `ssf.read` does, plus create, change or delete a stream, add or remove subjects, change the stream's status and request a verification event |

An app that only consumes a stream someone else created needs `ssf.read`. An app that creates its own stream, chooses its event types or adds the user as the stream's subject needs `ssf.manage`.

### iya-sts

With iya-sts, both scopes are gated by role. A person is issued `ssf.read` only while two things are true: they are in the group `ssf-read`, and your application is an **application member** of the native role `SSF_READ`. `ssf.manage` works the same way through the group `ssf-manage` and the role `SSF_MANAGE`, which does not authorize `ssf.read`, so ask for both. Every realm has these roles and groups by default. Applications have to be added to the roles; nothing adds them for you.

[`scripts/register-iya-sts-client.mjs`](../scripts/register-iya-sts-client.mjs) does all of this for the demo, from the demo's `OIDCConfiguration.plist`:

- registers the public client with the plist's redirect and post-logout redirect URIs;
- adds it to `SSF_READ` and `SSF_MANAGE`;
- creates a test user in `ssf-read` and `ssf-manage`.

Pass `--config` to run it on your own app's plist, or read it as an example of the management API calls involved. [Running the demo](../docs/demo.md) shows how to run it.

## 4. Create OIDCConfiguration.plist

The app's OpenID Connect settings live in a property list, the usual place for configuration that ships with a macOS app. Create **`OIDCConfiguration.plist`**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>MetadataURL</key>
	<string>https://idp.example.com/.well-known/openid-configuration</string>
	<key>ClientID</key>
	<string>my-native-app</string>
	<key>Scopes</key>
	<array>
		<string>openid</string>
		<string>profile</string>
		<string>email</string>
		<string>offline_access</string>
		<string>ssf.read</string>
		<string>ssf.manage</string>
	</array>
	<key>RedirectURI</key>
	<string>com.example.myapp:/callback</string>
	<key>PostLogoutRedirectURI</key>
	<string>com.example.myapp:/logged-out</string>
</dict>
</plist>
```

| Key | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `MetadataURL` | string | yes | — | The provider's metadata URL. It must contain `/.well-known/`, e.g. `…/.well-known/openid-configuration`. |
| `ClientID` | string | yes | — | The public client's `client_id`. |
| `Scopes` | array of strings, or a space-separated string | no | `openid profile email`, plus `offline_access` when the provider offers it | The scopes requested at sign-in. |
| `RedirectURI` | string | yes | — | A private-use scheme (`com.example.myapp:/callback`), or `https` with an associated domain. |
| `PostLogoutRedirectURI` | string | no | — | Where the provider returns after logout. Needed to sign out in the browser (step 10). |
| `Resource` | array or string | no | — | RFC 8707 resource indicators: the APIs the tokens are for. |
| `DPoP` | bool | no | `true` | Bind tokens to a key (RFC 9449). |
| `PAR` | string | no | `auto` | Pushed authorization requests: `auto`, `always` or `never`. |
| `IDTokenSignedResponseAlg` | string | no | `RS256` when the provider offers it, else the first algorithm it offers that the library verifies | The one ID token `alg` accepted. |
| `ACRValues` | string | no | — | `acr_values` for your sign-in requests. |
| `PrefersEphemeralWebBrowserSession` | bool | no | `false` | Sign in without the browser's cookies. |
| `SSFTransmitterIssuer` | string | no | the provider's issuer | The CAEP transmitter, when it is not the provider. |
| `CAEPEnabled` | bool | no | `true` | Whether the app should receive CAEP events. |
| `TrustedCertificates` | array | no | — | PEM or DER files (or inline PEM) to trust for TLS: a private CA's root, or a whole chain. Relative paths are resolved against the plist's folder. See [Linux and macOS](https://rcbj.github.io/swift-oidc-caep-native-app/linux.html#tls-trust). |
| `TrustSystemRoots` | bool | no | `true` | Whether the system's roots still count beside `TrustedCertificates`. |
| `InsecureSkipTLSVerification` | bool | no | `false` | Accept any TLS certificate. **Local test providers only.** |

`makeClient()` applies the first nine keys. The last four are read into `OIDCAppConfiguration` for your code to use, and the examples below show where: `acrValues` in the sign-in options, `prefersEphemeralWebBrowserSession` in the `SystemWebAuthenticator`, and `ssfTransmitterIssuer` and `caepEnabled` when starting the receiver.

**Add the file to the app target.**

- **Xcode:** drag it into the project and tick your app target, so it appears under **Build Phases → Copy Bundle Resources**. `OIDCAppConfiguration.load()` reads it from `Bundle.main`.
- **Swift Package Manager:** put it in the target's resources (`resources: [.process("Resources")]`, as in step 2) and load it from the package's bundle: `OIDCAppConfiguration.load(bundle: .module)`.

Instead of a separate file, the same dictionary can sit under an **`OIDCConfiguration`** key in the app's `Info.plist`; `load()` looks there when there is no file. `OIDCAppConfiguration.load(contentsOf:)` reads a plist from any URL, and `OIDCAppConfiguration(metadataURL:clientID:…)` builds the configuration in code.

## 5. Create the client

```swift
import OIDCCAEPClient

let configuration = try OIDCAppConfiguration.load()       // .load(bundle: .module) in a Swift package
let client = try await configuration.makeClient(dpopKeyStore: await preferredDPoPKeyStore())
```

`makeClient(dpopKeyStore:)` fetches the provider's metadata from `MetadataURL` and creates an `OIDCClient`. Before it returns, it checks the provider:

- the metadata's `issuer` must be the one `MetadataURL` was built from (Discovery §4.3);
- every endpoint must use `https`;
- the provider must offer PKCE `S256` and accept public clients (`none`);
- it must sign ID tokens with an algorithm the library verifies;
- PAR is used when the provider offers it (`PAR` `auto`).

It also loads the DPoP key, or creates one. With no `dpopKeyStore`, `makeClient` keeps it in secure storage: `preferredDPoPKeyStore()`, which returns `SecureEnclaveKeyStore` when the Mac's Secure Enclave can create a key and `KeychainKeyStore` otherwise (memory where neither exists). Tokens cached in the Keychain are bound to that key, so they can still be refreshed after a relaunch. Step 6 explains the difference between the two stores.

Without a plist, create the client from options:

```swift
let client = try await OIDCClient.discover(
    metadataURL: URL(string: "https://idp.example.com/.well-known/openid-configuration")!,
    options: OIDCClientOptions(
        clientID: "my-native-app",
        redirectURI: URL(string: "com.example.myapp:/callback")!,
        postLogoutRedirectURI: URL(string: "com.example.myapp:/logged-out")!,
        dpop: DPoPOptions(keyStore: await preferredDPoPKeyStore())))
```

`client.securityFeatures` summarizes the protections in effect (PKCE, PAR, DPoP algorithm and key thumbprint, whether the key is extractable). The demo shows it as **Protections in effect**.

## 6. Where tokens and keys are kept

| What | Default | Kept |
|---|---|---|
| Tokens, and `AccountManager`'s account list | `defaultTokenStore()` | `KeychainTokenStore` on Apple platforms; `MemoryTokenStore` where there is no Keychain |
| The DPoP key | `preferredDPoPKeyStore()` (when `makeClient` is given none) | `SecureEnclaveKeyStore` when available, else `KeychainKeyStore` |
| A sign-in in progress (state, nonce, PKCE verifier) | `MemoryTransactionStore` | memory; the redirect comes back to the process that started the sign-in |

**Tokens are cached in the platform's secure storage when it has one, otherwise in memory.** On macOS that is the Keychain: the tokens are encrypted at rest, survive relaunches, and every signed-in account stays signed in. Where no Keychain exists (Linux, where the tests run), `defaultTokenStore()` returns `MemoryTokenStore`, and a relaunch means signing in again.

**The DPoP key.** A key made in the **Secure Enclave** can be used to sign but never read out, not by the app and not by malware running as the user. Stolen access or refresh tokens are then useless on any other machine. Macs with Apple silicon or a T2 chip have one. What the Keychain holds for it is a handle only this Mac's Secure Enclave can use. The Secure Enclave creates ES256 keys only. Without it, `KeychainKeyStore` keeps a software key's private bytes in the Keychain: still sender-constrained, but the key could be copied along with the tokens.

**Keychain service names.** By default they are derived from the app's bundle identifier (`defaultKeychainService(_:)`: `<bundle id>.oidc-tokens` and `<bundle id>.oidc-dpop`), so two apps never share items. A binary with no bundle identifier (`swift run`) falls back to `oidc-caep-client.tokens` and `oidc-caep-client.dpop`. To choose them yourself:

```swift
let keyStore = await preferredDPoPKeyStore(service: "com.example.myapp.dpop")
let client = try await configuration.makeClient(dpopKeyStore: keyStore)
let accounts = AccountManager(client: client, options: AccountManagerOptions(
    store: defaultTokenStore(service: "com.example.myapp.tokens")))
```

**Other choices:**

- **Memory only:** `AccountManagerOptions(store: MemoryTokenStore())`. Nothing persists; after a relaunch, `resume` gets new tokens without a screen while the provider's session lasts.
- **The data protection keychain:** `KeychainTokenStore(service:accessGroup:useDataProtectionKeychain: true)`, and the same flag on the key store. Its items are `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. It needs a signed app with a `keychain-access-groups` entitlement (step 12). The default is the login keychain.
- **Your own store:** implement `TokenStore` (`get`, `set`, `delete`, `isPersistent`) or `DPoPKeyStore`.

`AccountManager` logs a warning when tokens go to persistent storage with DPoP off: anything that can read the store could use them anywhere.

## 7. Sign in

```swift
let authenticator = SystemWebAuthenticator(
    prefersEphemeralWebBrowserSession: configuration.prefersEphemeralWebBrowserSession)
let accounts = AccountManager(client: client)
try await accounts.restore()             // the accounts from the last launch, and the active one

do {
    let result = try await accounts.signIn(using: authenticator,
                                           AuthorizationRequestOptions(acrValues: configuration.acrValues))
    print("Signed in as", result.account.name ?? result.account.sub)
} catch let error as OIDCError where error.isUserCancellation {
    // The person closed the browser window.
}
```

`signIn(using:)` builds the authorization request (PKCE, `state`, `nonce`, PAR, `dpop_jkt`), opens it with `ASWebAuthenticationSession`, waits for the redirect, and completes the sign-in: the `state` is checked, the code is redeemed with the PKCE verifier and a DPoP proof, and the ID token is validated. The account is cached and becomes the active account.

`SystemWebAuthenticator` presents the browser over the app's key window. Pass `anchor:` to choose another window. Leave `prefersEphemeralWebBrowserSession` off unless you have a reason: sharing the browser's session is what makes single sign-on, `prompt=none` and several accounts work.

**Choosing the request.** Each has a `using:` form that runs the browser step:

| Call | Request | Use |
|---|---|---|
| `signIn(using:)` | the provider decides | Its account picker when several people are signed in there. |
| `chooseAccount(using:)` | `prompt=select_account` | Always the provider's picker. |
| `addAccount(using:)` | `prompt=login` | A fresh sign-in, added as another account. |
| `resume(key, using:)` | `prompt=none`, naming the account | New tokens without a screen while its session at the provider lasts. |
| `reauthenticate(key, using:)` | `prompt=login`, naming the account | Sign that person in again, e.g. step-up with `acrValues` or `maxAge`. |

`resume` and `reauthenticate` send `login_hint` and the cached `id_token_hint`. If the provider signs in somebody else, the sign-in is refused with `account_mismatch` and the tokens it got are revoked.

**After a relaunch.** `restore()` loads the account list from the store and reactivates the account that was active, refreshing its tokens if they are due. An account whose cached tokens can't be used has status `.tokensMissing`; get new ones without a screen, and fall back to a visible sign-in:

```swift
if let account = await accounts.active, account.status == .tokensMissing {
    do {
        try await accounts.resume(account.key, using: authenticator)
    } catch where needsInteraction(error) {
        try await accounts.reauthenticate(account.key, using: authenticator)
    }
}
```

### Several accounts in one app

Some providers keep several people signed in in one browser and let each request say which one it is for. iya-sts does this with `authn.multipleAccounts`, on by default. `AccountManager` is the app's side of that:

- **One token cache.** Every signed-in account's tokens are cached until that account is signed out or its session ends, so any of them can become active without a password.
- **One active account.** Only its tokens can be reached: `getTokenSet()` takes no account. Only its tokens are refreshed in the background. The others are **dormant**: stored, not used, not refreshed.

```swift
await accounts.list()                       // every account, in the order added
try await accounts.activate(otherKey)       // the previous account goes dormant
let tokenSet = try await accounts.getTokenSet()   // the ACTIVE account's, refreshed when due
```

**Activating** a dormant account refreshes its tokens first if they are due, then runs `onActivate` (step 9), and only then makes it active. If either fails, the previously active account is reactivated and the error is thrown.

**Statuses:** `.signedIn`, `.tokensMissing`, `.signedOut` and `.ended` (ended by the provider, a security event or a refused refresh; `endedReason` says why). Signed-out accounts stay listed for `rememberSignedOutDays` (default 30). Past `maxAccounts` (default 10), the account that left longest ago is forgotten; when all of them are signed in, a new sign-in is refused (`too_many_accounts`).

**Following changes.** `accounts.events` delivers `.added`, `.updated`, `.activated`, `.refreshed`, `.signedOut`, `.ended`, `.forgotten`, `.activationError` and `.change`, as callbacks or as an `AsyncStream`:

```swift
Task { @MainActor in
    for await event in accounts.events.stream() {
        if case .ended(let account, let reason) = event { model.show("\(account.name ?? account.sub): \(reason ?? "session ended")") }
        if case .change = event { await model.reload(from: accounts) }
    }
}
```

### One person only

Without an account list, use `OIDCClient` and `TokenManager` directly:

```swift
let tokens = TokenManager(client: client)                 // the Keychain by default, auto-refreshing
let result = try await client.authorize(using: authenticator)
try await tokens.set("user", result.tokenSet)
let tokenSet = try await tokens.getTokenSet("user")       // refreshed first when (nearly) expired
```

## 8. Call your APIs

`fetchResource` sends a request with the access token. A DPoP-bound token gets a fresh proof for that method and URL. When the resource server asks for a DPoP nonce, it retries once with it.

```swift
let tokenSet = try await accounts.getTokenSet()
let response = try await client.fetchResource(tokenSet, url: URL(string: "https://api.example.com/me")!)
if response.isOK {
    let me = try JSONValue.parse(response.body)
}
```

It takes `method:`, `headers:` and `body:` too. To send the request with your own `URLSession`, ask for the headers instead:

```swift
let url = URL(string: "https://api.example.com/orders")!
var request = URLRequest(url: url)
request.httpMethod = "POST"
for (name, value) in try client.resourceHeaders(for: tokenSet, method: "POST", url: url) {
    request.setValue(value, forHTTPHeaderField: name)    // authorization, and dpop when bound
}
```

Make the headers again for every request: a DPoP proof is for one request only. `resourceHeaders` doesn't retry on a nonce challenge; `fetchResource` does.

**UserInfo.** `try await client.userinfo(tokenSet)` returns the claims, after checking that their `sub` is the ID token's.

**A 401 from your API** usually means the access token expired or was revoked. Call `accounts.refresh()` and retry once. If the refresh fails with `invalid_grant`, the account's tokens are dropped and it is ended; ask the person to sign in again.

## 9. Receive CAEP events

### Wire a receiver to the active account

Each account has its own stream at the transmitter: iya-sts gives a stream created with a person's token to that person, and sends it only events about them. So the receiver follows the active account. `AccountManager`'s three hooks are where it starts and stops:

- **`onActivate`** runs before an account becomes active, with access to its tokens. Start its receiver here with `catchUp: true`, so the events queued while it was dormant are acted on before the account is used.
- **`onDeactivate`** runs when it stops being active. Stop polling; its stream keeps queueing.
- **`onLeave`** runs when it is signed out or ended, while its tokens still work. Delete its stream.

The receiver's handlers call `accounts.end(_:reason:)` to end the account an event is about. That runs `onLeave` and `onDeactivate` **while the handler is still running**. Calling `SSFReceiver.stop()` there is safe: from inside a handler it returns at once, and the poll running the handler sends the last acknowledgements when it finishes.

```swift
import OIDCCAEPClient

/// The active account's SSF receiver.
actor Signals {
    private let client: OIDCClient
    private let transmitter: String
    private let stepUp: @Sendable (_ key: String, _ why: String) async -> Void
    private var accounts: AccountManager?
    private var receiver: SSFReceiver?
    private var key: String?

    init(client: OIDCClient, transmitter: String, stepUp: @escaping @Sendable (String, String) async -> Void) {
        self.client = client
        self.transmitter = transmitter
        self.stepUp = stepUp
    }

    func attach(_ accounts: AccountManager) { self.accounts = accounts }

    /// onActivate: open the account's stream and act on what it queued while it was dormant.
    func start(_ account: Account, _ access: AccountAccess) async {
        let receiver = SSFReceiver(SSFReceiverConfiguration(
            transmitterIssuer: transmitter,
            // Every call to the transmitter carries this person's token, with a DPoP proof when bound.
            authorization: .oidc(client) { try await access.getTokenSet() }))
        register(receiver, account, access)
        self.receiver = receiver
        key = account.key
        do {
            try await receiver.start(catchUp: true)
            try? await receiver.addSubject(Subject.issSub(account.iss, account.sub))   // needs ssf.manage
        } catch {
            print("CAEP is not running for \(account.sub): \(error)")
        }
        // A handler may have ended the account during the catch-up, which stopped this receiver.
        if self.receiver !== receiver { await receiver.stop() }
    }

    /// onDeactivate.
    func stop() {
        guard let receiver else { return }
        self.receiver = nil
        key = nil
        Task { await receiver.stop() }
    }

    /// onLeave: the account's tokens still work, so its stream can be deleted (needs ssf.manage).
    func leave(_ account: Account) async {
        guard let receiver, key == account.key else { return }
        try? await receiver.deleteStream()
        stop()
    }

    private func register(_ receiver: SSFReceiver, _ account: Account, _ access: AccountAccess) {
        let key = account.key
        let identity = account.identity
        // Act only on events about this account: another of the person's sessions is not this one.
        let mine: @Sendable (SecurityEvent) -> Bool = { subjectMatches($0.subject, identity) }
        receiver
            .onSessionRevoked { event in
                if mine(event) { await self.end(key, event.reasonUser?["en"] ?? "The session was revoked.") }
            }
            .onTokenClaimsChange { event in
                if mine(event) { _ = try await access.getTokenSet(forceRefresh: true) }
            }
            .onCredentialChange { event in
                if mine(event), let change = event.payload["change_type"]?.stringValue, ["revoke", "delete"].contains(change) {
                    await self.end(key, "A credential was \(change)d. Sign in again.")
                }
            }
            .onAssuranceLevelChange { event in
                if mine(event), event.payload["change_direction"]?.stringValue == "decrease" {
                    await self.stepUp(key, "Assurance dropped.")
                }
            }
            .onDeviceComplianceChange { event in
                if mine(event), event.payload["current_status"]?.stringValue == "not-compliant" {
                    await self.end(key, "This device no longer meets policy.")
                }
            }
            .onRiskLevelChange { event in
                guard mine(event) else { return }
                switch event.payload["current_level"]?.stringValue {
                case "HIGH": await self.end(key, "Unusual activity was detected.")
                case "MEDIUM": await self.stepUp(key, "The risk level was raised.")
                default: break
                }
            }
            .onError { error, context in
                print("CAEP", context.phase.rawValue, error.code ?? "", error.message)
            }
    }

    private func end(_ key: String, _ reason: String) async {
        _ = try? await accounts?.end(key, reason: reason)
    }
}
```

Create it before the account manager, give the manager the hooks, then attach it and restore:

```swift
let signals = Signals(client: client,
                      transmitter: configuration.ssfTransmitterIssuer ?? client.issuer,
                      stepUp: { key, why in await model.requireStepUp(key, why) })
let caep = configuration.caepEnabled
let accounts = AccountManager(client: client, options: AccountManagerOptions(
    store: defaultTokenStore(service: "com.example.myapp.tokens"),
    onActivate: { account, access in if caep { await signals.start(account, access) } },
    onDeactivate: { _ in await signals.stop() },
    onLeave: { account, _ in await signals.leave(account) }))
await signals.attach(accounts)
try await accounts.restore()             // runs onActivate for the account that was active
```

`model.requireStepUp` stands for your UI: show a banner, and call `accounts.reauthenticate(key, using: authenticator, AuthorizationRequestOptions(acrValues: …))` when the person agrees.

Here a receiver that fails to start is reported and the account is activated anyway. To refuse activation instead, rethrow from `start`: an error thrown by `onActivate` aborts the activation.

`start()` either opens an existing stream or creates one:

- **Opening an existing stream:** pass its id as `SSFReceiverConfiguration(streamID:)`. Keep the id, for example in `UserDefaults`, to reopen the same stream later.
- **Creating a stream:** this needs `ssf.manage`. If the transmitter refuses the create because the person already has streams (HTTP 409, or HTTP 403 `access_denied` when they hold as many as it allows; iya-sts allows `ssf.maxStreams`, 25), one of their streams is reused and re-pointed at this receiver: the one whose `description` is this receiver's, else the first. So an app that lost its stored stream id doesn't fail at the limit.

With `ssf.read` only, you can't create a stream. Find one with `listStreams()` and pass its id as `streamID`.

### Choose the event types

A new stream asks for every CAEP event type (`CAEP.all`) unless you pass `eventsRequested`. To change an existing stream's types (needs `ssf.manage`):

```swift
try await receiver.updateStream(["events_requested": JSONValue([CAEP.sessionRevoked, CAEP.credentialChange, CAEP.riskLevelChange])])
let delivered = await receiver.stream?["events_delivered"]   // what the transmitter will actually send
```

The transmitter decides `events_delivered`: the types you asked for that it supports. The scopes control which operations you may perform on the stream, not which event types you may receive. The demo's **CAEP events** tab lets the person tick types and applies them with this call. `getStatus()` returns the stream's status, and `requestVerification()` asks the transmitter for a verification event and returns it once it arrives.

### Handle the events

Each handler gets a validated `SecurityEvent`: `type`, `name`, `payload`, `subject`, `eventTimestamp`, `initiatingEntity`, `reasonAdmin`, `reasonUser`, `jti` and the whole SET. A handler that throws leaves the event for the transmitter to send again.

Which events need action is your policy. These are reasonable defaults, and the ones the demo uses:

| Event | Reasonable reaction |
|---|---|
| session-revoked | End the account and discard its tokens: `accounts.end(key, reason:)`. |
| token-claims-change | Refresh tokens so the new claims (`payload["claims"]`) take effect. |
| credential-change | Revoked or deleted: end the account. Otherwise tell the person. |
| assurance-level-change | Decrease: require step-up before sensitive actions. |
| device-compliance-change | Not compliant: end the account, or limit what the app allows. |
| risk-level-change | HIGH: end the account. MEDIUM: require step-up. |
| session-established, session-presented | Informational; record or display them. |

**Check who an event is about.** A stream can carry events about other sessions of the same person. Compare the event's subject with the account before acting: `subjectMatches(event.subject, account.identity)`, or `accounts.accountsForSubject(subId)` to find every listed account it is about. An email or phone number subject counts only when the ID token said it was verified. An event that names a session matches only the account holding that `sid`.

### Add your own logic for every event

`onEventReceived` runs once for every accepted event, before the typed handlers. By default it is `logEventReceived`, which logs the event's name and `jti` through `OIDCLog`, leaving out the payload and subject, which can carry personal data. Put logging, auditing or analytics here:

```swift
let configuration = SSFReceiverConfiguration(
    transmitterIssuer: transmitter,
    authorization: .oidc(client) { try await access.getTokenSet() },
    onEventReceived: { event in
        try await logEventReceived(event)                 // keep the log line, or drop it
        await audit.record(event.name, event.subject, event.eventTimestamp)
    })
```

Pass `onEventReceived: nil` to turn it off. If it throws, `onError` gets the error with phase `.hook`, and the typed handlers still run. `OIDCLog.handler` decides where the library's log lines go; replace it to send them to `os.Logger` or nowhere.

### What the receiver checks for you

Every event (a signed SET) is refused unless all of these hold:

- **The signature** verifies against the transmitter's keys, uses an asymmetric algorithm, and has `typ: secevent+jwt`.
- **`iss`** is the transmitter.
- **`aud`** is your stream's.
- **`iat`** isn't in the future. There's no age limit by default, so events queued while nobody was polling are still acted on when the receiver catches up.
- **`events`** holds exactly one event, and a stream event (verification, stream-updated) names this stream.
- **`jti`** hasn't been seen before. A repeat is dropped.

The receiver is careful about what it tells the transmitter, because an acknowledged event, or one reported as an error, is never sent again:

- **An invalid event** goes to `onError`, is reported back to the transmitter on the next poll, and never reaches your handlers.
- **An event that couldn't be checked** for a reason that may pass (a network error fetching the keys, a key the cached set doesn't hold yet) is left for the transmitter to send again.
- **An event is acknowledged only after your handlers succeed.** If one throws, the event comes back on a later poll, up to `maxDeliveryAttempts` times (default 5). Write handlers so that running twice is harmless.
- **The poll URL** must use https and be at the transmitter's origin, because every poll carries the person's access token.

Without an `onError`, errors are logged through `OIDCLog`, so a lost event always leaves a trace.

### Stop and clean up

```swift
await receiver.stop()                        // stop polling; the stream keeps queueing events
await receiver.stop(deleteStream: true)      // with ssf.manage: also remove the stream
```

`stop()` sends the acknowledgements still owed. Called from inside a handler, it leaves that to the poll running the handler.

**When to delete the stream, and when not:**

- **Signing out or removing an account:** delete it when the token holds `ssf.manage` (`stop(deleteStream: true)`, in `onLeave` while the tokens still work); otherwise just stop polling. The demo does this.
- **The app is quit, put in the background, or its account made dormant:** don't delete it. The transmitter keeps queueing events for it, and `start(catchUp: true)` acts on them when the app comes back. Keep the stream id (the demo uses `UserDefaults`) and pass it as `streamID` on the next launch.
- **An app that never comes back** (killed, uninstalled) leaves its stream behind. The transmitter removes it: iya-sts deletes a person's poll stream after `ssf.personStreamInactivityTimeoutS` (a day by default) with no poll ([iya-sts#1094](https://github.com/rcbj/iya-sts/issues/1094)). Within that time, a reinstalled app that lost the id reuses the stream (see above).

## 10. Sign out

```swift
do {
    try await accounts.signOut(using: authenticator)          // the active account
} catch let error as OIDCError where error.isUserCancellation {
    // Signed out of the app already; the provider's session was left as it was.
}
```

`signOut(using:)` signs the account out of the app first: `onLeave` runs, its tokens are revoked at the provider (RFC 7009) and removed from the Keychain, and it stays listed as `.signedOut`. If it was the active account, the most recently added signed-in account becomes active. Then it opens the provider's logout page in the browser (RP-Initiated Logout), naming that account's ID token so the provider ends that session only, and checks the `state` it returns with.

- Pass a key to sign out another account: `accounts.signOut(key, using: authenticator)`.
- `accounts.signOutAll(using: authenticator)` signs every account out, with one logout request that names nobody, so the provider asks which sessions to end.
- The browser step needs `PostLogoutRedirectURI`, so that the window closes when the provider is done. Without one (or without an `end_session_endpoint`), `signOut(using:)` signs out locally and opens no browser window.
- To sign out of the app only and leave the provider's session: `accounts.signOut(endSession: false)`.

With `TokenManager`, do the same steps yourself:

```swift
let tokenSet = try await tokens.getTokenSet("user")
let logout = try await client.createEndSessionRequest(idTokenHint: tokenSet.idToken)
try await tokens.delete("user", revoke: true)
try await client.endSession(using: authenticator, request: logout)
```

## 11. Errors

Every error the library throws is an `OIDCError`. Match on `kind` and `code`, not on the message.

| `kind` | When | Examples of `code` |
|---|---|---|
| `.oauth` | The provider answered with an OAuth error. `oauthErrorDescription` and `errorURI` hold the rest. | `login_required`, `consent_required`, `account_selection_required`, `invalid_grant`, `invalid_scope` |
| `.validation` | A response, token or provider setting failed a check. | `state_missing`, `state_mismatch`, `state_reused`, `transaction_expired`, `issuer_mismatch`, `nonce_mismatch`, `invalid_id_token`, `acr_mismatch`, `account_mismatch`, `front_channel_token`, `insecure_endpoint`, `insecure_redirect_uri`, `pkce_not_supported`, `public_client_not_supported`, `dpop_downgrade` |
| `.setValidation` | A security event was refused. Reported to `onError`. | `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience` |
| `.ssf` | The transmitter can't be used as configured, or a stream call failed. | `insecure_endpoint`, `untrusted_endpoint`, `verification_timeout`, `handler_failed`, `http_error` |
| `.general` | Everything else. | `user_cancelled`, `web_authentication_failed`, `network_error`, `http_error`, `keychain_error`, `secure_enclave_unavailable`, `no_tokens`, `not_active`, `too_many_accounts`, `invalid_argument` |

Two helpers:

- **`error.isUserCancellation`** is true when the person closed the browser window (`user_cancelled`). Treat it as "never mind", not as a failure.
- **`needsInteraction(error)`** is true when only a visible sign-in can fix the problem: `login_required`, `interaction_required`, `consent_required` or `account_selection_required`. When it is true, sign the person in with a screen rather than retrying silently.

An error from a `resume` or `reauthenticate` carries the account it was for in `error.account`, and the request's `context` in `error.context`. `status` and `response` hold the HTTP status and body when there was one.

## 12. Sandboxed and signed apps

**App Sandbox.** A sandboxed app needs the outgoing network entitlement to reach the provider and the transmitter. Without it, every request fails with `network_error`.

```xml
<key>com.apple.security.app-sandbox</key>
<true/>
<key>com.apple.security.network.client</key>
<true/>
```

`ASWebAuthenticationSession` needs no entitlement, and the private-use scheme needs no `CFBundleURLTypes` entry.

**Keychain.**

- **The login keychain** (the default) needs no entitlement. Its items are tied to the code signature of the app that created them. An app signed with a stable identity (Apple Development, Developer ID) reads them without a prompt across updates. An ad-hoc-signed build has a new signature each time it is built, so macOS may ask whether the new build may use the items.
- **The data protection keychain** (`useDataProtectionKeychain: true`) needs an app signed with a team identity and a `keychain-access-groups` entitlement. Without them the Keychain answers `errSecMissingEntitlement`, which the library reports as `keychain_error`. Pass `accessGroup:` to share the items with other apps of the same team.

```xml
<key>keychain-access-groups</key>
<array>
	<string>$(AppIdentifierPrefix)com.example.myapp</string>
</array>
```

**Secure Enclave.** Creating a Secure Enclave key can fail for an unsigned or ad-hoc-signed build. `preferredDPoPKeyStore()` then falls back to `KeychainKeyStore`, so the app still works; `client.securityFeatures.dpop?.extractable` tells you which you got. Sign the app to get the non-extractable key.

**Hardened runtime** needs no exception for this library.

## 13. Security checklist

- [ ] The client is public. The app holds no secret.
- [ ] The redirect URI is a private-use scheme in reverse-domain form that you control, registered exactly at the provider.
- [ ] Sign-in happens in the system browser (`SystemWebAuthenticator`), never in a `WKWebView`.
- [ ] DPoP is on, and `makeClient` is given a persistent key store, the Secure Enclave where available.
- [ ] Tokens are in the Keychain under your app's own service name.
- [ ] The app asks for only the scopes it uses. `ssf.manage` is only for apps that manage their own stream.
- [ ] The receiver catches up (`start(catchUp: true)`) in `onActivate`, before a restored account is used.
- [ ] CAEP handlers check `subjectMatches()` before acting, and fail safe.
- [ ] Signing out revokes tokens, deletes or stops the stream, and clears any stored events.
- [ ] A sandboxed app has `com.apple.security.network.client` and nothing broader.

## 14. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `invalid_argument`: "No OIDCConfiguration.plist in …" | The plist isn't in the app's bundle. In Xcode, tick the app target for it; in a Swift package, list it in `resources` and call `load(bundle: .module)`. |
| `invalid_argument`: "MetadataURL must be the provider's metadata URL" | `MetadataURL` is the issuer. Use the full `…/.well-known/openid-configuration` URL. |
| `issuer_mismatch` at `makeClient` | The metadata's `issuer` isn't the one its URL was built from. Check the provider's configured issuer. |
| `network_error` on discovery, token or SSF calls | The Mac doesn't trust the provider's certificate, the provider isn't reachable, or a sandboxed app lacks `com.apple.security.network.client`. |
| `insecure_endpoint` / `insecure_redirect_uri` | An endpoint isn't `https`, or the redirect URI's scheme has no period (`myapp:/callback`). Use `com.example.myapp:/callback`. Only loopback may use `http`. |
| `invalid_argument`: "ASWebAuthenticationSession cannot receive a loopback http redirect" | The redirect URI is `http://127.0.0.1…`. Use a private-use scheme with `SystemWebAuthenticator`. |
| The provider shows "invalid redirect_uri" in the browser | The URI in the plist isn't registered exactly as written at the provider. |
| `web_authentication_failed` | The browser session couldn't start (for example, no window to present it over) or ended without a redirect. |
| `public_client_not_supported` / `pkce_not_supported` | The provider's metadata doesn't list `none` in `token_endpoint_auth_methods_supported`, or `S256` in `code_challenge_methods_supported`. |
| `dpop_not_supported` | The provider accepts no DPoP algorithm the key store creates. The Secure Enclave creates ES256 only; use `KeychainKeyStore` for ES384 or ES512. |
| Every account is signed out after a relaunch | `makeClient` was given no key store, so the DPoP key was in memory and the cached tokens can't be refreshed; or the token store is `MemoryTokenStore`. |
| macOS asks for the keychain password, or to allow access, at launch | The build's signature changed (ad-hoc signing), so the login keychain asks before giving the new build the items. Choose **Always Allow**, or sign with a stable identity. |
| `keychain_error` | With `useDataProtectionKeychain`, the app lacks the `keychain-access-groups` entitlement or a team signature. |
| `state_mismatch` or `transaction_expired` | The sign-in was started in an earlier launch, or took longer than 10 minutes. Start again. |
| `invalid_scope`, or a scope missing from the token | The client isn't allowed that scope, or (iya-sts) the person or application lacks the role. iya-sts logs `STS-ADMIN-0821` saying which condition failed. |
| The SSF calls answer 401 or 403 | The access token lacks `ssf.read` / `ssf.manage`, or the stream belongs to somebody else. |
| `untrusted_endpoint` | The stream's poll URL isn't at the transmitter's origin. Add its origin to `trustedPollOrigins` if it is legitimately elsewhere. |
| No events arrive | The stream doesn't ask for that type (`stream["events_delivered"]`), has no subject, or isn't polling (`onError` with phase `.poll`). |
| `account_mismatch` | A request that named an account came back signed in as somebody else. The tokens were revoked; ask the person to sign in as the named account. |

To check a setup end to end, run the demo against your provider ([Running the demo](../docs/demo.md)), and send test events from the provider's admin console or API.
