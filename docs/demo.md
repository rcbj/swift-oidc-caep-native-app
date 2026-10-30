---
title: Running the demo
---

# Running the demo

The demo, `CAEPDemo`, is a macOS SwiftUI app built on `OIDCCAEPClient`. It is the native counterpart of [oidc-caep-client's demo](https://rcbj.github.io/oidc-caep-client/demo.html), with the same screens and the same reactions to CAEP events.

It lives in [`Demo/`](https://github.com/rcbj/swift-oidc-caep-native-app/tree/main/Demo), a Swift package of its own. It depends on the library by path (`..`), the same way your app depends on it by URL, so the library and the demo stay separate: the library's `Package.swift` doesn't mention the demo. It needs macOS 14 or later.

## Start it

From the repository root:

```sh
cd Demo && swift run CAEPDemo
```

Or build an app bundle and open it:

```sh
Demo/scripts/build-app.sh
open Demo/build/CAEPDemo.app
```

`build-app.sh` builds the demo and wraps it in `Demo/build/CAEPDemo.app`, signed ad hoc. An app bundle behaves more like a shipped app than `swift run` does: it has a bundle identifier and a code signature, which the Keychain ties its items to. Because an ad-hoc signature changes with every build, macOS may ask whether a new build may use the items the previous one stored; choose **Always Allow**.

The app reads [`Demo/Sources/CAEPDemo/Resources/OIDCConfiguration.plist`](https://github.com/rcbj/swift-oidc-caep-native-app/blob/main/Demo/Sources/CAEPDemo/Resources/OIDCConfiguration.plist):

| Key | Value |
|---|---|
| `MetadataURL` | `https://localhost:8081/.well-known/openid-configuration` |
| `ClientID` | `oidc-caep-native-demo` |
| `Scopes` | `openid profile email offline_access ssf.read ssf.manage` |
| `RedirectURI` | `net.rcbj.caepdemo:/callback` |
| `PostLogoutRedirectURI` | `net.rcbj.caepdemo:/logged-out` |

Edit it to point at another provider; [Building a native macOS app](native-app-guide.md#4-create-oidcconfigurationplist) lists every key. The Mac must trust the provider's TLS certificate, since both the app and the browser connect to it. For iya-sts's development certificate on `localhost:8081`, add it to the login keychain in Keychain Access and set it to **Always Trust**, or issue one from a local CA such as mkcert.

## Register the client on iya-sts

The default plist points at iya-sts on `https://localhost:8081`, client `oidc-caep-native-demo`. Register it in the default realm, from the repository root:

```sh
ADMIN_API_CLIENT_SECRET=… node scripts/register-iya-sts-client.mjs
```

[`scripts/register-iya-sts-client.mjs`](https://github.com/rcbj/swift-oidc-caep-native-app/blob/main/scripts/register-iya-sts-client.mjs) needs Node.js and nothing installed. It reads the plist, gets a management API token as `sts-api-client` (the client iya-sts seeds for its management API), and:

- creates the public client (`token_endpoint_auth_method: none`) with the plist's redirect URI and post-logout redirect URI, and the plist's scopes. A native app needs no CORS origin;
- adds the client to `SSF_READ` and `SSF_MANAGE`, for whichever of `ssf.read` and `ssf.manage` the plist asks for (iya-sts issues each only when the application is a member of the role and the person is in its group, `ssf-read` or `ssf-manage`);
- creates a test user, `caep-demo-user`, in those groups. Its password is `CAEP_DEMO_USER_PASSWORD`, or one is generated and printed once.

| Option | Use |
|---|---|
| `--config path` | Another `OIDCConfiguration.plist`, such as your own app's. |
| `--test-user name`, `--no-test-user` | Name the test user, or skip it. |

The secret is `ADMIN_API_CLIENT_SECRET` or `STS_ADMIN_API_CLIENT_SECRET`. Every step can be repeated safely.

## What it does

- **Sign-in** happens in the system browser through `ASWebAuthenticationSession` (RFC 8252), never in an embedded web view. The browser's session is shared, so a second sign-in can use the provider's account picker.
- **DPoP** binds tokens to a key in the Secure Enclave when the Mac has one, and otherwise to a key kept in the Keychain.
- **PAR** is used whenever the provider offers it.
- **Tokens** for every signed-in account are cached in the Keychain, so they survive a relaunch.
- **CAEP:** the stream is created with the person's access token (with a DPoP proof) and polled from the app. With `ssf.manage`, the person is added as the stream's subject, and the stream asks for the event types picked on the **CAEP events** tab.

The window has a top bar and two tabs.

**The top bar** shows the active account. Its menu switches to another signed-in account, signs in with another account, signs out, and signs out of all accounts.

**Identity:**

- **Sign in**, when nobody is signed in.
- **Protections in effect:** PKCE, `state`, `nonce`, issuer identification, PAR, the DPoP algorithm, key thumbprint and whether the key is in the Secure Enclave, resource indicators, TLS and the ID token checks (`client.securityFeatures`).
- **Session claims:** the validated ID token's claims for the active account.
- **Token cache:** the cached token set, with a meter showing the time left before the access token expires, and **Call UserInfo** and **Force refresh**.
- **Tokens:** the tokens issued at sign-in beside the current ones, decoded.

**CAEP events:**

- **The stream:** the transmitter, the `stream_id` and the stream's status.
- **Event types:** a picker of the CAEP event types, and **Update subscription**, which applies them to the stream (`updateStream`).
- **Request verification** asks the transmitter for a verification event; **Reconnect** restarts the receiver.
- **The event log:** each event received for the active account, with the action taken.

It reacts to events about the signed-in person:

| Event | Action |
|---|---|
| session-revoked | Ends the account and discards its tokens. |
| token-claims-change | Refreshes the tokens. |
| credential-change | Revoked or deleted: ends the account. Otherwise tells the person. |
| assurance-level-change | Decrease: asks for step-up (re-authentication). |
| device-compliance-change | Not compliant: ends the account. |
| risk-level-change | HIGH: ends the account. MEDIUM: asks for step-up. |
| session-established, session-presented | Logged only. |

## Several accounts

iya-sts can keep several people signed in to one browser (`authn.multipleAccounts`). The app has **one active account**: only its tokens are used and refreshed, and only its stream is polled. The others are dormant.

- **Switching** (the account menu) needs no password. The account's stream first catches up on the events queued while it was dormant.
- **A signed-out or ended account** in the menu starts a sign-in that names it (`login_hint`) and refuses anybody else.
- **Sign in with another account** is a fresh sign-in (`prompt=login`).
- **The event log** shows the active account's events only, and is cleared for an account when it signs out.
- **An event that ends a session** ends that account only. A `session-revoked` naming another of the person's sessions is ignored.
- **Sign out** revokes that account's tokens, ends its session at the provider in the browser, and keeps the other accounts. **Sign out of all** ends them all.
- **Quitting the app** keeps every account: the cache is in the Keychain, and the active account is reactivated at the next launch.
