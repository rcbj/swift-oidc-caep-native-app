---
title: Linux and macOS
---

# Linux and macOS

The library and the demo run on **macOS** and on **Linux desktops** (GNOME, KDE). Both versions do the same protocol work with the same checks. They differ in what each platform provides:

- how the browser returns to the app;
- where tokens and the DPoP key are kept;
- how TLS trust is configured;
- what the user interface is built with.

This page lists every difference, for the library and for the demo app.

## At a glance

| | macOS | Linux (GNOME, KDE) |
|---|---|---|
| **Sign-in window** | `SystemWebAuthenticator`: `ASWebAuthenticationSession`, a sheet over the app using the default browser's session | `LoopbackWebAuthenticator`: the default browser, opened with `xdg-open`, in its own window or tab |
| **Redirect URI** | Private-use scheme: `net.rcbj.caepdemo:/callback` (RFC 8252 §7.1) | Loopback: `http://127.0.0.1:53682/callback` (RFC 8252 §7.3) |
| **Post-logout redirect URI** | `net.rcbj.caepdemo:/logged-out` | `http://127.0.0.1:53682/logged-out` |
| **Token cache** | Keychain (`KeychainTokenStore`): encrypted at rest, kept across launches | Memory (`MemoryTokenStore`): cleared when the app quits |
| **DPoP key** | Secure Enclave (`SecureEnclaveKeyStore`, non-extractable) when the Mac has one, else Keychain (`KeychainKeyStore`) | Memory (`MemoryKeyStore`): a new key every launch |
| **After a restart** | Every account is still signed in | Accounts must sign in again |
| **HTTP** | `URLSession` | `URLSession`. With `TrustedCertificates` or `InsecureSkipTLSVerification` set, the system's `curl` |
| **Extra trusted CAs** (`TrustedCertificates`) | Added as anchors to the URLSession trust evaluation | Written to a private CA bundle passed to `curl --cacert` |
| **Demo user interface** | SwiftUI | GTK 4, through [SwiftCrossUI](https://github.com/stackotter/swift-cross-ui) 0.9.0 |
| **Demo configuration file** | `OIDCConfiguration.plist` | `OIDCConfiguration-Linux.plist`, or `~/.config/caep-demo/OIDCConfiguration.plist` |
| **Demo package** | `Demo/scripts/build-app.sh` → `CAEPDemo.app` (ad-hoc signed) | `install/appimage.sh` → `CAEP_Demo-<version>-x86_64.AppImage` |
| **Minimum OS** | macOS 13 for the library; macOS 14 for the demo | glibc 2.35 and GTK 4.6 (Ubuntu 22.04 or newer) |

Everything else is the same code on both platforms:

- discovery and metadata validation;
- PKCE, `state` and `nonce`;
- PAR and DPoP proofs;
- RFC 9207 issuer checks;
- ID token validation;
- refresh and revocation;
- several accounts with one active account;
- the SSF receiver and every CAEP handler;
- the demo's event policies.

The library's 51 tests run on Linux in CI and on macOS.

## Signing in

**macOS.** `ASWebAuthenticationSession` opens the provider's page in a sheet tied to the app's window. It uses the default browser's cookies, so single sign-on and several accounts work. The session ends when the browser is sent to the private-use scheme, which macOS hands back to the app; no app registration is needed. Closing the sheet throws an error whose `isUserCancellation` is true.

**Linux.** There is no `ASWebAuthenticationSession`. `LoopbackWebAuthenticator` does what RFC 8252 §7.3 describes:

1. It starts listening on `127.0.0.1` at the redirect URI's port, before the browser opens.
2. It opens the authorization URL with `xdg-open`, in the browser GNOME or KDE has as default.
3. It waits for the browser's request to the redirect path, answers with a short page ("Signed in. You can close this window…"), and stops listening.

On Linux:

- **The tab stays open.** The browser tab is not closed for you.
- **Other paths get a 404.** Requests to any other path on that port, such as a favicon, are answered with `404` and ignored.
- **It times out.** The listener gives up after 5 minutes (`timeout`).
- **Cancelling the task stops the listener.** There is no cancel button: close the tab and the sign-in times out.

Inside an AppImage, the browser is started with the system's `LD_LIBRARY_PATH`, not the image's.

The provider must allow the loopback redirect URI. iya-sts accepts loopback URIs on any port (RFC 8252 §7.3). Register `http://127.0.0.1:53682/callback` and `http://127.0.0.1:53682/logged-out` for the demo's client; [the registration script](demo.md#register-the-client-on-iya-sts) does it with `--config Demo/Sources/CAEPDemo/Resources/OIDCConfiguration-Linux.plist`. Use `127.0.0.1`, not `localhost`: the listener binds IPv4, and a browser may try `::1` for `localhost` first.

A loopback redirect is weaker than a private-use scheme in one way: while the sign-in is in progress, another program running as the same user could listen on the port first. PKCE keeps a code it captures useless to it, and `state` keeps a forged response out.

## Where tokens and keys are kept

The library's rule is the same on both platforms: **cache tokens in the platform's secure storage when there is one, otherwise in memory.**

- **macOS** has the Keychain. `defaultTokenStore()` returns a `KeychainTokenStore`. The DPoP key goes to the Secure Enclave when the Mac has one (`preferredDPoPKeyStore()`), so a stolen refresh token can't be used on any other machine.
- **Linux** has no store this library uses. The GNOME Keyring and KWallet Secret Service, and TPM-backed keys, are not supported yet. So `defaultTokenStore()` returns a `MemoryTokenStore`, and `makeClient()` keeps the DPoP key in a `MemoryKeyStore`. Nothing is written to disk. Quitting the app ends every account's session in the app; the provider's session in the browser remains, so signing in again may need no password.

To keep tokens on Linux anyway, pass a `TokenStore` of your own to `AccountManagerOptions(store:)`. Pair it with DPoP. Without DPoP, `AccountManager` logs a warning for any persistent store.

## TLS trust

Both platforms verify the provider's and the transmitter's certificates. The demo's default provider, a local iya-sts, uses certificates from its own private CA, which neither platform trusts. Two settings in the configuration file handle that:

| Key | Type | Default | |
|---|---|---|---|
| `TrustedCertificates` | array of strings | — | PEM or DER files, or inline PEM text. Each may hold a trust anchor (a root) or a whole chain (leaf, intermediates, root); every certificate counts as an anchor. Relative paths are resolved against the configuration file's folder; `~` is allowed. |
| `TrustSystemRoots` | bool | `true` | Whether the system's trusted roots still count beside `TrustedCertificates`. With `false`, only the listed certificates are trusted. |
| `InsecureSkipTLSVerification` | bool | `false` | Accept **any** certificate. For a local test provider only: anybody who can intercept the connection can then impersonate the provider, its signing keys and its CAEP signals. The library logs a warning when it is on. |

The host name is always checked, except with `InsecureSkipTLSVerification`.

- **macOS:** the certificates are added as anchors to the URLSession server-trust evaluation (`SecTrustSetAnchorCertificates`). `TrustSystemRoots` false sets `SecTrustSetAnchorCertificatesOnly`.
- **Linux:** URLSession there can neither take extra CAs nor skip verification. With either setting, requests are made with the system's `curl`, given a private CA bundle (`--cacert`) or `--insecure`.
  - The bundle holds the system roots, when allowed, and your certificates.
  - It is written to the temporary folder, readable by your user only.
  - Request headers, which carry tokens, are passed through a private file, never on the command line, so other users can't read them in the process list.

In code, the same settings are `TLSTrust` and `URLSessionTransport(trust:)` or `URLSessionTransport(insecureSkipTLSVerification:)`. `OIDCAppConfiguration.makeTransport()` returns the transport the file asks for. Pass that one transport to the client and to every `SSFReceiverConfiguration`.

To trust a local iya-sts, save the root CA it sends with its chain:

```sh
echo | openssl s_client -connect localhost:8081 -showcerts 2>/dev/null \
  | awk '/-----BEGIN CERTIFICATE-----/{n++} n==4' | sed '/-----END CERTIFICATE-----/q' \
  > ~/.config/caep-demo/sts-root.pem
openssl x509 -in ~/.config/caep-demo/sts-root.pem -noout -subject   # subject=CN = sts Root CA, O = sts
```

Then list it under `TrustedCertificates`. The browser has its own trust store, so it must trust the same certificate for the sign-in page.

## The demo's user interface

The demo has one model (`Demo/Sources/CAEPDemo/DemoModel.swift`) shared by both front ends:

- the accounts;
- the CAEP stream of the active account;
- the event policies;
- the event log.

The front ends show the same layout:

- a top bar with the account menu;
- banners;
- the **Identity** tab: sign-in, protections in effect, session, token cache, tokens;
- the **CAEP events** tab: stream, event-type picker, verification, reconnect, event log.

Differences in the Linux (GTK) front end:

| | macOS (SwiftUI) | Linux (GTK via SwiftCrossUI) |
|---|---|---|
| Tabs | A tab view | Two toggle buttons above the content |
| Cards | Group boxes | Headed sections separated by rules |
| Token and payload details | Collapsible sections | Shown in full, selectable |
| Event-type picker | A grid of checkboxes | A column of checkboxes |
| Redraw | Swift Observation, as the model changes | Once a second and after every action (SwiftCrossUI does not follow Swift Observation) |
| Rendering | Core Animation | GTK's Cairo renderer in the AppImage (`GSK_RENDERER=cairo`); set `GSK_RENDERER=gl` to use the GPU |
| `--version` | — | Prints the version and exits without a window |

## Running the Linux demo

### From the AppImage

```sh
install/appimage-docker.sh                  # no Swift needed: builds in the Swift 6.1 Ubuntu 22.04 image
./dist/CAEP_Demo-0.1.0-x86_64.AppImage
```

`install/appimage.sh` builds the image directly where Swift 6.1 and `libgtk-4-dev` are installed; the AppImage workflow runs it on every push and uploads the result as the `caep-demo-x86_64` artifact.

- **What it contains:** the demo and every library it needs besides the system C library and the host OpenGL loader. The Swift runtime is linked in statically.
- **Where it runs:** it uses the glibc of the machine that built it, so the CI copy runs on Ubuntu 22.04 and newer.
- **Without FUSE:** run it with `APPIMAGE_EXTRACT_AND_RUN=1`.

### From source

```sh
sudo apt install libgtk-4-dev            # and Swift 6.1 from swift.org
cd Demo && swift run CAEPDemo
```

### Configuration

The configuration is the first of:

1. `OIDC_CONFIG=/path/to/file.plist`;
2. `~/.config/caep-demo/OIDCConfiguration.plist`;
3. the built-in `OIDCConfiguration-Linux.plist`.

To point the demo at another provider, or add `TrustedCertificates`, copy the built-in file to the second location and edit it.
