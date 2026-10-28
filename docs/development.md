---
title: Development
---

# Development

## Tests

On macOS, from the repository root:

```sh
swift test
```

On Linux, or anywhere with Docker:

```sh
docker run --rm -v "$PWD":/pkg -w /pkg swift:6.1-noble swift test
```

The 45 XCTest tests in `Tests/OIDCCAEPClientTests` run against a strict in-memory OpenID Provider and SSF transmitter (`StubOP.swift`), injected as the library's `HTTPTransport`. The stub enforces public clients, PKCE, PAR and DPoP (proof signature, `htm`/`htu`/`ath`, key binding and nonces). The suite covers:

- discovery from a metadata URL, the plist configuration, and the setup checks (S256, public clients, TLS, redirect URIs);
- state, the front channel, RFC 9207, OAuth errors and reserved parameters;
- ID token validation (EC and RSA keys, `alg`, `typ`, `acr`, `expectedSub`), refresh (OIDC Core §12.2) and UserInfo;
- DPoP (downgrades, nonces), PAR, logout state and dynamic registration;
- the token cache: merged refreshes, background refresh, `invalid_grant`, revocation on delete;
- several accounts: sign-in, switching, `resume`, sign-out, `end`, subject matching, restoring from a persistent store, `too_many_accounts`;
- the SSF receiver: one handler per event, acknowledgement, redelivery after a throwing handler, invalid and replayed SETs, verification, subjects, and the poll endpoint's origin.

The Linux run covers everything but the Apple-only parts (`KeychainTokenStore`, `KeychainKeyStore`, `SecureEnclaveKeyStore`, `SystemWebAuthenticator`), which are compiled only where `Security`, CryptoKit and `AuthenticationServices` exist.

The demo is built separately:

```sh
cd Demo && swift build
```

## API reference (DocC)

The site's [DocC reference](https://rcbj.github.io/swift-oidc-caep-native-app/api/documentation/oidccaepclient/) is generated from the source's documentation comments and the catalog in `Sources/OIDCCAEPClient/OIDCCAEPClient.docc`. It needs macOS, so that the Apple-only symbols are included. To build it locally:

```sh
xcodebuild docbuild -scheme OIDCCAEPClient -destination 'generic/platform=macOS' -derivedDataPath .build/docc
open "$(find .build/docc -name OIDCCAEPClient.doccarchive -type d | head -n 1)"   # opens in Xcode
```

## Continuous integration

| Workflow | Runs on | Does |
|---|---|---|
| [`tests.yml`](https://github.com/rcbj/swift-oidc-caep-native-app/blob/main/.github/workflows/tests.yml) | every push to `main` and `develop`, and pull requests | `swift test` on Linux (Swift 6.1 container); on macOS `swift test`, a release build of the library, and the demo app bundle (`Demo/scripts/build-app.sh`) |
| [`pages.yml`](https://github.com/rcbj/swift-oidc-caep-native-app/blob/main/.github/workflows/pages.yml) | pushes to `main` that change the docs or the library's source, and on demand | builds this site, generates the DocC reference on a macOS runner, and deploys both to GitHub Pages |

GitHub Pages for a private repository needs a paid GitHub plan. Before the first run, Pages must be set to build from GitHub Actions; the workflow's header says how.

## Branches

- **`develop`** is where work comes together. Create every feature or fix branch from it, and merge back into it.
- **`main`** is what is released. It receives `develop` when a release is cut, and its pushes publish this site.

```sh
git switch develop && git pull
git switch -c feature/<short-name>    # or fix/<short-name>
# commit, push, and open a pull request into develop
```

A release is a semantic-version tag on `main` (`0.1.0`, `0.1.1`, …). Swift Package Manager resolves `from: "0.1.0"` against those tags.

## Layout of the repository

```
Package.swift                     the library only: product OIDCCAEPClient
Sources/OIDCCAEPClient/
  Core/                           OIDCError, HTTP transport, JSONValue, EventHub, OIDCLog
  JOSE/                           JWS signing and verification, JWKS
  OIDC/                           OIDCClient, discovery, DPoP, registration,
                                  OIDCAppConfiguration (the plist), WebAuthenticator
  Tokens/                         TokenSet, token and transaction stores, TokenManager, AccountManager
  CAEP/                           SSFReceiver, CAEP/SSF/RISC constants, subjects
  Platform/                       Apple only: Keychain stores, Secure Enclave, SystemWebAuthenticator
  OIDCCAEPClient.docc/            the DocC catalog's landing page
Tests/OIDCCAEPClientTests/        XCTest suite and the in-memory OP and SSF transmitter
Demo/                             the SwiftUI demo, a package of its own (depends on .. by path)
  Sources/CAEPDemo/Resources/     OIDCConfiguration.plist
  scripts/build-app.sh            builds Demo/build/CAEPDemo.app
Documentation/
  native-app-guide.md             the integration guide
  reference.md                    the API reference
docs/                             this site's frame and pages (Jekyll)
scripts/register-iya-sts-client.mjs   registers the demo's client on iya-sts
.github/workflows/tests.yml       tests on Linux and macOS, builds the demo
.github/workflows/pages.yml       builds and deploys this site
```

The guide and the reference are written once, in `Documentation/`, and read the same in the repository and on this site: the Pages workflow copies them in and rewrites the few links that point outside the site.
