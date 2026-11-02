# swift-oidc-caep-native-app

An OpenID Connect client for native macOS applications, and a CAEP receiver. The Swift package product is `OIDCCAEPClient`. The client is public: Authorization Code with PKCE in the system browser, PAR, and DPoP. It is the native counterpart of [oidc-caep-client](https://github.com/rcbj/oidc-caep-client). It is related to the Node, JavaScript, and TypeScript client libraries and is not one of them.

macOS 13 or later (`Package.swift` declares `.macOS(.v13)`). Swift tools 5.9. The Linux tests run in the `swift:6.1-noble` image. There is no npm package.

Documentation: <https://rcbj.github.io/swift-oidc-caep-native-app/>. The license is the MIT License in `LICENSE`. `Package.swift` carries `SPDX-License-Identifier: MIT`. The Business Source License used by iya-sts does not apply here.

## Layout

| Path | What it is |
|---|---|
| `Package.swift` | This package only. Product `OIDCCAEPClient`. Depends on apple/swift-crypto `3.8.0` ..< `5.0.0`. |
| `Sources/OIDCCAEPClient` | The library. `Core/` (errors, HTTP, JSON), `JOSE/`, `OIDC/` (client, discovery, DPoP, the plist configuration, `WebAuthenticator`), `Tokens/` (`TokenSet`, stores, `TokenManager`, `AccountManager`), `CAEP/`, `Platform/` (Keychain and the system browser, compiled where Apple frameworks exist). |
| `Sources/OIDCCAEPClient/OIDCCAEPClient.docc` | The DocC catalog. |
| `Tests/OIDCCAEPClientTests` | XCTest against `StubOP`, an in-memory provider and SSF transmitter. |
| `Demo` | A second package. SwiftUI on macOS, GTK 4 on Linux. `swift run CAEPDemo`. |
| `install` | The Linux AppImage (`install/appimage.sh`, or `install/appimage-docker.sh` without Swift installed). |
| `scripts/register-iya-sts-client.mjs` | Registers the public client on iya-sts. The Node `redirects.mjs` port recipe from the other libraries does not apply here. |
| `Documentation` | The integration guide and the API reference. |
| `docs` | The GitHub Pages site. |

## Usage

In `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/rcbj/swift-oidc-caep-native-app.git", from: "0.1.0"),
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "OIDCCAEPClient", package: "swift-oidc-caep-native-app"),
    ]),
]
```

```swift
import OIDCCAEPClient

let config = try OIDCAppConfiguration.load()
let client = try await config.makeClient(dpopKeyStore: await preferredDPoPKeyStore())
let accounts = try await AccountManager(client: client).restore()
try await accounts.signIn(using: SystemWebAuthenticator())
let tokens = try await accounts.getTokenSet()
```

Settings live in `OIDCConfiguration.plist`: the provider metadata URL, `client_id`, scopes, and the redirect URI. Swift Package Manager resolves `from: "0.1.0"` against version tags on `main`.

## Tests

On macOS, from the repository root:

```sh
swift test
```

On Linux:

```sh
docker run --rm -v "$PWD":/pkg -w /pkg swift:6.1-noble swift test
```

The Linux run covers the suite except the Apple-only types (`KeychainTokenStore`, `KeychainKeyStore`, `SecureEnclaveKeyStore`, `SystemWebAuthenticator`), which compile only where Security, CryptoKit, and AuthenticationServices exist. The demo is a separate build: `cd Demo && swift build`.

`.github/workflows/tests.yml` runs `swift test` in the Swift 6.1 container and, on macOS, `swift test` plus a release build of the library and `Demo/scripts/build-app.sh`. `appimage.yml` builds the Linux AppImage.

## Demo

```sh
node scripts/register-iya-sts-client.mjs
cd Demo && swift run CAEPDemo
```

The register script needs `ADMIN_API_CLIENT_SECRET` and runs once. The demo's settings are `Demo/Sources/CAEPDemo/Resources/OIDCConfiguration.plist`. On a Linux desktop, `install/appimage-docker.sh` writes `dist/CAEP_Demo-0.1.0-x86_64.AppImage`.

## Releases

A release is a semantic-version tag on `main` and a GitHub Release. `publish.yml` creates both after the Tests workflow succeeds on `main` for a commit that came from a merged pull request; a direct push does not release. `VERSION` holds M.N and the tag is M.N.0, as `install/appimage.sh` and `Demo/scripts/build-app.sh` already assume. A tag that already exists stays; the next release is a new minor number in `VERSION`. The Swift Package Index lists the package from those tags and builds the DocC documentation as `.spi.yml` says. Nothing is uploaded to a registry, and the demo (`Demo/`) is not part of the published product. This repository does not publish to npm. `pages.yml` deploys the site and the DocC archive from `main`. DocC needs macOS so the Apple-only symbols are included.

## Changes

Branch from `develop`. Open a pull request into `develop` and merge it there. The default branch is `main`, so a closing keyword on that pull request does not close the issue. Close the issue in a comment that names the `develop` commit. Then merge `develop` into `main`, and fast-forward `develop` to that same commit so both branches name one hash.
