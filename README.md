# swift-oidc-caep-native-app

An OpenID Connect client library for **native macOS apps** written in Swift, and a demo app built on it. It is the native counterpart of [oidc-caep-client](https://github.com/rcbj/oidc-caep-client) (the browser library): the same use case and protections, for an app instead of a single-page app. The client runs in the app as a **public client** (Authorization Code + PKCE in the system browser, PAR, DPoP) and receives **CAEP** security events through the Shared Signals Framework.

**Documentation:** <https://rcbj.github.io/swift-oidc-caep-native-app/>

| Path | |
|---|---|
| [`Sources/OIDCCAEPClient`](Sources/OIDCCAEPClient) | The library: the `OIDCCAEPClient` product of this Swift package. |
| [`Demo`](Demo) | The demo app, a package of its own that depends on the library as any app would: SwiftUI on macOS, GTK 4 on Linux. |
| [`install`](install) | The Linux AppImage build (`install/appimage.sh`, or `install/appimage-docker.sh` without Swift installed). |
| [`Documentation`](Documentation) | The integration guide and the API reference. |

## Install

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

In Xcode: **File → Add Package Dependencies…**, enter the repository URL, and add `OIDCCAEPClient` to the app target. macOS 13 or later.

Put the app's settings in `OIDCConfiguration.plist` (the provider's metadata URL, the `client_id`, the scopes and the redirect URI), then:

```swift
import OIDCCAEPClient

let config = try OIDCAppConfiguration.load()                       // OIDCConfiguration.plist
let client = try await config.makeClient(dpopKeyStore: await preferredDPoPKeyStore())
let accounts = try await AccountManager(client: client).restore()  // tokens cached in the Keychain
try await accounts.signIn(using: SystemWebAuthenticator())         // the system browser (RFC 8252)
let tokens = try await accounts.getTokenSet()                      // refreshed when due
```

See [Building a native macOS app](Documentation/native-app-guide.md) for the walkthrough and the [API reference](Documentation/reference.md) for every option.

## Run the demo

```sh
node scripts/register-iya-sts-client.mjs   # once: register the client on iya-sts (needs ADMIN_API_CLIENT_SECRET)
cd Demo && swift run CAEPDemo               # or: Demo/scripts/build-app.sh && open Demo/build/CAEPDemo.app
```

The demo's settings are in [`Demo/Sources/CAEPDemo/Resources/OIDCConfiguration.plist`](Demo/Sources/CAEPDemo/Resources/OIDCConfiguration.plist). See [Running the demo](docs/demo.md).

On a Linux desktop (GNOME, KDE):

```sh
install/appimage-docker.sh                 # builds dist/CAEP_Demo-0.1.0-x86_64.AppImage in Docker
./dist/CAEP_Demo-0.1.0-x86_64.AppImage
```

[Linux and macOS](docs/linux.md) lists every difference between the two, including TLS trust settings for a provider with a private CA (`TrustedCertificates`, `InsecureSkipTLSVerification`).

## Develop

```sh
swift test                                                                    # macOS
docker run --rm -v "$PWD":/pkg -w /pkg swift:6.1-noble swift test             # Linux
```

Branch from `develop`. See [Development](docs/development.md).

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
