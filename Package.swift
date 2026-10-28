// swift-tools-version:5.9
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The reusable library only. The sample app is a package of its own (Demo/), which depends on this one
// by path exactly as another app would depend on it by URL.
import PackageDescription

let package = Package(
    name: "swift-oidc-caep-native-app",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "OIDCCAEPClient", targets: ["OIDCCAEPClient"]),
    ],
    dependencies: [
        // Apple's swift-crypto: CryptoKit's API on every platform (it re-exports CryptoKit on Apple
        // platforms), plus _CryptoExtras for RSA signature verification.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.8.0"..<"5.0.0"),
    ],
    targets: [
        .target(
            name: "OIDCCAEPClient",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "OIDCCAEPClientTests",
            dependencies: [
                "OIDCCAEPClient",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        ),
    ]
)
