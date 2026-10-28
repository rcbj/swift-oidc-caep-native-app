// swift-tools-version:5.9
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The CAEP demo: a macOS SwiftUI app built on OIDCCAEPClient. It is a package of its own and depends on the
// library by path, the way another app depends on it by URL:
//
//     .package(url: "https://github.com/rcbj/swift-oidc-caep-native-app.git", from: "0.1.0")
import PackageDescription

let package = Package(
    name: "CAEPDemo",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(name: "swift-oidc-caep-native-app", path: ".."),
    ],
    targets: [
        .executableTarget(
            name: "CAEPDemo",
            dependencies: [.product(name: "OIDCCAEPClient", package: "swift-oidc-caep-native-app")],
            resources: [.process("Resources")]
        ),
    ]
)
