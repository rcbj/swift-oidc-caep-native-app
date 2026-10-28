// swift-tools-version:5.10
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The CAEP demo, built on OIDCCAEPClient. It is a package of its own and depends on the library by path, the
// way another app depends on it by URL:
//
//     .package(url: "https://github.com/rcbj/swift-oidc-caep-native-app.git", from: "0.1.0")
//
// One app, two front ends over the same model (DemoModel.swift):
//   macOS   SwiftUI (CAEPDemoApp.swift and the views beside it).
//   Linux   GTK 4 through SwiftCrossUI (Linux/), for GNOME and KDE desktops. SwiftCrossUI is a dependency on
//           Linux only.
import PackageDescription

let package = Package(
    name: "CAEPDemo",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(name: "swift-oidc-caep-native-app", path: ".."),
        .package(url: "https://github.com/stackotter/swift-cross-ui.git", exact: "0.9.0"),
    ],
    targets: [
        .executableTarget(
            name: "CAEPDemo",
            dependencies: [
                .product(name: "OIDCCAEPClient", package: "swift-oidc-caep-native-app"),
                .product(name: "SwiftCrossUI", package: "swift-cross-ui", condition: .when(platforms: [.linux])),
                .product(name: "GtkBackend", package: "swift-cross-ui", condition: .when(platforms: [.linux])),
            ],
            resources: [.process("Resources")]
        ),
    ]
)
