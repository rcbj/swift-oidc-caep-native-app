// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// The macOS front end (SwiftUI). The Linux one is in Linux/.
#if os(macOS)

import AppKit
import SwiftUI

@main
struct CAEPDemoApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = DemoModel()

    var body: some Scene {
        WindowGroup("CAEP Demo") {
            ContentView()
                .environment(model)
                .frame(minWidth: 820, minHeight: 640)
                .task { await model.start() }
        }
        .windowResizability(.contentMinSize)
    }
}

/// `swift run` starts the app without a bundle; this makes it a regular app with a Dock icon and focus.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
#endif
