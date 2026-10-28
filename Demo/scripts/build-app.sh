#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# Builds the demo as a macOS app bundle, Demo/build/CAEPDemo.app, ad-hoc signed.
#
# `swift run CAEPDemo` is enough to try the demo. A bundle gives it a bundle identifier, which the Keychain
# and the Secure Enclave key are tied to, and a stable code signature, so macOS does not ask again for
# Keychain access after every rebuild of an unchanged binary.
#
#   Demo/scripts/build-app.sh            # release build
#   CONFIGURATION=debug Demo/scripts/build-app.sh
#   open Demo/build/CAEPDemo.app
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
config="${CONFIGURATION:-release}"
app="${here}/build/CAEPDemo.app"

cd "${here}"
swift build -c "${config}" --product CAEPDemo
bin="$(swift build -c "${config}" --show-bin-path)"

rm -rf "${app}"
mkdir -p "${app}/Contents/MacOS" "${app}/Contents/Resources"
cp "${bin}/CAEPDemo" "${app}/Contents/MacOS/CAEPDemo"
# The configuration goes in the bundle's Resources, where OIDCAppConfiguration.load(bundle: .main) finds it.
cp "${here}/Sources/CAEPDemo/Resources/OIDCConfiguration.plist" "${app}/Contents/Resources/"
if [ -d "${bin}/CAEPDemo_CAEPDemo.bundle" ]; then
  cp -R "${bin}/CAEPDemo_CAEPDemo.bundle" "${app}/Contents/Resources/"
fi

cat > "${app}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key><string>net.rcbj.caepdemo</string>
	<key>CFBundleName</key><string>CAEP Demo</string>
	<key>CFBundleDisplayName</key><string>CAEP Demo</string>
	<key>CFBundleExecutable</key><string>CAEPDemo</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>$(cat "${here}/../VERSION" 2>/dev/null || echo 0.1).0</string>
	<key>CFBundleVersion</key><string>1</string>
	<key>LSMinimumSystemVersion</key><string>14.0</string>
	<key>NSHighResolutionCapable</key><true/>
	<key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
PLIST

codesign --force --sign - "${app}"
echo "Built ${app}"
