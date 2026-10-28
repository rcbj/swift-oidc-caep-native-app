#!/bin/sh
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# Build the AppImage on a machine without Swift: runs install/appimage.sh in
# the official Swift 6.1 image for Ubuntu 22.04 (the glibc the AppImage is
# linked against, as in CI), with GTK 4's headers installed. Needs Docker.
#
#   install/appimage-docker.sh      # writes dist/CAEP_Demo-<version>-x86_64.AppImage
set -eu

cd "$(dirname "$0")/.."

docker run --rm \
    -v "$PWD":/w \
    -v caep-demo-swiftpm-cache:/root/.cache \
    -w /w \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    swift:6.1-jammy \
    sh -c '
        set -eu
        apt-get update -qq >/dev/null
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libgtk-4-dev curl file binutils >/dev/null
        sh ./install/appimage.sh
        chown -R "$HOST_UID:$HOST_GID" dist Demo/.build Demo/build
    '
