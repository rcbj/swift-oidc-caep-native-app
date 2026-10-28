#!/bin/sh
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# Build a self-contained x86_64 AppImage of the CAEP demo's Linux (GTK 4) front end.
#
# The image contains the demo and every library it needs besides the system C
# library and the host OpenGL loader. The Swift runtime is linked in
# statically. The result uses the glibc of the machine that builds it. GitHub
# Actions builds on Ubuntu 22.04, so that artifact runs on Ubuntu 22.04 and
# newer. On a machine without Swift, install/appimage-docker.sh runs this
# script in the Swift 6.1 Ubuntu 22.04 image.
set -eu

cd "$(dirname "$0")/.."

if [ "$(uname -m)" != "x86_64" ]; then
    echo "CAEP demo AppImage builds are x86_64" >&2
    exit 1
fi

if ! command -v swift >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    echo "swift and curl are required" >&2
    exit 1
fi

version="$(tr -d '[:space:]' < VERSION).0"

(cd Demo && swift build -c release --static-swift-stdlib --product CAEPDemo)
bin_dir=$(cd Demo && swift build -c release --static-swift-stdlib --show-bin-path)

binary="$bin_dir/CAEPDemo"
if ldd "$binary" | grep -q "not found"; then
    echo "the release binary is missing a shared library" >&2
    ldd "$binary" >&2
    exit 1
fi

appdir="Demo/build/appimage/CAEP_Demo.AppDir"
rm -rf "$appdir"
mkdir -p "$appdir/usr/bin" "$appdir/usr/lib" \
    "$appdir/usr/share/applications" \
    "$appdir/usr/share/icons/hicolor/256x256/apps"

cp "$binary" "$appdir/usr/bin/caep-demo"
if command -v strip >/dev/null 2>&1; then
    strip --strip-unneeded "$appdir/usr/bin/caep-demo"
fi
chmod 755 "$appdir/usr/bin/caep-demo"

# SwiftPM's resource bundle (the OIDC configuration). Bundle.module looks for it
# beside the executable.
cp -R "$bin_dir/CAEPDemo_CAEPDemo.resources" "$appdir/usr/bin/"

# Keep libraries other than the C library next to the binary. glibc stays
# on the system; it has to match the kernel's dynamic linker.
ldd "$binary" | while IFS= read -r line; do
    case $line in
        *linux-vdso* | *ld-linux*) continue ;;
    esac
    lib=$(printf "%s\n" "$line" | sed -n "s/.* => \\([^ ]*\\) (.*/\\1/p")
    if [ -z "$lib" ] || [ ! -f "$lib" ]; then
        continue
    fi
    base=$(basename "$lib")
    case $base in
        libc.so* | libm.so* | libpthread.so* | libdl.so* | librt.so* | libresolv.so*)
            continue
            ;;
        # The host OpenGL dispatcher loads the GPU driver. A copy inside the
        # image points that loader at the wrong place.
        libGL.so* | libGLX.so* | libGLdispatch.so* | libEGL.so*)
            continue
            ;;
    esac
    cp -L "$lib" "$appdir/usr/lib/$base"
done

cat > "$appdir/AppRun" <<'EOF'
#!/bin/sh
set -eu
here=$(dirname "$(readlink -f "$0")")
# The browser opened for sign-in must load the system's libraries, not these:
# the library restores this value for it.
export CAEP_ORIGINAL_LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}"
if [ -n "${LD_LIBRARY_PATH:-}" ]; then
    LD_LIBRARY_PATH="$here/usr/lib:$LD_LIBRARY_PATH"
else
    LD_LIBRARY_PATH="$here/usr/lib"
fi
export LD_LIBRARY_PATH
# GTK's Cairo renderer needs no GPU driver. A driver loaded from the host next
# to the image's older C++ runtime is the usual way an AppImage crashes. Set
# GSK_RENDERER=gl (or ngl) to use the GPU anyway.
export GSK_RENDERER="${GSK_RENDERER:-cairo}"
# The demo draws for a light theme; GTK_THEME set by the user wins.
export GTK_THEME="${GTK_THEME:-Adwaita}"
exec "$here/usr/bin/caep-demo" "$@"
EOF
chmod 755 "$appdir/AppRun"

cp install/net.rcbj.caepdemo.png "$appdir/net.rcbj.caepdemo.png"
cp install/net.rcbj.caepdemo.png "$appdir/.DirIcon"
cp install/net.rcbj.caepdemo.png \
    "$appdir/usr/share/icons/hicolor/256x256/apps/net.rcbj.caepdemo.png"

cat > "$appdir/net.rcbj.caepdemo.desktop" <<'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=CAEP Demo
GenericName=OpenID Connect and CAEP client demo
Comment=Sign in with OpenID Connect and receive CAEP security events
Exec=caep-demo
Icon=net.rcbj.caepdemo
Terminal=false
Categories=Network;Security;
StartupNotify=true
EOF
cp "$appdir/net.rcbj.caepdemo.desktop" \
    "$appdir/usr/share/applications/net.rcbj.caepdemo.desktop"

tool_dir="Demo/build/appimage/tools"
mkdir -p "$tool_dir"
fetch() {
    dest=$1
    url=$2
    sum=$3
    if [ -f "$dest" ] && echo "$sum  $dest" | sha256sum -c - >/dev/null 2>&1; then
        return 0
    fi
    curl -fsSL -o "$dest.partial" "$url"
    echo "$sum  $dest.partial" | sha256sum -c -
    mv "$dest.partial" "$dest"
    chmod 755 "$dest"
}
# AppImage/appimagetool 1.9.1, the static x86_64 binary.
fetch "$tool_dir/appimagetool" \
    "https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage" \
    "ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
# AppImage/type2-runtime 20251108. appimagetool would otherwise download
# whatever "continuous" points at.
fetch "$tool_dir/runtime-x86_64" \
    "https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64" \
    "2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"

# Without FUSE (a container), the AppImages run by extracting themselves.
if [ ! -e /dev/fuse ]; then
    export APPIMAGE_EXTRACT_AND_RUN=1
fi

mkdir -p dist
out="dist/CAEP_Demo-${version}-x86_64.AppImage"
rm -f "$out"
ARCH=x86_64 VERSION="$version" "$tool_dir/appimagetool" \
    --runtime-file "$tool_dir/runtime-x86_64" \
    --no-appstream \
    "$appdir" "$out"
chmod 755 "$out"

# The runtime can extract the image when FUSE is not available. --version
# answers without opening a window.
version_text=$(APPIMAGE_EXTRACT_AND_RUN=1 "$out" --version)
printf "%s\n" "$version_text" | grep -q "CAEP Demo"
echo "wrote $out"
