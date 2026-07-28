#!/bin/bash
# build.sh - build the archive helper and (optionally) install it into Zip.app.
#
#   ./build.sh            build a universal (arm64 + x86_64) ad-hoc-signed binary
#                         into ./build/archive
#   ./build.sh install    also copy it into ../Zip.app/Contents/Helpers/archive
#                         and re-seal the app with appletbuilder (validate +
#                         codesign), when the AppletBuilder CLI can be found
#
# archive links the system libarchive via the SDK's libarchive.tbd stub. No public
# archive.h ships in the SDK, so libarchive's own headers are vendored next to
# the source; they carry extern "C" guards, so C++ includes them unchanged.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/archive.cpp"
OUTDIR="$HERE/build"
OUT="$OUTDIR/archive"
APP="$HERE/../Zip.app"
SDK="$(xcrun --show-sdk-path)"

mkdir -p "$OUTDIR"

echo "Compiling universal archive (arm64 + x86_64)..."
clang++ -arch arm64 -arch x86_64 \
      -std=c++17 \
      -O2 -Wall -Wextra \
      -mmacosx-version-min=14.6 \
      -isysroot "$SDK" \
      -I"$HERE" \
      -larchive \
      -o "$OUT" "$SRC"

echo "Codesigning (ad-hoc)..."
codesign --force --timestamp=none --sign - "$OUT"

echo "Built: $OUT"
file "$OUT"

if [ "$1" = "install" ]; then
    DEST="$APP/Contents/Helpers"
    mkdir -p "$DEST"
    cp "$OUT" "$DEST/archive"
    codesign --force --timestamp=none --sign - "$DEST/archive"
    echo "Installed: $DEST/archive"

    # Re-seal the app: a changed nested binary invalidates the bundle signature.
    # The AppletBuilder CLI validates the whole applet and re-signs it. Look in
    # the usual sibling checkout, then PATH; without it, just print the reminder.
    AB="$HERE/../../OMC/Distribution/AppletBuilder.app/Contents/Resources/Agents/appletbuilder"
    if [ ! -x "$AB" ]; then
        AB="$(command -v appletbuilder || true)"
    fi
    if [ -n "$AB" ] && [ -x "$AB" ]; then
        echo "Re-sealing the app with appletbuilder..."
        "$AB" build "$APP"
    else
        echo "AppletBuilder CLI not found - re-seal the app manually:"
        echo "  appletbuilder build \"$APP\""
    fi
fi
