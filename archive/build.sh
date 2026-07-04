#!/bin/bash
# build.sh - build the archive helper and (optionally) install it into Zip.app.
#
#   ./build.sh            build a universal (arm64 + x86_64) ad-hoc-signed binary
#                         into ./build/archive
#   ./build.sh install    also copy it into ../Zip.app/Contents/Helpers/archive
#
# archive links the system libarchive via the SDK's libarchive.tbd stub. No public
# archive.h ships in the SDK, so archive.c declares the small ABI subset it uses.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/archive.c"
OUTDIR="$HERE/build"
OUT="$OUTDIR/archive"
APP="$HERE/../Zip.app"
SDK="$(xcrun --show-sdk-path)"

mkdir -p "$OUTDIR"

echo "Compiling universal archive (arm64 + x86_64)..."
clang -arch arm64 -arch x86_64 \
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
    echo "Remember to re-seal the app:  appletbuilder build \"$APP\""
fi
