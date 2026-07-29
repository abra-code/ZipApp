#!/bin/bash
# build.sh - build the archive helper.
#
#   ./build.sh            same as 'release'
#   ./build.sh release    universal (arm64 + x86_64), -Os, local symbols stripped
#   ./build.sh debug      native arch only, -O0 -g, unstripped, with a .dSYM
#
# Output:
#   build/release/archive
#   build/debug/archive   (archive.o and archive.dSYM land beside it)
#
# This builds the tool and nothing else. Embedding it into an applet is
# ../update_zip.sh's job; nothing here knows that an app bundle exists.
#
# archive links the system libarchive via the SDK's libarchive.tbd stub. No public
# archive.h ships in the SDK, so libarchive's own headers are vendored next to
# the source; they carry extern "C" guards, so C++ includes them unchanged.
set -e

CONFIG="${1:-release}"
case "$CONFIG" in
    release|debug)
        ;;
    install)
        echo "build.sh no longer installs anything." >&2
        echo "Run ../update_zip.sh to build the helper and embed it in Zip.app." >&2
        exit 1 ;;
    -h|--help)
        echo "Usage: $0 [release|debug]"
        echo
        echo "  release  universal arm64 + x86_64, -Os, local symbols stripped (default)"
        echo "  debug    native arch only, -O0 -g, unstripped, with a .dSYM"
        exit 0 ;;
    *)
        echo "Unknown argument: $CONFIG (expected 'release' or 'debug')" >&2
        exit 1 ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/archive.cpp"
OUTDIR="$HERE/build/$CONFIG"
OUT="$OUTDIR/archive"
SDK="$(xcrun --show-sdk-path)"

COMPILE_FLAGS=(-std=c++17 -Wall -Wextra -mmacosx-version-min=14.6 -isysroot "$SDK" -I"$HERE")
LINK_FLAGS=(-mmacosx-version-min=14.6 -isysroot "$SDK" -larchive)

mkdir -p "$OUTDIR"
rm -f "$OUT" "$OUTDIR/archive.o"
rm -rf "$OUT.dSYM"

if [ "$CONFIG" = "release" ]; then
    echo "Compiling archive (release, universal arm64 + x86_64)..."
    # -Os rather than -O2: everything expensive - deflate, AES, the zip reader -
    # happens inside the system libarchive, so this translation unit is argument
    # handling and stream pumping. The smaller code costs nothing measurable and
    # cuts __text by about 14%.
    #
    # -Wl,-x strips local symbols during the LINK, not afterwards. We ad-hoc sign
    # below, and running strip(1) on an already-signed binary invalidates the
    # signature. This is the equivalent of Xcode's "Non-Global Symbols" strip
    # style: _main and the undefined imports stay, the mangled names of every
    # internal helper go.
    clang++ -arch arm64 -arch x86_64 \
        "${COMPILE_FLAGS[@]}" \
        -Os -DNDEBUG \
        -Wl,-x \
        -larchive \
        -o "$OUT" "$SRC"
else
    ARCH="$(uname -m)"
    echo "Compiling archive (debug, $ARCH)..."
    # Compile and link as two steps on purpose. A one-shot "clang++ -g archive.cpp
    # -o archive" builds through a temporary object file that the driver deletes
    # before it returns, leaving the binary's debug map pointing at a path that no
    # longer exists. Such a build is still debuggable - the driver covers for it by
    # auto-running dsymutil - but only through the .dSYM, with the debug map
    # permanently broken. Keeping archive.o beside the binary makes both routes
    # work and leaves a real object file to re-run dsymutil against.
    #
    # Native arch only: a debug build exists to be run under lldb on this machine,
    # and building the second slice just doubles the wait.
    clang++ -arch "$ARCH" "${COMPILE_FLAGS[@]}" -O0 -g -c -o "$OUTDIR/archive.o" "$SRC"
    clang++ -arch "$ARCH" "${LINK_FLAGS[@]}" -o "$OUT" "$OUTDIR/archive.o"
    dsymutil "$OUT"
fi

echo "Codesigning (ad-hoc)..."
codesign --force --timestamp=none --sign - "$OUT"

echo "Built: $OUT"
file "$OUT"
