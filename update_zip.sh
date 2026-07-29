#!/bin/bash
# update_zip.sh
# Build Zip.app's embedded command-line helper and re-sign the applet.
#
# One helper lives in Zip.app/Contents/Helpers:
#   * archive - built from the archive/ directory in this repo by archive/build.sh
#               (clang++ against the system libarchive, universal by default).
#               It is the app's entire zip engine: every read, list, extract,
#               create, and recrypt in Contents/Resources/Scripts goes through it,
#               so the bundle without it does nothing at all.
#
# archive builds in seconds, so it is rebuilt every run unless --skip-build.
#
# Built UNIVERSAL (arm64 + x86_64) to match the app, so nothing is thinned.
# Codesigning is delegated to codesign_applet.sh.
#
# Nothing else needs embedding: archive links the OS copy of libarchive rather
# than bundling one, so Helpers holds the single binary and no license texts.
#
# The .app bundle is auto-detected from this script's directory.

set -uo pipefail

GREEN=$(printf '\033[92m'); RED=$(printf '\033[91m'); YELLOW=$(printf '\033[93m'); RESET=$(printf '\033[0m')

SIGNING_IDENTITY="-"
DO_BUILD="yes"
DO_CODESIGN="yes"
CONFIG="release"

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "$0")" >/dev/null 2>&1 && pwd)"
ARCHIVE_DIR="$SCRIPT_DIR/archive"

while [ $# -gt 0 ]; do
    case "$1" in
        --debug) CONFIG="debug" ;;
        --skip-build) DO_BUILD="no" ;;
        --identity=*) SIGNING_IDENTITY="${1#*=}" ;;
        --no-codesign) DO_CODESIGN="no" ;;
        --help)
            echo "Usage: $0 [--debug] [--skip-build] [--identity=CERT] [--no-codesign]"
            echo
            echo "  --debug          embed a debug build (native arch, -O0 -g, unstripped)"
            echo "                   instead of the universal release build"
            echo "  --skip-build     reuse the already-embedded archive binary"
            echo "  --identity=CERT  codesign identity passed to codesign_applet.sh ('-' = ad-hoc, default)"
            echo "  --no-codesign    skip the codesign_applet.sh step"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

fail() { echo "${RED}$*${RESET}" >&2; exit 1; }

# Auto-detect the single .app bundle beside this script.
APP_BUNDLE=""
for _c in "$SCRIPT_DIR"/*.app; do [ -d "$_c" ] && { APP_BUNDLE="$_c"; break; }; done
[ -n "$APP_BUNDLE" ] || fail "No .app bundle found in $SCRIPT_DIR"
HELPERS_DIR="$APP_BUNDLE/Contents/Helpers"

echo
echo "==== Updating $(basename "$APP_BUNDLE") ($CONFIG) ===="
echo "  archive  : $ARCHIVE_DIR$([ "$DO_BUILD" = "no" ] && echo " (skipped - reusing embedded)")"
echo "  deploy to: $HELPERS_DIR"
echo

# --- 1. Build + embed the archive helper ----------------------------------
# build.sh knows how to build the tool and nothing else; where the result goes is
# decided here. A release build lands at archive/build/release/archive, ad-hoc
# signed and universal.
if [ "$DO_BUILD" = "yes" ]; then
    [ -x "$ARCHIVE_DIR/build.sh" ] || fail "no build.sh in $ARCHIVE_DIR - that does not look like an archive source dir"
    ( cd "$ARCHIVE_DIR" && ./build.sh "$CONFIG" ) || fail "archive build.sh failed"
    _built="$ARCHIVE_DIR/build/$CONFIG/archive"
    [ -x "$_built" ] || fail "archive build produced no binary at $_built"
    /bin/mkdir -p "$HELPERS_DIR" || fail "Could not create $HELPERS_DIR"
    # Replace rather than overwrite: cp -f truncates in place and keeps the inode,
    # which hands the running kernel a binary whose pages no longer match the
    # signature it already cached for that file.
    /bin/rm -f "$HELPERS_DIR/archive" || fail "Could not remove the old $HELPERS_DIR/archive"
    /bin/cp "$_built" "$HELPERS_DIR/archive" || fail "Could not copy archive"
    /bin/chmod +x "$HELPERS_DIR/archive"
    echo "  ${GREEN}Built${RESET} archive ($CONFIG)"
fi
[ -x "$HELPERS_DIR/archive" ] || fail "No archive at $HELPERS_DIR/archive (build first, or drop --skip-build)."

# Check what is actually IN the bundle, not what was just built - --skip-build
# signs whatever an earlier run left behind, and a debug helper from a previous
# --debug run must not slip into a distribution build unnoticed. A binary thinned
# to this machine's own arch runs fine here and fails on every other Mac, which is
# the worst possible time to find out.
_archs="$(/usr/bin/lipo -archs "$HELPERS_DIR/archive" 2>/dev/null)"
_universal="no"
case " $_archs " in
    *" arm64 "*) case " $_archs " in *" x86_64 "*) _universal="yes" ;; esac ;;
esac
if [ "$_universal" = "yes" ]; then
    echo "  Embedded archive: universal ($_archs)"
elif [ "$DO_BUILD" = "yes" ] && [ "$CONFIG" = "release" ]; then
    # A release build that came out thinned is a build-system fault, not something
    # to warn past.
    fail "the release build of archive is not universal (archs: $_archs)"
elif [ "$DO_CODESIGN" = "yes" ] && [ "$SIGNING_IDENTITY" != "-" ]; then
    # Signing with a real identity is the distribution path. Stop rather than hand
    # out a bundle that only runs on one architecture.
    fail "the embedded archive is not universal (archs: $_archs) - a debug or thinned build. Run a plain './update_zip.sh' before signing for distribution."
else
    echo "  ${YELLOW}WARNING: the embedded archive is not universal ($_archs) - do not ship this bundle.${RESET}"
fi

# Sweep Finder droppings out of Helpers before signing.
/usr/bin/find "$HELPERS_DIR" -name ".DS_Store" -delete 2>/dev/null

# --- 2. Codesign ----------------------------------------------------------
# codesign_applet.sh is the sole signer: it deep-signs the bundle (nested Mach-O
# first, app last) and auto-discovers OMCApplet.entitlements beside it. Copying a
# new binary into Helpers invalidates the app's own signature, so this step is not
# optional for a bundle that has to launch.
if [ "$DO_CODESIGN" = "yes" ]; then
    [ -x "$SCRIPT_DIR/codesign_applet.sh" ] || fail "codesign_applet.sh not found beside this script"
    "$SCRIPT_DIR/codesign_applet.sh" "$APP_BUNDLE" "$SIGNING_IDENTITY" \
        || fail "codesign_applet.sh failed. On a fresh clone this is expected - Contents/MacOS, Contents/Frameworks and Contents/Library/Python are gitignored, so the applet has to be regenerated once with 'appletbuilder build $APP_BUNDLE' before it can be signed."
fi

# --- 3. Verify ------------------------------------------------------------
# Everything below runs the SIGNED, EMBEDDED binary, so it proves the thing the
# app will actually launch - not the thing that was built a moment ago.
ARCHIVE_BIN="$HELPERS_DIR/archive"

# Run with no arguments: the helper prints its usage banner and exits 1. Match the
# TEXT, not the exit status - a binary the kernel kills for a broken signature also
# exits nonzero, and would otherwise pass for a working tool.
_usage="$("$ARCHIVE_BIN" 2>&1)"
case "$_usage" in
    usage*) echo "  ${GREEN}Verify OK${RESET}: archive launches" ;;
    *) fail "archive did not print its usage banner - build/link/sign failure." ;;
esac

# Every verb Contents/Resources/Scripts invokes. The app is a front end for these
# and nothing else, so a missing one is a dead command rather than a degraded
# feature. Keep in step with the ARCHIVE_BIN / ARCHIVE_TOOL call sites in
# ziptool.py and lib_zip.py.
_missing=""
for _verb in read extract list create recrypt; do
    case "$_usage" in
        *"archive $_verb"*) ;;
        *) _missing="$_missing $_verb" ;;
    esac
done
[ -z "$_missing" ] || fail "embedded archive is missing verbs the app calls:$_missing - wrong or old build?"
echo "  ${GREEN}Verify OK${RESET}: all 5 verbs the app calls are present"

# Capability spot-checks: flags the app EMITS. A verb existing is not enough - an
# embedded binary predating one of these fails at runtime with an unknown-option
# error, which is exactly how a stale helper hides. Each entry is a real call site
# in ziptool.py or lib_zip.py, so add to this list when the app starts emitting a
# newly added flag.
_check_flag() {   # $1 = flag, $2 = why the app needs it
    case "$_usage" in
        *"$1"*) return 0 ;;
    esac
    fail "embedded archive does not accept $1 ($2) - the helper predates it; rebuild without --skip-build."
}
_check_flag --max           "read caps how much of an entry the preview pulls in"
_check_flag --nul           "list uses NUL framing so names containing TAB or newline survive"
_check_flag --prefix        "extracting one selected folder"
_check_flag --progress      "extract feeds OMC's progress bar"
_check_flag --skip-junk     "extract drops __MACOSX/._*/.DS_Store"
_check_flag --mode          "recrypt selects aes256, zipcrypt, or none"
_check_flag --old-pwd-stdin "recrypt reads the current password from stdin, never argv"
_check_flag --new-pwd-stdin "recrypt reads the new password from stdin, never argv"
echo "  ${GREEN}Verify OK${RESET}: the flags the app emits are all accepted"

# Round trip on a throwaway archive. The checks above only read the usage text; this
# one proves the embedded binary can actually create, list, read, and extract - the
# four things the app does on every launch - with its shipped signature in place.
_tmp="$(/usr/bin/mktemp -d)" || fail "could not create a temp dir for the round trip"
# Cleanup hangs off EXIT alone. A signal trap that only deletes the directory does
# not stop the script: bash runs the handler and then RESUMES, so the remaining
# legs run against a directory that is already gone and an interrupt is reported
# as a helper failure. These exit instead, and the EXIT trap still cleans up.
trap '/bin/rm -rf "$_tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'zip round trip\n' > "$_tmp/a.txt"
printf 'a.txt\t%s/a.txt\n' "$_tmp" > "$_tmp/manifest"
/bin/mkdir -p "$_tmp/out"

# EVERY verb but `list` slurps stdin to EOF before it does anything, because that
# is the only channel a passphrase travels on (see the comment above the `list`
# special case in archive.cpp). Run interactively, a call that inherits the
# terminal blocks until Ctrl-D with nothing on screen to explain why - so each one
# below is handed either a real passphrase or /dev/null.
#
# The listing is captured rather than piped into grep: pipefail is on, and a reader
# that exits at the first match can hand the helper an EPIPE, failing the pipeline
# over a helper that did its job.
_step=""
if ! "$ARCHIVE_BIN" create "$_tmp/t.zip" --manifest "$_tmp/manifest" </dev/null >/dev/null 2>&1; then
    _step="create"
elif _listing="$("$ARCHIVE_BIN" list "$_tmp/t.zip" </dev/null 2>/dev/null)"; [ "${_listing#a.txt}" = "$_listing" ]; then
    _step="list"
elif [ "$("$ARCHIVE_BIN" read "$_tmp/t.zip" a.txt </dev/null 2>/dev/null)" != "zip round trip" ]; then
    _step="read"
elif ! "$ARCHIVE_BIN" extract "$_tmp/t.zip" "$_tmp/out" </dev/null >/dev/null 2>&1; then
    _step="extract"
elif [ "$(/bin/cat "$_tmp/out/a.txt" 2>/dev/null)" != "zip round trip" ]; then
    _step="extract"
# recrypt is the one verb the checks above cannot reach through its interface
# alone, and the encrypt / unlock / change-password flows rest entirely on it.
# Encrypt to AES-256, then read the entry back with the passphrase: that exercises
# the in-memory passphrase path this helper exists for.
elif ! printf 'round-trip-pw' | "$ARCHIVE_BIN" recrypt "$_tmp/t.zip" "$_tmp/enc.zip" --mode aes256 --new-pwd-stdin >/dev/null 2>&1; then
    _step="recrypt"
elif [ "$(printf 'round-trip-pw' | "$ARCHIVE_BIN" read "$_tmp/enc.zip" a.txt 2>/dev/null)" != "zip round trip" ]; then
    _step="encrypted read"
fi
[ -z "$_step" ] || fail "embedded archive failed the $_step round trip - the helper does not work in the bundle."
echo "  ${GREEN}Verify OK${RESET}: create/list/read/extract/recrypt round trip passes"

echo
echo "  ${GREEN}Done.${RESET} $(basename "$APP_BUNDLE") is ready."
echo
