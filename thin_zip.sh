#!/bin/bash
# thin_zip.sh - thin Zip.app's embedded Python to the module closure its scripts
# actually use, then verify, via the reusable Python-Embedding closure tools.
#
# This replaces the old hand-maintained blacklist: instead of naming what to remove,
# it traces the real workload (zip_trace_workload.py exercises every ziptool path and
# the handler stdlib usage), deletes everything outside that closure, and re-runs the
# workload to prove nothing needed was removed (auto-restoring on failure).
#
# Run AFTER `appletbuilder build Zip.app` (a rebuild restores the full Python).
#
# Usage:
#   ./thin_zip.sh [--arch arm64|x86_64] [--dry-run]

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

THINNER="$SCRIPT_DIR/../Python-Embedding/thin_with_closure.sh"
if [ ! -f "$THINNER" ]; then
    echo "Error: thin_with_closure.sh not found at: $THINNER"
    echo "Fetch Python-Embedding from: https://github.com/abra-code/Python-Embedding"
    exit 1
fi

PYDIR="$SCRIPT_DIR/Zip.app/Contents/Library/Python"
[ -d "$PYDIR" ] || { echo "Error: build Zip.app first (no $PYDIR)"; exit 1; }

# Pass through --arch / --dry-run.
PASS=()
while [ $# -gt 0 ]; do PASS+=("$1"); shift; done

# NOTE: --trace is the command AFTER `python -X importtime` (the tools prepend the
# embedded interpreter). So pass the script + args, NOT a leading python3.
exec "$THINNER" \
    --python "$PYDIR" \
    --trace "$SCRIPT_DIR/zip_trace_workload.py $SCRIPT_DIR/Zip.app" \
    --trace-timeout 30 \
    --static "$SCRIPT_DIR/Zip.app/Contents/Resources/Scripts" \
    ${PASS[@]+"${PASS[@]}"}
