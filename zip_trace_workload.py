#!/usr/bin/env python3
"""Exercise every Zip.app Python code path, so the Python-Embedding closure tools
(analyze_python_deps.py / thin_with_closure.sh) capture the complete runtime module
set. Run under the app's embedded interpreter:

    Zip.app/Contents/Library/Python/bin/python3 zip_trace_workload.py [Zip.app]

It drives ziptool.py across all subcommands against a throwaway archive and touches
the stdlib APIs the handler scripts use (json, urllib.parse, shutil, tempfile). The
handlers themselves are thin wrappers over lib_zip + the native Helpers/archive tool,
so their stdlib closure is a subset of what this exercises.
"""
import contextlib
import io
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
APP = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "Zip.app")
SCR = os.path.join(APP, "Contents", "Resources", "Scripts")
sys.path.insert(0, SCR)
os.environ.setdefault("OMC_APP_BUNDLE_PATH", APP)

# Import every module our source directly names, so their full runtime closures load.
import argparse  # noqa: F401
import json
import shutil
import urllib.parse
import lib_zip  # noqa: F401  (defines paths/functions; reads env only)
import ziptool

d = tempfile.mkdtemp(prefix="ziptrace-")
srcsub = os.path.join(d, "src", "sub")
os.makedirs(srcsub)
for i in range(3):
    with open(os.path.join(d, "src", "f%d.txt" % i), "w") as f:
        f.write("x%d" % i)
with open(os.path.join(srcsub, "deep.txt"), "w") as f:
    f.write("nested")
zippath = os.path.join(d, "t.zip")
subprocess.run(["/usr/bin/zip", "-q", "-r", zippath, "."], cwd=os.path.join(d, "src"),
               capture_output=True)


def run(*a):
    try:
        ziptool.main(list(a))
    except SystemExit:
        pass
    except Exception as e:  # noqa: BLE001
        print("exercise", a, "->", repr(e), file=sys.stderr)


# Capture a model TSV so the level/find browsing paths can be exercised.
tsv = os.path.join(d, "model.tsv")
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    run("list", zippath)
with open(tsv, "w") as f:
    f.write(buf.getvalue())

run("probe", zippath)
run("read", zippath, "--entry", "f0.txt")
run("extract", zippath, "--dest", os.path.join(d, "o_all"), "--all")
run("extract", zippath, "--dest", os.path.join(d, "o_pre"), "--prefix", "sub/")
run("extract", zippath, "--dest", os.path.join(d, "o_one"), "--entry", "f1.txt")
run("level", "--tsv", tsv, "--prefix", "")
run("find", "--tsv", tsv, "--query", "deep")
run("create", os.path.join(d, "new.zip"))
run("delete", zippath, "--entry", "f2.txt")

# add reads file paths from stdin; feed an empty stream so it does not block.
_stdin = sys.stdin
try:
    sys.stdin = open(os.devnull, "r")
    run("add", os.path.join(d, "new.zip"), "--prefix", "")
finally:
    sys.stdin = _stdin

# Handler-side stdlib usage (json trigger context, file:// drop URL parsing).
json.loads(json.dumps({"k": [1, 2], "s": "v"}))
urllib.parse.unquote(urllib.parse.urlparse("file:///tmp/a%20b.txt").path)

shutil.rmtree(d, ignore_errors=True)
print("zip workload exercised", file=sys.stderr)
