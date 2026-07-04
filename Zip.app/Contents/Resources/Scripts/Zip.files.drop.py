#!/usr/bin/env python3
"""Zip.files.drop - files dropped on the window are added to the archive."""
import os
import sys
import json
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

ctx = os.environ.get("OMC_ACTIONUI_TRIGGER_CONTEXT", "")
if not ctx:
    sys.exit(0)

items = []
try:
    data = json.loads(ctx)
    if isinstance(data, dict):
        items = data.get("items", []) or []
    elif isinstance(data, list):
        items = data
except ValueError:
    items = []

paths = []
for p in items:
    if not p:
        continue
    if p.startswith("file://"):
        from urllib.parse import urlparse, unquote
        p = unquote(urlparse(p).path)
    if os.path.exists(p):
        paths.append(p)

if paths:
    add_paths(paths)
