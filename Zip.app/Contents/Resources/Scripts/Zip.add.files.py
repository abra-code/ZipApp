#!/usr/bin/env python3
"""Zip.add.files - add files/folders chosen in the picker to the archive."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

chosen = os.environ.get("OMC_DLG_CHOOSE_OBJECT_PATH", "")
if not chosen:
    sys.exit(0)
paths = [p for p in chosen.splitlines() if p.strip()]
if paths:
    add_paths(paths)
