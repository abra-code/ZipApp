#!/usr/bin/env python3
"""Zip.reveal - reveal the last-extracted file or folder in Finder.

Hooked to the extraction toast's "Show in Finder" button; the path was stashed in
PB_EX_LAST by do_extract.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

path = pb_get(PB_EX_LAST)
if path and os.path.exists(path):
    subprocess.run(["/usr/bin/open", "-R", path], capture_output=True)
else:
    set_status("The extracted item is no longer there.")
