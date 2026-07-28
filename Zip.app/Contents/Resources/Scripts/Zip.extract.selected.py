#!/usr/bin/env python3
"""Zip.extract.selected - extract the selected file or folder subtree."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

dest = os.environ.get("OMC_DLG_CHOOSE_FOLDER_PATH", "")
if not dest:
    sys.exit(0)
if not sel_path():
    alert("Select a file or folder in the list first.", level="note")
    sys.exit(0)
pb_set(PB_EX_DEST, dest)
pb_set(PB_EX_MODE, "selected")
do_extract()
