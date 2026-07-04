#!/usr/bin/env python3
"""Zip.extract.all - extract the whole archive into the chosen folder."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

dest = os.environ.get("OMC_DLG_CHOOSE_FOLDER_PATH", "")
if not dest:
    sys.exit(0)
pb_set(PB_EX_DEST, dest)
pb_set(PB_EX_MODE, "all")
do_extract()
