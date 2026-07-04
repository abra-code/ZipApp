#!/usr/bin/env python3
"""Zip.save.as - save the archive to the path chosen in the Save As dialog."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

dest = os.environ.get("OMC_DLG_SAVE_AS_PATH", "")
closing = pb_get(PB_CLOSE_AFTER_SAVE) == "1"

if not dest:
    if closing:
        cleanup()
    else:
        set_status("Save cancelled")
    sys.exit(0)

ok = save_as(dest)
if closing:
    cleanup()
elif ok:
    refresh_title()
else:
    set_status("Save failed")
