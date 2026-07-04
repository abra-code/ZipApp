#!/usr/bin/env python3
"""Zip.delete.selected - remove the selected file or folder from the archive."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

sel = pb_get(PB_SEL_PATH)
if not sel:
    sys.exit(0)
name = os.path.basename(sel.rstrip("/")) or sel
rc = alert("Remove “%s” from the archive?" % name, title="Delete",
           level="caution", ok="Delete", cancel="Cancel")
if rc == 0:
    delete_selected()
