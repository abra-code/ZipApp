#!/usr/bin/env python3
"""Zip.selection.changed - update the inspector + preview and button state."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

name = get_table_value(2)
size = get_table_value(3)
modified = get_table_value(4)
fullpath = get_table_value(5)
isdir = get_table_value(6)
enc = get_table_value(7)

if not fullpath or fullpath == "__UP__":
    pb_set(PB_SEL_PATH, "")
    pb_set(PB_SEL_ISDIR, "")
    clear_inspector()
    enable_view(ID_EXTRACT_BTN, False)
    enable_view(ID_DELETE_BTN, False)
    set_status(arc_location(pb_get(PB_PREFIX)))   # nothing selected: show current folder
    sys.exit(0)

pb_set(PB_SEL_PATH, fullpath)
pb_set(PB_SEL_ISDIR, isdir)

set_value(ID_DET_NAME, name)
set_value(ID_DET_PATH, fullpath)
set_value(ID_DET_SIZE, "Folder" if isdir == "1" else size)
set_value(ID_DET_MOD, modified or "-")
set_value(ID_DET_ENC, "Yes" if enc == "1" else "No")

enable_view(ID_EXTRACT_BTN, True)
enable_view(ID_DELETE_BTN, True)
set_status(arc_location(fullpath))   # Finder-like: full path of the selection
describe_and_preview(fullpath, isdir, enc)
