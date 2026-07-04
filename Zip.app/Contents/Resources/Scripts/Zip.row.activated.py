#!/usr/bin/env python3
"""Zip.row.activated - double-click a row: ".." goes up, a folder drills in,
a file refreshes the inline Quick Look preview."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

fullpath = get_table_value(5)
isdir = get_table_value(6)
log("row.activated: fullpath=%r isdir=%r" % (fullpath, isdir))
if not fullpath:
    sys.exit(0)
if fullpath == "__UP__":
    nav_up()
elif isdir == "1":
    populate_level(fullpath)
else:
    # A file: make it the active selection and refresh the inline Quick Look pane.
    enc = get_table_value(7)
    pb_set(PB_SEL_PATH, fullpath)
    pb_set(PB_SEL_ISDIR, isdir)
    describe_and_preview(fullpath, isdir, enc)
