#!/usr/bin/env python3
"""Zip.main - the document command. Opens a window for the object that was
opened/dropped: a .zip opens for browsing; any other file/folder starts a new
archive containing it.

A launch with no document shows the command's open panel (OPEN_OBJECT_DIALOG);
if that is canceled the engine does not run this command at all, so nothing
opens. A new untitled archive is File > New (Zip.new). The last branch below
only covers the command running with no object some other way."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

obj = os.environ.get("OMC_OBJ_PATH", "")
first = obj.splitlines()[0] if obj else ""

# load_archive IS the "is this a zip?" test: it returns False, having claimed no
# document state, for anything the helper cannot read as one. Asking first with a
# separate probe meant reading a large archive's whole central directory twice
# before the window showed anything.
if first and os.path.isfile(first) and load_archive(first):
    pass
elif first and os.path.exists(first):
    new_archive_with(first)
else:
    new_archive()
