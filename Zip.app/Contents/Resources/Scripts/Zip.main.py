#!/usr/bin/env python3
"""Zip.main - the document command. Opens a window for the object that was
opened/dropped, or (blank launch with the open panel cancelled) a new untitled
archive. A .zip opens for browsing; any other file/folder starts a new archive
containing it."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

obj = os.environ.get("OMC_OBJ_PATH", "")
first = obj.splitlines()[0] if obj else ""

if first and is_zip(first):
    load_archive(first)
elif first and os.path.exists(first):
    new_archive_with(first)
else:
    new_archive()
