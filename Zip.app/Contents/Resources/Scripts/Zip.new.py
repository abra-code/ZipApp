#!/usr/bin/env python3
"""Zip.new - File > New: open a new window with an empty untitled archive."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

new_archive()
