#!/usr/bin/env python3
"""Zip.quicklook - extract the selected file entry to a scratch dir and open it
in Quick Look."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

do_quicklook()
