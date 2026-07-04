#!/usr/bin/env python3
"""Zip.sheet.cancel - dismiss the active password sheet (unlock or encrypt)."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

dismiss_modal()
