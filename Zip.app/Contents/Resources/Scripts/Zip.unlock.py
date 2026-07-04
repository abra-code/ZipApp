#!/usr/bin/env python3
"""Zip.unlock - open the single-field password sheet to unlock the archive."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

present_modal("UnlockSheet")
