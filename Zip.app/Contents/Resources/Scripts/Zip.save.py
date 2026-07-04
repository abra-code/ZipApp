#!/usr/bin/env python3
"""Zip.save - save to the original path, or chain to Save As if untitled."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

save_document()
