#!/usr/bin/env python3
"""Zip.extract.run - run the extraction after a password has been entered."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

do_extract()
