#!/usr/bin/env python3
"""Zip.nav.up - go up one folder level."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

nav_up()
