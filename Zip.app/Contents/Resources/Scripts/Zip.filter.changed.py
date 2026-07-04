#!/usr/bin/env python3
"""Zip.filter.changed - filter the listing (flat) or restore the current folder."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

if not os.path.isfile(tsv_path()):
    sys.exit(0)

# The native .searchable field has no addressable view id; its query arrives as the
# action context (OMC_ACTIONUI_TRIGGER_CONTEXT), not as a control value.
q = os.environ.get("OMC_ACTIONUI_TRIGGER_CONTEXT", "")
if q:
    populate_filter(q)
else:
    populate_level(pb_get(PB_PREFIX))
