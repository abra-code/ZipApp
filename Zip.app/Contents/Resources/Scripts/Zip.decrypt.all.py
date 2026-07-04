#!/usr/bin/env python3
"""Zip.decrypt.all - remove encryption from the archive (rewrite as plain)."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

enc = pb_get(PB_ENC)
if enc != "encrypted":
    sys.exit(0)
if not pb_get(PB_PASSWORD):
    alert("Unlock the archive first.", level="note")
    sys.exit(0)

if alert("Remove encryption from this archive?\nAnyone will be able to read it.",
         level="caution", ok="Remove", cancel="Cancel") != 0:
    set_status("Encryption kept.")
    sys.exit(0)

if do_recrypt("none", ""):
    set_status("Encryption removed - Save to keep it.")
