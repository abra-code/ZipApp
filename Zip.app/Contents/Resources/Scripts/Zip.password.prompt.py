#!/usr/bin/env python3
"""Zip.password.prompt - cache the entered password and resume extraction."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

pw = os.environ.get("OMC_DLG_INPUT_TEXT", "")
if not pw:
    set_status("Extraction canceled (no password).")
    sys.exit(0)
pb_set(PB_PASSWORD, pw)
refresh_lock_menu()   # the archive is now unlocked for the session
subprocess.run([NEXT_CMD, CMD_GUID, "Zip.extract.run"], capture_output=True)
