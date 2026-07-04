#!/usr/bin/env python3
"""Zip.encrypt.confirm - validate the two password fields, then (re)encrypt.

Runs in the main window context (the sheet's controls live in this window's pool),
so reading the fields and refreshing the UI after recrypt all work directly.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

ID_PW = 100
ID_CONFIRM = 101
ID_ERROR = 104

pw = get_view_value(ID_PW)
confirm = get_view_value(ID_CONFIRM)

if not pw:
    set_value(ID_ERROR, "Password cannot be empty.")
    sys.exit(0)
if pw != confirm:
    set_value(ID_ERROR, "Passwords do not match.")
    sys.exit(0)

dismiss_modal()
if do_recrypt("aes256", pw):
    set_status("Archive encrypted (AES-256) - Save to keep it.")
