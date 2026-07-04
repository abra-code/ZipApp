#!/usr/bin/env python3
"""Zip.unlock.confirm - validate the entered password and unlock for the session.

On a wrong password the sheet stays open with an inline error so the user can
retry; on success it dismisses, caches the password, and refreshes the UI.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

ID_PW = 110
ID_ERROR = 114

pw = get_view_value(ID_PW)
if not pw:
    set_value(ID_ERROR, "Enter a password.")
    sys.exit(0)

if not validate_password(pw):
    set_value(ID_ERROR, "Incorrect password.")
    sys.exit(0)

dismiss_modal()
pb_set(PB_PASSWORD, pw)
refresh_lock_menu()
# Re-render the current selection now that we can decrypt it.
sel = pb_get(PB_SEL_PATH)
if sel and pb_get(PB_SEL_ISDIR) != "1":
    describe_and_preview(sel, "0", "1")
set_status("Archive unlocked.")
