#!/usr/bin/env python3
"""Zip.encrypt - open the two-field password sheet to encrypt or change password.

Both the "Encrypt with Password" (plain archive) and "Change Password" (already
encrypted, must be unlocked) menu items route here; the actual mode is decided
from the archive's encryption state in Zip.encrypt.confirm.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

enc = pb_get(PB_ENC)
if enc == "encrypted" and not pb_get(PB_PASSWORD):
    alert("Unlock the archive first, then change its password.", level="note")
    sys.exit(0)

present_modal("PasswordSheet")
