#!/usr/bin/env python3
"""Zip.window.close - on window close, prompt to save if dirty, then clean up."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

if is_dirty():
    rc = alert("Do you want to save the changes you made to “%s”?" % doc_name(),
               title="Unsaved Changes", level="caution", ok="Save", cancel="Don’t Save")
    if rc == 0:  # Save
        if get_original():
            save_document()
            cleanup()
        else:
            # New, unsaved: chain to Save As and let it clean up afterward.
            pb_set(PB_CLOSE_AFTER_SAVE, "1")
            subprocess.run([NEXT_CMD, CMD_GUID, "Zip.save.as"], capture_output=True)
            sys.exit(0)
    else:        # Don't Save
        cleanup()
else:
    cleanup()
