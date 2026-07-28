#!/usr/bin/env python3
"""Zip.save.as - save the archive to the path chosen in the Save As dialog."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

# Diagnostics (no-op unless $TMPDIR/zip_debug exists). Deliberately the FIRST
# statement and env-only - no pb_get, no subprocess - so that its absence proves
# the script never ran, rather than that it died reaching the pasteboard tool.
log("save.as: ENTERED dest=%r support=%r window=%r parent=%r guid=%r"
    % (os.environ.get("OMC_DLG_SAVE_AS_PATH"), SUPPORT_PATH,
       WINDOW_UUID, PARENT_UUID, CMD_GUID))

dest = os.environ.get("OMC_DLG_SAVE_AS_PATH", "")
closing = pb_get(PB_CLOSE_AFTER_SAVE) == "1"
log("save.as: state closing=%r work=%r doc=%s" % (closing, get_work(), DOCUMENT_UUID))

if not dest:
    if closing:
        # Cancelling the location picker IS a decision not to save: the user has
        # already answered "Save" to the close prompt and then declined to pick a
        # destination. Treat it as a discard and clean up. Trying to preserve the
        # document here would mean a dirty untitled archive could never be closed
        # without saving it somewhere, since OMC cannot call the close off.
        #
        # In practice this branch does not run - OMC aborts the command when the
        # save panel is cancelled, so the script never starts (verified against
        # the running applet). It is kept because the OMC docs advise checking
        # for an empty OMC_DLG_SAVE_AS_PATH, so some path may yet deliver one.
        cleanup()
    else:
        set_status("Save cancelled")
    sys.exit(0)

ok = save_as(dest)
if ok and closing:
    cleanup()
elif ok:
    refresh_title()
elif closing:
    # Save failed while closing: same reasoning as Cancel above. save_as has
    # already said why, so this only adds where the recoverable copy is.
    offer_recovery(get_work(), "“%s” could not be saved." % doc_name())
# A failed save never calls cleanup(): that would throw the document away.
