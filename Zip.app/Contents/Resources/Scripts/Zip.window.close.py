#!/usr/bin/env python3
"""Zip.window.close - on window close, prompt to save if dirty, then clean up."""
import os
import sys
sys.path.insert(0, os.path.join(os.environ.get("OMC_APP_BUNDLE_PATH", ""),
                                "Contents/Resources/Scripts"))
from lib_zip import *

# Diagnostics for the close/save handoff (no-ops unless $TMPDIR/zip_debug exists).
# The chained Zip.save.as runs in a fresh process, so the only way to tell whether
# it ran - and whether it resolved the SAME document UUID - is to log both ends.
log("close: dirty=%s original=%r work=%r doc=%s window=%s parent=%s"
    % (is_dirty(), get_original(), get_work(), DOCUMENT_UUID, WINDOW_UUID, PARENT_UUID))

if is_dirty():
    rc = alert("Do you want to save the changes you made to “%s”?" % doc_name(),
               title="Unsaved Changes", level="caution", ok="Save", cancel="Don’t Save")
    log("close: alert rc=%r" % rc)
    if rc == 0:  # Save
        if get_original():
            # cleanup() deletes the working copy, so it may only run once the
            # save is known to have succeeded. On failure save_document has
            # already told the user why; leaving the temp dir and the pasteboard
            # state in place keeps the edits recoverable instead of discarding
            # them behind a dialog the user cannot act on.
            if save_document():
                cleanup()
        else:
            # New, unsaved: chain to Save As and let it clean up afterward.
            pb_set(PB_CLOSE_AFTER_SAVE, "1")
            cr = subprocess.run([NEXT_CMD, CMD_GUID, "Zip.save.as"], capture_output=True)
            log("close: chained Zip.save.as rc=%s err=%r"
                % (cr.returncode, (cr.stderr or b"").decode("utf-8", "replace").strip()))
            sys.exit(0)
    elif rc == 1:  # explicit "Don't Save" - the only answer that may discard
        cleanup()
    else:
        # The alert returns 2 for Other, 3 on timeout and -1/255 on error. None
        # of those is a decision to discard, so they must not delete the working
        # copy the way a plain `else: cleanup()` did.
        log("close: unexpected alert result %r - preserving working copy" % rc)
        offer_recovery(get_work(), "“%s” has unsaved changes." % doc_name())
else:
    cleanup()
