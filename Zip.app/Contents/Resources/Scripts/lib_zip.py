"""Shared helpers for the Zip applet (document-based).

Model (mirrors ICEdit): each window is one document. We keep a working copy of
the archive in a per-window temp directory and track the on-disk original and a
dirty flag in the pasteboard, keyed by the document window UUID. Browsing and
extraction read the *active* archive (the working copy once it exists, else the
original). The working copy is created lazily on the first mutation so opening a
large archive for browsing costs no copy. Save writes the working copy back to
the original (or Save As to a chosen path).
"""

import os
import re
import sys
import shutil
import subprocess
import tempfile
import urllib.parse

# --- OMC environment ------------------------------------------------------
SUPPORT_PATH = os.environ.get("OMC_OMC_SUPPORT_PATH", "")
APP_BUNDLE = os.environ.get("OMC_APP_BUNDLE_PATH", "")
WINDOW_UUID = os.environ.get("OMC_ACTIONUI_WINDOW_UUID", "")
PARENT_UUID = os.environ.get("OMC_PARENT_DIALOG_GUID", "")
CMD_GUID = os.environ.get("OMC_CURRENT_COMMAND_GUID", "")
# Document window UUID — parent if running in a child dialog, else self.
DOCUMENT_UUID = PARENT_UUID or WINDOW_UUID

DIALOG_TOOL = os.path.join(SUPPORT_PATH, "omc_dialog_control")
NEXT_CMD = os.path.join(SUPPORT_PATH, "omc_next_command")
PASTEBOARD_TOOL = os.path.join(SUPPORT_PATH, "pasteboard")
ALERT_TOOL = os.path.join(SUPPORT_PATH, "alert")
NOTIFY_TOOL = os.path.join(SUPPORT_PATH, "notify")
PLISTER = os.path.join(SUPPORT_PATH, "plister")
PYTHON3 = os.path.join(APP_BUNDLE, "Contents/Library/Python/bin/python3")
ZIPTOOL = os.path.join(APP_BUNDLE, "Contents/Resources/Scripts/ziptool.py")
ARCHIVE_TOOL = os.path.join(APP_BUNDLE, "Contents/Helpers/archive")  # native libarchive helper (recrypt)
FILE_TOOL = "/usr/bin/file"      # type detection + human-readable Kind

# --- View IDs (match Zip.json) -------------------------------------------
ID_TABLE = 10
ID_ADD_BTN = 31
ID_DELETE_BTN = 32
ID_EXTRACT_BTN = 33
ID_EXTRACT_ALL_BTN = 34
ID_LOCK_MENU = 36
ID_UNLOCK = 37
ID_ENCRYPT = 38
ID_CHANGE_PW = 39
# No ID_FILTER. The search field is the window's "searchable" modifier, and that
# modifier takes only "prompt" and "actionID" - ActionUI gives it no id, so there
# is nothing for omc_dialog_control to address. Clearing it on load is therefore
# not expressible; a stale query stays in the box until the user clears it, and
# Zip.filter.changed restores the current folder as soon as it goes empty. This
# used to be ID_FILTER = 40, written to on every load, addressing nothing.
ID_REMOVE_ENC = 41
ID_UP_BTN = 50
ID_BREADCRUMB = 51
ID_DET_NAME = 60
ID_DET_PATH = 61
ID_DET_SIZE = 62
ID_DET_MOD = 63
ID_DET_ENC = 64
ID_DET_KIND = 65
ID_PREVIEW = 70
ID_STATUS = 80

# --- Pasteboard keys (per document) --------------------------------------
PB_WORK = "zip_work_%s" % DOCUMENT_UUID            # working-copy archive path (temp)
PB_ORIGINAL = "zip_original_%s" % DOCUMENT_UUID    # on-disk original ("" = untitled)
PB_DIRTY = "zip_dirty_%s" % DOCUMENT_UUID          # "1" if unsaved changes
PB_PREFIX = "zip_prefix_%s" % DOCUMENT_UUID        # current browse folder prefix
PB_SEL_PATH = "zip_sel_path_%s" % DOCUMENT_UUID
PB_SEL_ISDIR = "zip_sel_isdir_%s" % DOCUMENT_UUID
PB_ENC = "zip_enc_%s" % DOCUMENT_UUID              # plain | encrypted
PB_PASSWORD = "zip_pw_%s" % DOCUMENT_UUID          # session password (cleared on close)
PB_EX_DEST = "zip_ex_dest_%s" % DOCUMENT_UUID
PB_EX_MODE = "zip_ex_mode_%s" % DOCUMENT_UUID      # all | selected
PB_EX_LAST = "zip_ex_last_%s" % DOCUMENT_UUID      # last-extracted path (for toast "Show in Finder")
PB_CLOSE_AFTER_SAVE = "zip_close_after_save_%s" % DOCUMENT_UUID

TMP = os.environ.get("TMPDIR", "/tmp")
DEBUG = os.path.isfile(os.path.join(TMP, "zip_debug"))
_LOG = os.path.join(TMP, "zip_debug.log")


def log(msg):
    if DEBUG:
        try:
            with open(_LOG, "a", errors="surrogateescape") as f:
                f.write(str(msg) + "\n")
        except OSError:
            pass


# --- Pasteboard -----------------------------------------------------------
def pb_get(key):
    # Bytes in, decoded with surrogateescape: the selected entry path travels
    # through here, and a legacy CP437 / Shift-JIS name is not valid UTF-8. A
    # strict decode would raise, and errors="replace" would silently corrupt the
    # path so the entry could never be extracted or deleted.
    # rstrip("\n") only, never .strip(): a leading or trailing SPACE is a legal
    # zip name and common in Windows-authored archives, and stripping it made
    # " name.txt" collide with a sibling "name.txt" - so an action aimed at one
    # landed on the other. (The tool appends no trailing newline anyway.)
    r = subprocess.run([PASTEBOARD_TOOL, key, "get"], capture_output=True)
    return (r.stdout or b"").decode("utf-8", "surrogateescape").rstrip("\n")


def pb_set(key, value):
    # Pass the value on stdin, never as an argv parameter, so secrets (the session
    # password in PB_PASSWORD) never appear in the process list. The pasteboard
    # tool reads stdin when given no value argument; empty stdin clears the entry.
    subprocess.run([PASTEBOARD_TOOL, key, "set"],
                   input=(value or "").encode("utf-8", "surrogateescape"),
                   capture_output=True)


def path_encode(s):
    """Mirror of ziptool.path_encode - see path_decode for why paths cross these
    channels percent-encoded."""
    return urllib.parse.quote(s.encode("utf-8", "surrogateescape"), safe="/")


def path_decode(s):
    """Decode a path that came back from the table feed or the pasteboard.

    Both channels carry the percent-encoded form produced by ziptool's
    path_encode: they are UTF-8 only, and the encoding is what keeps two entries
    whose names differ only in a tab or a space from collapsing onto each other.
    Inverse of path_encode; leaves ordinary paths and the "__UP__" sentinel
    unchanged."""
    if not s:
        return s
    return urllib.parse.unquote_to_bytes(s).decode("utf-8", "surrogateescape")


def get_table_path(column=5):
    """The hidden fullpath column, decoded back to the exact stored bytes."""
    return path_decode(get_table_value(column))


def sel_path():
    """The selected entry's real path. PB_SEL_PATH holds the ENCODED form because
    the pasteboard tool cannot store invalid UTF-8 - it clears the key instead,
    which silently emptied the selection for legacy-named entries."""
    return path_decode(pb_get(PB_SEL_PATH))


def cur_prefix():
    """The current browse folder, decoded. Stored encoded for the same reason."""
    return path_decode(pb_get(PB_PREFIX))


# --- UI helpers -----------------------------------------------------------
def set_value(view_id, value):
    subprocess.run([DIALOG_TOOL, WINDOW_UUID, str(view_id), str(value)], capture_output=True)


def enable_view(view_id, enabled=True):
    cmd = "omc_enable" if enabled else "omc_disable"
    subprocess.run([DIALOG_TOOL, WINDOW_UUID, str(view_id), cmd], capture_output=True)


def show_view(view_id, visible=True):
    cmd = "omc_show" if visible else "omc_hide"
    subprocess.run([DIALOG_TOOL, WINDOW_UUID, str(view_id), cmd], capture_output=True)


def set_status(msg):
    set_value(ID_STATUS, msg)


def arc_location(p):
    """Finder-style in-archive path for the status bar: leading '/', no trailing
    slash; the archive root is '/'."""
    p = (p or "").rstrip("/")
    return "/" + p if p else "/"


def set_breadcrumb(msg):
    set_value(ID_BREADCRUMB, msg)


def set_window_title(title):
    subprocess.run([DIALOG_TOOL, WINDOW_UUID, "omc_window", title], capture_output=True)


def present_modal(resource, dismiss_action=None):
    """Present an ActionUI JSON resource (Base.lproj/<resource>.json) as a sheet on
    this window. The sheet's controls live in this window's pool, so their handlers
    run in this (main) window context."""
    cmd = [DIALOG_TOOL, WINDOW_UUID, "omc_window", "omc_present_modal", resource]
    if dismiss_action:
        cmd.append(dismiss_action)
    subprocess.run(cmd, capture_output=True)


def dismiss_modal():
    subprocess.run([DIALOG_TOOL, WINDOW_UUID, "omc_window", "omc_dismiss_modal"],
                   capture_output=True)


def present_toast(message, duration=6, action_title=None, action_id=None):
    """Show a transient toast on this window. If action_title and action_id are both
    given, the toast gets one inline button whose action_id is dispatched as a
    subcommand when tapped."""
    cmd = [DIALOG_TOOL, WINDOW_UUID, "omc_window", "omc_present_toast", message, str(duration)]
    if action_title and action_id:
        cmd += [action_title, action_id]
    subprocess.run(cmd, capture_output=True)


def feed_table(tsv_text):
    subprocess.run([DIALOG_TOOL, WINDOW_UUID, str(ID_TABLE), "omc_table_set_rows_from_stdin"],
                   input=tsv_text.encode("utf-8", "surrogateescape"),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def clear_table():
    subprocess.run([DIALOG_TOOL, WINDOW_UUID, str(ID_TABLE), "omc_table_remove_all_rows"], capture_output=True)


def alert(message, title="Zip", level="note", ok="OK", cancel=None, other=None):
    """Show a modal alert; return exit code (0 ok, 1 cancel, 2 other)."""
    cmd = [ALERT_TOOL, "--level", level, "--title", title, "--ok", ok]
    if cancel is not None:
        cmd += ["--cancel", cancel]
    if other is not None:
        cmd += ["--other", other]
    cmd.append(message)
    return subprocess.run(cmd).returncode


def notify(message, title="Zip"):
    subprocess.run([NOTIFY_TOOL, "--title", title, message], capture_output=True)


def get_table_value(column):
    return os.environ.get("OMC_ACTIONUI_TABLE_%d_COLUMN_%d_VALUE" % (ID_TABLE, column), "")


def get_view_value(view_id):
    return os.environ.get("OMC_ACTIONUI_VIEW_%d_VALUE" % view_id, "")


# --- ziptool wrapper ------------------------------------------------------
def run_ziptool(*args, stdin=None, capture=True, stream_stdout=False,
                discard_stdout=False):
    cmd = [PYTHON3, ZIPTOOL] + [str(a) for a in args]
    log("ziptool: %s" % " ".join(cmd))
    inp = stdin.encode("utf-8", "surrogateescape") if stdin else None
    if discard_stdout:
        # For reads done purely to verify (password checking): the helper streams
        # the entry to fd 1, so capturing it would buffer the whole entry in
        # memory for output nobody looks at.
        return subprocess.run(cmd, input=inp, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, text=False)
    if stream_stdout:
        # Let ziptool's stdout reach our own stdout (fd 1) untouched so OMC's
        # PROGRESS parser sees the live "file N of M" lines; capture stderr only.
        return subprocess.run(cmd, input=inp, stdout=None, stderr=subprocess.PIPE,
                              text=False)
    return subprocess.run(cmd, input=inp, capture_output=capture, text=False)


# --- Document state -------------------------------------------------------
def doc_dir():
    d = os.path.join(TMP, "zip-%s" % DOCUMENT_UUID)
    os.makedirs(d, exist_ok=True)
    return d


def tsv_path():
    return os.path.join(doc_dir(), "entries.tsv")


def work_zip_path(name):
    wd = os.path.join(doc_dir(), "work")
    os.makedirs(wd, exist_ok=True)
    return os.path.join(wd, name)


def preview_dir():
    """Per-document scratch dir for a single Quick Look extraction (under doc_dir,
    so cleanup() removes it on close)."""
    return os.path.join(doc_dir(), "preview")


def get_original():
    return pb_get(PB_ORIGINAL)


def get_work():
    return pb_get(PB_WORK)


def active_archive():
    """The archive to read/extract: the working copy if it exists, else the original."""
    w = get_work()
    if w and os.path.isfile(w):
        return w
    return get_original()


def is_dirty():
    return pb_get(PB_DIRTY) == "1"


def mark_dirty():
    pb_set(PB_DIRTY, "1")
    refresh_title()


def mark_clean():
    pb_set(PB_DIRTY, "")
    refresh_title()


def doc_name():
    orig = get_original()
    if orig:
        return os.path.basename(orig)
    w = get_work()
    return os.path.basename(w) if w else "Untitled"


def refresh_title():
    name = doc_name()
    set_window_title(("● " + name) if is_dirty() else name)


def ensure_working_copy():
    """Return a writable working-copy path, creating it on first mutation."""
    w = get_work()
    if w and os.path.isfile(w):
        return w
    orig = get_original()
    if orig and os.path.isfile(orig):
        dest = work_zip_path(os.path.basename(orig))
        shutil.copy2(orig, dest)
        pb_set(PB_WORK, dest)
        return dest
    # No original and no working copy -> make an empty untitled archive.
    dest = work_zip_path("Untitled.zip")
    run_ziptool("create", dest, "--force")
    pb_set(PB_WORK, dest)
    return dest


def regenerate_model():
    """Rebuild the cached entries.tsv from the active archive."""
    arc = active_archive()
    if not arc or not os.path.isfile(arc):
        open(tsv_path(), "w").close()
        return
    r = run_ziptool("list", arc)
    with open(tsv_path(), "wb") as f:
        f.write(r.stdout or b"")
    pb_set(PB_ENC, _probe(arc))


def _probe(arc):
    r = run_ziptool("probe", arc)
    return (r.stdout or b"").decode("utf-8", "replace").strip() or "plain"


# --- Population / navigation ---------------------------------------------
def populate_level(prefix):
    # Stored encoded: the pasteboard cannot hold invalid UTF-8, and an encoded
    # value also survives a folder name containing a tab or newline.
    pb_set(PB_PREFIX, path_encode(prefix))
    r = run_ziptool("level", "--tsv=%s" % tsv_path(), "--prefix=%s" % prefix)
    feed_table((r.stdout or b"").decode("utf-8", "surrogateescape"))
    if prefix:
        set_breadcrumb("/" + prefix)
        enable_view(ID_UP_BTN, True)
    else:
        set_breadcrumb("/")
        enable_view(ID_UP_BTN, False)
    enable_view(ID_EXTRACT_BTN, False)
    enable_view(ID_DELETE_BTN, False)
    clear_inspector()


def populate_filter(query):
    r = run_ziptool("find", "--tsv=%s" % tsv_path(), "--query=%s" % query)
    feed_table((r.stdout or b"").decode("utf-8", "surrogateescape"))
    set_breadcrumb("Filter: " + query)
    enable_view(ID_UP_BTN, False)
    enable_view(ID_EXTRACT_BTN, False)
    enable_view(ID_DELETE_BTN, False)
    clear_inspector()


def nav_up():
    prefix = cur_prefix()
    if not prefix:
        return
    inner = prefix.rstrip("/")
    parent = (inner.rsplit("/", 1)[0] + "/") if "/" in inner else ""
    populate_level(parent)


def clear_inspector():
    set_value(ID_DET_NAME, "-")
    set_value(ID_DET_KIND, "-")
    set_value(ID_DET_PATH, "-")
    set_value(ID_DET_SIZE, "-")
    set_value(ID_DET_MOD, "-")
    set_value(ID_DET_ENC, "-")
    set_value(ID_PREVIEW, "")


def _file_describe(buf):
    """Classify a byte prefix with file(1): returns (mime, human_description).
    Empty prefix -> ('inode/x-empty', 'empty'); file(1) missing -> ('', '')."""
    if not buf:
        return ("inode/x-empty", "empty")
    try:
        mime = subprocess.run([FILE_TOOL, "--mime-type", "--brief", "-"],
                              input=buf, capture_output=True).stdout.decode("utf-8", "replace").strip()
        desc = subprocess.run([FILE_TOOL, "--brief", "-"],
                              input=buf, capture_output=True).stdout.decode("utf-8", "replace").strip()
    except OSError:
        return ("", "")
    return (mime, desc)


def consume_result_file(path):
    """Parse ziptool's --result-file summary into (count, root, skipped, renamed),
    or None when it is missing or carries no count and path. The file is a
    throwaway both callers write only to read back once, so it is removed here -
    on every path, including a parse that raises.

    The fields are NUL-framed: the path field holds a user-chosen destination, and
    a TAB in a folder name split it across two fields, so `skipped` was read from
    the tail of the path and parsed as 0 - a partial extraction reported as
    complete. A path cannot contain NUL. The older tab-separated form is still
    accepted, including its shorter 2- and 3-field variants.

    Decoding is surrogateescape for the same reason the model file's is: an entry
    name need not be UTF-8, and a strict decode raised UnicodeDecodeError out of a
    caller that was only guarding against OSError.

    One parser for both callers on purpose - the preview pane kept reading the tab
    form after the writer moved to NUL and silently previewed nothing.
    """
    # newline="" disables universal-newline translation, which would rewrite a CR
    # in the path to LF and a CRLF to a single LF. The path field is the user's
    # chosen destination and a CR is legal in a folder name; translating it hands
    # back a path that does not exist, so "Show in Finder" answered a successful
    # extraction with "The extracted item is no longer there." Nothing in the
    # framing can survive the reader rewriting bytes underneath it.
    try:
        with open(path, "r", encoding="utf-8", errors="surrogateescape",
                  newline="") as f:
            raw = f.read()
    except OSError:
        return None
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    if "\0" in raw:
        # Every record the writer emits ends in NUL, so one that does not was cut
        # short mid-write. Taking the fields that did land would report a partial
        # extraction as a complete measurement and stash a truncated path for
        # "Show in Finder" - the exact failure this framing exists to prevent -
        # and it would do so by bypassing the no-summary branch that handles it.
        if not raw.endswith("\0"):
            return None
        parts = raw.split("\0")
        parts.pop()                       # trailing terminator, not a field
        # All four fields or none. Only the tab form ever had 2- and 3-field
        # variants to stay compatible with; a NUL record short of four fields was
        # cut at a field boundary, and reading what landed is the same wrong
        # answer as reading a record cut anywhere else.
        if len(parts) < 4:
            return None
    else:
        parts = raw.strip().split("\t")
    # An empty path field is no more usable than a missing one: it reaches the
    # reporting as "Extracted 5 items to " and puts "" in PB_EX_LAST for Reveal.
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1]:
        return None
    # isdigit() is not int()-safe: it is true for superscript and circled digits,
    # which int() rejects, and for a 4400-digit run, which trips CPython's
    # conversion limit. The writer only ever emits str(int), so this guards a
    # corrupt or foreign file rather than a reachable case - but the exception
    # would escape a caller that only expects a value back.
    try:
        count = int(parts[0])
        skipped = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 0
        renamed = int(parts[3]) if len(parts) >= 4 and parts[3].isdigit() else 0
    except ValueError:
        return None
    return (count, parts[1], skipped, renamed)


def extract_for_preview(entry, pw):
    """Quietly extract a single file entry to the per-document preview scratch
    dir and return the extracted file path, or None on failure. Only the current
    preview is ever held (the dir is wiped first). Unlike do_extract this shows
    no progress/toast and never triggers the password prompt - it is safe to call
    on every selection change to feed the inline Quick Look pane."""
    arc = active_archive()
    if not arc:
        return None
    pdir = preview_dir()
    shutil.rmtree(pdir, ignore_errors=True)   # only ever hold the current preview
    os.makedirs(pdir, exist_ok=True)
    rf = tempfile.NamedTemporaryFile(prefix="zipql-", delete=False)
    rf_path = rf.name
    rf.close()
    args = ["extract", arc, "--dest=%s" % pdir, "--entry=%s" % entry,
            "--result-file=%s" % rf_path]
    if pw:
        args.append("--pwd-stdin")
    r = run_ziptool(*args, stdin=(pw or None))
    summary = consume_result_file(rf_path)
    root = summary[1] if summary is not None else None
    # 5 is a partial extraction; for a single-entry preview it still means this
    # entry landed, so the preview is valid.
    #
    # A regular file and nothing else, checked WITHOUT following a link: exists()
    # follows, and a zip may legally store an entry that IS a symlink, which
    # libarchive restores as one. An entry named "readme.txt" pointing at
    # /etc/passwd or ~/.ssh/id_rsa would then be opened, described by file(1) and
    # rendered in the Quick Look pane - reading a file outside the archive from a
    # single click on an ordinary looking row.
    #
    # The directory case is not hypothetical either: an archive holding both a
    # file "foo" and an explicit "foo/" record makes ziptool reroute --entry to
    # prefix mode, so root comes back as a subtree while the row still looks like
    # a plain file. That path then raised IsADirectoryError on the read below and
    # handed a folder to the preview view. Preview shows the archive's own bytes
    # or nothing.
    if r.returncode not in (0, 5) or not root:
        return None
    if os.path.islink(root) or not os.path.isfile(root):
        return None
    return root


def describe_and_preview(fullpath, isdir, enc):
    """Set the Kind detail row and feed the inline native Quick Look pane.

    The selected entry is extracted on demand to a per-document scratch dir and
    handed to the QuickLook view (ID_PREVIEW) by file path. Kind is detected
    content-based via file(1) on the extracted bytes - so extensionless text such
    as README/Makefile/LICENSE is named, not guessed. Folders, and encrypted
    entries before the session password is known, clear the pane.
    """
    if isdir == "1":
        set_value(ID_DET_KIND, "Folder")
        set_value(ID_PREVIEW, "")
        return
    # Encrypted entries preview once the session password is known.
    pw = pb_get(PB_PASSWORD)
    if enc == "1" and not pw:
        set_value(ID_DET_KIND, "Encrypted")
        set_value(ID_PREVIEW, "")
        return
    path = extract_for_preview(fullpath, pw)
    if not path:
        # Extraction failed - on an encrypted entry this means a wrong password.
        set_value(ID_DET_KIND, "Encrypted" if enc == "1" else "-")
        set_value(ID_PREVIEW, "")
        return
    try:
        with open(path, "rb") as f:
            head = f.read(8192)
    except OSError:
        head = b""
    mime, desc = _file_describe(head)
    set_value(ID_DET_KIND, desc or mime or "-")
    set_value(ID_PREVIEW, path)


# --- Loading / creating documents ----------------------------------------
def is_zip(path):
    if not path or not os.path.isfile(path):
        return False
    r = run_ziptool("probe", path)
    return r.returncode == 0


def load_archive(path):
    """Open an existing archive for browsing (no working copy yet)."""
    pb_set(PB_ORIGINAL, path)
    pb_set(PB_WORK, "")
    pb_set(PB_DIRTY, "")
    pb_set(PB_PASSWORD, "")
    pb_set(PB_SEL_PATH, "")
    pb_set(PB_SEL_ISDIR, "")
    regenerate_model()
    populate_level("")
    enable_view(ID_EXTRACT_ALL_BTN, True)
    enable_view(ID_ADD_BTN, True)
    refresh_title()
    refresh_lock_menu()
    _status_summary("Opened")


def new_archive():
    """Create a new empty untitled document."""
    pb_set(PB_ORIGINAL, "")
    pb_set(PB_DIRTY, "")
    pb_set(PB_PASSWORD, "")
    pb_set(PB_SEL_PATH, "")
    pb_set(PB_SEL_ISDIR, "")
    dest = work_zip_path("Untitled.zip")
    run_ziptool("create", dest, "--force")
    pb_set(PB_WORK, dest)
    regenerate_model()
    populate_level("")
    enable_view(ID_EXTRACT_ALL_BTN, True)
    enable_view(ID_ADD_BTN, True)
    refresh_title()
    refresh_lock_menu()
    set_status("New archive - add files, then Save.")


def new_archive_with(content_path):
    """Create a new untitled document containing a dropped/opened file or folder."""
    new_archive()
    add_paths([content_path], prefix="")
    set_status("New archive from %s - Save to keep it." % os.path.basename(content_path.rstrip("/")))


MODEL_COLS = 7   # keep in sync with ziptool.MODEL_COLS


def _read_model_rows():
    """Parse the cached model file: MODEL_COLS NUL-terminated fields per record.
    Not line-based - a zip name may legally contain a newline."""
    try:
        with open(tsv_path(), "rb") as f:
            fields = f.read().split(b"\0")
    except OSError:
        return []
    if fields and fields[-1] == b"":
        fields.pop()
    return [[x.decode("utf-8", "surrogateescape") for x in fields[i:i + MODEL_COLS]]
            for i in range(0, len(fields) - (MODEL_COLS - 1), MODEL_COLS)]


def _added_under_other_names(r):
    """How many items ziptool had to store under a name of its own choosing.

    It prints one "stored as: <name>" line per item and a count at the end; the
    count is what we parse. Renaming is silent otherwise, and it is not
    cosmetic: a renamed entry does NOT replace an existing one of that name, so
    re-adding an edited file whose name has to change lands beside the old copy
    instead of over it.

    Anchored, and it keeps scanning: an entry can be NAMED "9 names changed to
    fit the archive", and matching that line loosely reported zero renames -
    exactly the silence this exists to prevent.

    split("\\n"), NOT splitlines(): splitlines also breaks on VT, FF, FS, GS, RS,
    NEL, U+2028 and U+2029, and repair folds only TAB, CR and LF - so a filename
    carrying any of those eight splits one stderr line into two and can forge a
    line of its own.

    And scanned BACKWARDS, because a name can still carry a real newline: the
    folder being added INTO is never repaired (repairing it would add to a new
    folder beside the one the user is looking at), so a folder whose stored name
    contains a newline puts one into the "stored as:" lines. Every line a name
    can forge is printed before this count, which ziptool emits last, so the
    LAST match is the true one. Taking the first let a crafted folder name
    report zero renames - the silence this exists to prevent."""
    for line in reversed((r.stderr or b"").decode("utf-8", "replace").split("\n")):
        m = re.fullmatch(r"(\d+) names? changed to fit the archive", line.rstrip("\r"))
        if m:
            return int(m.group(1))
    return 0


def _status_summary(verb, note=""):
    n = len(_read_model_rows())
    enc = pb_get(PB_ENC)
    # libarchive does not expose the cipher (AES vs ZipCrypto) on read, so the
    # status reports encryption generically.
    enc_note = " - encrypted" if enc == "encrypted" else ""
    set_status("%s %s - %d entries%s%s" % (verb, doc_name(), n, enc_note, note))


# --- Mutations ------------------------------------------------------------
def add_paths(paths, prefix=None):
    recrypted_note = False
    renamed_note = 0
    if prefix is None:
        prefix = cur_prefix()

    if pb_get(PB_ENC) == "encrypted":
        # Adding to an encrypted archive must preserve the all-or-nothing invariant:
        # Info-ZIP's fast in-place append would store the new entries UNENCRYPTED,
        # leaving a mixed archive. Instead append to a scratch copy, then re-encrypt
        # the whole thing with libarchive (correctness over speed for protected zips).
        # The working copy is swapped in only if BOTH steps succeed, so a failure can
        # never leave a half-encrypted working copy that a later Save would persist.
        pw = pb_get(PB_PASSWORD)
        if not pw:
            alert("Unlock this archive before adding files.", level="caution")
            return
        work = ensure_working_copy()
        scratch = work + ".addtmp"
        recrypted = scratch + ".recrypt"
        try:
            shutil.copy2(work, scratch)
            r = run_ziptool("add", scratch, "--prefix=%s" % prefix, stdin="\n".join(paths))
            if r.returncode != 0:
                alert("Could not add the selected items.", level="caution")
                return
            renamed_note = _added_under_other_names(r)
            # scratch is now mixed (existing encrypted + new plaintext); re-encrypt all
            # entries under the session password so none is left in the clear.
            rr = _run_recrypt(scratch, recrypted, "aes256", pw, pw)
            if rr.returncode != 0:
                log("encrypted add re-encrypt failed: %s"
                    % (rr.stderr or b"").decode("utf-8", "replace"))
                alert("Could not add the selected items.", level="caution")
                return
            os.replace(recrypted, work)   # atomic: working copy is fully encrypted again
            recrypted_note = True
        finally:
            for tmp in (scratch, recrypted):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    else:
        work = ensure_working_copy()
        r = run_ziptool("add", work, "--prefix=%s" % prefix, stdin="\n".join(paths))
        if r.returncode != 0:
            alert("Could not add the selected items.", level="caution")
            return
        renamed_note = _added_under_other_names(r)

    mark_dirty()
    regenerate_model()
    populate_level(cur_prefix())
    note = ""
    if recrypted_note:
        # The whole archive is rewritten as AES-256 regardless of what it was
        # before, so a ZipCrypto archive gets silently upgraded - a security
        # improvement, but a compatibility change worth saying out loud. Setting
        # this inside the branch above meant _status_summary overwrote it before
        # the user could read it.
        note += " - re-encrypted (AES-256)"
    if renamed_note:
        note += " - %d item%s stored under a different name" % (
            renamed_note, "" if renamed_note == 1 else "s")
    _status_summary("Added to", note=note)
    if renamed_note:
        # ziptool named each one on stderr (kept only when debug logging is on).
        # The alert is the part that matters: without it the sole evidence is an
        # entry appearing in the list under a name the user did not choose - and
        # re-adding an edited file whose name has to change does NOT replace the
        # old entry, it lands beside it, so silence here is genuinely misleading.
        log((r.stderr or b"").decode("utf-8", "replace"))
        # Cause-neutral on purpose: the count covers a folded tab or line break
        # AND the plainer case of two items wanting the same name, and naming
        # only the first would be wrong most of the time.
        alert("%d item%s could not be stored under %s own name - either the "
              "archive already had an item of that name, or the name contains a "
              "tab or a line break - so %s stored under a changed one. Check the "
              "list for the new name%s."
              % (renamed_note, "" if renamed_note == 1 else "s",
                 "its" if renamed_note == 1 else "their",
                 "it was" if renamed_note == 1 else "they were",
                 "" if renamed_note == 1 else "s"))


def delete_selected():
    sel = sel_path()
    isdir = pb_get(PB_SEL_ISDIR)
    if not sel:
        return
    work = ensure_working_copy()
    if isdir == "1":
        r = run_ziptool("delete", work, "--prefix=%s" % sel)
    else:
        r = run_ziptool("delete", work, "--entry=%s" % sel)
    # rc 5 means the archive WAS modified but not exactly as asked. Treating that
    # as a plain failure left the table showing rows that no longer exist and,
    # worse, skipped mark_dirty() - so closing the window silently discarded a
    # mutation the user had been told did not happen.
    if r.returncode not in (0, 5):
        log("delete failed: %s" % (r.stderr or b"").decode("utf-8", "replace"))
        alert("Could not delete the selected item.", level="caution")
        return
    mark_dirty()
    regenerate_model()
    populate_level(cur_prefix())
    if r.returncode == 5:
        detail = (r.stderr or b"").decode("utf-8", "replace").strip()
        log("partial delete: %s" % detail)
        alert("The archive was changed, but not exactly as requested. Check the "
              "contents before saving.\n\n%s" % detail.split("\n")[-1],
              level="caution")
        set_status("Delete completed with problems - check before saving.")
        return
    _status_summary("Updated")


# --- Saving ---------------------------------------------------------------
def _atomic_copy(src, dest):
    """Copy src onto dest without ever truncating dest in place.

    shutil.copy2 opens the destination "wb", so anything that interrupts the copy
    - ENOSPC, an I/O error, a crash, a force quit, loss of power - leaves the
    user's archive truncated and unrecoverable, with the only other instance of
    the data sitting in a temp dir that cleanup() is about to delete. Write a
    sibling temp file on the same volume and rename it into place instead: the
    rename is atomic, and any failure before it leaves the original intact
    byte for byte. Raises on failure; the caller reports it.

    The destination is resolved first: when the archive path is a symlink the
    file the user means is its target, and os.replace() would otherwise swap the
    LINK for a regular file and leave the real archive stale. copy2 followed the
    link, so resolving keeps that behavior while staying atomic. The temp file
    must be a sibling of the RESOLVED path, or the rename could cross volumes.

    Deliberate trade-offs of replacing rather than overwriting in place, all
    accepted because the alternative is a destroyed archive:
      * the destination gets a NEW inode, so a second hardlink to the archive
        keeps the old content, and extended attributes that lived on the old
        inode (Finder tags, Where From, quarantine) are not carried over;
      * a destination carrying a "deny delete" ACL, or one inside a read-only
        directory, now fails the save cleanly where copy2 would have succeeded
        by writing through the existing inode. The original survives and the
        caller reports the error, which is the right way round."""
    dest = os.path.realpath(dest)
    dest_dir = os.path.dirname(dest) or "."
    fd, tmp = tempfile.mkstemp(prefix=".zipsave-", suffix=".tmp", dir=dest_dir)
    try:
        # Write through the mkstemp fd and fsync before the rename: without it,
        # the rename can reach the disk ahead of the data, so a power loss could
        # leave a destination that exists but is empty - with the original inode
        # already gone. open(fd) takes ownership, so fd is not closed separately.
        with open(fd, "wb") as fdst, open(src, "rb") as fsrc:
            shutil.copyfileobj(fsrc, fdst)
            fdst.flush()
            os.fsync(fdst.fileno())
        shutil.copystat(src, tmp)
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def save_document():
    """Save to the original path, or chain to Save As for an untitled document.

    Returns True only when the document is safely on disk. Callers that discard
    the working copy afterwards (window close) MUST check it - a False return
    means the edits still exist only in the temp working copy."""
    orig = get_original()
    if not orig:
        # Untitled: omc_next_command only QUEUES Zip.save.as, so the save has not
        # happened yet. True here means "handed off", not "on disk" - callers must
        # not take it as licence to delete the working copy. Zip.window.close.py
        # is safe because it only reaches this branch behind `if get_original()`.
        subprocess.run([NEXT_CMD, CMD_GUID, "Zip.save.as"], capture_output=True)
        return True

    work = get_work()
    # An empty work path means the document was never mutated - nothing to write.
    # A work path whose file has vanished is an error: TMPDIR is purged
    # periodically, and silently skipping the copy here would mark the document
    # clean and report "Saved" while every edit is lost.
    if work and not os.path.isfile(work):
        log("save: working copy missing at %s" % work)
        alert("The unsaved changes to “%s” could not be found, so nothing was "
              "saved. The archive on disk is unchanged." % os.path.basename(orig),
              level="caution")
        set_status("Save failed - working copy missing.")
        # Deliberately NOT calling cleanup() here even though there is nothing
        # left to preserve: save_document also runs for a plain Cmd-S, where the
        # window stays open, and cleanup() clears the per-window pasteboard keys
        # that give the document its identity. Tearing that down under a live
        # window is worse than leaking a temp dir that is already empty.
        return False
    if not work and is_dirty():
        # Should be unreachable (every mark_dirty() follows ensure_working_copy),
        # but it is the same silent-success shape as the vanished-copy case, so
        # refuse rather than report a save that never wrote anything.
        log("save: document is dirty but has no working copy")
        alert("The unsaved changes to “%s” could not be found, so nothing was "
              "saved. The archive on disk is unchanged." % os.path.basename(orig),
              level="caution")
        set_status("Save failed - no working copy.")
        return False
    if work:
        try:
            _atomic_copy(work, orig)
        except OSError as e:
            log("save failed: %s" % e)
            # Name the working copy: the window is closing and cannot be vetoed,
            # so this path is the user's only route back to the edits.
            alert("Could not save “%s”.\n\n%s\n\nThe archive on disk is "
                  "unchanged. Your edited copy is at:\n%s"
                  % (os.path.basename(orig), e, work), level="caution")
            set_status("Save failed.")
            return False

    mark_clean()
    regenerate_model()
    set_status("Saved %s" % os.path.basename(orig))
    return True


def save_as(dest):
    if not dest.lower().endswith(".zip"):
        dest += ".zip"
        # NSSavePanel ran its overwrite check against the name the user typed,
        # not against this one. Appending the extension can land on a DIFFERENT
        # existing file that the user was never asked about - typing "backup"
        # when "backup.zip" exists silently replaced it. Ask now. lexists, so a
        # symlink occupying the name counts.
        if os.path.lexists(dest):
            if os.path.isdir(dest) and not os.path.islink(dest):
                alert("“%s” is a folder and cannot be replaced. Choose another name."
                      % os.path.basename(dest), title="Cannot Save", level="caution")
                set_status("Save cancelled - that name is a folder.")
                return False
            # _atomic_copy follows symlinks, so the file actually replaced may
            # live somewhere else entirely. Name what really gets overwritten.
            real = os.path.realpath(dest)
            what = os.path.basename(dest)
            if os.path.islink(dest):
                what = "%s (which points to %s)" % (os.path.basename(dest), real)
            if alert("“%s” already exists. Do you want to replace it?" % what,
                     title="Replace File", level="caution",
                     ok="Replace", cancel="Cancel") != 0:
                set_status("Save cancelled")
                return False
    # Same guard as save_document, and it matters more here: active_archive()
    # FALLS BACK to the original when the working copy is missing, so a purged
    # TMPDIR would silently write the unedited original to the new path and
    # report success - losing every edit in the one operation users reach for
    # when they want a safe second copy.
    work = get_work()
    if work and not os.path.isfile(work):
        log("save as: working copy missing at %s" % work)
        alert("The unsaved changes could not be found, so nothing was saved. "
              "Nothing was written to “%s”." % os.path.basename(dest),
              level="caution")
        set_status("Save failed - working copy missing.")
        return False
    src = active_archive()
    if not src or not os.path.isfile(src):
        log("save as: no readable source archive (%r)" % src)
        alert("There is nothing to save yet.", level="caution")
        set_status("Save failed - no archive data.")
        return False
    try:
        _atomic_copy(src, dest)
    except OSError as e:
        log("save as failed: %s" % e)
        alert("Could not save to “%s”.\n\n%s" % (os.path.basename(dest), e),
              level="caution")
        set_status("Save failed.")
        return False
    pb_set(PB_ORIGINAL, dest)
    # The working copy (if any) now corresponds to dest; keep editing it.
    mark_clean()
    set_status("Saved %s" % os.path.basename(dest))
    return True


def offer_recovery(path, message):
    """Point the user at a working copy that is about to be orphaned.

    Zip.window.close is the window's END_CANCEL_SUBCOMMAND_ID - a notification
    fired as the window goes away, not a veto - so a close cannot be called off.
    When the document was not saved, the honest move is to keep the working copy
    and say where it is; Reveal is the only practical way back to a TMPDIR path.
    Does nothing (so the caller can call it unconditionally) if there is no file
    left to point at."""
    if not path or not os.path.isfile(path):
        return
    # Say "temporary" plainly: this lives under TMPDIR, which macOS sweeps after
    # a few days. Promising a kept copy without that caveat would recreate the
    # very "purged TMPDIR = lost edits" trap that issue 4 was about.
    rc = alert("%s\n\nA temporary copy of your changes is here - move it "
               "somewhere safe to keep it:\n%s" % (message, path),
               title="Not Saved", level="caution", ok="Show in Finder", cancel="OK")
    if rc == 0:
        subprocess.run(["/usr/bin/open", "-R", path], capture_output=True)


def cleanup():
    d = os.path.join(TMP, "zip-%s" % DOCUMENT_UUID)
    shutil.rmtree(d, ignore_errors=True)
    for k in (PB_WORK, PB_ORIGINAL, PB_DIRTY, PB_PREFIX, PB_SEL_PATH, PB_SEL_ISDIR,
              PB_ENC, PB_PASSWORD, PB_EX_DEST, PB_EX_MODE, PB_EX_LAST, PB_CLOSE_AFTER_SAVE):
        pb_set(k, "")


# --- Extraction (shared by extract.selected/all and extract.run) ----------
def do_extract():
    arc = active_archive()
    dest = pb_get(PB_EX_DEST)
    mode = pb_get(PB_EX_MODE)
    enc = pb_get(PB_ENC)
    if not arc or not dest:
        return

    args = ["extract", arc, "--dest=%s" % dest]
    if mode == "all":
        args.append("--all")
    elif pb_get(PB_SEL_ISDIR) == "1":
        args += ["--prefix=%s" % sel_path()]
    else:
        args += ["--entry=%s" % sel_path()]

    pw = pb_get(PB_PASSWORD)
    if enc == "encrypted" and not pw:
        subprocess.run([NEXT_CMD, CMD_GUID, "Zip.password.prompt"], capture_output=True)
        return

    set_status("Extracting...")
    if pw:
        args.append("--pwd-stdin")
    # ziptool streams "file N of M" progress lines to stdout (parsed live by OMC's
    # PROGRESS) and writes its "<count> <top-level path> <skipped> <renamed>"
    # summary to this result file, NUL-framed. The path is Finder-style:
    # auto-renamed if a same-name item already existed.
    rf = tempfile.NamedTemporaryFile(prefix="zipresult-", delete=False)
    rf_path = rf.name
    rf.close()
    args += ["--result-file=%s" % rf_path]
    r = run_ziptool(*args, stdin=(pw or None), stream_stdout=True)
    rc = r.returncode
    # No summary means ziptool could not write one (its temp dir gone, disk full,
    # killed before the write) - NOT that nothing was extracted. The fallback
    # tuple below is a placeholder, never a measurement: presented as fact it
    # announces "Extracted 0 items" for a run that did place files, and at rc 5 it
    # states skipped == 0 when rc 5 is the helper's own word that entries were
    # rejected - the one thing the reporting here exists to never do.
    summary = consume_result_file(rf_path)
    count, root, skipped, renamed = summary if summary is not None else (0, dest, 0, 0)
    # rc 5 means a PARTIAL extraction: entries were rejected (unsafe path, name
    # collision) but everything else is on disk and placed. Report it as a
    # success that names its own shortfall - never as a clean, complete run.
    if rc in (0, 5) and summary is None:
        # Report only what rc still proves: the extraction ran, and at 5 it left
        # entries behind. The count, the skipped total and the placed path are all
        # unknown here, so none of them is stated as fact - and the rename note
        # below cannot be judged either, since it compares a path we do not have.
        set_status("Extracted to %s%s"
                   % (root, " - some entries were skipped" if rc == 5 else ""))
        pb_set(PB_EX_LAST, root)
        present_toast("Extracted" + (", some entries skipped" if rc == 5 else ""),
                      6, "Show in Finder", "Zip.reveal")
        log("extract: no result summary (rc=%s): %s"
            % (rc, (r.stderr or b"").decode("utf-8", "replace")))
        if rc == 5:
            # The whole destination, not its basename: root is the chosen folder
            # rather than a placed item here, and that path comes from the folder
            # chooser unnormalized - a trailing slash made basename() return "",
            # so the alert named nothing at all. It is also the more useful of the
            # two when the placed item's own name is what we failed to learn.
            alert("Some entries could not be extracted. The rest was extracted to %s"
                  % root, level="caution")
    elif rc in (0, 5):
        if mode == "all":
            base = os.path.basename(arc)
            intended = base[:-4] if base.lower().endswith(".zip") else base
        else:
            intended = os.path.basename(sel_path().rstrip("/"))
        msg = "Extracted %d item%s to %s" % (count, "" if count == 1 else "s", root)
        if os.path.basename(root) != intended:
            msg += "  (renamed to avoid overwriting)"
        if skipped:
            msg += "  - %d entr%s skipped" % (skipped, "y" if skipped == 1 else "ies")
        if renamed:
            msg += "  - %d name%s changed" % (renamed, "" if renamed == 1 else "s")
        set_status(msg)
        # Transient toast acknowledges the quick action and offers Reveal; no
        # notification (that is for background work the user has looked away from).
        pb_set(PB_EX_LAST, root)
        toast = "Extracted %d item%s" % (count, "" if count == 1 else "s")
        if skipped:
            toast += ", %d skipped" % skipped
        present_toast(toast, 6, "Show in Finder", "Zip.reveal")
        if skipped or renamed:
            # The helper named each rejected and each repaired entry on stderr.
            # log() only writes when debug logging is switched on, so this is a
            # diagnostic aid rather than the user's answer to "which ones?" -
            # for a rename that answer is the extracted folder itself, which is
            # why the alert below points at it by name.
            log((r.stderr or b"").decode("utf-8", "replace"))
        # A rename is not a failure - those files ARE on disk - but they are not
        # under the name the archive lists, so saying nothing leaves the user
        # looking for something that is not there. It must be said even when
        # something was also skipped, so the two are one message rather than a
        # branch where the rarer news is swallowed by the louder.
        if skipped or renamed:
            notes = []
            if skipped:
                notes.append("%d entr%s could not be extracted"
                             % (skipped, "y" if skipped == 1 else "ies"))
            if renamed:
                # Cause-neutral: this count covers a name the filesystem cannot
                # hold, a name two entries both wanted, and an entry whose name
                # the archive did not record at all.
                notes.append("%d item%s could not be written under the name the "
                             "archive lists and %s renamed"
                             % (renamed, "" if renamed == 1 else "s",
                                "was" if renamed == 1 else "were"))
            tail = ("The rest was extracted to “%s”." if skipped
                    else "They are in “%s”.") % os.path.basename(root)
            alert("%s. %s" % ("; ".join(notes), tail),
                  level="caution" if skipped else "note")
    elif rc == 2:
        pb_set(PB_PASSWORD, "")
        set_status("Incorrect password.")
        subprocess.run([NEXT_CMD, CMD_GUID, "Zip.password.prompt"], capture_output=True)
    elif rc == 3:
        alert("This archive uses an unsupported compression or encryption method.", level="caution")
        set_status("Unsupported method.")
    else:
        # stream_stdout captures the helper's stderr into r.stderr; without this
        # the "see log" advice pointed at a log that never received anything.
        log("extract failed (rc=%s): %s"
            % (rc, (r.stderr or b"").decode("utf-8", "replace")))
        alert("Extraction failed. See log for details.", level="caution")
        set_status("Extraction failed.")


# --- Encryption (unlock / encrypt / change password / remove) -------------
def refresh_lock_menu():
    """Enable the Lock-menu items that apply to the archive's current state."""
    enc = pb_get(PB_ENC)
    is_enc = (enc == "encrypted")
    unlocked = bool(pb_get(PB_PASSWORD))
    enable_view(ID_UNLOCK, is_enc and not unlocked)
    enable_view(ID_ENCRYPT, enc == "plain")
    enable_view(ID_CHANGE_PW, is_enc and unlocked)
    enable_view(ID_REMOVE_ENC, is_enc and unlocked)


# Above this size the check falls back to the format's verification byte. Set
# high deliberately: for a STORED (uncompressed) entry that fallback is still
# ~1/256 on ZipCrypto, and stored is exactly what large entries are - jpg, mp4,
# nested zips - so a low cap missed the archives it was meant to help. A full
# read plus CRC of a 4 MB AES entry measures 0.08 s, so the ceiling can be high.
VALIDATE_FULL_READ_MAX = 256 * 1024 * 1024


# CRC-32 only reaches full strength at 4 bytes, and a ZERO-byte entry's CRC is 0
# - it matches any key, so reading one "in full" proves nothing beyond the
# format's check byte. Entries below this are never chosen as the validation
# target when a better one exists.
MIN_VERIFIABLE_SIZE = 4


def first_encrypted_entry():
    """(path, size) of the encrypted entry that is cheapest to read AMONG THOSE A
    FULL READ ACTUALLY VERIFIES, or (None, 0).

    Picking the plain smallest entry defeated the whole point: it lands on the
    0-byte .gitkeep / empty __init__.py that most trees contain, whose CRC check
    is vacuous - measured at 14 wrong passwords accepted out of 2999. Entries
    below MIN_VERIFIABLE_SIZE, and rows whose size will not parse, are kept only
    as a last resort."""
    best, best_size = None, None
    fallback, fallback_size = None, 0
    for parts in _read_model_rows():
        if len(parts) < 6 or parts[1] != "0" or parts[5] != "1":
            continue
        try:
            size = int(parts[2])
        except (TypeError, ValueError):
            size = None            # unknown: must never win the comparison
        if size is not None and size >= MIN_VERIFIABLE_SIZE:
            if best is None or size < best_size:
                best, best_size = parts[0], size
        elif fallback is None:
            fallback, fallback_size = parts[0], size or 0
    if best is not None:
        return (best, best_size)
    return (fallback, fallback_size) if fallback else (None, 0)


def validate_password(pw):
    """True if pw decrypts an encrypted entry (or nothing is encrypted).

    Reads the chosen entry IN FULL so libarchive verifies the CRC (and, for
    WinZip AES, the HMAC). Reading a single byte only exercised the format's
    verification byte, which is 1 byte for ZipCrypto - so roughly 1 wrong
    password in 256 was accepted, the app reported "unlocked", and the failure
    surfaced later as a confusing extraction error. Entries above
    VALIDATE_FULL_READ_MAX keep the cheap check rather than stall the UI."""
    entry, size = first_encrypted_entry()
    if not entry:
        return True
    args = ["read", active_archive(), "--entry=%s" % entry, "--pwd-stdin"]
    if size > VALIDATE_FULL_READ_MAX:
        args.append("--max=1")
    # stdout goes to /dev/null: this reads for verification, not for content.
    r = run_ziptool(*args, stdin=pw, discard_stdout=True)
    return r.returncode == 0


def _run_recrypt(src, dest, mode, old_pw, new_pw):
    """Low-level libarchive recrypt: rewrite src -> dest in the given mode
    ('aes256' or 'none'). old_pw / new_pw are each either a string (that side is
    needed; handed to the helper on stdin, never argv) or None (omit that side).
    Returns the CompletedProcess so callers map the exit code (2 = wrong/needed
    password)."""
    cmd = [ARCHIVE_TOOL, "recrypt", src, dest, "--mode", mode]
    parts = []
    if old_pw is not None:
        cmd.append("--old-pwd-stdin")
        parts.append(old_pw.encode("utf-8"))
    if new_pw is not None:
        cmd.append("--new-pwd-stdin")
        parts.append(new_pw.encode("utf-8"))
    return subprocess.run(cmd, input=b"\0".join(parts), capture_output=True)


def do_recrypt(mode, new_pw):
    """Rewrite the working copy with a new encryption mode via the archive helper.
    mode is 'aes256' (encrypt / change password) or 'none' (remove). Old and new
    passwords go to the helper on stdin (never argv). Returns True on success."""
    work = ensure_working_copy()
    enc = pb_get(PB_ENC)
    old_pw = pb_get(PB_PASSWORD)
    dest = work + ".recrypt"
    r = _run_recrypt(work, dest, mode,
                     old_pw if enc == "encrypted" else None,
                     new_pw if mode != "none" else None)
    if r.returncode != 0:
        # A failed recrypt leaves a partial <work>.recrypt behind; the helper
        # writes as it goes and cannot unwind. Remove it rather than leaving a
        # truncated archive next to the working copy.
        try:
            os.remove(dest)
        except OSError:
            pass
        if r.returncode == 2:
            alert("Incorrect password.", level="caution")
            return False
        log("recrypt failed: %s" % (r.stderr or b"").decode("utf-8", "replace"))
        alert("Could not change the archive encryption.", level="caution")
        return False
    os.replace(dest, work)
    pb_set(PB_PASSWORD, new_pw if mode != "none" else "")
    mark_dirty()
    regenerate_model()          # re-probes encryption -> updates PB_ENC
    populate_level(cur_prefix())
    refresh_lock_menu()
    return True
