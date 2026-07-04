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
import sys
import shutil
import subprocess
import tempfile

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
QLMANAGE = "/usr/bin/qlmanage"   # Quick Look preview of an extracted entry

# --- View IDs (match Zip.json) -------------------------------------------
ID_TABLE = 10
ID_ADD_BTN = 31
ID_DELETE_BTN = 32
ID_EXTRACT_BTN = 33
ID_EXTRACT_ALL_BTN = 34
ID_QL_BTN = 35
ID_LOCK_MENU = 36
ID_UNLOCK = 37
ID_ENCRYPT = 38
ID_CHANGE_PW = 39
ID_FILTER = 40
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
            with open(_LOG, "a") as f:
                f.write(str(msg) + "\n")
        except OSError:
            pass


# --- Pasteboard -----------------------------------------------------------
def pb_get(key):
    r = subprocess.run([PASTEBOARD_TOOL, key, "get"], capture_output=True, text=True)
    return r.stdout.strip()


def pb_set(key, value):
    # Pass the value on stdin, never as an argv parameter, so secrets (the session
    # password in PB_PASSWORD) never appear in the process list. The pasteboard
    # tool reads stdin when given no value argument; empty stdin clears the entry.
    subprocess.run([PASTEBOARD_TOOL, key, "set"],
                   input=(value or "").encode("utf-8"), capture_output=True)


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
                   input=tsv_text.encode("utf-8"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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
def run_ziptool(*args, stdin=None, capture=True, stream_stdout=False):
    cmd = [PYTHON3, ZIPTOOL] + [str(a) for a in args]
    log("ziptool: %s" % " ".join(cmd))
    inp = stdin.encode("utf-8") if stdin else None
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
    pb_set(PB_PREFIX, prefix)
    r = run_ziptool("level", "--tsv", tsv_path(), "--prefix", prefix)
    feed_table((r.stdout or b"").decode("utf-8", "replace"))
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
    r = run_ziptool("find", "--tsv", tsv_path(), "--query", query)
    feed_table((r.stdout or b"").decode("utf-8", "replace"))
    set_breadcrumb("Filter: " + query)
    enable_view(ID_UP_BTN, False)
    enable_view(ID_EXTRACT_BTN, False)
    enable_view(ID_DELETE_BTN, False)
    clear_inspector()


def nav_up():
    prefix = pb_get(PB_PREFIX)
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
    enable_view(ID_QL_BTN, False)


# Source/config formats that file(1) reports under application/* but are really text.
TEXT_MIMES = {
    "application/json", "application/xml", "application/javascript",
    "application/x-sh", "application/x-shellscript", "application/x-csh",
    "application/x-perl", "application/x-python", "application/x-python-code",
    "application/x-ruby", "application/x-yaml", "application/x-yic",
    "application/x-tex", "application/x-php", "application/x-httpd-php",
    "application/toml", "application/x-ndjson", "application/sql",
}


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


def _is_text_mime(mime):
    return mime.startswith("text/") or mime in TEXT_MIMES


def describe_and_preview(fullpath, isdir, enc):
    """Set the Kind detail row + inline preview, and enable Quick Look for files.

    Detection is content-based via file(1) on a capped in-memory prefix read
    straight from the archive (no temp file) - so extensionless text such as
    README/Makefile/LICENSE previews, and binaries are named, not guessed.
    """
    enable_view(ID_QL_BTN, isdir != "1")   # Quick Look applies to real files
    if isdir == "1":
        set_value(ID_DET_KIND, "Folder")
        set_value(ID_PREVIEW, "(folder)")
        return
    # Encrypted entries preview inline once the session password is known (the
    # read is routed through ziptool, which uses the libarchive helper for AES).
    pw = pb_get(PB_PASSWORD)
    if enc == "1" and not pw:
        set_value(ID_DET_KIND, "Encrypted")
        set_value(ID_PREVIEW, "(encrypted - unlock to preview)")
        return
    read_args = ["read", active_archive(), "--entry", fullpath, "--max", "8192"]
    if pw:
        read_args.append("--pwd-stdin")
    r = run_ziptool(*read_args, stdin=(pw or None))
    if enc == "1" and r.returncode == 2:
        set_value(ID_DET_KIND, "Encrypted")
        set_value(ID_PREVIEW, "(encrypted - wrong password?)")
        return
    buf = r.stdout or b""
    mime, desc = _file_describe(buf)
    set_value(ID_DET_KIND, desc or mime or "-")
    if not buf or mime == "inode/x-empty":
        set_value(ID_PREVIEW, "(empty file)")
    elif _is_text_mime(mime):
        set_value(ID_PREVIEW, buf.decode("utf-8", "replace"))
    else:
        set_value(ID_PREVIEW, "(%s - use Quick Look to view)" % (mime or "binary file"))


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
    set_value(ID_FILTER, "")
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
    set_value(ID_FILTER, "")
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


def _status_summary(verb):
    try:
        with open(tsv_path(), "r", encoding="utf-8", errors="replace") as f:
            n = sum(1 for line in f if line.strip())
    except OSError:
        n = 0
    enc = pb_get(PB_ENC)
    # libarchive does not expose the cipher (AES vs ZipCrypto) on read, so the
    # status reports encryption generically.
    note = " - encrypted" if enc == "encrypted" else ""
    set_status("%s %s - %d entries%s" % (verb, doc_name(), n, note))


# --- Mutations ------------------------------------------------------------
def add_paths(paths, prefix=None):
    if prefix is None:
        prefix = pb_get(PB_PREFIX)

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
            r = run_ziptool("add", scratch, "--prefix", prefix, stdin="\n".join(paths))
            if r.returncode != 0:
                alert("Could not add the selected items.", level="caution")
                return
            # scratch is now mixed (existing encrypted + new plaintext); re-encrypt all
            # entries under the session password so none is left in the clear.
            rr = _run_recrypt(scratch, recrypted, "aes256", pw, pw)
            if rr.returncode != 0:
                log("encrypted add re-encrypt failed: %s"
                    % (rr.stderr or b"").decode("utf-8", "replace"))
                alert("Could not add the selected items.", level="caution")
                return
            os.replace(recrypted, work)   # atomic: working copy is fully encrypted again
        finally:
            for tmp in (scratch, recrypted):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    else:
        work = ensure_working_copy()
        r = run_ziptool("add", work, "--prefix", prefix, stdin="\n".join(paths))
        if r.returncode != 0:
            alert("Could not add the selected items.", level="caution")
            return

    mark_dirty()
    regenerate_model()
    populate_level(pb_get(PB_PREFIX))
    _status_summary("Added to")


def delete_selected():
    sel = pb_get(PB_SEL_PATH)
    isdir = pb_get(PB_SEL_ISDIR)
    if not sel:
        return
    work = ensure_working_copy()
    if isdir == "1":
        r = run_ziptool("delete", work, "--prefix", sel)
    else:
        r = run_ziptool("delete", work, "--entry", sel)
    if r.returncode != 0:
        alert("Could not delete the selected item.", level="caution")
        return
    mark_dirty()
    regenerate_model()
    populate_level(pb_get(PB_PREFIX))
    _status_summary("Updated")


# --- Saving ---------------------------------------------------------------
def save_document():
    """Save to the original path, or chain to Save As for an untitled document."""
    orig = get_original()
    if orig:
        work = get_work()
        if work and os.path.isfile(work):
            shutil.copy2(work, orig)
        mark_clean()
        regenerate_model()
        set_status("Saved %s" % os.path.basename(orig))
    else:
        subprocess.run([NEXT_CMD, CMD_GUID, "Zip.save.as"], capture_output=True)


def save_as(dest):
    if not dest.lower().endswith(".zip"):
        dest += ".zip"
    src = active_archive()
    if not src or not os.path.isfile(src):
        return False
    shutil.copy2(src, dest)
    pb_set(PB_ORIGINAL, dest)
    # The working copy (if any) now corresponds to dest; keep editing it.
    mark_clean()
    set_status("Saved %s" % os.path.basename(dest))
    return True


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

    args = ["extract", arc, "--dest", dest]
    if mode == "all":
        args.append("--all")
    elif pb_get(PB_SEL_ISDIR) == "1":
        args += ["--prefix", pb_get(PB_SEL_PATH)]
    else:
        args += ["--entry", pb_get(PB_SEL_PATH)]

    pw = pb_get(PB_PASSWORD)
    if enc == "encrypted" and not pw:
        subprocess.run([NEXT_CMD, CMD_GUID, "Zip.password.prompt"], capture_output=True)
        return

    set_status("Preparing Quick Look..." if mode == "quicklook" else "Extracting...")
    if pw:
        args.append("--pwd-stdin")
    # ziptool streams "file N of M" progress lines to stdout (parsed live by OMC's
    # PROGRESS) and writes its "<count>\t<top-level path created>" summary to this
    # result file. The path is Finder-style: auto-renamed if a same-name item
    # already existed.
    rf = tempfile.NamedTemporaryFile(prefix="zipresult-", delete=False)
    rf_path = rf.name
    rf.close()
    args += ["--result-file", rf_path]
    r = run_ziptool(*args, stdin=(pw or None), stream_stdout=True)
    rc = r.returncode
    count, root = 0, dest
    try:
        with open(rf_path, "r", encoding="utf-8") as f:
            parts = f.read().strip().split("\t")
        if len(parts) == 2 and parts[0].isdigit():
            count, root = int(parts[0]), parts[1]
    except OSError:
        pass
    finally:
        try:
            os.remove(rf_path)
        except OSError:
            pass
    if rc == 0:
        if mode == "quicklook":
            set_status("Quick Look: %s" % os.path.basename(root))
            subprocess.run([QLMANAGE, "-p", root], capture_output=True)
        else:
            if mode == "all":
                base = os.path.basename(arc)
                intended = base[:-4] if base.lower().endswith(".zip") else base
            else:
                intended = os.path.basename(pb_get(PB_SEL_PATH).rstrip("/"))
            msg = "Extracted %d item%s to %s" % (count, "" if count == 1 else "s", root)
            if os.path.basename(root) != intended:
                msg += "  (renamed to avoid overwriting)"
            set_status(msg)
            # Transient toast acknowledges the quick action and offers Reveal; no
            # notification (that is for background work the user has looked away from).
            pb_set(PB_EX_LAST, root)
            toast = "Extracted %d item%s" % (count, "" if count == 1 else "s")
            present_toast(toast, 6, "Show in Finder", "Zip.reveal")
    elif rc == 2:
        pb_set(PB_PASSWORD, "")
        set_status("Incorrect password.")
        subprocess.run([NEXT_CMD, CMD_GUID, "Zip.password.prompt"], capture_output=True)
    elif rc == 3:
        alert("This archive uses an unsupported compression or encryption method.", level="caution")
        set_status("Unsupported method.")
    else:
        alert("Extraction failed. See log for details.", level="caution")
        set_status("Extraction failed.")


# --- Quick Look -----------------------------------------------------------
def do_quicklook():
    """Extract the selected file entry to the document's preview scratch dir and
    open it in Quick Look (qlmanage -p). Reuses do_extract so the encrypted
    password chain (and AES rejection) is shared."""
    sel = pb_get(PB_SEL_PATH)
    if not sel or pb_get(PB_SEL_ISDIR) == "1":
        return
    pdir = preview_dir()
    shutil.rmtree(pdir, ignore_errors=True)   # only ever hold the current preview
    os.makedirs(pdir, exist_ok=True)
    pb_set(PB_EX_DEST, pdir)
    pb_set(PB_EX_MODE, "quicklook")
    do_extract()


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


def first_encrypted_entry():
    """Full path of the first encrypted file entry in the cached model, or None."""
    try:
        with open(tsv_path(), "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 6 and parts[1] == "0" and parts[5] == "1":
                    return parts[0]
    except OSError:
        pass
    return None


def validate_password(pw):
    """True if pw decrypts an encrypted entry (or nothing is encrypted)."""
    entry = first_encrypted_entry()
    if not entry:
        return True
    r = run_ziptool("read", active_archive(), "--entry", entry, "--max", "1",
                    "--pwd-stdin", stdin=pw)
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
    if r.returncode == 2:
        alert("Incorrect password.", level="caution")
        return False
    if r.returncode != 0:
        log("recrypt failed: %s" % (r.stderr or b"").decode("utf-8", "replace"))
        alert("Could not change the archive encryption.", level="caution")
        return False
    os.replace(dest, work)
    pb_set(PB_PASSWORD, new_pw if mode != "none" else "")
    mark_dirty()
    regenerate_model()          # re-probes encryption -> updates PB_ENC
    populate_level(pb_get(PB_PREFIX))
    refresh_lock_menu()
    return True
