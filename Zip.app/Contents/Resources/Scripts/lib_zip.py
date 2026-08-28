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
# The Preview pane's own indicator: a spinner centered OVER the QuickLook view,
# in a ZStack with it. Pulling one entry out of a large archive is seconds of
# work, and the pane sat showing the PREVIOUS selection's contents throughout -
# so a click read as "nothing happened" until it suddenly did. A spinner rather
# than the status row's bar because this is a content pane, not a strip: the
# right shape here is something centered in the space being filled.
ID_PREVIEW_BUSY = 71
ID_STATUS = 80
# The status row's two progress indicators. The test suite imports these by
# reading bare "ID_NAME = <digits>" lines out of this file, so the note goes
# above rather than at the end of the line: a trailing comment does not match
# and the name silently arrives empty.
# 82 is determinate (a linear bar), 83 indeterminate (a small spinner).
ID_PROGRESS_BAR = 82
# The part of the progress message that CHANGES WIDTH as the work runs - the
# percentage, or the running scan tally. It sits AFTER the indicator, so its
# width cannot move the indicator; everything to the indicator's left stays the
# same string for the whole phase. Padding the numbers instead did not work: a
# space is narrower than a digit in a proportional font, so the text still grew
# and the bar still walked sideways.
ID_PROGRESS_DETAIL = 84

# --- Pasteboard keys (per document) --------------------------------------
PB_WORK = "zip_work_%s" % DOCUMENT_UUID            # working-copy archive path (temp)
PB_ORIGINAL = "zip_original_%s" % DOCUMENT_UUID    # on-disk original ("" = untitled)
PB_DIRTY = "zip_dirty_%s" % DOCUMENT_UUID          # "1" if unsaved changes
PB_PREFIX = "zip_prefix_%s" % DOCUMENT_UUID        # current browse folder prefix
PB_SEL_PATH = "zip_sel_path_%s" % DOCUMENT_UUID
PB_SEL_ISDIR = "zip_sel_isdir_%s" % DOCUMENT_UUID
PB_ENC = "zip_enc_%s" % DOCUMENT_UUID              # plain | encrypted
PB_COUNT = "zip_count_%s" % DOCUMENT_UUID          # entries in the cached model
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


# --- Progress -------------------------------------------------------------
# The bar lives in the window's status row rather than in a PROGRESS dialog.
# OMC's PROGRESS panel is the documented mechanism and it does raise a dialog,
# but on OMC 5.2.0 that dialog never closes: it was still on screen minutes
# after the task ended, both on a command of ours and on the untouched
# Zip.extract.run, and a second run stacks a second panel. A three-minute
# compression that ends by leaving a dead window behind is worse than no
# progress at all, so the applet drives its own indicator, which it can also
# retire on every exit path.


# One element for every phase, because ActionUI's ProgressView can now be told
# to be LINEAR in both states (progressViewStyle, added for this). It is
# declared with that style and NO "value", so it starts indeterminate - an
# animated bar rather than a spinner - and a numeric progress state turns it
# determinate. Before the style existed an indeterminate ProgressView was a
# circular spinner for life, which forced either a second element (whose hidden
# slot still reserved the bar's width, stranding the spinner in a gap, because
# hidden does not collapse layout) or a bar sitting flat at zero through every
# phase that cannot be counted.


def show_bar(fraction=None):
    """Reveal the status-row bar. `fraction` None leaves it indeterminate, which
    now still moves - so a phase with nothing to count shows activity rather
    than an empty track."""
    set_progress(fraction)
    show_view(ID_PROGRESS_BAR, True)


def set_progress(fraction):
    """Move the bar, or None to return it to indeterminate.

    "null" for that, which the element reads as no progress. It is also
    belt-and-braces: were the tool ever to store it as the STRING "null", the
    Swift side's `states["progress"] as? Double` would still come back nil, and
    with no "value" in the JSON there is nothing behind it to fall back to - so
    the element ends up indeterminate either way."""
    if fraction is None:
        value = "null"
    else:
        value = repr(min(max(float(fraction), 0.0), 1.0))
    subprocess.run([DIALOG_TOOL, WINDOW_UUID, str(ID_PROGRESS_BAR),
                    "omc_set_state", "progress", value], capture_output=True)


def set_progress_detail(text):
    """The changing half of the message, to the right of the indicator."""
    set_value(ID_PROGRESS_DETAIL, text)


def hide_progress():
    """Retire the bar and the detail label. Must run on every exit path from a
    long operation, including the failures - one left behind says the work is
    still going, which is the confusion this whole change exists to remove."""
    show_view(ID_PROGRESS_BAR, False)
    set_progress_detail("")


def show_preview_busy(busy=True):
    """The Preview pane's spinner. Indeterminate: reading one entry out of a zip
    gives no progress to report - libarchive walks the archive until it reaches
    it - so there is a duration but never a fraction.

    It spins over an empty pane: describe_and_preview clears the previous
    selection before starting, so what is on screen for those seconds is the new
    row's details and a spinner, never the old row's contents."""
    show_view(ID_PREVIEW_BUSY, busy)


def grouped(n):
    """1234567 -> "1,234,567". Six-figure item counts are unreadable without it."""
    return "{:,}".format(n)


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
                discard_stdout=False, stdout_file=None):
    cmd = [PYTHON3, ZIPTOOL] + [str(a) for a in args]
    log("ziptool: %s" % " ".join(cmd))
    inp = stdin.encode("utf-8", "surrogateescape") if stdin else None
    if discard_stdout:
        # For reads done purely to verify (password checking): the helper streams
        # the entry to fd 1, so capturing it would buffer the whole entry in
        # memory for output nobody looks at.
        return subprocess.run(cmd, input=inp, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, text=False)
    if stdout_file is not None:
        # Straight into a file: the preview writes an entry's bytes out without
        # ever holding them in this process, which capture_output would.
        return subprocess.run(cmd, input=inp, stdout=stdout_file,
                              stderr=subprocess.PIPE, text=False)
    if stream_stdout:
        # Let ziptool's stdout reach our own stdout (fd 1) untouched so OMC's
        # PROGRESS parser sees the live "file N of M" lines; capture stderr only.
        return subprocess.run(cmd, input=inp, stdout=None, stderr=subprocess.PIPE,
                              text=False)
    return subprocess.run(cmd, input=inp, capture_output=capture, text=False)


def run_ziptool_watched(*args, stdin=None, on_line=None):
    """Run ziptool, handing each stdout line to on_line AS IT ARRIVES.

    Returns the same shape as run_ziptool - a CompletedProcess with returncode
    and stderr - so callers read the outcome unchanged.

    stderr goes to a temp FILE, never a pipe. ziptool prints a line per renamed
    item with no matching stdout, so a filled stderr pipe would deadlock against
    this read loop, which is the same trap cmd_extract avoids on its side."""
    cmd = [PYTHON3, ZIPTOOL] + [str(a) for a in args]
    log("ziptool: %s" % " ".join(cmd))
    errf = tempfile.TemporaryFile()
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=errf)
        try:
            if stdin:
                proc.stdin.write(stdin.encode("utf-8", "surrogateescape"))
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass    # child exited early; the return code below reports it
        for line in proc.stdout:
            if on_line:
                on_line(line.decode("utf-8", "replace").rstrip("\r\n"))
        rc = proc.wait()
        errf.seek(0)
        err = errf.read()
    finally:
        errf.close()
    return subprocess.CompletedProcess(cmd, rc, b"", err)


# ziptool's progress contract: "<Verb> file <n> of <m>" for a countable phase,
# "Scanning: <n> items found" for the walk, which has no total until it ends.
# The scan is a phase like any other, but it has no total to key on.
_SCANNING = ("Scanning", None)

_PROGRESS_LINE = re.compile(r"^([A-Za-z]+) file (\d+) of (\d+)$")
_SCAN_LINE = re.compile(r"^Scanning: (\d+) items found$")


def progress_reporter():
    """A ziptool stdout line handler that drives the status row.

    Pushes an update only when the whole percentage changes: each one is a
    subprocess spawn, and a six-figure add would otherwise spend minutes
    launching omc_dialog_control to redraw the same pixel.

    Keyed on the phase as well as the percentage. On the percentage alone, a
    staging phase that ended at 100% silenced the whole of the compression phase
    that starts again at 0 - so the slowest part of the operation, the one this
    exists for, reported nothing at all. A phase change always reports, whatever
    the percentage, because it rewrites the fixed half of the message too."""
    # The phase is (verb, total) rather than the verb alone: the closing line of
    # a phase can report a total different from the one its earlier lines used
    # (items skipped during staging), and that is a new fixed string to show.
    phase = [None]
    pct_shown = [-1]

    def report(line):
        m = _PROGRESS_LINE.match(line)
        if m:
            verb, n, total = m.group(1), int(m.group(2)), int(m.group(3))
            pct = int(n * 100 / total) if total else 0
            if (verb, total) != phase[0]:
                # Split either side of the indicator. What is to its LEFT names
                # the phase and its total and does not change again until the
                # phase does - so the indicator cannot move while the work runs.
                # What DOES change goes to its right, where growing by a
                # character pushes nothing but empty space. Padding the numbers
                # instead did not work: a space is narrower than a digit in a
                # proportional font, so the text still grew.
                phase[0] = (verb, total)
                pct_shown[0] = -1
                set_status("%s %s items" % (verb, grouped(total)))
            elif pct == pct_shown[0]:
                return
            pct_shown[0] = pct
            set_progress(pct / 100.0)
            set_progress_detail("%d%%" % pct)
            return
        m = _SCAN_LINE.match(line)
        if m:
            # The walk cannot say how far along it is - finding the total IS the
            # work - so the bar stays indeterminate and the tally, which is the
            # part that grows, goes to the right of it.
            if phase[0] != _SCANNING:
                phase[0] = _SCANNING
                set_status("Scanning for items")
            set_progress_detail("%s found" % grouped(int(m.group(1))))
    return report


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
    """Rebuild the cached entries.tsv from the active archive.

    Returns the entry count, or None when the archive could not be read - the
    caller must then not present it as an open document.

    One pass over the archive, not three. Opening used to cost a full read of
    the central directory for `is_zip`, another to build this model, and a third
    for a separate `probe` to answer the one yes/no question the model already
    contains - then a fourth parse of the 34 MB model just to count its rows for
    the status line. On the archive that prompted this (180k entries) that was
    the whole of the delay the window sat blank for."""
    arc = active_archive()
    if not arc or not os.path.isfile(arc):
        open(tsv_path(), "w").close()
        pb_set(PB_COUNT, "0")
        pb_set(PB_ENC, "plain")
        return 0
    r = run_ziptool("list", arc)
    if r.returncode != 0:
        log("list failed (rc=%s): %s"
            % (r.returncode, (r.stderr or b"").decode("utf-8", "replace")))
        open(tsv_path(), "w").close()
        pb_set(PB_COUNT, "")
        return None
    with open(tsv_path(), "wb") as f:
        f.write(r.stdout or b"")
    count, enc = _model_facts(r.stderr)
    pb_set(PB_COUNT, "" if count is None else str(count))
    pb_set(PB_ENC, enc)
    return count or 0


def _model_facts(stderr):
    """(entry count, "plain"|"encrypted") as ziptool reported them alongside the
    model it just wrote. Scanned backwards and matched whole-line, for the same
    reason _added_under_other_names is: take the LAST answer, never a line that
    merely contains one."""
    count, enc = None, None
    for line in reversed((stderr or b"").decode("utf-8", "replace").split("\n")):
        line = line.rstrip("\r")
        if count is None:
            m = re.fullmatch(r"entries (\d+)", line)
            if m:
                count = int(m.group(1))
        if enc is None:
            m = re.fullmatch(r"encryption (plain|encrypted)", line)
            if m:
                enc = m.group(1)
        if count is not None and enc is not None:
            break
    # An unreadable or truncated report must not silently downgrade an encrypted
    # archive to "plain" - that would enable Encrypt on an archive that already
    # has a password and hide Unlock. Absent is treated as plain only because
    # ziptool prints the line unconditionally, so absent means no model at all.
    return count, enc or "plain"


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


def _preview_filename(entry):
    """A filename of OUR choosing for the preview scratch dir.

    The basename only, so no part of the archive's path can steer where the file
    lands, and every character the filesystem or a path could choke on is folded
    to "_" - separators, control characters, and the lone surrogates a non-UTF-8
    archive name arrives as. The EXTENSION is what survives and what matters:
    QuickLook picks its renderer from it.
    """
    base = os.path.basename(entry.rstrip("/"))
    safe = "".join("_" if (ch in "/\\\0" or ord(ch) < 32 or "\ud800" <= ch <= "\udfff")
                   else ch for ch in base)
    # A name that folded away to nothing, or to dots, is not a filename.
    return (safe[:200] if safe.strip(". ") else "preview")


def extract_for_preview(entry, pw):
    """Write one entry's bytes into the per-document preview scratch dir and
    return the path, or None on failure. Only the current preview is ever held
    (the dir is wiped first). Shows no toast and never triggers the password
    prompt - it is safe to call on every selection change.

    Reads the entry directly instead of going through `extract`, which lists the
    WHOLE archive first - once to total the files for progress, once more to
    spot an entry that is really a directory. On the archive that prompted this
    (181,665 entries) that listing was 4.5 of the 7.0 seconds every single click
    on a row cost, for a 4 KB file. Nothing here needs it: the caller already
    knows from the model whether the row is a directory, and a preview has no
    progress to total. The remaining ~2.5 s is libarchive walking the archive to
    reach the entry, which is the read itself.

    Two hazards the old extract path had to guard against are gone rather than
    guarded: the bytes land under a name this function chooses, so a preview
    cannot be made to write outside the scratch dir, and an entry that IS a
    symlink is written as a regular file holding its target text instead of
    being restored as a link and then opened - which would have read a file
    outside the archive from a single click on an ordinary looking row.
    """
    arc = active_archive()
    if not arc:
        return None
    pdir = preview_dir()
    shutil.rmtree(pdir, ignore_errors=True)   # only ever hold the current preview
    try:
        os.makedirs(pdir, exist_ok=True)
    except OSError as e:
        log("preview: cannot make %s: %s" % (pdir, e))
        return None
    dest = os.path.join(pdir, _preview_filename(entry))
    args = ["read", arc, "--entry=%s" % entry]
    if pw:
        args.append("--pwd-stdin")
    try:
        with open(dest, "wb") as out:
            r = run_ziptool(*args, stdin=(pw or None), stdout_file=out)
    except OSError as e:
        log("preview: cannot write %s: %s" % (dest, e))
        return None
    if r.returncode != 0:
        # Wrong password, an unreadable entry, a method the helper cannot decode.
        log("preview read failed (rc=%s): %s"
            % (r.returncode, (r.stderr or b"").decode("utf-8", "replace")))
        return None
    return dest


def describe_and_preview(fullpath, isdir, enc):
    """Set the Kind detail row and feed the inline native Quick Look pane.

    The selected entry is extracted on demand to a per-document scratch dir and
    handed to the QuickLook view (ID_PREVIEW) by file path. Kind is detected
    content-based via file(1) on the extracted bytes - so extensionless text such
    as README/Makefile/LICENSE is named, not guessed. Folders, and encrypted
    entries before the session password is known, clear the pane.
    """
    # Cleared FIRST, before anything that takes time, and on every path out of
    # here. Left until the new bytes arrived, the pane went on showing the
    # PREVIOUS selection - which on a large archive is seconds of the wrong file
    # displayed beside the right one's name, size and path in the inspector.
    # Whether the row that follows is a folder, a locked entry or a file that
    # takes two seconds to read, the honest thing to show meanwhile is nothing.
    set_value(ID_PREVIEW, "")
    if isdir == "1":
        set_value(ID_DET_KIND, "Folder")
        return
    # Encrypted entries preview once the session password is known.
    pw = pb_get(PB_PASSWORD)
    if enc == "1" and not pw:
        set_value(ID_DET_KIND, "Encrypted")
        return
    # Raised before the read and lowered after it, on both outcomes.
    show_preview_busy(True)
    try:
        path = extract_for_preview(fullpath, pw)
    finally:
        show_preview_busy(False)
    if not path:
        # Extraction failed - on an encrypted entry this means a wrong password.
        # The pane is already empty; it was cleared on the way in.
        set_value(ID_DET_KIND, "Encrypted" if enc == "1" else "-")
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
    """Standalone "can the helper read this as a zip?" check.

    NOT used to open a document: load_archive answers the same question as a
    by-product of the read it has to do anyway, and asking here first meant
    reading a large archive's central directory twice for one boolean. Kept for
    callers that need the answer without opening anything."""
    if not path or not os.path.isfile(path):
        return False
    r = run_ziptool("probe", path)
    return r.returncode == 0


def load_archive(path):
    """Open an existing archive for browsing (no working copy yet).

    Returns False, having claimed no document state, when the file is not
    something the helper can read as a zip - so the caller can fall back to
    treating it as content to compress. This IS the "is it a zip?" test: asking
    separately first meant reading the whole central directory twice.
    """
    # Said before the read, not after: on a large archive the read is seconds of
    # a window that otherwise shows "No archive open" and an empty list, which
    # is indistinguishable from having failed. It is the first thing the user
    # sees and the reason they thought the app was broken.
    set_status("Opening %s..." % os.path.basename(path))
    # Indeterminate: libarchive streams the central directory and cannot say how
    # many entries are coming until it has read them all, so there is no honest
    # fraction to show. A spinner still answers the question the blank window
    # could not - is it working, or has it failed?
    show_bar()
    try:
        pb_set(PB_ORIGINAL, path)
        pb_set(PB_WORK, "")
        pb_set(PB_DIRTY, "")
        pb_set(PB_PASSWORD, "")
        pb_set(PB_SEL_PATH, "")
        pb_set(PB_SEL_ISDIR, "")
        if regenerate_model() is None:
            pb_set(PB_ORIGINAL, "")
            pb_set(PB_ENC, "")
            set_status("")
            return False
        set_status("Listing %s..." % os.path.basename(path))
        populate_level("")
        enable_view(ID_EXTRACT_ALL_BTN, True)
        enable_view(ID_ADD_BTN, True)
        refresh_title()
        refresh_lock_menu()
        _status_summary("Opened")
        return True
    finally:
        hide_progress()


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
    """Create a new untitled document containing a dropped/opened file or folder.

    Compressing a folder is the slowest thing this app does, so add_paths shows
    the status row's progress bar while it runs."""
    new_archive()
    if not add_paths([content_path], prefix=""):
        # add_paths has already said what went wrong, in the status bar and in
        # an alert. Overwriting that with "Save to keep it" would invite the
        # user to save an archive that got nothing.
        return
    set_status("New archive from %s - Save to keep it."
               % os.path.basename(content_path.rstrip("/")))


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


def _add_missing_count(r):
    """How many staged items ziptool could not find in the archive afterwards.

    Same shape and same reasoning as _added_under_other_names: anchored,
    whole-line, and scanned BACKWARDS. ziptool names each missing item on its
    own line before printing this count, and an entry name can contain a
    newline - so a name can forge a line that looks like this one, and only the
    LAST match is guaranteed to be ziptool's own."""
    for line in reversed((r.stderr or b"").decode("utf-8", "replace").split("\n")):
        m = re.fullmatch(r"missing (\d+) of (\d+) items", line.rstrip("\r"))
        if m:
            return int(m.group(1)), int(m.group(2))
    return 0, 0


def _status_summary(verb, note=""):
    # regenerate_model cached the count, which every caller has just run. Falling
    # back to parsing the model keeps this correct if that ever stops being true,
    # but it is the expensive path: 34 MB and a million strings on a large
    # archive, for one number.
    cached = pb_get(PB_COUNT)
    n = int(cached) if cached.isdigit() else len(_read_model_rows())
    enc = pb_get(PB_ENC)
    # libarchive does not expose the cipher (AES vs ZipCrypto) on read, so the
    # status reports encryption generically.
    enc_note = " - encrypted" if enc == "encrypted" else ""
    set_status("%s %s - %d entries%s%s" % (verb, doc_name(), n, enc_note, note))


# --- Mutations ------------------------------------------------------------
# Free space the applet refuses to compress into, over and above the archive it
# is about to write. macOS needs room for swap and system caches, and a Mac
# driven to zero is a Mac that stops working rather than one that is merely
# full. Named through a variable for the same reason Cadabra names its own: a
# test cannot free gigabytes, so with the number hardcoded a space test would
# pass or fail on how full the developer's disk happened to be that day.
#
# Smaller than Cadabra's 15 GB on purpose. That figure guards multi-gigabyte
# model downloads; most archives are far smaller, and a reserve that large would
# question every compression on a comfortably-working Mac.
def _headroom_bytes():
    """The reserve, from the environment, never raising.

    Parsed in a function because this runs at IMPORT: a stray
    ZIP_DISK_HEADROOM_GB=5.5 or an empty one would otherwise take down every
    handler in the applet with a traceback, not merely the preflight. A float is
    accepted for the same reason - refusing "5.5" would be a surprise - and a
    negative value clamps to 0, which disables the check rather than silently
    weakening it into nonsense."""
    try:
        gb = float(os.environ.get("ZIP_DISK_HEADROOM_GB", "5"))
    except (TypeError, ValueError):
        gb = 5.0
    return int(max(gb, 0.0) * 1024 ** 3)


DISK_HEADROOM_BYTES = _headroom_bytes()

_SPACE_LINE = re.compile(r"space (\d+) (\d+) (\d+)")


def free_bytes(path):
    """Free space on the volume holding `path`, or None if it cannot be asked.
    The nearest EXISTING directory is measured: the path in question is
    routinely one that does not exist yet, such as a Save As destination.

    Deliberately a second copy of ziptool's function of the same name rather
    than an import: ziptool is a command run under its own interpreter, not a
    module this process loads."""
    path = os.path.abspath(path)
    while path and not os.path.isdir(path):
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent
    try:
        st = os.statvfs(path)
    except OSError:
        return None
    # f_bavail, not f_bfree: the blocks available to THIS user, which is what a
    # write actually gets.
    return st.f_bavail * st.f_frsize


def human_bytes(n):
    """Sizes for a sentence the user reads, not for arithmetic."""
    n = float(n)
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024.0 or unit == "TB":
            return "%d %s" % (n, unit) if unit == "bytes" else "%.1f %s" % (n, unit)
        n /= 1024.0


def _confirm_low_space(r):
    """ziptool refused on space. Show what it measured and ask.

    Asked rather than refused, because the number it judged is the sources'
    UNCOMPRESSED size - the archive's worst case. A folder of source code
    routinely lands at a fifth of it, so a flat refusal would block operations
    that fit with room to spare. What the user cannot see for themselves, and
    what this is really for, is that the Mac is close enough to full that
    filling it further is a system problem rather than a Zip problem."""
    text = (r.stderr or b"").decode("utf-8", "replace")
    log("space preflight refused: %s" % text)
    source = free = needed = None
    for line in reversed(text.split("\n")):
        m = _SPACE_LINE.fullmatch(line.rstrip("\r"))
        if m:
            source, free, needed = (int(g) for g in m.groups())
            break
    if source is None:
        # No measurement to show. Refuse rather than invite a decision nobody
        # has the facts for.
        alert("There may not be enough free disk space to do this safely.",
              level="caution")
        return False
    return alert(
        "Compressing this could leave the disk too full for macOS to work "
        "comfortably.\n\n"
        "These items hold %s uncompressed. The archive will be smaller - how "
        "much smaller is not known until it is written - and the compressed "
        "copy is written before the originals are freed, so the space is "
        "needed either way.\n\n"
        "Free space now: %s\nWanted before starting: %s"
        % (human_bytes(source), human_bytes(free), human_bytes(needed)),
        title="Low Disk Space", level="caution",
        ok="Compress Anyway", cancel="Cancel") == 0


def _run_add(archive, prefix, paths):
    """ziptool's add, with the space preflight in front of it.

    Returns the CompletedProcess, or None when the user answered the low-space
    question with Cancel. The retry runs the whole add again, scan included:
    the check happens after the walk (which is where the byte total comes from)
    and before anything is written, so a second walk is the price of offering
    the choice at all - and it is only paid when the answer is Yes."""
    args = ["add", archive, "--prefix=%s" % prefix, "--progress"]
    payload = "\n".join(paths)
    r = run_ziptool_watched(*args, "--min-free-bytes=%d" % DISK_HEADROOM_BYTES,
                            stdin=payload, on_line=progress_reporter())
    if r.returncode != 6:
        return r
    if not _confirm_low_space(r):
        return None
    return run_ziptool_watched(*args, stdin=payload, on_line=progress_reporter())


def _copy_failed(e):
    """ensure_working_copy or the encrypted scratch copy could not be made.

    Both duplicate a whole archive before the space preflight has anything to
    judge - the preflight needs the walk's byte total, and the walk has not run
    yet - so on a full disk they are where the operation dies. It used to die as
    an unhandled OSError: no alert, and a status line still saying the applet was
    compressing."""
    log("could not prepare the working copy: %s" % e)
    alert("Could not prepare the archive for editing.\n\n%s" % e, level="caution")
    set_status("Add failed.")


def _adding_status(paths):
    """What the status bar says while an add runs. Compressing a folder is the
    slow case and the one worth naming; a multi-item add just gets a count."""
    if len(paths) == 1:
        name = os.path.basename(paths[0].rstrip("/")) or paths[0]
        if os.path.isdir(paths[0]) and not os.path.islink(paths[0]):
            return "Compressing %s..." % name
        return "Adding %s..." % name
    return "Adding %d items..." % len(paths)


def _add_failed(r, what="Could not add the selected items."):
    """Report a failed add with the reason attached.

    The old message said only that it had failed. After a multi-minute
    compression that is the least useful thing the app can say, and it is what
    left a real failure with nothing to go on: the exit code and Info-ZIP's own
    complaint were captured and thrown away."""
    detail = (r.stderr or b"").decode("utf-8", "replace")
    log("add failed (rc=%s): %s" % (r.returncode, detail))
    # The FIRST line, not the last. ziptool prints the zip tool's own complaint
    # before anything of its own, so the first line is the diagnosis; the last
    # is bookkeeping ("nothing was added"), which the alert used to quote as
    # though it were the reason.
    first = detail.strip().split("\n")[0].strip()
    why = "The zip tool exited with code %d." % r.returncode
    if first:
        why = "%s\n\n%s" % (first, why)
    alert("%s\n\n%s" % (what, why), level="caution")
    set_status("Add failed.")


def add_paths(paths, prefix=None):
    """Add the given files/folders to the archive, with live progress.

    Thin wrapper so the status row's progress bar is retired on EVERY exit path
    - the failures and an unexpected exception included. A bar left standing
    says the work is still running, which is the exact confusion this whole
    change exists to remove."""
    show_bar()
    try:
        return _add_paths(paths, prefix)
    finally:
        hide_progress()


def _add_paths(paths, prefix=None):
    recrypted_note = False
    renamed_note = 0
    partial = False
    if prefix is None:
        prefix = cur_prefix()

    set_status(_adding_status(paths))

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
            set_status("Add canceled - the archive is locked.")
            return False
        try:
            work = ensure_working_copy()
        except OSError as e:
            _copy_failed(e)
            return False
        scratch = work + ".addtmp"
        recrypted = scratch + ".recrypt"
        try:
            # A full copy of the working copy, made BEFORE the preflight can run
            # - the preflight needs the walk's byte total, which does not exist
            # yet. This one is exact, so it can be checked exactly.
            if not _space_for_write(work, scratch):
                set_status("Compression canceled - not enough free space.")
                return False
            shutil.copy2(work, scratch)
            r = _run_add(scratch, prefix, paths)
            if r is None:
                set_status("Compression canceled - not enough free space.")
                return False
            # rc 5 is a partial add: some items are in, the rest are not. The
            # archive on disk changed either way, so it must be carried through
            # and reported rather than discarded as a failure.
            if r.returncode not in (0, 5):
                _add_failed(r)
                return False
            partial = (r.returncode == 5)
            renamed_note = _added_under_other_names(r)
            # scratch is now mixed (existing encrypted + new plaintext); re-encrypt all
            # entries under the session password so none is left in the clear.
            show_bar()                # no counter for this phase
            set_status("Re-encrypting archive...")
            rr = _run_recrypt(scratch, recrypted, "aes256", pw, pw)
            if rr.returncode != 0:
                log("encrypted add re-encrypt failed: %s"
                    % (rr.stderr or b"").decode("utf-8", "replace"))
                _add_failed(rr, "The items could not be added without leaving part "
                                "of the archive unencrypted, so nothing was added.")
                return False
            os.replace(recrypted, work)   # atomic: working copy is fully encrypted again
            recrypted_note = True
        finally:
            for tmp in (scratch, recrypted):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    else:
        try:
            work = ensure_working_copy()
        except OSError as e:
            _copy_failed(e)
            return False
        r = _run_add(work, prefix, paths)
        if r is None:
            set_status("Compression canceled - not enough free space.")
            return False
        if r.returncode not in (0, 5):
            _add_failed(r)
            return False
        partial = (r.returncode == 5)
        renamed_note = _added_under_other_names(r)

    mark_dirty()
    # Re-reading a freshly written multi-gigabyte archive is seconds of its own,
    # with no per-item counter to report. Say what is happening and keep the bar
    # up, spinning, so the window is never silently busy.
    show_bar()
    set_status("Updating list...")
    regenerate_model()
    populate_level(cur_prefix())
    note = ""
    if partial:
        note += " - some items could not be added"
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
    if partial:
        # Named separately from the rename note below: those items ARE in the
        # archive under another name, these are not in it at all. ziptool
        # checked each staged item against the archive's own listing - by name,
        # and for a file by size too - rather than trusting the zip tool's exit
        # code, and named the ones that did not make it on stderr.
        log("partial add: %s" % (r.stderr or b"").decode("utf-8", "replace"))
        n, total = _add_missing_count(r)
        # The counts, never a raw stderr line: the line before this one holds an
        # entry name, which may contain a newline and would put a fragment of
        # itself in the alert.
        alert("%s could not be added. The rest are in the archive - check the "
              "list before saving."
              % ("%d of %d items" % (n, total) if total else "Some items"),
              level="caution")
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
    # True once anything is in the archive, partial runs included: the document
    # IS changed and the caller must not overwrite the status with a message
    # that implies otherwise.
    return True


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
def _space_for_write(src, dest):
    """True if it is safe to write `src`'s bytes to `dest`, having asked first.

    Exact, unlike the compression preflight: the file exists, so this is not an
    estimate of what an archive might come to but the number of bytes about to
    be written. _atomic_copy writes a sibling temp file and renames, so the
    destination volume needs a whole second copy while it runs even when it is
    replacing a file of the same name.

    Returning True on an unmeasurable volume is deliberate: a network or
    synthetic filesystem that will not answer statvfs must not become a
    filesystem the app refuses to save to. The write then fails the honest way,
    with an error the caller already reports."""
    try:
        need = os.path.getsize(src)
    except OSError:
        return True
    real = os.path.realpath(dest)
    free = free_bytes(os.path.dirname(real) or ".")
    if free is None or free >= need + DISK_HEADROOM_BYTES:
        return True
    if free < need:
        alert("There is not enough free space to save “%s”.\n\n"
              "Needed: %s\nFree: %s\n\nNothing was written."
              % (os.path.basename(dest), human_bytes(need), human_bytes(free)),
              title="Not Enough Disk Space", level="caution")
        return False
    # It fits, but only by eating the reserve macOS wants for swap and caches.
    # The user's call, with the numbers in front of them.
    #
    # Replacing a file gives its bytes back: os.replace drops the old inode, so
    # the space afterwards is what is left once the OLD copy goes. Reporting the
    # transient minimum as "after saving" overstated the danger badly - saving
    # over a same-sized archive reads as losing the whole of it - and could talk
    # a user out of a save that costs nothing.
    try:
        replaced = os.path.getsize(real) if os.path.isfile(real) else 0
    except OSError:
        replaced = 0
    return alert("Saving “%s” would leave very little free space.\n\n"
                 "This archive is %s.\nFree space after saving: about %s\n\n"
                 "macOS needs free space for swap files and system caches."
                 % (os.path.basename(dest), human_bytes(need),
                    human_bytes(max(free - need + replaced, 0))),
                 title="Low Disk Space", level="caution",
                 ok="Save Anyway", cancel="Cancel") == 0


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
        if not _space_for_write(work, orig):
            set_status("Save canceled - not enough free space.")
            return False
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
                set_status("Save canceled - that name is a folder.")
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
                set_status("Save canceled")
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
    if not _space_for_write(src, dest):
        set_status("Save canceled - not enough free space.")
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
              PB_ENC, PB_COUNT, PB_PASSWORD, PB_EX_DEST, PB_EX_MODE, PB_EX_LAST,
              PB_CLOSE_AFTER_SAVE):
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
