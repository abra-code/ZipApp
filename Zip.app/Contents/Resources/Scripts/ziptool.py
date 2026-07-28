#!/usr/bin/env python3
"""ziptool.py - zip model helper for the Zip OMC applet.

Subcommands (see argparse below):
  list    <archive>                       full TSV model of the archive (incl. synthesized dirs)
  level   --tsv FILE --prefix P           immediate children of folder P, as table-feed rows
  find    --tsv FILE --query Q            flat filtered table-feed rows (substring on full path)
  probe   <archive>                       prints one of: plain | encrypted
  read    <archive> --entry E [--pwd-stdin] [--max N]   entry bytes to stdout (preview)
  extract <archive> --dest D (--all | --entry E | --prefix P) [--pwd-stdin]
  create  <archive> [--force]             create an empty archive
  add     <archive> [--prefix P]          add files (paths on stdin) in place
  delete  <archive> (--entry E | --prefix P)

Design notes:
  * All archive reading/extraction/creation goes through the native libarchive
    helper (Contents/Helpers/archive) - this file no longer uses Python's stdlib
    zipfile. The helper handles plain, ZipCrypto, and WinZip-AES uniformly.
  * In-place mutation uses Info-ZIP: add via /usr/bin/zip (staging dir), delete via
    /usr/bin/zip -d. libarchive cannot modify in place without a full rewrite.
  * The "list" model is cached to a TSV by the caller; "level"/"find" read that TSV
    so navigation/filtering never re-opens the archive.
  * Passwords are only ever read from stdin (--pwd-stdin) and forwarded to the
    helper on its stdin, never argv, so they do not leak to the process list.
  * Extraction sanitizes member names to stay within the destination (zip-slip).

Exit codes: 0 ok | 1 generic error | 2 needs/incorrect password | 4 not a valid zip
            5 extract only: partial - some entries were rejected (unsafe path,
              name collision) but the rest extracted and are placed on disk
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import urllib.parse

# Zip stores entry names as bytes with no reliable encoding declaration, so a
# legacy CP437 / Shift-JIS archive carries names that are not valid UTF-8.
# Decoding those with errors="replace" turned them into U+FFFD and made the
# entries permanently unaddressable - they could be listed but never extracted or
# deleted, because the name could no longer be handed back to the helper. Every
# name in this tool is therefore carried as str decoded with "surrogateescape",
# which round-trips arbitrary bytes exactly, and stdout/stderr are reconfigured
# so those strings can be written back out unchanged.
# stdin too: a source path handed to `add` may itself hold non-UTF-8 bytes on a
# non-APFS volume, and a strict decode there crashed the add. Guarded against a
# closed standard stream, where reconfigure() would raise on None.
for _stream in (sys.stdin, sys.stdout, sys.stderr):
    if _stream is not None:
        _stream.reconfigure(errors="surrogateescape")

# Internal model TSV columns (one row per real or synthesized entry):
#   fullpath  isdir(0/1)  size  csize  mtime("YYYY-MM-DD HH:MM" or "")  enc(0/1)  enctype
# csize and enctype are retained for format stability but unused now ("0"/"").
MODEL_COLS = 7

# Emit an extraction progress line every N completed files (plus always the last)
# rather than on every file, so OMC's PROGRESS parser refreshes in batches instead
# of redrawing on each item.
PROGRESS_EVERY = 10

# Native libarchive helper at Contents/Helpers/archive; this file is at
# Contents/Resources/Scripts/.
ARCHIVE_BIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "Helpers", "archive")


def eprint(*a):
    print(*a, file=sys.stderr)


def _msg(b):
    """Decode a subprocess's output for display. Never text=True on anything that
    echoes an entry name: Info-ZIP prints the names it deletes, and a legacy
    CP437 / Shift-JIS name is not valid UTF-8, so a strict decode raises
    UnicodeDecodeError - which turned a delete that had actually SUCCEEDED into a
    reported failure."""
    return (b or b"").decode("utf-8", "surrogateescape").strip()


# --------------------------------------------------------------------------- native helper

def _archive_read(archive, entry, maxbytes, pwd):
    """Stream one entry to stdout via the helper (handles plain/ZipCrypto/AES).
    Password (bytes or None) goes on the helper's stdin, never argv. The helper's
    exit codes already match ours (0 ok / 2 password / 4 bad archive / 1 other)."""
    cmd = [ARCHIVE_BIN, "read", archive, entry]
    if maxbytes and maxbytes > 0:
        cmd += ["--max", str(maxbytes)]
    # The helper writes straight to our stdout instead of being captured: with
    # capture_output the whole entry was buffered in memory, which is unbounded
    # when --max is absent. Flush first so our own buffered output cannot land
    # after the child's.
    sys.stdout.flush()
    r = subprocess.run(cmd, input=(pwd or b""), stdout=None, stderr=subprocess.PIPE)
    if r.returncode != 0 and r.stderr:
        sys.stderr.buffer.write(r.stderr)
    return r.returncode


def _archive_list(archive, raw=False):
    """Run the helper's `list`; return rows [(path, isdir, size, mtime, enc, ad)]
    or None on error. Encryption is a boolean (libarchive does not expose the
    cipher); ad is "1" for a "._*" file confirmed (or, when encrypted, presumed)
    to be an AppleDouble sidecar. Readable without a password.

    raw=True skips OUR normalization (stripping a leading "./") so mutation can
    address entries closer to their stored name. It is NOT a stored-name oracle:
    libarchive itself still rewrites some names on the way out - a directory
    entry stored without a trailing slash is reported with one, and a "\\" in a
    name with no "/" is reported as "/" (a DOS-path heuristic). Callers must
    verify the effect of a mutation rather than assume the name matched."""
    # --nul: six NUL-terminated fields per record. The TSV form cannot represent
    # a name containing a tab (field split, name truncated) or a newline (record
    # split into two phantom rows), and both are legal in a zip. A pathname
    # arrives from libarchive as a C string, so NUL is the one byte it cannot
    # contain - which makes this framing lossless with no escaping.
    r = subprocess.run([ARCHIVE_BIN, "list", archive, "--nul"], input=b"", capture_output=True)
    if r.returncode != 0:
        if r.stderr:
            sys.stderr.buffer.write(r.stderr)
        return None
    fields = (r.stdout or b"").split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()                      # trailing terminator, not a field
    rows = []
    for i in range(0, len(fields) - 5, 6):
        parts = [f.decode("utf-8", "surrogateescape") for f in fields[i:i + 6]]
        # Normalize a leading "./" here, at the single entry point of archive
        # names into the model, so matching/counting agrees with the helper's
        # norm()-based comparisons for bsdtar-style "./name" archives.
        if not raw and parts[0].startswith("./"):
            parts[0] = parts[0][2:]
        rows.append(parts)
    return rows


# --------------------------------------------------------------------------- helpers

def is_junk(name, appledouble="1"):
    """macOS metadata noise we hide from the listing. Mirrors the helper's
    junk rules exactly (leading './' normalized, bare __MACOSX matched) so
    progress totals line up with what it extracts. A "._*" name alone is only
    a candidate: the helper's list peeks for the AppleDouble magic and reports
    it in the ad column, passed here as `appledouble` - a user file genuinely
    named "._foo" is real content, not junk. Callers without the flag keep the
    conservative name-based behavior."""
    if name.startswith("./"):
        name = name[2:]
    if name == "__MACOSX" or name == "__MACOSX/" or name.startswith("__MACOSX/"):
        return True
    base = name.rstrip("/").rsplit("/", 1)[-1]
    if base == ".DS_Store":
        return True
    if base.startswith("._"):
        return appledouble == "1"
    return False


def human_size(n):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return ""
    if n < 1024:
        return "%d B" % n
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024.0:
            return "%.1f %s" % (n, unit)
    return "%.1f PB" % n


# --------------------------------------------------------------------------- list

def build_model(archive):
    """Return model rows (each a 7-tuple) incl. synthesized parent dirs, built from
    the native list. Returns None if the archive cannot be read."""
    listed = _archive_list(archive)
    if listed is None:
        return None
    files = {}          # fullpath -> (size, mtime, enc)
    explicit_dirs = {}  # "a/b/" -> mtime
    all_dirs = set()

    for name, isdir, size, mtime, enc, ad in listed:
        if not name or is_junk(name, ad):
            continue
        if isdir == "1":
            d = name if name.endswith("/") else name + "/"
            explicit_dirs[d] = mtime
            acc = ""
            for p in d.rstrip("/").split("/"):
                acc += p + "/"
                all_dirs.add(acc)
            continue
        files[name] = (size, mtime, enc)
        if "/" in name:
            acc = ""
            for p in name.split("/")[:-1]:
                acc += p + "/"
                all_dirs.add(acc)

    rows = []
    for d in all_dirs:
        rows.append((d, "1", "0", "0", explicit_dirs.get(d, ""), "0", ""))
    for name, (sz, mt, enc) in files.items():
        rows.append((name, "0", str(sz), "0", mt, str(enc), ""))
    return rows


def cmd_list(args):
    rows = build_model(args.archive)
    if rows is None:
        return 4
    out = sys.stdout
    # Same framing as the helper's --nul output, and for the same reason: the
    # cached model is written to a file and read back, so a tab or newline in a
    # name would corrupt it exactly as it corrupted the helper's TSV. Seven
    # NUL-terminated fields per record.
    for r in rows:
        out.write("\0".join(r) + "\0")
    return 0


# --------------------------------------------------------------------------- level / find

def read_model(tsv_path):
    """Parse the cached model: MODEL_COLS NUL-terminated fields per record."""
    with open(tsv_path, "rb") as f:
        fields = f.read().split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    rows = []
    for i in range(0, len(fields) - (MODEL_COLS - 1), MODEL_COLS):
        rows.append([x.decode("utf-8", "surrogateescape")
                     for x in fields[i:i + MODEL_COLS]])
    return rows


def display_name(fullpath, isdir):
    # Folders are shown by name only - the folder icon already marks them as
    # directories, so a trailing "/" just exposes archive internals. The real
    # path (with its slash) still travels in the hidden fullpath column.
    return fullpath.rstrip("/").rsplit("/", 1)[-1]


def display_safe(s):
    """Render a value for a VISIBLE table column.

    Two constraints, both from OMC's table feed. It is tab-separated and
    newline-terminated, so those characters cannot appear in a field; and its
    reader decodes each row as strict UTF-8 and silently DROPS any row it cannot
    decode, so a legacy CP437 / Shift-JIS name would make the whole entry vanish
    from the list. Undecodable bytes therefore become U+FFFD here - display only.
    The exact bytes still travel in the hidden column, which is what the app
    actually addresses entries by."""
    s = s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return s.replace("\t", " ").replace("\r", " ").replace("\n", " ")


def path_encode(s):
    """Encode a path for the hidden ADDRESSING column.

    Must be injective and pure ASCII. Injective because sanitizing for display
    is not: "a<TAB>b.txt" and "a<SPACE>b.txt" both flatten to the same string, so
    selecting one row and deleting it destroyed the OTHER entry and reported
    success. ASCII because both channels this value crosses are UTF-8 only - the
    table feed drops an undecodable row, and the pasteboard tool clears the key
    rather than storing invalid UTF-8, which silently emptied the selection.

    Percent-encoding satisfies both and round-trips exactly. "/" stays literal so
    ordinary paths remain readable in a log."""
    return urllib.parse.quote(s.encode("utf-8", "surrogateescape"), safe="/")


def feed_row(symbol, name, size_h, mtime, fullpath, isdir, enc):
    """Seven tab-separated fields: visible (Icon, Name, Size) + Modified + hidden
    (percent-encoded fullpath, isdir, enc)."""
    return "\t".join([display_safe(symbol), display_safe(name), display_safe(size_h),
                      display_safe(mtime), path_encode(fullpath), isdir, enc])


def icon_for(isdir, enc):
    """SF Symbol name for an entry's leading icon column."""
    if isdir == "1":
        return "folder"
    return "lock.doc" if enc == "1" else "doc"


def sort_key(row):
    # row is a model row; dirs first, then case-insensitive by display name
    fullpath, isdir = row[0], row[1]
    return (0 if isdir == "1" else 1, display_name(fullpath, isdir).lower())


def cmd_level(args):
    prefix = args.prefix or ""
    rows = read_model(args.tsv)
    children = []
    for r in rows:
        fp, isdir = r[0], r[1]
        if fp == prefix or not fp.startswith(prefix):
            continue
        rem = fp[len(prefix):]
        if isdir == "1":
            # immediate dir child: rem like "name/"
            inner = rem[:-1]
            if "/" in inner:
                continue
        else:
            if "/" in rem:
                continue
        children.append(r)
    children.sort(key=sort_key)

    out = sys.stdout
    if prefix:
        out.write(feed_row("arrow.up", "..", "", "", "__UP__", "1", "0") + "\n")
    for r in children:
        fp, isdir, size, _csz, mt, enc, _et = r
        size_h = "--" if isdir == "1" else human_size(size)
        out.write(feed_row(icon_for(isdir, enc), display_name(fp, isdir), size_h, mt, fp, isdir, enc) + "\n")
    return 0


def cmd_find(args):
    q = (args.query or "").lower()
    rows = read_model(args.tsv)
    if not q:
        return 0
    matches = [r for r in rows if r[1] == "0" and q in r[0].lower()]
    matches.sort(key=lambda r: r[0].lower())
    out = sys.stdout
    for r in matches:
        fp, isdir, size, _csz, mt, enc, _et = r
        # Name column shows the basename only; the full path stays in the hidden
        # fullpath field (5th) for the Path detail, selection, and double-click open.
        out.write(feed_row(icon_for(isdir, enc), display_name(fp, isdir), human_size(size), mt, fp, isdir, enc) + "\n")
    return 0


# --------------------------------------------------------------------------- probe

def cmd_probe(args):
    listed = _archive_list(args.archive)
    if listed is None:
        return 4
    for name, isdir, size, mtime, enc, ad in listed:
        if isdir != "1" and enc == "1" and not is_junk(name, ad):
            print("encrypted")
            return 0
    print("plain")
    return 0


# --------------------------------------------------------------------------- crypto helpers

def read_password(use_stdin):
    if not use_stdin:
        return None
    data = sys.stdin.buffer.read()
    if data.endswith(b"\r\n"):
        data = data[:-2]
    elif data.endswith(b"\n"):
        data = data[:-1]
    return data if data else None


# --------------------------------------------------------------------------- read (preview)

def cmd_read(args):
    pwd = read_password(args.pwd_stdin)
    return _archive_read(args.archive, args.entry, args.max, pwd)


# --------------------------------------------------------------------------- extract

# --------------------------------------------------------------------------- name repair

# A zip name is arbitrary bytes; a macOS filename is not. APFS refuses anything
# that is not well-formed UTF-8 ([Errno 92] Illegal byte sequence), and TAB, CR
# and LF - storable, but the framing character of every protocol between the
# helper, this script and the UI - can only ever be displayed folded. So a name
# is REPAIRED at the two points where it crosses into that world: when the
# helper writes an entry to disk, and when a file from disk is stored in an
# archive. Names already in an archive are never rewritten - listing, matching
# and deleting all still work on the exact bytes the archive holds.
#
# These two functions mirror archive.c's repair_component() byte for byte.
# Python decodes entry names with surrogateescape, so each byte that is not
# valid UTF-8 arrives as one lone surrogate - the same unit the C side replaces.

def _is_noncharacter(ch):
    """Well-formed UTF-8 that the filesystem still refuses (verified: Errno 92).
    Permanent by Unicode's stability policy. Note APFS also refuses UNASSIGNED
    code points, a set that changes with every Unicode revision - so repair
    makes a name storable far more often, but cannot promise it."""
    cp = ord(ch)
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def repair_component(c):
    """One path component with TAB/CR/LF folded to a space and every byte that
    is not well-formed UTF-8 folded to '_'. One surrogate is one such byte,
    which is what makes this match archive.c's repair_component exactly."""
    out = []
    for ch in c:
        if ch in "\t\r\n":
            out.append(" ")
        elif "\ud800" <= ch <= "\udfff":
            out.append("_")
        elif _is_noncharacter(ch):
            out.append("_" * len(ch.encode("utf-8")))
        else:
            out.append(ch)
    return "".join(out)


def needs_repair(s):
    return any(ch in "\t\r\n" or "\ud800" <= ch <= "\udfff" or _is_noncharacter(ch)
               for ch in s)


def unstorable(s):
    """True when the filesystem will REFUSE this name outright (EILSEQ), rather
    than it merely being awkward for us. TAB, CR and LF are perfectly storable
    on APFS - we fold them for our own protocols' sake - so they do not count
    here. Bytes that are not well-formed UTF-8, and noncharacters, do."""
    return any("\ud800" <= ch <= "\udfff" or _is_noncharacter(ch) for ch in s)


def repair_path(p):
    return "/".join(repair_component(c) for c in p.split("/"))


def sanitize_rel(rel):
    """Return a safe relative path or None if it tries to escape."""
    rel = rel.replace("\\", "/")
    if rel.startswith("/"):
        return None
    parts = []
    for p in rel.split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            return None
        parts.append(p)
    if not parts:
        return None
    return os.path.join(*parts)


def parent_prefix_of(folder):
    """For folder 'a/b/' return 'a/' (the part to strip so 'b' stays the root)."""
    inner = folder.rstrip("/")
    if "/" in inner:
        return inner.rsplit("/", 1)[0] + "/"
    return ""


def _unique_in(dest, name, is_dir):
    """Finder-style unique name within dest: 'name', then 'name 2', 'name 3', ...
    For files the counter is inserted before the extension ('a.txt' -> 'a 2.txt');
    for folders it is appended ('a' -> 'a 2'). lexists, not exists: a dangling
    symlink still occupies the name (renaming onto it would fail)."""
    if not name or not os.path.lexists(os.path.join(dest, name)):
        return name
    stem, ext = (name, "") if is_dir else os.path.splitext(name)
    n = 2
    while True:
        cand = "%s %d%s" % (stem, n, ext)
        if not os.path.lexists(os.path.join(dest, cand)):
            return cand
        n += 1


def cmd_extract(args):
    # Mirror the helper's prefix rule: it now requires a path boundary, so
    # without this the Python-side count would include "docs2/..." for
    # "--prefix docs" while the helper correctly skipped it, and the progress
    # total would never be reached.
    if getattr(args, "prefix", None) and not args.prefix.endswith("/"):
        args.prefix += "/"
    pwd = read_password(args.pwd_stdin)
    dest = os.path.abspath(args.dest)
    os.makedirs(dest, exist_ok=True)

    archive_base = os.path.basename(args.archive)
    if archive_base.lower().endswith(".zip"):
        archive_base = archive_base[:-4]

    listed = _archive_list(args.archive)
    if listed is None:
        return 4

    # Callers pass --prefix for folders, but harden --entry too: an entry that
    # is a directory (explicit trailing slash or a dir row in the model) is
    # rerouted to prefix mode, where the whole subtree is extracted.
    if args.entry is not None:
        ename = args.entry
        is_dir_entry = ename.endswith("/")
        if not is_dir_entry:
            for name, isdir, _sz, _mt, _enc, _ad in listed:
                if isdir == "1" and name.rstrip("/") == ename:
                    is_dir_entry = True
                    break
        if is_dir_entry:
            args.prefix = ename if ename.endswith("/") else ename + "/"
            args.entry = None

    # Decide which real entries to extract and how to map their output paths.
    def out_rel(name):
        if args.all:
            return archive_base + "/" + name
        if args.entry is not None:
            if name != args.entry:
                return None
            return os.path.basename(name.rstrip("/"))
        if args.prefix is not None:
            if not name.startswith(args.prefix):
                return None
            return name[len(parent_prefix_of(args.prefix)):]
        return None

    # Finder-style: everything lands under a single top-level item in dest (the
    # archive-named folder for --all, the prefix folder for --prefix, the file for
    # --entry). Make that item unique so an existing same-name item is never
    # overwritten or merged into; the new name (if any) replaces the top component
    # of every output path.
    #
    # repair_component first: the helper writes the entry under its repaired
    # name, so the item we go looking for - and the name the user ends up with -
    # has to be the repaired one too. Without it a folder whose archive name
    # carries a tab or a legacy encoding would be "not found" and the whole
    # extraction thrown away.
    if args.all:
        top, top_is_dir = archive_base, True
    elif args.prefix is not None:
        top, top_is_dir = os.path.basename(args.prefix.rstrip("/")), True
    else:
        top, top_is_dir = os.path.basename((args.entry or "").rstrip("/")), False
    top = repair_component(top)
    unique_top = _unique_in(dest, top, top_is_dir)

    # Count the files the helper will extract so progress can report a known
    # total ("file N of M"). The filters mirror the helper's: junk skipped,
    # directories excluded from the count, member/prefix matching. (For an
    # ENCRYPTED non-AppleDouble "._*" file the helper - which has the password
    # and can peek the magic - may extract one more file than counted here;
    # the progress display is momentarily conservative, nothing else.)
    total = 0
    for name, isdir, size, mtime, enc, ad in listed:
        if not name or is_junk(name, ad) or isdir == "1":
            continue
        if out_rel(name) is None:
            continue
        total += 1

    # The helper extracts with libarchive's archive_write_disk, which restores
    # symlinks and permissions (executable bits!) that the old per-entry byte
    # streaming lost - both are load-bearing for .app bundles. Its secure flags
    # reject absolute/".." paths (zip-slip). Extraction lands in a private temp
    # dir inside dest (same volume, so the final placement is a rename), then the
    # single top-level item is moved to its Finder-style unique name.
    tmproot = tempfile.mkdtemp(prefix=".ziptool-extract-", dir=dest)
    cmd = [ARCHIVE_BIN, "extract", args.archive, tmproot, "--progress"]
    if args.all:
        cmd.append("--skip-junk")
    elif args.prefix is not None:
        cmd += ["--skip-junk", "--prefix", args.prefix]
    else:
        cmd.append(args.entry)

    count = 0
    skipped = 0
    renamed = 0
    try:
        # stderr goes to a file, not a pipe: the helper can emit a diagnostic
        # line per rejected entry with no matching stdout, and a filled stderr
        # pipe would deadlock against our stdout read loop.
        errf = tempfile.TemporaryFile()
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=errf)
        try:
            proc.stdin.write(pwd or b"")
            proc.stdin.close()
        except BrokenPipeError:
            pass   # helper exited early (e.g. bad archive); rc handling below reports it
        # One line per extracted file/symlink; batch into "file N of M" every
        # PROGRESS_EVERY files (and always on the last) so OMC's PROGRESS counter
        # advances the bar in batches rather than redrawing per item. The line is
        # matched (and hidden) by the command's DETERMINATE_COUNTER.
        for line in proc.stdout:
            # The helper's tail line ("skipped N") reports entries it refused to
            # extract - unsafe paths, name collisions. It is not a progress tick.
            if line.startswith(b"skipped "):
                try:
                    skipped = int(line.split()[1])
                except (ValueError, IndexError):
                    pass
                continue
            # Likewise "renamed N": entries the filesystem could not store under
            # their archive name. Those DID extract - they just landed under a
            # repaired name, so the user has to be told which files moved.
            if line.startswith(b"renamed "):
                try:
                    renamed = int(line.split()[1])
                except (ValueError, IndexError):
                    pass
                continue
            count += 1
            if count % PROGRESS_EVERY == 0 or count >= total:
                # An entry whose name libarchive discarded is extracted but is
                # not in the listing `total` came from, so count can overtake it.
                print("file %d of %d" % (count, max(total, count)))
                sys.stdout.flush()
        rc = proc.wait()
        # rc 5 is a PARTIAL extraction: some entries were rejected, but the rest
        # are on disk and must be kept and placed. Discarding them would lose far
        # more than the rejected entries. The skipped count travels in the
        # summary so the caller never calls a partial result complete.
        if rc not in (0, 5):
            errf.seek(0)
            stderr = errf.read()
            if stderr:
                sys.stderr.buffer.write(stderr)
            errf.close()
            return 2 if rc == 2 else (4 if rc == 4 else 1)
        # Also on a rename: the helper named every repaired entry on stderr, and
        # that list is the only record of which file landed under which name.
        if rc == 5 or renamed:
            errf.seek(0)
            stderr = errf.read()
            if stderr:
                sys.stderr.buffer.write(stderr)
        errf.close()

        # Move the extracted content to its final, uniquely named location.
        if args.all:
            src_top = tmproot
        elif args.prefix is not None:
            src_top = os.path.join(tmproot,
                                   *repair_path(args.prefix.rstrip("/")).split("/"))
        else:
            safe = sanitize_rel(args.entry)
            src_top = os.path.join(tmproot, repair_path(safe)) if safe else None
        # Placement must NOT be gated on `count`, which counts files only: a
        # selection that is entirely directories (an empty folder) extracted
        # correctly into the staging dir and was then deleted by the finally
        # below, so the user got rc 1 and nothing on disk.
        placed = bool(src_top and os.path.lexists(src_top) and unique_top)
        if placed:
            final = os.path.join(dest, unique_top)
            try:
                os.rename(src_top, final)
            except OSError as e:
                eprint("cannot place extracted content: %s" % e)
                return 1
            if args.all:
                # mkdtemp creates the dir 0700; opened folders should be normal.
                os.chmod(final, 0o755)
                tmproot = None   # renamed away; nothing left to clean up
        elif count > 0:
            eprint("extracted content not found at expected location")
            return 1
    finally:
        if tmproot and os.path.isdir(tmproot):
            shutil.rmtree(tmproot, ignore_errors=True)

    root = os.path.join(dest, unique_top) if unique_top else dest
    eprint("extracted %d item(s) to %s" % (count, root))
    if skipped:
        eprint("%d entr%s could not be extracted" % (skipped, "y" if skipped == 1 else "ies"))
    if renamed:
        eprint("%d name%s could not be stored as-is and %s changed"
               % (renamed, "" if renamed == 1 else "s",
                  "was" if renamed == 1 else "were"))
    if count == 0 and not placed:
        eprint("nothing matched")
        return 1
    # Machine-readable summary: count, the top-level path created, skipped,
    # renamed. With --result-file it is written there so stdout stays reserved
    # for the live progress lines OMC parses; otherwise it goes to stdout.
    #
    # The result file is NUL-framed, for the same reason `list --nul` is: the
    # path field holds the user's chosen destination, and a TAB in a folder name
    # split it across two fields, so `skipped` was read from the tail of the path
    # and parsed as 0 - a PARTIAL extraction reported as complete, and the
    # "Show in Finder" path truncated. A path cannot contain NUL. The stdout form
    # stays tab-separated for CLI use, with the same lossiness as `list`.
    fields = [str(count), root, str(skipped), str(renamed)]
    if getattr(args, "result_file", None):
        try:
            with open(args.result_file, "w", encoding="utf-8",
                      errors="surrogateescape") as rf:
                rf.write("\0".join(fields) + "\0")
        except OSError as e:
            eprint("result-file write failed: %s" % e)
    else:
        print("\t".join(fields))
    return 5 if skipped else 0


# --------------------------------------------------------------------------- create / add / delete

def cmd_create(args):
    if os.path.exists(args.archive) and not args.force:
        eprint("already exists: %s" % args.archive)
        return 1
    r = subprocess.run([ARCHIVE_BIN, "create", args.archive], input=b"", capture_output=True)
    if r.returncode != 0:
        if r.stderr:
            sys.stderr.buffer.write(r.stderr)
        eprint("create failed")
        return 1
    return 0


def _additions_from_sources(sources, prefix):
    """Yield (source_file, arcname) pairs. A folder keeps its own name as the
    root under prefix; a file is stored as prefix + basename.

    Symlinks are collected as entries in their own right, never followed:
    os.walk (followlinks=False) lists a symlink-to-dir in dirs without
    recursing, and symlinks-to-files appear in files. Bundles (.app,
    frameworks) depend on those links; following or dropping them breaks
    code signatures ("unsealed contents" from duplicated framework binaries)."""
    pairs = []
    for src in sources:
        src = src.rstrip("/")
        if not src or not os.path.lexists(src):
            eprint("skip missing: %s" % src)
            continue
        base = os.path.basename(src)
        if os.path.isdir(src) and not os.path.islink(src):
            parent = os.path.dirname(src)
            for root, dirs, files in os.walk(src):
                for fn in files:
                    full = os.path.join(root, fn)
                    rel = os.path.relpath(full, parent)   # keeps 'base/...'
                    pairs.append((full, prefix + rel.replace(os.sep, "/")))
                for d in dirs:
                    full = os.path.join(root, d)
                    if os.path.islink(full):
                        rel = os.path.relpath(full, parent)
                        pairs.append((full, prefix + rel.replace(os.sep, "/")))
                # An empty directory has no file to imply it, so without this it
                # vanished from the archive and the add still reported success.
                # Staging recreates the directory and Info-ZIP stores it, which
                # matters for project trees and bundles that rely on the shape.
                if not dirs and not files:
                    rel = os.path.relpath(root, parent)
                    pairs.append((root, prefix + rel.replace(os.sep, "/")))
        else:
            pairs.append((src, prefix + base))
    return pairs


def _fold(s):
    """Key under which the STAGING FILESYSTEM considers two names the same.

    Staging happens on APFS, which is case- and normalization-insensitive, so a
    byte-exact comparison misses collisions the filesystem will not - and the
    loser of such a collision is written THROUGH a staged hardlink, straight
    into the user's original file (see cmd_add)."""
    return unicodedata.normalize("NFC", s).casefold()


def _unique_arc(prefix, cand, batch, existing, is_dir):
    """Finder-style free variant of <cand> within the archive: 'name', then
    'name 2', 'name 3'. Mirrors _unique_in and archive.c's unique_name. Avoids
    both what this operation has already assigned and what the archive already
    holds - an invented name must never land on either."""
    def free(x):
        k = _fold(prefix + x)
        return k not in batch and k not in existing
    if free(cand):
        return cand
    head, _, base = cand.rpartition("/")
    stem, ext = (base, "") if is_dir else os.path.splitext(base)
    n = 2
    while True:
        nxt = "%s%s %d%s" % (head + "/" if head else "", stem, n, ext)
        if free(nxt):
            return nxt
        n += 1


def _resolve_arcnames(pairs, prefix, archive):
    """Decide the archive name every source lands under, so that no two sources
    can ever be staged at the same path.

    Two jobs, one rule:

    - Fold TAB/CR/LF and any non-UTF-8 byte out of the name, so a NEW archive
      never carries a name we would have to repair on the way back out (or fold
      for display, leaving what the user sees different from what the archive
      holds).
    - Give a Finder-style counter to any name this operation has already
      assigned to something else. That covers the fold, which is lossy
      ("a<TAB>b.txt" and "a b.txt" are two files with one folded name), and the
      plainer case of two sources sharing a basename ("X/report.txt" plus
      "Y/report.txt"). Both used to collide in the staging dir, where the file
      staged first is a HARDLINK to the user's original - so the loser was
      written straight through it and the source file on disk was destroyed.

    A name that merely matches an entry the archive ALREADY holds is left alone:
    that is the in-place update the user asked for. Only an INVENTED name has to
    dodge the existing entries, which is why the archive is listed lazily - a
    clean add never reads it.

    <prefix> is the folder being added into. It is an EXISTING archive name and
    is never touched - repairing it would add to a new folder beside the one the
    user is looking at."""
    existing = None

    def load_existing():
        nonlocal existing
        if existing is None:
            listed = _archive_list(archive)
            if listed is None:
                return None
            existing = {_fold(row[0].rstrip("/")) for row in listed}
        return existing

    dirs, batch = {}, set()
    out, changed = [], 0
    for full, arc in pairs:
        is_dir = os.path.isdir(full) and not os.path.islink(full)
        parts = [c for c in arc[len(prefix):].split("/") if c]
        acc = ""
        for i, comp in enumerate(parts):
            last = (i == len(parts) - 1)
            keep = (not last) or is_dir   # a directory: remember where it landed
            key = prefix + "/".join(parts[:i + 1])
            if keep and key in dirs:
                acc = dirs[key][len(prefix):]
                continue
            rep = repair_component(comp)
            cand = (acc + "/" + rep) if acc else rep
            if rep != comp or _fold(prefix + cand) in batch:
                ex = load_existing()
                if ex is None:
                    # We are about to invent a name and zip -r REPLACES a
                    # same-named entry. Without the archive's own list there is
                    # no way to know what the invented name would land on.
                    eprint("cannot read the archive's entry list; "
                           "refusing to rename into it")
                    return None, 0
                cand = _unique_arc(prefix, cand, batch, ex, keep)
            batch.add(_fold(prefix + cand))
            if keep:
                dirs[key] = prefix + cand
            acc = cand
        new = prefix + acc
        if new != arc:
            changed += 1
            eprint("stored as: %s" % new)
        out.append((full, new))
    return out, changed


def cmd_add(args):
    # Staging mirrors the archive's folder structure on disk, so a target folder
    # whose stored name the filesystem cannot hold has nowhere to be staged. The
    # mkdir would raise EILSEQ and take the whole command down with a traceback;
    # say it in a sentence instead. (Such a folder is reachable in the UI now
    # that legacy archives list and extract.)
    if unstorable(args.prefix or ""):
        eprint("cannot add into this folder: its name in the archive contains "
               "characters this Mac cannot use in a path")
        return 1
    # Order-preserving dedup: the same path listed twice is one addition, not
    # two entries holding identical bytes.
    #
    # The key collapses only what is ALWAYS redundant - repeated slashes, "/./"
    # segments, a trailing slash. It deliberately does NOT collapse "..", which
    # os.path.normpath does: that is a lexical rewrite and it is wrong across a
    # symlink, so "s/a/link/../c.txt" and "s/a/c.txt" - two different files -
    # keyed the same and one was silently dropped at rc 0. Leaving ".." alone
    # can only ever fail the other way, letting a duplicate through, and
    # _resolve_arcnames gives that a counter rather than losing it.
    seen = set()
    sources = []
    for p in sys.stdin.read().splitlines():
        if not p.strip():
            continue
        key = re.sub(r"/+", "/", p)
        while "/./" in key:
            key = key.replace("/./", "/")
        if key.startswith("./"):
            key = key[2:]
        key = key.rstrip("/") or "/"
        if not key.startswith("/"):
            # Absolute, but by prefixing rather than os.path.abspath, which
            # calls normpath and would bring ".." collapsing back with it.
            key = os.path.join(os.getcwd(), key)
        if key not in seen:
            seen.add(key)
            sources.append(p)
    if not sources:
        eprint("no sources on stdin")
        return 1
    to_add = _additions_from_sources(sources, args.prefix or "")
    if not to_add:
        eprint("nothing to add")
        return 1
    to_add, repaired = _resolve_arcnames(to_add, args.prefix or "", args.archive)
    if to_add is None:
        return 4

    # Stage the additions under their archive names, then let Info-ZIP add them in
    # place. zip appends/updates without recompressing existing entries (libarchive
    # cannot modify in place); hardlinks avoid copying the source data. Symlinks
    # are recreated as symlinks (os.link would follow to the target) and stored as
    # such by zip -y.
    staging = tempfile.mkdtemp(prefix="zipadd-")
    staged = 0
    try:
        for full, arc in to_add:
            dst = os.path.join(staging, arc)
            os.makedirs(os.path.dirname(dst) or staging, exist_ok=True)
            # NOTHING may be written onto an already staged path. A staged file
            # is a HARDLINK to the user's original, so copy2 onto it does not
            # replace the staged copy - it writes THROUGH the link and destroys
            # the source file on disk, outside the archive entirely. The naming
            # pass above should make this unreachable; it stays because that
            # failure is silent and irreversible.
            if os.path.islink(full):
                if os.path.lexists(dst):
                    eprint("skip: %s is already staged" % arc)
                    continue
                os.symlink(os.readlink(full), dst)
                staged += 1
                continue
            if os.path.isdir(full):
                # exist_ok tolerates an existing DIRECTORY only; a file already
                # staged under this name would otherwise raise, and the reverse
                # order silently copied the file INTO the directory ("foo/foo").
                if os.path.lexists(dst) and not os.path.isdir(dst):
                    eprint("skip: %s collides with a file of the same name" % arc)
                    continue
                os.makedirs(dst, exist_ok=True)   # empty dir: shape only, no data
                staged += 1
                continue
            if os.path.lexists(dst):
                eprint("skip: %s is already staged" % arc)
                continue
            try:
                os.link(full, dst)
            except OSError:
                shutil.copy2(full, dst)
            staged += 1
        archive_abs = os.path.abspath(args.archive)
        r = subprocess.run(["/usr/bin/zip", "-r", "-q", "-X", "-y", archive_abs, "."],
                           cwd=staging, capture_output=True)
        if r.returncode != 0:
            eprint(_msg(r.stderr) or _msg(r.stdout))
            return 1
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    eprint("added %d item(s)" % staged)
    if repaired:
        eprint("%d name%s changed to fit the archive" % (repaired, "" if repaired == 1 else "s"))
    return 0


def zip_pattern(name):
    r"""Escape Info-ZIP's pattern metacharacters so `zip -d` matches <name> literally.

    zip -d takes PATTERNS, not names. An entry whose stored name contains *, ?
    or [ would otherwise take its siblings with it: `zip -d a.zip 'a?c.txt'`
    deletes abc.txt and a*c.txt as well, and reports success.

    Escaping rather than -nw is deliberate: -nw is INCOMPLETE, not inapplicable.
    It does make *, [ and \ literal for -d, but ? still globs (verified both
    orderings, with and without --), so -nw alone would silently reinstate the
    single-character-wildcard case. Backslash-escaping covers all of them; \ is
    escaped first, which the per-character map does for free.

    "/" is escaped too, and that is what makes bsdtar-style archives reachable.
    zip strips a leading "./" from the PATTERN but not from the stored name, so
    neither "foo.txt" nor "./foo.txt" matches a stored "./foo.txt" - the entry
    was simply undeletable. Escaping the slash (".\/foo.txt") suppresses that
    normalization and matches exactly. It is harmless for ordinary names."""
    return "".join("\\" + ch if ch in "\\[]*?/" else ch for ch in name)


def _resolve_targets(rows, entry, prefix):
    """Map a model name onto the archive's ACTUAL listed names.

    The model normalizes a leading "./" away, so the name the UI sends never
    matched a bsdtar-style archive and the delete silently did nothing. Going
    through the real listing fixes that, lets every descendant be named
    literally instead of globbed with "prefix*", and gives the caller a way to
    tell "nothing matched" apart from "matched and deleted". Returns a list of
    (listed_name, isdir) pairs."""
    # An empty prefix would make every startswith() true and wipe the archive.
    if entry is None and not prefix:
        return []
    # A prefix must end at a path boundary or "sub" would swallow "sub2/...".
    # In-app callers always pass the model's trailing slash; a CLI caller may not.
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    targets = []
    for name, isdir, _sz, _mt, _enc, _ad in rows:
        norm = name[2:] if name.startswith("./") else name
        if entry is not None:
            # Exact match. Comparing rstrip("/") on both sides would make a file
            # "sub" and a directory marker "sub/" collide, so deleting either one
            # destroyed the other.
            if norm == entry:
                targets.append((name, isdir))
        elif norm.startswith(prefix):
            # The folder marker "sub/" and every descendant.
            targets.append((name, isdir))
        elif isdir == "1" and norm.rstrip("/") == prefix.rstrip("/"):
            # The folder's own marker when it is reported without a trailing
            # slash. Gated on isdir so a same-named FILE is never swept up.
            targets.append((name, isdir))
    return targets


def cmd_delete(args):
    if args.entry is None and args.prefix is None:
        eprint("need --entry or --prefix")
        return 1
    rows = _archive_list(args.archive, raw=True)
    if rows is None:
        return 4
    targets = _resolve_targets(rows, args.entry, args.prefix)
    if not targets:
        eprint("nothing matched")
        return 1

    listed_names = set(n for n, *_ in rows)
    patterns = []
    for name, isdir in targets:
        patterns.append(zip_pattern(name))
        # libarchive REPORTS directory entries with a trailing "/" even when the
        # archive stores them without one, so the listed name is not always the
        # stored name. Offer the slash-less spelling too - but only when no other
        # entry already owns it, or deleting the folder "sub/" would also match a
        # sibling FILE literally named "sub". An unmatched extra pattern is just
        # a warning, and the verification below is what decides success.
        if isdir == "1" and name.endswith("/") and name[:-1] not in listed_names:
            patterns.append(zip_pattern(name[:-1]))
    # Names normally go on argv after "--", which ends zip's option parsing so an
    # entry called "-r" or "-@" is a name and not a flag. A large folder can
    # exceed ARG_MAX, so past a threshold they go on stdin via -@ instead, which
    # honors the same escaping.
    #
    # -@ splits on BOTH \n and \r, so either one in a name would cut the pattern
    # in two and the tail could match an unrelated entry - a real collateral
    # deletion, reproduced with a "big/x\ry.txt" entry taking "y.txt" with it.
    # Such names fall back to argv, where no delimiter exists. Both halves of this
    # guard are load-bearing: since the listing moved to NUL framing a newline in
    # a name survives all the way to here, where it previously could not.
    delimiter_safe = not any("\n" in p or "\r" in p for p in patterns)
    try:
        if sum(len(p) + 1 for p in patterns) > 200000 and delimiter_safe:
            r = subprocess.run(["/usr/bin/zip", "-d", args.archive, "-@"],
                               input=("\n".join(patterns) + "\n").encode("utf-8", "surrogateescape"),
                               capture_output=True)
        else:
            r = subprocess.run(["/usr/bin/zip", "-d", args.archive, "--"] + patterns,
                               capture_output=True)
    except OSError as e:
        # Only reachable when the argv fallback above is forced by a delimiter in
        # a name AND the list is enormous; better an honest error than a crash.
        eprint("could not run zip: %s" % e)
        return 1

    # Verify against the archive instead of trusting the exit code. zip exits
    # non-zero with "Nothing to do" when no pattern matched - which used to be
    # scored as SUCCESS - and treats an unmatched name as a mere warning. Re-
    # listing is the only check that cannot be fooled by either.
    after = _archive_list(args.archive, raw=True)
    if after is None:
        eprint(_msg(r.stderr) or _msg(r.stdout))
        eprint("archive unreadable after delete")
        return 1
    before_names = set(n for n, *_ in rows)
    after_names = set(n for n, *_ in after)
    target_names = set(n for n, _ in targets)
    survivors = after_names & target_names
    # Checking only that the targets are gone proves half the property. The other
    # half - that nothing ELSE was removed - is what catches a pattern matching
    # more than it should, which is the whole class of bug this rewrite exists to
    # prevent. `rows` is already in hand, so the check is free.
    collateral = (before_names - after_names) - target_names
    if collateral or survivors:
        eprint(_msg(r.stderr) or _msg(r.stdout))
        if collateral:
            eprint("delete removed %d entr%s it was not asked to: %s"
                   % (len(collateral), "y" if len(collateral) == 1 else "ies",
                      ", ".join(sorted(collateral)[:5])))
        if survivors:
            eprint("delete left %d of %d target entr%s in place"
                   % (len(survivors), len(targets), "y" if len(survivors) == 1 else "ies"))
        # 5 = the archive WAS modified, just not exactly as asked, so the caller
        # must refresh its model and treat the document as changed. 1 = nothing
        # was touched, so the caller's model is still accurate.
        return 5 if before_names != after_names else 1
    return 0


# --------------------------------------------------------------------------- main

def main(argv):
    p = argparse.ArgumentParser(prog="ziptool.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list"); sp.add_argument("archive"); sp.set_defaults(fn=cmd_list)

    sp = sub.add_parser("level")
    sp.add_argument("--tsv", required=True); sp.add_argument("--prefix", default="")
    sp.set_defaults(fn=cmd_level)

    sp = sub.add_parser("find")
    sp.add_argument("--tsv", required=True); sp.add_argument("--query", default="")
    sp.set_defaults(fn=cmd_find)

    sp = sub.add_parser("probe"); sp.add_argument("archive"); sp.set_defaults(fn=cmd_probe)

    sp = sub.add_parser("read")
    sp.add_argument("archive"); sp.add_argument("--entry", required=True)
    sp.add_argument("--pwd-stdin", action="store_true", dest="pwd_stdin")
    sp.add_argument("--max", type=int, default=0)
    sp.set_defaults(fn=cmd_read)

    sp = sub.add_parser("extract")
    sp.add_argument("archive"); sp.add_argument("--dest", required=True)
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--all", action="store_true")
    g.add_argument("--entry")
    g.add_argument("--prefix")
    sp.add_argument("--pwd-stdin", action="store_true", dest="pwd_stdin")
    sp.add_argument("--result-file", dest="result_file",
                    help="write the '<count>\\t<path>' summary here instead of stdout")
    sp.set_defaults(fn=cmd_extract)

    sp = sub.add_parser("create")
    sp.add_argument("archive")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(fn=cmd_create)

    sp = sub.add_parser("add")
    sp.add_argument("archive")
    sp.add_argument("--prefix", default="")   # archive folder to add into
    sp.set_defaults(fn=cmd_add)

    sp = sub.add_parser("delete")
    sp.add_argument("archive")
    gd = sp.add_mutually_exclusive_group(required=True)
    gd.add_argument("--entry")
    gd.add_argument("--prefix")
    sp.set_defaults(fn=cmd_delete)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
