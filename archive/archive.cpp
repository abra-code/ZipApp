/*
 * archive - libarchive-backed archive reader/extractor with a stdin passphrase.
 *
 * Purpose: give Zip.app a way to read and extract WinZip-AES (and ZipCrypto)
 * encrypted zip entries WITHOUT ever putting the password on a command line.
 * The macOS `tar`/bsdtar can decrypt AES, but it only accepts the passphrase via
 * --passphrase on argv, which leaks to `ps`. This tool links the same system
 * libarchive and hands the passphrase to archive_read_add_passphrase() in memory;
 * the secret arrives only on stdin and is never an argument.
 *
 * Usage:
 *   archive read    <archive> <entry> [--max BYTES]
 *       Stream one entry's bytes to stdout. Passphrase on stdin. For previews.
 *   archive extract <archive> <destdir> [member ...]
 *       Extract all entries (or only the listed members) into destdir, preserving
 *       the archive's internal paths. Passphrase on stdin. libarchive's secure
 *       flags reject absolute/".." escapes; the caller maps paths afterwards.
 *       A name the filesystem cannot hold is repaired for the write only - see
 *       "on-disk name repair" below.
 *
 * The passphrase is read from stdin in full; a single trailing newline (and an
 * optional preceding CR) is stripped. Empty stdin means "no passphrase".
 *
 * Exit codes (aligned with Scripts/ziptool.py):
 *   0 ok | 1 generic error / entry not found | 2 passphrase required or incorrect
 *   4 cannot open / not a valid archive
 *   5 extract only: PARTIAL - some entries were rejected (unsafe path, name
 *     collision) but everything else did extract and is on disk. The caller
 *     keeps the output and reports the skipped count; it must not present the
 *     result as a complete extraction.
 *
 * The macOS SDK ships no public archive.h, so libarchive 3.7.4's public headers
 * (archive.h, archive_entry.h - BSD 2-clause) are vendored next to this source.
 * They match the system dylib version (3.7.4 on macOS 14.6+). We still link the
 * system library via the SDK's libarchive.tbd stub (-larchive); only the
 * declarations come from the vendored headers. Both carry extern "C" guards, so
 * they are included from C++ unchanged.
 *
 * Memory and failure model (C++): every libarchive handle, FILE and buffer is
 * owned by an RAII type, so no path can leak one and none of the error returns
 * has to unwind by hand. Allocation failure arrives as an exception rather than
 * a NULL that every caller must re-check:
 *   - inside the extract loop it is caught per ENTRY and counted as skipped,
 *     because aborting would discard every file already written to disk;
 *   - inside create/recrypt it is caught around the whole loop, which then joins
 *     the ordinary failure path and unlinks the half-written output;
 *   - anything else reaches main(), which reports it and exits 1.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fstream>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "archive.h"
#include "archive_entry.h"

namespace {

/* ---- RAII handles --------------------------------------------------------- */

constexpr size_t BLOCK = 16384;

struct ArchiveReadDeleter {
    /* archive_read_free() closes first if the archive is still open, so an early
     * return needs no separate archive_read_close(). The read side never checks
     * close()'s result, so nothing is lost by letting the deleter do it. */
    void operator()(struct archive *a) const noexcept { archive_read_free(a); }
};
struct ArchiveWriteDeleter {
    /* The write side DOES check archive_write_close() - a failure there means the
     * central directory may be missing - so every writer is closed explicitly
     * before its owner is reset; this is the backstop for the exception paths. */
    void operator()(struct archive *a) const noexcept { archive_write_free(a); }
};
struct ArchiveEntryDeleter {
    void operator()(struct archive_entry *e) const noexcept { archive_entry_free(e); }
};
struct FileDeleter {
    void operator()(FILE *f) const noexcept { fclose(f); }
};

using ArchiveReadPtr  = std::unique_ptr<struct archive, ArchiveReadDeleter>;
using ArchiveWritePtr = std::unique_ptr<struct archive, ArchiveWriteDeleter>;
using ArchiveEntryPtr = std::unique_ptr<struct archive_entry, ArchiveEntryDeleter>;
using FilePtr         = std::unique_ptr<FILE, FileDeleter>;

/* Raised when no free variant of a name is left (10000 tried). Handled exactly
 * like an allocation failure at the same point: this ENTRY gets no name. */
struct NoUsableName : std::runtime_error {
    NoUsableName() : std::runtime_error("no usable name") {}
};

/* ---- helpers -------------------------------------------------------------- */

/* Read all of stdin. Secrets only ever arrive here, never on argv. NUL bytes are
 * preserved so a two-field "old\0new" payload (recrypt) round-trips intact. */
std::string slurp_stdin()
{
    std::string out;
    char tmp[256];
    ssize_t n;
    while ((n = read(STDIN_FILENO, tmp, sizeof tmp)) > 0)
        out.append(tmp, static_cast<size_t>(n));
    return out;
}

/* Copy [buf,len) into a passphrase, stripping one trailing newline (+CR).
 * An empty result means "no passphrase" - every consumer treats it that way. */
std::string strip_passphrase(const char *buf, size_t len)
{
    if (len > 0 && buf[len - 1] == '\n') {
        len--;
        if (len > 0 && buf[len - 1] == '\r') len--;
    }
    return std::string(buf, len);
}

std::string strip_passphrase(const std::string &s)
{
    return strip_passphrase(s.data(), s.size());
}

/* libarchive takes the passphrase as a C string, so it sees nothing past an
 * embedded NUL - and nothing at all when the first byte is one. The gates below
 * therefore have to ask what the LIBRARY will receive, not how many bytes
 * arrived on stdin: a payload starting with NUL is no passphrase, and treating
 * it as one would let open_zip_writer's fail-closed check pass while libarchive
 * silently registered nothing. */
bool has_passphrase(const std::string &pass)
{
    return !pass.empty() && pass[0] != '\0';
}

/* A pathname comparison that tolerates a leading "./" on either side and a
 * trailing "/" (libarchive/bsdtar store "./name"; our model uses "name"). */
const char *norm(const char *p)
{
    if (p == nullptr)
        return "";
    if (p[0] == '.' && p[1] == '/') p += 2;
    return p;
}

bool name_eq(const char *a, const char *b)
{
    a = norm(a); b = norm(b);
    size_t la = strlen(a), lb = strlen(b);
    while (la > 0 && a[la - 1] == '/') la--;
    while (lb > 0 && b[lb - 1] == '/') lb--;
    return la == lb && strncmp(a, b, la) == 0;
}

/* macOS metadata noise that is junk by NAME alone: the __MACOSX sidecar tree
 * (an archive-only convention, junk wholesale) and .DS_Store. "._*" names are
 * handled separately - only files carrying the AppleDouble magic are junk;
 * a user file that happens to be named "._foo" is real content. */
bool is_name_junk(const char *raw)
{
    const char *name = norm(raw);
    if (strncmp(name, "__MACOSX", 8) == 0 && (name[8] == '\0' || name[8] == '/'))
        return true;
    size_t len = strlen(name);
    while (len > 0 && name[len - 1] == '/') len--;
    size_t start = len;
    while (start > 0 && name[start - 1] != '/') start--;
    size_t blen = len - start;
    return blen == 9 && strncmp(name + start, ".DS_Store", 9) == 0;
}

/* AppleDouble magic (version 2): 0x00 0x05 0x16 0x07. */
const unsigned char AD_MAGIC[4] = { 0x00, 0x05, 0x16, 0x07 };

/* True when the basename starts with "._" (outside __MACOSX, which is already
 * junk by name). Such an entry is only a CANDIDATE - the AppleDouble magic in
 * its first bytes decides. */
bool is_dot_underscore(const char *raw)
{
    const char *name = norm(raw);
    if (strncmp(name, "__MACOSX", 8) == 0 && (name[8] == '\0' || name[8] == '/'))
        return false;
    size_t len = strlen(name);
    while (len > 0 && name[len - 1] == '/') len--;
    size_t start = len;
    while (start > 0 && name[start - 1] != '/') start--;
    return (len - start) >= 2 && name[start] == '.' && name[start + 1] == '_';
}

/* True when <name> (normalized) is <prefix> or lies under it; null matches all.
 * The match must end at a path boundary: a bare strncmp let "--prefix docs"
 * pull in "docs2/b.txt", so extracting one folder could silently drag in a
 * sibling whose name merely starts the same way. */
bool prefix_match(const char *name, const char *prefix)
{
    if (prefix == nullptr)
        return true;
    const char *n = norm(name);
    size_t pl = strlen(prefix);
    if (strncmp(n, prefix, pl) != 0)
        return false;
    if (pl == 0 || prefix[pl - 1] == '/')
        return true;                    /* prefix already ends at a boundary */
    return n[pl] == '\0' || n[pl] == '/';
}

/* libarchive returns NULL from archive_error_string() when it has no message,
 * and passing NULL to a "%s" conversion is undefined. Darwin's printf happens to
 * print "(null)", but a signed helper should not rely on that. */
const char *errstr(struct archive *a)
{
    const char *m = archive_error_string(a);
    return (m != nullptr) ? m : "unknown error";
}

/* Distinguish a wrong/missing passphrase from other libarchive failures. */
bool is_passphrase_error(struct archive *a)
{
    const char *m = archive_error_string(a);
    if (m == nullptr)
        return false;
    return strcasestr(m, "passphrase") != nullptr ||
           strcasestr(m, "incorrect password") != nullptr;
}

ArchiveReadPtr open_archive(const char *path, const std::string &pass)
{
    ArchiveReadPtr a(archive_read_new());
    if (!a)
        return nullptr;
    archive_read_support_format_zip(a.get());
    archive_read_support_filter_all(a.get());
    if (has_passphrase(pass))
        archive_read_add_passphrase(a.get(), pass.c_str());
    if (archive_read_open_filename(a.get(), path, BLOCK) != ARCHIVE_OK) {
        fprintf(stderr, "archive: cannot open archive: %s\n", errstr(a.get()));
        return nullptr;                 /* the deleter frees (and closes) it */
    }
    return a;
}

/* ---- read: one entry to stdout -------------------------------------------- */

int cmd_read(const char *path, const char *entry, long long maxbytes, const std::string &pass)
{
    ArchiveReadPtr a = open_archive(path, pass);
    if (!a)
        return 4;

    struct archive_entry *e;
    int rc = 1;  /* entry not found, unless we find it */
    int r;
    /* ARCHIVE_WARN: header read, entry usable - see cmd_extract. */
    while ((r = archive_read_next_header(a.get(), &e)) == ARCHIVE_OK || r == ARCHIVE_WARN) {
        if (!name_eq(archive_entry_pathname(e), entry))
            continue;
        char buf[BLOCK];
        long long written = 0;
        la_ssize_t n;
        rc = 0;
        while ((n = archive_read_data(a.get(), buf, sizeof buf)) > 0) {
            size_t want = (size_t)n;
            if (maxbytes > 0 && written + (long long)want > maxbytes)
                want = (size_t)(maxbytes - written);
            /* A short write means the consumer went away or the pipe filled and
             * failed; reporting success would hand the caller a silently
             * truncated preview. */
            if (fwrite(buf, 1, want, stdout) != want) {
                fprintf(stderr, "archive: short write to stdout\n");
                rc = 1;
                break;
            }
            written += (long long)want;
            if (maxbytes > 0 && written >= maxbytes)
                break;
        }
        if (n < 0) {
            rc = is_passphrase_error(a.get()) ? 2 : 1;
            fprintf(stderr, "archive: read error: %s\n", errstr(a.get()));
        }
        break;
    }
    if (r < ARCHIVE_OK && r != ARCHIVE_EOF && rc == 1)
        rc = is_passphrase_error(a.get()) ? 2 : 1;
    if (rc == 1 && r == ARCHIVE_EOF)
        fprintf(stderr, "archive: no such entry: %s\n", entry);

    /* fwrite into a stdio FILE only fails once the buffer flushes, so an entry
     * whose tail fits in the buffer is written entirely by this flush - its
     * return is the only place that failure can surface. */
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "archive: could not flush stdout\n");
        if (rc == 0) rc = 1;
    }
    return rc;
}

/* ---- extract: all or listed members into destdir -------------------------- */

int copy_data(struct archive *ar, struct archive *aw)
{
    for (;;) {
        const void *buff;
        size_t size;
        la_int64_t offset;
        int r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF)
            return ARCHIVE_OK;
        if (r < ARCHIVE_OK)
            return r;
        if (archive_write_data_block(aw, buff, size, offset) < ARCHIVE_OK)
            return ARCHIVE_FATAL;
    }
}

bool member_wanted(const char *name, const std::vector<const char *> &members)
{
    if (members.empty())
        return true;  /* no list => extract everything */
    for (const char *m : members)
        if (name_eq(name, m))
            return true;
    return false;
}

/* ---- on-disk name repair -------------------------------------------------- */

/*
 * macOS cannot store every name a zip can hold. APFS rejects a pathname that is
 * not well-formed UTF-8 outright ([Errno 92] Illegal byte sequence) - for a
 * plain open() as much as for libarchive - so an entry named in CP437 or
 * Shift-JIS, which is what any archive made on legacy Windows carries, could
 * not be extracted under its own name at all. TAB, CR and LF are storable but
 * unwanted: every protocol between this helper and the UI is line- or
 * tab-framed, so such a name can only ever be displayed folded.
 *
 * So the name is REPAIRED, for the write and only for the write: TAB/CR/LF
 * become a space and every byte that is not part of a well-formed UTF-8
 * sequence becomes '_'. Member matching, --prefix, and junk detection all still
 * run on the original bytes, so what the caller addresses is unchanged; only
 * the name the file lands under differs, and every such entry is reported.
 *
 * Repair is lossy - a whole Shift-JIS name collapses to a run of underscores -
 * so different entries routinely repair to the SAME name. Letting the second
 * one overwrite the first would turn a rescue into data loss, so a repaired
 * name that is already taken (on disk, or by an earlier repair in this run)
 * gets a Finder-style counter: "name 2.txt". Directory names are resolved once
 * and remembered, so everything under a repaired directory lands together in
 * that one directory rather than being scattered across several.
 */

/* Length of the well-formed UTF-8 sequence at s, or 0 if s does not start one.
 * Overlong forms, surrogates and anything above U+10FFFF are not well-formed,
 * which is exactly the set the filesystem refuses. */
size_t utf8_seq_len(const unsigned char *s, size_t len)
{
    unsigned char b = s[0];
    if (b < 0x80)
        return 1;
    if (b < 0xC2)
        return 0;  /* continuation, or overlong lead */
    if (b < 0xE0) {
        if (len < 2 || (s[1] & 0xC0) != 0x80)
            return 0;
        return 2;
    }
    if (b < 0xF0) {
        if (len < 3 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80)
            return 0;
        if (b == 0xE0 && s[1] < 0xA0)
            return 0;  /* overlong */
        if (b == 0xED && s[1] >= 0xA0)
            return 0;  /* surrogate */
        return 3;
    }
    if (b < 0xF5) {
        if (len < 4 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 ||
            (s[3] & 0xC0) != 0x80) {
            return 0;      /* braced: the condition wraps, so the body needs to stand apart */
        }
        if (b == 0xF0 && s[1] < 0x90)
            return 0;  /* overlong */
        if (b == 0xF4 && s[1] >= 0x90)
            return 0;  /* beyond U+10FFFF */
        return 4;
    }
    return 0;
}

/* Code point of the well-formed sequence at s (sl bytes, from utf8_seq_len). */
unsigned utf8_cp(const unsigned char *s, size_t sl)
{
    switch (sl) {
    case 1: return s[0];
    case 2: return ((unsigned)(s[0] & 0x1F) << 6) | (s[1] & 0x3F);
    case 3: return ((unsigned)(s[0] & 0x0F) << 12) | ((unsigned)(s[1] & 0x3F) << 6) |
                   (s[2] & 0x3F);
    default: return ((unsigned)(s[0] & 0x07) << 18) | ((unsigned)(s[1] & 0x3F) << 12) |
                    ((unsigned)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
    }
}

/* Unicode NONCHARACTERS: well-formed UTF-8, but the filesystem refuses them
 * (verified - [Errno 92], same as a bad byte). They are permanently
 * noncharacters by Unicode's stability policy, so folding them is safe forever.
 *
 * Not covered, and deliberately: APFS also refuses UNASSIGNED code points
 * (measured - U+2065, U+D7A4-D7AF, U+20C2-20CF and more all fail), and that set
 * shrinks with every Unicode revision. Repair therefore does NOT guarantee a
 * storable name; it removes the encoding-level and framing problems, which is
 * what makes legacy archives extractable. A name that survives repair and is
 * still refused is reported as skipped, exactly as before. */
bool is_noncharacter(unsigned cp)
{
    if (cp >= 0xFDD0 && cp <= 0xFDEF)
        return true;
    return (cp & 0xFFFE) == 0xFFFE;          /* U+xFFFE and U+xFFFF in every plane */
}

bool needs_repair(const char *s, size_t len)
{
    for (size_t i = 0; i < len; ) {
        unsigned char b = (unsigned char)s[i];
        if (b == '\t' || b == '\r' || b == '\n')
            return true;
        size_t sl = utf8_seq_len((const unsigned char *)s + i, len - i);
        if (sl == 0)
            return true;
        if (is_noncharacter(utf8_cp((const unsigned char *)s + i, sl)))
            return true;
        i += sl;
    }
    return false;
}

/* Repaired copy of one path component. The replacement is byte for byte, so the
 * result is never longer than the input and can never become empty, "." or ".."
 * from something that was not already that. */
std::string repair_component(const char *c, size_t len, bool &changed)
{
    std::string out;
    out.reserve(len);
    changed = false;
    for (size_t i = 0; i < len; ) {
        unsigned char b = (unsigned char)c[i];
        if (b == '\t' || b == '\r' || b == '\n') {
            out += ' ';
            i++;
            changed = true;
            continue;
        }
        size_t sl = utf8_seq_len((const unsigned char *)c + i, len - i);
        if (sl == 0) {
            out += '_';
            i++;
            changed = true;
            continue;
        }
        if (is_noncharacter(utf8_cp((const unsigned char *)c + i, sl))) {
            out.append(sl, '_');
            i += sl;
            changed = true;
            continue;
        }
        out.append(c + i, sl);
        i += sl;
    }
    return out;
}

/* The three maps are only ever populated once a name has actually needed
 * repair, so a clean archive pays nothing for them. */
struct NameMap {
    std::unordered_map<std::string, std::string> dirs;  /* original dir path -> where it landed */
    std::unordered_set<std::string> claimed;            /* every name this run invented (folded) */
    std::unordered_set<std::string> placed;             /* dev:ino of what we wrote under a chosen name */
    bool active = false;      /* set once anything has needed repair */
    bool degraded = false;    /* a name we placed could not be recorded (see below) */
};

/* The filesystem is the only exact oracle for its own idea of "same name", and
 * asking it is cheaper and more honest than carrying a case-folding table.
 * fold_key below is ASCII, so "O with stroke" and "o with stroke" - which have
 * no canonical decomposition and so are not split into an ASCII base letter -
 * fold APART here and TOGETHER on APFS. A clean entry then landed straight on
 * top of a repaired one: rc 0, "extracted 2 item(s)", one file on disk.
 *
 * So every entry written under a name we chose has its identity recorded, and a
 * clean candidate is looked up on disk: if something is already there and it is
 * one of ours, the name is taken however the filesystem happens to spell it.
 * Recording identity rather than the name is what keeps this from changing
 * ordinary behaviour - a pre-existing file in the destination is still simply
 * overwritten, exactly as before, because it is not one of ours. */
std::string ino_key(const struct stat &st)
{
    char buf[64];
    snprintf(buf, sizeof buf, "%llu:%llu", (unsigned long long)st.st_dev,
             (unsigned long long)st.st_ino);
    return std::string(buf);
}

/* False only when the identity could not be recorded; see the caller. */
bool nm_remember(NameMap &nm, const char *path) noexcept
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return true;  /* nothing there: nothing to guard */
    try {
        nm.placed.insert(ino_key(st));
    } catch (const std::bad_alloc &) {
        return false;
    }
    return true;
}

bool nm_is_ours(const NameMap &nm, const std::string &path)
{
    struct stat st;
    if ((nm.placed.empty() && !nm.degraded) || lstat(path.c_str(), &st) != 0)
        return false;
    /* Once a name we placed could not be recorded, the set is no longer a
     * complete answer, so anything already on disk has to be assumed ours. That
     * over-renames; the alternative is writing over a file we just rescued.
     * Repair CREATES these collisions - two names that were distinct in the
     * archive can fold together - so "no worse than before the guard existed"
     * is not good enough here: before the guard, they were distinct. */
    if (nm.degraded)
        return true;
    return nm.placed.count(ino_key(st)) != 0;
}

/* ASCII-lowercased copy, for keying <claimed>. The destination filesystem
 * compares case-insensitively, so a byte-exact key is not enough: after
 * "A<TAB>B.txt" is repaired to "A B.txt", a clean entry named "a b.txt" is a
 * DIFFERENT file that APFS considers the same name, and writing it would
 * destroy the repaired one.
 *
 * ASCII only, deliberately: it needs no Unicode tables and covers the names
 * that actually collide here (repair emits '_' and ' ', and the surviving parts
 * of a broken name are ASCII trail bytes). A pair differing only in a non-ASCII
 * case mapping, or only in NFC/NFD spelling, is still missed - the residual is
 * the same shape as the bug, but far rarer, and closing it exactly would mean
 * carrying a case-folding table and a normalizer in this helper. */
std::string fold_key(const std::string &s)
{
    std::string out;
    out.reserve(s.size());
    for (char ch : s) {
        unsigned char c = (unsigned char)ch;
        out += (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : (char)c;
    }
    return out;
}

bool claimed_has(const std::unordered_set<std::string> &claimed, const std::string &name)
{
    return claimed.count(fold_key(name)) != 0;
}

void claim(std::unordered_set<std::string> &claimed, const std::string &name)
{
    claimed.insert(fold_key(name));
}

/* Free variant of <cand>, Finder-style: "name", then "name 2", "name 3", ...
 * The counter goes before the extension for a file and at the end for a
 * directory, matching ziptool's _unique_in so a rename looks the same wherever
 * it happens. Throws NoUsableName if 10000 variants are all taken. */
std::string unique_name(const std::unordered_set<std::string> &claimed,
                        const std::string &cand, bool is_dir)
{
    struct stat st;
    if (!claimed_has(claimed, cand) && lstat(cand.c_str(), &st) != 0)
        return cand;

    size_t slash = cand.rfind('/');
    size_t dlen = (slash != std::string::npos) ? slash + 1 : 0;
    std::string dir = cand.substr(0, dlen);
    std::string base = cand.substr(dlen);
    size_t dot = is_dir ? std::string::npos : base.rfind('.');
    if (dot == 0) dot = std::string::npos;       /* ".hidden" is not an extension */
    std::string stem = (dot != std::string::npos) ? base.substr(0, dot) : base;
    std::string ext  = (dot != std::string::npos) ? base.substr(dot) : std::string();

    for (int n = 2; n <= 10000; n++) {
        std::string x = dir + stem + ' ' + std::to_string(n) + ext;
        if (!claimed_has(claimed, x) && lstat(x.c_str(), &st) != 0)
            return x;
    }
    throw NoUsableName();
}

/* The name <raw> should land under on disk, or nullopt to extract it unchanged
 * (which is the answer for every entry in an ordinary archive). Throws when no
 * name can be settled on at all; the caller counts that entry as skipped.
 *
 * <invented> marks a name WE made up rather than read from the archive. Such a
 * name has to dodge whatever is already there even though it needs no repair:
 * an archive holding a real file called "unnamed 1" next to an entry whose name
 * libarchive discarded would otherwise have one written over the other. */
std::optional<std::string> resolve_disk_path(NameMap &nm, const char *raw, bool is_dir,
                                             bool invented)
{
    const char *p = norm(raw);
    if (p[0] == '\0' || p[0] == '/')
        return std::nullopt;    /* absolute: leave it to ARCHIVE_EXTRACT_SECURE_* */

    /* A ".." component is precisely what ARCHIVE_EXTRACT_SECURE_NODOTDOT exists
     * to reject. Rewriting such a path could only ever help it through, so it
     * is handed to libarchive exactly as it arrived. */
    for (const char *c = p; ; ) {
        const char *e = strchr(c, '/');
        size_t n = (e != nullptr) ? (size_t)(e - c) : strlen(c);
        if (n == 2 && c[0] == '.' && c[1] == '.')
            return std::nullopt;
        if (e == nullptr)
            break;
        c = e + 1;
    }

    size_t plen = strlen(p);
    bool trailing = (plen > 0 && p[plen - 1] == '/');
    while (plen > 0 && p[plen - 1] == '/') plen--;
    if (plen == 0)
        return std::nullopt;

    /* Until something has needed repair there is no invented name for a clean
     * one to collide with, so nothing has to be tracked at all. */
    if (!nm.active && !invented && !needs_repair(p, plen))
        return std::nullopt;

    /* "a//b" and "a/./b" are both "a/b", so those components are skipped rather
     * than carried. That is what lets the memo key below be the CANONICAL
     * original path: keyed on raw bytes, "a/b/f1" and "a//b/f2" looked like two
     * different directories, so a repaired "b" was resolved twice and its
     * contents were split between two folders. (".." cannot appear here - it
     * was rejected above, before any of this.) One pass first to find where the
     * final real component starts, so each one knows whether it is the last. */
    size_t last_start = 0;
    for (size_t k = 0; k < plen; ) {
        size_t m = k;
        while (m < plen && p[m] != '/') m++;
        if (!(m == k || (m - k == 1 && p[k] == '.')))
            last_start = k;
        k = m + 1;
    }

    std::string acc;        /* resolved path so far */
    std::string oacc;       /* the same prefix in ORIGINAL bytes, canonicalized */
    bool repaired = false;  /* a component was actually rewritten */
    size_t i = 0;
    while (i < plen) {
        size_t j = i;
        while (j < plen && p[j] != '/') j++;
        size_t clen = j - i;
        if (clen == 0 || (clen == 1 && p[i] == '.')) {
            i = j + 1;
            continue;
        }
        bool last = (i == last_start);
        /* Every DIRECTORY path - a prefix walked through, or a directory entry
         * in its own right - is resolved once and remembered, even when it comes
         * through unchanged. Without that, a later entry could find the name
         * taken by an earlier repair and take a counter of its own, scattering
         * one directory's contents across several; and an archive storing "d/"
         * before "d/f.txt" would resolve that name twice and leave the children
         * beside the empty first copy. */
        bool is_dir_component = (!last || is_dir);

        std::string okey;
        if (is_dir_component) {
            okey = oacc;
            if (!okey.empty()) okey += '/';
            okey.append(p + i, clen);
            auto hit = nm.dirs.find(okey);
            if (hit != nm.dirs.end()) {
                /* A remembered directory may have landed somewhere else. This
                 * entry moves with it, and that IS a rewrite of this entry's
                 * path even though none of its own components changed - without
                 * this the children of a repaired directory were handed back
                 * unchanged and went on failing to extract. */
                if (hit->second != okey)
                    repaired = true;
                acc = hit->second;
                oacc = std::move(okey);
                i = j + 1;
                continue;
            }
        }

        bool changed = false;
        std::string rep = repair_component(p + i, clen, changed);
        std::string cand;
        if (!acc.empty()) { cand = acc; cand += '/'; }
        cand += rep;

        if (invented && last) changed = true;   /* our name, so it must claim a slot */
        if (changed) { nm.active = true; repaired = true; }
        bool taken = claimed_has(nm.claimed, cand);
        /* Ask the filesystem whether this clean name is already one of ours
         * under a spelling the ASCII fold cannot see (see nm_is_ours). */
        if (!changed && !taken && nm_is_ours(nm, cand))
            taken = true;
        if (changed || taken) {
            std::string u = unique_name(nm.claimed, cand, is_dir_component);
            if (u != cand)
                repaired = true;
            cand = std::move(u);
            nm.active = true;
            claim(nm.claimed, cand);
        }
        if (is_dir_component) {
            nm.dirs.emplace(okey, cand);        /* first mapping wins */
            oacc = std::move(okey);             /* canonical original prefix, for the next key */
        } else {
            oacc.clear();
        }
        acc = std::move(cand);
        i = j + 1;
    }

    if (acc.empty())
        return std::nullopt;
    /* Only a real rewrite counts. Collapsing "a//b" to "a/b" changes the string
     * but not where the file lands, and reporting it would tell the user a name
     * had characters the filesystem could not hold when it did not. */
    if (!repaired)
        return std::nullopt;
    if (trailing) acc += '/';               /* keep the directory shape */
    return acc;
}

int cmd_extract(const char *path, const char *destdir, const std::vector<const char *> &members,
                const char *prefix, bool skip_junk, bool progress, const std::string &pass)
{
    /* Open the archive before chdir so a relative <archive> still resolves
     * against the original cwd; the open fd survives the chdir below. */
    ArchiveReadPtr a = open_archive(path, pass);
    if (!a)
        return 4;

    if (chdir(destdir) != 0) {
        fprintf(stderr, "archive: cannot enter destination: %s\n", destdir);
        return 1;
    }

    ArchiveWritePtr ext(archive_write_disk_new());
    if (!ext) {
        fprintf(stderr, "archive: out of memory\n");
        return 1;
    }
    archive_write_disk_set_options(ext.get(), ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_TIME |
                                   ARCHIVE_EXTRACT_SECURE_SYMLINKS | ARCHIVE_EXTRACT_SECURE_NODOTDOT |
                                   ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS);
    archive_write_disk_set_standard_lookup(ext.get());

    NameMap nm;

    struct archive_entry *e;
    int rc = 0, r = ARCHIVE_EOF, count = 0, skipped = 0, renamed = 0, unnamed = 0;
    try {
    /* ARCHIVE_WARN from next_header means "header read, something about it was
     * odd" - the entry is complete and usable. Treating it as the end of the
     * archive made ONE bad header condemn the whole file: an archive whose
     * UTF-8 flag is set on a name that is not UTF-8 (legacy Windows archivers
     * do this) warns on that entry, and every entry after it was lost. */
    while ((r = archive_read_next_header(a.get(), &e)) == ARCHIVE_OK || r == ARCHIVE_WARN) {
        if (r == ARCHIVE_WARN)
            fprintf(stderr, "archive: header warning: %s\n", errstr(a.get()));
        const char *pathname = archive_entry_pathname(e);
        if (!member_wanted(pathname, members))
            continue;
        if (!prefix_match(pathname, prefix))
            continue;
        if (skip_junk && is_name_junk(pathname))
            continue;
        /* "._*" files: peek the first data block and skip only true AppleDouble
         * sidecars (magic 00 05 16 07); a user file merely named "._foo" is
         * extracted. The peeked block is written after the header below. The
         * passphrase (if any) is active here, so encrypted entries peek fine. */
        bool peeked = false; const void *pbuff = nullptr; size_t psize = 0; la_int64_t poffset = 0;
        if (skip_junk && S_ISREG(archive_entry_filetype(e)) && is_dot_underscore(pathname)) {
            int pr = archive_read_data_block(a.get(), &pbuff, &psize, &poffset);
            if (pr == ARCHIVE_OK) {
                peeked = true;
                if (psize >= sizeof AD_MAGIC && memcmp(pbuff, AD_MAGIC, sizeof AD_MAGIC) == 0)
                    continue;   /* true AppleDouble: junk (rest auto-skipped by next_header) */
            } else if (pr != ARCHIVE_EOF) {   /* EOF = empty file: keep it */
                rc = is_passphrase_error(a.get()) ? 2 : 1;
                fprintf(stderr, "archive: extract error: %s\n", errstr(a.get()));
                break;
            }
        }
        /* libarchive DISCARDS a name it cannot decode: when the zip's UTF-8 flag
         * is set on bytes that are not UTF-8, next_header warns and the pathname
         * comes back NULL. The entry's DATA is still perfectly readable, so
         * giving it a name of our own recovers a file that is otherwise
         * unreachable through this tool. It is marked invented so it claims its
         * slot properly - a real "unnamed 1" in the same archive must not be
         * written over. The filters above ran on the real (empty) name, so a
         * --prefix run correctly leaves it out: it belongs to no folder. */
        char synth[32];
        bool invented = false;
        if (pathname == nullptr || pathname[0] == '\0') {
            snprintf(synth, sizeof synth, "unnamed %d", unnamed + 1);
            unnamed++;
            pathname = synth;
            invented = true;
        }
        /* Everything above matched on the bytes the archive actually holds. From
         * here the entry carries the name it will land under, which is also the
         * name the diagnostics below should show. */
        std::optional<std::string> disk;
        try {
            disk = resolve_disk_path(nm, pathname, S_ISDIR(archive_entry_filetype(e)) != 0,
                                     invented);
        } catch (const std::exception &) {
            /* Could not settle on a name (allocation failure, or 10000 variants
             * of one already taken). That is a per-ENTRY failure and is counted
             * like any other: aborting the run here would discard every file
             * already extracted, which is exactly the trade the rejected-header
             * path below refuses to make. */
            fprintf(stderr, "archive: no usable name for %s\n", pathname);
            skipped++;
            continue;
        }
        bool renamed_this_entry = disk.has_value();
        if (disk) {
            /* Both names: the one the archive holds is what the user will be
             * looking for, and for a tab/CR/LF fold it is perfectly readable.
             * (Undecodable bytes go out as-is; stderr is a byte stream.) An
             * invented name has no "from" side to show. */
            if (invented)
                fprintf(stderr, "archive: entry with an unusable name stored as %s\n", disk->c_str());
            else
                fprintf(stderr, "archive: renamed %s -> %s\n", pathname, disk->c_str());
            archive_entry_copy_pathname(e, disk->c_str());
            pathname = archive_entry_pathname(e);
            renamed++;
        }
        /* Only ARCHIVE_OK and ARCHIVE_WARN mean the entry exists on disk now.
         * WARN is a partial success (some attribute could not be restored) and
         * MUST still receive its data - skipping it left a 0-byte file.
         *
         * Anything worse means nothing was created, but that is NOT necessarily
         * an extraction failure: ARCHIVE_FAILED is the by-design outcome for
         * every entry the ARCHIVE_EXTRACT_SECURE_* flags reject (absolute path,
         * "..", traversal through a symlink) and for local defects such as a
         * name colliding with an existing file. Failing the whole run over one
         * of those would discard every good file with it - a far bigger loss
         * than the rejected entry. So count it and keep going; the exit code
         * (5) and the count tell the caller the result is partial, which is what
         * actually matters: a partial extraction must never be presented as
         * complete. Only ARCHIVE_FATAL, where the writer is unusable, aborts. */
        int wh = archive_write_header(ext.get(), e);
        if (wh != ARCHIVE_OK && wh != ARCHIVE_WARN) {
            fprintf(stderr, "archive: skipped %s: %s\n",
                    pathname ? pathname : "(unnamed)", errstr(ext.get()));
            skipped++;
            if (wh == ARCHIVE_FATAL) {
                rc = 1;
                break;
            }
            continue;
        }
        if (wh == ARCHIVE_WARN)
            fprintf(stderr, "archive: warning: %s\n", errstr(ext.get()));
        /* Regular files carry data; symlinks and directories are fully described
         * by the header (the zip reader resolves symlink targets on open). */
        if (S_ISREG(archive_entry_filetype(e))) {
            if (peeked && archive_write_data_block(ext.get(), pbuff, psize, poffset) < ARCHIVE_OK) {
                rc = 1;
                fprintf(stderr, "archive: write data: %s\n", errstr(ext.get()));
                break;
            }
            if (copy_data(a.get(), ext.get()) < ARCHIVE_OK) {
                rc = is_passphrase_error(a.get()) ? 2 : 1;
                fprintf(stderr, "archive: extract error: %s\n", errstr(a.get()));
                break;
            }
        }
        /* finish_entry is where deferred work lands (padding a sparse file,
         * restoring times). A failure here means the entry is on disk but not
         * intact, so it must not be counted as extracted - same partial-result
         * accounting as a rejected header above. */
        int fe = archive_write_finish_entry(ext.get());
        if (fe != ARCHIVE_OK && fe != ARCHIVE_WARN) {
            fprintf(stderr, "archive: incomplete %s: %s\n",
                    pathname ? pathname : "(unnamed)", errstr(ext.get()));
            skipped++;
            if (fe == ARCHIVE_FATAL) {
                rc = 1;
                break;
            }
            continue;
        }
        /* Now that it is genuinely on disk, remember what we put there, so a
         * later clean name that the filesystem considers the same cannot land
         * on top of it (see nm_is_ours). Only names WE chose need guarding. */
        if (renamed_this_entry && !nm_remember(nm, archive_entry_pathname(e))) {
            /* Not fatal, deliberately: the entry IS on disk, and aborting would
             * throw away every file already extracted - the same trade the
             * name-resolution failure above refuses to make. Instead the map is
             * marked incomplete, and from here nm_is_ours assumes anything on
             * disk is ours. That renames more than it needs to, which is the
             * only direction that cannot destroy a file. */
            nm.degraded = true;
            fprintf(stderr, "archive: out of memory tracking extracted names; "
                            "later entries will be renamed more conservatively\n");
        }
        /* One stdout line per extracted file/symlink (dirs excluded) so the
         * caller can turn the stream into live progress. The line carries only
         * the running number - entry names could contain newlines and corrupt
         * the line-per-file contract. */
        if (progress && !S_ISDIR(archive_entry_filetype(e))) {
            printf("%d\n", count + 1);
            fflush(stdout);
        }
        count++;
    }
    } catch (const std::exception &ex) {
        /* Nothing inside the loop allocates outside the guarded name resolution,
         * so this is the last resort. Everything already written stays on disk
         * and the close below still runs; the run is reported as failed. */
        fprintf(stderr, "archive: %s\n", ex.what());
        rc = 1;
    }
    if (r < ARCHIVE_OK && r != ARCHIVE_EOF && rc == 0)
        rc = is_passphrase_error(a.get()) ? 2 : 1;

    /* Checked for symmetry only: archive_write_disk's close() just forwards the
     * last finish_entry, which is already ARCHIVE_OK here because the loop calls
     * finish_entry per entry. The deferred directory fixups it performs (times,
     * permissions, ACLs, flags) have their return values discarded internally,
     * so libarchive offers no way to detect a failure in them. */
    int cl = archive_write_close(ext.get());
    if (cl != ARCHIVE_OK && cl != ARCHIVE_WARN) {
        fprintf(stderr, "archive: close: %s\n", errstr(ext.get()));
        if (rc == 0)
            rc = 1;
    }

    /* Promote to "partial" only after the read-side result is known, so a real
     * passphrase error still surfaces as 2 rather than being masked by a skip. */
    if (rc == 0 && skipped > 0)
        rc = 5;

    /* Machine-readable tail for the caller's progress stream: entry names could
     * contain newlines, but this line is a fixed keyword plus an integer. */
    if (progress) {
        printf("skipped %d\n", skipped);
        printf("renamed %d\n", renamed);
        fflush(stdout);
    }
    if (rc == 0)
        fprintf(stderr, "archive: extracted %d item(s)\n", count);
    else if (rc == 5)
        fprintf(stderr, "archive: extracted %d item(s), %d not extracted\n", count, skipped);
    if (renamed > 0)
        fprintf(stderr, "archive: %d name(s) could not be stored as-is and were changed\n",
                renamed);
    return rc;
}

/* ---- list: one record per entry (no passphrase needed) -------------------- */

/* Emits six fields per entry: pathname, isdir, size, mtime, enc, ad.
 * mtime is "YYYY-MM-DD HH:MM" (local) or empty; enc is 1 if the entry is
 * encrypted; ad is 1 for a "._*" file confirmed (or, when encrypted,
 * presumed) to be an AppleDouble sidecar. The zip central directory
 * (names/sizes/flags) is not encrypted, so this works without a password.
 *
 * Two output shapes:
 *   default  TAB between fields, NEWLINE between records. Human/CLI readable,
 *            but LOSSY: a zip name may legally contain a tab or a newline, and
 *            either one silently corrupts the record.
 *   --nul    every field NUL-terminated, six per record. A pathname comes from
 *            libarchive as a C string and therefore cannot contain NUL, so this
 *            is unambiguous for every name a zip can hold. Zip.app always uses
 *            it - the delimiters are the only bytes a name cannot contain, so
 *            nothing needs escaping and nothing can be truncated or split. */
void put_field(const char *s)
{
    if (s != nullptr)
        fwrite(s, 1, strlen(s), stdout);
    fputc('\0', stdout);
}

int cmd_list(const char *path, bool nul)
{
    ArchiveReadPtr a(archive_read_new());
    if (!a)
        return 1;
    archive_read_support_format_zip(a.get());
    archive_read_support_filter_all(a.get());
    if (archive_read_open_filename(a.get(), path, BLOCK) != ARCHIVE_OK) {
        fprintf(stderr, "archive: cannot open archive: %s\n", errstr(a.get()));
        return 4;
    }
    struct archive_entry *e;
    int r, warned = 0;
    char tbuf[32];
    /* ARCHIVE_WARN: header read, entry usable - see cmd_extract. Stopping here
     * made a single odd header report the whole archive as invalid, which in the
     * app means "not a valid zip" and no listing at all. */
    while ((r = archive_read_next_header(a.get(), &e)) == ARCHIVE_OK || r == ARCHIVE_WARN) {
        if (r == ARCHIVE_WARN)
            warned++;
        const char *name = archive_entry_pathname(e);
        if (name == nullptr)
            continue;
        int isdir = S_ISDIR(archive_entry_filetype(e)) ? 1 : 0;
        long long size = (long long) archive_entry_size(e);
        time_t mt = archive_entry_mtime(e);
        tbuf[0] = '\0';
        if (mt > 0) {
            struct tm tmv;
            localtime_r(&mt, &tmv);
            if (tmv.tm_year + 1900 >= 1980)
                strftime(tbuf, sizeof tbuf, "%Y-%m-%d %H:%M", &tmv);
        }
        int enc = archive_entry_is_encrypted(e) ? 1 : 0;
        /* ad: 1 when a "._*" regular file is a (confirmed or presumed)
         * AppleDouble sidecar. Unencrypted candidates are peeked for the magic;
         * encrypted ones cannot be read without a password here, so they keep
         * the name-based presumption. 0 for everything else. */
        int ad = 0;
        if (!isdir && S_ISREG(archive_entry_filetype(e)) && is_dot_underscore(name)) {
            if (enc) {
                ad = 1;
            } else {
                unsigned char m[sizeof AD_MAGIC];
                la_ssize_t n = archive_read_data(a.get(), m, sizeof m);
                ad = (n == (la_ssize_t)sizeof m && memcmp(m, AD_MAGIC, sizeof m) == 0) ? 1 : 0;
            }
        }
        if (nul) {
            char nbuf[32];
            put_field(name);
            snprintf(nbuf, sizeof nbuf, "%d", isdir);   put_field(nbuf);
            snprintf(nbuf, sizeof nbuf, "%lld", size);  put_field(nbuf);
            put_field(tbuf);
            snprintf(nbuf, sizeof nbuf, "%d", enc);     put_field(nbuf);
            snprintf(nbuf, sizeof nbuf, "%d", ad);      put_field(nbuf);
        } else {
            printf("%s\t%d\t%lld\t%s\t%d\t%d\n", name, isdir, size, tbuf, enc, ad);
        }
    }
    if (r < ARCHIVE_OK && r != ARCHIVE_EOF) {
        fprintf(stderr, "archive: list error: %s\n", errstr(a.get()));
        return 1;
    }
    /* One line, not one per entry: an archive that warns usually warns about
     * every entry, and the listing is run on every UI refresh. */
    if (warned > 0)
        fprintf(stderr, "archive: %d entr%s had a header warning\n",
                warned, warned == 1 ? "y" : "ies");
    /* A short write would hand the caller a TRUNCATED listing with a success
     * code, and cmd_delete diffs before/after listings as sets - a truncated
     * "after" reads as entries removed that were never targeted. Same class as
     * the fwrite check in cmd_read. */
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "archive: list: write failed\n");
        return 1;
    }
    return 0;
}

/* ---- write path: create / recrypt ----------------------------------------- */

/* Open a zip writer for <dst> with encryption <mode> ("aes256"|"zipcrypt"|"none")
 * and an in-memory passphrase. Fails closed: an encryption mode with no
 * passphrase, an unknown mode, or an encryption option the library rejects all
 * return null rather than silently producing an unencrypted archive. */
ArchiveWritePtr open_zip_writer(const char *dst, const char *mode, const std::string &pass)
{
    bool want_enc = (strcmp(mode, "aes256") == 0 || strcmp(mode, "zipcrypt") == 0);
    if (!want_enc && strcmp(mode, "none") != 0) {
        fprintf(stderr, "archive: unknown mode '%s' (use aes256|zipcrypt|none)\n", mode);
        return nullptr;
    }
    if (want_enc && !has_passphrase(pass)) {
        fprintf(stderr, "archive: encryption mode '%s' requires a passphrase\n", mode);
        return nullptr;
    }
    ArchiveWritePtr w(archive_write_new());
    if (!w)
        return nullptr;
    archive_write_set_format_zip(w.get());
    if (want_enc) {
        const char *opt = (strcmp(mode, "aes256") == 0) ? "zip:encryption=aes256"
                                                        : "zip:encryption=zipcrypt";
        if (archive_write_set_options(w.get(), opt) != ARCHIVE_OK) {
            fprintf(stderr, "archive: encryption option rejected: %s\n", errstr(w.get()));
            return nullptr;
        }
        archive_write_set_passphrase(w.get(), pass.c_str());
    }
    if (archive_write_open_filename(w.get(), dst) != ARCHIVE_OK) {
        fprintf(stderr, "archive: cannot create %s: %s\n", dst, errstr(w.get()));
        return nullptr;
    }
    return w;
}

/* recrypt: copy every entry of <src> into a fresh <dst>, changing encryption.
 * Reads with oldpass (if the source is encrypted), writes with newpass per mode.
 * No entry is filtered - this faithfully re-encrypts the whole archive. */
int cmd_recrypt(const char *src, const char *dst, const char *mode,
                const std::string &oldpass, const std::string &newpass)
{
    /* Allocated BEFORE the writer opens <dst>: everything from here to the try
     * below has to be non-throwing, because an exception between creating the
     * file and entering the try would unwind past the unlink at the end - and
     * the writer's deleter would close it on the way out, finalizing an empty
     * but structurally valid zip that the caller cannot tell from a real one. */
    std::vector<char> buf(BLOCK);

    ArchiveReadPtr a = open_archive(src, oldpass);
    if (!a)
        return 4;
    ArchiveWritePtr w = open_zip_writer(dst, mode, newpass);
    if (!w)
        return 1;

    struct archive_entry *e;
    int rc = 0, r = ARCHIVE_EOF, count = 0;
    try {
    /* ARCHIVE_WARN: header read, entry usable - see cmd_extract. Stopping here
     * would silently drop that entry and every one after it from the rewritten
     * archive, which for recrypt means losing data outright. */
    while ((r = archive_read_next_header(a.get(), &e)) == ARCHIVE_OK || r == ARCHIVE_WARN) {
        /* A WARN header can arrive with the pathname DISCARDED (NULL) - see
         * cmd_extract. The zip writer dereferences it unconditionally, so this
         * has to fail CLOSED: an archive whose entries we cannot all name is
         * one we must not rewrite. Extraction can invent a name because it only
         * creates files; recrypt replaces the user's archive, and inventing a
         * name there would store something they never chose under a command
         * that is only supposed to change the password. */
        if (archive_entry_pathname(e) == nullptr) {
            fprintf(stderr, "archive: an entry name could not be decoded; "
                            "refusing to rewrite this archive\n");
            rc = 1;
            break;
        }
        if (archive_write_header(w.get(), e) != ARCHIVE_OK) {
            fprintf(stderr, "archive: write header: %s\n", errstr(w.get()));
            rc = 1;
            break;
        }
        la_ssize_t n; bool werr = false;
        while ((n = archive_read_data(a.get(), buf.data(), buf.size())) > 0) {
            if (archive_write_data(w.get(), buf.data(), (size_t)n) < 0) {
                werr = true;
                break;
            }
        }
        if (werr) {
            fprintf(stderr, "archive: write data: %s\n", errstr(w.get()));
            rc = 1;
            break;
        }
        if (n < 0) {
            rc = is_passphrase_error(a.get()) ? 2 : 1;
            fprintf(stderr, "archive: read error: %s\n", errstr(a.get()));
            break;
        }
        count++;
    }
    } catch (const std::exception &ex) {
        fprintf(stderr, "archive: %s\n", ex.what());
        rc = 1;
    }
    if (r < ARCHIVE_OK && r != ARCHIVE_EOF && rc == 0)
        rc = is_passphrase_error(a.get()) ? 2 : 1;

    if (archive_write_close(w.get()) != ARCHIVE_OK && rc == 0) rc = 1;
    w.reset();                         /* flush and release before unlinking */
    if (rc != 0) unlink(dst);          /* same reason as cmd_create */
    if (rc == 0)
        fprintf(stderr, "archive: rewrote %d entr%s -> %s (%s)\n",
                count, count == 1 ? "y" : "ies", dst, mode);
    return rc;
}

/* create: build a fresh <dst> zip from a manifest file of "arcname\tsrcpath"
 * lines (paths are not secret, so the manifest is a plain file argument).
 * Optional encryption via <mode>+passphrase. */
int cmd_create(const char *dst, const char *manifest, const char *mode, const std::string &pass)
{
    /* std::getline rather than fgets: a manifest line is one source path, and a
     * fixed line buffer silently split any path longer than it into two bogus
     * lines. The payload below stays on stdio - it needs ferror() to tell a read
     * error from a clean EOF. */
    std::ifstream mf;
    if (manifest != nullptr) {
        mf.open(manifest, std::ios::binary);
        if (!mf.is_open()) {
            fprintf(stderr, "archive: cannot read manifest: %s\n", manifest);
            return 1;
        }
    }
    /* Before the writer opens <dst> - see the note in cmd_recrypt. */
    std::vector<char> buf(BLOCK);

    ArchiveWritePtr w = open_zip_writer(dst, mode, pass);
    if (!w)
        return 1;

    int rc = 0, count = 0;
    try {
    std::string line;
    while (manifest != nullptr && std::getline(mf, line)) {
        /* A path cannot contain NUL, so a line that does is malformed. getline
         * keeps those bytes where fgets+strlen ended the line at the first one,
         * and without this the tab AFTER an embedded NUL would still be found -
         * storing an entry under a name silently truncated at the NUL instead of
         * rejecting the line. Ending the line where a C string would keeps the
         * malformed input an error. */
        size_t nul = line.find('\0');
        if (nul != std::string::npos)
            line.resize(nul);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();
        if (line.empty())
            continue;
        size_t tab = line.find('\t');
        if (tab == std::string::npos) {
            fprintf(stderr, "archive: bad manifest line (no tab)\n");
            rc = 1;
            break;
        }
        std::string arcname = line.substr(0, tab);
        std::string srcpath = line.substr(tab + 1);

        /* lstat, not stat: a symlink must be archived as a symlink entry, never
         * silently replaced by its target (duplicated framework binaries broke
         * code signatures: "unsealed contents" on extraction). */
        struct stat st;
        if (lstat(srcpath.c_str(), &st) != 0) {
            fprintf(stderr, "archive: cannot stat %s\n", srcpath.c_str());
            rc = 1;
            break;
        }

        ArchiveEntryPtr e(archive_entry_new());
        if (!e) {
            fprintf(stderr, "archive: out of memory\n");
            rc = 1;
            break;
        }
        archive_entry_set_pathname(e.get(), arcname.c_str());
        archive_entry_copy_stat(e.get(), &st);
        if (S_ISLNK(st.st_mode)) {
            char target[4096];
            ssize_t tl = readlink(srcpath.c_str(), target, sizeof target - 1);
            if (tl < 0 || tl >= (ssize_t)(sizeof target - 1)) {
                /* error, or target possibly truncated - storing a wrong link
                 * target silently would corrupt the archive's content */
                fprintf(stderr, "archive: cannot readlink %s\n", srcpath.c_str());
                rc = 1;
                break;
            }
            target[tl] = '\0';
            archive_entry_set_symlink(e.get(), target);
        }
        if (archive_write_header(w.get(), e.get()) != ARCHIVE_OK) {
            fprintf(stderr, "archive: write header: %s\n", errstr(w.get()));
            rc = 1;
            break;
        }
        if (S_ISREG(st.st_mode)) {
            FilePtr in(fopen(srcpath.c_str(), "rb"));
            if (!in) {
                fprintf(stderr, "archive: cannot open %s\n", srcpath.c_str());
                rc = 1;
                break;
            }
            size_t got;
            while ((got = fread(buf.data(), 1, buf.size(), in.get())) > 0) {
                la_ssize_t nw = archive_write_data(w.get(), buf.data(), got);
                if (nw < 0) {
                    fprintf(stderr, "archive: write data: %s\n", errstr(w.get()));
                    rc = 1;
                    break;
                }
                /* nw < got is NOT truncation here: libarchive's zip writer clamps
                 * each write to the size declared from lstat, so a source file
                 * that grew after we stat'd it returns a short count with no
                 * error set. The excess is dropped and the entry still matches
                 * its declared size. Treating that as failure aborted the whole
                 * create on a perfectly ordinary growing file. */
            }
            /* fread returning 0 means EOF *or* error, and treating an I/O error
             * as a clean EOF stored a truncated entry and still exited 0. */
            if (rc == 0 && ferror(in.get())) {
                fprintf(stderr, "archive: read error on %s\n", srcpath.c_str());
                rc = 1;
            }
            if (rc != 0)
                break;
        }
        count++;
    }
    } catch (const std::exception &ex) {
        fprintf(stderr, "archive: %s\n", ex.what());
        rc = 1;
    }
    if (archive_write_close(w.get()) != ARCHIVE_OK && rc == 0) rc = 1;
    w.reset();                         /* flush and release before unlinking */
    /* Never leave a half-written archive behind for the caller to mistake for a
     * real one - the same cleanup do_recrypt does on the Python side. */
    if (rc != 0) unlink(dst);
    if (rc == 0)
        fprintf(stderr, "archive: created %s with %d file(s) (%s)\n", dst, count, mode);
    return rc;
}

/* ---- main ----------------------------------------------------------------- */

int usage()
{
    fprintf(stderr,
        "usage (passphrases always arrive on stdin, never on argv):\n"
        "  archive read    <archive> <entry> [--max BYTES]      # entry -> stdout\n"
        "  archive extract <archive> <destdir> [member ...] [--prefix P] [--skip-junk] [--progress]\n"
        "                                                       # extract all, listed members, or entries under P;\n"
        "                                                       # --skip-junk drops __MACOSX/._*/.DS_Store;\n"
        "                                                       # --progress prints one line per extracted file,\n"
        "                                                       # then 'skipped N' and 'renamed N';\n"
        "                                                       # names the filesystem cannot hold (not UTF-8) or\n"
        "                                                       # that carry a TAB/CR/LF are repaired for the write\n"
        "                                                       # and reported - matching is always on the originals\n"
        "  archive list    <archive> [--nul]                    # path,isdir,size,mtime,enc,ad per entry (no password)\n"
        "                                                       # default: TAB between fields, NEWLINE between records (lossy -\n"
        "                                                       # a zip name may contain either); --nul: every field NUL-terminated,\n"
        "                                                       # six per record, unambiguous for any name a zip can hold\n"
        "  archive create  <dest.zip> [--manifest <file>] [--encrypt aes256|zipcrypt]\n"
        "                                                       # build zip from 'arcname<TAB>srcpath' lines (empty if no manifest)\n"
        "  archive recrypt <src> <dest.zip> --mode aes256|zipcrypt|none [--old-pwd-stdin] [--new-pwd-stdin]\n"
        "                                                       # stdin: oldpw | newpw | oldpw NUL newpw\n");
    return 1;
}

int run(int argc, char **argv)
{
    if (argc < 2)
        return usage();

    const char *cmd = argv[1];

    /* list needs no passphrase, so don't slurp stdin for it (the caller may not
     * close stdin, which would otherwise block). */
    if (strcmp(cmd, "list") == 0) {
        if (argc < 3)
            return usage();
        bool nul = false;
        for (int i = 3; i < argc; i++)
            if (strcmp(argv[i], "--nul") == 0) nul = true;
        return cmd_list(argv[2], nul);
    }

    /* Slurp stdin once - the only channel secrets travel on. */
    const std::string sbuf = slurp_stdin();

    if (strcmp(cmd, "read") == 0) {
        if (argc < 4)
            return usage();
        long long maxbytes = 0;
        for (int i = 4; i < argc; i++)
            if (strcmp(argv[i], "--max") == 0 && i + 1 < argc)
                maxbytes = strtoll(argv[++i], nullptr, 10);
        return cmd_read(argv[2], argv[3], maxbytes, strip_passphrase(sbuf));
    }
    if (strcmp(cmd, "extract") == 0) {
        if (argc < 4)
            return usage();
        /* Split trailing args into flags and member names. */
        const char *prefix = nullptr;
        bool skip_junk = false, progress = false;
        std::vector<const char *> members;
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--prefix") == 0 && i + 1 < argc) prefix = argv[++i];
            else if (strcmp(argv[i], "--skip-junk") == 0) skip_junk = true;
            else if (strcmp(argv[i], "--progress") == 0) progress = true;
            else members.push_back(argv[i]);
        }
        return cmd_extract(argv[2], argv[3], members, prefix, skip_junk, progress,
                           strip_passphrase(sbuf));
    }
    if (strcmp(cmd, "create") == 0) {
        if (argc < 3)
            return usage();
        const char *manifest = nullptr, *mode = "none";
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--manifest") == 0 && i + 1 < argc) manifest = argv[++i];
            else if (strcmp(argv[i], "--encrypt") == 0 && i + 1 < argc) mode = argv[++i];
        }
        return cmd_create(argv[2], manifest, mode, strip_passphrase(sbuf));
    }
    if (strcmp(cmd, "recrypt") == 0) {
        const char *mode = nullptr;
        bool oldf = false, newf = false;
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) mode = argv[++i];
            else if (strcmp(argv[i], "--old-pwd-stdin") == 0) oldf = true;
            else if (strcmp(argv[i], "--new-pwd-stdin") == 0) newf = true;
        }
        if (argc < 4 || mode == nullptr)
            return usage();
        std::string oldp, newp;
        if (oldf && newf) {
            /* payload is old NUL new */
            size_t k = sbuf.find('\0');
            if (k != std::string::npos) {
                oldp = sbuf.substr(0, k);
                newp = strip_passphrase(sbuf.data() + k + 1, sbuf.size() - k - 1);
            } else {
                oldp = strip_passphrase(sbuf);  /* no NUL: treat all as old */
            }
        } else if (oldf) {
            oldp = strip_passphrase(sbuf);
        } else if (newf) {
            newp = strip_passphrase(sbuf);
        }
        return cmd_recrypt(argv[2], argv[3], mode, oldp, newp);
    }
    return usage();
}

}  // namespace

int main(int argc, char **argv)
{
    /* Last line of defence. Every command already handles allocation failure
     * where it can do something better than dying (see the file header); this
     * turns anything left into a diagnostic and exit 1 rather than a terminate()
     * with no message. */
    try {
        return run(argc, argv);
    } catch (const std::bad_alloc &) {
        fprintf(stderr, "archive: out of memory\n");
        return 1;
    } catch (const std::exception &ex) {
        fprintf(stderr, "archive: %s\n", ex.what());
        return 1;
    }
}
