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
 * declarations come from the vendored headers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "archive.h"
#include "archive_entry.h"

/* ---- helpers -------------------------------------------------------------- */

#define BLOCK 16384

/* Read all of stdin into a malloc'd buffer (caller frees); sets *outlen.
 * Secrets only ever arrive here, never on argv. NUL bytes are preserved so a
 * two-field "old\0new" payload (recrypt) round-trips intact. */
static unsigned char *slurp_stdin(size_t *outlen)
{
    size_t cap = 256, len = 0;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (buf == NULL) { *outlen = 0; return NULL; }
    unsigned char tmp[256];
    ssize_t n;
    while ((n = read(STDIN_FILENO, tmp, sizeof tmp)) > 0) {
        if (len + (size_t)n > cap) {
            size_t ncap = (len + (size_t)n) * 2;
            unsigned char *nb = (unsigned char *)realloc(buf, ncap);
            if (nb == NULL) { free(buf); *outlen = 0; return NULL; }
            buf = nb; cap = ncap;
        }
        memcpy(buf + len, tmp, (size_t)n);
        len += (size_t)n;
    }
    *outlen = len;
    return buf;
}

/* Copy [buf,len) to a fresh C string, stripping one trailing newline (+CR).
 * Returns NULL if the result is empty ("no passphrase"). Caller frees. */
static char *dup_stripped(const unsigned char *buf, size_t len)
{
    if (buf == NULL) return NULL;
    if (len > 0 && buf[len - 1] == '\n') {
        len--;
        if (len > 0 && buf[len - 1] == '\r') len--;
    }
    if (len == 0) return NULL;
    char *s = (char *)malloc(len + 1);
    if (s == NULL) return NULL;
    memcpy(s, buf, len);
    s[len] = '\0';
    return s;
}

/* A pathname comparison that tolerates a leading "./" on either side and a
 * trailing "/" (libarchive/bsdtar store "./name"; our model uses "name"). */
static const char *norm(const char *p)
{
    if (p == NULL) return "";
    if (p[0] == '.' && p[1] == '/') p += 2;
    return p;
}

static int name_eq(const char *a, const char *b)
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
static int is_name_junk(const char *raw)
{
    const char *name = norm(raw);
    if (strncmp(name, "__MACOSX", 8) == 0 && (name[8] == '\0' || name[8] == '/'))
        return 1;
    size_t len = strlen(name);
    while (len > 0 && name[len - 1] == '/') len--;
    size_t start = len;
    while (start > 0 && name[start - 1] != '/') start--;
    size_t blen = len - start;
    if (blen == 9 && strncmp(name + start, ".DS_Store", 9) == 0)
        return 1;
    return 0;
}

/* AppleDouble magic (version 2): 0x00 0x05 0x16 0x07. */
static const unsigned char AD_MAGIC[4] = { 0x00, 0x05, 0x16, 0x07 };

/* True when the basename starts with "._" (outside __MACOSX, which is already
 * junk by name). Such an entry is only a CANDIDATE - the AppleDouble magic in
 * its first bytes decides. */
static int is_dot_underscore(const char *raw)
{
    const char *name = norm(raw);
    if (strncmp(name, "__MACOSX", 8) == 0 && (name[8] == '\0' || name[8] == '/'))
        return 0;
    size_t len = strlen(name);
    while (len > 0 && name[len - 1] == '/') len--;
    size_t start = len;
    while (start > 0 && name[start - 1] != '/') start--;
    return (len - start) >= 2 && name[start] == '.' && name[start + 1] == '_';
}

/* True when <name> (normalized) is <prefix> or lies under it; NULL matches all.
 * The match must end at a path boundary: a bare strncmp let "--prefix docs"
 * pull in "docs2/b.txt", so extracting one folder could silently drag in a
 * sibling whose name merely starts the same way. */
static int prefix_match(const char *name, const char *prefix)
{
    if (prefix == NULL) return 1;
    const char *n = norm(name);
    size_t pl = strlen(prefix);
    if (strncmp(n, prefix, pl) != 0)
        return 0;
    if (pl == 0 || prefix[pl - 1] == '/')
        return 1;                       /* prefix already ends at a boundary */
    return n[pl] == '\0' || n[pl] == '/';
}

/* Distinguish a wrong/missing passphrase from other libarchive failures. */
static int is_passphrase_error(struct archive *a)
{
    const char *m = archive_error_string(a);
    if (m == NULL) return 0;
    return strcasestr(m, "passphrase") != NULL || strcasestr(m, "incorrect password") != NULL;
}

static struct archive *open_archive(const char *path, const char *pass)
{
    struct archive *a = archive_read_new();
    if (a == NULL) return NULL;
    archive_read_support_format_zip(a);
    archive_read_support_filter_all(a);
    if (pass != NULL && pass[0] != '\0')
        archive_read_add_passphrase(a, pass);
    if (archive_read_open_filename(a, path, BLOCK) != ARCHIVE_OK) {
        fprintf(stderr, "archive: cannot open archive: %s\n", archive_error_string(a));
        archive_read_free(a);
        return NULL;
    }
    return a;
}

/* ---- read: one entry to stdout -------------------------------------------- */

static int cmd_read(const char *path, const char *entry, long long maxbytes, const char *pass)
{
    struct archive *a = open_archive(path, pass);
    if (a == NULL) return 4;

    struct archive_entry *e;
    int rc = 1;  /* entry not found, unless we find it */
    int r;
    while ((r = archive_read_next_header(a, &e)) == ARCHIVE_OK) {
        if (!name_eq(archive_entry_pathname(e), entry))
            continue;
        char buf[BLOCK];
        long long written = 0;
        la_ssize_t n;
        rc = 0;
        while ((n = archive_read_data(a, buf, sizeof buf)) > 0) {
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
            rc = is_passphrase_error(a) ? 2 : 1;
            fprintf(stderr, "archive: read error: %s\n", archive_error_string(a));
        }
        break;
    }
    if (r < ARCHIVE_OK && r != ARCHIVE_EOF && rc == 1)
        rc = is_passphrase_error(a) ? 2 : 1;
    if (rc == 1 && r == ARCHIVE_EOF)
        fprintf(stderr, "archive: no such entry: %s\n", entry);

    /* fwrite into a stdio FILE only fails once the buffer flushes, so an entry
     * whose tail fits in the buffer is written entirely by this flush - its
     * return is the only place that failure can surface. */
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "archive: could not flush stdout\n");
        if (rc == 0) rc = 1;
    }
    archive_read_close(a);
    archive_read_free(a);
    return rc;
}

/* ---- extract: all or listed members into destdir -------------------------- */

static int copy_data(struct archive *ar, struct archive *aw)
{
    for (;;) {
        const void *buff;
        size_t size;
        la_int64_t offset;
        int r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF) return ARCHIVE_OK;
        if (r < ARCHIVE_OK)   return r;
        if (archive_write_data_block(aw, buff, size, offset) < ARCHIVE_OK)
            return ARCHIVE_FATAL;
    }
}

static int member_wanted(const char *name, int memberc, char **memberv)
{
    if (memberc == 0) return 1;  /* no list => extract everything */
    for (int i = 0; i < memberc; i++)
        if (name_eq(name, memberv[i]))
            return 1;
    return 0;
}

static int cmd_extract(const char *path, const char *destdir, int memberc, char **memberv,
                       const char *prefix, int skip_junk, int progress, const char *pass)
{
    /* Open the archive before chdir so a relative <archive> still resolves
     * against the original cwd; the open fd survives the chdir below. */
    struct archive *a = open_archive(path, pass);
    if (a == NULL) return 4;

    if (chdir(destdir) != 0) {
        fprintf(stderr, "archive: cannot enter destination: %s\n", destdir);
        archive_read_free(a);
        return 1;
    }

    struct archive *ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_TIME |
                                   ARCHIVE_EXTRACT_SECURE_SYMLINKS | ARCHIVE_EXTRACT_SECURE_NODOTDOT |
                                   ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS);
    archive_write_disk_set_standard_lookup(ext);

    struct archive_entry *e;
    int rc = 0, r, count = 0, skipped = 0;
    while ((r = archive_read_next_header(a, &e)) == ARCHIVE_OK) {
        const char *pathname = archive_entry_pathname(e);
        if (!member_wanted(pathname, memberc, memberv))
            continue;
        if (!prefix_match(pathname, prefix))
            continue;
        if (skip_junk && is_name_junk(pathname))
            continue;
        /* "._*" files: peek the first data block and skip only true AppleDouble
         * sidecars (magic 00 05 16 07); a user file merely named "._foo" is
         * extracted. The peeked block is written after the header below. The
         * passphrase (if any) is active here, so encrypted entries peek fine. */
        int peeked = 0; const void *pbuff = NULL; size_t psize = 0; la_int64_t poffset = 0;
        if (skip_junk && S_ISREG(archive_entry_filetype(e)) && is_dot_underscore(pathname)) {
            int pr = archive_read_data_block(a, &pbuff, &psize, &poffset);
            if (pr == ARCHIVE_OK) {
                peeked = 1;
                if (psize >= sizeof AD_MAGIC && memcmp(pbuff, AD_MAGIC, sizeof AD_MAGIC) == 0)
                    continue;   /* true AppleDouble: junk (rest auto-skipped by next_header) */
            } else if (pr != ARCHIVE_EOF) {   /* EOF = empty file: keep it */
                rc = is_passphrase_error(a) ? 2 : 1;
                fprintf(stderr, "archive: extract error: %s\n", archive_error_string(a));
                break;
            }
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
        int wh = archive_write_header(ext, e);
        if (wh != ARCHIVE_OK && wh != ARCHIVE_WARN) {
            fprintf(stderr, "archive: skipped %s: %s\n",
                    pathname ? pathname : "(unnamed)", archive_error_string(ext));
            skipped++;
            if (wh == ARCHIVE_FATAL) {
                rc = 1;
                break;
            }
            continue;
        }
        if (wh == ARCHIVE_WARN)
            fprintf(stderr, "archive: warning: %s\n", archive_error_string(ext));
        /* Regular files carry data; symlinks and directories are fully described
         * by the header (the zip reader resolves symlink targets on open). */
        if (S_ISREG(archive_entry_filetype(e))) {
            if (peeked && archive_write_data_block(ext, pbuff, psize, poffset) < ARCHIVE_OK) {
                rc = 1;
                fprintf(stderr, "archive: write data: %s\n", archive_error_string(ext));
                break;
            }
            if (copy_data(a, ext) < ARCHIVE_OK) {
                rc = is_passphrase_error(a) ? 2 : 1;
                fprintf(stderr, "archive: extract error: %s\n", archive_error_string(a));
                break;
            }
        }
        /* finish_entry is where deferred work lands (padding a sparse file,
         * restoring times). A failure here means the entry is on disk but not
         * intact, so it must not be counted as extracted - same partial-result
         * accounting as a rejected header above. */
        int fe = archive_write_finish_entry(ext);
        if (fe != ARCHIVE_OK && fe != ARCHIVE_WARN) {
            fprintf(stderr, "archive: incomplete %s: %s\n",
                    pathname ? pathname : "(unnamed)", archive_error_string(ext));
            skipped++;
            if (fe == ARCHIVE_FATAL) {
                rc = 1;
                break;
            }
            continue;
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
    if (r < ARCHIVE_OK && r != ARCHIVE_EOF && rc == 0)
        rc = is_passphrase_error(a) ? 2 : 1;

    /* Checked for symmetry only: archive_write_disk's close() just forwards the
     * last finish_entry, which is already ARCHIVE_OK here because the loop calls
     * finish_entry per entry. The deferred directory fixups it performs (times,
     * permissions, ACLs, flags) have their return values discarded internally,
     * so libarchive offers no way to detect a failure in them. */
    int cl = archive_write_close(ext);
    if (cl != ARCHIVE_OK && cl != ARCHIVE_WARN) {
        fprintf(stderr, "archive: close: %s\n", archive_error_string(ext));
        if (rc == 0)
            rc = 1;
    }
    archive_write_free(ext);
    archive_read_close(a);
    archive_read_free(a);

    /* Promote to "partial" only after the read-side result is known, so a real
     * passphrase error still surfaces as 2 rather than being masked by a skip. */
    if (rc == 0 && skipped > 0)
        rc = 5;

    /* Machine-readable tail for the caller's progress stream: entry names could
     * contain newlines, but this line is a fixed keyword plus an integer. */
    if (progress) {
        printf("skipped %d\n", skipped);
        fflush(stdout);
    }
    if (rc == 0)
        fprintf(stderr, "archive: extracted %d item(s)\n", count);
    else if (rc == 5)
        fprintf(stderr, "archive: extracted %d item(s), %d not extracted\n", count, skipped);
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
static void put_field(const char *s)
{
    if (s != NULL)
        fwrite(s, 1, strlen(s), stdout);
    fputc('\0', stdout);
}

static int cmd_list(const char *path, int nul)
{
    struct archive *a = archive_read_new();
    if (a == NULL) return 1;
    archive_read_support_format_zip(a);
    archive_read_support_filter_all(a);
    if (archive_read_open_filename(a, path, BLOCK) != ARCHIVE_OK) {
        fprintf(stderr, "archive: cannot open archive: %s\n", archive_error_string(a));
        archive_read_free(a);
        return 4;
    }
    struct archive_entry *e;
    int r;
    char tbuf[32];
    while ((r = archive_read_next_header(a, &e)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(e);
        if (name == NULL)
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
                la_ssize_t n = archive_read_data(a, m, sizeof m);
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
        fprintf(stderr, "archive: list error: %s\n", archive_error_string(a));
        archive_read_close(a);
        archive_read_free(a);
        return 1;
    }
    archive_read_close(a);
    archive_read_free(a);
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
 * return NULL rather than silently producing an unencrypted archive. */
static struct archive *open_zip_writer(const char *dst, const char *mode, const char *pass)
{
    int want_enc = (strcmp(mode, "aes256") == 0 || strcmp(mode, "zipcrypt") == 0);
    if (!want_enc && strcmp(mode, "none") != 0) {
        fprintf(stderr, "archive: unknown mode '%s' (use aes256|zipcrypt|none)\n", mode);
        return NULL;
    }
    if (want_enc && (pass == NULL || pass[0] == '\0')) {
        fprintf(stderr, "archive: encryption mode '%s' requires a passphrase\n", mode);
        return NULL;
    }
    struct archive *w = archive_write_new();
    if (w == NULL) return NULL;
    archive_write_set_format_zip(w);
    if (want_enc) {
        const char *opt = (strcmp(mode, "aes256") == 0) ? "zip:encryption=aes256"
                                                        : "zip:encryption=zipcrypt";
        if (archive_write_set_options(w, opt) != ARCHIVE_OK) {
            fprintf(stderr, "archive: encryption option rejected: %s\n", archive_error_string(w));
            archive_write_free(w);
            return NULL;
        }
        archive_write_set_passphrase(w, pass);
    }
    if (archive_write_open_filename(w, dst) != ARCHIVE_OK) {
        fprintf(stderr, "archive: cannot create %s: %s\n", dst, archive_error_string(w));
        archive_write_free(w);
        return NULL;
    }
    return w;
}

/* recrypt: copy every entry of <src> into a fresh <dst>, changing encryption.
 * Reads with oldpass (if the source is encrypted), writes with newpass per mode.
 * No entry is filtered - this faithfully re-encrypts the whole archive. */
static int cmd_recrypt(const char *src, const char *dst, const char *mode,
                       const char *oldpass, const char *newpass)
{
    struct archive *a = open_archive(src, oldpass);
    if (a == NULL) return 4;
    struct archive *w = open_zip_writer(dst, mode, newpass);
    if (w == NULL) { archive_read_free(a); return 1; }

    struct archive_entry *e;
    char buf[BLOCK];
    int rc = 0, r, count = 0;
    while ((r = archive_read_next_header(a, &e)) == ARCHIVE_OK) {
        if (archive_write_header(w, e) != ARCHIVE_OK) {
            fprintf(stderr, "archive: write header: %s\n", archive_error_string(w));
            rc = 1; break;
        }
        la_ssize_t n; int werr = 0;
        while ((n = archive_read_data(a, buf, sizeof buf)) > 0) {
            if (archive_write_data(w, buf, (size_t)n) < 0) { werr = 1; break; }
        }
        if (werr) { fprintf(stderr, "archive: write data: %s\n", archive_error_string(w)); rc = 1; break; }
        if (n < 0) { rc = is_passphrase_error(a) ? 2 : 1;
            fprintf(stderr, "archive: read error: %s\n", archive_error_string(a)); break; }
        count++;
    }
    if (r < ARCHIVE_OK && r != ARCHIVE_EOF && rc == 0)
        rc = is_passphrase_error(a) ? 2 : 1;

    if (archive_write_close(w) != ARCHIVE_OK && rc == 0) rc = 1;
    archive_write_free(w);
    archive_read_close(a);
    archive_read_free(a);
    if (rc != 0) unlink(dst);          /* same reason as cmd_create */
    if (rc == 0)
        fprintf(stderr, "archive: rewrote %d entr%s -> %s (%s)\n",
                count, count == 1 ? "y" : "ies", dst, mode);
    return rc;
}

/* create: build a fresh <dst> zip from a manifest file of "arcname\tsrcpath"
 * lines (paths are not secret, so the manifest is a plain file argument).
 * Optional encryption via <mode>+passphrase. */
static int cmd_create(const char *dst, const char *manifest, const char *mode, const char *pass)
{
    FILE *mf = NULL;
    if (manifest != NULL) {
        mf = fopen(manifest, "r");
        if (mf == NULL) { fprintf(stderr, "archive: cannot read manifest: %s\n", manifest); return 1; }
    }
    struct archive *w = open_zip_writer(dst, mode, pass);
    if (w == NULL) { if (mf) fclose(mf); return 1; }

    char line[8192];
    char buf[BLOCK];
    int rc = 0, count = 0;
    while (mf != NULL && fgets(line, sizeof line, mf) != NULL) {
        size_t L = strlen(line);
        while (L > 0 && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = '\0';
        if (L == 0) continue;
        char *tab = strchr(line, '\t');
        if (tab == NULL) { fprintf(stderr, "archive: bad manifest line (no tab)\n"); rc = 1; break; }
        *tab = '\0';
        const char *arcname = line;
        const char *srcpath = tab + 1;

        /* lstat, not stat: a symlink must be archived as a symlink entry, never
         * silently replaced by its target (duplicated framework binaries broke
         * code signatures: "unsealed contents" on extraction). */
        struct stat st;
        if (lstat(srcpath, &st) != 0) { fprintf(stderr, "archive: cannot stat %s\n", srcpath); rc = 1; break; }

        struct archive_entry *e = archive_entry_new();
        archive_entry_set_pathname(e, arcname);
        archive_entry_copy_stat(e, &st);
        if (S_ISLNK(st.st_mode)) {
            char target[4096];
            ssize_t tl = readlink(srcpath, target, sizeof target - 1);
            if (tl < 0 || tl >= (ssize_t)(sizeof target - 1)) {
                /* error, or target possibly truncated - storing a wrong link
                 * target silently would corrupt the archive's content */
                fprintf(stderr, "archive: cannot readlink %s\n", srcpath);
                archive_entry_free(e); rc = 1; break;
            }
            target[tl] = '\0';
            archive_entry_set_symlink(e, target);
        }
        if (archive_write_header(w, e) != ARCHIVE_OK) {
            fprintf(stderr, "archive: write header: %s\n", archive_error_string(w));
            archive_entry_free(e); rc = 1; break;
        }
        if (S_ISREG(st.st_mode)) {
            FILE *in = fopen(srcpath, "rb");
            if (in == NULL) { fprintf(stderr, "archive: cannot open %s\n", srcpath); archive_entry_free(e); rc = 1; break; }
            size_t got;
            while ((got = fread(buf, 1, sizeof buf, in)) > 0) {
                la_ssize_t nw = archive_write_data(w, buf, got);
                if (nw < 0) {
                    const char *em = archive_error_string(w);
                    fprintf(stderr, "archive: write data: %s\n", em ? em : "unknown error");
                    rc = 1; break;
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
            if (rc == 0 && ferror(in)) {
                fprintf(stderr, "archive: read error on %s\n", srcpath);
                rc = 1;
            }
            fclose(in);
            if (rc != 0) { archive_entry_free(e); break; }
        }
        archive_entry_free(e);
        count++;
    }
    if (mf != NULL) fclose(mf);
    if (archive_write_close(w) != ARCHIVE_OK && rc == 0) rc = 1;
    archive_write_free(w);
    /* Never leave a half-written archive behind for the caller to mistake for a
     * real one - the same cleanup do_recrypt does on the Python side. */
    if (rc != 0) unlink(dst);
    if (rc == 0)
        fprintf(stderr, "archive: created %s with %d file(s) (%s)\n", dst, count, mode);
    return rc;
}

/* ---- main ----------------------------------------------------------------- */

static int usage(void)
{
    fprintf(stderr,
        "usage (passphrases always arrive on stdin, never on argv):\n"
        "  archive read    <archive> <entry> [--max BYTES]      # entry -> stdout\n"
        "  archive extract <archive> <destdir> [member ...] [--prefix P] [--skip-junk] [--progress]\n"
        "                                                       # extract all, listed members, or entries under P;\n"
        "                                                       # --skip-junk drops __MACOSX/._*/.DS_Store;\n"
        "                                                       # --progress prints one line per extracted file\n"
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

int main(int argc, char **argv)
{
    if (argc < 2)
        return usage();

    const char *cmd = argv[1];

    /* list needs no passphrase, so don't slurp stdin for it (the caller may not
     * close stdin, which would otherwise block). */
    if (strcmp(cmd, "list") == 0) {
        if (argc < 3) return usage();
        int nul = 0;
        for (int i = 3; i < argc; i++)
            if (strcmp(argv[i], "--nul") == 0) nul = 1;
        return cmd_list(argv[2], nul);
    }

    /* Slurp stdin once - the only channel secrets travel on. */
    size_t slen = 0;
    unsigned char *sbuf = slurp_stdin(&slen);

    int rc;
    if (strcmp(cmd, "read") == 0) {
        if (argc < 4) { free(sbuf); return usage(); }
        long long maxbytes = 0;
        for (int i = 4; i < argc; i++)
            if (strcmp(argv[i], "--max") == 0 && i + 1 < argc)
                maxbytes = strtoll(argv[++i], NULL, 10);
        char *pass = dup_stripped(sbuf, slen);
        rc = cmd_read(argv[2], argv[3], maxbytes, pass);
        free(pass);
    } else if (strcmp(cmd, "extract") == 0) {
        if (argc < 4) { free(sbuf); return usage(); }
        /* Split trailing args into flags and member names. */
        const char *prefix = NULL;
        int skip_junk = 0, progress = 0;
        char *members[argc];
        int memberc = 0;
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--prefix") == 0 && i + 1 < argc) prefix = argv[++i];
            else if (strcmp(argv[i], "--skip-junk") == 0) skip_junk = 1;
            else if (strcmp(argv[i], "--progress") == 0) progress = 1;
            else members[memberc++] = argv[i];
        }
        char *pass = dup_stripped(sbuf, slen);
        rc = cmd_extract(argv[2], argv[3], memberc, members, prefix, skip_junk, progress, pass);
        free(pass);
    } else if (strcmp(cmd, "create") == 0) {
        const char *manifest = NULL, *mode = "none";
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--manifest") == 0 && i + 1 < argc) manifest = argv[++i];
            else if (strcmp(argv[i], "--encrypt") == 0 && i + 1 < argc) mode = argv[++i];
        }
        if (argc < 3) { free(sbuf); return usage(); }
        char *pass = dup_stripped(sbuf, slen);
        rc = cmd_create(argv[2], manifest, mode, pass);
        free(pass);
    } else if (strcmp(cmd, "recrypt") == 0) {
        const char *mode = NULL;
        int oldf = 0, newf = 0;
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) mode = argv[++i];
            else if (strcmp(argv[i], "--old-pwd-stdin") == 0) oldf = 1;
            else if (strcmp(argv[i], "--new-pwd-stdin") == 0) newf = 1;
        }
        if (argc < 4 || mode == NULL) { free(sbuf); return usage(); }
        char *oldp = NULL, *newp = NULL;
        if (oldf && newf) {
            /* payload is old NUL new */
            size_t k = 0;
            while (k < slen && sbuf[k] != '\0') k++;
            if (k < slen) {
                oldp = (k > 0) ? strndup((char *)sbuf, k) : NULL;
                newp = dup_stripped(sbuf + k + 1, slen - k - 1);
            } else {
                oldp = dup_stripped(sbuf, slen);  /* no NUL: treat all as old */
            }
        } else if (oldf) {
            oldp = dup_stripped(sbuf, slen);
        } else if (newf) {
            newp = dup_stripped(sbuf, slen);
        }
        rc = cmd_recrypt(argv[2], argv[3], mode, oldp, newp);
        free(oldp); free(newp);
    } else {
        free(sbuf);
        return usage();
    }

    free(sbuf);
    return rc;
}
