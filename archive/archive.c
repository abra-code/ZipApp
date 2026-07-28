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

/* libarchive returns NULL from archive_error_string() when it has no message,
 * and passing NULL to a "%s" conversion is undefined. Darwin's printf happens to
 * print "(null)", but a signed helper should not rely on that. */
static const char *errstr(struct archive *a)
{
    const char *m = archive_error_string(a);
    return (m != NULL) ? m : "unknown error";
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
        fprintf(stderr, "archive: cannot open archive: %s\n", errstr(a));
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
    /* ARCHIVE_WARN: header read, entry usable - see cmd_extract. */
    while ((r = archive_read_next_header(a, &e)) == ARCHIVE_OK || r == ARCHIVE_WARN) {
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
            fprintf(stderr, "archive: read error: %s\n", errstr(a));
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
static size_t utf8_seq_len(const unsigned char *s, size_t len)
{
    unsigned char b = s[0];
    if (b < 0x80) return 1;
    if (b < 0xC2) return 0;                      /* continuation, or overlong lead */
    if (b < 0xE0) {
        if (len < 2 || (s[1] & 0xC0) != 0x80) return 0;
        return 2;
    }
    if (b < 0xF0) {
        if (len < 3 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return 0;
        if (b == 0xE0 && s[1] < 0xA0) return 0;  /* overlong */
        if (b == 0xED && s[1] >= 0xA0) return 0; /* surrogate */
        return 3;
    }
    if (b < 0xF5) {
        if (len < 4 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 ||
            (s[3] & 0xC0) != 0x80) return 0;
        if (b == 0xF0 && s[1] < 0x90) return 0;  /* overlong */
        if (b == 0xF4 && s[1] >= 0x90) return 0; /* beyond U+10FFFF */
        return 4;
    }
    return 0;
}

/* Code point of the well-formed sequence at s (sl bytes, from utf8_seq_len). */
static unsigned utf8_cp(const unsigned char *s, size_t sl)
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
static int is_noncharacter(unsigned cp)
{
    if (cp >= 0xFDD0 && cp <= 0xFDEF) return 1;
    return (cp & 0xFFFE) == 0xFFFE;          /* U+xFFFE and U+xFFFF in every plane */
}

static int needs_repair(const char *s, size_t len)
{
    for (size_t i = 0; i < len; ) {
        unsigned char b = (unsigned char)s[i];
        if (b == '\t' || b == '\r' || b == '\n') return 1;
        size_t sl = utf8_seq_len((const unsigned char *)s + i, len - i);
        if (sl == 0) return 1;
        if (is_noncharacter(utf8_cp((const unsigned char *)s + i, sl))) return 1;
        i += sl;
    }
    return 0;
}

/* Repaired copy of one path component (malloc'd, NULL on OOM). The replacement
 * is byte for byte, so the result is never longer than the input and can never
 * become empty, "." or ".." from something that was not already that. */
static char *repair_component(const char *c, size_t len, int *changed)
{
    char *out = malloc(len + 1);
    if (out == NULL) return NULL;
    size_t o = 0;
    *changed = 0;
    for (size_t i = 0; i < len; ) {
        unsigned char b = (unsigned char)c[i];
        if (b == '\t' || b == '\r' || b == '\n') {
            out[o++] = ' '; i++; *changed = 1; continue;
        }
        size_t sl = utf8_seq_len((const unsigned char *)c + i, len - i);
        if (sl == 0) {
            out[o++] = '_'; i++; *changed = 1; continue;
        }
        if (is_noncharacter(utf8_cp((const unsigned char *)c + i, sl))) {
            for (size_t k = 0; k < sl; k++) out[o++] = '_';
            i += sl; *changed = 1; continue;
        }
        memcpy(out + o, c + i, sl);
        o += sl; i += sl;
    }
    out[o] = '\0';
    return out;
}

/* Small string map (open addressing, FNV-1a). Only ever allocated once a name
 * has actually needed repair, so a clean archive pays nothing for it. */
struct smap_ent { char *key; char *val; };
struct smap { struct smap_ent *tab; size_t cap, n; };

static size_t smap_hash(const char *s)
{
    size_t h = 1469598103934665603ULL;
    for (; *s != '\0'; s++) { h ^= (unsigned char)*s; h *= 1099511628211ULL; }
    return h;
}

static int smap_grow(struct smap *m, size_t cap)
{
    struct smap_ent *nt = calloc(cap, sizeof *nt);
    if (nt == NULL) return -1;
    for (size_t i = 0; i < m->cap; i++) {
        if (m->tab[i].key == NULL) continue;
        size_t j = smap_hash(m->tab[i].key) & (cap - 1);
        while (nt[j].key != NULL) j = (j + 1) & (cap - 1);
        nt[j] = m->tab[i];
    }
    free(m->tab);
    m->tab = nt; m->cap = cap;
    return 0;
}

static struct smap_ent *smap_find(struct smap *m, const char *key)
{
    if (m->cap == 0) return NULL;
    size_t j = smap_hash(key) & (m->cap - 1);
    while (m->tab[j].key != NULL) {
        if (strcmp(m->tab[j].key, key) == 0) return &m->tab[j];
        j = (j + 1) & (m->cap - 1);
    }
    return NULL;
}

/* Both strings are copied; val may be NULL (set membership). -1 on OOM. */
static int smap_put(struct smap *m, const char *key, const char *val)
{
    if ((m->n + 1) * 2 >= m->cap && smap_grow(m, m->cap != 0 ? m->cap * 2 : 64) != 0)
        return -1;
    size_t j = smap_hash(key) & (m->cap - 1);
    while (m->tab[j].key != NULL) {
        if (strcmp(m->tab[j].key, key) == 0)
            return 0;                            /* first mapping wins */
        j = (j + 1) & (m->cap - 1);
    }
    char *nk = strdup(key);
    char *nv = (val != NULL) ? strdup(val) : NULL;
    if (nk == NULL || (val != NULL && nv == NULL)) { free(nk); free(nv); return -1; }
    m->tab[j].key = nk; m->tab[j].val = nv; m->n++;
    return 0;
}

static void smap_free(struct smap *m)
{
    for (size_t i = 0; i < m->cap; i++) { free(m->tab[i].key); free(m->tab[i].val); }
    free(m->tab);
    m->tab = NULL; m->cap = 0; m->n = 0;
}

struct namemap {
    struct smap dirs;      /* original directory path -> path it landed under */
    struct smap claimed;   /* every name this run invented, so none is reused */
    struct smap placed;    /* dev:ino of everything written under a name we chose */
    int active;            /* set once anything has needed repair */
    int degraded;          /* a name we placed could not be recorded (see below) */
    int err;               /* allocation failure: the caller must abort */
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
static void ino_key(char *buf, size_t n, const struct stat *st)
{
    snprintf(buf, n, "%llu:%llu", (unsigned long long)st->st_dev,
             (unsigned long long)st->st_ino);
}

static int nm_remember(struct namemap *nm, const char *path)
{
    struct stat st;
    char key[64];
    if (lstat(path, &st) != 0) return 0;      /* nothing there: nothing to guard */
    ino_key(key, sizeof key, &st);
    return smap_put(&nm->placed, key, NULL);
}

static int nm_is_ours(struct namemap *nm, const char *path)
{
    struct stat st;
    char key[64];
    if ((nm->placed.n == 0 && !nm->degraded) || lstat(path, &st) != 0) return 0;
    /* Once a name we placed could not be recorded, the set is no longer a
     * complete answer, so anything already on disk has to be assumed ours. That
     * over-renames; the alternative is writing over a file we just rescued.
     * Repair CREATES these collisions - two names that were distinct in the
     * archive can fold together - so "no worse than before the guard existed"
     * is not good enough here: before the guard, they were distinct. */
    if (nm->degraded) return 1;
    ino_key(key, sizeof key, &st);
    return smap_find(&nm->placed, key) != NULL;
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
static char *fold_key(const char *s)
{
    size_t n = strlen(s);
    char *out = malloc(n + 1);
    if (out == NULL) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        out[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : (char)c;
    }
    out[n] = '\0';
    return out;
}

static int claimed_has(struct smap *claimed, const char *name)
{
    char *k = fold_key(name);
    if (k == NULL) return -1;               /* OOM: caller must treat as fatal */
    int found = smap_find(claimed, k) != NULL;
    free(k);
    return found;
}

static int claim(struct smap *claimed, const char *name)
{
    char *k = fold_key(name);
    if (k == NULL) return -1;
    int r = smap_put(claimed, k, NULL);
    free(k);
    return r;
}

/* Free variant of <cand>, Finder-style: "name", then "name 2", "name 3", ...
 * The counter goes before the extension for a file and at the end for a
 * directory, matching ziptool's _unique_in so a rename looks the same wherever
 * it happens. NULL on OOM (or if 10000 variants are all taken). */
static char *unique_name(struct smap *claimed, const char *cand, int is_dir)
{
    struct stat st;
    int h = claimed_has(claimed, cand);
    if (h < 0) return NULL;
    if (!h && lstat(cand, &st) != 0)
        return strdup(cand);

    const char *slash = strrchr(cand, '/');
    size_t dlen = (slash != NULL) ? (size_t)(slash - cand) + 1 : 0;
    const char *base = cand + dlen;
    const char *dot = is_dir ? NULL : strrchr(base, '.');
    if (dot == base) dot = NULL;                 /* ".hidden" is not an extension */
    size_t stemlen = (dot != NULL) ? (size_t)(dot - base) : strlen(base);
    const char *ext = (dot != NULL) ? dot : "";

    for (int n = 2; n <= 10000; n++) {
        size_t need = dlen + stemlen + strlen(ext) + 16;
        char *x = malloc(need);
        if (x == NULL) return NULL;
        snprintf(x, need, "%.*s%.*s %d%s", (int)dlen, cand, (int)stemlen, base, n, ext);
        h = claimed_has(claimed, x);
        if (h < 0) { free(x); return NULL; }
        if (!h && lstat(x, &st) != 0)
            return x;
        free(x);
    }
    return NULL;
}

/* The name <raw> should land under on disk, or NULL to extract it unchanged
 * (which is the answer for every entry in an ordinary archive). Sets nm->err on
 * allocation failure.
 *
 * <invented> marks a name WE made up rather than read from the archive. Such a
 * name has to dodge whatever is already there even though it needs no repair:
 * an archive holding a real file called "unnamed 1" next to an entry whose name
 * libarchive discarded would otherwise have one written over the other. */
static char *resolve_disk_path(struct namemap *nm, const char *raw, int is_dir,
                               int invented)
{
    const char *p = norm(raw);
    if (p[0] == '\0' || p[0] == '/')
        return NULL;        /* absolute: leave it to ARCHIVE_EXTRACT_SECURE_* */

    /* A ".." component is precisely what ARCHIVE_EXTRACT_SECURE_NODOTDOT exists
     * to reject. Rewriting such a path could only ever help it through, so it
     * is handed to libarchive exactly as it arrived. */
    for (const char *c = p; ; ) {
        const char *e = strchr(c, '/');
        size_t n = (e != NULL) ? (size_t)(e - c) : strlen(c);
        if (n == 2 && c[0] == '.' && c[1] == '.')
            return NULL;
        if (e == NULL) break;
        c = e + 1;
    }

    size_t plen = strlen(p);
    int trailing = (plen > 0 && p[plen - 1] == '/');
    while (plen > 0 && p[plen - 1] == '/') plen--;
    if (plen == 0) return NULL;

    /* Until something has needed repair there is no invented name for a clean
     * one to collide with, so nothing has to be tracked at all. */
    if (!nm->active && !invented && !needs_repair(p, plen))
        return NULL;

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

    char *acc = NULL;       /* resolved path so far */
    char *oacc = NULL;      /* the same prefix in ORIGINAL bytes, canonicalized */
    int repaired = 0;       /* a component was actually rewritten */
    size_t i = 0;
    while (i < plen) {
        size_t j = i;
        while (j < plen && p[j] != '/') j++;
        size_t clen = j - i;
        if (clen == 0 || (clen == 1 && p[i] == '.')) { i = j + 1; continue; }
        int last = (i == last_start);

        char *cand = NULL;
        char *okey = NULL;
        if (!last || is_dir) {
            /* Every DIRECTORY path - a prefix walked through, or a directory
             * entry in its own right - is resolved once and remembered, even
             * when it comes through unchanged. Without that, a later entry
             * could find the name taken by an earlier repair and take a counter
             * of its own, scattering one directory's contents across several;
             * and an archive storing "d/" before "d/f.txt" would resolve that
             * name twice and leave the children beside the empty first copy. */
            size_t olen = (oacc != NULL) ? strlen(oacc) : 0;
            okey = malloc(olen + (olen != 0 ? 1 : 0) + clen + 1);
            if (okey == NULL) goto oom;
            if (olen != 0) { memcpy(okey, oacc, olen); okey[olen++] = '/'; }
            memcpy(okey + olen, p + i, clen);
            okey[olen + clen] = '\0';
            struct smap_ent *hit = smap_find(&nm->dirs, okey);
            if (hit != NULL) {
                /* A remembered directory may have landed somewhere else. This
                 * entry moves with it, and that IS a rewrite of this entry's
                 * path even though none of its own components changed - without
                 * this the children of a repaired directory were handed back
                 * unchanged and went on failing to extract. */
                if (strcmp(hit->val, okey) != 0)
                    repaired = 1;
                cand = strdup(hit->val);
                if (cand == NULL) { free(okey); goto oom; }
                free(acc);
                acc = cand;
                free(oacc);
                oacc = okey;
                i = j + 1;
                continue;
            }
        }

        int changed = 0;
        char *rep = repair_component(p + i, clen, &changed);
        if (rep == NULL) { free(okey); goto oom; }
        size_t alen = (acc != NULL) ? strlen(acc) : 0;
        cand = malloc(alen + (alen != 0 ? 1 : 0) + strlen(rep) + 1);
        if (cand == NULL) { free(rep); free(okey); goto oom; }
        cand[0] = '\0';
        if (alen != 0) { memcpy(cand, acc, alen); cand[alen] = '/'; cand[alen + 1] = '\0'; }
        strcat(cand, rep);
        free(rep);

        if (invented && last) changed = 1;   /* our name, so it must claim a slot */
        if (changed) { nm->active = 1; repaired = 1; }
        int taken = claimed_has(&nm->claimed, cand);
        if (taken < 0) { free(cand); free(okey); goto oom; }
        /* Ask the filesystem whether this clean name is already one of ours
         * under a spelling the ASCII fold cannot see (see nm_is_ours). */
        if (!changed && !taken && nm_is_ours(nm, cand))
            taken = 1;
        if (changed || taken) {
            char *u = unique_name(&nm->claimed, cand, !last || is_dir);
            if (u != NULL && strcmp(u, cand) != 0)
                repaired = 1;
            free(cand);
            if (u == NULL) { free(okey); goto oom; }
            cand = u;
            nm->active = 1;
            if (claim(&nm->claimed, cand) != 0) { free(cand); free(okey); goto oom; }
        }
        if (okey != NULL) {
            int r = smap_put(&nm->dirs, okey, cand);
            if (r != 0) { free(cand); free(okey); goto oom; }
            free(oacc);
            oacc = okey;          /* canonical original prefix, for the next key */
        } else {
            free(oacc);
            oacc = NULL;
        }
        free(acc);
        acc = cand;
        i = j + 1;
    }

    free(oacc);
    if (acc == NULL) return NULL;
    /* Only a real rewrite counts. Collapsing "a//b" to "a/b" changes the string
     * but not where the file lands, and reporting it would tell the user a name
     * had characters the filesystem could not hold when it did not. */
    if (!repaired) {
        free(acc);
        return NULL;
    }
    if (trailing) {                                 /* keep the directory shape */
        size_t n = strlen(acc);
        char *t = realloc(acc, n + 2);
        if (t == NULL) { free(acc); nm->err = 1; return NULL; }
        t[n] = '/'; t[n + 1] = '\0';
        acc = t;
    }
    return acc;

oom:
    free(acc);
    free(oacc);
    nm->err = 1;
    return NULL;
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

    struct namemap nm;
    memset(&nm, 0, sizeof nm);

    struct archive_entry *e;
    int rc = 0, r, count = 0, skipped = 0, renamed = 0, unnamed = 0;
    /* ARCHIVE_WARN from next_header means "header read, something about it was
     * odd" - the entry is complete and usable. Treating it as the end of the
     * archive made ONE bad header condemn the whole file: an archive whose
     * UTF-8 flag is set on a name that is not UTF-8 (legacy Windows archivers
     * do this) warns on that entry, and every entry after it was lost. */
    while ((r = archive_read_next_header(a, &e)) == ARCHIVE_OK || r == ARCHIVE_WARN) {
        if (r == ARCHIVE_WARN)
            fprintf(stderr, "archive: header warning: %s\n", errstr(a));
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
                fprintf(stderr, "archive: extract error: %s\n", errstr(a));
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
        int invented = 0;
        if (pathname == NULL || pathname[0] == '\0') {
            snprintf(synth, sizeof synth, "unnamed %d", unnamed + 1);
            unnamed++;
            pathname = synth;
            invented = 1;
        }
        /* Everything above matched on the bytes the archive actually holds. From
         * here the entry carries the name it will land under, which is also the
         * name the diagnostics below should show. */
        char *disk = resolve_disk_path(&nm, pathname, S_ISDIR(archive_entry_filetype(e)),
                                       invented);
        if (nm.err) {
            /* Could not settle on a name (allocation failure, or 10000 variants
             * of one already taken). That is a per-ENTRY failure and is counted
             * like any other: aborting the run here would discard every file
             * already extracted, which is exactly the trade the rejected-header
             * path below refuses to make. */
            fprintf(stderr, "archive: no usable name for %s\n",
                    pathname ? pathname : "(unnamed)");
            nm.err = 0;
            skipped++;
            continue;
        }
        int renamed_this_entry = (disk != NULL);
        if (disk != NULL) {
            /* Both names: the one the archive holds is what the user will be
             * looking for, and for a tab/CR/LF fold it is perfectly readable.
             * (Undecodable bytes go out as-is; stderr is a byte stream.) An
             * invented name has no "from" side to show. */
            if (invented)
                fprintf(stderr, "archive: entry with an unusable name stored as %s\n", disk);
            else
                fprintf(stderr, "archive: renamed %s -> %s\n", pathname, disk);
            archive_entry_copy_pathname(e, disk);
            free(disk);
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
        int wh = archive_write_header(ext, e);
        if (wh != ARCHIVE_OK && wh != ARCHIVE_WARN) {
            fprintf(stderr, "archive: skipped %s: %s\n",
                    pathname ? pathname : "(unnamed)", errstr(ext));
            skipped++;
            if (wh == ARCHIVE_FATAL) {
                rc = 1;
                break;
            }
            continue;
        }
        if (wh == ARCHIVE_WARN)
            fprintf(stderr, "archive: warning: %s\n", errstr(ext));
        /* Regular files carry data; symlinks and directories are fully described
         * by the header (the zip reader resolves symlink targets on open). */
        if (S_ISREG(archive_entry_filetype(e))) {
            if (peeked && archive_write_data_block(ext, pbuff, psize, poffset) < ARCHIVE_OK) {
                rc = 1;
                fprintf(stderr, "archive: write data: %s\n", errstr(ext));
                break;
            }
            if (copy_data(a, ext) < ARCHIVE_OK) {
                rc = is_passphrase_error(a) ? 2 : 1;
                fprintf(stderr, "archive: extract error: %s\n", errstr(a));
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
                    pathname ? pathname : "(unnamed)", errstr(ext));
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
        if (renamed_this_entry && nm_remember(&nm, archive_entry_pathname(e)) != 0) {
            /* Not fatal, deliberately: the entry IS on disk, and aborting would
             * throw away every file already extracted - the same trade the
             * name-resolution failure above refuses to make. Instead the map is
             * marked incomplete, and from here nm_is_ours assumes anything on
             * disk is ours. That renames more than it needs to, which is the
             * only direction that cannot destroy a file. */
            nm.degraded = 1;
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
    if (r < ARCHIVE_OK && r != ARCHIVE_EOF && rc == 0)
        rc = is_passphrase_error(a) ? 2 : 1;

    /* Checked for symmetry only: archive_write_disk's close() just forwards the
     * last finish_entry, which is already ARCHIVE_OK here because the loop calls
     * finish_entry per entry. The deferred directory fixups it performs (times,
     * permissions, ACLs, flags) have their return values discarded internally,
     * so libarchive offers no way to detect a failure in them. */
    int cl = archive_write_close(ext);
    if (cl != ARCHIVE_OK && cl != ARCHIVE_WARN) {
        fprintf(stderr, "archive: close: %s\n", errstr(ext));
        if (rc == 0)
            rc = 1;
    }
    archive_write_free(ext);
    archive_read_close(a);
    archive_read_free(a);
    smap_free(&nm.dirs);
    smap_free(&nm.claimed);
    smap_free(&nm.placed);

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
        fprintf(stderr, "archive: cannot open archive: %s\n", errstr(a));
        archive_read_free(a);
        return 4;
    }
    struct archive_entry *e;
    int r, warned = 0;
    char tbuf[32];
    /* ARCHIVE_WARN: header read, entry usable - see cmd_extract. Stopping here
     * made a single odd header report the whole archive as invalid, which in the
     * app means "not a valid zip" and no listing at all. */
    while ((r = archive_read_next_header(a, &e)) == ARCHIVE_OK || r == ARCHIVE_WARN) {
        if (r == ARCHIVE_WARN)
            warned++;
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
        fprintf(stderr, "archive: list error: %s\n", errstr(a));
        archive_read_close(a);
        archive_read_free(a);
        return 1;
    }
    /* One line, not one per entry: an archive that warns usually warns about
     * every entry, and the listing is run on every UI refresh. */
    if (warned > 0)
        fprintf(stderr, "archive: %d entr%s had a header warning\n",
                warned, warned == 1 ? "y" : "ies");
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
            fprintf(stderr, "archive: encryption option rejected: %s\n", errstr(w));
            archive_write_free(w);
            return NULL;
        }
        archive_write_set_passphrase(w, pass);
    }
    if (archive_write_open_filename(w, dst) != ARCHIVE_OK) {
        fprintf(stderr, "archive: cannot create %s: %s\n", dst, errstr(w));
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
    /* ARCHIVE_WARN: header read, entry usable - see cmd_extract. Stopping here
     * would silently drop that entry and every one after it from the rewritten
     * archive, which for recrypt means losing data outright. */
    while ((r = archive_read_next_header(a, &e)) == ARCHIVE_OK || r == ARCHIVE_WARN) {
        /* A WARN header can arrive with the pathname DISCARDED (NULL) - see
         * cmd_extract. The zip writer dereferences it unconditionally, so this
         * has to fail CLOSED: an archive whose entries we cannot all name is
         * one we must not rewrite. Extraction can invent a name because it only
         * creates files; recrypt replaces the user's archive, and inventing a
         * name there would store something they never chose under a command
         * that is only supposed to change the password. */
        if (archive_entry_pathname(e) == NULL) {
            fprintf(stderr, "archive: an entry name could not be decoded; "
                            "refusing to rewrite this archive\n");
            rc = 1;
            break;
        }
        if (archive_write_header(w, e) != ARCHIVE_OK) {
            fprintf(stderr, "archive: write header: %s\n", errstr(w));
            rc = 1; break;
        }
        la_ssize_t n; int werr = 0;
        while ((n = archive_read_data(a, buf, sizeof buf)) > 0) {
            if (archive_write_data(w, buf, (size_t)n) < 0) { werr = 1; break; }
        }
        if (werr) { fprintf(stderr, "archive: write data: %s\n", errstr(w)); rc = 1; break; }
        if (n < 0) { rc = is_passphrase_error(a) ? 2 : 1;
            fprintf(stderr, "archive: read error: %s\n", errstr(a)); break; }
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
            fprintf(stderr, "archive: write header: %s\n", errstr(w));
            archive_entry_free(e); rc = 1; break;
        }
        if (S_ISREG(st.st_mode)) {
            FILE *in = fopen(srcpath, "rb");
            if (in == NULL) { fprintf(stderr, "archive: cannot open %s\n", srcpath); archive_entry_free(e); rc = 1; break; }
            size_t got;
            while ((got = fread(buf, 1, sizeof buf, in)) > 0) {
                la_ssize_t nw = archive_write_data(w, buf, got);
                if (nw < 0) {
                    fprintf(stderr, "archive: write data: %s\n", errstr(w));
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
