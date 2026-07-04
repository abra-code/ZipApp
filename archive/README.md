# archive - secure archive reader/extractor for Zip.app

`archive` lets Zip.app read and extract encrypted zip entries (WinZip AES and
traditional ZipCrypto) **without putting the password on a command line**.

## Why this exists

The macOS `tar`/bsdtar can decrypt AES zips, but it only accepts the passphrase
via `--passphrase` on argv, which is visible in `ps` for the life of the call.
Python's stdlib `zipfile` cannot read AES at all. `archive` links the same system
`libarchive` that backs bsdtar and hands the passphrase to
`archive_read_add_passphrase()` in memory. The secret arrives only on **stdin**
and is never an argument.

## Usage

```
archive read    <archive> <entry> [--max BYTES]    # entry bytes -> stdout (previews)
archive extract <archive> <destdir> [member ...]   # extract all, or only listed members
```

The passphrase is read from **stdin** in full; one trailing newline (and an
optional preceding CR) is stripped. Empty stdin means "no passphrase".

Extraction preserves the archive's internal paths under `<destdir>`;
libarchive's secure flags reject absolute and `..` escapes. The caller maps the
staged paths afterwards (see `Scripts/ziptool.py`).

### Exit codes (aligned with `Scripts/ziptool.py`)

| code | meaning |
|------|---------|
| 0 | ok |
| 1 | generic error / entry not found |
| 2 | passphrase required or incorrect |
| 4 | cannot open / not a valid archive |

## Build

```
./build.sh            # universal (arm64 + x86_64), ad-hoc signed, -> ./build/archive
./build.sh install    # also copy into ../Zip.app/Contents/Helpers/archive
```

After `install`, re-seal the app so the bundle signature covers the new binary:

```
appletbuilder build ../Zip.app
```

## Notes

- The macOS SDK ships no public `archive.h`, so libarchive 3.7.4's public
  headers (`archive.h`, `archive_entry.h`, BSD 2-clause) are vendored here next
  to `archive.c`. They match the system dylib version (`libarchive 3.7.4`, shipped
  with macOS 14.6+). We still link the *system* library via the SDK's
  `libarchive.tbd` stub (`-larchive`) - only the declarations are vendored, and
  `archive` does not bundle libarchive itself.
- To refresh the headers for a newer macOS libarchive, copy `archive.h` and
  `archive_entry.h` from the matching libarchive release tarball
  (https://www.libarchive.org/downloads/) - the version the system reports via
  `tar --version` / `archive_version_string()`.
- Build artifacts live in `build/` and are not part of the source.
