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
./build.sh            # same as 'release'
./build.sh release    # universal (arm64 + x86_64), -Os, stripped -> ./build/release/archive
./build.sh debug      # native arch only, -O0 -g, with a .dSYM  -> ./build/debug/archive
```

The source is C++17 (`clang++ -std=c++17`), with no dependency beyond the
system `libarchive` and the standard library. Both configurations are ad-hoc
signed.

The release build strips local symbols with `-Wl,-x` during the link rather than
with `strip(1)` afterwards, because running `strip` on an already-signed binary
invalidates its signature.

`build.sh` builds the tool and nothing else - it does not know that Zip.app
exists. To build the helper and embed it in the app, run `../update_zip.sh` from
the repository root; that script also re-signs the bundle and verifies the
embedded binary.

## Notes

- The macOS SDK ships no public `archive.h`, so libarchive 3.7.4's public
  headers (`archive.h`, `archive_entry.h`, BSD 2-clause) are vendored here next
  to `archive.cpp`. They match the system dylib version (`libarchive 3.7.4`, shipped
  with macOS 14.6+). We still link the *system* library via the SDK's
  `libarchive.tbd` stub (`-larchive`) - only the declarations are vendored, and
  `archive` does not bundle libarchive itself. Both headers carry their own
  `extern "C"` guards, so the C++ source includes them unmodified.
- To refresh the headers for a newer macOS libarchive, copy `archive.h` and
  `archive_entry.h` from the matching libarchive release tarball
  (https://www.libarchive.org/downloads/) - the version the system reports via
  `tar --version` / `archive_version_string()`.
- Build artifacts live in `build/` and are not part of the source.
