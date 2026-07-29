# Zip

A native macOS zip archive manager. Open a `.zip`, browse its contents in a Finder-like window, and extract, add, delete, or encrypt entries — including AES-encrypted archives that the stock tools handle awkwardly or not at all. Zip is a document-based editor: changes are staged and written back on save.

**Requires macOS 14.6 (Sonoma) or later.**

---

## Overview

Open a zip from Finder (double-click / Open With), by dropping it on the window, or through the in-app Open panel. Zip lists the archive's entries with name, size, compressed size, modified date, and an encrypted indicator, and lets you drill into folders with a breadcrumb or search across a flat filtered view.

---

## Requirements

| Requirement | Notes |
|---|---|
| macOS 14.6+ | Sonoma minimum |
| No external dependencies | Uses the system `zip`, `unzip`, and `tar` (libarchive) tools, an embedded Python 3 runtime, and the bundled `archive` helper. Nothing to install. |

---

## Features

- **Browse** entries with name, size, compressed size, and date; folder drill-down with a breadcrumb, plus a flat filtered/search view.
- **Extract** selected entries, a selected folder subtree, or the whole archive to a chosen destination.
- **Modify** the archive: add files and folders, delete selected entries.
- **Create** a new archive from dropped files.
- **Encryption**: detect encrypted archives, prompt for the password, and extract; create password-protected archives.
- **Reveal** extracted output in Finder.

`.cbz` comic archives are zips and open for free. Other formats (tar, 7z, rar) are out of scope; Zip is zip-only.

---

## Encrypted Archives

Zip reads both traditional ZipCrypto and WinZip **AES** encryption. AES support is the reason for the bundled `archive` helper: the stock `tar`/bsdtar can decrypt AES zips but only accepts the passphrase on the command line (visible in `ps`), and Python's `zipfile` cannot read AES at all.

The `archive` helper links the same system `libarchive` that backs `bsdtar` and passes the passphrase to `archive_read_add_passphrase()` in memory — the secret arrives only on **stdin** and is never a process argument. Extraction uses libarchive's secure flags, which reject absolute paths and `..` escapes. Source is in [`archive/`](archive/).

---

## Bundled Helper

| Helper | Location | Purpose |
|---|---|---|
| archive | `Contents/Helpers/archive` | Reads and extracts encrypted (AES / ZipCrypto) zip entries via libarchive, taking the passphrase on stdin; source in `archive/` |

The bundled binary and the embedded Python runtime are not committed to the repository (`Contents/Helpers/` and `Contents/Library/Python` are gitignored). Build the helper, embed it, and re-sign the app in one step with:

```bash
./update_zip.sh
```

---

## Underlying Tools

| Tool | Role |
|---|---|
| `zip` (Info-ZIP) | Create, add, delete entries; ZipCrypto encryption |
| `unzip` (Info-ZIP) | List, extract, test, decrypt |
| `tar` (libarchive) | AES-capable extraction backend |
| `ditto` | Finder-style archives |
| Embedded Python 3 | Robust listing, encryption probing, and safe path handling |
| `archive` (bundled) | In-memory-passphrase encrypted reads/extracts |

---

## Architecture

Zip is an OMC 5.1 applet. The OMC framework handles the app lifecycle, the document window, file/folder dialogs, drag-and-drop, and sheets (password prompt, encryption). The UI is defined declaratively in ActionUI JSON, and command routing is declared in `Contents/Resources/Command.json`. All business logic runs as Python 3 scripts in `Contents/Resources/Scripts/`, with shared helpers in `lib_zip.py` and archive operations centralized in `ziptool.py` (which routes encrypted reads through the `archive` helper).

---

## Building and Signing

`./update_zip.sh` is the whole build: it builds the `archive` helper (see [`archive/README.md`](archive/README.md)), embeds it in `Contents/Helpers/`, re-signs the bundle, and verifies the embedded binary still answers to every verb and flag the scripts emit.

```bash
./update_zip.sh                                            # ad-hoc (local use)
./update_zip.sh --identity="Developer ID Application: ..."  # for distribution
./update_zip.sh --debug                                    # embed a debug helper (do not ship)
./update_zip.sh --skip-build                               # re-sign only, reusing the embedded helper
```

After changing scripts or UI JSON without touching the helper, `--skip-build` is enough to re-seal the bundle. `update_zip.sh` delegates signing to `codesign_applet.sh`, which can also be run directly:

```bash
./codesign_applet.sh Zip.app -                                    # ad-hoc (local use)
./codesign_applet.sh Zip.app "Developer ID Application: ..."       # for distribution
```

Developer ID signing enables the hardened runtime and a timestamp; for distribution the app should then be notarized with `xcrun notarytool`.

---

## License

Zip is licensed under the Apache License 2.0 — see [LICENSE](LICENSE).
