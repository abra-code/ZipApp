"""An independent report of what is really stored in an archive.

    zip_oracle.py count <archive>              -> how many file entries
    zip_oracle.py has   <archive> <entry-name> -> yes or no
    zip_oracle.py names <archive>              -> one entry per line, for eyeballing
    zip_oracle.py content <archive> <entry>    -> the entry's bytes, or UNREADABLE

Deliberately independent: it uses the SYSTEM python's zipfile, not the applet's
ziptool and not the applet's embedded interpreter. An assertion about what a
delete removed is worthless if the thing reporting the contents is the same code
that performed the removal.

Directory entries are dropped, so the answer is always "which files are stored",
which is what every assertion using this is about.

Two things this had wrong when it was a shell here-doc, both found in review:

1. It emitted names one per line, and a zip entry name may legally contain a
   newline - lib_zip._read_model_rows is NUL-framed for exactly that reason. So
   an entry called "two\\nlines.txt" counted as two entries, and "has" answered
   yes for the string "lines.txt", which is in no archive. Counting and matching
   happen in here now, where a name is a value rather than a line. The "names"
   subcommand is still line-framed and is for reading, not for asserting.

2. An unreadable archive reported the same empty list as an empty one, and the
   exit status that would have told them apart was swallowed by a shell
   pipeline. A corrupt working copy therefore satisfied "with no entries in it".
   Every subcommand now says UNREADABLE out loud, so no assertion can mistake
   the two.

unzip(1) was the obvious oracle and is the wrong one: for an empty archive it
prints "Empty zipfile." on STDOUT, so a brand new document read back as having
one entry named after the error message.
"""
import sys
import zipfile

UNREADABLE = "UNREADABLE"


def stored_files(path):
    """Sorted names of the file entries, or None when the archive cannot be read."""
    try:
        with zipfile.ZipFile(path) as archive:
            return sorted(n for n in archive.namelist() if not n.endswith("/"))
    except (OSError, zipfile.BadZipFile):
        return None


def entry_bytes(path, name):
    """The entry's stored CONTENT, or None when it cannot be read.

    Needed because a name and a size do not settle whether an update actually
    happened: Info-ZIP keeps the existing entry when it cannot read the
    replacement, and rewrites that entry's header to the new size anyway, so the
    listing looks exactly like a successful update. Only the bytes tell them
    apart, and only an oracle outside the applet can be trusted to say so."""
    try:
        with zipfile.ZipFile(path) as archive:
            return archive.read(name)
    except (OSError, KeyError, RuntimeError, NotImplementedError,
            zipfile.BadZipFile):
        # RuntimeError is an encrypted entry and NotImplementedError an
        # unsupported compression method - both are "cannot be read", not a
        # reason for the helper to die with a traceback.
        return None


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(
            "usage: zip_oracle.py count|has|names|content <archive> [entry-name]\n")
        return 2
    action, path = argv[1], argv[2]
    names = stored_files(path)

    if action == "count":
        print(UNREADABLE if names is None else len(names))
    elif action == "has":
        if len(argv) != 4:
            sys.stderr.write("usage: zip_oracle.py has <archive> <entry-name>\n")
            return 2
        print(UNREADABLE if names is None else ("yes" if argv[3] in names else "no"))
    elif action == "content":
        if len(argv) != 4:
            sys.stderr.write("usage: zip_oracle.py content <archive> <entry>\n")
            return 2
        data = entry_bytes(path, argv[3])
        if data is None:
            print(UNREADABLE)
            return 1
        # Written as bytes: an entry's content is not required to be text, and
        # decoding it would make the assertion about the decoder.
        sys.stdout.flush()
        sys.stdout.buffer.write(data)
        return 0
    elif action == "names":
        if names is None:
            print(UNREADABLE)
        else:
            for name in names:
                print(name)
    else:
        sys.stderr.write("zip_oracle.py: unknown action [%s]\n" % action)
        return 2
    return 0 if names is not None else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
