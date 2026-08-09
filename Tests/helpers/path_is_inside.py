"""Is <path> inside <parent-dir>? For Tests/lib.test.zip.sh.

    path_is_inside.py <parent-dir> <path>     ->  prints yes or no

Answered about the FILESYSTEM, not about the spelling of the two strings,
because the applet reaches the same directory by two routes that spell it
differently.

The harness sets TMPDIR to "$OMCTEST_SCRATCH/tmp/", and OMCTEST_SCRATCH itself
came from mktemp under a macOS TMPDIR that already ends in a slash - so TMPDIR
arrives carrying an interior "//", as in "/var/folders/.../T//omctest.XXXX/tmp/".
lib_zip.preview_dir() keeps that doubling, because os.path.join preserves an
interior double slash; the path that comes back out of ziptool's result file has
been normalized and does not. Both name the same directory and both open fine -
only a string compare can tell them apart, and a string compare is not what the
assertion is about.

A path equal to the parent answers "no": the question is containment, not
identity.
"""
import os
import sys


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: path_is_inside.py <parent-dir> <path>\n")
        return 2
    parent, child = argv[1], argv[2]
    if not parent or not child:
        print("no")
        return 0
    parent = os.path.realpath(parent)
    child = os.path.realpath(child)
    try:
        inside = child != parent and os.path.commonpath([parent, child]) == parent
    except ValueError:
        # Not reachable on POSIX: realpath has already made both absolute, and
        # commonpath only raises for a mix of absolute and relative paths or for
        # different Windows drives. Kept so a future caller that skips realpath
        # gets "no" rather than a traceback.
        inside = False
    print("yes" if inside else "no")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
