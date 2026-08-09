"""Evaluate one expression in lib_zip's namespace, for Tests/lib.test.zip.sh.

Run under the APPLET's own interpreter, with the test file's environment, so
pb_get, DOCUMENT_UUID and the tool paths resolve exactly the way they do inside
a handler.

    zip_eval.py <expression> [argument ...]

Arguments after the expression arrive as ARGV, a list of strings. They are
passed rather than pasted into the expression on purpose: an entry name may
legally contain a quote, a backslash or a newline, and this suite deliberately
feeds it some, so an expression assembled by string interpolation would be a
quoting bug waiting for exactly the input the applet is being tested against.

Prints the value, or nothing when it is None. No trailing newline is added,
which every current caller reads through "$(...)" and so cannot observe - it
matters only if something ever pipes this.
"""
import os
import sys

_BUNDLE = os.environ.get("OMC_APP_BUNDLE_PATH", "")
if not _BUNDLE:
    # Without this the join yields a RELATIVE path and "import lib_zip" quietly
    # resolves against the current directory - the wrong module, silently, if
    # one happens to be there.
    sys.exit("zip_eval.py: OMC_APP_BUNDLE_PATH is not set")

sys.path.insert(0, os.path.join(_BUNDLE, "Contents/Resources/Scripts"))
import lib_zip  # noqa: E402  - the path above has to be set first


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: zip_eval.py <expression> [argument ...]\n")
        return 2
    namespace = dict(vars(lib_zip))
    namespace["ARGV"] = argv[2:]
    value = eval(argv[1], namespace)
    sys.stdout.write("" if value is None else str(value))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
