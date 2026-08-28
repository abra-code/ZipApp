"""Evaluate one expression in ziptool's namespace, for Tests/lib.test.zip.sh.

    ziptool_eval.py <expression> [argument ...]

The sibling of zip_eval.py, and it exists for the same reason: several of
ziptool's rules are named functions worth testing directly, and dispatching a
whole handler to reach them says much less about which rule broke.

ziptool is a COMMAND, not a module on any path - the applet runs it as an argv
program under its own interpreter - so it is loaded here by file location rather
than imported by name. Under the applet's interpreter, like zip_eval, because
that is the one ziptool really runs under.

Arguments after the expression arrive as ARGV, a list of strings, for the
quoting reason zip_eval.py sets out at length: a path may legally contain a
quote, a backslash or a newline, and an expression assembled by interpolation
would be a bug waiting for exactly that input.
"""
import importlib.util
import os
import sys

# Before any applet code is loaded: importing it would otherwise leave a
# __pycache__ directory INSIDE the signed app bundle. Those must never be
# hidden away in .gitignore - a stray .pyc in a bundle is something to see and
# delete - so the fix is not to create one in the first place.
sys.dont_write_bytecode = True

_BUNDLE = os.environ.get("OMC_APP_BUNDLE_PATH", "")
if not _BUNDLE:
    sys.exit("ziptool_eval.py: OMC_APP_BUNDLE_PATH is not set")

_PATH = os.path.join(_BUNDLE, "Contents/Resources/Scripts/ziptool.py")
_spec = importlib.util.spec_from_file_location("ziptool", _PATH)
if _spec is None or _spec.loader is None:
    sys.exit("ziptool_eval.py: cannot load %s" % _PATH)
ziptool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ziptool)


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: ziptool_eval.py <expression> [argument ...]\n")
        return 2
    namespace = dict(vars(ziptool))
    namespace["ARGV"] = argv[2:]
    value = eval(argv[1], namespace)
    sys.stdout.write("" if value is None else str(value))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
