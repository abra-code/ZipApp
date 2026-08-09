#!/bin/sh
# lib.test.zip.sh - the Zip applet's own test vocabulary.
#
# Sourced by every Tests/*.test.sh file, after omctest.sh. omctest supplies the
# generic half - the scratch tree, the interposition directory, the alert and
# omc_dialog_control stubs, check/section/omctest_end - and knows nothing about
# this applet. Everything below encodes Zip's private layout: where its
# per-document scratch lives, which pasteboard keys carry its state, which table
# columns the handlers read, and how to call into lib_zip.py directly.
#
# Zip is a Python applet; the test files are still POSIX sh, because the
# assertion surface (files, exit codes, recorded window writes) is
# language-neutral. Where a helper genuinely needs Python it lives in
# Tests/helpers/ as a real .py file with its own docstring, rather than as a
# here-doc inside a shell function: a script in a file can be read, linted and
# run on its own, and it does not force the reader to hold two languages'
# quoting rules in mind at once.
#
# POSIX sh only. Validate with "sh -n", never "bash -n".

TEST_HELPERS="$OMCTEST_TESTS/helpers"

# --- Where the applet keeps things --------------------------------------------

# lib_zip.py: DOCUMENT_UUID = PARENT_UUID or WINDOW_UUID. Factored out because
# both the scratch directory and every pasteboard key are keyed off it, and the
# two disagreeing is a silent failure - a wrong key reads back empty, and
# several checks below assert that a value IS empty.
document_uuid() { printf '%s' "${OMC_PARENT_DIALOG_GUID:-$OMC_ACTIONUI_WINDOW_UUID}"; }

# lib_zip.doc_dir() is os.path.join(TMP, "zip-<uuid>"), and os.path.join
# COLLAPSES the trailing slash macOS puts on TMPDIR. Shell interpolation does
# not, so "${TMPDIR}zip-x" would be right and "${TMPDIR}/zip-x" would be a
# doubled slash that only fails when a path is compared as a string. ${TMPDIR%/}
# reproduces what Python actually produces, either way.
doc_dir() {
    local tmp_dir="${TMPDIR:-/tmp}"
    printf '%s/zip-%s' "${tmp_dir%/}" "$(document_uuid)"
}

tsv_path() { printf '%s/entries.tsv' "$(doc_dir)"; }
preview_dir() { printf '%s/preview' "$(doc_dir)"; }

# --- Per-document state, which lives entirely in the pasteboard ----------------
#
# The real pasteboard tool, reached through the interposition directory exactly
# as the handlers reach it - not the framework copy directly, so a test that
# stubs the tool still reads what the handler wrote.
pb_key() { printf 'zip_%s_%s' "$1" "$(document_uuid)"; }
pb_get() { "$OMC_OMC_SUPPORT_PATH/pasteboard" "$(pb_key "$1")" get 2>/dev/null; }
pb_set() { printf '%s' "$2" | "$OMC_OMC_SUPPORT_PATH/pasteboard" "$(pb_key "$1")" set; }

original() { pb_get original; }
work() { pb_get work; }
dirty() { pb_get dirty; }
enc_state() { pb_get enc; }
# PB_PREFIX and PB_SEL_PATH hold the PERCENT-ENCODED form (lib_zip stores them
# that way because the pasteboard tool cannot hold invalid UTF-8), so these
# decode before handing the value back - a test comparing against the raw stored
# form would be asserting about the encoding rather than about the selection.
sel_path() { zip_eval 'path_decode(pb_get(PB_SEL_PATH))'; }
cur_prefix() { zip_eval 'path_decode(pb_get(PB_PREFIX))'; }

# --- Calling lib_zip directly --------------------------------------------------
#
# Whole-handler dispatch is coarse: most of this applet's rules live in named
# functions in lib_zip.py, and those are worth testing directly.
#
# A separate process on purpose: lib_zip's module-level code recomputes
# DOCUMENT_UUID and the pasteboard key names from the environment at import, so
# an in-process cache would go stale the moment a test switched windows.
#
# Arguments after the expression arrive as ARGV rather than being pasted into
# it. See helpers/zip_eval.py for why that is a correctness requirement here and
# not a style preference.
zip_eval() { # <python-expression> [argument ...]
    "$OMCTEST_PYTHON" "$TEST_HELPERS/zip_eval.py" "$@"
}

zip_path_encode() { zip_eval 'path_encode(ARGV[0])' "$1"; }

# yes/no for an expression that answers a question. Named for what the caller
# wants to read, so the check line says the rule rather than the plumbing.
#
# It answers "no" for a Python-level failure too - a traceback is not True - so
# a check whose expected value happens to BE "no" would pass on a broken
# expression. Every such check in this suite is therefore paired with its
# opposite, which cannot pass that way.
zip_is() { # <python-expression> [argument ...]
    local expression="$1"
    shift
    if [ "$(zip_eval "bool($expression)" "$@")" = "True" ]; then echo yes; else echo no; fi
}

# Is <path> inside <parent-dir>? Asked of the FILESYSTEM, not of the spelling of
# the two strings - the applet reaches the same directory by two routes that
# spell it differently, and helpers/path_is_inside.py explains which and why.
#
# A plain "case $2 in $1/*" would not do even for the string version: a command
# substitution inside a case PATTERN inside another command substitution does
# not parse in bash 3.2 posix mode.
path_is_inside() { # <parent-dir> <path>
    /usr/bin/python3 "$TEST_HELPERS/path_is_inside.py" "$1" "$2"
}

# --- An independent oracle for what is really in an archive --------------------
#
# The SYSTEM python's zipfile, deliberately neither the applet's own ziptool nor
# its embedded interpreter: an assertion about what a delete removed is
# worthless if the thing reporting the contents is the same code that performed
# the removal. helpers/zip_oracle.py records why unzip(1) was the wrong oracle.
#
# Counting and matching happen inside the helper, not here. A zip entry name may
# legally contain a newline, so a line-framed answer piped into "wc -l" or
# "grep -x" miscounts and can match a name that is not in the archive - the same
# hazard lib_zip._read_model_rows is NUL-framed to avoid. Both helpers below
# answer with a single value, and both say UNREADABLE rather than "empty" when
# the archive cannot be read at all.
zip_count() { # <archive> -> how many file entries, or UNREADABLE
    /usr/bin/python3 "$TEST_HELPERS/zip_oracle.py" count "$1"
}

zip_has() { # <archive> <entry-name> -> yes, no, or UNREADABLE
    /usr/bin/python3 "$TEST_HELPERS/zip_oracle.py" has "$1" "$2"
}

# For reading, not for asserting - this one IS line-framed.
zip_names() { # <archive>
    /usr/bin/python3 "$TEST_HELPERS/zip_oracle.py" names "$1"
}

# --- Fixtures ------------------------------------------------------------------
#
# Synthesized rather than committed: no binaries in the repository, and the
# block that builds one is a readable statement of exactly which shape the
# assertions depend on. Three FILE entries and no stored directory records, so
# the two folders in the listing are ones the applet's model synthesizes - which
# is the part of build_model the navigation checks actually exercise.
#
# zip(1) is asserted present where the fixture is built rather than discovered
# 200 lines later as a run of failures that read like an applet defect.
make_sample_zip() { # [name, default Sample.zip] -> prints the archive path
    local archive_name="${1:-Sample.zip}" stage_dir archive_path
    check "fixture precondition: /usr/bin/zip is present" "yes" \
        "$([ -x /usr/bin/zip ] && echo yes || echo no)"
    stage_dir="$OMCTEST_WORK/stage-${archive_name%.zip}"
    archive_path="$OMCTEST_WORK/$archive_name"
    /bin/rm -rf "$stage_dir" "$archive_path"
    /bin/mkdir -p "$stage_dir/docs/notes"
    printf 'top level\n' > "$stage_dir/top.txt"
    printf 'read me first\n' > "$stage_dir/docs/readme.txt"
    printf 'deep note\n' > "$stage_dir/docs/notes/deep.txt"
    # -X drops the extra attribute blocks; the explicit file list (rather than
    # -r) is what keeps the stored directory records out.
    ( cd "$stage_dir" && /usr/bin/zip -q -X "$archive_path" \
        top.txt docs/readme.txt docs/notes/deep.txt ) || return 1
    printf '%s' "$archive_path"
}

# --- The table the handlers read back ------------------------------------------
#
# ziptool.feed_row emits seven tab-separated fields per row and the handlers read
# them back by number (lib_zip.get_table_value / get_table_path). The applet
# names none of them, so they are named here once, against feed_row's own
# docstring, rather than spelled as bare digits at twenty call sites.
COL_ICON=1
COL_NAME=2
COL_SIZE=3
COL_MODIFIED=4
COL_FULLPATH=5
COL_ISDIR=6
COL_ENC=7

# Hand the handler one table row exactly as the engine would: the visible cells,
# the hidden addressing cells, and the trigger that says the table fired.
#
# The fullpath cell carries the PERCENT-ENCODED form, because that is what
# ziptool put in the hidden column and what lib_zip.get_table_path decodes. A
# test that passed the raw path here would be feeding the handler something the
# real table never contains.
feed_row_to() { # <command-id> <name> <size> <modified> <fullpath> <isdir> <enc>
    local command_id="$1" row_name="$2" row_size="$3" row_modified="$4"
    local row_fullpath="$5" row_isdir="$6" row_enc="$7" encoded
    encoded="$(zip_path_encode "$row_fullpath")"
    omc_table_cell "$ID_TABLE" "$COL_NAME" "$row_name"
    omc_table_cell "$ID_TABLE" "$COL_SIZE" "$row_size"
    omc_table_cell "$ID_TABLE" "$COL_MODIFIED" "$row_modified"
    omc_table_cell "$ID_TABLE" "$COL_FULLPATH" "$encoded"
    omc_table_cell "$ID_TABLE" "$COL_ISDIR" "$row_isdir"
    omc_table_cell "$ID_TABLE" "$COL_ENC" "$row_enc"
    omc_trigger "$ID_TABLE"
    omc_run "$command_id"
}

# The searchable field is a modifier on the content VStack in Zip.json, not an
# element of its own, so its query arrives as the trigger CONTEXT rather than as
# a control value - which is why there is no id to set here.
#
# What the engine puts in the view-id slot is the CARRIER element's id, and that
# VStack declares none, so ActionUI auto-assigns it a negative one. An empty
# string is therefore not literally what the engine sends. It is the right
# simulation anyway: Zip.filter.changed.py never reads the view id, and pinning
# a made-up negative number would assert an ActionUI implementation detail this
# suite has no business depending on. Stated so nobody reads the empty argument
# as a claim about the engine.
#
# omc_trigger unsets an empty context, which is exactly how the engine delivers
# a cleared search field.
fire_filter() { # <query>
    omc_trigger "" "" "$1"
    omc_run Zip.filter.changed
}

# --- Resetting between scenarios ------------------------------------------------
#
# Discard the whole document: the scratch tree AND every pasteboard key. Removing
# only the directory would leave PB_ORIGINAL and PB_DIRTY pointing at a document
# that no longer exists, and the next section would inherit them.
reset_document() {
    local state_key
    /bin/rm -rf "$(doc_dir)"
    for state_key in work original dirty prefix sel_path sel_isdir enc password \
        ex_dest ex_mode ex_last close_after_save; do
        pb_set "$state_key" ""
    done
}

# --- View ids, imported from the applet rather than restated ---------------------
#
# lib_zip.py already names every view the applet drives (ID_TABLE = 10, ...). A
# second list here is a list that can disagree with the first, and the way it
# disagrees is silent: a name that fails to import expands to the empty string,
# omc_control writes OMC_ACTIONUI_VIEW__VALUE, and every check fails one by one
# with no hint why.
#
# Only bare "ID_NAME = <digits>" lines are taken, so nothing else in lib_zip can
# arrive here through the eval. Note the Python spacing - the shell form in the
# omctest guide ("NAME_ID=129") does not match a .py file.
omctest_import_view_ids() { # <script ...>
    local script
    for script; do
        eval "$(/usr/bin/sed -n \
            's/^\(ID_[A-Z0-9_]*\)  *=  *\([0-9][0-9]*\)  *$/\1=\2/p;
             s/^\(ID_[A-Z0-9_]*\)  *=  *\([0-9][0-9]*\)$/\1=\2/p' "$script")"
    done
}
omctest_import_view_ids \
    "$OMC_APP_BUNDLE_PATH/Contents/Resources/Scripts/lib_zip.py"

# Fail once, here, and name every id the suite drives rather than a sample of
# them: an id that went missing from the app is exactly the case this is for.
for omctest_required_id in ID_TABLE ID_ADD_BTN ID_DELETE_BTN ID_EXTRACT_BTN \
    ID_EXTRACT_ALL_BTN ID_UNLOCK ID_ENCRYPT ID_CHANGE_PW \
    ID_REMOVE_ENC ID_UP_BTN ID_BREADCRUMB ID_DET_NAME ID_DET_PATH ID_DET_SIZE \
    ID_DET_MOD ID_DET_ENC ID_DET_KIND ID_PREVIEW ID_STATUS; do
    eval "omctest_required_value=\$$omctest_required_id"
    [ -n "$omctest_required_value" ] || {
        printf 'lib.test.zip: %s did not import from lib_zip.py\n' \
            "$omctest_required_id" >&2
        exit 1
    }
done
unset omctest_required_id omctest_required_value
