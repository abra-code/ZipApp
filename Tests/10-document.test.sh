#!/bin/sh
# Tests/10-document.test.sh - Zip's document lifecycle and archive browsing.
#
# A starter suite, not full coverage. It pins the spine of the applet: opening
# an archive and getting its contents into the table, creating a new one,
# navigating and selecting, the three mutations that make a document dirty and
# clean again, and three paths where the applet must REFUSE - a canceled delete,
# a canceled replace, and a save whose working copy has vanished underneath it.
#
# Encryption, extraction and the password sheets are out of scope here and are
# not covered by any test in this directory; nothing below should be read as
# evidence that they work.
#
# POSIX sh only. Validate with "sh -n", never "bash -n".
. "${OMCTEST_LIB:?set OMCTEST_LIB, or run via: appletbuilder test}"
. "$OMCTEST_TESTS/lib.test.zip.sh"

# Three FILE entries, no stored directory records: docs/ and docs/notes/ exist
# only because the applet's model synthesizes them, which is what the navigation
# section actually exercises.
sample="$(make_sample_zip)"

section "1. a new untitled document"
reset_document
omc_object ""
omc_run Zip.main
check_status "the handler succeeded"      0
check "nothing on disk yet"               ""              "$(original)"
check "an empty working copy was made"    "Untitled.zip"  "$(/usr/bin/basename "$(work)")"
check_exists "and it is a real file"      "$(work)"
# Empty here is the point, and section 2 is its positive control: the same
# helper reads three names out of the sample archive.
check "with no entries in it"             "0"             "$(zip_count "$(work)")"
check "the table shows nothing"           "0"             "$(ui_row_count $ID_TABLE)"
check "at the archive root"               "/"             "$(ui_value $ID_BREADCRUMB)"
check "Up is off at the root"             "0"             "$(ui_enabled $ID_UP_BTN)"
check "Add is on"                         "1"             "$(ui_enabled $ID_ADD_BTN)"
check "titled Untitled.zip"               "Untitled.zip"  "$(ui_title)"
check "and says what to do next" "New archive - add files, then Save." "$(ui_value $ID_STATUS)"

section "2. opening an existing archive"
reset_document
omc_object "$sample"
omc_run Zip.main
check_status "the handler succeeded"      0
check "the original was adopted"          "$sample"       "$(original)"
# Opening for browsing must not copy the archive - the working copy is created
# lazily, on the first mutation. Section 7 is the positive control: a confirmed
# delete does make one.
check "no working copy just to browse"    ""              "$(work)"
check "clean on open"                     ""              "$(dirty)"
check "probed as a plain archive"         "plain"         "$(enc_state)"
check_exists "the model was cached"       "$(tsv_path)"
check "the root level reached the table"  "2"             "$(ui_row_count $ID_TABLE)"
check "folders sort first"                "docs"          "$(ui_rows $ID_TABLE | /usr/bin/sed -n 1p | /usr/bin/cut -f $COL_NAME)"
check "the file row carries its path"     "top.txt"       "$(ui_rows $ID_TABLE | /usr/bin/sed -n 2p | /usr/bin/cut -f $COL_FULLPATH)"
# 5, not 3: the count is of MODEL rows, so the two synthesized folders are in it.
check "the status line counts entries"    "Opened Sample.zip - 5 entries" "$(ui_value $ID_STATUS)"
check "titled after the document"         "Sample.zip"    "$(ui_title)"
check "Extract All is on"                 "1"             "$(ui_enabled $ID_EXTRACT_ALL_BTN)"

section "3. drilling into a folder and back out"
feed_row_to Zip.row.activated "docs" "--" "" "docs/" "1" "0"
check "the breadcrumb follows"            "/docs/"        "$(ui_value $ID_BREADCRUMB)"
check "Up is on below the root"           "1"             "$(ui_enabled $ID_UP_BTN)"
check "the level is .. plus two children" "3"             "$(ui_row_count $ID_TABLE)"
check "the folder was remembered"         "docs/"         "$(cur_prefix)"
omc_run Zip.nav.up
check "back at the root"                  "/"             "$(ui_value $ID_BREADCRUMB)"
check "the root level again"              "2"             "$(ui_row_count $ID_TABLE)"

section "4. selecting a file fills the inspector"
feed_row_to Zip.selection.changed "top.txt" "10 B" "2026-01-01 00:00" "top.txt" "0" "0"
check "name"                              "top.txt"       "$(ui_value $ID_DET_NAME)"
check "in-archive path"                   "top.txt"       "$(ui_value $ID_DET_PATH)"
check "size"                              "10 B"          "$(ui_value $ID_DET_SIZE)"
check "modified"                          "2026-01-01 00:00" "$(ui_value $ID_DET_MOD)"
check "not encrypted"                     "No"            "$(ui_value $ID_DET_ENC)"
# Kind is read from the extracted BYTES, not guessed from the extension - which
# is the whole reason the entry is extracted on selection at all.
check "kind came from the content"        "ASCII text"    "$(ui_value $ID_DET_KIND)"
check "Extract is on"                     "1"             "$(ui_enabled $ID_EXTRACT_BTN)"
check "Delete is on"                      "1"             "$(ui_enabled $ID_DELETE_BTN)"
check "the status bar shows the location" "/top.txt"      "$(ui_value $ID_STATUS)"
check "the selection was recorded"        "top.txt"       "$(sel_path)"
check "the preview pane got a real file"  "yes"           "$([ -f "$(ui_value $ID_PREVIEW)" ] && echo yes || echo no)"
# It must be the archive's own bytes in the document's own scratch, never a path
# reached by following a stored symlink out of the extraction directory.
check "extracted inside the document"     "yes"           "$(path_is_inside "$(preview_dir)" "$(ui_value $ID_PREVIEW)")"

section "5. the .. row is not a selection"
feed_row_to Zip.selection.changed ".." "" "" "__UP__" "1" "0"
check "the selection was cleared"         ""              "$(sel_path)"
check "the inspector was cleared"         "-"             "$(ui_value $ID_DET_NAME)"
check "Extract is off again"              "0"             "$(ui_enabled $ID_EXTRACT_BTN)"
check "Delete is off again"               "0"             "$(ui_enabled $ID_DELETE_BTN)"
check "the status bar falls back"         "/"             "$(ui_value $ID_STATUS)"

section "6. filtering is flat, and reverts to the folder you were in"
# Filtering is driven from INSIDE a folder on purpose. The first version of this
# section filtered at the root, where Up is already off - so "Up is off while
# filtering" was asserting the state it started in and stayed green with the
# whole filter branch deleted.
feed_row_to Zip.row.activated "docs" "--" "" "docs/" "1" "0"
check "inside a folder Up is on"          "1"             "$(ui_enabled $ID_UP_BTN)"
fire_filter "readme"
check "the breadcrumb names the filter"   "Filter: readme" "$(ui_value $ID_BREADCRUMB)"
check "one match"                         "1"             "$(ui_row_count $ID_TABLE)"
# Flat: the match is in docs/, and the filter searches the whole archive rather
# than the level being browsed.
check "and it is the nested entry"        "docs/readme.txt" "$(ui_rows $ID_TABLE | /usr/bin/cut -f $COL_FULLPATH)"
check "a flat list has nowhere to go up"  "0"             "$(ui_enabled $ID_UP_BTN)"
fire_filter ""
check "clearing returns to that folder"   "/docs/"        "$(ui_value $ID_BREADCRUMB)"
check "with its rows back"                "3"             "$(ui_row_count $ID_TABLE)"
check "and Up with them"                  "1"             "$(ui_enabled $ID_UP_BTN)"
omc_run Zip.nav.up
check "back at the root for what follows" "2"             "$(ui_row_count $ID_TABLE)"

section "7. delete: Cancel really cancels"
feed_row_to Zip.selection.changed "top.txt" "10 B" "" "top.txt" "0" "0"
alerts_reset
alert_answer 1                                   # Cancel
omc_run Zip.delete.selected
check "the user was asked"                "1"             "$(alerts_count)"
check "and asked about the right entry"   "1"             "$(alerts_mention 'top.txt')"
# The strongest evidence that nothing happened: ensure_working_copy is never
# reached, so no copy of the archive exists at all.
check "no working copy was even made"     ""              "$(work)"
check "the document is still clean"       ""              "$(dirty)"
check "the entry is still in the file"    "yes"           "$(zip_has "$sample" top.txt)"

section "8. delete: confirmed"
alerts_reset
alert_answer 0                                   # Delete
omc_run Zip.delete.selected
check "the user was asked once"           "1"             "$(alerts_count)"
check "now there is a working copy"       "yes"           "$([ -f "$(work)" ] && echo yes || echo no)"
check "the entry is gone from it"         "no"            "$(zip_has "$(work)" top.txt)"
check "the other two survived"            "2"             "$(zip_count "$(work)")"
check "the document is dirty"             "1"             "$(dirty)"
# The marker is U+25CF, spelled as an escape so this file stays ASCII and
# evaluated by Python so the expected value is the real character.
check "the title marks unsaved changes"   "$(zip_eval '"\u25cf " + ARGV[0]' 'Sample.zip')" "$(ui_title)"
check "the file on disk is untouched"     "yes"           "$(zip_has "$sample" top.txt)"
check "the table dropped the row"         "1"             "$(ui_row_count $ID_TABLE)"

section "9. save writes the working copy back"
omc_run Zip.save
check "clean again"                       ""              "$(dirty)"
check "status says so"                    "Saved Sample.zip" "$(ui_value $ID_STATUS)"
check "the title lost its marker"         "Sample.zip"    "$(ui_title)"
check "the deletion reached disk"         "no"            "$(zip_has "$sample" top.txt)"
check "and the rest is intact"            "yes"           "$(zip_has "$sample" docs/readme.txt)"

section "10. save refuses when the working copy has vanished"
# TMPDIR is swept periodically. Skipping the copy here would mark the document
# clean and report "Saved" while every edit is lost, so it must refuse loudly.
/bin/rm -f "$(work)"
alerts_reset
omc_run Zip.save
check "the user was told"                 "1"             "$(alerts_count)"
check "and told what happened"            "1"             "$(alerts_mention 'could not be found')"
check "status names the failure"          "Save failed - working copy missing." "$(ui_value $ID_STATUS)"
check "the archive on disk is unchanged"  "yes"           "$(zip_has "$sample" docs/readme.txt)"
# Not cleanup(): the window is still open, and clearing the per-window keys here
# would strip a live document of its identity.
check "the document keeps its identity"   "$sample"       "$(original)"

section "11. Save As on an untitled document appends the extension"
omc_window_switch "saveas"
reset_document
omc_object ""
omc_run Zip.new
omc_dialog_answer save_as "$OMCTEST_WORK/Backup"
omc_run Zip.save.as
check "the extension was appended"        "$OMCTEST_WORK/Backup.zip" "$(original)"
check_exists "and the file is there"      "$OMCTEST_WORK/Backup.zip"
check "it is a readable archive"          "yes"           "$(zip_is 'is_zip(ARGV[0])' "$OMCTEST_WORK/Backup.zip")"
check "status says so"                    "Saved Backup.zip" "$(ui_value $ID_STATUS)"
check "the title followed the new name"   "Backup.zip"    "$(ui_title)"

section "12. Save As asks before replacing the file the panel never checked"
# NSSavePanel ran its overwrite check against "Existing", not "Existing.zip".
printf 'not an archive\n' > "$OMCTEST_WORK/Existing.zip"
alerts_reset
alert_answer 1                                   # Cancel the replace prompt
omc_dialog_answer save_as "$OMCTEST_WORK/Existing"
omc_run Zip.save.as
check "the user was asked"                "1"             "$(alerts_count)"
check "and asked to replace"              "1"             "$(alerts_mention 'already exists')"
check "Cancel left the other file alone"  "not an archive" "$(/bin/cat "$OMCTEST_WORK/Existing.zip")"
check "status says it was canceled"       "Save cancelled" "$(ui_value $ID_STATUS)"
check "and the path was not adopted"      "$OMCTEST_WORK/Backup.zip" "$(original)"
alert_answer 0                                   # Replace
omc_dialog_answer save_as "$OMCTEST_WORK/Existing"
omc_run Zip.save.as
check "Replace wrote a real archive"      "yes"           "$(zip_is 'is_zip(ARGV[0])' "$OMCTEST_WORK/Existing.zip")"
check "and the path was adopted"          "$OMCTEST_WORK/Existing.zip" "$(original)"

section "13. Cmd-S on an untitled document asks for a destination"
omc_window_switch "untitled-save"
reset_document
omc_object ""
omc_run Zip.new
omc_run Zip.save
check "it chained to Save As"             "1"             "$(chain_asked Zip.save.as)"
check "and wrote nothing anywhere"        ""              "$(original)"

section "14. closing a clean document cleans up"
alerts_reset
omc_run Zip.window.close
check "a clean document is not questioned" "0"            "$(alerts_count)"
check_absent "the scratch directory is gone" "$(doc_dir)"
check "and the per-window state cleared"  ""              "$(work)"

section "15. closing a dirty document: Don't Save discards"
omc_window_switch "close-discard"
reset_document
discard_sample="$(make_sample_zip Discard.zip)"
omc_object "$discard_sample"
omc_run Zip.main
feed_row_to Zip.selection.changed "top.txt" "10 B" "" "top.txt" "0" "0"
alert_answer 0
omc_run Zip.delete.selected
check "the document is dirty first"       "1"             "$(dirty)"
alerts_reset
# The close alert wires Don't Save to the Cancel slot, so 1 is the discard.
alert_answer 1
omc_run Zip.window.close
check "the user was asked"                "1"             "$(alerts_count)"
check_absent "the scratch went with it"   "$(doc_dir)"
check "the state was cleared"             ""              "$(original)"
check "and the archive on disk kept its entry" "yes"      "$(zip_has "$discard_sample" top.txt)"

section "16. closing a dirty document: Save writes it first"
omc_window_switch "close-save"
reset_document
keep_sample="$(make_sample_zip Keep.zip)"
omc_object "$keep_sample"
omc_run Zip.main
feed_row_to Zip.selection.changed "top.txt" "10 B" "" "top.txt" "0" "0"
alert_answer 0
omc_run Zip.delete.selected
alerts_reset
alert_answer 0                                   # Save
omc_run Zip.window.close
check "the user was asked"                "1"             "$(alerts_count)"
check "the deletion reached disk"         "no"            "$(zip_has "$keep_sample" top.txt)"
check "the rest of the archive is there"  "2"             "$(zip_count "$keep_sample")"
check_absent "and then it cleaned up"     "$(doc_dir)"

section "17. an alert answer that is not a decision never discards the edits"
# The close alert can also come back 2 (Other), 3 (timed out) or 255 (failed to
# display). None of those is the user choosing to throw work away, and a plain
# else: cleanup() used to treat them as one.
omc_window_switch "close-timeout"
reset_document
timeout_sample="$(make_sample_zip Timeout.zip)"
omc_object "$timeout_sample"
omc_run Zip.main
feed_row_to Zip.selection.changed "top.txt" "10 B" "" "top.txt" "0" "0"
alert_answer 0
omc_run Zip.delete.selected
alerts_reset
# 3 = timed out for the close question; 1 = the recovery offer's "OK" slot, so
# the handler does not shell out to Finder in the middle of a test run.
alert_answer 3 1
omc_run Zip.window.close
check "the question and the recovery offer" "2"           "$(alerts_count)"
check "the offer names the temporary copy" "1"            "$(alerts_mention 'temporary copy')"
check "the working copy was NOT discarded" "yes"          "$([ -f "$(work)" ] && echo yes || echo no)"
check_exists "the scratch directory survives" "$(doc_dir)"
check "the edits are still in it"         "no"            "$(zip_has "$(work)" top.txt)"

section "18. a file that is not an archive starts a new archive containing it"
omc_window_switch "wrap"
reset_document
printf 'hello\n' > "$OMCTEST_WORK/notes.txt"
omc_object "$OMCTEST_WORK/notes.txt"
omc_run Zip.main
check "the file was not adopted as the document" ""       "$(original)"
check "it was stored in a new archive"    "yes"           "$(zip_has "$(work)" notes.txt)"
check "one row in the table"              "1"             "$(ui_row_count $ID_TABLE)"
check "status explains what happened" "New archive from notes.txt - Save to keep it." "$(ui_value $ID_STATUS)"
check "dirty from the start"              "1"             "$(dirty)"

section "19. two rules the browsing depends on, called directly"
check "the archive root reads as /"       "/"             "$(zip_eval 'arc_location(ARGV[0])' '')"
check "a folder loses its trailing slash" "/docs"         "$(zip_eval 'arc_location(ARGV[0])' 'docs/')"
# The hidden addressing column must be injective, or selecting one row deletes
# another: display sanitizing folds a tab to a space, and these two names would
# then be the same string.
check "a tab and a space stay distinct"   "no"            "$(zip_is 'path_encode(ARGV[0]) == path_encode(ARGV[1])' "$(printf 'a\tb.txt')" 'a b.txt')"
check "and the encoding round-trips"      "yes"           "$(zip_is 'path_decode(path_encode(ARGV[0])) == ARGV[0]' "$(printf 'a\tb.txt')")"

section "cumulative: the window never wrote to a view id it does not declare"
# unknown_ids.log accumulates across the whole file, so this one assertion covers
# every section above it. The line before it is its positive control: if the
# bundle's id extraction had produced nothing, the detector would be silently
# inert and the assertion could not fail.
#
# This check was red on its first run, and it was red for a real defect rather
# than a test problem - which is the whole argument for having it.
#
# lib_zip.py declared ID_FILTER = 40, and load_archive() and new_archive() each
# called set_value(ID_FILTER, "") to clear the search field on load. No view
# with id 40 existed. The search field is the "searchable" modifier on the
# window in Zip.json, and that modifier's schema accepts only "prompt" and
# "actionID" - ActionUI gives it no id at all, so there was nothing for
# omc_dialog_control to address and the two calls silently did nothing.
# Zip.filter.changed.py had said so all along in a comment.
#
# Fixed by deleting the constant and both calls, which is the only fix available:
# an id cannot be added to a searchable modifier. Clearing the box on load is
# simply not expressible, so a stale query stays until the user clears it, and
# Zip.filter.changed restores the current folder as soon as it goes empty.
check "the id set was extracted"          "yes"           "$([ -s "$OMCTEST_UI/known_ids.txt" ] && echo yes || echo no)"
check "no undeclared ids"                 ""              "$(ui_unknown_writes)"
check "no bare value clobbered a table"   ""              "$(ui_suspect_writes)"
check "no malformed omc_dialog_control calls" ""          "$(ui_errors)"

omctest_end
