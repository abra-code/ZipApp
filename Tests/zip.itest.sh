# Tests/zip.itest.sh - Zip through the real engine (appletbuilder itest, OMC 5.5).
#
# The omctest suites (*.test.sh) run Zip's Python handlers one at a time with stand-in tools; this
# file launches the applet itself: the launch's own open panel, opening an archive through the
# main command, and Extract All through its CHOOSE_FOLDER_DIALOG, answered by the test, with the
# handlers passing the folder along on their per-window pasteboards as a user's run does.

ID_EXTRACT_ALL_BTN=34
ID_STATUS=80

SRC="$ITEST_WORK/src"
/bin/mkdir -p "$SRC/docs"
printf 'alpha\n' > "$SRC/a.txt"
printf 'beta\n' > "$SRC/docs/b.txt"
ARCHIVE="$ITEST_WORK/sample.zip"
# --norsrc: no AppleDouble ._ entries from whatever extended attributes the files picked up.
/usr/bin/ditto -c -k --norsrc --keepParent "$SRC" "$ARCHIVE"
check "the sample archive was made" "yes" "$([ -s "$ARCHIVE" ] && printf yes || printf no)"
OUT="$ITEST_WORK/out"
OUT2="$ITEST_WORK/out2"
/bin/mkdir -p "$OUT" "$OUT2"
file_count() { /usr/bin/find "$@" -type f | /usr/bin/wc -l | /usr/bin/tr -d ' '; }

section "A launch with no document asks for one; a cancel opens nothing"
# The panel comes before the test can queue an answer, so it is the one a user dismisses. The
# engine then runs nothing (OMCCommandRunner: a canceled open panel is userCanceledErr), so no
# window opens. Zip.main.py's docstring says a canceled blank launch opens a new untitled archive,
# but its new_archive() branch needs the main command to run with no object, and with
# act_file_or_folder and OPEN_OBJECT_DIALOG it never does through the menu or a launch.
check "the launch showed the main command's open panel" "Choose a zip archive to open" "$(itest_panel 1 message)"
check "for zip archives" "public.zip-archive com.pkware.zip-archive" "$(itest_panel 1 allowedContentTypes | /usr/bin/tr '\n' ' ' | /usr/bin/sed 's/ $//')"
check "canceled, as no answer was queued" "true" "$(itest_panel 1 canceled)"
check "and no window opened" "0" "$(itest_windows | /usr/bin/grep -c .)"

section "The main command opens an archive"
itest_panels_clear
before="$(itest_windows)"
itest_run Zip --file "$ARCHIVE" > /dev/null
itest_wait_idle 60
window="$(itest_new_window "$before")"
check "a document window opened" "yes" "$([ -n "$window" ] && printf yes || printf no)"
# Four entries: src/, src/a.txt, src/docs/ and src/docs/b.txt (folders are entries of their own).
check "the status names the archive and counts its entries" "Opened sample.zip - 4 entries" "$(itest_value "$window" "$ID_STATUS")"
check "no panel: the file came with the command" "0" "$(itest_panel_count)"

section "Extract All into the folder the user chooses"
itest_answer_open "$OUT"
check "the button fires Zip.extract.all" "Zip.extract.all" "$(itest_click "$window" "$ID_EXTRACT_ALL_BTN")"
itest_wait_idle 60
check "a folder chooser was asked for" "open" "$(itest_panel last kind)"
check "for folders only" "true false" "$(itest_panel last canChooseDirectories) $(itest_panel last canChooseFiles)"
check "with the command's message" "Choose where to extract the whole archive" "$(itest_panel last message)"
check "and its own identifier" "Zip.extract.location" "$(itest_panel last identifier)"
check "both files were extracted" "2" "$(file_count "$OUT")"
check "a.txt came out whole" "alpha" "$(/bin/cat "$OUT/sample/src/a.txt" 2>/dev/null)"
check "the status reports where" "Extracted 2 items to $OUT/sample" "$(itest_value "$window" "$ID_STATUS")"

section "A second Extract All asks again"
# USE_PATH_CACHING keeps a chosen path for the subcommands of one run, not across runs.
itest_answer_open "$OUT2"
itest_click "$window" "$ID_EXTRACT_ALL_BTN" > /dev/null
itest_wait_idle 60
check "the chooser was shown again" "2" "$(itest_panel_count)"
check "and the archive went to the new folder" "2" "$(file_count "$OUT2")"
check "the status follows" "Extracted 2 items to $OUT2/sample" "$(itest_value "$window" "$ID_STATUS")"

section "Canceling the chooser extracts nothing"
itest_answer_cancel
itest_click "$window" "$ID_EXTRACT_ALL_BTN" > /dev/null
itest_wait_idle 60
check "the chooser was canceled" "true" "$(itest_panel last canceled)"
check "no files were added anywhere" "4" "$(file_count "$OUT" "$OUT2")"
check "and the status still reports the last extraction" "Extracted 2 items to $OUT2/sample" "$(itest_value "$window" "$ID_STATUS")"
