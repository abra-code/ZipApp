#!/bin/sh
# Tests/20-progress.test.sh - the feedback a long operation owes the user, and
# the outcome an add reports when the zip tool only half succeeds.
#
# Both come from the same report: compressing a 4.1 GB folder ran for minutes
# with the window showing "No archive open" and an unchanged status line, and
# then said "Could not add the selected items" - a message that names no cause
# and, worse, was printed for runs where the archive had in fact been written.
#
# What is pinned here: that the applet says what it is doing before it starts,
# that it drives the status-row progress bar while it works and retires it
# afterwards, and that an add whose zip tool exits non-zero is judged by what
# reached the archive rather than by the exit code.
#
# Not covered: how any of it LOOKS. The harness records what was pushed toward
# the window, not what was drawn.
#
# POSIX sh only. Validate with "sh -n", never "bash -n".
. "${OMCTEST_LIB:?set OMCTEST_LIB, or run via: appletbuilder test}"
. "$OMCTEST_TESTS/lib.test.zip.sh"

section "1. opening an archive says so before it reads it"
reset_document
ui_reset
sample="$(make_sample_zip Feedback.zip)"
omc_object "$sample"
omc_run Zip.main
check_status "the handler succeeded"       0
# The status line ends on the summary, so the "Opening" message is only visible
# in the journal of what was pushed - which is the point: it has to be pushed
# BEFORE the read, or the window sits blank through it. The positive control for
# this check is the summary assertion below: both read the same journal.
check "it announced the open first"        "1" "$(ui_calls "Opening Feedback.zip")"
check "and the summary replaced it"        "Opened Feedback.zip - 5 entries" \
                                           "$(ui_value $ID_STATUS)"
# One pass over the archive now answers all three questions - contents, count,
# encryption - where opening used to read the whole central directory three
# times and then parse the model back a fourth time to count its rows.
check "the entry count was cached"         "5"     "$(pb_get count)"
check "and so was the encryption state"    "plain" "$(enc_state)"
check "the bar was raised for the read"    "1"     "$(ui_calls "\b$ID_PROGRESS_BAR.omc_show")"
check "and retired when it finished"       "0"     "$(ui_visible $ID_PROGRESS_BAR)"

section "2. a file that is not an archive costs one failed read, not a probe"
reset_document
ui_reset
not_an_archive="$OMCTEST_WORK/notes.txt"
printf 'not a zip\n' > "$not_an_archive"
omc_object "$not_an_archive"
omc_run Zip.main
check_status "the handler succeeded"       0
check "it was not adopted as the document" ""    "$(original)"
check "it went into a new archive"         "yes" "$(zip_has "$(work)" notes.txt)"
# load_archive IS the "is it a zip?" test now. Having answered no, it must leave
# no trace of the document it was about to open - a stale original would make
# the next Save write over the file the user only dropped in, and a stale title
# would name it as the document.
# The leading dirty marker is stripped rather than spelled here: it is a
# non-ASCII glyph, and what this check is about is the NAME, which must be the
# new untitled archive and not the file that was dropped in.
check "the window is not named after it"   "Untitled.zip" \
    "$(ui_title | /usr/bin/sed 's/^[^A-Za-z]*//')"
check "and no count survived the attempt"  "1"   "$(pb_get count)"
check "and the bar is down"                "0"   "$(ui_visible $ID_PROGRESS_BAR)"

section "3. compressing a folder drives the bar and puts it away"
reset_document
ui_reset
tree="$(make_source_tree Sources)"
omc_object "$tree"
omc_run Zip.main
check_status "the handler succeeded"       0
check "the folder is in the archive"       "yes" "$(zip_has "$(work)" Sources/a.txt)"
check "including its nested member"        "yes" "$(zip_has "$(work)" Sources/sub/b.txt)"
check "dirty from the start"               "1"   "$(dirty)"
# The two phases the user waits through. Both report; neither used to.
check "it reported staging progress"       "1"   "$(ui_calls "Preparing.*items")"
check "and compression progress"           "1"   "$(ui_calls "Compressing.*items")"
# The half of the message that changes width lives in its own label to the RIGHT
# of the indicator, so nothing that grows can move the bar. Everything to the
# bar's left is one fixed string per phase.
# Twice, once per phase: this fixture is small enough that each phase reports
# only its closing line. Two rather than one is also what says the compression
# phase reported at all.
check "the changing half is kept apart"    "2"   "$(ui_calls "\b$ID_PROGRESS_DETAIL.100%")"
check "and cleared when the work ends"     ""    "$(ui_value $ID_PROGRESS_DETAIL)"
# Filled once per counted phase: this fixture is far below ADD_PROGRESS_EVERY,
# so each phase reports only its closing line. Two rather than one is the
# assertion that matters - on a percentage-only throttle the compression phase
# pushed nothing, because staging had already left the counter at 100. Matched
# on the FULL value, so the zeroes every raise of the bar writes cannot stand in
# for a phase that never reported.
check "the bar filled once per phase"      "2"   "$(ui_calls "$ID_PROGRESS_BAR.omc_set_state progress 1[.]0")"
check "and it is down at the end"          "0"   "$(ui_visible $ID_PROGRESS_BAR)"
check "with the closing status"            "New archive from Sources - Save to keep it." \
                                           "$(ui_value $ID_STATUS)"

section "4. an add the zip tool half completes keeps what landed"
reset_document
ui_reset
alerts_reset
alert_answers_reset
alert_answer 0
partial_tree="$(make_source_tree Partial unreadable)"
omc_object "$partial_tree"
omc_run Zip.main
check_status "the handler succeeded"       0
# Info-ZIP exits non-zero because it cannot open locked.txt, having stored
# everything else. The old code read that exit code alone and threw the whole
# add away with "Could not add the selected items", which was false twice over:
# the items were added, and it named no cause.
check "the readable members are stored"    "yes" "$(zip_has "$(work)" Partial/a.txt)"
check "and the nested one too"             "yes" "$(zip_has "$(work)" Partial/sub/b.txt)"
check "the unreadable one is not"          "no"  "$(zip_has "$(work)" Partial/locked.txt)"
# The document changed, so it must be dirty - scoring this as a failure skipped
# mark_dirty and let a close discard a mutation that had really happened.
check "the document is dirty"              "1"   "$(dirty)"
check "the user was told"                  "1"   "$(alerts_mention 'could not be added')"
check "and the bar is down"                "0"   "$(ui_visible $ID_PROGRESS_BAR)"
# Positive control for the negative check above: the same helper on the same
# archive answers "yes" for a member that IS there, so "no" cannot be an
# unreadable archive answering everything the same way.
check "control: the archive is readable"   "2"   "$(zip_count "$(work)")"
/bin/chmod 644 "$partial_tree/locked.txt"

section "5. the facts regenerate_model reads back, called directly"
# ziptool reports the count and the encryption on stderr beside the model it
# writes, so the applet gets both without a second pass over the archive.
check "count and encryption are read"      "(3, 'plain')" \
    "$(zip_eval '_model_facts(ARGV[0].encode())' 'entries 3
encryption plain')"
check "an encrypted archive is seen"       "(7, 'encrypted')" \
    "$(zip_eval '_model_facts(ARGV[0].encode())' 'entries 7
encryption encrypted')"
# Last answer wins, and only a whole line counts - the same rule
# _added_under_other_names follows, and for the same reason: an entry NAME can
# reach stderr, and a name is allowed to look like anything.
check "the last report wins"               "(9, 'plain')" \
    "$(zip_eval '_model_facts(ARGV[0].encode())' 'entries 1
encryption encrypted
entries 9
encryption plain')"
check "a line that merely contains one does not" "(None, 'plain')" \
    "$(zip_eval '_model_facts(ARGV[0].encode())' 'stored as: entries 4
about encryption encrypted')"

section "6. an update the zip tool could not read is never called stored"
reset_document
ui_reset
alerts_reset
alert_answers_reset
upd_tree="$(make_source_tree Updated)"
omc_object "$upd_tree"
omc_run Zip.main
check "the first add stored the content"  "one" "$(zip_content "$(work)" Updated/a.txt)"
# Replace that file with different content the zip tool cannot read, and add the
# folder again - an UPDATE of an entry the archive already holds.
printf 'replacement\n' > "$upd_tree/a.txt"
/bin/chmod 000 "$upd_tree/a.txt"
alerts_reset
alert_answer 0
omc_dialog_answer choose_object "$upd_tree"
omc_run Zip.add.files
/bin/chmod 644 "$upd_tree/a.txt"
check_status "the handler succeeded"      0
# Info-ZIP keeps the existing entry and rewrites its header to the NEW size, so
# the listing is indistinguishable from a real update - the name is there and
# the size is right, and only the bytes disagree. Verifying by name (and even by
# size) called this a complete add and said nothing. zip's own "will just copy
# entry over" is the evidence, and this is the check that it is being read.
check "the old bytes are still in there"  "one" "$(zip_content "$(work)" Updated/a.txt)"
check "so the user is told, not thanked"  "1"   "$(alerts_mention 'could not be added')"
# Positive control: the same archive, the same helper, an entry that WAS written.
check "control: the other member is fine" "two" "$(zip_content "$(work)" Updated/sub/b.txt)"

section "7. previewing a row reads that one entry, and says it is working"
reset_document
ui_reset
preview_sample="$(make_sample_zip Previewed.zip)"
omc_object "$preview_sample"
omc_run Zip.main
# Only the SELECTION's writes are in question here, and opening the document
# clears the pane once itself (clear_inspector, as it populates the table).
ui_reset
feed_row_to Zip.selection.changed "top.txt" "10 B" "" "top.txt" "0" "0"
check_status "the handler succeeded"       0
# Pulling one entry out of a large archive is seconds of work, and the pane
# showed the PREVIOUS selection throughout - a click that read as nothing
# happening until it suddenly did.
# Cleared before the read, not after it: the pane used to keep showing the
# previous selection for the whole two seconds, beside the new row's name and
# size in the inspector. The write carries no argument, which is what the
# trailing-space match below is.
check "the pane was cleared first"         "1" "$(ui_calls "\b$ID_PREVIEW. *$")"
check "the busy indicator was raised"      "1" "$(ui_calls "\b$ID_PREVIEW_BUSY.omc_show")"
check "and lowered again afterwards"       "0" "$(ui_visible $ID_PREVIEW_BUSY)"
previewed="$(ui_value $ID_PREVIEW)"
# The extension has to survive: it is what QuickLook picks a renderer by.
check "the preview kept the extension"     "top.txt" "$(/usr/bin/basename "$previewed")"
check "it holds the entry's own bytes"     "top level" "$(/bin/cat "$previewed")"
check "and sits inside the document dir"   "yes" "$(path_is_inside "$(preview_dir)" "$previewed")"
# The name is ours, built from the basename alone, so no part of an archive path
# can steer where the bytes land.
check "a path cannot escape the dir"       "evil.txt" \
    "$(zip_eval '_preview_filename(ARGV[0])' '../../evil.txt')"
check "a newline in a name is folded"      "a_b.txt" \
    "$(zip_eval '_preview_filename(ARGV[0])' 'a
b.txt')"
check "a name that folds away still names something" "preview" \
    "$(zip_eval '_preview_filename(ARGV[0])' '..')"

section "8. narrowing on raw bytes must not lose a non-ASCII match"
# level and find filter the cached model on its RAW BYTES and decode only what
# survives - that is what makes navigating a six-figure archive quick. The
# shortcut is exact only for ASCII: bytes.lower() folds A-Z and nothing else, so
# a lowercase query for an accented name matches once decoded and does NOT match
# as bytes. Getting that wrong drops real hits from the search with no sign.
reset_document
ui_reset
unicode_zip="$(make_unicode_zip)"
omc_object "$unicode_zip"
omc_run Zip.main
check_status "the handler succeeded"       0
# Positive control, and the path the fast test really does take.
fire_filter "readme"
check "an ASCII name still matches"        "1" "$(ui_row_count $ID_TABLE)"
# The case that must survive the shortcut: a LOWERCASE needle carrying the same
# accents as the stored name. Decoded, "RESUME.txt" with acutes lowercases to
# match it; as raw bytes it does not, because bytes.lower() leaves the accented
# characters alone. Not "resum" without accents - substring matching has never
# been accent-insensitive, and expecting that of it was my own mistake.
#
# The needles are built with printf escapes rather than written as literals, so
# this file stays ASCII while the bytes on the wire are the UTF-8 ones.
fire_filter "$(printf 'r\303\251sum\303\251')"
check "a lowercase accented needle hits"   "1" "$(ui_row_count $ID_TABLE)"
fire_filter "$(printf 'R\303\211SUM\303\211')"
check "and so does its own spelling"       "1" "$(ui_row_count $ID_TABLE)"
fire_filter "zzz"
check "control: a real miss is still a miss" "0" "$(ui_row_count $ID_TABLE)"

section "cumulative: the window never wrote to a view id it does not declare"
check "no undeclared ids"                  ""    "$(ui_unknown_writes)"
check "no bare value clobbered a table"    ""    "$(ui_suspect_writes)"
check "no malformed omc_dialog_control calls" "" "$(ui_errors)"

omctest_end
