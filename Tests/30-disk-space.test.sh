#!/bin/sh
# Tests/30-disk-space.test.sh - the disk-space preflight in front of compressing
# and saving.
#
# Compressing does not free space, it consumes it: the archive is written in
# full before anything is deleted, and Info-ZIP rewrites through a temp file
# beside it, so the volume briefly holds a second copy. Doing that on a Mac
# already close to full is a system problem rather than a Zip problem, and the
# applet has no business being the thing that tips it over without saying so.
#
# The headroom is read from $ZIP_DISK_HEADROOM_GB precisely so these checks do
# not depend on how full the machine running them happens to be. A test cannot
# free gigabytes; it can move the bar.
#
# POSIX sh only. Validate with "sh -n", never "bash -n".
. "${OMCTEST_LIB:?set OMCTEST_LIB, or run via: appletbuilder test}"
. "$OMCTEST_TESTS/lib.test.zip.sh"

section "1. no headroom asked for, no question raised"
reset_document
alerts_reset
alert_answers_reset
omctest_setvar ZIP_DISK_HEADROOM_GB 0
tree="$(make_source_tree Roomy)"
omc_object "$tree"
omc_run Zip.main
check_status "the handler succeeded"       0
check "it compressed without asking"       "yes" "$(zip_has "$(work)" Roomy/a.txt)"
check "and raised no alert at all"         "0"   "$(alerts_count)"

section "2. a headroom nothing can satisfy stops before writing anything"
reset_document
alerts_reset
alert_answers_reset
alert_answer 1                             # Cancel
# A terabyte of headroom: no machine this runs on can satisfy it, so the answer
# does not depend on the disk, only on the applet asking.
omctest_setvar ZIP_DISK_HEADROOM_GB 1048576
tight="$(make_source_tree Tight)"
omc_object "$tight"
omc_run Zip.main
check_status "the handler succeeded"       0
check "the user was asked"                 "1" "$(alerts_mention 'too full for macOS')"
check "the numbers were shown"             "1" "$(alerts_mention 'Free space now')"
# The document exists and is empty: new_archive made the working copy, and the
# refusal came before anything was put in it.
check "nothing was compressed"             "0"  "$(zip_count "$(work)")"
check "so the document is not dirty"       ""   "$(dirty)"
check "and the status says why"            "Compression canceled - not enough free space." \
                                           "$(ui_value $ID_STATUS)"
check "the bar was retired"                "0"  "$(ui_visible $ID_PROGRESS_BAR)"

section "3. the same question answered Compress Anyway goes ahead"
reset_document
alerts_reset
alert_answers_reset
alert_answer 0                             # Compress Anyway
omctest_setvar ZIP_DISK_HEADROOM_GB 1048576
anyway="$(make_source_tree Anyway)"
omc_object "$anyway"
omc_run Zip.main
check_status "the handler succeeded"       0
check "it still asked first"               "1"   "$(alerts_mention 'too full for macOS')"
# The retry runs the add again with the check off. This is the check that the
# override is a real second run and not a message the applet shows before
# giving up anyway.
check "and then compressed"                "yes" "$(zip_has "$(work)" Anyway/a.txt)"
check "including the nested member"        "yes" "$(zip_has "$(work)" Anyway/sub/b.txt)"
check "the document is dirty"              "1"   "$(dirty)"
check "and the bar was retired"            "0"   "$(ui_visible $ID_PROGRESS_BAR)"
omctest_setvar ZIP_DISK_HEADROOM_GB 0

section "4. the save check is exact, not an estimate"
# Compressing judges the sources' UNCOMPRESSED size, because the archive's real
# size is not known until it is written. Saving has the file in hand, so the
# number is the one being written - and _atomic_copy writes a temp beside the
# destination first, so the volume needs a second copy of it.
saveable="$(make_source_tree Saveable)"
reset_document
alerts_reset
alert_answers_reset
omctest_setvar ZIP_DISK_HEADROOM_GB 0
omc_object "$saveable"
omc_run Zip.main
check "there is something to save"         "1"   "$(dirty)"
# A terabyte of headroom again, and Cancel: the write must not happen.
omctest_setvar ZIP_DISK_HEADROOM_GB 1048576
alerts_reset
alert_answers_reset
alert_answer 1
dest="$OMCTEST_WORK/Saveable.zip"
omc_dialog_answer save_as "$dest"
omc_run Zip.save.as
check_status "the handler succeeded"       0
check "the user was asked"                 "1"  "$(alerts_mention 'very little free space')"
# No check_missing in the harness; ask the filesystem directly. The positive
# control is the Save Anyway pass below, which asserts the same path DOES exist.
check "and nothing was written"            "no" "$([ -e "$dest" ] && echo yes || echo no)"
check "the document is still dirty"        "1"  "$(dirty)"
# Answering Save Anyway writes it, which is the positive control for the check
# above: without it, "nothing was written" would also pass on a save that can
# never work.
alerts_reset
alert_answers_reset
alert_answer 0
omc_dialog_answer save_as "$dest"
omc_run Zip.save.as
check "it asked again"                     "1"   "$(alerts_mention 'very little free space')"
check_exists "and then wrote the archive"  "$dest"
check "which holds the folder"             "yes" "$(zip_has "$dest" Saveable/a.txt)"
check "and the document is clean"          ""    "$(dirty)"
omctest_setvar ZIP_DISK_HEADROOM_GB 0

section "5. what the preflight counts, asked of ziptool directly"
# The applet-level sections above prove the question gets asked. This one is
# about the NUMBER, which they cannot see: the peak an add really needs is more
# than the sources.
space_tree="$(make_source_tree Counted)"
space_archive="$OMCTEST_WORK/counted.zip"
/bin/rm -f "$space_archive"
# 8192 bytes of archive standing in for a large existing one.
/usr/bin/python3 -c "open('$space_archive','wb').write(b'PK\x05\x06' + b'\0' * 8189)"
# Info-ZIP rewrites an archive through a temp file beside it, so the volume
# holds the new archive AND the old one at once. Counting only the sources let
# a one-byte addition to a 40 GB archive pass a check that the rewrite then
# blew straight through.
check "the existing archive is counted" "yes" \
    "$(ziptool_eval 'str(sum(n for _p, n in _space_requirements(ARGV[0], 1000, [ARGV[1]]).values()) >= 1000 + 8192).lower().replace("true","yes").replace("false","no")' \
        "$space_archive" "$space_tree")"
# Positive control for the line above: with no archive on disk there is nothing
# to rewrite, so the requirement is the sources alone. If the check above passed
# because the helper always returns something large, this one fails.
/bin/rm -f "$space_archive"
check "and nothing extra when there is none" "yes" \
    "$(ziptool_eval 'str(sum(n for _p, n in _space_requirements(ARGV[0], 1000, [ARGV[1]]).values()) == 1000).lower().replace("true","yes").replace("false","no")' \
        "$space_archive" "$space_tree")"
# Same-volume sources hardlink into staging and cost nothing there; only a
# cross-device add has to copy them. Asked about the real staging dir, which is
# the volume the applet would actually use.
check "same-volume sources cost no staging" "no" \
    "$(ziptool_eval 'str(_sources_cross_device(ARGV[0], [ARGV[1]])).lower().replace("true","yes").replace("false","no")' \
        "$OMCTEST_WORK" "$space_tree")"
# A headroom of 0 disables the check whatever the numbers say.
check "headroom 0 disables it"          "" \
    "$(ziptool_eval '_space_shortfall(ARGV[0], 10**15, [ARGV[1]], 0)' "$space_archive" "$space_tree")"

section "cumulative: the window never wrote to a view id it does not declare"
check "no undeclared ids"                     ""  "$(ui_unknown_writes)"
check "no bare value clobbered a table"       ""  "$(ui_suspect_writes)"
check "no malformed omc_dialog_control calls" ""  "$(ui_errors)"

omctest_end
