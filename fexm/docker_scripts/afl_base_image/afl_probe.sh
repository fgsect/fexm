#!/usr/bin/env bash
# ************************************
# Vincent Ulitzsch:
# I modified the afl-cmin script, such that
# it only returns the number of tuples find, not which
# files they use ( we are only interested in the coverage, for now).
# Also afl-cmin is now parallelized.
# ************************************

# american fuzzy lop - corpus minimization tool
# ---------------------------------------------
#
# Written and maintained by Michal Zalewski <lcamtuf@google.com>
#
# Copyright 2014, 2015 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# This tool tries to find the smallest subset of files in the input directory
# that still trigger the full range of instrumentation data points seen in
# the starting corpus. This has two uses:
#
#   - Screening large corpora of input files before using them as a seed for
#     afl-fuzz. The tool will remove functionally redundant files and likely
#     leave you with a much smaller set.
#
#     (In this case, you probably also want to consider running afl-tmin on
#     the individual files later on to reduce their size.)
#
#   - Minimizing the corpus generated organically by afl-fuzz, perhaps when
#     planning to feed it to more resource-intensive tools. The tool achieves
#     this by removing all entries that used to trigger unique behaviors in the
#     past, but have been made obsolete by later finds.
#
# Note that the tool doesn't modify the files themselves. For that, you want
# afl-tmin.
#
# This script must use bash because other shells may have hardcoded limits on
# array sizes.
AFL_PATH="/usr/local/bin"
echo "corpus minimization tool for afl-fuzz by <lcamtuf@google.com>"
echo

#########
# SETUP #
#########

# Process command-line options...

MEM_LIMIT=100
TIMEOUT=none

unset IN_DIR OUT_DIR STDIN_FILE EXTRA_PAR MEM_LIMIT_GIVEN \
  AFL_CMIN_CRASHES_ONLY AFL_CMIN_ALLOW_ANY QEMU_MODE

OUT_DIR="tmp/"

while getopts "+i:o:f:m:t:eQC" opt; do

  case "$opt" in

    "i")
         IN_DIR="$OPTARG"
         ;;
    "o")
         OUT_DIR="$OPTARG"
         ;;
    "f")
         STDIN_FILE="$OPTARG"
         ;;
    "m")
         MEM_LIMIT="$OPTARG"
         MEM_LIMIT_GIVEN=1
         ;;
    "t")
         TIMEOUT="$OPTARG"
         ;;
    "e")
         EXTRA_PAR="$EXTRA_PAR -e"
         ;;
    "C")
         export AFL_CMIN_CRASHES_ONLY=1
         ;;
    "Q")
         EXTRA_PAR="$EXTRA_PAR -Q"
         test "$MEM_LIMIT_GIVEN" = "" && MEM_LIMIT=250
         QEMU_MODE=1
         ;;
    "?")
         exit 1
         ;;

   esac

done

shift $((OPTIND-1))

TARGET_BIN="$1"

if [ "$TARGET_BIN" = "" -o "$IN_DIR" = "" -o "$OUT_DIR" = "" ]; then

  cat 1>&2 <<_EOF_
Usage: $0 [ options ] -- /path/to/target_app [ ... ]
Required parameters:
  -i dir        - input directory with the starting corpus
Execution control settings:
  -f file       - location read by the fuzzed program (stdin)
  -m megs       - memory limit for child process ($MEM_LIMIT MB)
  -t msec       - run time limit for child process (none)
  -Q            - use binary-only instrumentation (QEMU mode)
Minimization settings:
  -C            - keep crashing inputs, reject everything else
  -e            - solve for edge coverage only, ignore hit counts
For additional tips, please consult docs/README.
_EOF_
  exit 1
fi

# Do a sanity check to discourage the use of /tmp, since we can't really
# handle this safely from a shell script.

if [ "$AFL_ALLOW_TMP" = "" ]; then

  echo "$IN_DIR" | grep -qE '^(/var)?/tmp/'
  T1="$?"

  echo "$TARGET_BIN" | grep -qE '^(/var)?/tmp/'
  T2="$?"

  echo "$OUT_DIR" | grep -qE '^(/var)?/tmp/'
  T3="$?"

  echo "$STDIN_FILE" | grep -qE '^(/var)?/tmp/'
  T4="$?"

  echo "$PWD" | grep -qE '^(/var)?/tmp/'
  T5="$?"

  if [ "$T1" = "0" -o "$T2" = "0" -o "$T3" = "0" -o "$T4" = "0" -o "$T5" = "0" ]; then
    echo "[-] Error: do not use this script in /tmp or /var/tmp." 1>&2
    exit 1
  fi

fi

# If @@ is specified, but there's no -f, let's come up with a temporary input
# file name.

TRACE_DIR="$OUT_DIR/.traces"

if [ "$STDIN_FILE" = "" ]; then

  if echo "$*" | grep -qF '@@'; then
    STDIN_FILE="$TRACE_DIR/.cur_input"
  fi

fi

# Check for obvious errors.

if [ ! "$MEM_LIMIT" = "none" ]; then

  if [ "$MEM_LIMIT" -lt "5" ]; then
    echo "[-] Error: dangerously low memory limit." 1>&2
    exit 1
  fi

fi

if [ ! "$TIMEOUT" = "none" ]; then

  if [ "$TIMEOUT" -lt "10" ]; then
    echo "[-] Error: dangerously low timeout." 1>&2
    exit 1
  fi

fi

if [ ! -f "$TARGET_BIN" -o ! -x "$TARGET_BIN" ]; then

  TNEW="`which "$TARGET_BIN" 2>/dev/null`"

  if [ ! -f "$TNEW" -o ! -x "$TNEW" ]; then
    echo "[-] Error: binary '$TARGET_BIN' not found or not executable." 1>&2
    exit 1
  fi

  TARGET_BIN="$TNEW"

fi

if [ "$AFL_SKIP_BIN_CHECK" = "" -a "$QEMU_MODE" = "" ]; then

  if ! grep -qF "__AFL_SHM_ID" "$TARGET_BIN"; then
    echo "[-] Error: binary '$TARGET_BIN' doesn't appear to be instrumented." 1>&2
    exit 1
  fi

fi

if [ ! -d "$IN_DIR" ]; then
  echo "[-] Error: directory '$IN_DIR' not found." 1>&2
  exit 1
fi

test -d "$IN_DIR/queue" && IN_DIR="$IN_DIR/queue"

find "$OUT_DIR" -name 'id[:_]*' -maxdepth 1 -exec rm -- {} \; 2>/dev/null
rm -rf "$TRACE_DIR" 2>/dev/null

rmdir "$OUT_DIR" 2>/dev/null

if [ -d "$OUT_DIR" ]; then
  echo "[-] Error: directory '$OUT_DIR' exists and is not empty - delete it first." 1>&2
  exit 1
fi

mkdir -m 700 -p "$TRACE_DIR" || exit 1

if [ ! "$STDIN_FILE" = "" ]; then
  rm -f "$STDIN_FILE" || exit 1
  touch "$STDIN_FILE" || exit 1
fi

if [ "$AFL_PATH" = "" ]; then
  SHOWMAP="${0%/afl-cmin}/afl-showmap"
else
  SHOWMAP="$AFL_PATH/afl-showmap"
fi

if [ ! -x "$SHOWMAP" ]; then
  echo "[-] Error: can't find 'afl-showmap' - please set AFL_PATH." 1>&2
  rm -rf "$TRACE_DIR"
  exit 1
fi

IN_COUNT=$((`ls -- "$IN_DIR" 2>/dev/null | wc -l`))

if [ "$IN_COUNT" = "0" ]; then
  echo "[+] Hmm, no inputs in the target directory. Nothing to be done."
  rm -rf "$TRACE_DIR"
  exit 1
fi

FIRST_FILE=`ls "$IN_DIR" | head -1`

# Make sure that we're not dealing with a directory.

if [ -d "$IN_DIR/$FIRST_FILE" ]; then
  echo "[-] Error: The target directory contains subdirectories - please fix." 1>&2
  rm -rf "$TRACE_DIR"
  exit 1
fi

# Check for the more efficient way to copy files...

if ln "$IN_DIR/$FIRST_FILE" "$TRACE_DIR/.link_test" 2>/dev/null; then
  CP_TOOL=ln
else
  CP_TOOL=cp
fi

# Make sure that we can actually get anything out of afl-showmap before we
# waste too much time.

echo "[*] Testing the target binary..."

if [ "$STDIN_FILE" = "" ]; then

  AFL_CMIN_ALLOW_ANY=1 "$SHOWMAP" -m "$MEM_LIMIT" -t "$TIMEOUT" -o "$TRACE_DIR/.run_test" -Z $EXTRA_PAR -- "$@" <"$IN_DIR/$FIRST_FILE"

else

  cp "$IN_DIR/$FIRST_FILE" "$STDIN_FILE"
  AFL_CMIN_ALLOW_ANY=1 "$SHOWMAP" -m "$MEM_LIMIT" -t "$TIMEOUT" -o "$TRACE_DIR/.run_test" -Z $EXTRA_PAR -A "$STDIN_FILE" -- "$@" </dev/null

fi

#VINCENT ULITZSCH: I patched this step, because it aborts the execution if the randomly chosen file leads to a timeout.
#FIRST_COUNT=$((`grep -c . "$TRACE_DIR/.run_test"`))


# if [ "$FIRST_COUNT" -gt "0" ]; then
#
#  echo "[+] OK, $FIRST_COUNT tuples recorded."
#
#else

# echo "[-] Error: no instrumentation output detected (perhaps crash or timeout)." 1>&2
#  test "$AFL_KEEP_TRACES" = "" && rm -rf "$TRACE_DIR"
#  exit 1

#fi

# Let's roll!

#############################
# STEP 1: COLLECTING TRACES #
#############################
sample_files=$(ls "$IN_DIR" |sort -R |tail -5)
array=($sample_files)
for element in "${array[@]}"
do
    echo "$element"
done
echo "[*] Obtaining traces for input files in '$IN_DIR'..."


  CUR=0

  if [ "$STDIN_FILE" = "" ]; then

    for fn in "${array[@]}"
    do
      CUR=$((CUR+1))
      printf "\\r    Processing file $CUR/$IN_COUNT... "

      "$SHOWMAP" -m "$MEM_LIMIT" -t "$TIMEOUT" -o "$TRACE_DIR/$fn" -Z $EXTRA_PAR -- "$@" <"$IN_DIR/$fn"

    done
    # done < <(ls "$IN_DIR")

  else

    for fn in "${array[@]}"
    do
     CUR=$((CUR+1))
      printf "\\r    Processing file $CUR/$IN_COUNT... "

      cp "$IN_DIR/$fn" "$STDIN_FILE"

      "$SHOWMAP" -m "$MEM_LIMIT" -t "$TIMEOUT" -o "$TRACE_DIR/$fn" -Z $EXTRA_PAR -A "$STDIN_FILE" -- "$@" </dev/null

    done
  fi


#find "$IN_DIR" -maxdepth 1 -type f -print0 | parallel -0 "$SHOWMAP" -m "$MEM_LIMIT" -t "$TIMEOUT" \
#-o "$TRACE_DIR"/{/} -Z $EXTRA_PAR -A {} -- "$@"

echo

##########################
# STEP 2: SORTING TUPLES #
##########################

# With this out of the way, we sort all tuples by popularity across all
# datasets. The reasoning here is that we won't be able to avoid the files
# that trigger unique tuples anyway, so we will want to start with them and
# see what's left.

echo "[*] Sorting trace sets (this may take a while)..."

#ls "$IN_DIR" | sed "s#^#$TRACE_DIR/#" | tr '\n' '\0' | xargs -0 -n 1 cat | \
#  sort | uniq -c | sort -n >"$TRACE_DIR/.all_uniq"
echo "$sample_files" | sed "s#^#$TRACE_DIR/#" | tr '\n' '\0' | xargs -0 -n 1 cat | uniq -c >"$TRACE_DIR/.all_uniq"

#find "$IN_DIR" -maxdepth 1 -type f -print0 | parallel -0 cat "$TRACE_DIR"/{/} | sort | uniq -c | sort -n >"$TRACE_DIR/.all_uniq"

TUPLE_COUNT=$((`grep -c . "$TRACE_DIR/.all_uniq"`))

rm -rf "$TRACE_DIR"
echo "[+] Found $TUPLE_COUNT unique tuples across $CUR files."