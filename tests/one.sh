#!/bin/bash
# Run one AutoIt file with a given interpreter.
#   bash one.sh <interpreter> <script.au3> [args...]
#
# MSYS_NO_PATHCONV is exported here and the switch is written with ONE slash. Both matter and
# both were measured: with the conversion on, "//ErrorStdOut" survives as a path-looking argument
# and AutoIt tries to open a script named "\\ErrorStdOut" -- a modal "AutoIt Error" dialog, rc 1
# and zero bytes of output, which looks exactly like a script that crashed on load. With the
# conversion off, a single "/ErrorStdOut" would be rewritten to a Git Bash path instead.
#
# The capture file carries the caller's pid, because tests/gate.sh runs three of these at the
# same time and a shared tmp file mixes their output.
export MSYS_NO_PATHCONV=1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 9
AI="$1"
SCR="$2"
shift 2
cd "$ROOT" || exit 9
TMP="tmp_one_$$.out"
"$AI" /ErrorStdOut "$SCR" "$@" > "$TMP" 2>&1
echo "rc=$?"
tr -d '\r' < "$TMP"
rm -f "$TMP"
