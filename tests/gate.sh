#!/bin/bash
# =============================================================================
# tests/gate.sh -- the whole Pulse gate, both bitnesses, live sockets included.
#
#   bash tests/gate.sh
#
# Three kinds of entry:
#   static   Au3Check on every shipped .au3 (the checker is a single binary)
#   unit     --auto self tests and the five-UDF coexistence probe, x86 and x64
#   live     the console as its own process, two demo agents as two more, and a
#            read of what actually arrived
#
# AutoIt is never started from inside AutoIt here: measured on this machine, a
# Run() of one .au3 from another produced a process that never executed. Every
# process in the live section is a direct child of this shell.
#
# The verdict is the file tests/out/gate_summary.txt: one line per entry,
#   [rc=0] PASS <label>   or   [rc=1] FAIL <label>
# and a final DONE_GATE line. Read that file; do not judge the run by the exit
# code of a background job.
# =============================================================================
AI86="${AI86:-C:/Program Files (x86)/AutoIt3/AutoIt3.exe}"
AI64="${AI64:-}"
if [ -z "$AI64" ]; then
	if [ -f "${AI86%/*}/AutoIt3_x64.exe" ]; then
		AI64="${AI86%/*}/AutoIt3_x64.exe"
	elif command -v AutoIt3_x64.exe >/dev/null 2>&1; then
		AI64="$(command -v AutoIt3_x64.exe)"
	else
		echo "Set AI64 to the 64-bit AutoIt3_x64.exe path." >&2
		exit 9
	fi
fi
AU3CHECK="${AU3CHECK:-C:/Program Files (x86)/AutoIt3/Au3Check.exe}"
NODE_BIN="${NODE:-}"
if [ -z "$NODE_BIN" ] && command -v node >/dev/null 2>&1; then NODE_BIN="$(command -v node)"; fi
if [ -z "$NODE_BIN" ]; then
	for candidate in "${LOCALAPPDATA//\\//}/Programs/Qoder/Qoder.exe" "C:/Program Files/Qoder/Qoder.exe"; do
		if [ -f "$candidate" ]; then NODE_BIN="$candidate"; break; fi
	done
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 9
OUT="$ROOT/tests/out"
SUM="$OUT/gate_summary.txt"
# The agent's own connect budget, quoted in the comment below; named so the value
# in this file and the one in Pulse_Agent.au3 can be compared by eye.
MAX_MS=1200

cd "$ROOT" || exit 9
mkdir -p "$OUT"
: > "$SUM"
export MSYS_NO_PATHCONV=1

pass() { echo "[rc=0] PASS $1" >> "$SUM"; }
fail() { echo "[rc=1] FAIL $1" >> "$SUM"; }
# unit <label> <interpreter> <script> <args...> -- rc 0 AND the last RESULT line says fail=0
unit() {
	local label="$1" ai="$2" scr="$3"; shift 3
	local log="$OUT/${label}.log"
	bash tests/one.sh "$ai" "$scr" "$@" > "$log" 2>&1
	local rc=$?
	local res
	res=$(grep -a "^RESULT" "$log" | tr -d '\r' | tail -1)
	if [ "$rc" = "0" ] && echo "$res" | grep -q "fail=0"; then
		pass "$label ($res)"
	else
		fail "$label rc=$rc ${res:-no RESULT line}"
	fi
}

# --- static ------------------------------------------------------------------
for f in Pulse.au3 Pulse_Agent.au3 Pulse_Json.au3 Examples/demo_build.au3 Examples/demo_watch.au3 tests/coexist.au3; do
	if "$AU3CHECK" -w 1 "$f" > "$OUT/check_$(basename "$f").log" 2>&1; then
		pass "au3check $f"
	else
		fail "au3check $f (see $OUT/check_$(basename "$f").log)"
	fi
done
# The WebSocket umbrella is the only Lib file meant to be included directly; the
# four layers beside it are included by it and are not independently checkable.
for f in Lib/WebView2.au3 Lib/Tree.au3 Lib/CompoundFile.au3 Lib/WinEventManager.au3 Lib/WebSocket.au3; do
	if "$AU3CHECK" -w 1 "$f" > "$OUT/check_$(basename "$f").log" 2>&1; then
		pass "au3check $f"
	else
		fail "au3check $f (see $OUT/check_$(basename "$f").log)"
	fi
done

if [ -n "$NODE_BIN" ] && ELECTRON_RUN_AS_NODE=1 "$NODE_BIN" --check Web/app.js > "$OUT/check_web.log" 2>&1; then
	pass "web syntax"
else
	fail "web syntax (set NODE to a Node.js 18+ executable; see $OUT/check_web.log)"
fi
if [ -n "$NODE_BIN" ] && ELECTRON_RUN_AS_NODE=1 "$NODE_BIN" tests/web_test.js > "$OUT/web_dom.log" 2>&1; then
	pass "web_dom ($(grep -a '^RESULT' "$OUT/web_dom.log" | tr -d '\r' | tail -1))"
else
	fail "web_dom (see $OUT/web_dom.log)"
fi

# --- unit, both bitnesses ----------------------------------------------------
unit "console_x86"  "$AI86" Pulse.au3 --auto
unit "console_x64"  "$AI64" Pulse.au3 --auto
unit "agent_x86"    "$AI86" Pulse_Agent.au3 --auto
unit "agent_x64"    "$AI64" Pulse_Agent.au3 --auto
unit "coexist_x86"  "$AI86" tests/coexist.au3
unit "coexist_x64"  "$AI64" tests/coexist.au3

# --- live: console + two agents, three separate processes --------------------
# live_pair <label> <console interpreter> <agent interpreter> <port>
# The agents run on their own bitness so the third call can cross the two: an x86
# script feeding an x64 console is the case a developer actually hits.
live_pair() {
	local label="$1" ai_console="$2" ai_agent="$3" port="$4"
	local tag="${label}"
	rm -f "$OUT/${tag}_console.log" "$OUT/${tag}_build.log" "$OUT/${tag}_watch.log"

	bash tests/one.sh "$ai_console" Pulse.au3 --headless --port "$port" --seconds 16 > "$OUT/${tag}_console.log" 2>&1 &
	local CONS=$!
	# The listener has to exist before a connect can be answered. The agent's own
	# budget is $MAX_MS, so this sleep is a convenience, not a correctness condition.
	sleep 2
	bash tests/one.sh "$ai_agent" Examples/demo_build.au3 --port "$port" --loops 2 --ms 150 > "$OUT/${tag}_build.log" 2>&1 &
	local BUILD=$!
	bash tests/one.sh "$ai_agent" Examples/demo_watch.au3 --port "$port" --path "$(pwd -W)/Web" --every 600 --seconds 9 > "$OUT/${tag}_watch.log" 2>&1 &
	local WATCH=$!
	# Touch a watched file so the watcher has something true to report.
	sleep 4
	printf 'gate touched %s\n' "$(date +%s)" > Web/gate_note.txt
	wait $BUILD; local RC_BUILD=$?
	wait $WATCH; local RC_WATCH=$?
	wait $CONS;  local RC_CONS=$?
	rm -f Web/gate_note.txt

	local final events srcs nodes rej cfb cfb_unix cfbsize
	final=$(grep -a "^FINAL" "$OUT/${tag}_console.log" | tr -d '\r' | tail -1)
	events=$(echo "$final" | sed -n 's/.*events=\([0-9]*\).*/\1/p')
	srcs=$(echo "$final" | sed -n 's/.*srcs=\([0-9]*\).*/\1/p')
	nodes=$(echo "$final" | sed -n 's/.*nodes=\([0-9]*\).*/\1/p')
	rej=$(echo "$final" | sed -n 's/.*rejected=\([0-9]*\).*/\1/p')
	cfb=$(grep -a "ARCHIVE " "$OUT/${tag}_console.log" | tr -d '\r' | tail -1 | sed 's/.*ARCHIVE //')
	local cfb_unix="$cfb"
	cfbsize=0
	if [ -n "$cfb" ]; then
		# The console prints a Windows path; stat wants the Unix spelling of the same file.
		cfb_unix=$(cygpath -u "$cfb" 2>/dev/null || echo "$cfb")
		cfbsize=$(stat -c %s "$cfb_unix" 2>/dev/null || echo 0)
	fi

	# A short live session is a small .cfb: 27 events across three sectors' worth of
	# streams came to 14336 bytes, against 1228800 for the 5000-row self test. The
	# size only has to prove the file is not empty; the read-back below is what
	# actually checks the contents.
	if [ "$RC_CONS" = "0" ] && [ "${events:-0}" -ge 20 ] && [ "${srcs:-0}" -ge 2 ] && [ "${rej:-1}" = "0" ] && [ "${cfbsize:-0}" -gt 4096 ]; then
		pass "$label: $final cfb=$cfb bytes=$cfbsize (build rc=$RC_BUILD watch rc=$RC_WATCH)"
	else
		fail "$label rc=$RC_CONS events=${events:-?} srcs=${srcs:-?} nodes=${nodes:-?} rejected=${rej:-?} cfb=${cfb:-none} bytes=$cfbsize build=$RC_BUILD watch=$RC_WATCH"
	fi

	# The archive of the live run must carry both sources by name.
	if [ -n "$cfb" ]; then
		bash tests/one.sh "$AI86" tests/readcfb.au3 "$cfb" DemoBuild DemoWatch > "$OUT/${tag}_cfb.log" 2>&1
		if grep -qa "fail=0" "$OUT/${tag}_cfb.log"; then
			pass "$label archive reads back ($(grep -a '^RESULT' "$OUT/${tag}_cfb.log" | tr -d '\r' | tail -1))"
		else
			fail "$label archive read-back (see $OUT/${tag}_cfb.log)"
		fi
	else
		fail "$label archive read-back (no .cfb written)"
	fi
}

live_pair "live_x86" "$AI86" "$AI86" 48471
live_pair "live_x64" "$AI64" "$AI64" 48472
live_pair "live_mixed" "$AI64" "$AI86" 48473

# --- the agents must be useful on their own, with nothing listening ----------
# An instrument that breaks the host script when the console is not running is
# worse than no instrument, so this is a gate entry and not a remark.
dead_port() {
	local label="$1" ai="$2"
	bash tests/one.sh "$ai" Examples/demo_build.au3 --port 1 --loops 1 --ms 40 > "$OUT/${label}.log" 2>&1
	local rc=$?
	if [ "$rc" = "0" ] && grep -qa "no console listening" "$OUT/${label}.log" && grep -qa "Build.Summary" "$OUT/${label}.log"; then
		pass "$label: degrades to a local log, host script still finishes (rc=$rc)"
	else
		fail "$label against a closed port rc=$rc (see $OUT/${label}.log)"
	fi
}
dead_port "nolisten_x86" "$AI86"
dead_port "nolisten_x64" "$AI64"

echo "DONE_GATE" >> "$SUM"
cat "$SUM"
