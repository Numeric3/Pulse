# Pulse 1.0.0 — what it does not do

Every number in this file was read out of the shipped code or measured on this
machine (AutoIt 3.3.16.1, Windows 10 19045, x86 and x64). Where a limit is a
choice, the choice is named. A limit that is not in this file is a bug.

## 1. Transport and trust

| Item | State | What that means for you |
|---|---|---|
| Listening address | `ws://127.0.0.1:48411/stream` | Loopback only. A script on another machine cannot feed this console, and that is deliberate. |
| TLS | none | `wss://` is supported by the WebSocket UDF, not used here. Nothing leaves the machine, so nothing is encrypted. |
| Authentication | none | Any process that can open a TCP port on this machine can post events. Do not run Pulse on a shared workstation and treat the archive as evidence of who did what. |
| `Origin` header | not checked | A browser page on this machine could post frames if it guessed the port. Nothing here enforces the path either: a request for `/anything` is upgraded the same way as `/stream`. |
| Direction | one way over the socket | The console never writes to an agent's socket. The dashboard's own messages (`ready`, `commit`, `clear`, `log`) travel between the page and the console through WebView2 post-message, not the socket. |
| Slots | `$g_iWspSlots = 8` connections | The ninth `_Pulse_Attach()` fails and the host script does not notice; the agent then logs locally. |
| Accept rate | one accept per loop turn | A burst of simultaneous peers is served over several turns, not at once. |

## 2. Volume

| Named bound | Value | What happens past it |
|---|---|---|
| Throughput, measured | **628 events/s** (5050 frames end to end in 8041 ms, x86, headless, 4 bus handlers + journal, none shed) | Past that the loop simply spends more turns reading; nothing is dropped until the next two lines bite. |
| Frames read per connection per turn | `$g_iMaxPerTurn = 120` (× 8 slots = 960) | The rest wait in the WebSocket UDF's receive queue. If that queue fills, `_WS_Pump` returns `@error 3` and the lost count is added to `shed` — it is counted, never silent. |
| Bus queue | 1000 pending events (`WinEventManager`) | `_WinEvent_Post` returns False, the event is dropped, `shed` increases and the panel says "bus queue full, event lost". The loop therefore drains the bus completely each turn (`_WinEvent_Process(0)`); a partial drain of 200 was measured losing events at this rate. |
| In-memory rows | `$g_iRingCap = 5000` | Oldest rows are overwritten. The archive carries the **tail**, so a session longer than 5000 events has its early events in the journal only as counts, not rows. |
| Frame in | `$g_iFrameCap = 8000` bytes | Refused whole: `rejected` +1, reason in the last-error line. |
| Frame out (agent) | `$PULSE_MAX_FRAME = 4000` bytes | Not refused: trimmed, and the row carries `"truncated":"1"` plus a count of the fields that were dropped. |
| Text field | `$PULSE_MAX_FRAME - 200` characters | Same trim path, `StringLeft` at that width. |
| Event name | 128 characters (`$PULSE_MAX_NAME`) | Cut to 128, no error. |
| Malformed JSON / missing `name` | — | Refused, `rejected` +1, offset printed. A **binary** frame arrives as an empty string from `_WS_MessageText` and is therefore refused as unparseable. |
| Retry against a closed port | one attempt per `$g_iPulseRetryMs = 15000` ms, except during the first `$g_iPulseGraceMs = 20000` ms of the process, when the gap is `$g_iPulseGraceGapMs = 2000` ms | The exception exists because the console cannot answer a handshake while its browser boots. Measured: a demo launched 3 s into a GUI run with a 24.6 s cold boot delivered 49 of 49 events on the grace schedule; on the 15 s gate alone it delivered none. Against a truly closed port a refusal is immediate, so the grace window costs nothing there. |

## 3. The name tree

* `$g_iTreeCap = 20000` nodes. Past that the rolling counters stop being
  maintained in the trie and live in a flat Map only, so a deep namespace can no
  longer be summed by prefix. The console says so in the tree panel header.
* `$g_iTreeRows = 220` rows reach the tree panel. The archive carries what
  `Tree_Export` returned — up to 20000 rows — and `--auto` compares the exported
  row count with the node count recorded at the same instant, so a silent loss
  here fails the run.
* Rebuild cost is real: the UDF's own measurement was 368 ms for 20 000 nodes, so
  Pulse rebuilds only on demand (a click), not per event.

## 4. The window

* **WebView2 Runtime is required.** Pulse does not bundle it; `_WV2_Create` answers
  0 with `@error` and the console logs the reason and carries on headless.
* **The browser boot blocks the process.** `_WV2_Create` is synchronous, and the
  loop is the only thing that answers a handshake, so no agent is accepted while it
  boots. Measured on this machine: 24 638 ms for a cold profile, 4 638 ms and 710 ms
  for the same profile afterwards. The console logs the number
  (`dashboard at http://pulse.local/index.html (browser took N ms)`) and the agent's
  grace window is what carries a script through it. Starting the view with
  `_WV2_CreateStart` and polling was tried and cannot work from the public surface:
  `_WV2_IsReady` only turns true inside `_WV2_CreateWait`, and a
  `_WV2_CreateWait` that times out releases the handle.
* **`--out` is resolved to a full path** before anything sees it, because WebView2
  refuses a relative user data folder: `tmp_gui\wv2` gave `@error 6` with HRESULT
  `0x80080005` (`CO_E_SERVER_EXEC_FAILURE`) while the same folder spelled in full
  created, navigated and captured cleanly.
* `--capture` takes its shot at `$g_iGrabMs` **once the page has said ready**, and at
  twice that delay if it never says it, so a picture exists either way. A view that
  never came up prints `CAPTURE_SKIP` rather than a fake success.
* `$g_iUiRows = 400` rows per push, and `$g_iUiTicks = 10` WebView2 events per
  turn. The page is therefore at most 400 rows behind the ring, and a burst of
  clicks on the page is served over several turns.
* Nothing is pumped inside a handler. The loop is the only place that calls
  `_WS_Pump`, `_WinEvent_Process`, `_WV2_DispatchEvents` and the commit, which is
  what makes re-entrancy impossible — and also means a handler that blocks
  blocks the whole console.

## 5. The archive

* One `.cfb` per session, committed every `$g_iCommitMs = 5000` ms and once more at
  exit. A process killed with `taskkill /F` loses the last ≤ 5 s.
* **Rotation is left to you.** Pulse writes one file per session into `--out` and
  never deletes, renames, or sizes anything. A day of live recording is a folder
  of `.cfb` files you have to prune.
* Contents are the four streams (`Manifest.json`, `events.ndjson`,
  `Index\tree.txt`, `journal.txt`) under `Sessions\<id>`. The journal is the full
  sequence of dispatch rows; `events.ndjson` is the ring tail.
* There is no index by time, no search, no dedup, no compression. The archive is a
  CompoundFile, not a database: `tests/readcfb.au3` is the reference reader and it
  walks the whole NDJSON.

## 6. Escalation to the Windows Event Log

* Only `lvl = error` rows escalate, at most one per `$g_iEscalateMs = 1000` ms, with
  the text cut to 900 characters (`_WinEvent_Write` in `Pulse.au3:472`).
* Writing to the Event Log needs the right to do it. A refused write is recorded as
  `event log write failed @error n` on the last-error line; the event itself is not
  lost, it stays in the ring and the archive.

## 7. Text and encoding — measured 2026-11-18

* This machine's AutoIt 3.3.16.1 keeps strings as **UTF-8 bytes**:
  `Asc(ChrW(233))` returns 195, the first byte of `C3 A9`, and
  `StringToBinary(s, 0/1/8)` is a byte-for-byte copy (`mode 2` is UTF-16 little
  endian, `mode 3` big endian). A text frame therefore goes on the wire as valid
  UTF-8 without anybody encoding it, and Pulse is byte-transparent end to end.
* Proof: the `ChrW(233)` probe over a real socket, read back out of the `.cfb` —
  **18 occurrences of `C3 A9`, 3 of the euro `E2 82 AC`, 0 of the replacement
  sequence `EF BF BD`**.
* `Chr(n)` for `n > 127` is the one thing that does damage a string: `Chr(233)`
  puts a lone `0xE9` into a UTF-8 string, and the next conversion turns it into
  `EF BF BD`. That is an authoring bug in the *host script*, not a transport bug,
  and Pulse cannot fix it — use `ChrW`. An earlier run that looked like an accent
  bug was exactly this, in my own probe.
* Truncation is by bytes/characters, not by codepoints: `StringLeft` at
  `$PULSE_MAX_FRAME - 200` can cut a multi-byte character in half, and the browser
  then shows one replacement character at the end of the line. Rare, and the row is
  already marked `truncated`.

## 8. The agent include

* One connection per process; `_Pulse_Attach()` twice with the same source is a
  no-op, with a different source it detaches and re-attaches.
* The agent carries **no** WinEventManager, no Tree, no CompoundFile: an
  instrument must not be able to crash what it measures. If that trade is wrong
  for you, Pulse is the wrong instrument.
* The agent never reads, so anything the console ever sent back would sit in a
  64 KB receive buffer until the close.
* `_Pulse_Attach` blocks up to 1200 ms when nothing listens: attach at start-up,
  not inside a loop.
* A console never attaches to itself. `_WS_Connect` waits for the peer's `101` and
  a listener in the same process cannot answer itself before the timeout; the
  console posts its own events on the bus instead.

## 9. Not supported, and not quietly half-supported

* No remote or multi-console ingest, no fan-out, no replay of an archive into a
  running console.
* No schema, no typed fields: values that are not scalars arrive as their raw text,
  because a frame is one flat JSON object.
* No filtering server-side. The filters are in the page; every event still crosses
  the socket and still occupies a ring slot.
* No alerting beyond the Event Log line described above.
* No AutoIt 3.3.14 or earlier: Maps, `MapKeys`, `VarGetType` and the compound-file
  writer all need 3.3.16+.
* Unicode beyond the Basic Multilingual Plane is not exercised by any test here. The
  path is byte-transparent so an emoji should travel, but it is not measured.

## 10. When something looks wrong

| Symptom | First thing to read |
|---|---|
| `shed` not zero | You are past 960 frames per turn or the bus queue hit 1000; raise `$g_iMaxPerTurn` or split the sender. |
| `rejected` not zero | The frame is over 8000 bytes, is not flat JSON, has no `name`, or was sent as a binary frame. |
| Nothing in the window but events arrive | The page did not get its `ready`; check the last-error line and re-open. |
| Window blank on a first run | Cold WebView2 profile (35 s measured); re-run or raise `--grab-ms`. |
| Agent prints "no console listening" | Pulse is not up on that port; the host script carried on, which is the point. |
| Archive smaller than expected | Kill via the window, not `taskkill /F` — the last commit is at exit. |
