# The Pulse wire protocol

Version 1. Everything below is what `Pulse.au3` and `Pulse_Agent.au3` actually do, as
measured by `Pulse.au3 --auto` and the live entries in `tests/gate.sh`.

## Transport

```
ws://127.0.0.1:48411/stream
```

* Plain WebSocket over TCP, **no TLS**. The listener binds `127.0.0.1` only, so the
  port is not reachable from another machine.
* One **text** frame per event. A binary frame is dequeued like any other and arrives as
  an empty string, so it is counted in `rejected` rather than dropped in silence.
* The path is not checked: `/stream` is the convention the agent uses, and any other
  path on that port gets upgraded like any other client. That is a limit, not a feature —
  see [LIMITS.md](LIMITS.md).
* No subprotocol is negotiated and no Origin is required (the console calls
  `_WS_Upgrade($h, 2000)`, which accepts a peer that sends no Origin at all — a
  non-browser client).
* The connection is **one-way**. The console never sends a data frame back to an agent;
  an agent that never reads costs itself nothing but a socket buffer.

## The frame

A flat JSON object. Nesting is allowed on the wire but the value arrives as raw text,
because the console deliberately carries no schema and no flattening rules.

```json
{"v":1,"name":"Build.Compile.Step","src":"Demo","lvl":"ok","ms":812,"txt":"37 units","files":7}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `v` | number | protocol version, currently 1; absent is accepted |
| `name` | string | **required**, the dotted event name. This is the only field with meaning attached: it builds the tree. Up to 128 characters |
| `src` | string | who sent it; `unknown` when absent. One row per distinct value in the sources panel |
| `lvl` | string | `debug`, `info`, `ok`, `warn`, `error`. Anything else becomes `info`; `warning`/`err`/`fatal`/`trace` are folded onto their canonical spelling |
| `ms` | number | duration in milliseconds, shown next to the row |
| `txt` | string | the human line |
| `truncated` | any | if the key is present at all, the row is marked as trimmed |
| anything else | scalar | merged into the row's text as `key=value`, in key order |

Refusals are counted, never silent: a frame over 8000 bytes, one that is not an object
(`[1,2,3]`), and one without a `name` are each counted in `rejected` and named in
`$g_sLastErr`, which the dashboard footer shows.

### The two frames the agent sends for you

On `_Pulse_Attach`:

```json
{"v":1,"name":"Agent.Hello","src":"DemoBuild","lvl":"info","pid":1204,"x64":0,"aver":"3.3.16.1","script":"demo_build.au3"}
```

`Agent.Hello` is the only frame the console interprets beyond the table above: it fills
the pid/bitness column of the sources panel. On `_Pulse_Detach` (also registered at
exit) the agent sends `Agent.Gone` with the reason in `txt`, then closes with code 1000.

## Levels and what they trigger

| Level | Stream colour | Tree branch takes | Escalation |
| --- | --- | --- | --- |
| `debug` | dim | unchanged | no |
| `info` | default | unchanged | no |
| `ok` | green | only upgraded from `info` | no |
| `warn` | amber | upgraded | no |
| `error` | red | upgraded, and stays for the whole subtree | Windows Event Log, at most one write per second, text cut at 900 characters |

A branch's level is the worst level seen beneath it, which is why the panel can say
"`Build` is red" before you read a single row.

## Sending from something that is not AutoIt

The console has no client-side requirements beyond the handshake, so any WebSocket
client works:

```bash
# one event, using nothing but a WebSocket-capable tool
echo '{"name":"Deploy.Start","src":"bash","lvl":"info","txt":"env=prod"}' | wscat -c ws://127.0.0.1:48411/stream
```

```python
import json, websocket  # pip install websocket-client
ws = websocket.create_connection("ws://127.0.0.1:48411/stream")
ws.send(json.dumps({"name": "pytest.collected", "src": "tests", "lvl": "info", "files": 42}))
ws.close()
```

Rules of courtesy: keep `name` dotted and stable (it is an index key, not a sentence),
put the variable part in `txt`, and do not send a frame per byte of output — see the
throughput number in [../README.md](../README.md).

## What the dashboard speaks

The page is a local file served on the virtual host `http://pulse.local`, and it has no
network access. Console → page, as JSON via `postWebMessage`:

| `k` | Payload | Panel |
| --- | --- | --- |
| `evs` | `a`: rows of `[time, lvl, name, src, ms, txt, cut]` | live stream |
| `stat` | totals, rate, sources, nodes, dead, queue, journal, conns, peak, shed, rejected, overflow, port, listening, bytes, file, err | header |
| `tree` | `a`: `[name, count, level]` preorder, capped at 220 rows | name index |
| `srcs` | `a`: `[source, "pid bitness", events, errors]` | sources |
| `arch` | `a`: `[name, size-or-"storage"]` for the current session | archive |

Page → console: `{"k":"ready"}` when the script has attached, `{"k":"commit"}` to flush
the archive now, `{"k":"clear"}` to reset the counters, `{"k":"log","text":…}` to echo a
line to the console's stdout. Anything else is named in the footer as having no meaning;
it is not ignored in silence.
