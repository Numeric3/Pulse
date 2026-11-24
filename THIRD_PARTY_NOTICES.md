# Bundled component notices

Pulse bundles the following Numeric1 components so the release runs from one folder.
Each component is Copyright (c) 2026 Numeric1 and distributed under the MIT License
published at <https://github.com/Numeric3/Pulse/blob/main/LICENSE>.

| Component | Version in this repository | Role in Pulse |
| --- | --- | --- |
| WebView2.au3 | 0.10.1 | Local dashboard window and page bridge |
| WebSocket.au3, wsk.au3, tls.au3, wsp.au3, ws.au3 | bundled release snapshot | Loopback WebSocket ingestion |
| WinEventManager.au3 | 1.4.1 | Named event bus, retries, dead letters and Event Log escalation |
| Tree.au3 | 0.2.0 | Dotted event-name index and rolling subtree counts |
| CompoundFile.au3 | 1.0.0 | One native `.cfb` archive per session |

The WebView2 UDF contains no Microsoft source code. Its interface identifiers and
vtable layout follow the Microsoft WebView2 SDK, which is also MIT licensed.
Windows, AutoIt and the WebView2 Runtime are system dependencies and are not
redistributed in this repository.
