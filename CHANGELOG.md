# Changelog

## 1.0.0 - 2026-11-24

- Initial public release of the Pulse flight recorder and local dashboard.
- One AutoIt console integrates WebSocket, WinEventManager, Tree, CompoundFile and
  WebView2; `Pulse_Agent.au3` adds a two-line instrumentation path to host scripts.
- Native `.cfb` session archives contain the manifest, bus journal, name tree and
  bounded event tail.
- Console self test: 18 assertions on x86 and x64.
- Full gate: 27 entries on the source tree and on the extracted release ZIP.
- Live archive read-back: 11 checks per run for x86, x64 and mixed-bitness pairs.
- Dashboard regression checks: 10 checks covering escaping, filtering, counters,
  sources, tree, archive, message safety and the row cap.
- Measured extracted-ZIP throughput on Windows 10 19045: about 640 events/s on
  x86 and 636 events/s on x64, with no loss at the tested load.
