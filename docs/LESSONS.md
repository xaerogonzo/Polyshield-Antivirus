# Lessons

Moved out of [`CLAUDE.md`](../CLAUDE.md) so they are not loaded on every
message. Section CONTENT is verbatim and in its original
order. The only lines this file adds are `## From:` headings,
which say where a subsection came from when its parent stayed
behind.

## Health Snapshot (last recorded — pre v1.2)

```
Quality signal : 8725 / 10000
Acyclicity     : 1.000  (no circular imports)
Modularity     : 0.917  (good separation)
Redundancy     : 1.000  (no duplicate symbols)
Depth          : 1.000  (shallow hierarchy)
Equality       : 0.552  (some files carry more weight than others — expected for views)
```

Largest classes by method count (god-class risk): `ScanView`, `GuardianView`, `UpdateView`, `WinSecView`.  
Most-connected symbols: `run_scan`, `status_callback`, `on_show`, `_navigate`.

**New files since last snapshot** (re-run `tokensave sync` to refresh):
- `src/ui/core/win_security.py` — Windows Security supplement backend
- `src/ui/core/shell_ext.py` — Explorer context menu (HKCU)
- `src/ui/views/winsec_view.py` — Windows Security view
- `src/ui/core/network_monitor.py` — psutil-based network connection monitor, C2/unsigned-outbound detection
- `src/ui/views/network_view.py` — Network sidebar view (live connections table, alert feed, block button)
