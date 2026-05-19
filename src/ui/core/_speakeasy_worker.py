"""
_speakeasy_worker.py
────────────────────
Standalone subprocess worker for Speakeasy PE emulation.

Invoked by emulate_engine.emulate_async() as a completely separate Python
process.  Running Speakeasy in a subprocess (rather than a thread) eliminates
GIL starvation: unicorn-engine makes Python hook callbacks from C on every
emulated API call, each re-acquiring the GIL and starving the CustomTkinter
main thread.  A separate process has its own GIL — the UI stays responsive.

Usage
─────
    python _speakeasy_worker.py <pe_path> [exe|dll|sc]

    mode "exe" — PE executable (default)
    mode "dll" — PE DLL
    mode "sc"  — raw shellcode (.bin / .sc)

Stdout
──────
    Single JSON line on success:  {"ok": true, "report": {...}}
    Single JSON line on failure:  {"error": "..."}

Exit codes
──────────
    0 — success (report written to stdout)
    1 — error   (error message written to stdout as JSON)
"""
from __future__ import annotations

import json
import sys


def main() -> None:
    if len(sys.argv) < 2:
        _fail("Usage: _speakeasy_worker.py <path> [exe|dll|sc]")

    path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "exe"

    try:
        import speakeasy  # type: ignore[import]
    except ImportError:
        _fail("speakeasy-emulator not installed in this Python environment.")

    try:
        se = speakeasy.Speakeasy()
        module = se.load_module(path)

        if mode == "sc":
            se.run_shellcode(module, offset=0)
        else:
            # run_module handles both .exe and .dll correctly
            se.run_module(module)

        raw = se.get_report()
        # Emit the report as a single JSON line on stdout
        print(json.dumps({"ok": True, "report": raw}), flush=True)

    except Exception as exc:
        _fail(str(exc)[:600])


def _fail(msg: str) -> None:
    """Print an error JSON line and exit with code 1."""
    print(json.dumps({"error": msg}), flush=True)
    sys.exit(1)


if __name__ == "__main__":
    main()
