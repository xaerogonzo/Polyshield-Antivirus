"""
intel_hooks.py
──────────────
Wires this process's in-memory intelligence consumers to update_intelligence's
post-update hook registry.

Why this exists
───────────────
Three consumers cache intelligence in RAM and would otherwise keep serving
stale data until the process restarts:

  • guardian_engine._scanner    — MalwareBazaar MD5 set        → "hashes"
  • ProcessMonitor._known_bad   — MalwareBazaar MD5 set        → "hashes"
  • network_monitor             — memoised per-IP verdicts     → "ips"

(YARA needs no hook: yara_engine._compile() re-reads the rule files on every
scan.  intel_db queries SQLite live and caches no rows.)

Registration must be EAGER and per-process.  The service in particular can run
for days without ever entering guardian_engine.scan_async(), which used to be
the only place the Guardian hook was registered — so a service that never
scanned a watched file never learned about intelligence updates at all.

Call register_intel_consumers() once at start-up — App.__init__ in the UI
process, SvcDoRun in the service process.  It is idempotent.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

_registered = False


def register_intel_consumers(force: bool = False) -> list[str]:
    """Register every in-memory intelligence consumer available in this process.

    Returns the names of the consumers successfully wired up.  A consumer that
    cannot be imported (missing psutil / WMI, or a standalone guardian env with
    no tools package) degrades to a warning — there is simply nothing in this
    process for that domain to refresh.
    """
    global _registered
    if _registered and not force:
        return []

    try:
        from tools.update_intelligence import register_post_update_hook
    except Exception as exc:
        log.warning("Post-update hook registry unavailable: %s", exc)
        return []

    wired: list[str] = []

    try:
        from ui.core import guardian_engine as ge
        if ge.register_intel_hooks():
            wired.append("guardian_engine")
    except Exception as exc:
        log.warning("Guardian reload hook not registered: %s", exc)

    try:
        from ui.core import process_monitor as pm
        register_post_update_hook(pm.reload_all_known_bad, domains=("hashes",))
        wired.append("process_monitor")
    except Exception as exc:
        log.warning("Process monitor reload hook not registered: %s", exc)

    try:
        from ui.core import network_monitor as nm
        register_post_update_hook(nm.clear_ip_cache, domains=("ips",))
        wired.append("network_monitor")
    except Exception as exc:
        log.warning("Network IP cache hook not registered: %s", exc)

    _registered = True
    log.info("Intelligence post-update hooks registered: %s",
             ", ".join(wired) or "none")
    return wired
