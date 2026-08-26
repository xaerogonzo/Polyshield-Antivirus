"""
network_monitor.py
──────────────────
Network connection monitor for PolyShield.

Uses psutil to enumerate established TCP connections and checks each remote IP
against the ip_blocklist table in intelligence/threat_db.sqlite.  No kernel
driver required — runs without elevation for monitoring; blocking requires a
UAC-elevated PowerShell call (handled by the service/UI layer).

Performance design
──────────────────
  • IP check cache   — is_known_bad_ip() results are memoised per-IP so the
                       SQLite query only fires once per unique remote address
                       seen.  Cache is cleared every _CACHE_RESET_POLLS polls,
                       and immediately by clear_ip_cache() after a C2 blocklist
                       import (the "ips" post-update hook).
  • PID process cache — process name/path resolved once per PID and cached in
                       memory, keyed on the process's create_time so a recycled
                       PID cannot inherit the previous process's identity.
                       Entries are evicted when the PID is gone or its identity
                       cannot be verified.

Flagging tiers (in order)
─────────────────────────
  1. C2 blocklist  — IP found in ip_blocklist table → reason "c2:<tags>"
  2. Unsigned outbound — process has no valid path / not verifiable AND connects
                       to a non-private remote → reason "unsigned"
  3. Clean          — none of the above → reason "clean"

Key exports
───────────
  poll_connections()         → list[dict]  (one-shot snapshot)
  is_known_bad_ip(ip)        → (bool, tags)
  NetworkMonitorThread       — background thread; calls push_event_cb on alerts
"""
from __future__ import annotations

import ipaddress as _ip
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

_ROOT    = Path(__file__).resolve().parents[3]
_DB_PATH = _ROOT / "intelligence" / "threat_db.sqlite"

POLL_INTERVAL      = 30    # seconds between connection sweeps
_CACHE_RESET_POLLS = 20    # clear ip cache after this many polls (~10 min)
_PID_CACHE_MAX     = 500   # max entries in the PID cache before full eviction

# Ranges PolyShield does not monitor.
#
# Deliberately an explicit list rather than ipaddress.is_private(): that would
# also skip 100.64.0.0/10 (CGNAT -- what Tailscale runs on), and whether
# PolyShield should stop watching that traffic is a product decision, not a
# side effect of a refactor.  Add to this list on purpose, never by delegation.
#
# The prefix-string version this replaces could not express 172.16.0.0/12 at
# all, so every Docker / WSL2 / Hyper-V bridge address was treated as public
# and every container process with an unresolvable exe path was flagged
# "unsigned" on every poll.
_SKIP_NETWORKS = tuple(_ip.ip_network(_c) for _c in (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fe80::/10",       # IPv6 link-local
    "fc00::/7",        # IPv6 unique-local
))

# ── Module-level caches ───────────────────────────────────────────────────────

# ip  → (flagged: bool, reason: str)
_ip_check_cache: dict[str, tuple[bool, str]] = {}
_ip_cache_lock  = threading.Lock()
_poll_count     = 0

# pid → (create_time: float, name: str, path: str)
#
# create_time is the identity half.  Windows recycles PIDs aggressively, and
# without it a recycled PID served the dead process's name and path -- which
# _is_unsigned() then keys off, so a new process could inherit a stale clean
# verdict or collect a bogus "unsigned" flag.
_pid_proc_cache: dict[int, tuple[float, str, str]] = {}


def clear_ip_cache() -> None:
    """Drop memoised IP verdicts so the next poll re-reads ip_blocklist.

    Registered as the "ips" post-update hook.  After a C2 blocklist import the
    cached "clean" verdicts are stale, and waiting out the periodic reset
    (_CACHE_RESET_POLLS x POLL_INTERVAL, about 10 minutes) would leave
    freshly-imported C2 addresses unflagged in the meantime.  _poll_count is
    reset as well so the periodic sweep stays a predictable interval away
    after a manual clear.
    """
    global _poll_count
    with _ip_cache_lock:
        _ip_check_cache.clear()
        _poll_count = 0


# ── IP blocklist lookup ────────────────────────────────────────────────────────

def is_known_bad_ip(ip: str) -> tuple[bool, str]:
    """
    Check ip against the ip_blocklist table.
    Returns (True, tags) if found, (False, "") otherwise.
    Result is cached until the cache is next reset.
    """
    if not ip or not _DB_PATH.exists():
        return False, ""

    with _ip_cache_lock:
        if ip in _ip_check_cache:
            return _ip_check_cache[ip]

    result: tuple[bool, str] = (False, "")
    try:
        con = sqlite3.connect(str(_DB_PATH), timeout=2)
        try:
            row = con.execute(
                "SELECT tags FROM ip_blocklist WHERE ip=?", (ip,)
            ).fetchone()
            if row:
                result = (True, row[0] or "")
        finally:
            con.close()
    except Exception:
        pass

    with _ip_cache_lock:
        _ip_check_cache[ip] = result
    return result


def _is_private(ip: str) -> bool:
    """True when *ip* is in a range PolyShield does not monitor.

    A malformed address returns False -- matching the old prefix behaviour, and
    deliberately so: an address we cannot parse is surfaced rather than silently
    dropped.  What it must never do is raise, because the only caller is the
    polling loop and psutil hands it whatever the OS reported.
    """
    try:
        addr = _ip.ip_address(ip)
    except ValueError:
        return False
    # Mismatched-version containment is False, not an error, so v4 addresses
    # simply miss the v6 networks.
    return any(addr in net for net in _SKIP_NETWORKS)


# ── Process resolution (with PID cache) ───────────────────────────────────────

def _resolve_process(pid: int) -> tuple[str, str]:
    """
    Return (process_name, process_path) for a PID.
    Caches results to avoid repeated psutil calls for the same PID.
    """
    if not _PSUTIL_OK or not pid:
        return "Unknown", ""

    try:
        proc        = psutil.Process(pid)
        create_time = proc.create_time()
    except psutil.NoSuchProcess:
        _pid_proc_cache.pop(pid, None)      # the PID is gone; so is its entry
        return f"PID {pid}", ""
    except psutil.AccessDenied:
        # Identity is unverifiable, so a cached entry cannot be trusted either
        # -- it may belong to a different process that recycled this PID.
        # Drop it and report the connection as unattributed rather than
        # guessing.
        _pid_proc_cache.pop(pid, None)
        return f"PID {pid}", ""
    except Exception:
        return f"PID {pid}", ""

    cached = _pid_proc_cache.get(pid)
    if cached is not None and cached[0] == create_time:
        return cached[1], cached[2]         # same PID, same process

    # Either a miss or a recycled PID.  name()/exe() are the expensive calls
    # the cache exists to avoid; create_time() above is the cheap identity
    # check that decides whether we can skip them.
    try:
        name = proc.name()
        path = proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        name = f"PID {pid}"
        path = ""

    if len(_pid_proc_cache) >= _PID_CACHE_MAX:
        _pid_proc_cache.clear()
    _pid_proc_cache[pid] = (create_time, name, path)
    return name, path


def _is_unsigned(process_path: str) -> bool:
    """
    Return True when the process path is empty or unresolvable — a minimal
    heuristic that flags processes with no verifiable executable path.
    We intentionally avoid running Get-AuthenticodeSignature here (it's
    expensive per-process); the absence of a resolvable path is a useful
    first-pass proxy.
    """
    return not process_path or not Path(process_path).exists()


# ── Connection snapshot ────────────────────────────────────────────────────────

def poll_connections() -> list[dict]:
    """
    Return a snapshot of established outbound TCP connections.

    Each entry is a dict:
      pid, process_name, process_path,
      remote_addr, remote_port,
      flagged (bool), reason ('c2:<tags>' | 'unsigned' | 'clean')
    """
    global _poll_count
    if not _PSUTIL_OK:
        return []

    # Periodically clear the IP check cache so newly added blocklist entries
    # are picked up without requiring a service restart.
    _poll_count += 1
    if _poll_count % _CACHE_RESET_POLLS == 0:
        with _ip_cache_lock:
            _ip_check_cache.clear()

    connections: list[dict] = []
    try:
        raw = psutil.net_connections(kind="inet")
    except Exception:
        return []

    for c in raw:
        # Only ESTABLISHED outbound connections with a known remote address
        if c.status != "ESTABLISHED":
            continue
        if not c.raddr:
            continue
        remote_ip   = c.raddr.ip
        remote_port = c.raddr.port
        if _is_private(remote_ip):
            continue   # skip loopback / LAN

        pid = c.pid or 0
        process_name, process_path = _resolve_process(pid)

        # ── Flagging logic ────────────────────────────────────────────────────
        bad_ip, tags = is_known_bad_ip(remote_ip)
        if bad_ip:
            # Tier 1: known C2 IP
            flagged = True
            reason  = f"c2:{tags}" if tags else "c2"
        elif _is_unsigned(process_path):
            # Tier 2: process with no verifiable path phoning home (LotL / dropper indicator)
            flagged = True
            reason  = "unsigned"
        else:
            flagged = False
            reason  = "clean"

        connections.append({
            "pid":          pid,
            "process_name": process_name,
            "process_path": process_path,
            "remote_addr":  remote_ip,
            "remote_port":  remote_port,
            "flagged":      flagged,
            "reason":       reason,
        })

    return connections


# ── Background monitor thread ──────────────────────────────────────────────────

class NetworkMonitorThread(threading.Thread):
    """
    Polls TCP connections every POLL_INTERVAL seconds.
    Calls push_event_cb(event_dict) whenever flagged connections are found.

    The callback receives:
      {
        "event":       "network_event",
        "connections": [list of all outbound connections],
        "alerts":      [subset where flagged=True],
        "ts":          ISO timestamp string,
      }
    """

    def __init__(self, push_event_cb: Callable[[dict], None]):
        super().__init__(daemon=True, name="PolyShield-NetMonitor")
        self._push  = push_event_cb
        self._stop  = threading.Event()

    def run(self):
        # Stagger first poll by 10 s so the service finishes starting up
        self._stop.wait(10)
        while not self._stop.is_set():
            try:
                connections = poll_connections()
                alerts      = [c for c in connections if c["flagged"]]
                if alerts:
                    self._push({
                        "event":       "network_event",
                        "connections": connections,
                        "alerts":      alerts,
                        "ts":          datetime.now().isoformat(timespec="seconds"),
                    })
            except Exception:
                pass
            self._stop.wait(POLL_INTERVAL)

    def stop(self):
        self._stop.set()
