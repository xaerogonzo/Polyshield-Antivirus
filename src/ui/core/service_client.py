"""
PolyShield Service IPC client.

Communicates with polyshield_service.py over localhost:52614 using
newline-delimited JSON. All public functions are synchronous and
safe to call from any thread.
"""

import json
import socket
import threading
import time

from ui.core import paths

_PORT = 52614
_CONNECT_TIMEOUT = 0.5   # seconds — used for is_service_running() probe
_CMD_TIMEOUT     = 5.0   # seconds — for regular command responses

# How long an is_service_running() answer may be reused.
#
# The probe is not cheap when the answer is "no". A closed port is *supposed*
# to refuse instantly, but measured on Windows 11 with the service installed
# and stopped, connecting to 127.0.0.1:52614 times out after the full 0.5s
# instead — the SYN is dropped rather than reset. Launch alone paid that twice,
# from two different modules (app.py's process-monitor branch and
# ProcessView._refresh_state via attach_monitor), for 1.0s of a 1.6s startup.
# Thirteen call sites do this, several on every navigation to a page.
#
# Two seconds is chosen to collapse a burst — a startup, or one page's worth of
# checks — without outliving a user action. It does not weaken anything: this
# probe was always a routing hint that could be wrong the instant it returned,
# which is why intel_updater re-checks at the point of use and why the actual
# one-writer guarantee is the cross-process file lock, not this answer. Callers
# that display service state pass max_age=0.
_PROBE_TTL_S = 2.0

_probe_lock = threading.Lock()
_probe_cache: "tuple[float, bool] | None" = None


def _token_file():
    r"""The IPC shared secret, resolved the same way the service resolves it.

    Read on every call rather than bound at import: the service writes this
    file on first start, so a client that cached the path -- or the absence of
    the file -- before the service ever ran would keep failing afterwards.

    Both sides went through a hard-coded ``C:\ProgramData`` literal until
    v1.16, in two separate modules. They agreed only because someone kept them
    agreeing; a token path the client and the server disagree about fails as
    "unauthorized", which reads exactly like an attacker being turned away.
    """
    return paths.state_dir() / "service_token.txt"


def _read_token() -> str:
    try:
        return _token_file().read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def _send_cmd(cmd: str, timeout: float = _CMD_TIMEOUT, **kwargs) -> dict | None:
    """
    Connect to the service, send one JSON command, return the parsed response.
    Returns None on any failure (connection refused, timeout, bad JSON).
    """
    token = _read_token()
    payload = json.dumps({"cmd": cmd, "token": token, **kwargs}).encode() + b"\n"
    try:
        with socket.create_connection(("127.0.0.1", _PORT), timeout=timeout) as s:
            s.sendall(payload)
            s.settimeout(timeout)
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            line = buf.split(b"\n", 1)[0]
            return json.loads(line.decode("utf-8"))
    except Exception:
        return None


# ── Public API ─────────────────────────────────────────────────────────────────

def _probe_service_running() -> bool:
    """One real PING. Costs up to _CONNECT_TIMEOUT when the service is down."""
    result = _send_cmd("PING", timeout=_CONNECT_TIMEOUT)
    return result is not None and result.get("ok") is True


def is_service_running(max_age: float = _PROBE_TTL_S) -> bool:
    """Return True if the PolyShield service socket is accepting connections.

    The answer is reused for `max_age` seconds (see _PROBE_TTL_S for why).
    Pass ``max_age=0`` to force a real probe — do that when displaying service
    state, or immediately after starting or stopping the service, where a
    two-second-old answer would be visibly wrong.

    The probe runs under the lock so a burst of callers collapses into one
    round trip rather than each paying for its own.
    """
    global _probe_cache

    with _probe_lock:
        if max_age > 0 and _probe_cache is not None:
            probed_at, cached = _probe_cache
            if (time.monotonic() - probed_at) < max_age:
                return cached
        running = _probe_service_running()
        _probe_cache = (time.monotonic(), running)
        return running


def invalidate_service_probe() -> None:
    """Drop the cached answer, so the next caller probes for real.

    For anything that changes service state through a route this module cannot
    see — `sc start`, the Services console, an installer.
    """
    global _probe_cache
    with _probe_lock:
        _probe_cache = None


def send_command(cmd: str, **kwargs) -> dict | None:
    """Send a named command with optional keyword args; return the response dict."""
    return _send_cmd(cmd, **kwargs)


def get_status() -> dict | None:
    """Return the STATUS response or None."""
    return _send_cmd("STATUS")


def get_events(since_id: int = 0) -> list[dict]:
    """Return scan events with id > since_id, or empty list on failure."""
    result = _send_cmd("GET_EVENTS", since_id=since_id)
    if result and result.get("ok"):
        return result.get("events", [])
    return []


def get_network_events(limit: int = 50) -> list[dict]:
    """Return the most recent network events buffered in the service."""
    result = _send_cmd("GET_NETWORK_EVENTS", limit=limit)
    if result and result.get("ok"):
        return result.get("events", [])
    return []


def block_ip(ip: str) -> tuple[bool, str]:
    """
    Ask the service to add a Windows Firewall outbound-block rule for ip.
    Returns (success, error_message).
    Note: the service will attempt this with its own privileges (LocalService).
    If that fails, the UI should fall back to a direct elevated PowerShell call.
    """
    result = _send_cmd("BLOCK_IP", ip=ip)
    if result is None:
        return False, "Service not reachable"
    return bool(result.get("ok")), result.get("error", "")


def get_intel_status() -> dict | None:
    """Return the service's intelligence freshness + updater state, or None."""
    return _send_cmd("GET_INTEL_STATUS")


def run_intel_update(feeds: list[str] | None = None, force: bool = True) -> tuple[bool, str]:
    """Ask the service to refresh intelligence now.

    The service starts the run on a worker thread and answers immediately, so
    this returns as soon as the run is accepted — not when it finishes.  Watch
    for the intel_update event (or poll GET_INTEL_STATUS) for the outcome.
    Returns (accepted, status_or_error).
    """
    result = _send_cmd("RUN_INTEL_UPDATE", feeds=feeds, force=force)
    if result is None:
        return False, "Service not reachable"
    if not result.get("ok"):
        return False, result.get("error", "Service rejected the request")
    return True, result.get("status", "started")


def subscribe_events(callback, stop_flag: threading.Event | None = None):
    """
    Open a persistent SUBSCRIBE connection and call callback(event_dict) for each
    pushed event. Runs a blocking loop with exponential-backoff reconnects.
    Returns a threading.Event that can be set to stop the loop.

    Intended to be called from a daemon thread.

    callback(event_dict) is called on the background thread — the caller is
    responsible for marshalling to the UI thread (self.after(0, ...)).
    """
    if stop_flag is None:
        stop_flag = threading.Event()

    def _loop():
        backoff = 1.0
        while not stop_flag.is_set():
            token = _read_token()
            payload = json.dumps({"cmd": "SUBSCRIBE", "token": token}).encode() + b"\n"
            try:
                with socket.create_connection(("127.0.0.1", _PORT), timeout=2.0) as s:
                    s.sendall(payload)
                    s.settimeout(None)  # blocking recv
                    buf = b""
                    backoff = 1.0  # reset backoff on successful connect
                    while not stop_flag.is_set():
                        try:
                            s.settimeout(60)  # heartbeat interval + buffer
                            chunk = s.recv(4096)
                        except socket.timeout:
                            # No heartbeat received — service may be stale
                            break
                        if not chunk:
                            break
                        buf += chunk
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            try:
                                event = json.loads(line.decode("utf-8"))
                                if event.get("event") != "heartbeat":
                                    callback(event)
                            except Exception:
                                pass
            except Exception:
                pass

            if not stop_flag.is_set():
                stop_flag.wait(backoff)
                backoff = min(backoff * 2, 30.0)  # exponential backoff, cap at 30s

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return stop_flag
