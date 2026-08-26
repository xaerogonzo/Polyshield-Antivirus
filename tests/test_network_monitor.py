"""
Network connection monitoring.

Two defects motivated this file, both of them about the monitor telling the
user something untrue rather than about it crashing:

  * `_is_private()` was a tuple of string prefixes, which cannot express
    172.16.0.0/12. Every Docker / WSL2 / Hyper-V bridge address was therefore
    treated as public, and because tier 2 flags any process whose exe path
    psutil cannot resolve, container traffic was reported as "unsigned" on
    every single poll.

  * The PID cache stored `pid -> (name, path)` and never evicted, while its
    own docstring claimed dead PIDs were evicted automatically. Windows
    recycles PIDs aggressively, so a connection could be attributed to a
    long-dead process -- and `_is_unsigned()` keys off that cached path, so a
    new process could inherit a stale clean verdict.

psutil is stubbed throughout. Real connection enumeration would make the
result depend on whatever happened to be running on the developer's machine.
"""
from __future__ import annotations

import pytest

from ui.core import network_monitor as nm

from conftest import add_c2_ip


# ── Fakes ─────────────────────────────────────────────────────────────────────

class FakeAddr:
    def __init__(self, ip, port):
        self.ip, self.port = ip, port


class FakeConn:
    def __init__(self, ip="8.8.8.8", port=443, pid=100, status="ESTABLISHED"):
        self.raddr = FakeAddr(ip, port) if ip else None
        self.pid, self.status = pid, status


class FakeProcess:
    """psutil.Process with controllable identity and failure modes."""

    def __init__(self, name="app.exe", path=r"C:\app.exe", create_time=1000.0):
        self._name, self._path, self._create = name, path, create_time
        self.name_calls = 0

    def create_time(self):
        return self._create

    def name(self):
        self.name_calls += 1
        return self._name

    def exe(self):
        return self._path


@pytest.fixture
def psutil_stub(net_sandbox, monkeypatch):
    """Install a controllable psutil and guarantee _PSUTIL_OK."""
    monkeypatch.setattr(nm, "_PSUTIL_OK", True)
    return monkeypatch


# ── _is_private ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ip", [
    "10.0.0.1", "10.255.255.255",
    "172.16.0.1", "172.31.255.255",          # the range the prefix tuple missed
    "192.168.1.1", "127.0.0.1", "169.254.1.1",
    "::1", "fe80::1", "fd00::abcd",
])
def test_private_ranges_are_skipped(ip):
    assert nm._is_private(ip) is True


@pytest.mark.parametrize("ip", [
    "172.15.255.255",     # one below the /12
    "172.32.0.0",         # one above it
    "8.8.8.8", "2606:4700::1111",
])
def test_public_addresses_are_not_skipped(ip):
    assert nm._is_private(ip) is False


def test_docker_and_wsl_bridge_traffic_is_no_longer_flagged():
    """The user-visible bug: 172.16/12 could not be expressed as a prefix, so
    every container process phoning out looked like an unsigned dropper."""
    assert nm._is_private("172.17.0.2") is True     # Docker default bridge
    assert nm._is_private("172.18.0.5") is True     # docker-compose networks


def test_cgnat_is_still_monitored():
    """Pinning a product decision, not an implementation detail.

    100.64.0.0/10 is CGNAT -- what Tailscale runs on. ipaddress.is_private()
    would skip it; PolyShield deliberately does not. If this ever changes it
    should be because someone decided to, and this test is what makes them.
    """
    assert nm._is_private("100.64.0.1") is False
    assert nm._is_private("100.127.255.255") is False


@pytest.mark.parametrize("garbage", ["", "not-an-ip", "999.999.999.999", "::zz"])
def test_a_malformed_address_never_raises(garbage):
    """The only caller is the polling loop, and psutil hands it whatever the
    OS reported. ip_address() raises ValueError where the old prefix match
    could not -- an unparseable address must not kill the monitor thread."""
    assert nm._is_private(garbage) is False


# ── is_known_bad_ip ───────────────────────────────────────────────────────────

def test_a_blocklisted_ip_is_flagged_with_its_tags(intel_db, net_sandbox):
    add_c2_ip(intel_db, "203.0.113.5", tags="emotet")

    flagged, tags = nm.is_known_bad_ip("203.0.113.5")

    assert flagged is True and tags == "emotet"


def test_an_unlisted_ip_is_clean(intel_db, net_sandbox):
    assert nm.is_known_bad_ip("203.0.113.9") == (False, "")


def test_verdicts_are_memoised(intel_db, net_sandbox, monkeypatch):
    """One SQLite open per unique address, not per connection per poll.

    Asserted by counting opens rather than by breaking _DB_PATH: the existence
    check in is_known_bad_ip() runs *before* the cache lookup, so a missing DB
    short-circuits ahead of the cache and would pass this test for the wrong
    reason.
    """
    add_c2_ip(intel_db, "203.0.113.5", tags="emotet")

    opens = []
    real_connect = nm.sqlite3.connect
    monkeypatch.setattr(nm.sqlite3, "connect",
                        lambda *a, **kw: opens.append(1) or real_connect(*a, **kw))

    assert nm.is_known_bad_ip("203.0.113.5") == (True, "emotet")
    assert nm.is_known_bad_ip("203.0.113.5") == (True, "emotet")
    assert nm.is_known_bad_ip("203.0.113.5") == (True, "emotet")

    assert len(opens) == 1, f"queried SQLite {len(opens)} times for one address"


def test_an_empty_ip_is_never_looked_up(intel_db, net_sandbox):
    assert nm.is_known_bad_ip("") == (False, "")


# ── PID cache ─────────────────────────────────────────────────────────────────

def test_a_cache_hit_skips_the_expensive_lookups(psutil_stub):
    """create_time() is the cheap identity check; name()/exe() are what the
    cache exists to avoid. A hit must not pay for them again."""
    proc = FakeProcess(name="chrome.exe")
    psutil_stub.setattr(nm.psutil, "Process", lambda pid: proc)

    assert nm._resolve_process(100) == ("chrome.exe", r"C:\app.exe")
    assert nm._resolve_process(100) == ("chrome.exe", r"C:\app.exe")

    assert proc.name_calls == 1, "the cached entry was re-resolved"


def test_a_recycled_pid_does_not_inherit_the_old_attribution(psutil_stub):
    """The defect. Same PID, different process -- Windows does this constantly.

    Before v1.13 the second call returned malware.exe's connection labelled
    chrome.exe, and _is_unsigned() judged it on chrome's path.
    """
    procs = iter([FakeProcess(name="chrome.exe", path=r"C:\chrome.exe",
                              create_time=1000.0),
                  FakeProcess(name="malware.exe", path=r"C:\temp\x.exe",
                              create_time=2000.0)])
    current = {"p": next(procs)}
    psutil_stub.setattr(nm.psutil, "Process", lambda pid: current["p"])

    assert nm._resolve_process(100) == ("chrome.exe", r"C:\chrome.exe")

    current["p"] = next(procs)                     # PID 100 is reused
    assert nm._resolve_process(100) == ("malware.exe", r"C:\temp\x.exe"), (
        "a recycled PID served the dead process's identity")


def test_a_dead_pid_is_evicted(psutil_stub):
    proc = FakeProcess()
    psutil_stub.setattr(nm.psutil, "Process", lambda pid: proc)
    nm._resolve_process(100)
    assert 100 in nm._pid_proc_cache

    def gone(pid):
        raise nm.psutil.NoSuchProcess(pid)

    psutil_stub.setattr(nm.psutil, "Process", gone)

    assert nm._resolve_process(100) == ("PID 100", "")
    assert 100 not in nm._pid_proc_cache, "the docstring promised eviction"


def test_access_denied_does_not_serve_a_stale_entry(psutil_stub):
    """If identity cannot be verified, a cached entry cannot be trusted either
    -- it may belong to a different process that recycled this PID. Report the
    connection as unattributed rather than guessing."""
    proc = FakeProcess(name="chrome.exe")
    psutil_stub.setattr(nm.psutil, "Process", lambda pid: proc)
    nm._resolve_process(100)

    def denied(pid):
        raise nm.psutil.AccessDenied(pid)

    psutil_stub.setattr(nm.psutil, "Process", denied)

    assert nm._resolve_process(100) == ("PID 100", "")
    assert 100 not in nm._pid_proc_cache


def test_the_cache_is_bounded(psutil_stub):
    psutil_stub.setattr(nm.psutil, "Process",
                        lambda pid: FakeProcess(create_time=float(pid)))

    for pid in range(1, nm._PID_CACHE_MAX + 3):
        nm._resolve_process(pid)

    assert len(nm._pid_proc_cache) <= nm._PID_CACHE_MAX


# ── poll_connections ──────────────────────────────────────────────────────────

def _stub_connections(monkeypatch, conns):
    monkeypatch.setattr(nm.psutil, "net_connections", lambda kind="inet": conns)


def test_c2_outranks_the_unsigned_heuristic(intel_db, psutil_stub):
    """Tier order matters: a known C2 address should say so, not "unsigned",
    even when the process path is also unresolvable."""
    add_c2_ip(intel_db, "203.0.113.5", tags="cobaltstrike")
    psutil_stub.setattr(nm.psutil, "Process",
                        lambda pid: FakeProcess(path=r"C:\gone\missing.exe"))
    _stub_connections(psutil_stub, [FakeConn(ip="203.0.113.5")])

    (conn,) = nm.poll_connections()

    assert conn["flagged"] is True
    assert conn["reason"] == "c2:cobaltstrike"


def test_an_unresolvable_process_path_is_flagged_unsigned(intel_db, psutil_stub):
    psutil_stub.setattr(nm.psutil, "Process",
                        lambda pid: FakeProcess(path=r"C:\gone\missing.exe"))
    _stub_connections(psutil_stub, [FakeConn(ip="8.8.8.8")])

    (conn,) = nm.poll_connections()

    assert conn["flagged"] is True and conn["reason"] == "unsigned"


def test_a_resolvable_process_to_a_clean_ip_is_clean(intel_db, psutil_stub, tmp_path):
    real_exe = tmp_path / "app.exe"
    real_exe.write_bytes(b"MZ")
    psutil_stub.setattr(nm.psutil, "Process",
                        lambda pid: FakeProcess(path=str(real_exe)))
    _stub_connections(psutil_stub, [FakeConn(ip="8.8.8.8")])

    (conn,) = nm.poll_connections()

    assert conn["flagged"] is False and conn["reason"] == "clean"


def test_private_established_and_addrless_rows_are_skipped(intel_db, psutil_stub):
    psutil_stub.setattr(nm.psutil, "Process", lambda pid: FakeProcess())
    _stub_connections(psutil_stub, [
        FakeConn(ip="10.0.0.5"),                       # private
        FakeConn(ip="172.17.0.2"),                     # Docker bridge
        FakeConn(ip="8.8.8.8", status="LISTEN"),       # not established
        FakeConn(ip=None),                             # no remote address
    ])

    assert nm.poll_connections() == []


def test_poll_returns_empty_when_psutil_is_unavailable(monkeypatch):
    monkeypatch.setattr(nm, "_PSUTIL_OK", False)

    assert nm.poll_connections() == []


def test_an_enumeration_failure_is_not_fatal(intel_db, psutil_stub):
    """The poll loop runs forever in the service; one failed sweep must not
    end it."""
    def boom(kind="inet"):
        raise OSError("enumeration failed")

    psutil_stub.setattr(nm.psutil, "net_connections", boom)

    assert nm.poll_connections() == []


# ── NetworkMonitorThread ──────────────────────────────────────────────────────

def test_the_thread_pushes_only_when_something_is_flagged(monkeypatch):
    pushed = []
    thread = nm.NetworkMonitorThread(pushed.append)

    monkeypatch.setattr(nm, "poll_connections",
                        lambda: [{"flagged": False, "reason": "clean"}])
    thread._stop.set()                        # one pass, no waiting
    thread.run()
    assert pushed == [], "a clean sweep produced an alert"

    monkeypatch.setattr(nm, "poll_connections",
                        lambda: [{"flagged": True, "reason": "c2:x"},
                                 {"flagged": False, "reason": "clean"}])
    thread._stop.clear()

    def stop_after_one():
        thread._stop.set()
        return [{"flagged": True, "reason": "c2:x"},
                {"flagged": False, "reason": "clean"}]

    monkeypatch.setattr(nm, "poll_connections", stop_after_one)
    monkeypatch.setattr(thread._stop, "wait", lambda t=None: None)
    thread.run()

    assert len(pushed) == 1
    assert pushed[0]["event"] == "network_event"
    assert len(pushed[0]["alerts"]) == 1, "clean rows leaked into alerts"


# ── clear_ip_cache ────────────────────────────────────────────────────────────

def test_clearing_the_cache_makes_a_new_blocklist_entry_visible(intel_db,
                                                                net_sandbox):
    """The reason the "ips" post-update hook exists. A cached clean verdict has
    no expiry, so without the clear a freshly imported C2 address stays
    unflagged until the periodic sweep ~10 minutes later."""
    ip = "203.0.113.77"
    assert nm.is_known_bad_ip(ip)[0] is False      # caches the clean verdict

    add_c2_ip(intel_db, ip, tags="freshly-imported")
    assert nm.is_known_bad_ip(ip)[0] is False, "served from the stale cache"

    nm.clear_ip_cache()

    assert nm.is_known_bad_ip(ip) == (True, "freshly-imported")
