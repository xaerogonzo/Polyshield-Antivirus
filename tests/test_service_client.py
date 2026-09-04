"""
The service-probe cache.

`is_service_running()` is not the cheap call it looks like. A closed port is
supposed to refuse instantly, but measured on Windows 11 with the service
installed and stopped, connecting to 127.0.0.1:52614 times out after the full
0.5s — the SYN is dropped rather than reset. Thirteen call sites make that
probe, several on every navigation.

Launch paid it twice, from two modules that cannot see each other:
app.py's process-monitor branch, then ProcessView._refresh_state by way of
attach_monitor(). 1.0s of a 1.6s startup, on a machine where nothing was wrong.

The cache is deliberately short-lived and deliberately bypassable. What these
tests pin is that both halves of that hold: a burst collapses, and anything
that has to be current can still get the truth.
"""
from __future__ import annotations

import threading

import pytest

from ui.core import service_client as sc


@pytest.fixture(autouse=True)
def clean_probe_cache():
    """Each test starts with no cached answer and leaves none behind."""
    sc.invalidate_service_probe()
    yield
    sc.invalidate_service_probe()


@pytest.fixture
def counted_probe(monkeypatch):
    """Replace the real socket probe with a counter over a settable answer."""
    state = {"calls": 0, "answer": False}

    def fake():
        state["calls"] += 1
        return state["answer"]

    monkeypatch.setattr(sc, "_probe_service_running", fake)
    return state


# ── Collapsing a burst ────────────────────────────────────────────────────────

def test_repeated_calls_within_the_window_probe_once(counted_probe):
    for _ in range(10):
        assert sc.is_service_running() is False
    assert counted_probe["calls"] == 1, (
        "ten callers in the same moment must share one round trip")


def test_a_true_answer_is_cached_too(counted_probe):
    counted_probe["answer"] = True
    assert sc.is_service_running() is True
    assert sc.is_service_running() is True
    assert counted_probe["calls"] == 1


def test_concurrent_callers_collapse_into_one_probe(counted_probe):
    """The probe runs under the lock, so a thundering herd costs one round trip.

    Without the lock each thread would find an empty cache and probe — which on
    a real machine is eight threads holding a 0.5s socket timeout at once.
    """
    barrier = threading.Barrier(8)
    results = []

    def worker():
        barrier.wait()
        results.append(sc.is_service_running())

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(results) == 8
    assert counted_probe["calls"] == 1


# ── Not outliving its welcome ─────────────────────────────────────────────────

def test_the_answer_expires(counted_probe, monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(sc.time, "monotonic", lambda: clock["now"])

    sc.is_service_running()
    clock["now"] += sc._PROBE_TTL_S + 0.01
    sc.is_service_running()

    assert counted_probe["calls"] == 2, "the cache must not be permanent"


def test_a_state_change_is_seen_after_the_window(counted_probe, monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(sc.time, "monotonic", lambda: clock["now"])

    assert sc.is_service_running() is False
    counted_probe["answer"] = True                  # service starts
    assert sc.is_service_running() is False, "still inside the window"

    clock["now"] += sc._PROBE_TTL_S + 0.01
    assert sc.is_service_running() is True


# ── Getting the truth on demand ───────────────────────────────────────────────

def test_max_age_zero_always_probes(counted_probe):
    sc.is_service_running()
    for _ in range(3):
        sc.is_service_running(max_age=0)
    assert counted_probe["calls"] == 4


def test_a_forced_probe_refreshes_what_everyone_else_sees(counted_probe):
    """The Service page forcing a probe must not leave others on the old answer.

    It is the screen that watches state change, so its fresh result becomes the
    cached one rather than being thrown away.
    """
    assert sc.is_service_running() is False

    counted_probe["answer"] = True
    assert sc.is_service_running(max_age=0) is True

    counted_probe["calls"] = 0
    assert sc.is_service_running() is True, "the cached answer was refreshed"
    assert counted_probe["calls"] == 0


def test_invalidate_forces_the_next_caller_to_probe(counted_probe):
    """For state changed by a route this module cannot see — sc start, the
    Services console, an installer. ServiceView calls it after every action."""
    assert sc.is_service_running() is False
    counted_probe["answer"] = True

    sc.invalidate_service_probe()

    assert sc.is_service_running() is True
    assert counted_probe["calls"] == 2


# ── The seam this replaced ────────────────────────────────────────────────────

def test_the_probe_itself_is_still_a_real_ping(monkeypatch):
    """The cache must not have changed what a probe actually asks.

    is_service_running() means "the socket answered a PING with ok", not "a
    process by that name exists" — a service that is up but wedged has to read
    as not running.
    """
    sent = {}

    def fake_send(cmd, timeout=None, **kw):
        sent["cmd"] = cmd
        sent["timeout"] = timeout
        return {"ok": True}

    monkeypatch.setattr(sc, "_send_cmd", fake_send)
    assert sc.is_service_running() is True
    assert sent["cmd"] == "PING"
    assert sent["timeout"] == sc._CONNECT_TIMEOUT

    sc.invalidate_service_probe()
    monkeypatch.setattr(sc, "_send_cmd", lambda *a, **k: {"ok": False})
    assert sc.is_service_running() is False

    sc.invalidate_service_probe()
    monkeypatch.setattr(sc, "_send_cmd", lambda *a, **k: None)
    assert sc.is_service_running() is False
