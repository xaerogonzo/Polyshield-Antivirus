"""
Phase C tests — the service's intelligence surface.

The service class is bound to the Windows SCM, so instances are built with
__new__ and given just the attributes the methods under test touch.  That keeps
the real dispatch logic (token check, command routing, worker-thread handoff)
under test without needing an installed service.

The end-to-end check — install the service, send RUN_INTEL_UPDATE, read
C:\\ProgramData\\PolyShield\\service.log — stays a manual step; it is also the
LocalService write-permission test.
"""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest


# ── Shared event shape ────────────────────────────────────────────────────────

def test_scheduled_and_manual_runs_emit_the_same_shape():
    """One operation, one vocabulary — the Service view must not show a
    scheduled run and a "Run now" run as if they were different features."""
    from ui.core.intel_updater import build_update_event

    result = {
        "status": "partial",
        "feeds": {"malwarebazaar": {"status": "updated", "added": 12},
                  "c2": {"status": "failed", "error": "HTTP 403"}},
        "error": "",
    }
    event = build_update_event(result)

    assert event["event"] == "intel_update"
    assert event["status"] == "partial"
    assert "malwarebazaar: updated" in event["summary"]
    assert "c2: failed" in event["summary"]
    assert event["feeds"]["c2"]["error"] == "HTTP 403"
    assert event["time"]


# ── Service instance helpers ──────────────────────────────────────────────────

@pytest.fixture
def svc(monkeypatch):
    """A PolyShieldService with only the state the intel methods need."""
    pytest.importorskip("win32serviceutil")
    import polyshield_service as ps

    s = ps.PolyShieldService.__new__(ps.PolyShieldService)
    s._token = "test-token"
    s._intel_updater = None
    s._intel_last_result = {}
    s._intel_run_lock = threading.Lock()
    s._pushed = []
    s._push_event = s._pushed.append          # capture instead of broadcasting
    return s


class _FakeConn:
    """Minimal stand-in for the accepted client socket."""

    def __init__(self, request: dict):
        self._data = json.dumps(request).encode() + b"\n"
        self.sent = b""
        self.closed = False

    def settimeout(self, _):
        pass

    def recv(self, _n):
        data, self._data = self._data, b""
        return data

    def sendall(self, payload):
        self.sent += payload

    def close(self):
        self.closed = True

    @property
    def response(self) -> dict:
        return json.loads(self.sent.split(b"\n", 1)[0].decode())


# ── Dispatch ──────────────────────────────────────────────────────────────────

def test_run_intel_update_command_starts_a_run(svc, monkeypatch):
    from ui.core import intel_updater as iu

    seen = {}

    def fake_run_updates(feeds=None, force=False, owner="ui", on_progress=None, notify=True):
        seen["feeds"] = feeds
        seen["force"] = force
        seen["owner"] = owner
        return {"status": "updated", "feeds": {"c2": {"status": "updated"}}}

    monkeypatch.setattr(iu, "run_updates", fake_run_updates)

    conn = _FakeConn({"cmd": "RUN_INTEL_UPDATE", "token": "test-token",
                      "feeds": ["c2"], "force": True})
    svc._handle_client(conn)

    assert conn.response == {"ok": True, "status": "started", "error": ""}

    # Wait on the LAST thing the worker does (the push), not the first
    # (_intel_last_result) — otherwise this races the worker under load.
    deadline = time.time() + 5
    while not svc._pushed and time.time() < deadline:
        time.sleep(0.02)

    assert seen["feeds"] == ["c2"]
    assert seen["owner"] == "service", "the service must run as the owner, not as ui"
    assert svc._intel_last_result["status"] == "updated"
    assert svc._pushed and svc._pushed[0]["event"] == "intel_update"


def test_second_run_request_is_rejected_while_one_is_active(svc, monkeypatch):
    from ui.core import intel_updater as iu

    release = threading.Event()

    def slow_run(**kwargs):
        release.wait(timeout=5)
        return {"status": "updated", "feeds": {}}

    monkeypatch.setattr(iu, "run_updates", slow_run)

    first = _FakeConn({"cmd": "RUN_INTEL_UPDATE", "token": "test-token"})
    svc._handle_client(first)
    assert first.response["status"] == "started"

    second = _FakeConn({"cmd": "RUN_INTEL_UPDATE", "token": "test-token"})
    svc._handle_client(second)
    assert second.response["status"] == "already_running"
    assert second.response["error"]

    release.set()


def test_get_intel_status_reports_feeds(svc, intel_db, hooks, settings_sandbox):
    conn = _FakeConn({"cmd": "GET_INTEL_STATUS", "token": "test-token"})
    svc._handle_client(conn)

    resp = conn.response
    assert resp["ok"] is True
    assert resp["updater_running"] is False
    assert set(resp["feeds"]) == {"malwarebazaar", "c2", "yara"}
    assert resp["feeds"]["malwarebazaar"]["state"] in {
        "never", "fresh", "aging", "stale", "error", "auth_required"}


def test_a_fresh_install_is_not_reported_as_an_error_by_the_service(
    svc, intel_db, hooks, settings_sandbox, yara_sandbox,
):
    """The service has to read a first launch the same way the GUI does.

    Both import the same intel_updater, so what this pins is that neither grows
    its own copy of the rule — the divergence class the shared-data-root work
    has been closing, where the two processes disagreed about the same files.
    A service that reports a fresh install as an error is a service the UI will
    show a red banner for on a machine where nothing is wrong.
    """
    intel_db.unlink()                       # nothing has ever been downloaded

    conn = _FakeConn({"cmd": "GET_INTEL_STATUS", "token": "test-token"})
    svc._handle_client(conn)
    resp = conn.response

    assert resp["ok"] is True
    assert {f["state"] for f in resp["feeds"].values()} == {"never"}, \
        "a fresh install has never updated; it has not errored"

    from ui.core import intel_updater as iu
    posture = iu.get_posture()
    assert posture["state"] == iu.POSTURE_UPDATE_REQ
    assert "Never updated" in posture["detail"]


def test_intel_commands_require_the_token(svc):
    for cmd in ("GET_INTEL_STATUS", "RUN_INTEL_UPDATE"):
        conn = _FakeConn({"cmd": cmd, "token": "wrong"})
        svc._handle_client(conn)
        assert conn.response == {"ok": False, "error": "unauthorized"}


# ── Client wrappers ───────────────────────────────────────────────────────────

class _StubService:
    """A one-shot localhost server speaking the service's line protocol."""

    def __init__(self, response: dict):
        self._response = response
        self.received: dict | None = None
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
            with conn:
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(1024)
                    if not chunk:
                        return
                    buf += chunk
                self.received = json.loads(buf.split(b"\n", 1)[0].decode())
                conn.sendall(json.dumps(self._response).encode() + b"\n")
        except OSError:
            pass

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


@pytest.fixture
def stub_service(monkeypatch):
    from ui.core import service_client as sc

    created = []

    def make(response: dict):
        stub = _StubService(response)
        created.append(stub)
        monkeypatch.setattr(sc, "_PORT", stub.port)
        monkeypatch.setattr(sc, "_read_token", lambda: "test-token")
        return stub

    yield make
    for stub in created:
        stub.close()


def test_run_intel_update_client_accepts_a_started_response(stub_service):
    from ui.core import service_client as sc

    stub = stub_service({"ok": True, "status": "started", "error": ""})
    accepted, status = sc.run_intel_update(feeds=["yara"], force=True)

    assert accepted is True
    assert status == "started"
    assert stub.received["cmd"] == "RUN_INTEL_UPDATE"
    assert stub.received["feeds"] == ["yara"]


def test_run_intel_update_client_surfaces_already_running(stub_service):
    from ui.core import service_client as sc

    stub_service({"ok": True, "status": "already_running", "error": "busy"})
    accepted, status = sc.run_intel_update()

    assert accepted is True
    assert status == "already_running"


def test_run_intel_update_client_handles_an_unreachable_service(monkeypatch):
    from ui.core import service_client as sc

    monkeypatch.setattr(sc, "_send_cmd", lambda *a, **k: None)
    accepted, msg = sc.run_intel_update()

    assert accepted is False
    assert "not reachable" in msg


def test_get_intel_status_client(stub_service):
    from ui.core import service_client as sc

    payload = {"ok": True, "updater_running": True,
               "feeds": {"c2": {"state": "fresh"}}, "last_result": {}}
    stub_service(payload)

    assert sc.get_intel_status() == payload


# ── UI routing ────────────────────────────────────────────────────────────────

def test_request_update_prefers_the_service(monkeypatch, intel_db, hooks, settings_sandbox):
    """Every UI surface goes through request_update() so the Dashboard button
    and the Settings button can never disagree about who writes."""
    from ui.core import intel_updater as iu
    from ui.core import service_client as sc

    monkeypatch.setattr(sc, "is_service_running", lambda: True)
    monkeypatch.setattr(sc, "send_command",
                        lambda cmd, **kw: {"ok": True, "status": "started"})

    def must_not_run(**kwargs):
        raise AssertionError("UI ran the update itself while the service was up")

    monkeypatch.setattr(iu, "run_updates", must_not_run)

    out = iu.request_update(feeds=["c2"])
    assert out["via"] == "service"
    assert out["status"] == "started"


def test_request_update_falls_back_when_the_service_rejects_the_command(
        monkeypatch, intel_db, hooks, settings_sandbox):
    """An older service build will not know RUN_INTEL_UPDATE.  Falling back is
    safe because the cross-process lock still arbitrates writers."""
    from ui.core import intel_updater as iu
    from ui.core import service_client as sc

    monkeypatch.setattr(sc, "is_service_running", lambda: True)
    monkeypatch.setattr(sc, "send_command",
                        lambda cmd, **kw: {"ok": False, "error": "Unknown command"})
    monkeypatch.setattr(iu, "run_updates",
                        lambda **kw: {"status": "updated", "feeds": {}})

    out = iu.request_update(feeds=["c2"])
    assert out["via"] == "local"
    assert out["status"] == "updated"


# ── UI launch-time fallback ───────────────────────────────────────────────────

class _FakeApp:
    """Just enough of App for _maybe_auto_update_intel."""

    def __init__(self):
        self.statuses = []
        self.scheduled = []

    def after(self, delay, fn, *a):
        self.scheduled.append((delay, fn))

    def winfo_exists(self):
        return True

    def _set_status(self, text):
        self.statuses.append(text)


def _bind_fallback():
    import types
    import ui.app as app_mod
    fake = _FakeApp()
    fake._maybe_auto_update_intel = types.MethodType(
        app_mod.App._maybe_auto_update_intel, fake)
    return fake


def test_launch_fallback_does_nothing_when_disabled(monkeypatch, settings_sandbox):
    from ui.core import intel_updater as iu

    settings_sandbox["intel_auto_update"] = False
    monkeypatch.setattr(iu, "run_updates",
                        lambda **kw: pytest.fail("ran while disabled"))

    _bind_fallback()._maybe_auto_update_intel()      # must return immediately


def test_launch_fallback_stands_down_when_the_service_runs(monkeypatch, settings_sandbox):
    """The service owns updates whenever it exists — the UI must not race it."""
    from ui.core import intel_updater as iu
    from ui.core import service_client as sc

    settings_sandbox["intel_auto_update"] = True
    settings_sandbox["intel_update_on_launch"] = True
    monkeypatch.setattr(sc, "is_service_running", lambda: True)
    monkeypatch.setattr(iu, "run_updates",
                        lambda **kw: pytest.fail("UI ran while the service was up"))

    fake = _bind_fallback()
    fake._maybe_auto_update_intel()
    for _ in range(50):
        if not any(t.name == "IntelLaunchUpdate" and t.is_alive()
                   for t in threading.enumerate()):
            break
        time.sleep(0.02)


def test_launch_fallback_runs_when_due_and_no_service(monkeypatch, settings_sandbox,
                                                      intel_db, hooks):
    from ui.core import intel_updater as iu
    from ui.core import service_client as sc

    settings_sandbox["intel_auto_update"] = True
    settings_sandbox["intel_update_on_launch"] = True
    monkeypatch.setattr(sc, "is_service_running", lambda: False)
    monkeypatch.setattr(iu, "is_anything_due", lambda: True)

    ran = threading.Event()

    def fake_run(**kwargs):
        ran.set()
        return {"status": "updated", "feeds": {"c2": {"status": "updated"}}}

    monkeypatch.setattr(iu, "run_updates", fake_run)

    fake = _bind_fallback()
    fake._maybe_auto_update_intel()
    assert ran.wait(timeout=5)

