"""
Real-time watcher: engine verdicts and the completion contract.

Two layered defects, and fixing only the first would have left the user no
better off.

  * Engine results gated on each other. YARA's and ClamAV's callbacks only did
    anything while `entry["status"] == "clean"`, and Guardian's callback
    overwrote status unconditionally. All three run concurrently, so whenever
    Guardian landed first the YARA/ClamAV branch was skipped entirely --
    including its `notify_cb`. That detection produced no status and no tray
    alert at all.

  * Nobody could see the verdicts anyway. `scan_new_file()` ends in
    `run_scan()`, which returns immediately and works on a background thread,
    so `on_created` fired the detection callbacks with `status == "pending"`
    and the service read `entry.get("status")` on the line *after* calling
    `scan_new_file` -- persisting "pending" into service_events.json for
    essentially every real-time detection.

The contract is now: a detection callback means *scan complete*. Completion
order is driven explicitly here rather than raced -- a test that hopes to win
a race is a test that fails on someone else's machine.
"""
from __future__ import annotations

import threading

import pytest

from ui.core import watcher as wtch


class FakeEngine:
    """Captures the callbacks scan_async was handed, so the test decides when
    -- and in what order -- each engine reports."""

    def __init__(self, available: bool = True):
        self.available = available
        self.calls: list[tuple] = []
        self.launch_error: Exception | None = None

    def is_available(self):
        return self.available

    def scan_async(self, paths, on_result, on_done, **kwargs):
        if self.launch_error:
            raise self.launch_error
        self.calls.append((on_result, on_done, kwargs))

    # -- driving ----------------------------------------------------------
    def report(self, path="C:\\f.exe", infected=False, reason=""):
        on_result, on_done, _ = self.calls[0]
        if infected:
            on_result(path, True, reason)
        on_done(1 if infected else 0)

    def report_done_only(self):
        self.calls[0][1](0)


@pytest.fixture
def pipeline(watcher_sandbox, settings_sandbox, monkeypatch):
    """A scan pipeline whose k2 and engines are all driven by the test."""
    from ui.core import (clamav_engine as ce, guardian_engine as ge,
                         scanner as sc, yara_engine as ye)

    state: dict = {"k2_done": None, "notifications": [], "completions": []}

    def fake_run_scan(paths, action, line_cb, prog_cb, done_cb):
        state["k2_done"] = done_cb
        return object()

    monkeypatch.setattr(sc, "run_scan", fake_run_scan)

    engines = {}
    for name, module in (("guardian", ge), ("yara", ye), ("clamav", ce)):
        fake = FakeEngine()
        monkeypatch.setattr(module, "is_available", fake.is_available)
        monkeypatch.setattr(module, "scan_async", fake.scan_async)
        engines[name] = fake
    state["engines"] = engines

    def enable(*names):
        for n in names:
            settings_sandbox[f"watcher_{n}_scan"] = True

    state["enable"] = enable
    return state


def _entry(path=r"C:\downloads\f.exe"):
    return {"path": path, "filename": "f.exe", "time": "now", "status": "pending"}


def _start(state, entry, **kwargs):
    seen = []
    wtch.add_detection_callback(seen.append)
    wtch.scan_new_file(entry["path"], entry,
                       notify_cb=lambda f, m: state["notifications"].append((f, m)),
                       on_complete=state["completions"].append,
                       **kwargs)
    return seen


# ── start / stop ──────────────────────────────────────────────────────────────

def test_start_refuses_with_no_folders_configured(watcher_sandbox, settings_sandbox):
    settings_sandbox["watcher_folders"] = []

    assert wtch.start(lambda p, e: None) is False


def test_start_refuses_when_no_configured_folder_exists(watcher_sandbox,
                                                        settings_sandbox, tmp_path):
    settings_sandbox["watcher_folders"] = [str(tmp_path / "was_deleted")]

    assert wtch.start(lambda p, e: None) is False


def test_stop_is_idempotent(watcher_sandbox):
    wtch.stop()
    wtch.stop()

    assert wtch.is_running() is False


# ── Callback registration ─────────────────────────────────────────────────────

def test_callbacks_can_be_added_and_removed(watcher_sandbox):
    def cb(entry):
        pass

    wtch.add_detection_callback(cb)
    assert cb in wtch._on_detection_callbacks

    wtch.remove_detection_callback(cb)
    assert cb not in wtch._on_detection_callbacks


def test_removing_an_unregistered_callback_is_harmless(watcher_sandbox):
    wtch.remove_detection_callback(lambda e: None)


def test_registration_is_safe_under_concurrency(watcher_sandbox):
    """The list is mutated from view lifecycles and read from scan threads."""
    def churn():
        for _ in range(200):
            cb = lambda e: None
            wtch.add_detection_callback(cb)
            wtch.remove_detection_callback(cb)

    threads = [threading.Thread(target=churn) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert wtch._on_detection_callbacks == []


def test_one_raising_callback_does_not_starve_the_others(watcher_sandbox):
    delivered = []

    def angry(entry):
        raise RuntimeError("the view was destroyed")

    wtch.add_detection_callback(angry)
    wtch.add_detection_callback(delivered.append)

    wtch._notify_detection(_entry())

    assert len(delivered) == 1


# ── Completion timing ─────────────────────────────────────────────────────────

def test_observers_are_not_notified_until_every_engine_reports(pipeline):
    """The defect: observers used to be handed the entry before k2 started."""
    pipeline["enable"]("guardian", "yara")
    entry = _entry()
    seen = _start(pipeline, entry)

    assert seen == [], "notified before the scan even began"

    pipeline["k2_done"](0, None)
    assert seen == [], "notified while secondary engines were still running"

    pipeline["engines"]["guardian"].report()
    assert seen == [], "notified with YARA still outstanding"

    pipeline["engines"]["yara"].report()
    assert len(seen) == 1, "the completion never fired"
    assert seen[0]["status"] == "clean"


def test_the_k2_only_path_completes_once_with_k2s_verdict_present(pipeline):
    """Zero secondary engines is the off-by-one case: the barrier must not
    fire before k2's own verdict has been recorded."""
    entry = _entry()
    seen = _start(pipeline, entry)

    pipeline["k2_done"](0, None)

    assert len(seen) == 1
    assert [v["engine"] for v in entry["verdicts"]] == ["k2"]
    assert entry["status"] == "clean"


def test_a_k2_failure_still_completes_exactly_once(pipeline):
    entry = _entry()
    seen = _start(pipeline, entry)

    pipeline["k2_done"](-1, None)

    assert len(seen) == 1
    assert entry["status"] == "incomplete (K2 error)", (
        "a scan that never ran must not read as clean")


def test_an_enabled_but_unavailable_engine_does_not_hold_the_barrier(pipeline):
    """Enabled in settings is not the same as launched. ClamAV configured but
    not installed used to be indistinguishable from ClamAV still running."""
    pipeline["enable"]("guardian", "clamav")
    pipeline["engines"]["clamav"].available = False
    entry = _entry()
    seen = _start(pipeline, entry)

    pipeline["k2_done"](0, None)
    pipeline["engines"]["guardian"].report()

    assert len(seen) == 1, "an engine that never ran kept the barrier open"
    assert [v["engine"] for v in entry["verdicts"]] == ["k2", "guardian"]


def test_a_duplicate_on_done_does_not_notify_twice(pipeline):
    pipeline["enable"]("guardian")
    entry = _entry()
    seen = _start(pipeline, entry)

    pipeline["k2_done"](0, None)
    pipeline["engines"]["guardian"].report()
    pipeline["engines"]["guardian"].report_done_only()      # engine misbehaves

    assert len(seen) == 1, "a duplicate on_done produced a duplicate event"


def test_an_engine_that_fails_to_launch_does_not_hang_the_barrier(pipeline):
    """A launch that raises never calls on_done. A barrier that never fires
    means the detection is never recorded at all -- worse than the original
    bug."""
    pipeline["enable"]("guardian", "yara")
    pipeline["engines"]["yara"].launch_error = RuntimeError("rules failed to compile")
    entry = _entry()
    seen = _start(pipeline, entry)

    pipeline["k2_done"](0, None)
    pipeline["engines"]["guardian"].report()

    assert len(seen) == 1
    assert entry["status"] == "incomplete (YARA error)"


# ── Verdict survival ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("order", [
    ["guardian", "yara", "clamav"],      # the order that used to lose results
    ["clamav", "yara", "guardian"],
])
def test_every_engines_verdict_survives_in_any_completion_order(pipeline, order):
    """The headline regression.

    Guardian's callback set status unconditionally; YARA's and ClamAV's only
    ran while status was still "clean". So whenever Guardian finished first,
    both other engines' findings -- and their tray alerts -- vanished.
    """
    pipeline["enable"]("guardian", "yara", "clamav")
    entry = _entry()
    seen = _start(pipeline, entry)

    pipeline["k2_done"](0, None)
    for name in order:
        pipeline["engines"][name].report(infected=True, reason=f"{name} hit")

    assert len(seen) == 1
    infected = {v["engine"] for v in entry["verdicts"] if v["infected"]}
    assert infected == {"guardian", "yara", "clamav"}, (
        f"a verdict was discarded when engines completed in order {order}")


@pytest.mark.parametrize("order", [
    ["guardian", "yara"],
    ["yara", "guardian"],
])
def test_every_engine_raises_its_own_tray_alert(pipeline, order):
    """notify_cb used to live inside the status gate, so a suppressed verdict
    also meant a suppressed alert -- the detection was entirely silent."""
    pipeline["enable"]("guardian", "yara")
    entry = _entry()
    _start(pipeline, entry)

    pipeline["k2_done"](0, None)
    for name in order:
        pipeline["engines"][name].report(infected=True, reason=f"{name} hit")

    messages = [m for _f, m in pipeline["notifications"]]
    assert any(m.startswith("Guardian:") for m in messages)
    assert any(m.startswith("YARA:") for m in messages)


# ── Status reduction ──────────────────────────────────────────────────────────

def test_a_k2_threat_outranks_everything(pipeline):
    pipeline["enable"]("guardian")
    entry = _entry()
    _start(pipeline, entry)

    pipeline["k2_done"](1, None)
    pipeline["engines"]["guardian"].report(infected=True, reason="pattern")

    assert entry["status"] == "threat found"


def test_a_secondary_detection_names_the_engine(pipeline):
    pipeline["enable"]("yara")
    entry = _entry()
    _start(pipeline, entry)

    pipeline["k2_done"](0, None)
    pipeline["engines"]["yara"].report(infected=True, reason="rule match")

    assert entry["status"] == "suspicious (YARA)"


def test_clean_requires_every_launched_engine_to_have_completed_cleanly(pipeline):
    """"clean" is the only status that earns the green all-clear in both
    renderers, so an engine that errored must not be able to produce it."""
    pipeline["enable"]("guardian", "clamav")
    pipeline["engines"]["clamav"].launch_error = RuntimeError("clamscan missing")
    entry = _entry()
    _start(pipeline, entry)

    pipeline["k2_done"](0, None)
    pipeline["engines"]["guardian"].report()

    assert entry["status"] != "clean"
    assert entry["status"] == "incomplete (ClamAV error)"


def test_the_completion_callback_receives_the_finished_entry(pipeline):
    """What the Windows Service now uses instead of reading entry["status"]
    on the line after calling scan_new_file."""
    pipeline["enable"]("guardian")
    entry = _entry()
    _start(pipeline, entry)

    pipeline["k2_done"](0, None)
    pipeline["engines"]["guardian"].report(infected=True, reason="sig")

    assert len(pipeline["completions"]) == 1
    completed = pipeline["completions"][0]
    assert completed["status"] == "suspicious (Guardian)"
    assert completed["status"] != "pending", (
        "the service would have persisted this into service_events.json")


def test_a_raising_completion_callback_does_not_break_the_observers(pipeline):
    entry = _entry()
    seen = []
    wtch.add_detection_callback(seen.append)

    def angry(e):
        raise RuntimeError("service is shutting down")

    wtch.scan_new_file(entry["path"], entry, on_complete=angry)
    pipeline["k2_done"](0, None)

    assert len(seen) == 1


# ── Guardian pattern gating ───────────────────────────────────────────────────

def test_guardian_runs_signatures_only_at_watcher_cadence_by_default(pipeline):
    """v1.10 default: pattern false positives cascade at real-time speed --
    every new file in Downloads, Desktop and USB mounts trips them."""
    pipeline["enable"]("guardian")
    entry = _entry()
    _start(pipeline, entry)

    pipeline["k2_done"](0, None)

    _on_result, _on_done, kwargs = pipeline["engines"]["guardian"].calls[0]
    assert kwargs["use_patterns_override"] is False


def test_patterns_are_passed_through_when_the_user_opts_in(pipeline,
                                                           settings_sandbox):
    pipeline["enable"]("guardian")
    settings_sandbox["watcher_guardian_patterns"] = True
    entry = _entry()
    _start(pipeline, entry)

    pipeline["k2_done"](0, None)

    assert pipeline["engines"]["guardian"].calls[0][2]["use_patterns_override"] is True
