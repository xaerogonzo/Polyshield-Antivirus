"""
The scan pipeline's orchestration — which engines run, in what order, and what
happens when the user interrupts.

Six engines share one queue, one cancel event and one pause event, and every
one of them reports back on the Tk main thread. The failures that matter here
are not wrong verdicts but wrong *sequencing*: an engine silently dropped from
the queue, a second callback re-entering finalize and wiping the results panel,
a stop that leaves a suspended subprocess unkillable.

None of these run a real engine. The dispatch table in _run_secondary_engines
maps each engine to (checkbox var, availability probe, run function), which is
the seam: patch the probes, swap the run functions for recorders, and the
queue's behaviour is observable without scanning anything.
"""
from __future__ import annotations

import threading

import pytest

from ui.views import scan_view as sv
from ui.views.scan_view import _classify, _format_eta, _human_size

_ALL_ENGINES = ("k2", "guardian", "yara", "clamav", "defender")


@pytest.fixture
def available_engines(monkeypatch):
    """Make every engine report as installed.

    Availability is probed against the real machine — k2.exe on disk, ClamAV
    under Program Files, the yara module importable. Left alone, these tests
    would assert different things on a developer's box than on a CI runner.
    """
    monkeypatch.setattr(sv.sc, "is_available", lambda: True)
    monkeypatch.setattr(sv.ge, "is_available", lambda: True)
    monkeypatch.setattr(sv.ye, "is_available", lambda: True)
    monkeypatch.setattr(sv.ce, "is_available", lambda: True)
    monkeypatch.setattr(sv.df, "is_mpcmdrun_available", lambda: True)


@pytest.fixture
def view(tk_root, settings_sandbox, available_engines):
    """A built ScanView on the shared root, with a recorded status bar."""
    messages: list[str] = []
    v = sv.ScanView(tk_root, status_callback=messages.append,
                    navigate_callback=lambda *a: None)
    v.status_messages = messages
    yield v
    try:
        v.destroy()
    except Exception:
        pass


def _record_engines(view, monkeypatch):
    """Swap each _run_*_scan for a recorder that advances the queue.

    Advancing matters: an engine reports completion by calling _run_next_engine
    on the main thread, so a recorder that only records would stop the pipeline
    after its first step and every ordering assertion would pass vacuously.
    """
    order: list[str] = []

    def recorder(name):
        def _run(paths):
            order.append(name)
            view._run_next_engine()
        return _run

    for name in _ALL_ENGINES:
        monkeypatch.setattr(view, f"_run_{name}_scan", recorder(name))
    return order


@pytest.fixture
def queue_probe(view, monkeypatch):
    """Recorders in place, with the tail of the pipeline stubbed out."""
    order = _record_engines(view, monkeypatch)
    monkeypatch.setattr(view, "_maybe_run_speakeasy_pipeline",
                        lambda: order.append("<end>"))
    return order


def _enable(view, *engine_ids):
    for name in _ALL_ENGINES:
        getattr(view, f"_{name}_var").set(name in engine_ids)


# -- Queue construction -------------------------------------------------------

def test_engines_run_in_the_configured_pipeline_order(view, queue_probe, settings_sandbox):
    settings_sandbox["pipeline_order"] = ["clamav", "k2", "guardian", "yara", "defender"]
    _enable(view, *_ALL_ENGINES)

    view._run_secondary_engines(["C:\\tmp"])

    assert queue_probe == ["clamav", "k2", "guardian", "yara", "defender", "<end>"]


def test_a_disabled_engine_is_left_out(view, queue_probe, settings_sandbox):
    settings_sandbox["pipeline_order"] = list(sv.ScanView._DEFAULT_PIPELINE_ORDER)
    _enable(view, "k2", "guardian")

    view._run_secondary_engines(["C:\\tmp"])

    assert queue_probe == ["k2", "guardian", "<end>"]


def test_an_unavailable_engine_is_left_out_even_when_enabled(
        view, queue_probe, settings_sandbox, monkeypatch):
    """The checkbox can be on from a previous install where ClamAV existed."""
    settings_sandbox["pipeline_order"] = list(sv.ScanView._DEFAULT_PIPELINE_ORDER)
    _enable(view, "k2", "clamav")
    monkeypatch.setattr(sv.ce, "is_available", lambda: False)

    view._run_secondary_engines(["C:\\tmp"])

    assert queue_probe == ["k2", "<end>"]


def test_no_engines_still_reaches_the_end_of_the_pipeline(
        view, queue_probe, settings_sandbox):
    """A scan with everything switched off must still finish rather than
    leaving the UI stuck in its scanning state."""
    _enable(view)

    view._run_secondary_engines(["C:\\tmp"])

    assert queue_probe == ["<end>"]


def test_a_cancel_before_the_queue_is_built_skips_every_engine(
        view, queue_probe, settings_sandbox, monkeypatch):
    """Stop pressed while K2 was still running: the cancel event is already
    set by the time the secondaries are scheduled."""
    finalized = []
    monkeypatch.setattr(view, "_finalize_scan",
                        lambda aborted=False: finalized.append(aborted))
    _enable(view, *_ALL_ENGINES)
    view._pipeline_cancel_event = threading.Event()
    view._pipeline_cancel_event.set()

    view._run_secondary_engines(["C:\\tmp"])

    assert queue_probe == []
    assert finalized == [True], "a cancelled pipeline must finalize as aborted"


def test_a_cancel_midway_stops_the_remaining_engines(
        view, settings_sandbox, monkeypatch):
    """Stop pressed while the second engine was running. Engines already
    finished keep their results; the rest never start."""
    settings_sandbox["pipeline_order"] = ["k2", "guardian", "yara", "clamav", "defender"]
    _enable(view, *_ALL_ENGINES)
    view._pipeline_cancel_event = threading.Event()

    order: list[str] = []
    finalized: list[bool] = []
    monkeypatch.setattr(view, "_finalize_scan",
                        lambda aborted=False: finalized.append(aborted))
    monkeypatch.setattr(view, "_maybe_run_speakeasy_pipeline",
                        lambda: order.append("<end>"))

    def recorder(name):
        def _run(paths):
            order.append(name)
            if name == "guardian":
                view._pipeline_cancel_event.set()
            view._run_next_engine()
        return _run

    for name in _ALL_ENGINES:
        monkeypatch.setattr(view, f"_run_{name}_scan", recorder(name))

    view._run_secondary_engines(["C:\\tmp"])

    assert order == ["k2", "guardian"]
    assert finalized == [True]


# -- Pipeline order normalisation ---------------------------------------------

def test_an_engine_missing_from_saved_settings_is_restored(view, settings_sandbox):
    """Upgrading from a v1.6.0 config, whose saved order predates K2 becoming
    a peer engine. A silently dropped engine is a silently disabled one."""
    settings_sandbox["pipeline_order"] = ["defender", "guardian", "yara", "clamav"]

    assert set(view._normalized_pipeline_order()) == set(sv.ScanView._DEFAULT_PIPELINE_ORDER)


def test_normalisation_keeps_the_users_ordering(view, settings_sandbox):
    settings_sandbox["pipeline_order"] = ["clamav", "yara", "guardian", "defender"]

    result = view._normalized_pipeline_order()

    assert [e for e in result if e != "k2"] == ["clamav", "yara", "guardian", "defender"]


def test_an_empty_saved_order_falls_back_to_every_engine(view, settings_sandbox):
    settings_sandbox["pipeline_order"] = []

    assert view._normalized_pipeline_order() == list(sv.ScanView._DEFAULT_PIPELINE_ORDER)


# -- Finalize -----------------------------------------------------------------

def test_finalize_is_idempotent(view, monkeypatch):
    """Two engines reporting completion, or a stop racing a natural finish,
    both land here twice. The second pass must not rebuild the results panel
    the user is already reading."""
    builds = []
    monkeypatch.setattr(view, "_build_threat_actions", lambda: builds.append(1))
    monkeypatch.setattr(view, "_check_disputes", lambda: None)
    view._scanning = True
    view._scan_start_time = 0.0

    view._finalize_scan()
    view._finalize_scan()

    assert builds == [1]


def test_finalize_clears_the_scanning_state(view, monkeypatch):
    monkeypatch.setattr(view, "_build_threat_actions", lambda: None)
    monkeypatch.setattr(view, "_check_disputes", lambda: None)
    view._scanning = True
    view._paused = True
    view._scan_start_time = 0.0

    view._finalize_scan()

    assert view._scanning is False
    assert view._paused is False
    assert str(view._scan_btn.cget("state")) == "normal"


def test_disputes_are_checked_only_on_a_complete_run(view, monkeypatch):
    """Half a pipeline is not disagreement: if Guardian never ran, every K2
    detection would read as a dispute."""
    checked = []
    monkeypatch.setattr(view, "_build_threat_actions", lambda: None)
    monkeypatch.setattr(view, "_check_disputes", lambda: checked.append(1))
    view._scan_start_time = 0.0

    view._scanning = True
    view._finalize_scan(aborted=True)
    assert checked == []

    view._scanning = True
    view._finalize_scan(aborted=False)
    assert checked == [1]


def test_a_failing_dispute_check_does_not_break_finalize(view, monkeypatch):
    """Dispute detection is a convenience. It must never be able to leave the
    Start button disabled and the view stuck mid-scan."""
    def _boom():
        raise RuntimeError("dispute check exploded")

    monkeypatch.setattr(view, "_build_threat_actions", lambda: None)
    monkeypatch.setattr(view, "_check_disputes", _boom)
    view._scanning = True
    view._scan_start_time = 0.0

    view._finalize_scan()

    assert view._scanning is False


# -- Pause and stop -----------------------------------------------------------

class _FakeController:
    """Stands in for the K2 ScanController's suspend/resume/kill surface.

    Records whether the shared pause event was already released at the moment
    cancel() arrived. Resuming the k2.exe process itself is ScanController's
    own responsibility (its cancel() resumes before killing); what the view
    owes the pipeline is releasing the event the other engines block on.
    """

    def __init__(self, view=None):
        self.view = view
        self.paused = False
        self.cancelled = False
        self.pause_event_released_at_cancel = None

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def cancel(self):
        if self.view is not None:
            self.pause_event_released_at_cancel = \
                self.view._pipeline_pause_event.is_set()
        self.cancelled = True


def test_pause_drives_both_the_shared_event_and_the_k2_controller(view):
    """Guardian and YARA block on the event; K2 is a suspended subprocess.
    Pausing one without the other leaves half the pipeline running."""
    view._scanning = True
    view._pipeline_pause_event = threading.Event()
    view._pipeline_pause_event.set()
    view._scan_ctrl = _FakeController()

    view._toggle_pause()

    assert view._paused is True
    assert not view._pipeline_pause_event.is_set()
    assert view._scan_ctrl.paused is True


def test_resume_releases_both(view):
    view._scanning = True
    view._pipeline_pause_event = threading.Event()
    view._pipeline_pause_event.set()
    view._scan_ctrl = _FakeController()

    view._toggle_pause()
    view._toggle_pause()

    assert view._paused is False
    assert view._pipeline_pause_event.is_set()
    assert view._scan_ctrl.paused is False


def test_pause_does_nothing_when_no_scan_is_running(view):
    view._scanning = False
    view._pipeline_pause_event = threading.Event()
    view._pipeline_pause_event.set()

    view._toggle_pause()

    assert view._paused is False
    assert view._pipeline_pause_event.is_set()


def test_stop_releases_the_pause_before_cancelling(view):
    """Windows ignores TerminateProcess on a suspended process, and Guardian
    and YARA sit blocked in pause_event.wait(). Cancelling while the event is
    still cleared leaves those loops parked and never checking the cancel flag,
    so a paused scan becomes an unstoppable one."""
    view._scanning = True
    view._pipeline_pause_event = threading.Event()
    view._pipeline_pause_event.set()
    view._pipeline_cancel_event = threading.Event()
    view._scan_ctrl = _FakeController(view)

    view._toggle_pause()
    assert not view._pipeline_pause_event.is_set()

    view._stop_scan()

    assert view._pipeline_pause_event.is_set()
    assert view._pipeline_cancel_event.is_set()
    assert view._scan_ctrl.cancelled is True
    assert view._scan_ctrl.pause_event_released_at_cancel is True, (
        "the pause event must be released before the engines are cancelled")
    assert view._paused is False


def test_stop_does_nothing_when_no_scan_is_running(view):
    view._scanning = False
    view._pipeline_cancel_event = threading.Event()

    view._stop_scan()

    assert not view._pipeline_cancel_event.is_set()


# -- Module-level helpers -----------------------------------------------------

def test_log_lines_are_classified_by_keyword():
    assert _classify("infected: C:\\tmp\\evil.exe") == sv._TAG_INFECTED
    assert _classify("Some ordinary progress line") == sv._TAG_INFO


def test_eta_formatting_across_magnitudes():
    assert _format_eta(0) == "—"
    assert _format_eta(-5) == "—", "a negative estimate must not render as a duration"
    assert _format_eta(45) == "45s"
    assert _format_eta(90) == "1m 30s"
    assert _format_eta(3700) == "1h 1m"


def test_human_size_across_magnitudes():
    assert _human_size(512) == "512 B"
    assert _human_size(1536) == "1.5 KB"
    assert _human_size(5 * 1024 * 1024) == "5.0 MB"


def test_dropped_paths_are_parsed_out_of_the_brace_quoted_form(view):
    """Tk hands drag-and-drop paths back brace-quoted when they contain
    spaces — the common case on Windows, where most user folders do."""
    parsed = view._parse_dnd_paths(r"{C:\Program Files\thing.exe} C:\tmp\plain.exe")

    assert parsed == [r"C:\Program Files\thing.exe", r"C:\tmp\plain.exe"]


def test_a_single_unquoted_path_with_spaces_survives(view):
    parsed = view._parse_dnd_paths(r"{C:\Users\Test User\Downloads\file.zip}")

    assert parsed == [r"C:\Users\Test User\Downloads\file.zip"]


# -- VirusTotal gating --------------------------------------------------------

def test_vt_check_is_off_by_default(view):
    assert sv.ScanView._should_vt_check("C:\\tmp\\x.exe", [], {}, "off") is False


def test_pattern_level_checks_detections_virustotal_could_actually_inform(view):
    """The 'pattern' level spends quota where a second opinion adds something:
    a heuristic guess, or a hash hit the local DB could not put a name to.
    A hit already attributed to a family with an engine count is not improved
    by asking again."""
    path = "C:\\tmp\\x.exe"

    def _check(reason):
        return sv.ScanView._should_vt_check(path, [], {path: reason}, "pattern")

    assert _check("Suspicious pattern: MSHTA remote payload") is True
    assert _check("Known Signature (MD5: abc…)") is True, (
        "an unattributed hash hit is exactly what VirusTotal can name")
    assert _check("Emotet  [7 engines]") is False
    assert _check("NSRL (known-safe system file)") is False


def test_dual_level_checks_anything_both_engines_saw(view):
    path = "C:\\tmp\\x.exe"

    assert sv.ScanView._should_vt_check(
        path, [path], {path: "Known Signature (MD5: abc…)"}, "dual") is True
