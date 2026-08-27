"""
The one interface all three scanning engines claim to share.

guardian_engine, yara_engine and clamav_engine each document their scan_async
as "matches guardian_engine.scan_async() signature", and both real drivers --
scan_view._run_*_scan and watcher._make_launch -- call them through a single
code path that assumes exactly that. Nothing has ever asserted it.

This is a contract test, not an engine-correctness test: each engine's actual
scanning is stubbed, and what is checked is the shape of the conversation it
has with its caller. The per-engine verdict logic lives in
test_guardian_tiers.py, test_yara_engine.py and test_clamav_engine.py.

Deliberately NOT asserted: that the engines report progress at the same point
inside their loops. YARA reports before scanning a file and ClamAV after, and
no production caller consumes that ordering -- scan_view only forwards the
numbers to a progress bar. Pinning it would be inventing a requirement.
"""
from __future__ import annotations

import subprocess
import sys
import threading
import types

import pytest

from ui.core import clamav_engine as ce
from ui.core import guardian_engine as ge
from ui.core import yara_engine as ye

from test_clamav_engine import _FakeProc, _FakeSubprocess
from test_yara_engine import _FakeRules, _install_fake_yara


class _Recorder:
    def __init__(self):
        self.results: list[tuple] = []
        self.done: list[int] = []
        self.progress: list[tuple] = []
        self.errors: list[str] = []
        self.order: list[str] = []

    def on_result(self, fpath, infected, reason):
        self.results.append((fpath, infected, reason))

    def on_done(self, count):
        self.done.append(count)
        self.order.append("done")

    def on_progress(self, done, total, current):
        self.progress.append((done, total, current))

    def on_error(self, message):
        self.errors.append(message)
        self.order.append("error")


# -- Adapters: one per engine, each set up to scan cleanly --------------------

def _setup_guardian(monkeypatch, tmp_path, sample):
    monkeypatch.setattr(ge, "is_available", lambda: True)

    class _StubScanner:
        def reset_scan_session(self):
            pass

        def scan_file(self, fpath, use_patterns_override=None):
            return False, "", "clean", ""

    monkeypatch.setattr(ge, "_get_scanner", lambda: _StubScanner())
    return ge


def _setup_yara(monkeypatch, tmp_path, sample):
    rules_dir = tmp_path / "user_rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "r.yar").write_text("rule R { condition: true }", encoding="utf-8")
    monkeypatch.setattr(ye, "_USER_DIR", rules_dir)
    monkeypatch.setattr(ye, "_COMMUNITY_DIR", tmp_path / "community")
    monkeypatch.setattr(ye, "_ACTIVE_PTR", tmp_path / "community" / ".active")
    _install_fake_yara(monkeypatch, rules=_FakeRules())
    return ye


def _setup_clamav(monkeypatch, tmp_path, sample, settings_sandbox):
    install = tmp_path / "clamav"
    install.mkdir(exist_ok=True)
    (install / "clamscan.exe").write_bytes(b"")
    settings_sandbox["clamav_path"] = str(install)
    monkeypatch.setattr(ce, "_COMMON_PATHS", [])
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(
        proc=_FakeProc([f"{sample}: OK\n"])))
    return ce


_ENGINES = ["guardian", "yara", "clamav"]


@pytest.fixture
def engine(request, monkeypatch, tmp_path, settings_sandbox, guardian_sandbox,
           run_engines_inline):
    """Return one engine module, stubbed so a scan completes cleanly."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"harmless")

    if request.param == "guardian":
        module = _setup_guardian(monkeypatch, tmp_path, sample)
    elif request.param == "yara":
        module = _setup_yara(monkeypatch, tmp_path, sample)
    else:
        module = _setup_clamav(monkeypatch, tmp_path, sample, settings_sandbox)

    run_engines_inline(module)
    return module, str(sample)


@pytest.mark.parametrize("engine", _ENGINES, indirect=True)
def test_a_clean_scan_reports_one_result_per_file(engine):
    module, sample = engine
    r = _Recorder()

    module.scan_async([sample], r.on_result, r.on_done)

    assert [x[0] for x in r.results] == [sample]
    assert [x[1] for x in r.results] == [False]


@pytest.mark.parametrize("engine", _ENGINES, indirect=True)
def test_completion_is_signalled_exactly_once(engine):
    module, sample = engine
    r = _Recorder()

    module.scan_async([sample], r.on_result, r.on_done)

    assert r.done == [0]


@pytest.mark.parametrize("engine", _ENGINES, indirect=True)
def test_progress_uses_the_documented_three_argument_shape(engine):
    module, sample = engine
    r = _Recorder()

    module.scan_async([sample], r.on_result, r.on_done, on_progress=r.on_progress)

    assert r.progress, "no progress was reported at all"
    for done, total, current in r.progress:
        assert isinstance(done, int) and isinstance(total, int)
        assert isinstance(current, str)
        assert done <= total


@pytest.mark.parametrize("engine", _ENGINES, indirect=True)
def test_a_cancelled_scan_still_signals_completion(engine):
    """The pipeline advances on on_done; an engine that skips it stalls the run."""
    module, sample = engine
    cancel = threading.Event()
    cancel.set()
    r = _Recorder()

    module.scan_async([sample], r.on_result, r.on_done, cancel_event=cancel)

    assert r.done == [0]
    assert r.results == []


@pytest.mark.parametrize("engine", _ENGINES, indirect=True)
def test_a_set_pause_event_does_not_block_a_running_scan(engine):
    """SET means running. Passing one must not change the outcome."""
    module, sample = engine
    running = threading.Event()
    running.set()
    r = _Recorder()

    module.scan_async([sample], r.on_result, r.on_done, pause_event=running)

    assert r.done == [0]
    assert [x[0] for x in r.results] == [sample]


@pytest.mark.parametrize("engine", _ENGINES, indirect=True)
def test_every_engine_accepts_an_error_handler(engine):
    """The shared failure channel: accepted by all three, fired by none here."""
    module, sample = engine
    r = _Recorder()

    module.scan_async([sample], r.on_result, r.on_done, on_error=r.on_error)

    assert r.errors == []
    assert r.done == [0]


@pytest.mark.parametrize("engine", _ENGINES, indirect=True)
def test_an_engine_that_cannot_run_reports_an_error_before_completing(
        engine, monkeypatch, tmp_path, settings_sandbox):
    """The state the watcher's completion barrier needs to see.

    Each engine is broken in the way that is native to it -- Guardian loses its
    signatures, YARA's rules will not compile, ClamAV's executable disappears
    -- and all three must say so through the same channel, before on_done.
    """
    module, sample = engine
    if module is ge:
        monkeypatch.setattr(ge, "is_available", lambda: False)
    elif module is ye:
        _install_fake_yara(monkeypatch, compile_raises=Exception("syntax error"))
    else:
        settings_sandbox["clamav_path"] = ""
    r = _Recorder()

    module.scan_async([sample], r.on_result, r.on_done, on_error=r.on_error)

    assert r.errors, "a broken engine reported a completed scan"
    assert r.order == ["error", "done"], "the error must precede completion"
