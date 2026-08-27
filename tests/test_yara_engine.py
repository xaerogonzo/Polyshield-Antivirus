"""
The YARA engine's verdict and failure contract.

test_scan_pipeline.py drives the engine *queue*; nothing until now has run
yara_engine's own logic. The question here is what a caller can tell apart: a
clean file, a detection, a ruleset that will not compile, and an engine that
threw. Today those last two are spelled the same way as the first, and the
watcher's completion barrier reserves "clean" for runs where every launched
engine actually completed -- see docs/TESTING.md, "The watcher callback
contract".

yara-python is installed on a development machine but deliberately absent from
requirements-ci.txt, so every test here injects a fake `yara` module rather than
importing the real one. A test that imported yara would pass here and skip in
CI, which is precisely the local-vs-CI difference this suite exists to catch.
"""
from __future__ import annotations

import sys
import threading
import types

import pytest

from ui.core import yara_engine as ye


# -- Fake yara-python ---------------------------------------------------------

class _FakeMatch:
    def __init__(self, rule: str):
        self.rule = rule


class _FakeRules:
    """Stands in for a compiled yara.Rules object."""

    def __init__(self, matches=(), raises: BaseException | None = None):
        self._matches = list(matches)
        self._raises = raises
        self.calls: list[tuple] = []

    def match(self, path, timeout=None):
        self.calls.append((path, timeout))
        if self._raises is not None:
            raise self._raises
        return [_FakeMatch(r) for r in self._matches]


def _install_fake_yara(monkeypatch, *, rules=None, compile_raises=None):
    """Put a fake `yara` in sys.modules and return it.

    yara_engine imports yara *inside* is_available() and _compile(), so a
    sys.modules entry is enough -- no import-order games.
    """
    mod = types.ModuleType("yara")

    class Error(Exception):
        pass

    class TimeoutError(Error):       # noqa: A001 - mirrors yara-python's name
        pass

    mod.Error = Error
    mod.TimeoutError = TimeoutError
    mod.compile_calls = []

    def _compile(filepaths=None, **_):
        mod.compile_calls.append(filepaths)
        if compile_raises is not None:
            raise compile_raises
        return rules

    mod.compile = _compile
    monkeypatch.setitem(sys.modules, "yara", mod)
    return mod


def _write_rule(directory, name="sample.yar", body="rule R { condition: true }"):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(body, encoding="utf-8")
    return path


class _Collector:
    """Records everything an engine tells its caller."""

    def __init__(self):
        self.results: list[tuple] = []
        self.done: list[int] = []
        self.progress: list[tuple] = []
        self.errors: list[str] = []

    def on_result(self, fpath, infected, reason):
        self.results.append((fpath, infected, reason))

    def on_done(self, count):
        self.done.append(count)

    def on_progress(self, done, total, current):
        self.progress.append((done, total, current))

    def on_error(self, message):
        self.errors.append(message)


# -- Rule discovery and the .active generation pointer ------------------------

def test_the_active_pointer_selects_one_generation(yara_sandbox):
    _user, community = yara_sandbox
    _write_rule(community / "gen-2", "b.yar")
    _write_rule(community / "gen-1", "a.yar")
    (community / ".active").write_text("gen-2", encoding="utf-8")

    assert ye.active_community_dir() == community / "gen-2"


def test_superseded_generations_are_never_compiled(yara_sandbox):
    """The invariant that makes a rules update all-or-nothing for a scan."""
    _user, community = yara_sandbox
    _write_rule(community / "gen-1", "old.yar")
    _write_rule(community / "gen-2", "new.yar")
    (community / ".active").write_text("gen-2", encoding="utf-8")

    found = {p.name for p in ye._all_yar_files()}

    assert found == {"new.yar"}


def test_a_pointer_to_a_missing_generation_falls_back_to_the_flat_directory(yara_sandbox):
    _user, community = yara_sandbox
    _write_rule(community, "loose.yar")
    (community / ".active").write_text("gen-does-not-exist", encoding="utf-8")

    assert ye.active_community_dir() == community


def test_an_install_with_no_pointer_uses_the_flat_directory(yara_sandbox):
    """Installs predating the generation layout keep loose .yar files."""
    _user, community = yara_sandbox
    _write_rule(community, "loose.yar")

    assert ye.active_community_dir() == community
    assert {p.name for p in ye._all_yar_files()} == {"loose.yar"}


def test_missing_rule_directories_are_not_an_error(yara_sandbox):
    assert ye.active_community_dir() is None
    assert ye._all_yar_files() == []
    assert ye.get_rule_count() == 0


def test_rule_count_spans_user_and_community_rules(yara_sandbox):
    user, community = yara_sandbox
    _write_rule(user, "mine.yar")
    _write_rule(community, "theirs.yar")

    assert ye.get_rule_count() == 2


# -- is_available: runtime present AND rule files exist -----------------------

def test_is_available_is_false_without_the_yara_runtime(monkeypatch, yara_sandbox):
    user, _community = yara_sandbox
    _write_rule(user)
    monkeypatch.setitem(sys.modules, "yara", None)   # makes `import yara` raise

    assert ye.is_available() is False


def test_is_available_is_false_without_rule_files(monkeypatch, yara_sandbox):
    _install_fake_yara(monkeypatch, rules=_FakeRules())

    assert ye.is_available() is False


def test_is_available_reports_the_runtime_and_rules_not_compilability(
        monkeypatch, yara_sandbox):
    """Invariant A, pinned deliberately.

    is_available() answers "the runtime is installed and there are rules to
    compile" -- it does not compile them. Making it answer "the ruleset
    compiles" would put a full compile on the hot path (the watcher calls this
    per file event) and would re-create the failure shape recorded in
    WINDOWS_SERVICE.md: a malformed rule would drop YARA out of the pipeline
    silently, never queued and never launched, with nothing to report. The
    engine stays available and reports the compile failure instead -- see
    test_a_ruleset_that_cannot_compile_reaches_the_caller_as_an_error.
    """
    user, _community = yara_sandbox
    _write_rule(user)
    _install_fake_yara(monkeypatch, compile_raises=Exception("syntax error"))

    assert ye.is_available() is True
    assert ye._compile() is None


# -- scan_file: one file, pre-compiled rules ----------------------------------

def test_a_match_reports_every_rule_that_fired(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"payload")
    rules = _FakeRules(matches=["Dropper_A", "Dropper_B"])

    infected, reason = ye.scan_file(str(sample), rules)

    assert infected is True
    assert reason == "YARA: Dropper_A, Dropper_B"


def test_a_clean_file_reports_no_reason(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"payload")

    infected, reason = ye.scan_file(str(sample), _FakeRules())

    assert (infected, reason) == (False, "")


def test_the_scan_timeout_is_passed_to_the_matcher(tmp_path):
    """A 10s cap per file is the guard against hanging on a huge binary."""
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"payload")
    rules = _FakeRules()

    ye.scan_file(str(sample), rules)

    assert rules.calls == [(str(sample), ye._SCAN_TIMEOUT)]


@pytest.mark.parametrize("failure", [
    pytest.param(RuntimeError("rule threw"), id="matcher-raised"),
    pytest.param(MemoryError("out of memory"), id="matcher-out-of-memory"),
])
def test_a_matcher_failure_is_not_reported_as_clean(tmp_path, failure):
    """An engine that could not answer must not answer "clean".

    This is the defect the watcher PR named as the worst of the three: a
    consumer cannot distinguish "ran and found nothing" from "failed to produce
    a result", and a failure reading as clean earns the green all-clear.
    """
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"payload")

    infected, reason = ye.scan_file(str(sample), _FakeRules(raises=failure))

    assert infected is False
    assert reason != "", "a matcher failure is indistinguishable from a clean file"


def test_a_scan_timeout_is_not_reported_as_clean(monkeypatch, tmp_path):
    mod = _install_fake_yara(monkeypatch)
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"payload")

    infected, reason = ye.scan_file(
        str(sample), _FakeRules(raises=mod.TimeoutError("timed out")))

    assert infected is False
    assert reason != "", "a 10s timeout is indistinguishable from a clean file"


def test_an_unreadable_file_is_not_reported_as_clean(tmp_path):
    missing = tmp_path / "gone.bin"

    infected, reason = ye.scan_file(str(missing), _FakeRules())

    assert infected is False
    assert reason != "", "an unreadable file is indistinguishable from a clean file"


def test_a_file_over_the_size_cap_is_skipped_not_scanned(monkeypatch, tmp_path):
    """Pinned as it stands today; see docs/TESTING.md on the skip contract.

    A skipped file currently spells itself exactly like a clean one. Fixing
    that means changing on_result's shape across all three engines and every
    consumer, which is wider than this PR carries.
    """
    monkeypatch.setattr(ye, "_MAX_FILE_MB", 0)
    sample = tmp_path / "big.bin"
    sample.write_bytes(b"x" * 32)
    rules = _FakeRules(matches=["WouldHaveMatched"])

    infected, reason = ye.scan_file(str(sample), rules)

    assert (infected, reason) == (False, "")
    assert rules.calls == [], "an oversize file must not reach the matcher"


# -- scan_async: the run-level contract ---------------------------------------

def test_every_scanned_path_gets_exactly_one_result(
        monkeypatch, tmp_path, yara_sandbox, run_engines_inline):
    user, _community = yara_sandbox
    _write_rule(user)
    _install_fake_yara(monkeypatch, rules=_FakeRules())
    run_engines_inline(ye)
    paths = []
    for i in range(3):
        p = tmp_path / f"f{i}.bin"
        p.write_bytes(b"payload")
        paths.append(str(p))
    c = _Collector()

    ye.scan_async(paths, c.on_result, c.on_done, on_progress=c.on_progress)

    assert [r[0] for r in c.results] == paths
    assert c.done == [0]
    assert [p[:2] for p in c.progress] == [(1, 3), (2, 3), (3, 3)]


def test_the_infected_count_matches_the_reported_detections(
        monkeypatch, tmp_path, yara_sandbox, run_engines_inline):
    user, _community = yara_sandbox
    _write_rule(user)
    _install_fake_yara(monkeypatch, rules=_FakeRules(matches=["Hit"]))
    run_engines_inline(ye)
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"payload")
    c = _Collector()

    ye.scan_async([str(sample)], c.on_result, c.on_done)

    assert c.done == [1]
    assert c.results == [(str(sample), True, "YARA: Hit")]


def test_cancellation_stops_the_scan_early(
        monkeypatch, tmp_path, yara_sandbox, run_engines_inline):
    user, _community = yara_sandbox
    _write_rule(user)
    _install_fake_yara(monkeypatch, rules=_FakeRules())
    run_engines_inline(ye)
    cancel = threading.Event()
    cancel.set()
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"payload")
    c = _Collector()

    ye.scan_async([str(sample)], c.on_result, c.on_done, cancel_event=cancel)

    assert c.results == []
    assert c.done == [0]


def test_an_empty_ruleset_ends_the_scan_without_scanning_anything(
        monkeypatch, tmp_path, yara_sandbox, run_engines_inline):
    """No rule files at all: nothing to do, and nothing was claimed."""
    _install_fake_yara(monkeypatch, rules=None)
    run_engines_inline(ye)
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"payload")
    c = _Collector()

    ye.scan_async([str(sample)], c.on_result, c.on_done, on_error=c.on_error)

    assert c.results == []
    assert c.done == [0]


def test_a_ruleset_that_cannot_compile_reaches_the_caller_as_an_error(
        monkeypatch, tmp_path, yara_sandbox, run_engines_inline):
    """The core defect.

    One malformed rule file makes _compile() return None, exactly as an empty
    rules directory does. The scan then ends with on_done(0) and no results --
    which scan_view logs as "Done - no rule matches" and the watcher derives as
    "clean". YARA has silently stopped contributing while still advertising
    itself as available.
    """
    user, _community = yara_sandbox
    _write_rule(user)
    _install_fake_yara(monkeypatch, compile_raises=Exception("syntax error"))
    run_engines_inline(ye)
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"payload")
    c = _Collector()

    ye.scan_async([str(sample)], c.on_result, c.on_done, on_error=c.on_error)

    assert c.errors, "a ruleset that will not compile must not read as a clean scan"
    assert c.done == [0]


def test_the_error_arrives_before_the_completion_signal(
        monkeypatch, tmp_path, yara_sandbox, run_engines_inline):
    """Ordering is load-bearing, not incidental.

    on_done is what releases the watcher's completion barrier, and the barrier
    derives the entry status the moment the last engine reports. An error
    delivered after on_done would arrive to find the verdict already recorded
    and "clean" already published.
    """
    user, _community = yara_sandbox
    _write_rule(user)
    _install_fake_yara(monkeypatch, compile_raises=Exception("syntax error"))
    run_engines_inline(ye)
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"payload")
    order: list[str] = []

    ye.scan_async([str(sample)],
                  lambda *_: None,
                  lambda _count: order.append("done"),
                  on_error=lambda _msg: order.append("error"))

    assert order == ["error", "done"]


def test_a_file_that_cannot_be_scanned_is_reported_as_an_error(
        monkeypatch, tmp_path, yara_sandbox, run_engines_inline):
    """A per-file failure reaches the caller too, not only a compile failure."""
    user, _community = yara_sandbox
    _write_rule(user)
    _install_fake_yara(
        monkeypatch, rules=_FakeRules(raises=RuntimeError("rule threw")))
    run_engines_inline(ye)
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"payload")
    c = _Collector()

    ye.scan_async([str(sample)], c.on_result, c.on_done, on_error=c.on_error)

    assert c.done == [0]
    assert len(c.errors) == 1
    assert "rule threw" in c.errors[0]


def test_many_failures_are_summarised_rather_than_concatenated(
        monkeypatch, tmp_path, yara_sandbox, run_engines_inline):
    user, _community = yara_sandbox
    _write_rule(user)
    _install_fake_yara(
        monkeypatch, rules=_FakeRules(raises=RuntimeError("boom")))
    run_engines_inline(ye)
    paths = []
    for i in range(10):
        p = tmp_path / f"f{i}.bin"
        p.write_bytes(b"payload")
        paths.append(str(p))
    c = _Collector()

    ye.scan_async(paths, c.on_result, c.on_done, on_error=c.on_error)

    assert len(c.errors) == 1, "one summary, not one message per file"
    assert "+7 more" in c.errors[0]


def test_a_caller_that_passes_no_error_handler_still_completes(
        monkeypatch, tmp_path, yara_sandbox, run_engines_inline):
    """on_error is additive: every existing call site omits it."""
    user, _community = yara_sandbox
    _write_rule(user)
    _install_fake_yara(monkeypatch, compile_raises=Exception("syntax error"))
    run_engines_inline(ye)
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"payload")
    c = _Collector()

    ye.scan_async([str(sample)], c.on_result, c.on_done)

    assert c.done == [0]
