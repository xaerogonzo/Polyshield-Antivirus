"""
The ClamAV engine's verdict and failure contract.

Same concern as test_yara_engine.py, one layer over: ClamAV is a subprocess
engine, so "the engine failed" has more shapes -- clamscan.exe missing, Popen
refusing to start it, the process dying part-way through a scan it was
streaming results from. Every one of those used to end in on_done(count) with
no error signal, which scan_view logs as "Done - no threats found".

clamscan.exe does not exist on a CI runner, so nothing here executes it: the
engine's `subprocess` reference is swapped for a shim and the process is faked.
"""
from __future__ import annotations

import subprocess
import threading

import pytest

from ui.core import clamav_engine as ce


# -- Fake subprocess ----------------------------------------------------------

class _FakeProc:
    """Stands in for the clamscan.exe Popen object."""

    def __init__(self, lines=(), returncode=0, stdout_raises=None):
        self._lines = list(lines)
        self._stdout_raises = stdout_raises
        self.returncode = returncode
        self.pid = 4242
        self.terminated = False
        self.waited = False
        self.stdout = self._stream()

    def _stream(self):
        for line in self._lines:
            yield line
        if self._stdout_raises is not None:
            raise self._stdout_raises

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.waited = True
        return self.returncode

    def poll(self):
        return self.returncode


class _FakeSubprocess:
    """The subprocess module with Popen swapped for a factory.

    __getattr__ falls through to the real module, so CREATE_NO_WINDOW, PIPE and
    DEVNULL keep their real values. Patching subprocess.Popen directly would
    mutate the stdlib module for the whole process.
    """

    def __init__(self, proc=None, popen_raises=None, run_result=None):
        self._proc = proc
        self._popen_raises = popen_raises
        self._run_result = run_result
        self.popen_calls: list[tuple] = []
        self.file_lists: list[str] = []

    def Popen(self, argv, **kwargs):
        self.popen_calls.append((argv, kwargs))
        # Read the --file-list while it still exists: the engine unlinks it in
        # its own finally, so a test that opened it afterwards would be reading
        # a deleted path rather than testing expansion.
        for arg in argv:
            if isinstance(arg, str) and arg.startswith("--file-list="):
                with open(arg.split("=", 1)[1], encoding="utf-8") as fh:
                    self.file_lists.append(fh.read())
        if self._popen_raises is not None:
            raise self._popen_raises
        return self._proc

    def run(self, argv, **kwargs):
        return self._run_result

    def __getattr__(self, name):
        return getattr(subprocess, name)


@pytest.fixture
def clamav_installed(tmp_path, monkeypatch, settings_sandbox):
    """A directory that looks like a ClamAV install, and nothing more.

    _find_exe() only asks whether clamscan.exe is a file, so an empty file at
    the right name is a complete stand-in -- and guarantees the suite can never
    execute a real scanner even on a machine that has one installed.
    """
    install = tmp_path / "clamav"
    install.mkdir()
    (install / "clamscan.exe").write_bytes(b"")
    settings_sandbox["clamav_path"] = str(install)
    monkeypatch.setattr(ce, "_COMMON_PATHS", [])
    return install


class _Collector:
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


def _sample(tmp_path, name="f.bin", size=8):
    p = tmp_path / name
    p.write_bytes(b"x" * size)
    return p


# -- Locating the executable --------------------------------------------------

def test_the_configured_path_wins_over_the_common_locations(
        tmp_path, monkeypatch, settings_sandbox):
    configured = tmp_path / "custom"
    configured.mkdir()
    (configured / "clamscan.exe").write_bytes(b"")
    fallback = tmp_path / "common"
    fallback.mkdir()
    (fallback / "clamscan.exe").write_bytes(b"")
    settings_sandbox["clamav_path"] = str(configured)
    monkeypatch.setattr(ce, "_COMMON_PATHS", [str(fallback)])

    assert ce._find_exe("clamscan.exe") == configured / "clamscan.exe"


def test_is_available_is_false_when_clamscan_is_not_installed(
        monkeypatch, settings_sandbox):
    settings_sandbox["clamav_path"] = ""
    monkeypatch.setattr(ce, "_COMMON_PATHS", [])

    assert ce.is_available() is False


def test_get_version_returns_the_first_line(monkeypatch, clamav_installed):
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(
        run_result=subprocess.CompletedProcess(
            [], 0, stdout="ClamAV 1.0.1/27000\nsecond line\n", stderr="")))

    assert ce.get_version() == "ClamAV 1.0.1/27000"


def test_get_version_is_empty_without_an_executable(monkeypatch, settings_sandbox):
    settings_sandbox["clamav_path"] = ""
    monkeypatch.setattr(ce, "_COMMON_PATHS", [])

    assert ce.get_version() == ""


# -- Normal scanning ----------------------------------------------------------

def test_a_clean_file_is_reported_clean(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    sample = _sample(tmp_path)
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(
        proc=_FakeProc([f"{sample}: OK\n"])))
    run_engines_inline(ce)
    c = _Collector()

    ce.scan_async([str(sample)], c.on_result, c.on_done)

    assert c.results == [(str(sample), False, "")]
    assert c.done == [0]


def test_a_detection_carries_the_threat_name(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    sample = _sample(tmp_path)
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(
        proc=_FakeProc([f"{sample}: Win.Test.EICAR_HDB-1 FOUND\n"])))
    run_engines_inline(ce)
    c = _Collector()

    ce.scan_async([str(sample)], c.on_result, c.on_done)

    assert c.results == [(str(sample), True, "ClamAV: Win.Test.EICAR_HDB-1")]
    assert c.done == [1]


def test_a_windows_path_with_a_colon_still_splits_correctly(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    """Every path on this platform contains a drive colon; the split is rfind."""
    sample = _sample(tmp_path)
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(
        proc=_FakeProc([r"C:\Users\x\thing.exe: Trojan.Foo FOUND" + "\n"])))
    run_engines_inline(ce)
    c = _Collector()

    ce.scan_async([str(sample)], c.on_result, c.on_done)

    assert c.results == [(r"C:\Users\x\thing.exe", True, "ClamAV: Trojan.Foo")]


def test_a_directory_is_expanded_into_its_files(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    """clamscan --file-list does not descend; the engine must expand first."""
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "a.bin").write_bytes(b"a")
    (tree / "sub" / "b.bin").write_bytes(b"b")
    shim = _FakeSubprocess(proc=_FakeProc([]))
    monkeypatch.setattr(ce, "subprocess", shim)
    run_engines_inline(ce)
    c = _Collector()

    ce.scan_async([str(tree)], c.on_result, c.on_done)

    assert shim.popen_calls, "the scanner was never started"
    listed = shim.file_lists[0]
    assert "a.bin" in listed and "b.bin" in listed


def test_progress_counts_the_expanded_files_not_the_arguments(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    tree = tmp_path / "tree"
    tree.mkdir()
    files = []
    for i in range(3):
        f = tree / f"f{i}.bin"
        f.write_bytes(b"x")
        files.append(f)
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(
        proc=_FakeProc([f"{f}: OK\n" for f in files])))
    run_engines_inline(ce)
    c = _Collector()

    ce.scan_async([str(tree)], c.on_result, c.on_done, on_progress=c.on_progress)

    assert [p[:2] for p in c.progress] == [(1, 3), (2, 3), (3, 3)]


# -- The failure taxonomy -----------------------------------------------------

def test_a_missing_executable_is_reported_as_an_error(
        monkeypatch, tmp_path, settings_sandbox, run_engines_inline):
    """Not the same as a scan that ran and found nothing."""
    settings_sandbox["clamav_path"] = ""
    monkeypatch.setattr(ce, "_COMMON_PATHS", [])
    run_engines_inline(ce)
    sample = _sample(tmp_path)
    c = _Collector()

    ce.scan_async([str(sample)], c.on_result, c.on_done, on_error=c.on_error)

    assert c.errors, "a missing scanner must not read as a completed scan"
    assert c.done == [0]


def test_a_popen_failure_is_reported_as_an_error(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(
        popen_raises=OSError("cannot start clamscan")))
    run_engines_inline(ce)
    sample = _sample(tmp_path)
    c = _Collector()

    ce.scan_async([str(sample)], c.on_result, c.on_done, on_error=c.on_error)

    assert len(c.errors) == 1
    assert "cannot start clamscan" in c.errors[0]
    assert c.done == [0]


def test_a_scanner_that_exits_with_an_error_is_not_reported_as_clean(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    """clamscan exit 2 means the scan itself failed, not that nothing matched."""
    sample = _sample(tmp_path)
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(
        proc=_FakeProc([], returncode=2)))
    run_engines_inline(ce)
    c = _Collector()

    ce.scan_async([str(sample)], c.on_result, c.on_done, on_error=c.on_error)

    assert c.errors, "exit code 2 is a failed scan, not an all-clear"
    assert c.done == [0]


def test_partial_output_followed_by_a_crash_is_reported_as_an_error(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    """The worst shape: some real verdicts, then the process dies.

    The count is genuine as far as it goes, which is exactly why it is
    misleading on its own -- the caller has no way to know the scan stopped
    early unless it is told.
    """
    a, b = _sample(tmp_path, "a.bin"), _sample(tmp_path, "b.bin")
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(
        proc=_FakeProc([f"{a}: Trojan.X FOUND\n"],
                       stdout_raises=OSError("pipe died"))))
    run_engines_inline(ce)
    c = _Collector()

    ce.scan_async([str(a), str(b)], c.on_result, c.on_done, on_error=c.on_error)

    assert c.done == [1], "the detection it did find is still reported"
    assert c.errors, "but the caller must learn the scan did not finish"


def test_cancellation_is_distinguishable_from_completion(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    """A cancelled scan is not an error, and not a clean bill of health."""
    sample = _sample(tmp_path)
    cancel = threading.Event()
    cancel.set()
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(
        proc=_FakeProc([f"{sample}: OK\n"])))
    run_engines_inline(ce)
    c = _Collector()

    ce.scan_async([str(sample)], c.on_result, c.on_done,
                  cancel_event=cancel, on_error=c.on_error)

    assert c.done == [0]
    assert c.results == []


def test_the_error_arrives_before_the_completion_signal(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    """Same ordering guarantee as YARA: on_done releases the watcher barrier."""
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(
        popen_raises=OSError("nope")))
    run_engines_inline(ce)
    sample = _sample(tmp_path)
    order: list[str] = []

    ce.scan_async([str(sample)],
                  lambda *_: None,
                  lambda _count: order.append("done"),
                  on_error=lambda _msg: order.append("error"))

    assert order == ["error", "done"]


def test_a_caller_that_passes_no_error_handler_still_completes(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(
        popen_raises=OSError("nope")))
    run_engines_inline(ce)
    sample = _sample(tmp_path)
    c = _Collector()

    ce.scan_async([str(sample)], c.on_result, c.on_done)

    assert c.done == [0]


# -- The oversize skip, pinned as it stands -----------------------------------

def test_an_oversize_file_named_directly_is_reported_clean(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    """Pinned, not endorsed. See docs/TESTING.md on the skip contract.

    A file too large to scan produces the same (False, "") a scanned-and-clean
    file produces. It is not counted as a detection, so no threat total is
    wrong -- but the verdict itself claims more than the engine did.
    """
    monkeypatch.setattr(ce, "_MAX_FILE_MB", 0)
    sample = _sample(tmp_path, size=32)
    shim = _FakeSubprocess(proc=_FakeProc([]))
    monkeypatch.setattr(ce, "subprocess", shim)
    run_engines_inline(ce)
    c = _Collector()

    ce.scan_async([str(sample)], c.on_result, c.on_done)

    assert c.results == [(str(sample), False, "")]
    assert shim.popen_calls == [], "an oversize file must not reach the scanner"


def test_an_oversize_file_found_by_expansion_is_reported_not_at_all(
        monkeypatch, tmp_path, clamav_installed, run_engines_inline):
    """The same file, reached a different way, produces no verdict at all.

    Pinned to document the asymmetry rather than to bless it: the direct path
    above emits a clean verdict, this one emits nothing. Making a skipped file
    say so in its own right changes on_result's shape across all three engines
    and every consumer, which is wider than this PR carries.
    """
    monkeypatch.setattr(ce, "_MAX_FILE_MB", 0)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "big.bin").write_bytes(b"x" * 32)
    monkeypatch.setattr(ce, "subprocess", _FakeSubprocess(proc=_FakeProc([])))
    run_engines_inline(ce)
    c = _Collector()

    ce.scan_async([str(tree)], c.on_result, c.on_done)

    assert c.results == []
    assert c.done == [0]
