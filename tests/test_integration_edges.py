r"""
Four small modules where PolyShield touches Windows, none of which had a test.

Grouped because each is a thin, self-contained boundary surface with no
existing coverage -- *not* because they form a subsystem. Registry writes,
schtasks command construction, autorun parsing and the VirusTotal request
shape are four unrelated things that happen to share a size and a risk profile:
each is the last hop before something outside this process, so a mistake shows
up as Windows quietly doing nothing rather than as a traceback.

Nothing here touches the real registry, the real Task Scheduler, or the
network. The winreg fake follows test_system_surface.py; the subprocess and
urlopen stubs follow test_ps_run.py and test_intel_updater.py.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.error

import pytest

from ui.core import paths

#: The repository itself. Several assertions below deliberately read the real
#: tree rather than a fixture -- a mocked path cannot notice a file that moved.
_ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
from ui.core import scheduler as sch
from ui.core import shell_ext
from ui.core import startup_scanner as ss
from ui.core import virustotal as vt


# ══ Fake winreg ═══════════════════════════════════════════════════════════════

class _FakeKey:
    def __init__(self, store: dict, path: str):
        self.store = store
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class _FakeWinreg:
    """A dict-backed registry: {(hive, path): {value_name: data}}.

    Only what shell_ext and startup_scanner actually call. Writes are
    observable, so a test can assert what would have been written to HKCU
    without going near the real hive.
    """

    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"
    REG_SZ = 1
    REG_BINARY = 3
    REG_DWORD = 4
    KEY_READ = 0x20019
    KEY_SET_VALUE = 0x0002
    KEY_WOW64_64KEY = 0x0100

    def __init__(self):
        self.tree: dict = {}
        self.open_errors: dict = {}     # path -> exception to raise on OpenKey
        self.delete_errors: dict = {}   # path -> exception to raise on DeleteKey

    # -- reads --
    def OpenKey(self, hive, subkey, reserved=0, access=None):
        if subkey in self.open_errors:
            raise self.open_errors[subkey]
        if (hive, subkey) not in self.tree:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return _FakeKey(self.tree, subkey)

    def EnumValue(self, key, index):
        items = list(self.tree[(self._hive_of(key.path), key.path)].items())
        if index >= len(items):
            raise OSError(259, "No more data is available")
        name, data = items[index]
        return name, data, self.REG_SZ

    def _hive_of(self, path):
        for (hive, p) in self.tree:
            if p == path:
                return hive
        return self.HKEY_CURRENT_USER

    # -- writes --
    def CreateKey(self, hive, subkey):
        self.tree.setdefault((hive, subkey), {})
        return _FakeKey(self.tree, subkey)

    def SetValueEx(self, key, name, reserved, type_, data):
        for (hive, p), values in self.tree.items():
            if p == key.path:
                values[name] = data
                return
        raise FileNotFoundError(2, "no such key")

    def DeleteKey(self, hive, subkey):
        if subkey in self.delete_errors:
            raise self.delete_errors[subkey]
        if (hive, subkey) not in self.tree:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        del self.tree[(hive, subkey)]

    # -- single values --
    # autostart writes a VALUE under a key Windows owns, so it needs these three
    # where shell_ext only ever needed whole keys.
    def QueryValueEx(self, key, name):
        values = self.tree[(self._hive_of(key.path), key.path)]
        if name not in values:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        data = values[name]
        return data, (self.REG_BINARY if isinstance(data, (bytes, bytearray))
                      else self.REG_SZ)

    def DeleteValue(self, key, name):
        values = self.tree[(self._hive_of(key.path), key.path)]
        if name not in values:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        del values[name]


@pytest.fixture
def registry(monkeypatch):
    """One fake hive, shared by every module that writes to the real one.

    shell_ext and autostart both live in HKCU and a teardown removes both, so
    giving them separate fakes would let a test tear down against a tree nothing
    was written to and call that a pass.
    """
    from ui.core import autostart, dev_install

    fake = _FakeWinreg()
    # dev_install too. Leaving it out is how three register_all() tests below
    # wrote and then deleted the developer's real Settings > Apps entry on every
    # run of the suite. conftest's autouse floor now catches that as well.
    for mod in (shell_ext, autostart, dev_install):
        monkeypatch.setattr(mod, "winreg", fake)
        monkeypatch.setattr(mod, "_HKCU", fake.HKEY_CURRENT_USER)
    return fake


@pytest.fixture
def run_registry(monkeypatch):
    """A fake registry wired into startup_scanner, with its Run keys retargeted.

    _RUN_KEYS is built from the real winreg constants at import time, so the
    hive values have to be rewritten to match the fake's.
    """
    fake = _FakeWinreg()
    monkeypatch.setattr(ss, "winreg", fake)
    monkeypatch.setattr(ss, "_RUN_KEYS", [
        (fake.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    ])
    monkeypatch.setattr(ss, "_STARTUP_FOLDERS", [])
    return fake


# ══ VirusTotal: hash_file ═════════════════════════════════════════════════════

def test_hash_file_returns_all_three_digests(tmp_path):
    p = tmp_path / "sample.bin"
    body = b"content that will be hashed three ways\n"
    p.write_bytes(body)

    res = vt.hash_file(str(p))

    assert res == {
        "md5": hashlib.md5(body).hexdigest(),
        "sha1": hashlib.sha1(body).hexdigest(),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def test_hash_file_reads_past_one_chunk(tmp_path):
    """The read loop is chunked at 64 KiB; a file larger than one chunk must
    hash the whole thing, not the first block."""
    p = tmp_path / "big.bin"
    body = bytes(range(256)) * 1024        # 256 KiB
    p.write_bytes(body)

    assert vt.hash_file(str(p))["sha256"] == hashlib.sha256(body).hexdigest()


def test_hash_file_reports_an_unreadable_file_as_error_only(tmp_path):
    """The failure shape is `error` and *no* digest keys.

    Both callers already branch on it before indexing -- scan_view checks
    `not sha256 or "error" in hashes`, virustotal_view returns early on
    `"error" in hashes` -- so this pins the contract they rely on rather than
    proposing a new one. A caller that indexed blind would raise KeyError, and
    the fix for that would be the caller, not a placeholder digest here.
    """
    res = vt.hash_file(str(tmp_path / "does-not-exist.bin"))

    assert "error" in res
    assert not {"md5", "sha1", "sha256"} & set(res)


# ══ VirusTotal: lookup_hash ═══════════════════════════════════════════════════

class _FakeResponse:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _stub_vt(monkeypatch, outcome):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["headers"] = dict(req.headers)
        seen["timeout"] = timeout
        if isinstance(outcome, BaseException):
            raise outcome
        return _FakeResponse(outcome)

    monkeypatch.setattr(vt.urllib.request, "urlopen", fake_urlopen)
    return seen


_SHA256 = "b" * 64


def test_lookup_hash_refuses_without_an_api_key(monkeypatch):
    """Checked before the request is built, so no key means no network."""
    called = []
    monkeypatch.setattr(vt.urllib.request, "urlopen",
                        lambda *a, **k: called.append(1))

    res = vt.lookup_hash(_SHA256, "")

    assert "error" in res and "API key" in res["error"]
    assert called == []


def test_lookup_hash_sends_the_key_as_a_header_not_a_query_param(monkeypatch):
    """Credentials in a URL end up in logs and proxy history."""
    seen = _stub_vt(monkeypatch, json.dumps({"data": {}}).encode())

    vt.lookup_hash(_SHA256, "SECRET-KEY")

    assert seen["url"] == f"https://www.virustotal.com/api/v3/files/{_SHA256}"
    assert "SECRET-KEY" not in seen["url"]
    # urllib title-cases header names
    assert seen["headers"].get("X-apikey") == "SECRET-KEY"


def test_lookup_hash_returns_the_parsed_body(monkeypatch):
    _stub_vt(monkeypatch, json.dumps({"data": {"id": "abc"}}).encode())
    assert vt.lookup_hash(_SHA256, "k") == {"data": {"id": "abc"}}


@pytest.mark.parametrize("code,fragment", [
    (404, "not found"),
    (401, "Invalid API key"),
    (429, "Rate limit"),
])
def test_lookup_hash_maps_the_documented_http_codes(monkeypatch, code, fragment):
    _stub_vt(monkeypatch, urllib.error.HTTPError(
        "https://x", code, "reason", {}, None))

    res = vt.lookup_hash(_SHA256, "k")
    assert fragment.lower() in res["error"].lower()


def test_a_404_is_reported_as_an_error_like_any_other_failure(monkeypatch):
    """Pinning current behaviour, and flagging it.

    "Never submitted to VirusTotal" is an *absence*, not a failure: the lookup
    worked and the answer is "we have never seen this file". Both views render
    it the same as a broken lookup -- virustotal_view in red under "VirusTotal
    lookup failed", scan_view truncated to 50 characters, which cuts it
    mid-word. docs/TESTING.md draws exactly this distinction for the Windows
    Security probes under "Absent is not the same as unknown".

    Not changed here: what the user should see for an unknown file is a product
    decision, and it would change rendering in two views this PR does not
    otherwise touch.
    """
    _stub_vt(monkeypatch, urllib.error.HTTPError(
        "https://x", 404, "Not Found", {}, None))

    res = vt.lookup_hash(_SHA256, "k")

    assert set(res) == {"error"}, "no key distinguishes absence from failure"


def test_lookup_hash_reports_an_unexpected_status_verbatim(monkeypatch):
    _stub_vt(monkeypatch, urllib.error.HTTPError(
        "https://x", 503, "Service Unavailable", {}, None))

    assert vt.lookup_hash(_SHA256, "k")["error"] == "HTTP 503: Service Unavailable"


def test_lookup_hash_survives_a_transport_failure(monkeypatch):
    _stub_vt(monkeypatch, urllib.error.URLError("connection refused"))
    assert "error" in vt.lookup_hash(_SHA256, "k")


def test_lookup_hash_survives_a_body_that_is_not_json(monkeypatch):
    _stub_vt(monkeypatch, b"<html>gateway timeout</html>")
    assert "error" in vt.lookup_hash(_SHA256, "k")


def test_lookup_hash_async_delivers_to_the_callback(monkeypatch):
    import threading

    _stub_vt(monkeypatch, json.dumps({"data": {"id": "z"}}).encode())
    done = threading.Event()
    got = {}

    def cb(result):
        got.update(result)
        done.set()

    vt.lookup_hash_async(_SHA256, "k", cb)

    assert done.wait(5), "callback never fired"
    assert got == {"data": {"id": "z"}}


# ══ VirusTotal: parse_result ══════════════════════════════════════════════════

def _vt_report(stats=None, results=None, **attrs):
    body = {
        "last_analysis_stats": stats if stats is not None else {},
        "last_analysis_results": results if results is not None else {},
    }
    body.update(attrs)
    return {"data": {"attributes": body}}


def test_parse_result_passes_an_error_through_untouched():
    err = {"error": "Rate limit exceeded."}
    assert vt.parse_result(err) is err


def test_parse_result_summarises_a_report():
    raw = _vt_report(
        stats={"malicious": 3, "suspicious": 1, "undetected": 60, "harmless": 0},
        results={
            "EngineA": {"category": "malicious", "result": "Trojan.Gen"},
            "EngineB": {"category": "undetected", "result": None},
            "EngineC": {"category": "suspicious", "result": "Heur.Susp"},
        },
        meaningful_name="installer.exe",
        sha256=_SHA256,
        type_description="Win32 EXE",
        size=1024,
    )

    res = vt.parse_result(raw)

    assert (res["malicious"], res["suspicious"], res["undetected"]) == (3, 1, 60)
    assert res["name"] == "installer.exe"
    assert res["sha256"] == _SHA256
    assert res["type"] == "Win32 EXE"
    assert res["size"] == 1024


def test_parse_result_lists_only_flagging_engines_sorted_by_name():
    raw = _vt_report(
        stats={"malicious": 2, "undetected": 1},
        results={
            "Zeta":  {"category": "malicious", "result": "Trojan.Z"},
            "Alpha": {"category": "suspicious", "result": "Heur.A"},
            "Mid":   {"category": "undetected", "result": None},
        },
    )

    assert vt.parse_result(raw)["detections"] == [
        {"engine": "Alpha", "result": "Heur.A"},
        {"engine": "Zeta", "result": "Trojan.Z"},
    ]


def test_parse_result_substitutes_a_dash_for_a_missing_engine_verdict():
    raw = _vt_report(stats={"malicious": 1},
                     results={"EngineA": {"category": "malicious"}})
    assert vt.parse_result(raw)["detections"] == [{"engine": "EngineA", "result": "—"}]


def test_total_counts_every_bucket_including_the_ones_that_did_not_run():
    """`total` is the denominator scan_view prints as "N/M engines".

    It sums *all* of last_analysis_stats, so engines that timed out, failed, or
    do not handle the file type are in the denominator. Pinned rather than
    changed: it is the count of engines asked, which is what the ratio claims
    to be, and narrowing it would silently move a number the user reads.
    """
    raw = _vt_report(stats={"malicious": 1, "undetected": 5, "timeout": 2,
                            "failure": 1, "type-unsupported": 3})
    assert vt.parse_result(raw)["total"] == 12


def test_parse_result_falls_back_from_meaningful_name_to_name():
    raw = _vt_report(stats={"malicious": 0}, name="fallback.exe")
    assert vt.parse_result(raw)["name"] == "fallback.exe"


@pytest.mark.parametrize("raw", [
    {},
    {"data": {}},
    {"data": {"attributes": None}},
    {"data": "not-a-dict"},
])
def test_parse_result_reports_a_malformed_body_rather_than_raising(raw):
    assert "error" in vt.parse_result(raw)


# ══ shell_ext ═════════════════════════════════════════════════════════════════

def test_register_writes_all_three_roots(registry):
    ok, msg = shell_ext.register()

    assert ok, msg
    for root in ("*", "Directory", "Drive"):
        base = rf"Software\Classes\{root}\shell\PolyShield"
        assert registry.tree[("HKCU", base)][""] == "Scan with PolyShield"
        assert registry.tree[("HKCU", base + r"\command")][""]


def test_the_menu_icon_names_a_file_that_exists(registry, monkeypatch, tmp_path):
    """Icon came from sys.executable, which is a path to nothing in a build.

    Nuitka reports a python.exe beside the real binary and that file does not
    exist (see paths.running_executable), so Explorer silently showed no icon.
    Silently is the operative word: the command value beside it was already
    routed through paths and was correct, so nothing about the menu looked
    broken except the missing glyph.
    """
    from ui.core import paths

    exe = tmp_path / "PolyShield.exe"
    exe.write_text("binary", encoding="utf-8")
    monkeypatch.setattr(paths, "_FROZEN_OVERRIDE", True)
    monkeypatch.setattr(sys, "argv", [str(exe)])

    shell_ext.register()

    icon = registry.tree[("HKCU", r"Software\Classes\*\shell\PolyShield")]["Icon"]
    assert pathlib.Path(icon).exists(), f"icon points at nothing: {icon}"
    assert icon == str(exe)


def test_the_menu_icon_is_never_taken_from_sys_executable(
        registry, monkeypatch, tmp_path):
    """Pinned separately from the path above, because the two agree in a source
    checkout and only diverge inside a real compiled build."""
    from ui.core import paths

    exe = tmp_path / "PolyShield.exe"
    exe.write_text("binary", encoding="utf-8")
    monkeypatch.setattr(paths, "_FROZEN_OVERRIDE", True)
    monkeypatch.setattr(sys, "argv", [str(exe)])
    monkeypatch.setattr(sys, "executable", str(tmp_path / "does_not_exist.exe"))

    shell_ext.register()

    icon = registry.tree[("HKCU", r"Software\Classes\*\shell\PolyShield")]["Icon"]
    assert icon != sys.executable
    assert "does_not_exist" not in icon


def test_register_removes_the_legacy_kicomav_keys(registry):
    """A rename left entries behind; both would show in the context menu."""
    for root in ("*", "Directory", "Drive"):
        old = rf"Software\Classes\{root}\shell\KicomAV"
        registry.tree[("HKCU", old)] = {"": "Scan with KicomAV"}
        registry.tree[("HKCU", old + r"\command")] = {"": "old.exe"}

    shell_ext.register()

    assert not [p for (_h, p) in registry.tree if "KicomAV" in p]


def test_register_reports_a_write_failure_instead_of_raising(registry, monkeypatch):
    def _denied(*a, **k):
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(registry, "CreateKey", _denied)

    ok, msg = shell_ext.register()
    assert ok is False and "Access is denied" in msg


def test_unregister_removes_command_before_its_parent(registry):
    """DeleteKey refuses a key that still has subkeys, so the order is load-bearing."""
    shell_ext.register()
    deleted: list[str] = []
    real_delete = registry.DeleteKey

    def spy(hive, subkey):
        deleted.append(subkey)
        return real_delete(hive, subkey)

    registry.DeleteKey = spy
    ok, _msg = shell_ext.unregister()

    assert ok
    star = r"Software\Classes\*\shell\PolyShield"
    assert deleted.index(star + r"\command") < deleted.index(star)
    assert not [p for (_h, p) in registry.tree if "PolyShield" in p]


def test_unregister_is_quiet_when_nothing_is_registered(registry):
    ok, msg = shell_ext.unregister()
    assert ok is True and "removed" in msg.lower()


def test_unregister_reports_a_delete_that_failed_for_another_reason(registry):
    shell_ext.register()
    registry.delete_errors[r"Software\Classes\Drive\shell\PolyShield"] = \
        PermissionError(5, "Access is denied")

    ok, msg = shell_ext.unregister()
    assert ok is False and "Access is denied" in msg


def test_is_registered_follows_the_key(registry):
    assert shell_ext.is_registered() is False
    shell_ext.register()
    assert shell_ext.is_registered() is True


def test_is_registered_treats_an_unreadable_key_as_absent(registry):
    """Every read failure reads as "not registered", matching
    win_security._reg_key_exists.

    It used to catch FileNotFoundError alone. is_registered() is called during
    SettingsView._build(), so a PermissionError from a policy-locked hive
    propagated out of a view constructor and took the page down instead of
    leaving a checkbox unticked.
    """
    registry.open_errors[r"Software\Classes\*\shell\PolyShield"] = \
        PermissionError(5, "Access is denied")

    assert shell_ext.is_registered() is False


# -- the command Explorer will run --------------------------------------------

def test_the_registered_command_quotes_every_path_and_passes_one_target(registry):
    r"""The contract Explorer invokes, pinned before Phase 4a repoints it.

    `%1` is a single file: app.py reads exactly one path after --scan, and the
    verb is not registered for multi-select. That is the shape to preserve, not
    to extend.
    """
    shell_ext.register()
    cmd = registry.tree[("HKCU", r"Software\Classes\*\shell\PolyShield\command")][""]

    assert cmd.endswith('"--scan" "%1"')
    assert cmd.count("%1") == 1
    assert cmd.startswith('"')          # interpreter path quoted
    assert 'pythonw.exe"' in cmd
    assert 'app.py"' in cmd


@pytest.mark.parametrize("exe_dir", [
    r"C:\Program Files\PolyShield",     # spaces
    r"C:\Tools (x86)\PolyShield",       # shell metacharacters
    r"C:\Users\Ana Ivanovic\Escritorio",  # non-ASCII neighbours
    r"C:\a&b\PolyShield",               # ampersand
])
def test_the_command_survives_an_awkward_install_directory(
        registry, monkeypatch, exe_dir):
    """Every path in the command is quoted, so a directory with spaces, an
    ampersand or parentheses still produces one parseable command line."""
    # sys directly: shell_ext no longer imports it (the menu icon used to come
    # from sys.executable and now comes from paths.running_executable). This
    # always patched the one shared module object anyway.
    monkeypatch.setattr(sys, "executable", exe_dir + r"\python.exe")

    shell_ext.register()
    cmd = registry.tree[("HKCU", r"Software\Classes\*\shell\PolyShield\command")][""]

    assert cmd.startswith(f'"{exe_dir}\\pythonw.exe"')
    # Three quoted arguments plus the executable: nothing is left bare.
    assert cmd.count('"') == 8


# ══ scheduler ═════════════════════════════════════════════════════════════════

class _Completed:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _stub_schtasks(monkeypatch, *, returncode=0, stdout="", stderr="", raises=None):
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if raises is not None:
            raise raises
        return _Completed(returncode, stdout, stderr)

    monkeypatch.setattr(sch.subprocess, "run", fake_run)
    return calls


def test_create_task_builds_the_schtasks_invocation(monkeypatch):
    calls = _stub_schtasks(monkeypatch)

    ok, _out = sch.create_task(r"C:\Users\me\Downloads", "WEEKLY", "03:30")

    assert ok
    args, _kw = calls[0]
    assert args[:2] == ["schtasks", "/create"]
    assert args[args.index("/tn") + 1] == sch._TASK_NAME
    assert args[args.index("/sc") + 1] == "WEEKLY"
    assert args[args.index("/st") + 1] == "03:30"
    assert "/f" in args, "must overwrite an existing task rather than failing"


def test_the_scheduled_command_quotes_the_scan_path(monkeypatch):
    calls = _stub_schtasks(monkeypatch)

    sch.create_task(r"C:\Program Files\Some App", "DAILY", "02:00")

    args, _kw = calls[0]
    run_cmd = args[args.index("/tr") + 1]
    assert run_cmd.endswith('"C:\\Program Files\\Some App"')
    assert run_cmd.count('"') == 6      # python, script, path -- all quoted


@pytest.mark.parametrize("fn,args", [
    (sch.create_task, (r"C:\x", "DAILY", "01:00")),
    (sch.delete_task, ()),
    (sch.get_task_info, ()),
    (sch.run_now, ()),
])
def test_every_schtasks_call_suppresses_the_console_window(monkeypatch, fn, args):
    """CLAUDE.md makes this a project-wide invariant, and scheduler.py is one of
    the modules it names. A missing flag is a console flash on a GUI app."""
    calls = _stub_schtasks(monkeypatch, stdout='"n","t","s"')

    fn(*args)

    for _args, kwargs in calls:
        assert kwargs.get("creationflags") == subprocess.CREATE_NO_WINDOW


def test_a_schtasks_timeout_is_returned_not_raised(monkeypatch):
    _stub_schtasks(monkeypatch,
                   raises=subprocess.TimeoutExpired(cmd="schtasks", timeout=15))

    ok, msg = sch.run_now()
    assert ok is False and msg


def test_get_task_info_parses_the_csv_row(monkeypatch):
    _stub_schtasks(
        monkeypatch,
        stdout='"PolyShield_ScheduledScan","27/08/2026 02:00:00","Ready"')

    info = sch.get_task_info()

    assert info["exists"] is True
    assert info["next_run"] == "27/08/2026 02:00:00"
    assert info["status"] == "Ready"


def test_get_task_info_falls_back_when_the_row_has_too_few_columns(monkeypatch):
    _stub_schtasks(monkeypatch, stdout='"PolyShield_ScheduledScan"')

    info = sch.get_task_info()
    assert info["exists"] is True
    assert (info["next_run"], info["status"]) == ("—", "—")


def test_get_task_info_reports_any_query_failure_as_not_existing(monkeypatch):
    """Pinning current behaviour, and flagging it.

    A non-zero exit becomes {"exists": False}, so an access-denied query is
    indistinguishable from "no task scheduled" -- SchedulerView reads only
    info.get("exists"). Another instance of the absence-vs-failure distinction
    docs/TESTING.md draws, and left alone here for the same reason as the VT
    404: the consequence is a less informative screen, not a wrong scan.
    """
    _stub_schtasks(monkeypatch, returncode=1,
                   stderr="ERROR: Access is denied.")

    assert sch.get_task_info() == {"exists": False}


def test_run_now_targets_the_named_task(monkeypatch):
    calls = _stub_schtasks(monkeypatch)
    sch.run_now()
    args, _kw = calls[0]
    assert args == ["schtasks", "/run", "/tn", sch._TASK_NAME]


# ══ startup_scanner: _extract_path ════════════════════════════════════════════

@pytest.mark.parametrize("value,expected,why", [
    (r"C:\Windows\notepad.exe",
     r"C:\Windows\notepad.exe", "bare path"),
    ('"C:\\Program Files\\App\\app.exe" --flag',
     r"C:\Program Files\App\app.exe", "quoted path with arguments"),
    (r"C:\Program Files\App\app.exe --flag",
     r"C:\Program Files\App\app.exe", "unquoted path with spaces"),
    (r"rundll32.exe shell32.dll,Control_RunDLL",
     "rundll32.exe", "relative name with arguments"),
    (r"C:\Tools\Setup.EXE /silent",
     r"C:\Tools\Setup.EXE", "uppercase extension"),
    (r"C:\Program Files\App\app.EXE --flag",
     r"C:\Program Files\App\app.EXE", "uppercase extension AND spaces"),
    (r"C:\my.exe.tools\app.exe",
     r"C:\my.exe.tools\app.exe", "'.exe' inside a directory name"),
    (r"C:\Scripts\run.BAT",
     r"C:\Scripts\run.BAT", "a batch file is launchable too"),
    ('"C:\\Unclosed\\quote.exe',
     r"C:\Unclosed\quote.exe", "unterminated quote"),
    (r"C:\Legacy\loader",
     r"C:\Legacy\loader", "no recognisable extension"),
    ("", "", "empty value"),
    ("    ", "", "whitespace only"),
])
def test_extract_path(value, expected, why):
    assert ss._extract_path(value) == expected, why


def test_extract_path_expands_environment_variables(monkeypatch):
    r"""%ProgramFiles%\App\app.exe is an ordinary Run value and never resolved.

    Unexpanded, it fails Path.exists(), so get_scannable_paths() dropped it and
    the executable was never scanned -- silently, since nothing distinguishes
    "not on disk" from "we could not read the value".
    """
    monkeypatch.setenv("PROGRAMFILES", r"C:\Program Files")

    assert ss._extract_path(r"%ProgramFiles%\App\app.exe") == \
        r"C:\Program Files\App\app.exe"


def test_extract_path_leaves_an_unknown_variable_alone(monkeypatch):
    """No worse than before: it stays unresolved and the entry is skipped."""
    monkeypatch.delenv("POLYSHIELD_NOSUCHVAR", raising=False)
    value = r"%POLYSHIELD_NOSUCHVAR%\app.exe"
    assert ss._extract_path(value) == value


def test_extract_path_expands_inside_a_quoted_value(monkeypatch):
    monkeypatch.setenv("APPDATA", r"C:\Users\me\AppData\Roaming")
    assert ss._extract_path('"%APPDATA%\\Vendor\\app.exe" -q') == \
        r"C:\Users\me\AppData\Roaming\Vendor\app.exe"


# ══ startup_scanner: enumeration ══════════════════════════════════════════════

def test_enumerate_reads_every_value_in_a_run_key(run_registry):
    run_registry.tree[("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")] = {
        "Updater": r"C:\Vendor\updater.exe /background",
        "Sync":    r"C:\Vendor\sync.exe",
    }

    items = ss.enumerate_startup_items()

    assert [i["name"] for i in items] == ["Updater", "Sync"]
    assert items[0]["raw_value"] == r"C:\Vendor\updater.exe /background"
    assert items[0]["resolved_path"] == r"C:\Vendor\updater.exe"
    assert items[0]["source"].startswith("Registry: HKCU")


def test_enumerate_survives_a_missing_run_key(run_registry):
    assert ss.enumerate_startup_items() == []


def test_enumerate_marks_whether_the_target_is_on_disk(run_registry, tmp_path):
    real = tmp_path / "present.exe"
    real.write_bytes(b"MZ")
    run_registry.tree[("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")] = {
        "Real": str(real),
        "Ghost": r"C:\nowhere\absent.exe",
    }

    by_name = {i["name"]: i for i in ss.enumerate_startup_items()}
    assert by_name["Real"]["exists"] is True
    assert by_name["Ghost"]["exists"] is False


def test_enumerate_includes_startup_folder_contents(run_registry, tmp_path, monkeypatch):
    folder = tmp_path / "Programs" / "Startup"
    folder.mkdir(parents=True)
    (folder / "shortcut.lnk").write_bytes(b"lnk")
    monkeypatch.setattr(ss, "_STARTUP_FOLDERS", [str(folder)])

    items = ss.enumerate_startup_items()

    assert [i["name"] for i in items] == ["shortcut.lnk"]
    assert items[0]["source"].startswith("Startup folder")


def test_enumerate_skips_a_startup_folder_that_does_not_exist(
        run_registry, tmp_path, monkeypatch):
    monkeypatch.setattr(ss, "_STARTUP_FOLDERS", [str(tmp_path / "no-such-dir")])
    assert ss.enumerate_startup_items() == []


# ══ startup_scanner: get_scannable_paths ══════════════════════════════════════

def test_scannable_paths_keeps_only_existing_files(tmp_path):
    f = tmp_path / "real.exe"
    f.write_bytes(b"MZ")
    items = [
        {"resolved_path": str(f)},
        {"resolved_path": str(tmp_path / "absent.exe")},
        {"resolved_path": str(tmp_path)},          # a directory, not a file
        {"resolved_path": ""},
        {},                                        # no key at all
    ]

    assert ss.get_scannable_paths(items) == [str(f)]


def test_scannable_paths_deduplicates_while_preserving_order(tmp_path):
    a, b = tmp_path / "a.exe", tmp_path / "b.exe"
    for p in (a, b):
        p.write_bytes(b"MZ")
    items = [{"resolved_path": str(x)} for x in (a, b, a)]

    assert ss.get_scannable_paths(items) == [str(a), str(b)]


def test_a_run_key_entry_reaches_the_scan_list_end_to_end(run_registry, tmp_path,
                                                          monkeypatch):
    """The whole point of the module: an autorun must end up scannable.

    Written with an uppercase extension, spaces and an environment variable --
    the three shapes that previously resolved to something that did not exist,
    dropping the executable out of the scan list without a word.
    """
    app_dir = tmp_path / "Program Files" / "Vendor"
    app_dir.mkdir(parents=True)
    exe = app_dir / "agent.EXE"
    exe.write_bytes(b"MZ")
    monkeypatch.setenv("POLYSHIELD_TESTROOT", str(tmp_path))

    run_registry.tree[("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")] = {
        "Vendor Agent":
            r"%POLYSHIELD_TESTROOT%\Program Files\Vendor\agent.EXE --autostart",
    }

    paths = ss.get_scannable_paths(ss.enumerate_startup_items())
    assert paths == [str(exe)]


# ══ The Guardian setup button ═════════════════════════════════════════════════

def test_the_setup_script_is_where_the_button_looks_for_it():
    """The regression test for a button that did nothing.

    guardian_view pointed at scripts/setup_guardian.bat; the file moved to
    scripts/components/ in the scripts reorganisation. Because the launch was
    guarded by a bare `if bat.exists():`, clicking produced no window, no error
    and no status line. Asserting against the real tree is the point -- this is
    exactly the drift that a mocked path would hide.
    """
    from ui.views.guardian_view import GuardianView

    assert GuardianView.SETUP_BAT.is_file(), (
        f"the setup button points at {GuardianView.SETUP_BAT}, which is not there")


class _StubView:
    """Enough of GuardianView to call the handler without building a Tk page."""

    SETUP_BAT = None

    def __init__(self, bat):
        self.SETUP_BAT = bat
        self.said: list[str] = []
        self._status_cb = self.said.append


def test_a_missing_setup_script_is_reported_rather_than_ignored(tmp_path, monkeypatch):
    from ui.views.guardian_view import GuardianView

    launched = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: launched.append(a))
    view = _StubView(tmp_path / "gone.bat")

    GuardianView._open_setup_bat(view)

    assert launched == []
    assert view.said and "not found" in view.said[0].lower()


def test_the_setup_script_is_launched_when_present(tmp_path, monkeypatch):
    from ui.views.guardian_view import GuardianView

    bat = tmp_path / "setup_guardian.bat"
    bat.write_text("@echo off\n", encoding="utf-8")
    launched = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: launched.append(a[0]))
    view = _StubView(bat)

    GuardianView._open_setup_bat(view)

    assert launched == [["cmd", "/c", str(bat)]]
    assert view.said and "launched" in view.said[0].lower()


# ══ autostart ════════════════════════════════════════════════════════════════
#
# The login entry, modelled on the Explorer verb above and tested against the
# same failures, because they are the same two registry writes with different
# consequences: a bad verb produces a menu item that does nothing, a bad Run
# value produces a product that quietly does not start.


def _as():
    from ui.core import autostart

    return autostart


def test_the_startup_command_carries_the_minimized_flag(registry):
    """Without it the login launch opens a 1200x760 window over whatever the
    user was about to do, at every single sign-in."""
    ok, _msg = _as().register()
    assert ok
    assert "--minimized" in _as().current_command()


def test_the_startup_command_is_never_taken_from_sys_executable(registry, monkeypatch):
    r"""The sibling of test_the_menu_icon_is_never_taken_from_sys_executable.

    In a Nuitka build sys.executable names a python.exe beside the real binary
    that DOES NOT EXIST, and this value has to still be valid months from now.
    """
    monkeypatch.setattr(sys, "executable", r"C:\nowhere\python.exe")
    monkeypatch.setattr(paths, "is_frozen", lambda: True)
    monkeypatch.setattr(paths, "running_executable",
                        lambda: pathlib.Path(r"C:\Program Files\PolyShield\PolyShield.exe"))
    _as().register()
    cmd = _as().current_command()
    assert r"C:\nowhere" not in cmd
    assert "PolyShield.exe" in cmd


@pytest.mark.parametrize("exe_dir", [
    r"C:\Program Files\PolyShield",
    r"C:\Users\a b\Poly Shield (x64)",
    r"C:\tools\Poly&Shield",
])
def test_the_startup_command_survives_an_awkward_directory(
        registry, monkeypatch, exe_dir):
    monkeypatch.setattr(paths, "is_frozen", lambda: True)
    monkeypatch.setattr(paths, "running_executable",
                        lambda: pathlib.Path(exe_dir) / "PolyShield.exe")
    _as().register()
    cmd = _as().current_command()
    # One parseable command line: the exe quoted as a unit, the flag outside it.
    assert cmd == f'"{exe_dir}\\PolyShield.exe" "--minimized"'


def test_registering_twice_leaves_one_value(registry):
    a = _as()
    a.register()
    a.register()
    key = (registry.HKEY_CURRENT_USER, a._RUN_KEY)
    assert list(registry.tree[key]) == ["PolyShield"]


def test_unregister_is_quiet_when_nothing_is_registered(registry):
    ok, msg = _as().unregister()
    assert ok is True
    assert "no startup entry" in msg


def test_unregister_removes_the_value_and_not_the_key(registry):
    r"""...\CurrentVersion\Run belongs to Windows and holds every other
    application's entry. Deleting the key would take all of them."""
    a = _as()
    a.register()
    key = (registry.HKEY_CURRENT_USER, a._RUN_KEY)
    registry.tree[key]["SomebodyElse"] = "other.exe"

    assert a.unregister()[0] is True
    assert key in registry.tree
    assert list(registry.tree[key]) == ["SomebodyElse"]


def test_is_registered_treats_an_unreadable_key_as_absent(registry):
    """shell_ext.is_registered's lesson, applied before it can be relearned: a
    PermissionError here propagates out of SettingsView._build()."""
    a = _as()
    a.register()
    registry.open_errors[a._RUN_KEY] = PermissionError(5, "Access is denied")
    assert a.is_registered() is False


def test_is_current_is_false_after_the_checkout_moves(registry, monkeypatch):
    """The failure mode a source install has and a packaged one does not.

    The value embeds an absolute path. Rename the folder and Windows says
    nothing at every subsequent login; the switch in Settings would otherwise
    sit there reading ON over a command that cannot run.
    """
    a = _as()
    monkeypatch.setattr(paths, "is_frozen", lambda: True)
    monkeypatch.setattr(paths, "running_executable",
                        lambda: pathlib.Path(r"D:\Projects\PolyShield\PolyShield.exe"))
    a.register()
    assert a.is_current() is True

    monkeypatch.setattr(paths, "running_executable",
                        lambda: pathlib.Path(r"D:\Archive\PolyShield\PolyShield.exe"))
    assert a.is_registered() is True
    assert a.is_current() is False


# ── StartupApproved: what Task Manager writes ────────────────────────────────
#
# The byte layout below is not folklore. It was dumped from a live machine on
# which two entries had been switched off in Task Manager and the rest had not:
#
#     OneDrive        02 00 00 00 00 00 00 00 00 00 00 00   enabled
#     SecurityHealth  06 00 00 00 00 00 00 00 00 00 00 00   enabled
#     Discord         03 00 00 00 d4 37 9b 21 e2 9e dc 01   DISABLED
#     VoicemodV3      03 00 00 00 b4 9b 0a d0 ab e4 dc 01   DISABLED
#
# Bit 0 of the first byte is set for exactly the disabled pair, and the trailing
# eight bytes are a FILETIME of when that happened. An earlier draft had it as
# bit 1, which is the value most often repeated online and would have reported
# every enabled entry as switched off.

_OBSERVED_ENABLED = bytes.fromhex("02 00 00 00 00 00 00 00 00 00 00 00".replace(" ", ""))
_OBSERVED_ENABLED_HKLM = bytes.fromhex("060000000000000000000000")
_OBSERVED_DISABLED = bytes.fromhex("03000000d4379b21e29edc01")


def _approve(registry, value):
    a = _as()
    key = (registry.HKEY_CURRENT_USER, a._APPROVED_KEY)
    registry.tree.setdefault(key, {})["PolyShield"] = value


@pytest.mark.parametrize(("blob", "expected"), [
    (_OBSERVED_ENABLED, "enabled"),
    (_OBSERVED_ENABLED_HKLM, "enabled"),
    (_OBSERVED_DISABLED, "disabled"),
])
def test_startup_approval_matches_the_observed_bytes(registry, blob, expected):
    _approve(registry, blob)
    assert _as().startup_approval() == expected


def test_no_approval_record_means_enabled(registry):
    """The normal case: nobody has ever touched the Startup tab for this entry."""
    assert _as().startup_approval() == "enabled"


@pytest.mark.parametrize("blob", [b"", b"\x03", b"\x03\x00"])
def test_a_short_value_is_unknown_not_disabled(registry, blob):
    """If Windows changes the representation, saying "we cannot tell" beats
    telling somebody their startup entry is off when it is not."""
    _approve(registry, blob)
    assert _as().startup_approval() == "unknown"


def test_a_wrong_type_is_unknown_not_disabled(registry):
    _approve(registry, "not binary at all")
    assert _as().startup_approval() == "unknown"


def test_startup_approval_never_raises(registry):
    a = _as()
    registry.open_errors[a._APPROVED_KEY] = PermissionError(5, "denied")
    assert a.startup_approval() == "unknown"


# ── status precedence ────────────────────────────────────────────────────────


def test_a_user_disabled_entry_outranks_a_stale_path(registry, monkeypatch):
    """Both are true at once and only one is worth saying.

    Offering Repair here would fix a path the user did not ask about and leave
    the entry still not firing, because they are the one who switched it off.
    """
    a = _as()
    monkeypatch.setattr(paths, "is_frozen", lambda: True)
    monkeypatch.setattr(paths, "running_executable",
                        lambda: pathlib.Path(r"D:\Old\PolyShield.exe"))
    a.register()
    monkeypatch.setattr(paths, "running_executable",
                        lambda: pathlib.Path(r"D:\New\PolyShield.exe"))
    _approve(registry, _OBSERVED_DISABLED)

    assert a.is_current() is False
    assert a.status() == a.STATUS_USER_DISABLED


def test_status_walks_the_whole_ladder(registry, monkeypatch):
    a = _as()
    assert a.status() == a.STATUS_NOT_REGISTERED
    monkeypatch.setattr(paths, "is_frozen", lambda: True)
    monkeypatch.setattr(paths, "running_executable",
                        lambda: pathlib.Path(r"D:\Old\PolyShield.exe"))
    a.register()
    assert a.status() == a.STATUS_OK
    monkeypatch.setattr(paths, "running_executable",
                        lambda: pathlib.Path(r"D:\New\PolyShield.exe"))
    assert a.status() == a.STATUS_STALE


def test_an_unknown_approval_does_not_raise_a_false_alarm(registry):
    a = _as()
    a.register()
    _approve(registry, b"\x03")            # unrecognised layout
    assert a.startup_approval() == "unknown"
    assert a.status() == a.STATUS_OK


# ══ register_all: opt-in, structurally ═══════════════════════════════════════


def test_register_all_does_not_create_the_run_value_by_default(registry):
    """The invariant the whole feature rests on.

    PolyShield writing a Run value because somebody ran an installer that
    mentioned "integration" is the behaviour this is not allowed to have, and
    the way that rule gets broken is a future caller reading `register_all` as
    "register everything".
    """
    from ui.core import integration

    report = integration.register_all()
    assert report["ok"] is True
    assert _as().is_registered() is False
    assert report["steps"]["startup entry"]["detail"] == "not requested"


def test_register_all_creates_it_when_asked(registry):
    from ui.core import integration

    report = integration.register_all(startup=True)
    assert report["ok"] is True
    assert _as().is_registered() is True


def test_unregister_all_removes_the_run_value(registry, monkeypatch):
    from ui.core import integration

    monkeypatch.setattr(integration, "unregister_service",
                        lambda: (True, "stubbed"))
    monkeypatch.setattr(integration, "unregister_scheduled_task",
                        lambda: (True, "stubbed"))
    integration.register_all(startup=True)
    assert _as().is_registered() is True

    report = integration.unregister_all()
    assert report["steps"]["startup entry"]["ok"] is True
    assert _as().is_registered() is False


# ══ dev_install: the Add/Remove Programs entry ═══════════════════════════════


def _di():
    from ui.core import dev_install

    return dev_install


@pytest.fixture
def dev_registry(monkeypatch, registry, tmp_path):
    """`registry`, plus a checkout that actually contains the uninstaller.

    register() refuses to write an entry whose Uninstall button would run a file
    that is not there, so the fixture has to lay one down.
    """
    from ui.core import dev_install

    monkeypatch.setattr(dev_install, "winreg", registry)
    monkeypatch.setattr(dev_install, "_HKCU", registry.HKEY_CURRENT_USER)
    checkout = tmp_path / "PolyShield"
    (checkout / "scripts").mkdir(parents=True)
    (checkout / "scripts" / "uninstall_dev.bat").write_text("@echo off", encoding="utf-8")
    monkeypatch.setattr(paths, "install_root", lambda: checkout)
    monkeypatch.setattr(paths, "is_distribution", lambda: False)
    return checkout


def _values(registry):
    return registry.tree[(registry.HKEY_CURRENT_USER, _di()._UNINSTALL_KEY)]


def test_the_arp_uninstall_string_points_at_the_elevating_wrapper(
        dev_registry, registry):
    """The finding this whole module is shaped around.

    Windows launches an uninstall string UNELEVATED, and the first teardown step
    is the Windows service, which needs elevation. Pointing this at
    `app.py --unregister` would clear the HKCU entries, fail on the service, and
    still show success in Settings > Apps.
    """
    ok, _msg = _di().register()
    assert ok
    value = _values(registry)["UninstallString"]
    assert value.lower().endswith('uninstall_dev.bat"')
    assert "app.py" not in value.lower()
    assert "--unregister" not in value


def test_the_quiet_uninstall_string_is_the_same_script(dev_registry, registry):
    values = _values(registry) if _di().register()[0] else {}
    assert values["QuietUninstallString"] == values["UninstallString"] + " /quiet"


def test_the_display_name_says_this_is_a_development_install(dev_registry, registry):
    """It removes registrations, not the checkout.

    Somebody who finds "PolyShield Security Suite" in Settings > Apps and
    expects the folder to disappear has been misled by us.
    """
    _di().register()
    assert "development install" in _values(registry)["DisplayName"]


def test_the_entry_carries_no_display_icon(dev_registry, registry):
    """There is no .ico in the checkout outside the virtualenvs, and pointing
    this at pythonw.exe puts a Python logo beside PolyShield in the app list --
    worse than the generic icon Windows supplies."""
    _di().register()
    assert "DisplayIcon" not in _values(registry)


def test_the_version_comes_from_one_place(dev_registry, registry):
    from ui.version import __version__

    _di().register()
    assert _values(registry)["DisplayVersion"] == __version__


def test_a_distribution_writes_no_entry_of_its_own(dev_registry, registry, monkeypatch):
    """Inno registers the real one under its AppId. Two entries for one product
    is worse than none."""
    monkeypatch.setattr(paths, "is_distribution", lambda: True)
    ok, msg = _di().register()
    assert ok is True
    assert "packaged" in msg
    assert _di().is_registered() is False


def test_an_entry_is_refused_rather_than_written_without_its_uninstaller(
        dev_registry):
    """An Uninstall button that runs a missing file is worse than no entry: the
    user cannot clear the listing either."""
    (dev_registry / "scripts" / "uninstall_dev.bat").unlink()
    ok, msg = _di().register()
    assert ok is False
    assert "no uninstaller" in msg
    assert _di().is_registered() is False


def test_unregister_is_quiet_when_nothing_is_registered(dev_registry):
    ok, msg = _di().unregister()
    assert ok is True
    assert "no uninstall entry" in msg


def test_is_current_is_false_after_the_checkout_moves(dev_registry, monkeypatch, tmp_path):
    di = _di()
    di.register()
    assert di.is_current() is True

    moved = tmp_path / "Archive" / "PolyShield"
    (moved / "scripts").mkdir(parents=True)
    (moved / "scripts" / "uninstall_dev.bat").write_text("@echo off", encoding="utf-8")
    monkeypatch.setattr(paths, "install_root", lambda: moved)
    assert di.is_registered() is True
    assert di.is_current() is False


def test_is_current_is_false_when_the_uninstaller_is_gone(dev_registry):
    di = _di()
    di.register()
    (dev_registry / "scripts" / "uninstall_dev.bat").unlink()
    assert di.is_registered() is True
    assert di.is_current() is False


# ══ The two scripts are where the code says they are ═════════════════════════


@pytest.mark.parametrize("name", ["install_dev.bat", "uninstall_dev.bat"])
def test_the_dev_installer_scripts_exist(name):
    """The `if bat.exists(): ...` lesson, applied to the pair that a registry
    value and a button both point at."""
    assert (_ROOT_DIR / "scripts" / name).is_file(), f"scripts/{name} is missing"


def test_the_uninstaller_is_where_dev_install_points_it():
    from ui.core import dev_install

    assert dev_install.uninstaller_path().is_file()


def test_the_uninstaller_self_elevates():
    """It is what Windows runs from Settings > Apps, and Windows runs an
    uninstall string as the ordinary user -- while the first teardown step is
    the service, which needs rights."""
    text = (_ROOT_DIR / "scripts" / "uninstall_dev.bat").read_text(encoding="utf-8")
    assert "NET SESSION" in text
    assert "-Verb RunAs" in text


def test_the_installer_does_not_self_elevate():
    r"""Deliberately the opposite of its sibling, and it cost two failed runs to
    learn why.

    Elevating the whole script puts the prompt and every message into a spawned
    console that closes the moment the script ends, so a failure is unreadable
    and a step that silently does nothing is indistinguishable from one that
    worked. It is also the wrong hive: the three per-user registrations write to
    HKCU, and an elevated process writes to the administrator's HKCU when that
    is a different account.

    Only the service step elevates, and setup_service.bat raises that prompt
    itself.
    """
    text = (_ROOT_DIR / "scripts" / "install_dev.bat").read_text(encoding="utf-8")
    body = chr(10).join(ln for ln in text.splitlines()
                     if not ln.strip().upper().startswith("REM"))
    assert "-Verb RunAs" not in body, (
        "install_dev.bat elevates itself again; its prompt and its errors go "
        "into a console that vanishes")
    assert "NET SESSION" not in body
    assert "setup_service.bat" in body, "something still has to register the service"


def test_the_installer_verifies_the_outcome_not_the_existence():
    r"""`sc query` passes for a service that was already registered, so it could
    not tell "this step configured the service" from "this step did nothing".
    That is how a DEMAND_START registration survived a run and was reported as a
    success. Twice."""
    text = (_ROOT_DIR / "scripts" / "install_dev.bat").read_text(encoding="utf-8")
    body = chr(10).join(ln for ln in text.splitlines()
                     if not ln.strip().upper().startswith("REM"))
    assert "service_state()" in body
    assert "sc query" not in body.lower()


def test_the_dev_installer_never_creates_a_distribution_marker():
    r"""The most tempting "make it feel installed" move, and the one that
    destroys the data root.

    paths.is_distribution() reads that marker and flips app_root() from the
    checkout to %ProgramData%\PolyShield, orphaning the existing config,
    quarantine, logs and threat database -- silently, with the app reporting a
    clean first-run state.
    """
    text = (_ROOT_DIR / "scripts" / "install_dev.bat").read_text(encoding="utf-8")
    body = "\n".join(ln for ln in text.splitlines()
                     if not ln.strip().upper().startswith("REM"))
    assert paths.DISTRIBUTION_MARKER not in body
    assert paths.DATA_DIR_ENV not in body


# ══ The packaged installer keeps the same promise ════════════════════════════


def _iss_lines():
    """The .iss with its line continuations joined.

    Inno continues a directive with a trailing backslash, so a raw splitlines()
    puts `Filename:` and the `Tasks:` flag that gates it on different lines --
    and a test reading them separately would pass over an entry that runs
    unconditionally.
    """
    text = (_ROOT_DIR / "installer" / "polyshield.iss").read_text(encoding="utf-8")
    joined, buf = [], ""
    for raw in text.splitlines():
        if raw.rstrip().endswith(chr(92)):
            buf += raw.rstrip()[:-1].rstrip() + " "
            continue
        joined.append(buf + raw.strip())
        buf = ""
    if buf:
        joined.append(buf)
    return joined


def test_the_installer_startup_task_is_unchecked():
    """"Off by default" has to be true of the installer, not just the Settings
    switch. The installer is the one place where a checked-by-default box would
    put a Run value into the registry of everybody who clicked Next."""
    line = next((ln for ln in _iss_lines()
                 if ln.strip().startswith('Name: "startupicon"')), None)
    assert line is not None, "the .iss no longer declares a startupicon task"
    assert "unchecked" in line.lower(), (
        "the packaged installer would enable autostart by default:\n  " + line)


def test_the_installer_registers_autostart_only_under_that_task():
    run_lines = [ln for ln in _iss_lines() if "--register-autostart" in ln]
    assert run_lines, "the .iss never registers the startup entry"
    assert all("Tasks: startupicon" in ln for ln in run_lines)


def test_the_installer_version_matches_the_python_one():
    from ui.version import __version__

    define = next(ln for ln in _iss_lines() if ln.startswith("#define AppVersion"))
    assert f'"{__version__}"' in define, (
        f"installer/polyshield.iss says {define.strip()} and "
        f"ui/version.py says {__version__}")


# ══ Self-elevation ═══════════════════════════════════════════════════════════
#
# `-ArgumentList '%*'` expands to `-ArgumentList ''` when a script is run with
# no arguments, and Windows PowerShell 5.1 validates that parameter as
# NotNullOrEmpty. Every self-elevating script in this repo had it, and every one
# of them normally runs with no arguments -- so none of them could elevate. The
# failure is quiet in exactly the wrong way: PowerShell prints a binding error,
# the batch file exits 0, and the caller sees a step that "succeeded".
#
# It cost two failed installs to find, because the console it printed into
# belonged to a script that self-elevated and vanished. And a check of the
# construct under PowerShell 7, which accepts an empty ArgumentList, cleared it
# wrongly -- the scripts invoke `powershell`, not `pwsh`.

_ELEVATING_SCRIPTS = ["scripts/service/setup_service.bat",
                      "scripts/uninstall_dev.bat",
                      "scripts/vm_setup/build_tiny11_vm.bat"]


@pytest.mark.parametrize("rel", _ELEVATING_SCRIPTS)
def test_self_elevation_omits_an_empty_argument_list(rel):
    text = (_ROOT_DIR / rel).read_text(encoding="utf-8", errors="replace")
    body = chr(10).join(ln for ln in text.splitlines()
                        if not ln.strip().upper().startswith("REM"))
    if "-ArgumentList" not in body:
        return                      # nothing to get wrong
    assert 'if "%*"==""' in body, (
        f"{rel} passes -ArgumentList unconditionally; an argument-less run "
        "expands it to '' and Windows PowerShell 5.1 refuses to bind it")
    # And the no-argument branch must be the one without -ArgumentList.
    guard = body.index('if "%*"==""')
    branch = body[guard:body.index("else", guard)]
    assert "-ArgumentList" not in branch, (
        f"{rel} still passes -ArgumentList on the no-argument branch")


@pytest.mark.parametrize("rel", _ELEVATING_SCRIPTS)
def test_every_elevating_script_actually_tries_to_elevate(rel):
    """The guard above would also pass for a script that stopped elevating."""
    body = (_ROOT_DIR / rel).read_text(encoding="utf-8", errors="replace")
    assert "-Verb RunAs" in body, rel


def test_the_rollback_leaves_a_service_it_did_not_create(monkeypatch):
    r"""install_dev.bat does not elevate, so it never registers a service.

    Its rollback used to call plain --unregister, which asks to delete
    PolyShieldService regardless. That only ever failed harmlessly because the
    script is unelevated -- run the same thing from an elevated shell and a
    failure in an earlier step would take out a working, pre-existing service
    registration as its idea of undoing an install that never touched it.
    """
    from ui.core import integration

    called = []
    for _label, attr in integration._STEPS:
        monkeypatch.setattr(integration, attr,
                            lambda a=attr: (called.append(a), (True, "stub"))[1])

    report = integration.unregister_all(skip_service=True)
    assert "unregister_service" not in called
    assert "service" not in report["steps"]
    assert report["ok"] is True
    # Everything else still runs.
    assert "context menu" in report["steps"]
    assert "uninstall entry" in report["steps"]

    called.clear()
    integration.unregister_all()
    assert "unregister_service" in called, "the default must still remove it"


def test_the_installer_rollback_keeps_the_service():
    body = (_ROOT_DIR / "scripts" / "install_dev.bat").read_text(encoding="utf-8")
    body = chr(10).join(ln for ln in body.splitlines()
                        if not ln.strip().upper().startswith("REM"))
    assert "--unregister --keep-service" in body, (
        "install_dev.bat's rollback would delete a service it never created")


# ══ Batch blocks ═════════════════════════════════════════════════════════════
#
# An unescaped `)` inside a parenthesised block CLOSES that block, and whatever
# followed it on the line is then run as a command. setup_service.bat had
#
#     if errorlevel 1 (
#         echo   Installing pywin32 (not found in venv)...
#
# so cmd closed the `if` at "venv)" and tried to execute "...", producing
#
#     ... was unexpected at this time.
#
# and exiting at step 2 of 8 -- on every run this script has ever had. That is
# why the service was never configured, and why the elevated console it was
# launched in closed instantly: `cmd /C` closes when the batch dies, and the
# `pause` at the end was never reached.
#
# Only the CLOSING paren matters. `(` is harmless, which is why half of
# manage.bat escapes `^)` and leaves `(` bare.

def _echo_lines_inside_blocks(path):
    """(line number, text) for every echo that cmd parses inside a block."""
    import re

    caret = chr(94)
    depth, found = 0, []
    for n, raw in enumerate(path.read_text(encoding="utf-8", errors="replace")
                            .splitlines(), 1):
        line = raw.strip()
        if line.upper().startswith("REM") or line.startswith("::"):
            continue
        is_echo = bool(re.match(r"(?i)^echo\b", line))
        if depth > 0 and is_echo:
            found.append((n, line))
        code = re.sub(r'"[^"]*"', "", line)
        code = re.sub(re.escape(caret) + r"[()]", "", code)
        if is_echo:
            # Echo text is not structure -- that is the bug, not the ruler.
            code = ""
        depth = max(0, depth + code.count("(") - code.count(")"))
    return found


@pytest.mark.parametrize(
    "rel", sorted(p.relative_to(_ROOT_DIR).as_posix()
                  for p in (_ROOT_DIR / "scripts").rglob("*.bat")))
def test_no_batch_echo_closes_its_own_block(rel):
    import re

    caret = chr(94)
    offenders = [
        f"{n}: {text}"
        for n, text in _echo_lines_inside_blocks(_ROOT_DIR / rel)
        if re.search(r"(?<!" + re.escape(caret) + r")\)", text)
    ]
    assert offenders == [], (
        f"{rel} has an echo inside a block whose unescaped ')' ends that block; "
        "escape it as ^): " + "; ".join(offenders))


def test_the_guard_recognises_the_bug_it_was_written_for(tmp_path):
    """A guard that cannot fail is not a guard."""
    import re

    bad = tmp_path / "bad.bat"
    bad.write_text(
        "if errorlevel 1 (\n"
        "    echo   Installing pywin32 (not found in venv)...\n"
        ")\n", encoding="utf-8")
    found = _echo_lines_inside_blocks(bad)
    assert found, "the scanner did not see an echo inside the block"
    assert any(re.search(r"(?<!\^)\)", t) for _n, t in found)
