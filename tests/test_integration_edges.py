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
import subprocess
import sys
import urllib.error

import pytest

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
    KEY_READ = 0x20019
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


@pytest.fixture
def registry(monkeypatch):
    fake = _FakeWinreg()
    monkeypatch.setattr(shell_ext, "winreg", fake)
    monkeypatch.setattr(shell_ext, "_HKCU", fake.HKEY_CURRENT_USER)
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
    monkeypatch.setattr(shell_ext.sys, "executable", exe_dir + r"\python.exe")

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
