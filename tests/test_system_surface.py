"""
The two thin layers between this app and Windows itself.

`win_security._reg_read` / `_reg_key_exists` wrap winreg and swallow OSError so
that a missing key reads as "not configured" rather than as a crash; between
them they have a fan-in of eight and no test. `defender.get_status()` parses
what PowerShell hands back and promises, in its own docstring, to always return
a dict.

Neither talks to the real registry or a real PowerShell here.
"""
from __future__ import annotations

import json

import pytest

from ui.core import defender, win_security as ws


# -- Fake winreg --------------------------------------------------------------

class _FakeKey:
    def __init__(self, values):
        self.values = values
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def Close(self):
        self.closed = True


class _FakeWinreg:
    """Only what _reg_read and _reg_key_exists actually touch."""

    HKEY_LOCAL_MACHINE = "HKLM"
    HKEY_CURRENT_USER = "HKCU"

    def __init__(self, tree=None):
        self.tree = tree or {}

    def OpenKey(self, hive, subkey):
        try:
            return _FakeKey(self.tree[(hive, subkey)])
        except KeyError:
            raise FileNotFoundError(2, "The system cannot find the file specified")

    def QueryValueEx(self, key, name):
        try:
            return key.values[name], 1
        except KeyError:
            raise FileNotFoundError(2, "The system cannot find the file specified")


@pytest.fixture
def registry(monkeypatch):
    """Install a fake registry; returns its backing dict for the test to fill."""
    fake = _FakeWinreg()
    monkeypatch.setattr(ws, "winreg", fake)
    return fake


# -- _reg_read ----------------------------------------------------------------

def test_a_value_that_exists_is_returned(registry):
    registry.tree[("HKLM", r"SOFTWARE\Thing")] = {"EnableFirewall": 1}

    assert ws._reg_read("HKLM", r"SOFTWARE\Thing", "EnableFirewall") == 1


def test_a_missing_key_yields_the_default(registry):
    assert ws._reg_read("HKLM", r"SOFTWARE\Absent", "Whatever") is None
    assert ws._reg_read("HKLM", r"SOFTWARE\Absent", "Whatever", default=7) == 7


def test_a_missing_value_under_an_existing_key_yields_the_default(registry):
    registry.tree[("HKLM", r"SOFTWARE\Thing")] = {"Other": 1}

    assert ws._reg_read("HKLM", r"SOFTWARE\Thing", "EnableFirewall",
                        default="fallback") == "fallback"


def test_an_access_denied_read_yields_the_default_rather_than_raising(registry):
    """Callers run unelevated; a permission error is an expected answer."""
    def _denied(hive, subkey):
        raise PermissionError(5, "Access is denied")

    registry.OpenKey = _denied

    assert ws._reg_read("HKLM", r"SOFTWARE\Thing", "V", default="unknown") == "unknown"


def test_the_value_type_is_passed_through_untouched(registry):
    """Callers compare against 0/1 and against strings; no coercion happens."""
    registry.tree[("HKCU", "K")] = {"num": 0, "text": "value", "multi": ["a", "b"]}

    assert ws._reg_read("HKCU", "K", "num") == 0
    assert ws._reg_read("HKCU", "K", "text") == "value"
    assert ws._reg_read("HKCU", "K", "multi") == ["a", "b"]


def test_a_zero_value_is_returned_rather_than_falling_back(registry):
    """0 is the interesting answer for most of these flags -- it means OFF."""
    registry.tree[("HKLM", "K")] = {"EnableFirewall": 0}

    assert ws._reg_read("HKLM", "K", "EnableFirewall", default=1) == 0


# -- _reg_key_exists ----------------------------------------------------------

def test_an_existing_key_is_reported_present(registry):
    registry.tree[("HKLM", r"SOFTWARE\Present")] = {}

    assert ws._reg_key_exists("HKLM", r"SOFTWARE\Present") is True


def test_a_missing_key_is_reported_absent(registry):
    assert ws._reg_key_exists("HKLM", r"SOFTWARE\Absent") is False


def test_the_probe_closes_the_handle_it_opened(registry):
    """Called on every dashboard refresh; a leaked handle would accumulate."""
    opened = []
    registry.tree[("HKLM", "K")] = {}
    real_open = registry.OpenKey

    def _tracking(hive, subkey):
        key = real_open(hive, subkey)
        opened.append(key)
        return key

    registry.OpenKey = _tracking

    ws._reg_key_exists("HKLM", "K")

    assert opened and opened[0].closed


# -- defender.get_status ------------------------------------------------------

def _with_output(monkeypatch, ok, output):
    monkeypatch.setattr(defender, "_run_ps", lambda *_a, **_kw: (ok, output))


def test_a_status_object_is_returned_with_available_set(monkeypatch):
    _with_output(monkeypatch, True, json.dumps({
        "RealTimeProtectionEnabled": True, "AntivirusSignatureAge": 2}))

    status = defender.get_status()

    assert status["available"] is True
    assert status["RealTimeProtectionEnabled"] is True
    assert status["AntivirusSignatureAge"] == 2


def test_a_failed_command_reports_unavailable(monkeypatch):
    _with_output(monkeypatch, False, "timed out after 20s")

    assert defender.get_status() == {"available": False}


def test_empty_output_reports_unavailable(monkeypatch):
    _with_output(monkeypatch, True, "")

    assert defender.get_status() == {"available": False}


def test_unparseable_output_reports_unavailable(monkeypatch):
    _with_output(monkeypatch, True, "Get-MpComputerStatus : Access denied")

    assert defender.get_status() == {"available": False}


@pytest.mark.parametrize("payload,description", [
    ("[{\"AntivirusEnabled\": true}]", "an array"),
    ("null", "a JSON null"),
    ("42", "a bare scalar"),
    ("\"text\"", "a bare string"),
])
def test_json_that_is_not_an_object_reports_unavailable(
        monkeypatch, payload, description):
    """The docstring promises a dict on every path; this used to raise.

    `ConvertTo-Json` emits an array whenever `Select-Object` sees a collection
    rather than a single object, and `null` when it sees nothing. Both reached
    `data["available"] = True` and raised TypeError out of get_status -- on
    dashboard_view._load's background thread, *before* its
    self.after(0, self._apply, ...) marshal. The Dashboard would then sit on
    "Refreshing..." with its refresh button disabled until the app restarted.

    The sibling readers get_threat_history() and get_threat_names() already
    normalise the shape they are handed; this one did not.
    """
    _with_output(monkeypatch, True, payload)

    assert defender.get_status() == {"available": False}, description


def test_a_powershell_date_timestamp_is_normalised(monkeypatch):
    """PowerShell emits /Date(ms)/; the UI shows the string verbatim."""
    _with_output(monkeypatch, True, json.dumps({
        "AntivirusSignatureLastUpdated": "/Date(1700000000000)/"}))

    stamp = defender.get_status()["AntivirusSignatureLastUpdated"]

    assert "/Date(" not in stamp
    assert len(stamp) == 16      # "YYYY-MM-DD HH:MM"


def test_an_unrecognised_timestamp_is_left_alone(monkeypatch):
    _with_output(monkeypatch, True, json.dumps({
        "AntivirusSignatureLastUpdated": "2026-08-27T10:00:00"}))

    assert defender.get_status()["AntivirusSignatureLastUpdated"] == (
        "2026-08-27T10:00:00")


def test_a_malformed_date_does_not_lose_the_rest_of_the_status(monkeypatch):
    _with_output(monkeypatch, True, json.dumps({
        "AntivirusEnabled": True,
        "AntivirusSignatureLastUpdated": "/Date(not-a-number)/"}))

    status = defender.get_status()

    assert status["available"] is True
    assert status["AntivirusEnabled"] is True
