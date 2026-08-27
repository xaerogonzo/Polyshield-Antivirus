"""
Speakeasy's report parser and the indicators derived from it.

_parse_report() and EmulationReport.threat_indicators are functions over a
dict, so this file needs no emulator: speakeasy-emulator pins unicorn==1.0.2
and a specific setuptools to restore modules removed in Python 3.12+, and that
combination is deliberately kept out of requirements-ci.txt. What is tested
here is the half that decides what the Sandbox/Emulate view tells the user,
which is the half that can be wrong without anything crashing.

The emulation subprocess itself, and sandbox_engine.detonate(), stay live-only
concerns -- see docs/TESTING.md.
"""
from __future__ import annotations

import pytest

from conftest import _InlineThreading
from ui.core.emulate_engine import EmulationReport, _parse_report


def _report(*apis, traffic=()):
    """Build a raw Speakeasy report around a list of api entries."""
    entry = {"apis": list(apis)}
    if traffic:
        entry["network_events"] = {"traffic": list(traffic)}
    return {"entry_points": [entry]}


def _api(name, *args, ret=""):
    return {"api_name": name, "args": list(args), "ret_val": ret}


# -- Shape of the parse -------------------------------------------------------

def test_an_empty_report_yields_an_empty_result():
    report = _parse_report({})

    assert report.api_calls == []
    assert report.network == []
    assert report.registry == []
    assert report.file_ops == []
    assert report.threat_indicators == []


def test_an_entry_point_with_no_apis_is_not_an_error():
    report = _parse_report({"entry_points": [{}]})

    assert report.api_calls == []


def test_the_raw_report_is_preserved():
    raw = _report(_api("GetTickCount"))

    assert _parse_report(raw).raw is raw


def test_every_api_call_is_captured_with_its_arguments_and_return():
    raw = _report(_api("GetTickCount", {"val": "1"}, ret="0x2a"))

    call = _parse_report(raw).api_calls[0]

    assert call == {"api": "GetTickCount", "args": [{"val": "1"}], "ret": "0x2a"}


def test_an_api_entry_with_no_name_is_recorded_as_unknown():
    report = _parse_report(_report({"args": [], "ret_val": ""}))

    assert report.api_calls[0]["api"] == "?"


# -- Network extraction -------------------------------------------------------

def test_a_network_argument_is_read_from_a_val_dict():
    raw = _report(_api("InternetOpenUrl", {"val": "http://example.invalid/a"}))

    assert _parse_report(raw).network == ["http://example.invalid/a"]


def test_a_network_argument_is_read_from_a_bare_value():
    raw = _report(_api("connect", "203.0.113.9"))

    assert _parse_report(raw).network == ["203.0.113.9"]


@pytest.mark.parametrize("placeholder", ["0", "None", ""])
def test_placeholder_arguments_are_skipped_in_favour_of_a_real_one(placeholder):
    raw = _report(_api("WSAConnect", {"val": placeholder},
                       {"val": "198.51.100.7"}))

    assert _parse_report(raw).network == ["198.51.100.7"]


def test_only_the_first_usable_network_argument_is_taken():
    raw = _report(_api("HttpSendRequest", {"val": "first"}, {"val": "second"}))

    assert _parse_report(raw).network == ["first"]


def test_a_non_network_api_contributes_no_network_entry():
    raw = _report(_api("GetTickCount", {"val": "http://example.invalid/"}))

    assert _parse_report(raw).network == []


def test_the_dedicated_traffic_section_is_merged_without_duplicates():
    raw = _report(_api("connect", {"val": "192.0.2.5"}),
                  traffic=[{"server": "192.0.2.5"}, {"server": "192.0.2.6"}])

    assert _parse_report(raw).network == ["192.0.2.5", "192.0.2.6"]


# -- Registry and file operations ---------------------------------------------

@pytest.mark.parametrize("api,op", [
    ("RegSetValueEx", "write"),
    ("RegQueryValueEx", "read"),
    ("RegDeleteKey", "delete"),
])
def test_registry_apis_map_to_their_operation(api, op):
    raw = _report(_api(api, {"val": r"HKEY_CURRENT_USER\SOFTWARE\Thing"}))

    assert _parse_report(raw).registry == [
        {"op": op, "key": r"HKEY_CURRENT_USER\SOFTWARE\Thing", "value": ""}]


def test_a_registry_call_with_no_recognisable_key_is_recorded_as_unknown():
    raw = _report(_api("RegSetValueEx", {"val": "42"}))

    assert _parse_report(raw).registry[0]["key"] == "unknown"


@pytest.mark.parametrize("api,op", [
    ("CreateFileW", "create"),
    ("WriteFile", "write"),
    ("DeleteFileA", "delete"),
    ("ReadFile", "read"),
])
def test_file_apis_map_to_their_operation(api, op):
    raw = _report(_api(api, {"val": r"C:\Users\x\dropped.tmp"}))

    assert _parse_report(raw).file_ops == [
        {"op": op, "path": r"C:\Users\x\dropped.tmp"}]


def test_a_file_call_with_no_recognisable_path_is_recorded_as_unknown():
    raw = _report(_api("WriteFile", {"val": "0"}))

    assert _parse_report(raw).file_ops[0]["path"] == "unknown"


# -- Threat indicators --------------------------------------------------------

@pytest.mark.parametrize("hive", ["HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"])
def test_a_run_key_write_is_reported_as_persistence(hive):
    key = hive + r"\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    report = EmulationReport(registry=[{"op": "write", "key": key, "value": ""}])

    assert report.threat_indicators == [f"Persistence: writes Run key → {key}"]


def test_a_run_key_write_is_matched_case_insensitively():
    key = r"hkey_current_user\software\microsoft\windows\currentversion\run"
    report = EmulationReport(registry=[{"op": "write", "key": key, "value": ""}])

    assert report.threat_indicators


def test_merely_reading_a_run_key_is_not_persistence():
    key = r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    report = EmulationReport(registry=[{"op": "read", "key": key, "value": ""}])

    assert report.threat_indicators == []


def test_injection_apis_are_reported_once_and_sorted():
    report = EmulationReport(api_calls=[
        {"api": "WriteProcessMemory"}, {"api": "VirtualAllocEx"},
        {"api": "WriteProcessMemory"}, {"api": "GetTickCount"},
    ])

    assert report.threat_indicators == [
        "Injection: uses VirtualAllocEx, WriteProcessMemory"]


def test_encryption_apis_are_reported_once_and_sorted():
    report = EmulationReport(api_calls=[
        {"api": "CryptGenKey"}, {"api": "CryptEncrypt"}, {"api": "CryptGenKey"},
    ])

    assert report.threat_indicators == [
        "Encryption: calls CryptEncrypt, CryptGenKey"]


@pytest.mark.parametrize("needle", ["vssadmin delete shadows", "ShadowCopy"])
def test_shadow_copy_deletion_is_reported_once(needle):
    report = EmulationReport(api_calls=[
        {"api": "CreateProcessA", "args": [{"val": needle}]},
        {"api": "CreateProcessA", "args": [{"val": needle}]},
    ])

    assert report.threat_indicators == [
        "Ransomware: attempts shadow copy deletion"]


def test_each_contacted_host_is_reported():
    report = EmulationReport(network=["192.0.2.5", "example.invalid"])

    assert report.threat_indicators == [
        "Network: contacts 192.0.2.5",
        "Network: contacts example.invalid",
    ]


def test_a_benign_trace_produces_no_indicators():
    report = EmulationReport(api_calls=[
        {"api": "GetTickCount", "args": []},
        {"api": "ReadFile", "args": [{"val": r"C:\config.ini"}]},
    ])

    assert report.threat_indicators == []


# -- Malformed input: probed, and deliberately left to the caller ------------

@pytest.mark.parametrize("raw", [
    pytest.param({"entry_points": None}, id="entry_points-null"),
    pytest.param({"entry_points": [{"apis": None}]}, id="apis-null"),
    pytest.param({"entry_points": [{"apis": [{"api_name": "connect",
                                              "args": None}]}]}, id="args-null"),
    pytest.param({"entry_points": [{"apis": [], "network_events": None}]},
                 id="network_events-null"),
    pytest.param({"entry_points": {"a": 1}}, id="entry_points-not-a-list"),
])
def test_a_structurally_wrong_report_raises_rather_than_inventing_a_result(raw):
    """Probed and dismissed as a defect; pinned as behaviour.

    Every one of these shapes -- all of them JSON nulls or wrong types that a
    misbehaving worker could emit -- makes _parse_report raise. That was worth
    checking rather than assuming, and the answer is that raising is correct
    here: emulate_async wraps the call, turns the exception into
    EmulationReport(error=...) and still calls on_done, so the user is told the
    report could not be read. Making _parse_report swallow these instead would
    hand the view an empty report that looks like a clean emulation.

    See test_a_malformed_report_reaches_the_caller_as_an_error for the other
    half of that contract.
    """
    with pytest.raises((TypeError, AttributeError)):
        _parse_report(raw)


def test_a_malformed_report_reaches_the_caller_as_an_error(monkeypatch, tmp_path):
    """The containment that makes the raises above safe."""
    import json
    import subprocess as real_subprocess

    from ui.core import emulate_engine as ee

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    payload = json.dumps({"report": {"entry_points": None}}).encode()

    class _Proc:
        def communicate(self, timeout=None):
            return payload, b""

    class _Subprocess:
        def Popen(self, *_a, **_kw):
            return _Proc()

        def __getattr__(self, name):
            return getattr(real_subprocess, name)

    monkeypatch.setattr(ee, "is_available", lambda: True)
    monkeypatch.setattr(ee, "subprocess", _Subprocess())
    monkeypatch.setattr(ee, "threading", _InlineThreading())
    seen = []

    ee.emulate_async(str(sample), seen.append)

    assert len(seen) == 1, "on_done must fire exactly once on every path"
    assert seen[0].error, "a report that could not be parsed must say so"


def test_an_end_to_end_dropper_trace_produces_every_indicator():
    """One trace exercising the parse and the indicators together."""
    run_key = r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    raw = _report(
        _api("URLDownloadToFile", {"val": "http://example.invalid/stage2"}),
        _api("CreateFileW", {"val": r"C:\Users\x\AppData\stage2.exe"}),
        _api("RegSetValueEx", {"val": run_key}),
        _api("VirtualAllocEx", {"val": "0x1000"}),
        _api("CreateRemoteThread", {"val": "0x1000"}),
    )

    indicators = _parse_report(raw).threat_indicators

    assert f"Persistence: writes Run key → {run_key}" in indicators
    assert "Network: contacts http://example.invalid/stage2" in indicators
    assert "Injection: uses CreateRemoteThread, VirtualAllocEx" in indicators
