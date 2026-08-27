"""
The three Windows Security probes that read live machine state.

get_device_security, get_local_accounts and get_app_browser_control were the
top three untested-risk functions in src/ui/core once the PowerShell runner and
the score were covered. They were awkward to reach before that work: each one
mixes registry reads with PowerShell, and both halves used to be inline.

They are reachable now through the two seams that already exist -- `_run_ps`,
which every PowerShell call goes through, and `winreg`, faked here the same way
test_system_surface.py fakes it. Nothing in this file touches the real registry
or starts a real PowerShell.

What these functions decide is what the Windows Security view shows and what
get_security_score() charges points for, so the distinction that matters
throughout is *off* versus *unknown*: a machine whose TPM state could not be
read must not score the same as one whose TPM is present.
"""
from __future__ import annotations

import json

import pytest

from ui.core import win_security as ws


# -- Fakes --------------------------------------------------------------------

class _FakeKey:
    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def Close(self):
        pass


class _FakeWinreg:
    HKEY_LOCAL_MACHINE = "HKLM"
    HKEY_CURRENT_USER = "HKCU"

    def __init__(self):
        self.tree: dict = {}

    def OpenKey(self, hive, subkey):
        try:
            return _FakeKey(self.tree[subkey])
        except KeyError:
            raise FileNotFoundError(2, "not found")

    def QueryValueEx(self, key, name):
        try:
            return key.values[name], 1
        except KeyError:
            raise FileNotFoundError(2, "not found")


@pytest.fixture
def machine(monkeypatch):
    """A fake machine: a registry, a PowerShell, and an elevation state.

    `ps` maps a substring of the command to the (ok, output) it answers with,
    so a test names the query it cares about rather than the whole script.
    Anything unmatched answers (False, "") -- the command failed -- which is the
    honest default for a probe nobody set up.
    """
    reg = _FakeWinreg()
    monkeypatch.setattr(ws, "winreg", reg)

    state = {"elevated": False, "ps": {}, "calls": []}
    monkeypatch.setattr(ws, "_is_elevated", lambda: state["elevated"])

    def _fake_run_ps(command, timeout=20):
        state["calls"].append(command)
        for needle, answer in state["ps"].items():
            if needle in command:
                return answer
        return (False, "")

    monkeypatch.setattr(ws, "_run_ps", _fake_run_ps)
    state["reg"] = reg
    return state


# =============================================================================
# get_device_security
# =============================================================================

_SECURE_BOOT_KEY = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
_TPM_KEY = r"SYSTEM\CurrentControlSet\Services\TPM"
_DEVICE_GUARD_KEY = r"SYSTEM\CurrentControlSet\Control\DeviceGuard"


@pytest.mark.parametrize("raw,expected", [(1, True), (0, False)])
def test_secure_boot_is_read_from_the_registry_without_elevation(
        machine, raw, expected):
    """0 must survive as False rather than being mistaken for absent."""
    machine["reg"].tree[_SECURE_BOOT_KEY] = {"UEFISecureBootEnabled": raw}

    result = ws.get_device_security()

    assert result["secure_boot"] is expected
    assert "secure_boot_needs_elevation" not in result
    assert machine["calls"] == [], "the registry answered; no PowerShell needed"


def test_secure_boot_is_unknown_when_unelevated_and_absent_from_the_registry(
        machine):
    result = ws.get_device_security()

    assert result["secure_boot"] is None
    assert result["secure_boot_needs_elevation"] is True


def test_secure_boot_falls_back_to_powershell_when_elevated(machine):
    machine["elevated"] = True
    machine["ps"]["Confirm-SecureBootUEFI"] = (True, "True")

    assert ws.get_device_security()["secure_boot"] is True


def test_needs_elevation_is_set_only_when_both_sources_failed(machine):
    """What the docstring promises, stated as a test."""
    machine["elevated"] = True
    machine["ps"]["Confirm-SecureBootUEFI"] = (False, "access denied")

    result = ws.get_device_security()

    assert result["secure_boot"] is None
    assert result["secure_boot_needs_elevation"] is True


def test_the_tpm_driver_key_alone_reports_the_tpm_present(machine):
    machine["reg"].tree[_TPM_KEY] = {}

    assert ws.get_device_security()["tpm_present"] is True


def test_tpm_detail_comes_from_powershell_when_elevated(machine):
    machine["elevated"] = True
    machine["ps"]["Get-Tpm"] = (True, json.dumps(
        {"TpmPresent": True, "TpmReady": True, "TpmVersion": "2.0"}))

    result = ws.get_device_security()

    assert result["tpm_present"] is True
    assert result["tpm_ready"] is True
    assert result["tpm_version"] == "2.0"


def test_an_unreadable_tpm_is_reported_unknown_rather_than_omitted(machine):
    """Absent from the dict is not the same as None, and scores differently.

    Get-Tpm succeeds but returns something unparseable -- a warning banner, a
    partial line -- while the registry driver key is also absent. The parse
    lands in `except Exception: pass`, which leaves tpm_present never assigned
    at all rather than assigned None. get_security_score() then reads
    device_sec.get("tpm_present") is False -> False and
    .get("tpm_needs_elevation") -> None, charges nothing, and awards the
    machine full Device Security credit for a TPM whose state is unknown.
    """
    machine["elevated"] = True
    machine["ps"]["Get-Tpm"] = (True, "WARNING: TPM is not available")

    result = ws.get_device_security()

    assert "tpm_present" in result, "the key vanished instead of reading unknown"
    assert result["tpm_present"] is None
    assert result["tpm_needs_elevation"] is True


@pytest.mark.parametrize("raw,expected", [(1, True), (0, False)])
def test_vbs_is_read_from_the_registry(machine, raw, expected):
    machine["reg"].tree[_DEVICE_GUARD_KEY] = {
        "EnableVirtualizationBasedSecurity": raw}

    assert ws.get_device_security()["vbs_enabled"] is expected


def test_vbs_running_state_comes_from_device_guard_when_elevated(machine):
    """Status 2 means running; anything else is configured-but-not-running."""
    machine["elevated"] = True
    machine["ps"]["Win32_DeviceGuard"] = (True, json.dumps(
        {"VirtualizationBasedSecurityStatus": 2,
         "SecurityServicesRunning": [1, 2]}))

    result = ws.get_device_security()

    assert result["vbs_enabled"] is True
    assert result["credential_guard"] is True
    assert result["hvci"] is True


def test_vbs_configured_but_not_running_is_not_enabled(machine):
    machine["elevated"] = True
    machine["ps"]["Win32_DeviceGuard"] = (True, json.dumps(
        {"VirtualizationBasedSecurityStatus": 1, "SecurityServicesRunning": []}))

    result = ws.get_device_security()

    assert result["vbs_enabled"] is False
    assert result["credential_guard"] is False
    assert result["hvci"] is False


def test_a_single_running_service_is_handled_as_well_as_a_list(machine):
    """ConvertTo-Json collapses a one-element array to a scalar."""
    machine["elevated"] = True
    machine["ps"]["Win32_DeviceGuard"] = (True, json.dumps(
        {"VirtualizationBasedSecurityStatus": 2, "SecurityServicesRunning": 1}))

    assert ws.get_device_security()["credential_guard"] is True


def test_an_unreadable_device_guard_is_reported_unknown_rather_than_omitted(
        machine):
    """The same missing-key shape as the TPM case, on the VBS branch."""
    machine["elevated"] = True
    machine["ps"]["Win32_DeviceGuard"] = (True, "not a json document")

    result = ws.get_device_security()

    assert "vbs_enabled" in result, "the key vanished instead of reading unknown"
    assert result["vbs_enabled"] is None
    assert result["vbs_needs_elevation"] is True


def test_the_elevation_state_is_reported(machine):
    machine["elevated"] = True

    assert ws.get_device_security()["elevated"] is True


# =============================================================================
# get_local_accounts
# =============================================================================

def _users(*rows):
    return (True, json.dumps(list(rows)))


def _user(name, enabled=True, password_required=True, last_logon=None):
    return {"Name": name, "Enabled": enabled,
            "PasswordRequired": password_required, "LastLogon": last_logon}


def _recent_date_ms():
    from datetime import datetime, timedelta
    return int((datetime.now() - timedelta(days=1)).timestamp() * 1000)


def _stale_date_ms():
    from datetime import datetime, timedelta
    return int((datetime.now() - timedelta(days=120)).timestamp() * 1000)


def test_a_failed_enumeration_reports_unavailable(machine):
    assert ws.get_local_accounts() == {"available": False, "accounts": []}


def test_unparseable_output_reports_unavailable(machine):
    machine["ps"]["Get-LocalUser"] = (True, "Get-LocalUser : not recognised")

    assert ws.get_local_accounts() == {"available": False, "accounts": []}


def test_a_single_account_is_normalised_into_a_list(machine):
    """ConvertTo-Json emits an object, not an array, for one account."""
    machine["ps"]["Get-LocalUser"] = (True, json.dumps(_user("OnlyUser")))

    result = ws.get_local_accounts()

    assert result["available"] is True
    assert [a["name"] for a in result["accounts"]] == ["OnlyUser"]


def test_administrators_group_membership_is_matched(machine):
    machine["ps"]["Get-LocalUser"] = _users(_user("Alex"), _user("Guest"))
    machine["ps"]["Get-LocalGroupMember"] = (True, json.dumps(
        [{"Name": "DESKTOP-1\\Alex"}]))

    accounts = {a["name"]: a for a in ws.get_local_accounts()["accounts"]}

    assert accounts["Alex"]["is_admin"] is True
    assert accounts["Guest"]["is_admin"] is False


def test_a_bare_group_member_name_matches_too(machine):
    """Get-LocalGroupMember returns DOMAIN\\Name, but not always."""
    machine["ps"]["Get-LocalUser"] = _users(_user("Alex"))
    machine["ps"]["Get-LocalGroupMember"] = (True, json.dumps({"Name": "alex"}))

    assert ws.get_local_accounts()["accounts"][0]["is_admin"] is True


def test_an_admin_without_a_required_password_is_flagged(machine):
    machine["ps"]["Get-LocalUser"] = _users(
        _user("Alex", password_required=False))
    machine["ps"]["Get-LocalGroupMember"] = (True, json.dumps({"Name": "Alex"}))

    result = ws.get_local_accounts()

    assert result["accounts"][0]["risk"] == ["Admin without password"]
    assert result["flagged_count"] == 1


def test_a_stale_admin_login_is_flagged(machine):
    machine["ps"]["Get-LocalUser"] = _users(
        _user("Alex", last_logon=f"/Date({_stale_date_ms()})/"))
    machine["ps"]["Get-LocalGroupMember"] = (True, json.dumps({"Name": "Alex"}))

    assert ws.get_local_accounts()["accounts"][0]["risk"] == [
        "Admin — no login in 90+ days"]


def test_a_recent_admin_login_is_not_flagged(machine):
    machine["ps"]["Get-LocalUser"] = _users(
        _user("Alex", last_logon=f"/Date({_recent_date_ms()})/"))
    machine["ps"]["Get-LocalGroupMember"] = (True, json.dumps({"Name": "Alex"}))

    result = ws.get_local_accounts()

    assert result["accounts"][0]["risk"] == []
    assert result["flagged_count"] == 0


def test_a_non_admin_is_never_flagged(machine):
    """Every risk in this function is conditioned on being an admin."""
    machine["ps"]["Get-LocalUser"] = _users(
        _user("Guest", password_required=False,
              last_logon=f"/Date({_stale_date_ms()})/"))

    assert ws.get_local_accounts()["accounts"][0]["risk"] == []


def test_an_account_that_never_logged_in_reads_as_never(machine):
    machine["ps"]["Get-LocalUser"] = _users(_user("Fresh", last_logon=None))

    assert ws.get_local_accounts()["accounts"][0]["last_logon"] == "Never"


def test_only_enabled_admins_are_counted(machine):
    machine["ps"]["Get-LocalUser"] = _users(
        _user("Alex"), _user("Administrator", enabled=False))
    machine["ps"]["Get-LocalGroupMember"] = (True, json.dumps(
        [{"Name": "Alex"}, {"Name": "Administrator"}]))

    assert ws.get_local_accounts()["admin_count"] == 1


def test_an_unreadable_administrators_group_leaves_accounts_listed(machine):
    """Losing the group query must not lose the account list with it."""
    machine["ps"]["Get-LocalUser"] = _users(_user("Alex"))
    machine["ps"]["Get-LocalGroupMember"] = (True, "Access is denied")

    result = ws.get_local_accounts()

    assert result["available"] is True
    assert result["accounts"][0]["is_admin"] is False


# =============================================================================
# get_app_browser_control
# =============================================================================

_SS_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\System"
_SS_EXPLORER_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"


def test_smartscreen_defaults_to_on_when_nothing_is_configured(machine):
    """Windows ships it on; absent must not read as disabled."""
    result = ws.get_app_browser_control()

    assert result["smartscreen_on"] is True
    assert result["smartscreen_source"] == "default"


def test_a_smartscreen_policy_overrides_the_user_setting(machine):
    machine["reg"].tree[_SS_POLICY_KEY] = {"EnableSmartScreen": 0}
    machine["reg"].tree[_SS_EXPLORER_KEY] = {"SmartScreenEnabled": "RequireAdmin"}

    result = ws.get_app_browser_control()

    assert result["smartscreen_on"] is False
    assert result["smartscreen_source"] == "policy"


@pytest.mark.parametrize("value,expected", [
    ("RequireAdmin", True), ("Warn", True), ("Off", False), ("off", False),
])
def test_the_user_facing_smartscreen_setting_is_read_when_no_policy_exists(
        machine, value, expected):
    machine["reg"].tree[_SS_EXPLORER_KEY] = {"SmartScreenEnabled": value}

    result = ws.get_app_browser_control()

    assert result["smartscreen_on"] is expected
    assert result["smartscreen_source"] == "user"


@pytest.mark.parametrize("raw,enabled,audit", [
    (0, False, False), (1, True, False), (2, False, True),
])
def test_controlled_folder_access_modes(machine, raw, enabled, audit):
    machine["reg"].tree[ws._WD_EXPLOIT + r"\Controlled Folder Access"] = {
        "EnableControlledFolderAccess": raw}

    result = ws.get_app_browser_control()

    assert result["cfa_enabled"] is enabled
    assert result["cfa_audit"] is audit


def test_asr_rules_are_paired_with_their_actions(machine):
    rule = "56A863A9-875E-4185-98A7-B882C64B5CE5"
    machine["ps"]["Get-MpPreference"] = (True, json.dumps({
        "AttackSurfaceReductionRules_Ids": [rule],
        "AttackSurfaceReductionRules_Actions": [1]}))

    result = ws.get_app_browser_control()

    assert result["asr_rules"][0]["category"] == "Exploit Protection"
    assert result["asr_rules"][0]["action"] == "Block"
    assert result["asr_rules"][0]["enabled"] is True
    assert result["asr_active_count"] == 1


def test_a_single_asr_rule_is_handled_as_well_as_a_list(machine):
    """ConvertTo-Json collapses one-element arrays on both fields."""
    rule = "56A863A9-875E-4185-98A7-B882C64B5CE5"
    machine["ps"]["Get-MpPreference"] = (True, json.dumps({
        "AttackSurfaceReductionRules_Ids": rule,
        "AttackSurfaceReductionRules_Actions": 1}))

    assert ws.get_app_browser_control()["asr_active_count"] == 1


def test_only_blocking_asr_rules_count_as_active(machine):
    """Audit mode logs and permits; it is not protection."""
    machine["ps"]["Get-MpPreference"] = (True, json.dumps({
        "AttackSurfaceReductionRules_Ids": ["id-a", "id-b", "id-c"],
        "AttackSurfaceReductionRules_Actions": [1, 2, 0]}))

    result = ws.get_app_browser_control()

    assert result["asr_active_count"] == 1
    assert [r["action"] for r in result["asr_rules"]] == [
        "Block", "Audit", "Disabled"]


def test_an_unrecognised_asr_rule_is_kept_under_other(machine):
    """New rule IDs ship with Windows; they must not be dropped silently."""
    machine["ps"]["Get-MpPreference"] = (True, json.dumps({
        "AttackSurfaceReductionRules_Ids": ["brand-new-guid"],
        "AttackSurfaceReductionRules_Actions": [1]}))

    result = ws.get_app_browser_control()

    assert result["asr_rules"][0]["category"] == "Other"
    assert "Other" in result["asr_categories"]


def test_unreadable_asr_preferences_leave_the_registry_answers_intact(machine):
    machine["reg"].tree[_SS_EXPLORER_KEY] = {"SmartScreenEnabled": "Off"}
    machine["ps"]["Get-MpPreference"] = (True, "not json")

    result = ws.get_app_browser_control()

    assert result["smartscreen_on"] is False
    assert result["asr_rules"] == []
    assert result["asr_active_count"] == 0
