"""
The composite 0-100 security posture the Dashboard shows.

get_security_score() is the highest-complexity function in src/ui/core and had
no test at all. It is also the one the user reads as a single number, so an
arithmetic slip here is invisible in code review and loud on screen.

What is asserted is the published semantics -- each domain's documented weight,
the floors, and the boundaries between labels -- not the order of the branches
that produce them.

One thing worth knowing before editing it: the function is *nearly* pure when
all six dicts are supplied, but the Account Security branch calls
get_account_policy() live. Every test here patches that, or it would shell out
to PowerShell on a runner and score differently depending on the machine.
"""
from __future__ import annotations

import copy

import pytest

from ui.core import win_security as ws


# -- A configuration with nothing wrong with it -------------------------------

def _healthy():
    return {
        "defender_status": {
            "available": True,
            "RealTimeProtectionEnabled": True,
            "AntivirusEnabled": True,
            "AntivirusSignatureAge": 0,
        },
        "firewall_profiles": {
            "Domain":  {"enabled": True},
            "Private": {"enabled": True},
            "Public":  {"enabled": True},
        },
        "device_sec": {"secure_boot": True, "tpm_present": True, "vbs_enabled": True},
        "account_data": {"available": True, "flagged_count": 0},
        "app_control": {"smartscreen_on": True, "cfa_enabled": True,
                        "asr_active_count": 3},
        "sys_health": {"pending_reboot": False, "uptime_days": 1,
                       "driver_errors": 0},
    }


@pytest.fixture(autouse=True)
def _offline_account_policy(monkeypatch):
    """Account Security reaches out live; every test needs it pinned."""
    monkeypatch.setattr(ws, "get_account_policy",
                        lambda: {"available": True, "lockout_threshold": 5})


def _score(**overrides):
    args = _healthy()
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(args.get(key), dict):
            args[key] = {**args[key], **value}
        else:
            args[key] = value
    return ws.get_security_score(**args)


# -- The whole scale ----------------------------------------------------------

def test_a_healthy_machine_scores_exactly_one_hundred():
    result = _score()

    assert result["score"] == 100
    assert result["label"] == "Excellent"
    assert result["top_issue"] is None


def test_the_six_domain_weights_sum_to_one_hundred():
    breakdown = _score()["breakdown"]

    assert {name: cat["max"] for name, cat in breakdown.items()} == {
        "Defender": 25,
        "Firewall": 20,
        "Device Security": 20,
        "Account Security": 15,
        "App & Browser Control": 15,
        "System Health": 5,
    }
    assert sum(cat["max"] for cat in breakdown.values()) == 100


# Each entry is built to land on exactly one side of a label boundary, so an
# off-by-one in the >= comparisons shows up as a wrong label rather than as a
# wrong number nobody checks. The penalties used: Defender antivirus disabled
# is -10, Defender unavailable is -25, all three device features off is -20,
# and a single driver error is -1.
@pytest.mark.parametrize("overrides,expected_score,expected_label", [
    ({}, 100, "Excellent"),
    ({"defender_status": {"AntivirusEnabled": False}}, 90, "Excellent"),
    ({"defender_status": {"AntivirusEnabled": False},
      "sys_health": {"driver_errors": 1}}, 89, "Good"),
    ({"defender_status": {"available": False}}, 75, "Good"),
    ({"defender_status": {"available": False},
      "sys_health": {"driver_errors": 1}}, 74, "Fair"),
    ({"defender_status": {"available": False},
      "device_sec": {"secure_boot": False, "tpm_present": False,
                     "vbs_enabled": False}}, 55, "Fair"),
    ({"defender_status": {"available": False},
      "device_sec": {"secure_boot": False, "tpm_present": False,
                     "vbs_enabled": False},
      "sys_health": {"driver_errors": 1}}, 54, "At Risk"),
])
def test_the_label_boundaries(overrides, expected_score, expected_label):
    result = _score(**overrides)

    assert result["score"] == expected_score
    assert result["label"] == expected_label


# -- Defender (25) ------------------------------------------------------------

def test_defender_unavailable_forfeits_the_whole_category():
    result = _score(defender_status={"available": False})

    assert result["breakdown"]["Defender"]["score"] == 0
    assert result["score"] == 75


def test_defender_passed_as_none_is_treated_as_unavailable():
    """Pinned, not endorsed.

    The docstring says "Pass None to fetch live", and five of the six
    parameters do exactly that. defender_status is the exception: it is never
    fetched, so None falls through to the unavailable branch and costs the full
    25 points. Both live callers -- dashboard_view._load and
    fetch_overview_async -- pass it explicitly, so nothing is scoring wrong
    today. The docstring is what is wrong, and this test is here so that
    changing the behaviour is a decision rather than an accident.
    """
    result = _score(defender_status=None)

    assert result["breakdown"]["Defender"]["score"] == 0
    assert "Defender status unavailable" in result["breakdown"]["Defender"]["issues"]


def test_real_time_protection_off_costs_fifteen():
    result = _score(defender_status={"RealTimeProtectionEnabled": False})

    assert result["breakdown"]["Defender"]["score"] == 10
    assert result["score"] == 85


def test_antivirus_disabled_costs_ten():
    result = _score(defender_status={"AntivirusEnabled": False})

    assert result["breakdown"]["Defender"]["score"] == 15


def test_stale_signatures_cost_five_only_past_a_week():
    assert _score(defender_status={"AntivirusSignatureAge": 7}
                  )["breakdown"]["Defender"]["score"] == 25
    assert _score(defender_status={"AntivirusSignatureAge": 8}
                  )["breakdown"]["Defender"]["score"] == 20


def test_the_defender_category_cannot_go_negative():
    result = _score(defender_status={
        "available": True, "RealTimeProtectionEnabled": False,
        "AntivirusEnabled": False, "AntivirusSignatureAge": 99})

    assert result["breakdown"]["Defender"]["score"] == 0


# -- Firewall (20) ------------------------------------------------------------

def test_each_disabled_firewall_profile_costs_seven():
    result = _score(firewall_profiles={"Public": {"enabled": False}})

    assert result["breakdown"]["Firewall"]["score"] == 13


def test_an_unknown_firewall_profile_costs_less_than_a_disabled_one():
    """False and None are different states and must not score the same."""
    disabled = _score(firewall_profiles={"Public": {"enabled": False}})
    unknown = _score(firewall_profiles={"Public": {"enabled": None}})

    assert disabled["breakdown"]["Firewall"]["score"] == 13
    assert unknown["breakdown"]["Firewall"]["score"] == 18


def test_the_firewall_category_cannot_go_negative():
    result = _score(firewall_profiles={
        "Domain": {"enabled": False}, "Private": {"enabled": False},
        "Public": {"enabled": False}})

    assert result["breakdown"]["Firewall"]["score"] == 0


# -- Device Security (20) -----------------------------------------------------

@pytest.mark.parametrize("key,off_cost,unknown_cost", [
    ("secure_boot", 7, 3),
    ("tpm_present", 7, 3),
    ("vbs_enabled", 6, 2),
])
def test_an_unknown_device_feature_costs_less_than_a_disabled_one(
        key, off_cost, unknown_cost):
    """Half credit when the answer needs admin: unknown is not the same as off."""
    elevation_key = {"secure_boot": "secure_boot_needs_elevation",
                     "tpm_present": "tpm_needs_elevation",
                     "vbs_enabled": "vbs_needs_elevation"}[key]

    off = _score(device_sec={key: False})
    unknown = _score(device_sec={key: None, elevation_key: True})

    assert off["breakdown"]["Device Security"]["score"] == 20 - off_cost
    assert unknown["breakdown"]["Device Security"]["score"] == 20 - unknown_cost


# -- Account Security (15) ----------------------------------------------------

def test_flagged_accounts_cost_five_each_capped_at_ten():
    assert _score(account_data={"flagged_count": 1}
                  )["breakdown"]["Account Security"]["score"] == 10
    assert _score(account_data={"flagged_count": 2}
                  )["breakdown"]["Account Security"]["score"] == 5
    assert _score(account_data={"flagged_count": 9}
                  )["breakdown"]["Account Security"]["score"] == 5


def test_unavailable_account_data_costs_five():
    result = _score(account_data={"available": False})

    assert result["breakdown"]["Account Security"]["score"] == 10


def test_an_unconfigured_lockout_policy_costs_five(monkeypatch):
    monkeypatch.setattr(ws, "get_account_policy",
                        lambda: {"available": True, "lockout_threshold": 0})

    assert _score()["breakdown"]["Account Security"]["score"] == 10


def test_a_high_lockout_threshold_costs_two(monkeypatch):
    monkeypatch.setattr(ws, "get_account_policy",
                        lambda: {"available": True, "lockout_threshold": 20})

    assert _score()["breakdown"]["Account Security"]["score"] == 13


# -- App & Browser Control (15) -----------------------------------------------

def test_smartscreen_off_costs_seven():
    result = _score(app_control={"smartscreen_on": False})

    assert result["breakdown"]["App & Browser Control"]["score"] == 8


def test_controlled_folder_access_in_audit_mode_costs_less_than_off():
    off = _score(app_control={"cfa_enabled": False})
    audit = _score(app_control={"cfa_enabled": False, "cfa_audit": True})

    assert off["breakdown"]["App & Browser Control"]["score"] == 10
    assert audit["breakdown"]["App & Browser Control"]["score"] == 13


def test_no_active_asr_rules_costs_three():
    result = _score(app_control={"asr_active_count": 0})

    assert result["breakdown"]["App & Browser Control"]["score"] == 12


def test_a_missing_smartscreen_key_is_assumed_on():
    """The default matters: absent must not read as disabled."""
    result = _score(app_control={"cfa_enabled": True, "asr_active_count": 3})

    assert result["breakdown"]["App & Browser Control"]["score"] == 15


# -- System Health (5) --------------------------------------------------------

def test_a_pending_reboot_costs_three():
    result = _score(sys_health={"pending_reboot": True})

    assert result["breakdown"]["System Health"]["score"] == 2


def test_long_uptime_costs_two_only_past_thirty_days():
    assert _score(sys_health={"uptime_days": 30}
                  )["breakdown"]["System Health"]["score"] == 5
    assert _score(sys_health={"uptime_days": 31}
                  )["breakdown"]["System Health"]["score"] == 3


def test_an_unknown_uptime_is_not_penalised():
    result = _score(sys_health={"uptime_days": None})

    assert result["breakdown"]["System Health"]["score"] == 5


def test_driver_errors_cost_one():
    result = _score(sys_health={"driver_errors": 2})

    assert result["breakdown"]["System Health"]["score"] == 4


def test_the_system_health_category_cannot_go_negative():
    result = _score(sys_health={"pending_reboot": True, "uptime_days": 400,
                                "driver_errors": 5})

    assert result["breakdown"]["System Health"]["score"] == 0


# -- Reporting and hygiene ----------------------------------------------------

def test_the_worst_machine_scores_zero_and_is_at_risk(monkeypatch):
    monkeypatch.setattr(ws, "get_account_policy",
                        lambda: {"available": True, "lockout_threshold": 0})
    result = _score(
        defender_status={"available": False},
        firewall_profiles={"Domain": {"enabled": False},
                           "Private": {"enabled": False},
                           "Public": {"enabled": False}},
        device_sec={"secure_boot": False, "tpm_present": False,
                    "vbs_enabled": False},
        account_data={"available": True, "flagged_count": 9},
        app_control={"smartscreen_on": False, "cfa_enabled": False,
                     "asr_active_count": 0},
        sys_health={"pending_reboot": True, "uptime_days": 400,
                    "driver_errors": 5})

    # Every category bottoms out at 0 rather than going negative, and two of
    # them would: the firewall penalties total 21 against a 20-point category,
    # and System Health takes 6 penalty points out of 5. Without the max(0, …)
    # floors the composite would be negative rather than zero.
    assert result["score"] == 0
    assert result["label"] == "At Risk"
    assert all(cat["score"] == 0 for cat in result["breakdown"].values())


def test_the_first_issue_is_surfaced_as_the_top_issue():
    result = _score(defender_status={"RealTimeProtectionEnabled": False})

    assert result["top_issue"] == "Real-time protection is OFF"


def test_scoring_does_not_mutate_the_caller_s_data():
    """Callers reuse these dicts -- dashboard_view passes the same ones on."""
    args = _healthy()
    before = copy.deepcopy(args)

    ws.get_security_score(**args)

    assert args == before
