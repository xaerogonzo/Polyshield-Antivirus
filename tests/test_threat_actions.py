"""
The Threat Actions panel — what the user is actually shown after a scan.

Six engines write into six result maps, and this layer decides which paths
appear, in what order, under which filter chip, and whether each one reads as a
confirmed threat or a heuristic guess. Getting that wrong is not a cosmetic
bug: a suspicious pattern match rendered as a confirmed detection is the tool
telling the user to delete a file it merely finds unusual, and a confirmed hit
filtered out of view is a threat the user never sees.

The last test in the file is deliberately end-to-end. Everything above it
verifies one function against constructed state, which is fast and precise but
cannot catch the two layers disagreeing about the shape of that state.
"""
from __future__ import annotations

import threading

import pytest

from conftest import add_malicious, make_sample_file
from ui.views import scan_view as sv

_A = r"C:\tmp\alpha.exe"
_B = r"C:\tmp\beta.js"
_C = r"C:\tmp\gamma.dll"


@pytest.fixture
def available_engines(monkeypatch):
    monkeypatch.setattr(sv.sc, "is_available", lambda: True)
    monkeypatch.setattr(sv.ge, "is_available", lambda: True)
    monkeypatch.setattr(sv.ye, "is_available", lambda: True)
    monkeypatch.setattr(sv.ce, "is_available", lambda: True)
    monkeypatch.setattr(sv.df, "is_mpcmdrun_available", lambda: True)


@pytest.fixture
def view(tk_root, settings_sandbox, available_engines):
    v = sv.ScanView(tk_root, status_callback=lambda m: None,
                    navigate_callback=lambda *a: None)
    yield v
    try:
        v.destroy()
    except Exception:
        pass


# -- Collecting results across engines ----------------------------------------

def test_paths_are_deduped_across_engines_in_insertion_order(view):
    """The same file flagged by three engines is one row, not three."""
    view._k2_infected_paths = [_A, _B]
    view._g_infected = {_B: "Known Signature", _C: "Suspicious pattern: X"}
    view._yara_infected = {_A: "rule_match"}

    assert view._get_all_infected_paths() == [_A, _B, _C]


def test_no_detections_yields_no_paths(view):
    assert view._get_all_infected_paths() == []


def test_only_the_engines_that_flagged_a_path_produce_a_verdict_row(view):
    """An engine that ran and found nothing must not appear as a verdict —
    the panel would otherwise imply it disagreed when it simply passed."""
    view._k2_infected_paths = [_A]
    view._g_infected = {_A: "Emotet  [7 engines]"}
    view._yara_infected = {_B: "rule_match"}

    names = [name for name, _, _ in view._get_engine_verdicts(_A)]

    assert names == ["K2", "Guardian"]


def test_a_verdict_row_carries_the_engine_s_own_reason(view):
    view._g_infected = {_A: "Emotet  [7 engines]"}
    view._clamav_infected = {_A: "Win.Trojan.Generic"}

    verdicts = dict((name, reason) for name, _, reason in view._get_engine_verdicts(_A))

    assert verdicts["Guardian"] == "Emotet  [7 engines]"
    assert verdicts["ClamAV"] == "Win.Trojan.Generic"


# -- Severity -----------------------------------------------------------------

def test_an_explicit_severity_wins(view):
    view._threat_severity = {_A: "suspicious"}
    view._g_tier = {_A: "hash"}

    assert view._severity_for(_A) == "suspicious"


def test_a_guardian_pattern_hit_falls_back_to_suspicious(view):
    """The inference path, for results that arrived without a severity stamp."""
    view._g_tier = {_A: "pattern"}

    assert view._severity_for(_A) == "suspicious"


def test_everything_else_falls_back_to_confirmed(view):
    view._g_tier = {_A: "hash"}

    assert view._severity_for(_A) == "confirmed"
    assert view._severity_for(_B) == "confirmed"


# -- Reason buckets -----------------------------------------------------------

def test_a_resolved_path_outranks_every_other_bucket(view):
    view._threat_resolved = {_A}
    view._g_tier = {_A: "pattern"}
    view._disputes = [{"path": _A}]

    assert view._reason_bucket(_A) == "resolved"


def test_a_dispute_outranks_the_tier(view):
    view._g_tier = {_A: "hash"}
    view._disputes = [{"path": _A}]

    assert view._reason_bucket(_A) == "dispute"


def test_guardian_tiers_map_onto_buckets(view):
    view._g_tier = {_A: "hash", _B: "pattern"}

    assert view._reason_bucket(_A) == "known"
    assert view._reason_bucket(_B) == "heuristic"


def test_a_k2_detection_without_a_guardian_tier_is_known(view):
    view._k2_infected_paths = [_A]

    assert view._reason_bucket(_A) == "known"


def test_a_yara_rule_match_is_heuristic(view):
    view._yara_infected = {_A: "yara rule dropper_generic"}

    assert view._reason_bucket(_A) == "heuristic"


def test_dispute_matching_ignores_path_casing(view):
    view._disputes = [{"path": _A.upper()}]

    assert view._is_disputed(_A) is True
    assert view._dispute_for_path(_A) is not None


# -- Filtering ----------------------------------------------------------------

@pytest.fixture
def mixed_results(view):
    """One confirmed hash hit, one suspicious pattern hit, one resolved."""
    view._k2_infected_paths = [_A]
    view._g_infected = {_B: "Suspicious pattern: MSHTA remote payload",
                        _C: "Emotet  [7 engines]"}
    view._g_tier = {_B: "pattern", _C: "hash"}
    view._threat_severity = {_A: "confirmed", _B: "suspicious", _C: "confirmed"}
    return view


def test_resolved_paths_are_hidden_from_every_other_view(mixed_results, settings_sandbox):
    settings_sandbox["guardian_suspicious_display"] = "inline"
    mixed_results._threat_resolved = {_C}
    mixed_results._threat_filter_reason = "all"

    assert _C not in mixed_results._get_filtered_paths()


def test_the_resolved_chip_shows_only_resolved_paths(mixed_results, settings_sandbox):
    settings_sandbox["guardian_suspicious_display"] = "inline"
    mixed_results._threat_resolved = {_C}
    mixed_results._threat_filter_reason = "resolved"

    assert mixed_results._get_filtered_paths() == [_C]


def test_hidden_mode_keeps_suspicious_results_out_of_the_default_view(
        mixed_results, settings_sandbox):
    """The default. A heuristic guess should not sit in the same list as a
    signature hit unless the user asks for it."""
    settings_sandbox["guardian_suspicious_display"] = "hidden"
    mixed_results._threat_filter_reason = "all"

    paths = mixed_results._get_filtered_paths()

    assert _B not in paths
    assert paths == [_A, _C]


def test_the_suspicious_chip_reaches_them_even_in_hidden_mode(
        mixed_results, settings_sandbox):
    """Hidden must mean 'not by default', never 'unreachable'."""
    settings_sandbox["guardian_suspicious_display"] = "hidden"
    mixed_results._threat_filter_reason = "suspicious"

    assert mixed_results._get_filtered_paths() == [_B]


def test_inline_mode_interleaves_them(mixed_results, settings_sandbox):
    settings_sandbox["guardian_suspicious_display"] = "inline"
    mixed_results._threat_filter_reason = "all"

    assert mixed_results._get_filtered_paths() == [_A, _B, _C]


def test_collapsible_mode_sorts_suspicious_to_the_end(mixed_results, settings_sandbox):
    """So they group under one 'Heuristic Findings' header rather than
    scattering through the confirmed results."""
    settings_sandbox["guardian_suspicious_display"] = "collapsible"
    mixed_results._threat_filter_reason = "all"

    assert mixed_results._get_filtered_paths() == [_A, _C, _B]


def test_the_text_filter_matches_on_path(mixed_results, settings_sandbox):
    settings_sandbox["guardian_suspicious_display"] = "inline"
    mixed_results._threat_filter_reason = "all"
    mixed_results._threat_filter_text = "beta"

    assert mixed_results._get_filtered_paths() == [_B]


def test_the_text_filter_is_case_insensitive(mixed_results, settings_sandbox):
    settings_sandbox["guardian_suspicious_display"] = "inline"
    mixed_results._threat_filter_reason = "all"
    mixed_results._threat_filter_text = "ALPHA"

    assert mixed_results._get_filtered_paths() == [_A]


def test_the_known_chip_excludes_heuristic_findings(mixed_results, settings_sandbox):
    settings_sandbox["guardian_suspicious_display"] = "inline"
    mixed_results._threat_filter_reason = "known"

    assert mixed_results._get_filtered_paths() == [_A, _C]


def test_the_heuristic_chip_excludes_confirmed_ones(mixed_results, settings_sandbox):
    settings_sandbox["guardian_suspicious_display"] = "inline"
    mixed_results._threat_filter_reason = "heuristic"

    assert mixed_results._get_filtered_paths() == [_B]


def test_the_dispute_chip_shows_only_disagreements(mixed_results, settings_sandbox):
    settings_sandbox["guardian_suspicious_display"] = "inline"
    mixed_results._disputes = [{"path": _A}]
    mixed_results._threat_filter_reason = "dispute"

    assert mixed_results._get_filtered_paths() == [_A]


# -- Rendering ----------------------------------------------------------------

def test_the_panel_hides_itself_when_nothing_was_found(view):
    view._k2_infected_paths = []
    view._g_infected = {}

    view._build_threat_actions()

    assert not view._threat_actions_frame.winfo_ismapped()


def test_the_panel_renders_a_row_for_each_result(mixed_results, settings_sandbox):
    settings_sandbox["guardian_suspicious_display"] = "inline"

    mixed_results._build_threat_actions()

    assert set(mixed_results._row_registry) == {_A, _B, _C}


# -- End to end ---------------------------------------------------------------

def _run_until_done(root, done, timeout_ms=20000):
    """Run a real Tk mainloop until the scan reports back.

    root.update() is not sufficient here. scan_async marshals every result
    through self.after(0, ...) from a daemon thread, and Tkinter's after()
    registers a Tcl command — which raises 'main thread is not in main loop'
    unless a loop is actually running. Production has App.mainloop(); this is
    the same arrangement, with a watchdog so a stall fails the test rather
    than hanging the suite.
    """
    watchdog = root.after(timeout_ms, root.quit)
    root.mainloop()
    try:
        root.after_cancel(watchdog)
    except Exception:
        pass
    return done.is_set()


def test_a_real_detection_travels_from_guardian_to_the_threat_panel(
        tk_root, view, intel_db, settings_sandbox, guardian_sandbox,
        pattern_db, ignore_db, monkeypatch, tmp_path):
    """The contract between the engine and the UI, exercised for real.

    Every test above this one constructs the result maps by hand, which means
    they would all keep passing if guardian_engine started reporting a tier
    the panel does not understand. This one runs the actual scan path — real
    file, real hash lookup, real callback plumbing — and asserts the panel ends
    up showing that same file with that same tier.
    """
    settings_sandbox["guardian_use_patterns"] = False
    settings_sandbox["guardian_use_nsrl"] = False
    settings_sandbox["guardian_suspicious_display"] = "inline"

    sample, md5 = make_sample_file(
        tmp_path, b"a file whose hash is about to be known-bad", name="threat.bin")
    add_malicious(intel_db, md5, family="Emotet")

    done = threading.Event()

    def _finished():
        done.set()
        tk_root.quit()

    monkeypatch.setattr(view, "_maybe_run_speakeasy_pipeline", _finished)

    view._pipeline_cancel_event = threading.Event()
    view._pipeline_pause_event = threading.Event()
    view._pipeline_pause_event.set()

    view._run_guardian_scan([str(tmp_path)])

    assert _run_until_done(tk_root, done), "the Guardian scan never reported back"

    target = str(sample)
    assert target in view._g_infected, "the detection never reached the view"
    assert view._g_tier[target] == "hash"
    assert view._threat_severity[target] == "confirmed"
    assert "Emotet" in view._g_infected[target]

    assert target in view._get_all_infected_paths()
    assert target in view._get_filtered_paths()
    assert view._reason_bucket(target) == "known"
    assert ("Guardian", True, view._g_infected[target]) in \
        view._get_engine_verdicts(target)

    view._build_threat_actions()
    assert target in view._row_registry
