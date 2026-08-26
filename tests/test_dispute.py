"""
find_disputes() — where K2 and Guardian AI disagree.

A dispute is the case the user is asked to adjudicate, so the two things that
matter are that agreement never produces one, and that the path handed back is
one the rest of the UI can actually open.
"""
from __future__ import annotations

from ui.core.dispute import find_disputes


def test_agreement_produces_no_dispute():
    """Both engines flagging, or neither flagging, is not a disagreement."""
    both = find_disputes([r"C:\tmp\evil.exe"], {r"C:\tmp\evil.exe": "Known Signature"})
    assert both == []

    neither = find_disputes([], {})
    assert neither == []


def test_k2_only_detection_is_a_dispute():
    disputes = find_disputes([r"C:\tmp\evil.exe"], {})

    assert len(disputes) == 1
    assert disputes[0]["k2_verdict"] == "Infected"
    assert disputes[0]["guardian_verdict"] == "Clean"
    assert disputes[0]["guardian_reason"] == ""
    assert disputes[0]["filename"] == "evil.exe"


def test_guardian_only_detection_carries_its_reason():
    """The reason is the whole value of a Guardian-only dispute — it is what
    tells the user *why* one engine disagreed."""
    disputes = find_disputes([], {r"C:\tmp\script.js": "Suspicious pattern: MSHTA remote payload"})

    assert len(disputes) == 1
    assert disputes[0]["k2_verdict"] == "Clean"
    assert disputes[0]["guardian_verdict"] == "Infected"
    assert disputes[0]["guardian_reason"] == "Suspicious pattern: MSHTA remote payload"


def test_path_matching_is_case_insensitive():
    """Windows paths differ in case between a k2 report and a Guardian walk.
    Treating those as two different files would invent a dispute per engine."""
    disputes = find_disputes(
        [r"C:\Tmp\Evil.exe"],
        {r"c:\tmp\evil.exe": "Known Signature"},
    )

    assert disputes == []


def test_the_returned_path_keeps_k2_casing():
    """k2's path comes from a real scan report, so it is the one that opens."""
    disputes = find_disputes(
        [r"C:\Windows\System32\Thing.dll"],
        {r"c:\windows\system32\other.dll": "Known Signature"},
    )

    by_verdict = {d["k2_verdict"]: d for d in disputes}
    assert by_verdict["Infected"]["path"] == r"C:\Windows\System32\Thing.dll"


def test_k2_detections_sort_ahead_of_guardian_only_ones():
    """k2 is signature-based, so its verdict carries more confidence and is
    what the user should be asked about first."""
    disputes = find_disputes(
        [r"C:\tmp\zebra.exe"],
        {r"C:\tmp\alpha.js": "Suspicious pattern: Script dropper"},
    )

    assert [d["filename"] for d in disputes] == ["zebra.exe", "alpha.js"]


def test_same_verdict_group_sorts_by_filename():
    disputes = find_disputes([r"C:\tmp\b.exe", r"C:\tmp\a.exe"], {})

    assert [d["filename"] for d in disputes] == ["a.exe", "b.exe"]
