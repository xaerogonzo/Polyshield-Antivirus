"""
Per-pattern detection telemetry.

This is what drives the false-positive rates shown in Settings → Advanced
Guardian Settings, which is how a user decides whether to trust a heuristic.
A miscounted ratio there is advice pointing the wrong way, so the arithmetic
is asserted directly rather than through the UI.

These are also the tests that exercise the *real* telemetry writes. Elsewhere
(the Guardian tier matrix) the calls are stubbed so a verdict test cannot fail
for a telemetry reason — which only stays safe if the wiring is proven here.
"""
from __future__ import annotations

from ui.core import pattern_stats as ps

_LABEL = "MSHTA remote payload"


def test_detections_and_ignores_count_independently(pattern_db):
    ps.record_detection(_LABEL)
    ps.record_detection(_LABEL)
    ps.record_ignore(_LABEL)

    stats = {row["pattern"]: row for row in ps.get_stats()}
    assert stats[_LABEL]["detections"] == 2
    assert stats[_LABEL]["ignored"] == 1


def test_fp_rate_is_ignores_over_detections(pattern_db):
    for _ in range(4):
        ps.record_detection(_LABEL)
    ps.record_ignore(_LABEL)

    assert ps.fp_rate(_LABEL) == 0.25


def test_fp_rate_of_an_unknown_pattern_is_zero(pattern_db):
    assert ps.fp_rate("never recorded anything") == 0.0


def test_fp_rate_never_divides_by_zero(pattern_db):
    """An ignore can land before any detection — record_ignore() inserts the
    row with detections=0. The ratio must not raise; it must read as 0.0."""
    ps.record_ignore(_LABEL)

    assert ps.fp_rate(_LABEL) == 0.0
    assert ps.get_stats()[0]["fp_rate"] == 0.0


def test_empty_labels_are_not_recorded(pattern_db):
    ps.record_detection("")
    ps.record_ignore("")

    assert ps.get_stats() == []


def test_stats_are_ordered_by_detection_count(pattern_db):
    ps.record_detection("quiet pattern")
    for _ in range(3):
        ps.record_detection("noisy pattern")

    assert [row["pattern"] for row in ps.get_stats()] == ["noisy pattern", "quiet pattern"]


def test_a_detection_stamps_last_detected_and_an_ignore_does_not(pattern_db):
    ps.record_ignore(_LABEL)
    assert ps.get_stats()[0]["last_detected"] == ""

    ps.record_detection(_LABEL)
    assert ps.get_stats()[0]["last_detected"] != ""


def test_reset_clears_everything(pattern_db):
    ps.record_detection(_LABEL)
    ps.reset()

    assert ps.get_stats() == []
