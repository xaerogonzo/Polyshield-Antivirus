"""
Phase E — the Dashboard's Threat Intelligence card.

These build a real (withdrawn) Tk root and read the rendered widgets back, so
they cover what a screenshot would show without needing a visible window or the
mouse.  Skipped automatically where Tk cannot initialise.

The point of the card is honesty, so that is what is asserted: each of the four
posture states must reach the user verbatim, and a feed that downloaded fine but
cannot be loaded must not show up green.
"""
from __future__ import annotations

import pytest

ctk = pytest.importorskip("customtkinter")


@pytest.fixture(scope="session")
def tk_root():
    """One Tk root for the whole session.

    Deliberately session-scoped: creating and destroying a CTk root per test
    tears down Tcl's library state, and the *next* root then fails with
    'invalid command name "tcl_findLibrary"'.  That surfaced here as an
    intermittent skip — a test quietly protecting nothing.
    """
    import tkinter
    try:
        root = ctk.CTk()
    except tkinter.TclError as exc:                      # no display
        pytest.skip(f"Tk unavailable: {exc}")
    root.withdraw()
    import ui.theme as theme
    from ui.core import settings as cfg
    theme.init(cfg)
    theme.init_colors(cfg)
    yield root
    try:
        root.destroy()
    except Exception:
        pass


@pytest.fixture
def dash(tk_root):
    """A fresh view per test, on the shared root."""
    from ui.views.dashboard_view import DashboardView
    view = DashboardView(tk_root, status_callback=lambda m: None,
                         navigate_callback=lambda k: None)
    yield view
    try:
        view.destroy()
    except Exception:
        pass


def _labels(frame) -> list[str]:
    """Every label text in a frame tree, flattened."""
    out = []
    for w in frame.winfo_children():
        if isinstance(w, ctk.CTkLabel):
            out.append(str(w.cget("text")))
        out.extend(_labels(w))
    return out


def _posture(state, level, headline, detail, feeds, usable):
    return {"state": state, "level": level, "headline": headline,
            "detail": detail, "feeds": feeds, "usable": usable}


_FEEDS_OK = {
    "malwarebazaar": {"label": "MalwareBazaar hashes", "state": "fresh",
                      "age_hours": 2.0, "enabled": True},
    "c2": {"label": "C2 IP blocklist", "state": "fresh",
           "age_hours": 2.0, "enabled": True},
    "yara": {"label": "YARA community rules", "state": "fresh",
             "age_hours": 2.0, "enabled": True},
}
_USABLE_OK = {
    "malwarebazaar": {"usable": True, "count": 8738, "unit": "hashes"},
    "c2": {"usable": True, "count": 6, "unit": "IPs"},
    "yara": {"usable": True, "count": 1, "unit": "rule files"},
}


@pytest.mark.parametrize("state,level,headline,colour", [
    ("current",         "ok",    "Protected — intelligence current", "#50fa7b"),
    ("stale",           "warn",  "Protected — intelligence stale",   "#ffb86c"),
    ("update_required", "warn",  "Intelligence update required",     "#ffb86c"),
    ("unavailable",     "error", "Intelligence unavailable",         "#ff5555"),
])
def test_card_renders_each_posture_state(dash, state, level, headline, colour):
    dash._build_intel_card(_posture(state, level, headline, "detail line",
                                    _FEEDS_OK, _USABLE_OK))
    texts = _labels(dash._intel_frame)
    assert headline in texts, f"{state} headline missing from the card"

    headline_lbls = [w for w in dash._intel_frame.winfo_children()
                     if isinstance(w, ctk.CTkLabel) and str(w.cget("text")) == headline]
    assert headline_lbls, "headline label not found"
    assert headline_lbls[0].cget("text_color") == colour


def test_fresh_but_unusable_feed_is_not_shown_as_healthy(dash):
    """The Phase C failure, as the user would have seen it: YARA fresh, zero
    rules.  The row must read 'unusable' with a red dot, not a green tick."""
    usable = dict(_USABLE_OK)
    usable["yara"] = {"usable": False, "count": 0, "unit": "rule files"}

    dash._build_intel_card(_posture(
        "update_required", "warn", "Intelligence update required",
        "Reported current but unusable: YARA community rules",
        _FEEDS_OK, usable))

    texts = _labels(dash._intel_frame)
    assert "unusable" in texts
    assert "1,000 rule files" not in texts

    # The dot next to the YARA row must be red despite state == "fresh".
    for row in dash._intel_frame.winfo_children():
        kids = [w for w in row.winfo_children() if isinstance(w, ctk.CTkLabel)]
        if any(str(k.cget("text")) == "YARA community rules" for k in kids):
            dot = kids[0]
            assert str(dot.cget("text")) == "●"
            assert dot.cget("text_color") == "#ff5555"
            break
    else:
        pytest.fail("YARA row not rendered")


def test_never_updated_feed_reads_never_not_zero_hours(dash):
    feeds = {k: dict(v) for k, v in _FEEDS_OK.items()}
    feeds["c2"] = {"label": "C2 IP blocklist", "state": "never",
                   "age_hours": None, "enabled": True}
    dash._build_intel_card(_posture("update_required", "warn",
                                    "Intelligence update required",
                                    "Never updated: C2 IP blocklist",
                                    feeds, _USABLE_OK))
    assert "never" in _labels(dash._intel_frame)


def test_estimated_age_is_marked_as_such(dash):
    """Legacy installs have rules but no install timestamp; the age shown is
    inferred from disk and must not masquerade as a recorded fact."""
    feeds = {k: dict(v) for k, v in _FEEDS_OK.items()}
    feeds["yara"]["estimated"] = True
    feeds["yara"]["age_hours"] = 196.0
    dash._build_intel_card(_posture("stale", "warn",
                                    "Protected — intelligence stale",
                                    "Out of date: YARA community rules",
                                    feeds, _USABLE_OK))
    assert any("est." in t for t in _labels(dash._intel_frame))


def test_stale_intel_clamps_a_green_security_posture_card(dash):
    """A high Windows score must not paint the posture card green while the
    intelligence layer is degraded."""
    score = {"score": 92, "label": "Good", "top_issue": "",
             "breakdown": {"Firewall": {"issues": []}}}
    dfn_status = {"available": True, "RealTimeProtectionEnabled": True}

    dash._intel_posture = {"level": "ok", "headline": "Protected — intelligence current"}
    dash._apply(dfn_status, {"raw": ""}, None, [], score)
    assert dash._cards["defender"]["status"].cget("text_color") == "#50fa7b"

    dash._intel_posture = {"level": "warn", "headline": "Protected — intelligence stale"}
    dash._apply(dfn_status, {"raw": ""}, None, [], score)
    assert dash._cards["defender"]["status"].cget("text_color") == "#ffb86c"

    dash._intel_posture = {"level": "error", "headline": "Intelligence unavailable"}
    dash._apply(dfn_status, {"raw": ""}, None, [], score)
    assert dash._cards["defender"]["status"].cget("text_color") == "#ff5555"


def test_posture_headline_reaches_the_security_card(dash):
    score = {"score": 92, "label": "Good", "top_issue": "some windows issue",
             "breakdown": {"Firewall": {"issues": []}}}
    dash._intel_posture = {"level": "warn", "headline": "Intelligence update required"}
    dash._apply({"available": True, "RealTimeProtectionEnabled": True},
                {"raw": ""}, None, [], score)
    details = [l.cget("text") for l in dash._cards["defender"]["details"]]
    assert "Intelligence update required" in details
