"""
The shot list — one function per scene, registered by name.

A scene sets a view into a specific state and takes one or more shots. States
that are hard to reach on a real machine (a feed that downloaded but is
unusable, an intelligence store that cannot be read) are constructed directly,
which is the point: those are exactly the states nobody ever sees until they
matter.
"""
from __future__ import annotations

from datetime import datetime, timedelta

_SCENES: dict[str, callable] = {}


def scene(name: str):
    def register(fn):
        _SCENES[name] = fn
        return fn
    return register


def all_scenes() -> dict[str, callable]:
    return dict(_SCENES)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _feeds(**overrides):
    base = {
        "malwarebazaar": {"label": "MalwareBazaar hashes", "state": "fresh",
                          "age_hours": 2.0, "enabled": True},
        "c2": {"label": "C2 IP blocklist", "state": "fresh",
               "age_hours": 2.0, "enabled": True},
        "yara": {"label": "YARA community rules", "state": "fresh",
                 "age_hours": 2.0, "enabled": True},
    }
    for key, value in overrides.items():
        base[key] = {**base[key], **value}
    return base


def _usable(**overrides):
    base = {
        "malwarebazaar": {"usable": True, "count": 8738, "unit": "hashes"},
        "c2": {"usable": True, "count": 6, "unit": "IPs"},
        "yara": {"usable": True, "count": 1, "unit": "rule files"},
    }
    for key, value in overrides.items():
        base[key] = {**base[key], **value}
    return base


def _posture(state, level, headline, detail, feeds=None, usable=None):
    return {"state": state, "level": level, "headline": headline,
            "detail": detail, "feeds": feeds or _feeds(),
            "usable": usable or _usable()}


def _dashboard(session):
    from ui.views.dashboard_view import DashboardView
    return session.mount(DashboardView, status_callback=lambda m: None,
                         navigate_callback=lambda k: None)


# ── Scenes ────────────────────────────────────────────────────────────────────

@scene("dashboard")
def dashboard_live(session):
    """The Dashboard exactly as it is right now, against live data."""
    _dashboard(session)
    session.shot("dashboard")


@scene("intel-posture")
def intel_posture_states(session):
    """All four posture states — the ones a real machine shows one at a time."""
    view = _dashboard(session)

    view._build_intel_card(_posture(
        "current", "ok", "Protected — intelligence current",
        "All feeds up to date."))
    session.shot("intel_current")

    view._build_intel_card(_posture(
        "stale", "warn", "Protected — intelligence stale",
        "Out of date: MalwareBazaar hashes, C2 IP blocklist",
        feeds=_feeds(malwarebazaar={"state": "stale", "age_hours": 740.0},
                     c2={"state": "stale", "age_hours": 740.0})))
    session.shot("intel_stale")

    # The failure the Phase C live test found: downloaded fine, unusable.
    view._build_intel_card(_posture(
        "update_required", "warn", "Intelligence update required",
        "Reported current but unusable: YARA community rules",
        usable=_usable(yara={"usable": False, "count": 0})))
    session.shot("intel_unusable")

    view._build_intel_card(_posture(
        "update_required", "warn", "Intelligence update required",
        "Never updated: C2 IP blocklist, YARA community rules",
        feeds=_feeds(c2={"state": "never", "age_hours": None},
                     yara={"state": "never", "age_hours": None}),
        usable=_usable(c2={"usable": False, "count": 0},
                       yara={"usable": False, "count": 0})))
    session.shot("intel_never")

    view._build_intel_card(_posture(
        "unavailable", "error", "Intelligence unavailable",
        "The intelligence database could not be read.",
        usable=_usable(malwarebazaar={"usable": False, "count": 0,
                                      "readable": False})))
    session.shot("intel_unavailable")


@scene("settings")
def settings_view(session):
    from ui.views.settings_view import SettingsView
    view = session.mount(SettingsView)
    session.shot("settings_top")

    # Scroll to the intelligence section rather than clicking anything.
    try:
        view._parent_canvas.yview_moveto(0.82)
    except Exception:
        pass
    session.shot("settings_intel")


@scene("update-center")
def update_center(session):
    from ui.views.update_view import UpdateView
    session.mount(UpdateView, status_callback=lambda m: None)
    session.shot("update_center")


@scene("service")
def service_view(session):
    from ui.views.service_view import ServiceView
    view = session.mount(ServiceView, status_callback=lambda m: None)
    # Feed it the event shapes the service pushes, without a service running.
    for event in (
        {"event": "intel_update", "status": "updated",
         "summary": "malwarebazaar: updated, c2: updated, yara: unchanged",
         "time": "2026-08-20 06:12:30"},
        {"event": "intel_update", "status": "partial",
         "summary": "malwarebazaar: updated, c2: failed",
         "time": "2026-08-20 07:12:30"},
    ):
        view._handle_event(event)
    session.shot("service_events")
