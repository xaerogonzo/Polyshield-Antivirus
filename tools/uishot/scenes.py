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

from polybedrock.ui.uishot import SceneRegistry

#: PolyShield's scenes. The registry itself moved to PolyBedrock so PolyScour
#: can use the same decorator; every call site below is unchanged.
REGISTRY = SceneRegistry()
scene = REGISTRY.scene
all_scenes = REGISTRY.all_scenes
golden_scenes = REGISTRY.golden_scenes


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

@scene("dashboard", golden=False)
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


@scene("settings", golden=False)
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


@scene("update-center", golden=False)
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


# ── Threat Actions ────────────────────────────────────────────────────────────

def _scan(session):
    from ui.views.scan_view import ScanView
    view = session.mount(ScanView, status_callback=lambda m: None,
                         navigate_callback=lambda *a: None)
    # Collapse the pipeline panel — expanded it fills the window and pushes
    # Threat Actions, the subject of these scenes, below the fold. Collapsing
    # is also what a user does once the pipeline is configured.
    view._toggle_pipeline_panel()
    session.settle()
    return view


def _threats(view, *, k2=(), guardian=None, tier=None, severity=None,
             disputes=(), resolved=()):
    """Load a ScanView with engine results, the way a finished scan leaves it.

    Constructed rather than scanned, for the same reason the intel-posture
    scenes are: these are the states that matter and the ones nobody sees on
    demand. A real scan would also make the shot depend on whatever happens to
    be on this machine.
    """
    view._k2_infected_paths = list(k2)
    view._g_infected = dict(guardian or {})
    view._g_tier = dict(tier or {})
    view._threat_severity = dict(severity or {})
    view._disputes = list(disputes)
    view._threat_resolved = set(resolved)
    view._threat_filter_reason = "all"
    view._threat_filter_text = ""
    view._threat_page = 0
    # Clear the selection between scenes. Left set, a later scene renders the
    # previous scene's file in the detail pane beside its own results — a
    # screen that cannot occur in use, which is the worst thing a golden can
    # record.
    view._threat_selected_path = None
    view._build_threat_actions()


_CONFIRMED = {
    r"C:\Users\Test\Downloads\invoice_scan.exe": "Emotet  [61 engines]",
    r"C:\Users\Test\AppData\Local\Temp\svhost.exe": "TrickBot  [54 engines]",
}
_SUSPICIOUS = {
    r"C:\Users\Test\Documents\backup_helper.js":
        "Suspicious pattern: Script dropper (WScript.Shell.Run)",
    r"C:\Users\Test\Desktop\notes\recovery.txt":
        "Suspicious pattern: Ransomware note (files encrypted)",
}


@scene("scan-threats")
def scan_threat_states(session):
    """The Threat Actions panel across the states a scan can leave it in."""
    from ui.core import settings as cfg

    view = _scan(session)

    # Confirmed detections only — the unambiguous case.
    _threats(view,
             k2=list(_CONFIRMED),
             guardian=_CONFIRMED,
             tier={p: "hash" for p in _CONFIRMED},
             severity={p: "confirmed" for p in _CONFIRMED})
    session.shot("threats_confirmed")

    # Confirmed plus heuristic, grouped rather than interleaved. This is the
    # display mode where the distinction is visible at a glance.
    cfg.set_value("guardian_suspicious_display", "collapsible")
    merged = {**_CONFIRMED, **_SUSPICIOUS}
    _threats(view,
             k2=list(_CONFIRMED),
             guardian=merged,
             tier={**{p: "hash" for p in _CONFIRMED},
                   **{p: "pattern" for p in _SUSPICIOUS}},
             severity={**{p: "confirmed" for p in _CONFIRMED},
                       **{p: "suspicious" for p in _SUSPICIOUS}})
    session.shot("threats_mixed_collapsible")

    # One engine says infected, the other says clean — the case the user is
    # asked to adjudicate.
    disputed = r"C:\Users\Test\Downloads\installer.exe"
    cfg.set_value("guardian_suspicious_display", "inline")
    _threats(view,
             k2=[disputed],
             guardian={},
             disputes=[{"path": disputed,
                        "filename": "installer.exe",
                        "k2_verdict": "Infected",
                        "guardian_verdict": "Clean",
                        "guardian_reason": ""}])
    # Pin the hashes. The detail pane computes them on a background thread and
    # renders "computing…" until they land, so without this the shot records
    # whichever side of a race the capture happened to catch — a golden that
    # depends on thread timing is worse than no golden.
    view._hash_cache[disputed] = {
        "md5": "5d41402abc4b2a76b9719d911017c592",
        "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e"
                  "1b161e5c1fa7425e73043362938b9824",
    }
    view._threat_selected_path = disputed
    view._render_threat_detail()
    session.shot("threats_dispute")

    # The pattern tier gave up partway through the scan.
    _threats(view,
             k2=list(_CONFIRMED),
             guardian=_CONFIRMED,
             tier={p: "hash" for p in _CONFIRMED},
             severity={p: "confirmed" for p in _CONFIRMED})
    view._circuit_state = {"tripped": True, "hit_count": 200, "threshold": 200}
    view._circuit_banner_dismissed = False
    view._render_circuit_banner()
    session.shot("threats_circuit_tripped")
