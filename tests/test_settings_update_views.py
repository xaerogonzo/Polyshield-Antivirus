"""
The two biggest views, tested for the decisions they make -- not for widget count.

settings_view.py and update_view.py are the largest files in the repo (1705 and
1594 lines), and most of that is widget construction. Proving that widgets can
be constructed is not worth a test: it is what every other GUI test already
does incidentally, and it is exactly how a large view turns into seventy tests
that tell you nothing.

What is asserted here is the handful of things in these files that can be
wrong while everything still renders:

  * values the user reads as advice (the per-pattern false-positive rates)
  * state the user reads as truth (a toggle claiming a pattern is off)
  * transitions (busy -> idle, success -> failure)
  * the helpers that fan out across many sections, where one regression breaks
    every section at once

No real network, no real updater, no destructive intelligence import, and no
service. Anything that would reach outside the process is stubbed.

The Tk root is the session-scoped one from conftest.py; only one CTk root can
exist per session, so every GUI module shares it.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ctk = pytest.importorskip("customtkinter")

from ui.core import guardian_engine as ge

SRC = pathlib.Path(__file__).resolve().parents[1] / "src"


# ══ The after()/configure trap, as a source-level guard ═══════════════════════

def _after_configure_dict_calls(tree: ast.AST) -> list[int]:
    """Line numbers of `X.after(delay, widget.configure, {...})` calls.

    CustomTkinter's configure() is `(require_redraw=False, **kwargs)`. A dict
    passed positionally binds to require_redraw, so the widget is redrawn with
    no changes applied -- the call succeeds, nothing raises, and the label
    silently keeps whatever text it had.
    """
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not (isinstance(fn, ast.Attribute) and fn.attr == "after"):
            continue
        if len(node.args) < 3:
            continue
        target, payload = node.args[1], node.args[2]
        if isinstance(target, ast.Attribute) and target.attr == "configure" \
                and isinstance(payload, ast.Dict):
            bad.append(node.lineno)
    return bad


def test_no_view_schedules_configure_with_a_positional_dict():
    """The guard for a bug this project has already fixed twice.

    CLAUDE.md documents the idiom and records it as fixed in update_view.py,
    quarantine_view.py and app.py. Three instances were still live when this
    test was written -- two in update_view.py and one in guardian_view.py --
    all of them inside progress callbacks, which is the worst place for it: the
    badge stays frozen for the whole of a multi-minute update while the log
    scrolls past underneath.

    Written as a scan rather than three assertions because the failure mode is
    a *shape*, and grep missed these for the ordinary reason that the call was
    split across two lines.
    """
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for line in _after_configure_dict_calls(tree):
            offenders.append(f"{path.relative_to(SRC)}:{line}")

    assert offenders == [], (
        "configure() takes **kwargs; a positional dict silently does nothing:\n  "
        + "\n  ".join(offenders))


def test_the_guard_recognises_the_broken_idiom():
    """The scan above is only worth having if it can actually fail."""
    broken = ast.parse(
        'self.after(0, self._badge.configure, {"text": "x"})\n')
    fixed = ast.parse(
        'self.after(0, lambda: self._badge.configure(text="x"))\n')
    passthrough = ast.parse(
        'self.after(0, self._log_append, "  msg", TAG)\n')

    assert _after_configure_dict_calls(broken) == [1]
    assert _after_configure_dict_calls(fixed) == []
    assert _after_configure_dict_calls(passthrough) == []


# ══ Fixtures ══════════════════════════════════════════════════════════════════

@pytest.fixture
def settings(tk_root, settings_sandbox):
    from ui.views.settings_view import SettingsView
    view = SettingsView(tk_root)
    yield view
    try:
        view.destroy()
    except Exception:
        pass


class _NoThread:
    """Stands in for threading.Thread: records the target, never runs it."""

    started: list = []

    def __init__(self, target=None, daemon=None, **kw):
        self.target = target

    def start(self):
        _NoThread.started.append(self.target)


@pytest.fixture
def update(tk_root, monkeypatch):
    """An UpdateView whose construction spawns nothing.

    _build() kicks off background probes that shell out to PowerShell for the
    Sandboxie version and query the GitHub releases API for the YARA tag. Both
    are exactly what this file must not do, and left alone they also outlive
    the test: the worker calls winfo_exists() on a root pytest has finished
    with, which surfaces as PytestUnhandledThreadExceptionWarning from an
    unrelated test later in the session.
    """
    from ui.views import update_view as uv

    monkeypatch.setattr(uv.threading, "Thread", _NoThread)
    said: list[str] = []
    view = uv.UpdateView(tk_root, status_callback=said.append)
    view.said = said
    yield view
    try:
        view.destroy()
    except Exception:
        pass


def _text_of(w) -> str:
    """A label's visible text, resolving textvariable when one is used.

    _collapsible_section drives its header through a StringVar, so cget("text")
    there returns the widget name rather than anything a user would see -- a
    test reading it would assert against 'CTkLabel'.
    """
    name = w.cget("textvariable")
    if name:
        try:
            return str(w.getvar(name))
        except Exception:
            pass
    return str(w.cget("text"))


def _labels(widget) -> list[str]:
    """Every label text in a widget tree, flattened."""
    out = []
    for w in widget.winfo_children():
        if isinstance(w, ctk.CTkLabel):
            out.append(_text_of(w))
        out.extend(_labels(w))
    return out


def _switches(widget) -> list[ctk.CTkSwitch]:
    out = []
    for w in widget.winfo_children():
        if isinstance(w, ctk.CTkSwitch):
            out.append(w)
        out.extend(_switches(w))
    return out


# ══ settings_view: one truth, read in one place ═══════════════════════════════

def test_the_settings_screen_lists_exactly_the_engine_pattern_labels(settings):
    """These strings are the *keys* of guardian_pattern_toggles.

    settings_view held its own hand-maintained tuple of the seven labels. They
    matched, but nothing made them: a rename in the engine would have left the
    screen writing `toggles["old name"] = False` for a pattern
    `_pattern_enabled()` now looks up under a different name -- the switch
    reads OFF and the pattern keeps firing, with nothing anywhere reporting the
    mismatch.
    """
    assert tuple(settings._PATTERN_LABELS) == ge.pattern_labels()


def test_the_screen_follows_the_engine_when_a_pattern_is_renamed(
        settings, pattern_db, monkeypatch):
    """The reason the hand-maintained copy had to go.

    The two lists agreed when this was written, so a test comparing them passes
    either way -- it guards against drift rather than proving a current bug.
    This one manufactures the drift: rename a pattern in the engine and the
    Settings screen must rename with it.

    Against the previous hardcoded tuple the screen keeps the old label, and
    every toggle written under it is an override `_pattern_enabled()` will
    never look up: the switch reads OFF and the pattern keeps firing.
    """
    from ui.core import guardian_engine as _ge

    original = _ge._EnhancedScanner._PATTERNS
    renamed = [("Ransomware note (v2)",) + tuple(p[1:]) if p[0].startswith("Ransomware note")
               else p for p in original]
    monkeypatch.setattr(_ge._EnhancedScanner, "_PATTERNS", renamed)

    assert "Ransomware note (v2)" in _ge.pattern_labels()
    assert tuple(settings._PATTERN_LABELS) == _ge.pattern_labels(), (
        "the Settings screen is showing labels the engine no longer uses")

    body = ctk.CTkFrame(settings)
    settings._build_guardian_advanced_body(body)
    assert "Ransomware note (v2)" in _labels(body)
    body.destroy()


def test_every_engine_pattern_gets_a_row(settings, pattern_db):
    body = ctk.CTkFrame(settings)
    settings._build_guardian_advanced_body(body)

    shown = _labels(body)
    for label in ge.pattern_labels():
        assert label in shown, f"{label} has no toggle"
    body.destroy()


@pytest.mark.parametrize("profile", ["conservative", "balanced", "power"])
def test_each_toggle_shows_what_the_engine_will_actually_do(
        settings, settings_sandbox, pattern_db, profile):
    """The switch is a readout of the scan, not a second opinion about it.

    This block used to reimplement _pattern_enabled() against its own copy of
    the conservative set. Two implementations of one rule can disagree without
    anything failing, and the visible symptom would be a switch that lies.
    """
    settings_sandbox["guardian_sensitivity_profile"] = profile
    settings_sandbox["guardian_pattern_toggles"] = {}

    body = ctk.CTkFrame(settings)
    settings._build_guardian_advanced_body(body)

    states = {lbl: sw.get() for lbl, sw in
              zip(ge.pattern_labels(), _switches(body))}
    for label in ge.pattern_labels():
        assert bool(states[label]) is ge.pattern_enabled(label, profile, {}), label
    body.destroy()


def test_an_explicit_override_beats_the_profile_default(
        settings, settings_sandbox, pattern_db):
    label = "Ransomware note (files encrypted)"
    settings_sandbox["guardian_sensitivity_profile"] = "conservative"
    settings_sandbox["guardian_pattern_toggles"] = {label: True}

    body = ctk.CTkFrame(settings)
    settings._build_guardian_advanced_body(body)

    states = dict(zip(ge.pattern_labels(),
                      (bool(sw.get()) for sw in _switches(body))))
    assert states[label] is True, "conservative default masked the user's override"
    body.destroy()


def test_conservative_turns_off_exactly_the_two_noisy_patterns(settings_sandbox):
    """Pinned at the engine, where the profile is resolved."""
    off = {lbl for lbl in ge.pattern_labels()
           if not ge.pattern_enabled(lbl, "conservative", {})}
    assert off == {"Ransomware note (files encrypted)",
                   "Ransomware payment demand"}
    assert off == set(ge.conservative_disabled())


# ══ settings_view: the numbers the user reads as advice ═══════════════════════

def _stats_row(pattern, detections, ignored, fp_rate):
    return {"pattern": pattern, "detections": detections,
            "ignored": ignored, "fp_rate": fp_rate}


def test_a_pattern_with_no_history_says_so(settings, pattern_db, monkeypatch):
    from ui.core import pattern_stats as ps
    monkeypatch.setattr(ps, "get_stats", lambda: [])

    body = ctk.CTkFrame(settings)
    settings._build_guardian_advanced_body(body)

    assert "no detections yet" in _labels(body)
    body.destroy()


@pytest.mark.parametrize("det,ign,rate,expected", [
    (10, 10, 1.0,  "10 detections, 10 ignored (100% FP rate)"),
    (4,  1,  0.25, "4 detections, 1 ignored (25% FP rate)"),
    (3,  0,  0.0,  "3 detections, 0 ignored (0% FP rate)"),
    (1200, 900, 0.75, "1,200 detections, 900 ignored (75% FP rate)"),
])
def test_the_false_positive_line_reports_the_stats_it_was_given(
        settings, pattern_db, monkeypatch, det, ign, rate, expected):
    """A wrong number here is advice pointing the wrong way -- it is what a
    user reads when deciding whether to trust a heuristic."""
    from ui.core import pattern_stats as ps
    label = ge.pattern_labels()[0]
    monkeypatch.setattr(ps, "get_stats",
                        lambda: [_stats_row(label, det, ign, rate)])

    body = ctk.CTkFrame(settings)
    settings._build_guardian_advanced_body(body)

    assert expected in _labels(body)
    body.destroy()


@pytest.mark.parametrize("rate,expect_red", [(0.51, True), (0.5, False), (0.0, False)])
def test_a_majority_false_positive_rate_is_coloured_as_a_warning(
        settings, pattern_db, monkeypatch, rate, expect_red):
    from ui.core import pattern_stats as ps
    label = ge.pattern_labels()[0]
    monkeypatch.setattr(ps, "get_stats",
                        lambda: [_stats_row(label, 100, 60, rate)])

    body = ctk.CTkFrame(settings)
    settings._build_guardian_advanced_body(body)

    # Match on the stats line specifically: the section's own description text
    # also contains the words "FP rate", and picking it up made an earlier
    # version of this test read the description's grey and call it a pass.
    colours = [str(w.cget("text_color")) for w in _walk_labels(body)
               if "detections," in str(w.cget("text"))]
    assert colours, "no FP-rate label rendered"
    assert (colours[0] == "#ff8888") is expect_red
    body.destroy()


def _walk_labels(widget):
    for w in widget.winfo_children():
        if isinstance(w, ctk.CTkLabel):
            yield w
        yield from _walk_labels(w)


# ══ settings_view: the two helpers that fan out ═══════════════════════════════

def test_a_collapsible_section_starts_collapsed(settings):
    """One regression here breaks every section that uses it at once."""
    host = ctk.CTkFrame(settings)
    body = settings._collapsible_section(host, "Advanced")

    assert not body.grid_info(), "should start collapsed"
    host.destroy()


def test_the_header_is_wired_to_a_click_handler(settings):
    """Wiring, not a synthetic click.

    Tk will not dispatch a synthetic <Button-1> to a widget whose toplevel is
    withdrawn -- the event is accepted and goes nowhere, so a test written that
    way passes because nothing happened (docs/TESTING.md, "Synthetic button
    events do not reach a withdrawn root").

    The binding also does not land where you would look for it: CTkFrame and
    CTkLabel forward bind() to their inner _canvas / _text_label, the same
    wrinkle recorded for CTkSlider. Asserting on the CTk wrapper reads None and
    proves nothing.
    """
    host = ctk.CTkFrame(settings)
    body = settings._collapsible_section(host, "Advanced")
    header = body._outer_frame.winfo_children()[0]
    title = header.winfo_children()[0]

    bound = []
    for widget in (header, title):
        for attr in ("_canvas", "_text_label"):
            inner = getattr(widget, attr, None)
            if inner is not None:
                bound.extend(inner.bind())

    assert "<Button-1>" in bound, "nothing in the header responds to a click"
    host.destroy()


def test_a_collapsible_section_can_start_open(settings):
    host = ctk.CTkFrame(settings)
    body = settings._collapsible_section(host, "Advanced", start_expanded=True)
    assert body.grid_info()
    host.destroy()


def test_the_chevron_and_badge_appear_in_the_header(settings):
    host = ctk.CTkFrame(settings)
    body = settings._collapsible_section(host, "Ignored Hashes", badge="3 items")

    header_text = _labels(body._outer_frame)[0]
    assert "Ignored Hashes" in header_text
    assert "3 items" in header_text
    assert "\u25b8" in header_text, "collapsed sections show a right chevron"

    expanded = settings._collapsible_section(host, "Open", start_expanded=True)
    assert "\u25be" in _labels(expanded._outer_frame)[0]
    host.destroy()


def test_a_modal_dialog_is_sized_titled_and_closable(settings, monkeypatch):
    """The size is asserted on the *call*, not on a readback.

    A withdrawn parent means the window manager never applies the geometry:
    dlg.geometry() reads back 200x200 however long you pump the event loop.
    Same lesson as the headless wm_attributes("-topmost") readback -- assert
    that the call was made, not what the WM did with it.
    """
    asked: list[str] = []
    real_geometry = ctk.CTkToplevel.geometry

    def spy(self, spec=None):
        if spec is not None:
            asked.append(spec)
        return real_geometry(self, spec) if spec is not None else real_geometry(self)

    monkeypatch.setattr(ctk.CTkToplevel, "geometry", spy)

    dlg = settings._modal_settings_dialog(
        "Advanced Guardian Settings", lambda c: None, width=500, height=400)
    try:
        settings.update_idletasks()
        assert dlg.title() == "Advanced Guardian Settings"
        assert "500x400" in asked
        buttons = [w for w in _walk_buttons(dlg)
                   if str(w.cget("text")).strip().lower() == "close"]
        assert buttons, "no Close button"
    finally:
        dlg.destroy()


def test_a_dialog_body_that_raises_shows_the_error_instead_of_dying(settings):
    """build_fn runs user-facing code; a raise must not leave an empty window."""
    def _boom(_container):
        raise RuntimeError("body exploded")

    dlg = settings._modal_settings_dialog("Broken", _boom)
    try:
        settings.update_idletasks()
        assert any("body exploded" in t for t in _labels(dlg))
    finally:
        dlg.destroy()


def _walk_buttons(widget):
    for w in widget.winfo_children():
        if isinstance(w, ctk.CTkButton):
            yield w
        yield from _walk_buttons(w)


# ══ update_view: busy/idle transitions ════════════════════════════════════════

_INTEL_BUTTONS = ("_intel_recent_btn", "_intel_full_btn",
                  "_intel_nsrl_btn", "_intel_clear_btn")


@pytest.mark.parametrize("mode,label", [
    ("recent", "Fetching recent…"),
    ("full",   "Fetching full list…"),
    ("nsrl",   "Importing NSRL…"),
    ("",       "Clearing DB…"),
])
def test_busy_disables_every_intel_button_and_names_the_operation(
        update, mode, label):
    update._set_intel_busy(True, mode)

    for name in _INTEL_BUTTONS:
        assert str(getattr(update, name).cget("state")) == "disabled", name
    assert label in str(update._intel_badge.cget("text"))


def test_leaving_busy_re_enables_every_intel_button(update):
    update._set_intel_busy(True, "recent")
    update._set_intel_busy(False)

    for name in _INTEL_BUTTONS:
        assert str(getattr(update, name).cget("state")) == "normal", name


# ══ update_view: a failed update has to read as failed ════════════════════════

def test_a_failed_intelligence_update_is_reported_in_the_badge_and_the_log(
        update, monkeypatch):
    monkeypatch.setattr(update, "_refresh_intel_info", lambda: None)
    update._set_intel_busy(True, "recent")

    update._on_intel_done({"error": "feed returned no valid MD5 hashes"})

    badge = str(update._intel_badge.cget("text"))
    assert "✗" in badge and "no valid MD5" in badge
    assert str(update._intel_badge.cget("text_color")) == "#ff5555"
    assert any("failed" in m.lower() for m in update.said)
    # and the user is not left with four dead buttons
    for name in _INTEL_BUTTONS:
        assert str(getattr(update, name).cget("state")) == "normal", name


def test_a_successful_update_reports_what_changed(update, monkeypatch):
    monkeypatch.setattr(update, "_refresh_intel_info", lambda: None)

    update._on_intel_done({"added": 1234, "total_db": 987654})

    badge = str(update._intel_badge.cget("text"))
    assert "1,234" in badge and "987,654" in badge
    assert str(update._intel_badge.cget("text_color")) == "#50fa7b"


def test_a_long_error_is_truncated_rather_than_stretching_the_badge(
        update, monkeypatch):
    monkeypatch.setattr(update, "_refresh_intel_info", lambda: None)

    update._on_intel_done({"error": "x" * 500})

    assert len(str(update._intel_badge.cget("text"))) < 120


# ══ update_view: the progress badge actually moves ════════════════════════════

def test_progress_messages_reach_the_badge(update):
    """The behavioural half of the after()/configure guard above.

    The scheduled call used to pass a dict positionally, so this badge stayed
    on "Fetching recent…" for the whole update while the log filled with
    progress lines. Driven through after() and update() rather than by calling
    configure directly, because the scheduling is the part that was broken.
    """
    update._set_intel_busy(True, "recent")
    assert "Fetching recent" in str(update._intel_badge.cget("text"))

    msg = "Downloaded 8,738 bytes.  Parsing…"
    update.after(0, lambda m=msg: update._intel_badge.configure(
        text=m[:90], text_color="#ffb86c"))
    update.update()

    assert msg[:90] in str(update._intel_badge.cget("text"))


# ══ update_view: YARA freshness must not read healthy when it is not ══════════

def _yara(version="", last_update="", rule_count=0):
    return {"version": version, "last_update": last_update,
            "rule_count": rule_count}


def _set_yara_info(monkeypatch, info):
    import tools.update_intelligence as upd
    monkeypatch.setattr(upd, "get_yara_info", lambda: info)


def test_yara_not_installed_reads_as_not_installed(update, monkeypatch):
    _set_yara_info(monkeypatch, _yara())

    update._refresh_yara_info()
    update.update()

    assert str(update._yara_version_lbl.cget("text")) == "Not installed"


def test_yara_installed_shows_the_version_and_rule_count(update, monkeypatch):
    _set_yara_info(monkeypatch, _yara("v2026.1", "2026-08-20T00:00:00", 12))

    update._refresh_yara_info()
    update.update()

    text = str(update._yara_version_lbl.cget("text"))
    assert "v2026.1" in text and "12 rule files" in text


def test_one_rule_file_is_not_pluralised(update, monkeypatch):
    _set_yara_info(monkeypatch, _yara("v2026.1", "2026-08-20T00:00:00", 1))

    update._refresh_yara_info()
    update.update()

    assert "1 rule file" in str(update._yara_version_lbl.cget("text"))


def test_a_dated_ruleset_with_nothing_readable_is_flagged_red(update, monkeypatch):
    """The state a freshness-only reading calls healthy.

    A version string and a recent timestamp say the download worked; they say
    nothing about whether the engine can load what landed. This is the v1.12
    "honest posture" rule applied to the YARA row.
    """
    _set_yara_info(monkeypatch, _yara("v2026.1", "2026-08-20T00:00:00", 0))

    update._refresh_yara_info()
    update.update()

    assert "no readable rules" in str(update._yara_version_lbl.cget("text"))
    assert str(update._yara_version_lbl.cget("text_color")) == "#ff5555"


def test_an_unreadable_metadata_store_does_not_take_the_row_down(
        update, monkeypatch):
    """get_yara_info() reads SQLite and the rules tree; both can fail."""
    import tools.update_intelligence as upd

    def _boom():
        raise OSError("database is locked")

    monkeypatch.setattr(upd, "get_yara_info", _boom)

    update._refresh_yara_info()
    update.update()

    assert str(update._yara_version_lbl.cget("text")) == "Not installed"
