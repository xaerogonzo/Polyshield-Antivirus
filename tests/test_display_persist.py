"""
Slider persistence in the Display view.

Not a UI test so much as a cost guard. Making set_value() cross-process safe
turned it from a 0.2 ms write_text into a ~3 ms locked read-merge-atomic-
replace-fsync. That is fine for a button and wrong for a CTkSlider, whose
`command=` fires on every mouse-motion event: persisting per tick spent about
160 ms of main-thread time per second of dragging, on the Tk thread, which is
a visibly laggy slider.

The fix is to stop writing sixty times a second rather than to weaken the
durability the write exists to provide -- the fsync stays. These tests pin the
coalescing so it cannot quietly regress back to a per-tick write.

The view is built on the shared session Tk root, withdrawn, as
test_dashboard_intel_card.py does.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def display(tk_root, settings_sandbox, monkeypatch):
    """A DisplayView with set_value() counted rather than performed."""
    from ui.core import settings as cfg
    from ui.views.display_view import DisplayView

    writes: list[tuple] = []

    def counting_set(key, value):
        writes.append((key, value))
        settings_sandbox[key] = value
        return cfg.SAVE_OK

    monkeypatch.setattr(cfg, "set_value", counting_set)

    view = DisplayView(tk_root, status_callback=lambda m: None, app_ref=None)
    view.writes = writes            # type: ignore[attr-defined]
    yield view
    try:
        view.destroy()
    except Exception:
        pass


def _drag(view, handler, values):
    """Simulate a slider drag: one command callback per mouse-motion event."""
    for v in values:
        handler(v)


# ── Coalescing ────────────────────────────────────────────────────────────────

def test_dragging_a_slider_does_not_write_per_tick(display):
    """The regression guard. Sixty ticks used to mean sixty locked writes."""
    _drag(display, display._on_opacity_change, range(0, 60))

    assert display.writes == [], (
        "a settings write happened during the drag rather than after it")


def test_the_pending_value_is_the_last_one_seen(display):
    _drag(display, display._on_blur_change, [1, 5, 12, 20])

    assert display._pending_writes == {"display_bg_blur": 20}


def test_flushing_writes_each_key_once(display):
    _drag(display, display._on_opacity_change, [10, 20, 30])
    _drag(display, display._on_blur_change, [1, 2, 3])

    display._flush_pending_writes()

    assert sorted(display.writes) == [("display_bg_blur", 3),
                                      ("display_bg_opacity", 0.3)]


def test_a_drag_of_sixty_ticks_costs_one_write_per_key(display):
    """The whole point, stated as the number that matters."""
    _drag(display, display._on_opacity_change, range(60))
    display._flush_pending_writes()

    assert len(display.writes) == 1


# ── Flush behaviour ───────────────────────────────────────────────────────────

def test_releasing_the_slider_is_wired_to_flush(display):
    """The debounce is a backstop; the user should not wait 250 ms to see
    their preference stick, so release flushes immediately.

    Asserted as wiring plus behaviour rather than by generating a release
    event. Tk will not dispatch synthetic button events to a widget under a
    withdrawn root -- not with when="now", and not after pack() plus update()
    either. button.invoke() works elsewhere in the suite because it calls the
    command directly rather than going through event dispatch; there is no
    equivalent for a binding. Claiming otherwise would be a test that passes
    because nothing happened.
    """
    canvas = display._opacity_slider._canvas      # where CTkSlider.bind() forwards
    assert "<ButtonRelease-1>" in canvas.bind(), (
        "the slider release is no longer wired to a flush")

    _drag(display, display._on_opacity_change, [42])
    assert display.writes == []

    display._flush_pending_writes()               # what that binding invokes

    assert display.writes == [("display_bg_opacity", 0.42)]


def test_flushing_twice_does_not_write_twice(display):
    _drag(display, display._on_blur_change, [7])

    display._flush_pending_writes()
    display._flush_pending_writes()

    assert display.writes == [("display_bg_blur", 7)]


def test_flushing_with_nothing_pending_is_harmless(display):
    display._flush_pending_writes()

    assert display.writes == []


def test_the_label_still_updates_on_every_tick(display):
    """Only the write is deferred. Deferring the feedback too would trade a
    laggy slider for an unresponsive one."""
    display._on_blur_change(13)

    assert "13" in display._blur_lbl.cget("text")
    assert display.writes == [], "the label update pulled a write with it"
