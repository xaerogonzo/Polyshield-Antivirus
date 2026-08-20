# uishot — photograph the UI without it being on screen

Captures PolyShield's views as PNGs with **no visible window, no focus stealing,
and no mouse control**, then optionally diffs them against recorded golden
images to catch visual regressions.

```powershell
kicomav_env\Scripts\python.exe tools\uishot\__main__.py                 # capture all scenes
kicomav_env\Scripts\python.exe tools\uishot\__main__.py --list
kicomav_env\Scripts\python.exe tools\uishot\__main__.py --only intel-posture
kicomav_env\Scripts\python.exe tools\uishot\__main__.py --update-golden # record expected look
kicomav_env\Scripts\python.exe tools\uishot\__main__.py --check         # fail on drift
```

Shots land in `artifacts/ui/` (gitignored); goldens live in `tests/golden/ui/`
(tracked). `--check` exits 1 on drift and writes a side-by-side with the changed
region boxed in red to `artifacts/ui/diff/`.

### Golden scenes vs live scenes

Only scenes registered with `@scene(name)` are compared. Scenes registered
`@scene(name, golden=False)` read **live** data — feed ages tick over hourly,
row counts change after an update — so their shots drift for reasons that have
nothing to do with the code. They are documentary: worth looking at, useless as
a baseline. `--check` and `--update-golden` both skip them and say which.

This was learned the hard way: the first golden set included them, and an hour
later three scenes "drifted" purely because `just now` had become `11h ago`.

Currently live: `dashboard`, `settings`, `update-center`. Currently comparable:
`intel-posture`, `service`. Making a live scene comparable means pinning its
inputs — freeze the clock, fix the counts — not widening `--tolerance`.

## How it works, and why it works that way

Two decisions carry the whole design, and both were measured rather than assumed.

### 1. A hidden Win32 desktop, not off-screen coordinates

The obvious approach — park the window at `(-3200, -3200)` — produces
**confidently wrong screenshots**. Tk will not paint a window positioned outside
the virtual screen, so the capture comes back with text but no frame
backgrounds, no button fills, and the wrong page colour.

Measured on the Dashboard, same view and size, against the real on-screen render:

| Window location | PrintWindow flag | Result |
|---|---|---|
| Hidden desktop | `PW_RENDERFULLCONTENT` | **0 of 912,000 px differ** — identical |
| Hidden desktop | `0` | 95.58% differ — backgrounds missing |
| Off-screen coords | `PW_RENDERFULLCONTENT` | 91.7% pure white — mostly blank |
| Off-screen coords | `0` | 95.58% differ — backgrounds missing |

`CreateDesktop` + `SetThreadDesktop` gives the window a full coordinate space
where it is genuinely visible, so Tk paints normally. Nothing ever calls
`SwitchDesktop`, so it is never shown to anyone.

**Constraint:** `SetThreadDesktop` fails if the calling thread already owns a
window. The desktop must be bound *before* the toolkit initialises. This is also
why `tests/test_uishot.py` drives the CLI through a subprocess — the rest of the
suite holds a session-scoped Tk root.

### 2. Reproduce the entry point's global setup

`ui/app.py` calls `ctk.set_appearance_mode("dark")` at **module** level.
Importing only the view modules leaves CustomTkinter in its default *light*
appearance, and every label that does not set an explicit `text_color` renders
dark-on-dark — nearly invisible, but a perfectly valid-looking screenshot.

This bit during development: the first Settings capture looked like a real
contrast bug in the app. It was the harness. `TkSession` now imports `ui.app`
for its module-level configuration rather than guessing at it.

The general lesson: a capture harness that does not reproduce global
initialisation will hand you a picture that is wrong in ways no assertion
catches.

## Driving the UI

Widgets are driven through Tk, never by synthesising input:

```python
button.invoke()                     # not a mouse click at (x, y)
view._handle_event({...})           # feed a handler directly
view._parent_canvas.yview_moveto(0.82)   # scroll without a wheel
```

That is faster, immune to whatever else is on the machine, and works while the
window is invisible.

## Adding a scene

```python
@scene("my-thing")
def my_thing(session):
    view = session.mount(MyView, status_callback=lambda m: None)
    session.shot("my_thing_default")
    view.set_some_state(...)
    session.shot("my_thing_after")
```

Prefer constructing states directly over trying to reach them naturally — the
states worth photographing (a feed that downloaded but is unusable, an
unreadable intelligence store) are exactly the ones that are hard to produce on
demand and easy to get wrong.

## Portability

`desktop.py` and `capture.py` are toolkit-agnostic — they take an `hwnd`. Only
`session.py` and `scenes.py` know about Tk.

For a Qt app (e.g. OpenChem Studio) none of this machinery is needed:
`QWidget.grab()` renders a widget to a `QPixmap` with no window at all, and
`QT_QPA_PLATFORM=offscreen` gives true headless rendering. The reusable parts
there are `capture.compare` / `capture.write_diff` and the scene/golden/CLI
structure, not the desktop binding.

## Known limits

- Windows only. There is no Xvfb equivalent for Win32; the isolation comes from
  a separate desktop, not from the absence of a window.
- `PW_RENDERFULLCONTENT` needs Windows 8.1+.
- GPU-composited content (a DirectComposition surface, an embedded browser) can
  still come back blank. Tk draws with GDI, which is the well-behaved case.
- The golden images embed this machine's font rendering. Expect drift on a
  different DPI or font stack; `--tolerance` absorbs antialiasing noise, not a
  different font.
