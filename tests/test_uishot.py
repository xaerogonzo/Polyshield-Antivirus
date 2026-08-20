"""
Tests for the uishot capture harness.

The capture path itself is exercised through a subprocess, deliberately.
SetThreadDesktop fails once the calling thread owns a window, and the rest of
the suite creates a session-scoped Tk root — so binding a hidden desktop
in-process would fail depending on test order. Running the real CLI also tests
the thing users actually invoke.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI = PROJECT_ROOT / "tools" / "uishot" / "__main__.py"

pytestmark = pytest.mark.skipif(sys.platform != "win32",
                                reason="hidden-desktop capture is Windows-only")


def _run(*args, cwd=PROJECT_ROOT):
    return subprocess.run([sys.executable, str(CLI), *args],
                          cwd=str(cwd), capture_output=True, text=True,
                          timeout=300)


@pytest.fixture(scope="session")
def capture_supported():
    """Skip capture tests where the runner cannot host a hidden desktop.

    A CI box without an interactive window station is an environment limit, not
    a defect in this code — it should read as 'skipped', not as a red build.
    The probe runs out-of-process so it never conflicts with a Tk root this
    session may already hold.
    """
    probe = _run("--probe")
    if probe.returncode != 0:
        pytest.skip(f"capture unsupported here: {probe.stdout.strip()}")
    return True


# ── Pure helpers (no Tk, no desktop) ──────────────────────────────────────────

def test_compare_detects_identical_images():
    from PIL import Image
    sys.path.insert(0, str(PROJECT_ROOT / "tools"))
    from uishot.capture import compare

    img = Image.new("RGB", (40, 30), (12, 34, 56))
    result = compare(img, img.copy())
    assert result["match"] is True
    assert result["differing"] == 0


def test_compare_flags_a_changed_pixel_block():
    from PIL import Image
    sys.path.insert(0, str(PROJECT_ROOT / "tools"))
    from uishot.capture import compare

    a = Image.new("RGB", (40, 30), (12, 34, 56))
    b = a.copy()
    for x in range(10):
        for y in range(10):
            b.putpixel((x, y), (255, 0, 0))

    result = compare(a, b)
    assert result["match"] is False
    assert result["differing"] == 100
    assert result["bbox"] == (0, 0, 10, 10)


def test_compare_tolerates_subpixel_noise():
    """Font antialiasing shifts channels by a level or two between runs; that
    must not read as a visual regression."""
    from PIL import Image
    sys.path.insert(0, str(PROJECT_ROOT / "tools"))
    from uishot.capture import compare

    a = Image.new("RGB", (20, 20), (100, 100, 100))
    b = Image.new("RGB", (20, 20), (103, 103, 103))
    assert compare(a, b, tolerance=8)["match"] is True
    assert compare(a, b, tolerance=1)["match"] is False


def test_compare_reports_a_size_change_rather_than_diffing():
    from PIL import Image
    sys.path.insert(0, str(PROJECT_ROOT / "tools"))
    from uishot.capture import compare

    result = compare(Image.new("RGB", (40, 30)), Image.new("RGB", (40, 31)))
    assert result["size_changed"] is True
    assert result["match"] is False


# ── The CLI end to end ────────────────────────────────────────────────────────

def test_cli_lists_scenes():
    proc = _run("--list")
    assert proc.returncode == 0, proc.stderr
    assert "intel-posture" in proc.stdout


def test_cli_captures_a_scene_without_a_visible_window(capture_supported, tmp_path):
    out = tmp_path / "shots"
    proc = _run("--only", "intel-posture", "--out", str(out))
    assert proc.returncode == 0, proc.stderr + proc.stdout

    produced = sorted(p.name for p in out.glob("*.png"))
    assert produced == ["intel_current.png", "intel_never.png",
                        "intel_stale.png", "intel_unavailable.png",
                        "intel_unusable.png"]

    from PIL import Image
    for name in produced:
        img = Image.open(out / name)
        # NOT an exact size: a hidden desktop inherits the session's screen
        # metrics, and a CI runner's is smaller than a developer's. Measured on
        # windows-latest the window clamps to 1028x749 against a requested
        # 1200x760. Assert it is a real render, not a specific resolution.
        width, height = img.size
        assert width >= 800 and height >= 600, f"{name} captured at {img.size}"
        colours = img.getcolors(maxcolors=1_000_000) or []
        # A blank or all-white capture is the classic PrintWindow failure —
        # it returns success and hands back nothing useful.
        assert len(colours) > 50, f"{name} looks blank ({len(colours)} colours)"
        small = img.resize((100, 60)).convert("L")
        white = sum(1 for v in small.tobytes() if v > 250)
        assert white / 6000 < 0.5, f"{name} is mostly white — capture flag wrong?"


def test_cli_check_passes_against_freshly_recorded_golden(capture_supported, tmp_path):
    out, golden = tmp_path / "shots", tmp_path / "golden"

    record = _run("--only", "service", "--out", str(out),
                  "--golden", str(golden), "--update-golden")
    assert record.returncode == 0, record.stderr
    assert (golden / "service_events.png").exists()

    check = _run("--only", "service", "--out", str(out),
                 "--golden", str(golden), "--check")
    assert check.returncode == 0, check.stdout + check.stderr
    assert "match golden" in check.stdout


def test_cli_check_reports_drift_and_writes_a_side_by_side(capture_supported, tmp_path):
    out, golden = tmp_path / "shots", tmp_path / "golden"
    assert _run("--only", "service", "--out", str(out),
                "--golden", str(golden), "--update-golden").returncode == 0

    # Corrupt the golden so the next check must notice.
    from PIL import Image
    ref = Image.open(golden / "service_events.png").copy()
    for x in range(300):
        for y in range(200):
            ref.putpixel((x, y), (255, 0, 255))
    ref.save(golden / "service_events.png")

    check = _run("--only", "service", "--out", str(out),
                 "--golden", str(golden), "--check")
    assert check.returncode == 1
    assert "DRIFT" in check.stdout
    assert (out / "diff" / "service_events.png").exists()


def test_cli_rejects_an_unknown_scene(tmp_path):
    proc = _run("--only", "no-such-scene", "--out", str(tmp_path))
    assert proc.returncode == 2
    assert "unknown scene" in proc.stderr

# Helper program for test_session_works_without_the_cli, kept as a template so
# the quoting stays readable.
SCRIPT_TEMPLATE = """
import sys
sys.path.insert(0, r"{tools}")
from uishot import TkSession

with TkSession(out_dir=r"{out}") as session:
    from ui.views.service_view import ServiceView
    session.mount(ServiceView, status_callback=lambda m: None)
    shot = session.shot("direct")
    print("OK", shot.name, shot.size[0], shot.size[1])
"""


def test_session_works_without_the_cli(capture_supported, tmp_path):
    """TkSession used directly, as its module docstring documents.

    Every other test drives the CLI, which assigns session.current_scene before
    each scene — so a missing initialiser passes the entire suite and only
    breaks for someone importing the library. A rebase silently dropped exactly
    that line once, and nothing caught it.
    """
    out = tmp_path / "out"
    script = tmp_path / "direct.py"
    script.write_text(
        SCRIPT_TEMPLATE.format(tools=PROJECT_ROOT / "tools", out=out),
        encoding="utf-8")

    proc = subprocess.run([sys.executable, str(script)], capture_output=True,
                          text=True, timeout=300, cwd=str(PROJECT_ROOT))
    assert proc.returncode == 0, proc.stderr
    assert "OK direct" in proc.stdout
    assert (out / "direct.png").exists()
