"""
The view lifecycle contract: what App promises about building its 18 pages.

Views used to be constructed all at once in `_build()` and then hidden. That
cost 4,996 Tk windows, 3,715 USER handles (37% of the 10,000 per-process quota)
and 107.7 MB before the user clicked anything, to show one page — and it is
what tipped a memory-constrained Windows Sandbox into `Tk_GetPixmap: Error from
CreateDIBSection`. They are now built on first show.

Deferring construction moves three things from "obviously fine" to "silently
wrong if someone gets it back to front", and each has already bitten once:

  * `_views` stopped being the registry and became the *cache*. A membership
    test against it now answers "has the user opened this page", not "does this
    page exist". `ScanView._send_to_virustotal()` was written the old way and
    would have skipped its pre-load, landing the user on an empty page with no
    error anywhere.

  * `_HAS_ON_SHOW` / `_AUTO_REFRESH` name a method by string. `SchedulerView`
    sat in `_AUTO_REFRESH` with only `refresh_task_info()`, so every visit to
    that page raised AttributeError into Tk's error handler — invisible under
    pythonw — and the task status silently never refreshed.

  * the set of pages built at startup is now a behaviour rather than a
    constant, so it needs asserting rather than reading.

The first three tests are static: an AST read of `_view_factories` plus class
introspection, no Tk root. The last runs the real App on a hidden desktop in a
subprocess, because SetThreadDesktop fails once the calling thread owns a
window and the rest of the suite holds a session-scoped root.
"""
from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
APP_PY = SRC / "ui" / "app.py"


# ── Reading the registry out of the source ────────────────────────────────────

def _factory_nodes() -> dict[str, ast.expr]:
    """{view key: the AST node of its factory} from `self._view_factories`."""
    tree = ast.parse(APP_PY.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not node.targets:
            continue
        target = node.targets[0]
        if not (isinstance(target, ast.Attribute)
                and target.attr == "_view_factories"
                and isinstance(node.value, ast.Dict)):
            continue
        out: dict[str, ast.expr] = {}
        for key, value in zip(node.value.keys, node.value.values):
            assert isinstance(key, ast.Constant), (
                "every _view_factories key must be a literal string")
            out[key.value] = value
        return out
    raise AssertionError(
        "no `self._view_factories = {...}` literal in src/ui/app.py — if the "
        "registry moved, this whole module is testing nothing")


def _factory_class_names() -> dict[str, str]:
    """{view key: the class its factory constructs}."""
    names = {}
    for key, node in _factory_nodes().items():
        assert isinstance(node, ast.Lambda), f"{key!r} factory is not a lambda"
        call = node.body
        assert isinstance(call, ast.Call) and isinstance(call.func, ast.Name), (
            f"{key!r} factory does not directly construct a view class")
        names[key] = call.func.id
    return names


# ── The registry matches the sidebar ──────────────────────────────────────────

def test_every_nav_item_has_a_factory_and_vice_versa():
    """A nav button with no factory raises KeyError the first time it is
    clicked; a factory with no nav item is a page nothing can reach."""
    from ui.app import _NAV_ITEMS

    nav_keys = {key for label, key in _NAV_ITEMS if label is not None}
    assert nav_keys == set(_factory_nodes()), (
        "the sidebar and the view registry have drifted apart"
    )


def test_every_factory_takes_no_arguments():
    """get_view() calls the factory with nothing. A factory that grew a
    parameter would fail only on the first navigation to that page."""
    offenders = [key for key, node in _factory_nodes().items()
                 if not isinstance(node, ast.Lambda) or node.args.args]
    assert not offenders, (
        f"factories must be zero-argument lambdas: {sorted(offenders)}")


# ── The lifecycle sets name methods that exist ────────────────────────────────

def _views_missing(keys, method: str) -> list[str]:
    """Of the pages named by `keys`, those whose class has no `method`."""
    import ui.app as app_mod

    class_names = _factory_class_names()
    missing = []
    for key in sorted(keys):
        assert key in class_names, (
            f"{key!r} is named by a lifecycle registry but has no factory")
        view_cls = getattr(app_mod, class_names[key])
        if not callable(getattr(view_cls, method, None)):
            missing.append(f"{key} ({view_cls.__name__})")
    return missing


@pytest.mark.parametrize("registry_name, method", [("_HAS_ON_SHOW", "on_show"),
                                                   ("_AUTO_REFRESH", "refresh")])
def test_lifecycle_registry_names_a_method_the_view_actually_has(
    registry_name, method,
):
    """`_navigate()` calls this by name on every visit.

    When it is missing the page still appears — grid() has already run — so the
    only symptom is that it never updates, and the AttributeError goes to Tk's
    error handler, which under pythonw has nowhere to print.
    """
    import ui.app as app_mod

    missing = _views_missing(getattr(app_mod, registry_name), method)
    assert not missing, (
        f"{registry_name} requires {method}(), missing on: {missing}")


def test_the_lifecycle_check_catches_a_view_without_the_method():
    """A guard that cannot fail is not a guard.

    HelpView is a plain page defining neither hook. Naming it in either
    registry would be exactly the SchedulerView mistake, so the check has to
    report it rather than pass by looking the method up on the wrong object.
    """
    assert _views_missing({"help"}, "refresh") == ["help (HelpView)"]
    assert _views_missing({"help"}, "on_show") == ["help (HelpView)"]
    # VirusTotalView has on_show but no refresh — only the missing one reports.
    assert _views_missing({"virustotal"}, "on_show") == []
    assert _views_missing({"virustotal"}, "refresh") == ["virustotal (VirusTotalView)"]


# ── Nothing outside app.py may treat the cache as the registry ────────────────

def _view_cache_misuses(tree: ast.AST) -> list[int]:
    """Lines that index `_views` or test membership in it."""
    bad = []
    for node in ast.walk(tree):
        # x._views[key]
        if (isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "_views"):
            bad.append(node.lineno)
        # "key" in x._views
        if isinstance(node, ast.Compare):
            for op, comparator in zip(node.ops, node.comparators):
                if (isinstance(op, (ast.In, ast.NotIn))
                        and isinstance(comparator, ast.Attribute)
                        and comparator.attr == "_views"):
                    bad.append(node.lineno)
    return bad


def test_only_app_py_touches_the_view_cache_directly():
    """Everyone else goes through App.get_view(), which builds on demand.

    `_views` holds only pages already shown, so `key in app._views` is a
    question about the user's browsing history, not about the application.
    """
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        if path == APP_PY:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:                     # not ours to police
            continue
        for line in _view_cache_misuses(tree):
            offenders.append(f"{path.relative_to(SRC)}:{line}")

    assert not offenders, (
        "use App.get_view(key) instead of reaching into the _views cache: "
        + ", ".join(offenders))


def test_the_guard_recognises_the_shape_it_is_looking_for():
    """A guard that cannot fail is not a guard."""
    tree = ast.parse(
        'def f(app):\n'
        '    if "virustotal" in app._views:\n'
        '        app._views["virustotal"].load(1)\n'
    )
    assert len(_view_cache_misuses(tree)) == 2


# ── What actually gets built at startup ───────────────────────────────────────

_STARTUP_PROBE = '''
import json, sys
from pathlib import Path

root = Path(sys.argv[1])
service_running = sys.argv[2] == "true"
out_path = Path(sys.argv[3])

sys.path.insert(0, str(root / "tools"))
from uishot.desktop import hidden_desktop

for _p in (root, root / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


class _StubMonitor:
    def __init__(self, *a, **k): pass
    def start(self): pass
    def stop(self): pass
    def is_running(self): return False


def main():
    import ui.app as app_mod
    from ui.core import watcher as wtch
    from ui.core import service_client as svc
    import ui.core.process_monitor as pm

    # Everything that is not widget construction.
    app_mod._USE_TRAY = False
    wtch.start = lambda *a, **k: None
    svc.is_service_running = lambda *a, **k: service_running
    pm.ProcessMonitor = _StubMonitor

    app = app_mod.App()
    result = {
        "built": sorted(app._views),
        "registered": sorted(app._view_factories),
        "active": app._active_view,
    }
    try:
        for job in app.tk.call("after", "info"):
            try:
                app.after_cancel(job)
            except Exception:
                pass
    except Exception:
        pass
    try:
        app.destroy()
    except Exception:
        pass
    out_path.write_text(json.dumps(result), encoding="utf-8")


with hidden_desktop("ViewLifecycleProbe"):
    main()
'''

pytestmark_win = pytest.mark.skipif(
    sys.platform != "win32", reason="hidden-desktop probe is Windows-only")


def _probe_startup(tmp_path, service_running: bool) -> dict:
    script = tmp_path / "startup_probe.py"
    script.write_text(_STARTUP_PROBE, encoding="utf-8")
    out = tmp_path / f"startup_{service_running}.json"
    proc = subprocess.run(
        [sys.executable, str(script), str(ROOT),
         "true" if service_running else "false", str(out)],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300)
    if not out.exists():
        pytest.skip(
            "startup probe could not run here (no interactive window station?):"
            f"\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    return json.loads(out.read_text(encoding="utf-8"))


@pytestmark_win
def test_startup_builds_only_the_dashboard(tmp_path):
    """With the service owning process monitoring, one page exists at launch.

    This is the assertion the CreateDIBSection failure was really about: 17 of
    the 18 pages must not exist until asked for.
    """
    result = _probe_startup(tmp_path, service_running=True)

    assert result["active"] == "dashboard"
    assert result["built"] == ["dashboard"], (
        "startup built more than the page it shows: " + ", ".join(result["built"]))
    assert len(result["registered"]) == 18, (
        "all 18 pages must still be *registered*, just not built")


@pytestmark_win
def test_process_view_is_built_when_this_process_owns_the_monitor(tmp_path):
    """ProcessView is the one deliberate exception to build-on-first-show.

    Its `_on_alert()` is where `process_monitor_auto_terminate` actually kills a
    flagged process, so leaving it unbuilt would turn that setting into a no-op
    for anyone who never opens the Processes page.
    """
    result = _probe_startup(tmp_path, service_running=False)

    assert result["built"] == ["dashboard", "process"], (
        "expected exactly the dashboard plus the eagerly-built ProcessView, "
        "got: " + ", ".join(result["built"]))

def test_the_scanview_mixins_import_without_a_tk_root():
    """ScanView is assembled from three mixins in separate modules.

    Importing one must not construct a Tk root or a widget. Most of this suite
    imports view modules to read them statically -- the AST tests above do
    exactly that -- and a module that builds something at import time turns
    every one of those into a test that needs a display.

    The root check runs in a subprocess on purpose. tkinter._default_root is
    process-global and the rest of this suite holds a session-scoped root, so
    asserting on it in-process would pass alone and fail in a full run --
    exactly the order-dependence this file exists to catch.

    Also asserts no name is defined by more than one class in the MRO. A
    collision there resolves silently by inheritance order: the loser simply
    never runs, with no error anywhere.
    """
    probe = (
        "import sys, tkinter; sys.path.insert(0, 'src');"
        "import ui.views.scan_pipeline_mixin, ui.views.scan_engine_mixin;"
        "assert tkinter._default_root is None, 'a Tk root was created at import'"
    )
    proc = subprocess.run([sys.executable, "-c", probe], cwd=str(ROOT),
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        "importing a scan mixin created a Tk root:\n" + proc.stderr[-2000:])

    import ui.views.scan_engine_mixin as sem
    import ui.views.scan_pipeline_mixin as spm

    from ui.views.scan_view import ScanView
    from ui.views.threat_actions_mixin import _ThreatActionsMixin

    owners = {
        "ScanView":            ScanView,
        "_ThreatActionsMixin": _ThreatActionsMixin,
        "_ScanPipelineMixin":  spm._ScanPipelineMixin,
        "_ScanEngineMixin":    sem._ScanEngineMixin,
    }
    seen: dict[str, list[str]] = {}
    for label, cls in owners.items():
        for name in cls.__dict__:
            if not name.startswith("__"):
                seen.setdefault(name, []).append(label)
    clashes = {n: w for n, w in seen.items() if len(w) > 1}
    assert not clashes, f"defined by more than one class in the MRO: {clashes}"


def test_scanview_methods_resolve_to_the_class_that_owns_them():
    """Each ownership group still answers on one combined instance.

    Splitting a class across modules is only safe if the pieces still compose,
    and "the import worked" does not show that. These are representative
    methods from all four groups, checked against the class they should come
    from rather than merely being callable.
    """
    from ui.views.scan_engine_mixin import _ScanEngineMixin
    from ui.views.scan_pipeline_mixin import _ScanPipelineMixin
    from ui.views.scan_view import ScanView
    from ui.views.threat_actions_mixin import _ThreatActionsMixin

    expected = {
        "_normalized_pipeline_order": _ScanPipelineMixin,
        "_on_yara_toggle":            _ScanPipelineMixin,
        "_run_guardian_scan":         _ScanEngineMixin,
        "_run_clamav_scan":           _ScanEngineMixin,
        "_get_filtered_paths":        _ThreatActionsMixin,
        "_build_threat_actions":      _ThreatActionsMixin,
        "_start_scan":                ScanView,
        "_finalize_scan":             ScanView,
        "_log_append":                ScanView,
    }
    for name, owner in expected.items():
        resolved = next(c for c in ScanView.__mro__ if name in c.__dict__)
        assert resolved is owner, (
            f"{name} resolves to {resolved.__name__}, expected {owner.__name__}")
