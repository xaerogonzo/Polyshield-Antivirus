r"""
Where files live, in both execution modes and from both executables.

Before ui.core.paths existed, 33 sites across 26 files recomputed the project
root from `__file__`, in three different spellings, with nothing anywhere aware
that the code might not be running from a source checkout. Under a compiled
build every one of them would have put the threat database, the quarantine, the
logs and the user's settings inside a temporary extraction directory that is
deleted when the process exits.

Two things are asserted here, and the second is the one with teeth:

  * the API's own contract, in source and frozen mode
  * that the GUI and the service converge on the SAME durable data root, by
    canonical comparison rather than by asserting either against a literal --
    they are separate processes that may start in different environments, and
    they read the same threat database and the same settings file

The source scan at the bottom is a guard, not a proof. It cannot see a path
built lazily inside a function body, which is why it is paired with an
import-and-resolve smoke test over every module that was migrated.
"""
from __future__ import annotations

import ast
import importlib
import os
import pathlib
import subprocess
import sys
import textwrap

import pytest

from ui.core import paths

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


@pytest.fixture
def frozen(monkeypatch):
    """Run the body as though this were a compiled build."""
    monkeypatch.setattr(paths, "_FROZEN_OVERRIDE", True)
    return paths


@pytest.fixture
def source(monkeypatch):
    monkeypatch.setattr(paths, "_FROZEN_OVERRIDE", False)
    return paths


@pytest.fixture(autouse=True)
def _no_inherited_data_dir(monkeypatch):
    """POLYSHIELD_DATA_DIR outranks everything; a developer with it set would
    otherwise silently pass tests that assert the default resolution."""
    monkeypatch.delenv(paths.DATA_DIR_ENV, raising=False)


# ══ is_frozen ═════════════════════════════════════════════════════════════════

def test_a_source_checkout_is_not_frozen():
    assert paths.is_frozen() is False


def test_sys_frozen_is_honoured(monkeypatch):
    """PyInstaller and py2exe set this; the predicate should not need revisiting
    if the packager ever changes."""
    monkeypatch.setattr(paths, "_FROZEN_OVERRIDE", None)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert paths.is_frozen() is True


# ══ The two roots ═════════════════════════════════════════════════════════════

def test_the_source_data_root_is_the_checkout(source):
    assert paths.app_root() == ROOT


def test_resources_resolve_to_the_checkout_in_source_mode(source):
    assert paths.resource_root() == ROOT
    assert (paths.resource_root() / "src" / "ui" / "app.py").is_file()


def test_a_frozen_build_keeps_data_out_of_the_extraction_directory(
        frozen, monkeypatch, tmp_path):
    """The whole point of the module.

    resource_root() is the extraction directory under a onefile build -- it is
    deleted when the process exits. Nothing durable may resolve beneath it.
    """
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))

    data = paths.app_root()
    resource = paths.resource_root()

    assert data != resource
    assert resource not in data.parents and data != resource
    for named in (paths.intelligence_dir(), paths.quarantine_dir(),
                  paths.logs_dir(), paths.config_dir(), paths.rules_dir()):
        assert resource not in named.parents, f"{named} is under the extraction dir"


def test_frozen_resources_come_from_one_level_shallower(frozen):
    """A build has no src/ level, so the module tree is one directory shallower.

    A checkout is src/ui/core/paths.py -> parents[3] is the project root. A
    build is <dist>/PolyShield.dist/ui/core/paths.py, so the same expression
    walks one past the directory the bundled data is in: Nuitka put it in
    PolyShield.dist while parents[3] gave <dist>, and every RESOURCE lookup
    (scripts/, launch_ui.vbs, app.py) would have resolved somewhere that does
    not contain them.

    Found by tools/build_probe.py against a real build, because the layout that
    exposes it exists nowhere else. This pins the rule; the probe proves it.
    """
    assert paths.resource_root() == ROOT / "src"
    assert paths.resource_root() != ROOT


def test_running_executable_is_not_sys_executable_when_frozen(frozen, monkeypatch):
    """sys.executable is the obvious source and the wrong one.

    A Nuitka standalone build reports a python.exe beside the real binary that
    DOES NOT EXIST. Registering it in the Explorer context menu, or as a
    service image path, points Windows at nothing -- silently.
    """
    monkeypatch.setattr(sys, "executable", r"C:\nope\python.exe")
    monkeypatch.setattr(sys, "argv", [r"C:\app\PolyShield.exe", "--scan"])

    assert paths.running_executable() == pathlib.Path(r"C:\app\PolyShield.exe")
    assert "python.exe" not in str(paths.running_executable())


def test_the_launcher_uses_the_real_binary_when_frozen(frozen, monkeypatch):
    monkeypatch.setattr(sys, "executable", r"C:\nope\python.exe")
    monkeypatch.setattr(sys, "argv", [r"C:\app\PolyShield.exe"])

    argv = paths.app_launch_argv("--scan", r"C:\x.exe")
    assert argv == [r"C:\app\PolyShield.exe", "--scan", r"C:\x.exe"]


def test_the_service_registers_itself_as_its_own_image_when_frozen(
        frozen, monkeypatch):
    """The exe IS the service; its no-argument branch reaches the dispatcher."""
    monkeypatch.setattr(sys, "argv", [r"C:\app\PolyShieldService.exe"])

    exe, args = paths.service_registration()
    assert exe == r"C:\app\PolyShieldService.exe"
    assert args == "", "a frozen service takes no script argument"


def test_the_service_registers_interpreter_plus_script_from_source(source):
    exe, args = paths.service_registration()
    assert exe.endswith("python.exe")
    assert args.strip('"').endswith("polyshield_service.py")


def test_source_resources_still_come_from_the_checkout(source):
    """The frozen branch must not change where a checkout looks."""
    assert paths.resource_root() == ROOT


def test_a_frozen_build_writes_under_the_user_profile(frozen, monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    assert paths.app_root() == tmp_path / "Local" / "PolyShield"


def test_the_data_root_is_not_defined_as_beside_the_executable(
        frozen, monkeypatch, tmp_path):
    """A build installed under Program Files cannot write beside itself.

    Pinned because it is the obvious implementation and the one that produces a
    build that works from dist\\ and fails for every real installation.
    """
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    assert paths.app_root() != pathlib.Path(sys.executable).resolve().parent


def test_a_frozen_build_with_no_profile_still_returns_a_real_directory(
        frozen, monkeypatch):
    """A service account can have a stripped environment.

    Beside the executable is a poor durable root, but it is a real directory --
    and better than the extraction directory that is about to be deleted.
    """
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)

    assert paths.app_root() == pathlib.Path(sys.executable).resolve().parent


@pytest.mark.parametrize("mode", ["source", "frozen"])
def test_the_environment_override_wins_in_either_mode(monkeypatch, tmp_path, mode):
    """The seam an installer or a portable launcher uses, and the one Phase 4b
    needs if it chooses a portable layout."""
    monkeypatch.setattr(paths, "_FROZEN_OVERRIDE", mode == "frozen")
    monkeypatch.setenv(paths.DATA_DIR_ENV, str(tmp_path / "elsewhere"))

    assert paths.app_root() == tmp_path / "elsewhere"
    assert paths.intelligence_dir() == tmp_path / "elsewhere" / "intelligence"


def test_a_blank_override_is_ignored(source, monkeypatch):
    monkeypatch.setenv(paths.DATA_DIR_ENV, "   ")
    assert paths.app_root() == ROOT


# ══ Shipped as source, but still part of a distribution ══════════════════════

@pytest.fixture
def staged(monkeypatch, tmp_path):
    """A source-mode component staged inside a distribution.

    That is the shape the Windows service actually ships in: pywin32 does not
    survive the Nuitka build, so the service runs from source beside a compiled
    GUI (docs/ARCHITECTURE.md, "4b.2 is BLOCKED").
    """
    monkeypatch.setattr(paths, "_FROZEN_OVERRIDE", False)
    monkeypatch.setattr(paths, "_MODULE_ROOT", tmp_path)
    (tmp_path / paths.DISTRIBUTION_MARKER).write_text("staged", encoding="utf-8")
    return tmp_path


def test_a_checkout_is_not_a_distribution(source):
    assert paths.is_distribution() is False
    assert paths.app_root() == ROOT


def test_a_frozen_build_is_always_a_distribution(frozen):
    assert paths.is_distribution() is True


def test_a_marker_makes_a_source_tree_a_distribution(staged):
    assert paths.is_frozen() is False, "the service is genuinely not compiled"
    assert paths.is_distribution() is True


def test_a_staged_service_and_a_frozen_gui_agree_on_the_data_root(
        staged, monkeypatch, tmp_path):
    """The reason the marker exists at all.

    Without it the service asks is_frozen(), gets False, and resolves app_root()
    to the directory it was installed in -- while the compiled GUI two folders
    away resolves it to %LOCALAPPDATA%\PolyShield. A service writing detections
    somewhere the UI never looks is indistinguishable from a service that found
    nothing.
    """
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))

    staged_root = paths.app_root()

    monkeypatch.setattr(paths, "_FROZEN_OVERRIDE", True)
    frozen_root = paths.app_root()

    assert staged_root == frozen_root == tmp_path / "Local" / "PolyShield"
    assert staged_root != staged, "must not resolve to its own install directory"


def test_a_staged_component_keeps_its_own_resource_root(staged):
    """Data is shared; the component's own files are not."""
    assert paths.resource_root() == staged


def test_the_environment_override_still_wins_over_the_marker(
        staged, monkeypatch, tmp_path):
    monkeypatch.setenv(paths.DATA_DIR_ENV, str(tmp_path / "chosen"))
    assert paths.app_root() == tmp_path / "chosen"


# ══ GUI and service converge ══════════════════════════════════════════════════

_RESOLVE = textwrap.dedent(
    """
    import json, os, sys
    sys.path.insert(0, r"{root}")
    sys.path.insert(0, r"{src}")
    {bootstrap}
    from ui.core import paths
    paths._FROZEN_OVERRIDE = {frozen}
    print(json.dumps({{
        "app_root": str(paths.app_root().resolve()),
        "intelligence": str(paths.intelligence_dir().resolve()),
        "config": str(paths.config_dir().resolve()),
        "resource_root": str(paths.resource_root().resolve()),
    }}))
    """
)

# The service bootstraps from the repo root with `.parent`; the GUI bootstraps
# from src/ui/app.py with `parents[2]`. Different expressions, and the reason
# this is tested per-executable rather than once.
_BOOTSTRAPS = {
    "gui": 'sys.path.insert(0, r"{src}")',
    "service": 'sys.path.insert(0, r"{root}")',
}


def _resolve_in_subprocess(which: str, frozen: bool, env_extra: dict) -> dict:
    import json

    code = _RESOLVE.format(
        root=ROOT, src=SRC, frozen=repr(frozen),
        bootstrap=_BOOTSTRAPS[which].format(root=ROOT, src=SRC),
    )
    env = {**os.environ, **env_extra}
    env.pop(paths.DATA_DIR_ENV, None)
    env.update(env_extra)
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("frozen", [False, True])
def test_the_gui_and_the_service_agree_on_where_data_lives(frozen, tmp_path):
    """The invariant that matters most, in both modes.

    Compared canonically rather than against a literal: the two are separate
    processes that may start from different working directories, and what has
    to hold is that they land on the same directory -- they read the same
    threat database, the same settings file and the same quarantine.
    """
    env = {"LOCALAPPDATA": str(tmp_path / "Local")}
    gui = _resolve_in_subprocess("gui", frozen, env)
    service = _resolve_in_subprocess("service", frozen, env)

    assert gui["app_root"] == service["app_root"]
    assert gui["intelligence"] == service["intelligence"]
    assert gui["config"] == service["config"]


@pytest.mark.parametrize("which", ["gui", "service"])
def test_neither_executable_puts_data_under_the_extraction_directory(
        which, tmp_path):
    got = _resolve_in_subprocess(
        which, True, {"LOCALAPPDATA": str(tmp_path / "Local")})

    resource = pathlib.Path(got["resource_root"])
    for key in ("app_root", "intelligence", "config"):
        assert resource not in pathlib.Path(got[key]).parents, key


# ══ Launch targets ════════════════════════════════════════════════════════════

def test_the_source_launcher_runs_app_py_under_pythonw(source):
    argv = paths.app_launch_argv("--scan", r"C:\x.exe")

    assert argv[0].endswith("pythonw.exe")
    assert argv[1].endswith(str(pathlib.Path("src") / "ui" / "app.py"))
    assert argv[2:] == ["--scan", r"C:\x.exe"]


def test_a_frozen_build_launches_itself(frozen, monkeypatch):
    """There is no interpreter and no app.py; the executable *is* the GUI."""
    monkeypatch.setattr(sys, "argv", [r"C:\app\PolyShield.exe"])

    argv = paths.app_launch_argv("--scan", r"C:\x.exe")

    assert argv == [r"C:\app\PolyShield.exe", "--scan", r"C:\x.exe"]
    assert not any(a.endswith(".py") for a in argv)


def test_a_helper_script_has_no_frozen_target_yet(frozen):
    """Loud rather than wrong.

    A frozen build has no interpreter and no .py files, so scheduled_scan.py
    needs its own executable or a subcommand -- a Phase 4b decision. Returning
    the source command anyway would register a scheduled task that fails at
    02:00 some months later with nobody watching, which is the exact failure
    class this phase exists to prevent.
    """
    with pytest.raises(paths.FrozenLaunchUndecided):
        paths.script_launch_argv("scheduled_scan.py", r"C:\Users\me")


def test_the_source_helper_script_command_is_unchanged(source):
    argv = paths.script_launch_argv("scheduled_scan.py", r"C:\Users\me")

    assert argv[0].endswith("python.exe")
    assert argv[1].endswith("scheduled_scan.py")
    assert argv[2] == r"C:\Users\me"


def test_bootstrap_is_a_no_op_when_frozen(frozen, monkeypatch):
    """A compiled build has its modules baked in. Inserting the extraction
    directory would invite an import to resolve from a tree about to vanish."""
    before = list(sys.path)
    monkeypatch.setattr(sys, "path", list(sys.path))

    paths.bootstrap_sys_path()

    assert sys.path == before


def test_bootstrap_adds_the_checkout_in_source_mode(source, monkeypatch):
    monkeypatch.setattr(sys, "path", [p for p in sys.path
                                      if p not in (str(ROOT), str(SRC))])
    paths.bootstrap_sys_path()

    assert str(ROOT) in sys.path and str(SRC) in sys.path


# ══ The source scan, and why it is not enough on its own ══════════════════════

# Deriving a root from __file__ is legitimate in exactly these places.
_ALLOWED = {
    # paths.py is the module that resolves roots.
    "ui/core/paths.py":
        "the module that defines the roots",
    # The three bootstraps cannot import the module they bootstrap.
    "ui/app.py":
        "sys.path bootstrap, runs before ui.core is importable",
    "tools/update_intelligence.py":
        "sys.path bootstrap for direct `python src/tools/...` invocation",
    # Resolving a file BESIDE a module is not a root derivation: it is correct
    # in a checkout and correct in an extraction directory, which is precisely
    # why these two are not routed through paths.
    "ui/core/emulate_engine.py":
        "_speakeasy_worker.py sits beside the module",
    "ui/views/service_view.py":
        "_svc_helper.bat sits beside the module",
}

_ROOT_DERIVATION = ("Path(__file__).resolve().parents",
                    "Path(__file__).resolve().parent",
                    "Path(__file__).parent")


def _derives_a_root(path: pathlib.Path) -> bool:
    text = path.read_text(encoding="utf-8")
    return any(frag in text for frag in _ROOT_DERIVATION)


def test_only_the_listed_modules_resolve_a_root_themselves():
    """A guard, not a proof -- see the smoke test below.

    Written as an allow-list rather than a count so that adding a new one is a
    decision someone has to write down, with a reason, next to the others.
    """
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        if rel in _ALLOWED:
            continue
        if _derives_a_root(path):
            offenders.append(rel)

    assert offenders == [], (
        "these should resolve paths through ui.core.paths, or be added to "
        f"_ALLOWED with a reason: {offenders}")


@pytest.mark.parametrize("name", ["polyshield_service.py", "scheduled_scan.py"])
def test_the_root_level_scripts_derive_a_root_only_to_bootstrap(name):
    """These two live at the repo root, so they spell it `.parent` where
    everything else spells it `parents[3]`. Both are allowed to -- for the
    bootstrap, and only for it.

    The line that imports ui.core.paths is the boundary: everything above it is
    bootstrap, and nothing below it may still be reaching for the raw root.
    That is a sharper rule than "which lines mention sys.path", which counted
    `_SVC_SRC = _SVC_DIR / "src"` as a violation when it is the bootstrap's own
    second half.
    """
    text = (ROOT / name).read_text(encoding="utf-8")
    assert "from ui.core import paths" in text, name

    lines = text.splitlines()
    boundary = next(i for i, ln in enumerate(lines)
                    if ln.startswith("from ui.core import paths"))

    tree = ast.parse(text)
    roots = {n.targets[0].id for n in ast.walk(tree)
             if isinstance(n, ast.Assign)
             and isinstance(n.targets[0], ast.Name)
             and "__file__" in ast.dump(n.value)}
    assert roots, f"{name} derives no root at all -- did the bootstrap move?"

    after = [f"{i + 1}: {ln.strip()}" for i, ln in enumerate(lines[boundary:], boundary)
             for var in roots if var in ln]
    assert after == [], (
        f"{name} still uses a raw root after importing paths:\n  "
        + "\n  ".join(after))


def test_every_migrated_module_still_imports_and_resolves():
    """The half a source scan cannot do.

    A path built lazily inside a function body is invisible to the scan above,
    and so is a module that the scan reads happily but that no longer imports.
    """
    migrated = sorted(
        p for p in SRC.rglob("*.py")
        if "from ui.core import paths" in p.read_text(encoding="utf-8"))
    assert len(migrated) >= 20, "expected the migration to have touched ~21 modules"

    for path in migrated:
        module = (path.relative_to(SRC).with_suffix("")
                  .as_posix().replace("/", "."))
        mod = importlib.import_module(module)
        assert mod is not None


def test_the_scan_would_catch_a_reintroduced_root(tmp_path):
    """A guard that cannot fail is not a guard."""
    offender = tmp_path / "regression.py"
    offender.write_text(
        "from pathlib import Path\n"
        "_ROOT = Path(__file__).resolve().parents[3]\n", encoding="utf-8")

    assert _derives_a_root(offender) is True

    clean = tmp_path / "clean.py"
    clean.write_text("from ui.core import paths\n"
                     "_D = paths.intelligence_dir()\n", encoding="utf-8")
    assert _derives_a_root(clean) is False
