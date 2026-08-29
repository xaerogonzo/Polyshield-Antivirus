r"""
Where PolyShield's files live — the one module that knows.

Before this, 33 sites across 26 files each recomputed the project root from
`__file__`, in three different spellings, and nothing anywhere was aware that
the code might not be running from a source checkout.  That is fine while it
always is.  It stops being fine the moment the app is compiled: under a Nuitka
onefile build the modules are unpacked into a temporary directory that is
deleted on exit, so every one of those sites would have put the threat
database, the quarantine, the logs and the user's settings somewhere that does
not survive the process.

The distinction this module exists to encode is not "Nuitka is weird".  It is:

    RESOURCE lifetime   ships with the program, read-only, recreatable from
                        the bundle, may live in a temporary extraction
                        directory

    DATA lifetime       created or modified by the user or the application,
                        must survive a restart, must never live only in a
                        temporary extraction directory

That distinction outlives any particular packager, which is why the API is
about lifetimes rather than about being frozen.

Classification of everything that was resolved from `__file__` before this
module existed:

    DATA                                        RESOURCE
    ----                                        --------
    intelligence/threat_db.sqlite               src/                (sys.path)
    intelligence/nsrl_bloom.bin                 src/ui/app.py       (launch target)
    intelligence/ignore_list.sqlite             polyshield_service.py
    intelligence/pattern_stats.sqlite           scheduled_scan.py
    intelligence/.update.lock                   launch_ui.vbs
    quarantine/                                 scripts/**.bat
    logs/                                       _speakeasy_worker.py
    config/ui_settings.json (+ .lock)           _svc_helper.bat
    config/service_events.json
    rules/user_rules/          (user-authored)
    rules/community/**         (downloaded intel, atomically republished)
    rules/update.cfg           (written by k2 --update)
    guardianai/data/known_bad.txt

`rules/` is deliberately split rather than classified whole: `user_rules/` is
the user's own work and the community generations are downloaded intelligence,
so both are DATA even though a first-run tree ships neither.

Two paths belong to a third category the DATA/RESOURCE split does not describe,
and are called out here rather than forced into one of the two:

    kicomav_env/Scripts/{k2,python,pip}.exe     the development virtualenv
    guardianai/                                 a separately cloned repository

Neither is shipped and neither is user data — they are the *development
environment*, and they simply do not exist in a distribution.  `k2_exe()` and
`guardian_dir()` resolve them relative to the checkout and the callers already
degrade when they are absent (`scanner.is_available()` has returned False for a
missing k2 since v1.6.1).  Deciding whether k2 ships, and in what form, is an
explicit Phase 4b decision; this module only makes the question visible.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Resolved from this file: src/ui/core/paths.py -> parents[3] is the checkout.
# Under Nuitka the same expression lands in the extraction directory, which is
# exactly what resource_root() wants and exactly what app_root() must not use.
_MODULE_ROOT = Path(__file__).resolve().parents[3]

# Set by tests. None means "detect"; the detection itself is deliberately not
# cached, so a test can flip modes without reimporting every consumer.
_FROZEN_OVERRIDE: bool | None = None

#: Overrides the durable data root in both modes.  An installer, a portable
#: launcher, or Phase 4b can point this wherever the deployment needs without
#: touching code.
DATA_DIR_ENV = "POLYSHIELD_DATA_DIR"


def is_frozen() -> bool:
    """True when running from a compiled build rather than a source checkout.

    Covers Nuitka (which injects ``__compiled__`` into every module) and the
    ``sys.frozen`` flag that PyInstaller and py2exe set, so the predicate does
    not have to be revisited if the packager changes.
    """
    if _FROZEN_OVERRIDE is not None:
        return _FROZEN_OVERRIDE
    return bool(getattr(sys, "frozen", False)) or "__compiled__" in globals()


def resource_root() -> Path:
    """Directory holding files that ship with the program.

    Read-only, and disposable: under a onefile build this is the temporary
    extraction directory, so anything written here is gone when the process
    exits.  Never put durable state under it.

    Derived from sys.executable when frozen, NOT from this module's __file__.
    The module path is one level too deep in a compiled build and produces a
    root one level too high: a checkout has `src/ui/core/paths.py`, so the
    project root is `parents[3]` -- but a build has no `src/` level, so the
    same expression walks past the directory the resources are actually in.

    Measured, not reasoned about.  A standalone build lays the module tree out
    at <dist>/PolyShield.dist/ui/core/paths.py, so:

        parents[3]   <dist>                    <- one too high, no src/ level
        parents[2]   <dist>/PolyShield.dist    <- where the data actually is

    Derived from __file__ rather than from sys.executable, which looks like the
    obvious source and is not: Nuitka reports <dist>/PolyShield.dist/python.exe
    there, and that file DOES NOT EXIST (measured -- see running_executable()).
    Its parent happens to be the right directory, so a sys.executable version
    works by luck while resting on a path to nothing.

    Using the module tree also survives onefile, where the extracted modules
    and their data land together in a temporary directory that sys.argv[0]
    knows nothing about.

    tools/build_probe.py is what caught the original off-by-one: no unit test
    can, because the discrepancy is in a __file__ layout that exists only
    inside a real compiled build.
    """
    if is_frozen():
        # A build has no src/ level, so the module tree is one shallower.
        return Path(__file__).resolve().parents[2]
    return _MODULE_ROOT


def running_executable() -> Path:
    """The binary the user actually launched.

    Emphatically **not** `sys.executable`.  In a Nuitka standalone build that
    reports a `python.exe` sitting beside the real binary, and that file does
    not exist -- measured, not assumed:

        sys.executable              <dist>/PolyShield.dist/python.exe   absent
        sys.argv[0]                 <dist>/PolyShield.dist/PolyShield.exe
        __compiled__.original_argv0 <dist>/PolyShield.dist/PolyShield.exe

    Registering `sys.executable` in the Explorer context menu, or as a Windows
    service image path, points the OS at nothing -- and does it silently, which
    is the failure class this whole phase exists to remove.

    `original_argv0` is preferred over `sys.argv[0]` because onefile re-executes
    the extracted binary: argv[0] is then the temporary copy, while
    original_argv0 stays the exe the user actually double-clicked, which is the
    one worth writing into the registry.
    """
    if is_frozen():
        compiled = globals().get("__compiled__", None)
        original = getattr(compiled, "original_argv0", None)
        return Path(original or sys.argv[0]).resolve()
    return Path(sys.executable).resolve()


def service_registration() -> tuple[str, str]:
    """`(_exe_name_, _exe_args_)` for the Windows service registration.

    Source checkout: the interpreter, plus the script as its argument.
    Frozen: the executable itself with no arguments -- the exe *is* the
    service, and its no-argument branch hands control to the SCM dispatcher.
    """
    if is_frozen():
        return str(running_executable()), ""
    return sys.executable, f'"{resource_root() / "polyshield_service.py"}"'


def app_root() -> Path:
    """The durable writable application-data root.

    Deliberately *not* defined as ``Path(sys.executable).parent``.  A build
    installed under ``C:\\Program Files\\PolyShield`` cannot write beside
    itself without elevation, and PolyShield writes a threat database, a
    quarantine, logs and settings on an ordinary run — so a beside-the-exe
    definition produces a build that works from ``dist\\`` and fails for every
    real installation.

    Resolution order:

      1. ``%POLYSHIELD_DATA_DIR%`` if set — the seam for an installer, a
         portable launcher, or a deployment that keeps data on another volume.
      2. Frozen: ``%LOCALAPPDATA%\\PolyShield``, which is writable for the
         running user in both a portable and an installed layout.
      3. Source checkout: the project root, unchanged from before.

    Step 2 is the one Phase 4b may revisit — portable-beside-exe is a
    legitimate choice for a distribution that ships as a folder.  It is a
    one-line change *here*, which is the point of the module.
    """
    override = os.environ.get(DATA_DIR_ENV, "").strip()
    if override:
        return Path(override).expanduser()

    if is_frozen():
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / "PolyShield"
        # No profile directory at all (a service account with a stripped
        # environment). Beside the executable is a poor durable root, but it is
        # a real directory, and returning it is better than returning the
        # extraction directory that is about to be deleted.
        return Path(sys.executable).resolve().parent

    return _MODULE_ROOT


# ── Named data locations ──────────────────────────────────────────────────────
#
# Thin, but they exist so a caller never has to remember which of the two roots
# a given directory belongs to -- which is the mistake this module is for.

def intelligence_dir() -> Path:
    """Threat database, NSRL bloom, ignore list, pattern stats, update lock."""
    return app_root() / "intelligence"


def quarantine_dir() -> Path:
    return app_root() / "quarantine"


def logs_dir() -> Path:
    return app_root() / "logs"


def config_dir() -> Path:
    return app_root() / "config"


def rules_dir() -> Path:
    """User rules and downloaded community generations both live here."""
    return app_root() / "rules"


def guardian_dir() -> Path:
    """The separately cloned guardianai repository (development environment).

    Not shipped and not user data. `guardianai/data/known_bad.txt` *is* written
    at runtime, so the directory sits under the data root rather than the
    resource root -- but whether a distribution has one at all is a Phase 4b
    question.
    """
    return app_root() / "guardianai"


def k2_exe() -> Path:
    """The bundled kicomav scanner binary, inside the development virtualenv.

    Resolved against the checkout because that is the only place it currently
    exists.  `scanner.is_available()` already reports False when it is missing,
    so a build without it degrades rather than breaks -- see the module
    docstring on why packaging k2 is a Phase 4b decision rather than a path.
    """
    return resource_root() / "kicomav_env" / "Scripts" / "k2.exe"


def venv_python() -> Path:
    """The checkout's virtualenv interpreter (development environment)."""
    return resource_root() / "kicomav_env" / "Scripts" / "python.exe"


def venv_pip() -> Path:
    """The checkout's virtualenv pip (development environment).

    Used by the Update Center to install or refresh optional engines in place.
    A distribution has no virtualenv to install into, which is one more thing
    Phase 4b has to answer for the packaged build.
    """
    return resource_root() / "kicomav_env" / "Scripts" / "pip.exe"


# ── Launching ourselves ───────────────────────────────────────────────────────

class FrozenLaunchUndecided(RuntimeError):
    """Raised where a launch target has no frozen equivalent decided yet.

    Deliberately loud.  The alternative -- returning a command line built from
    a `pythonw.exe` and a `.py` file that a distribution does not contain --
    registers a context-menu verb or a scheduled task that fails silently when
    the user finally triggers it, which is the exact failure mode this whole
    phase exists to prevent.
    """


def app_launch_argv(*args: str) -> list[str]:
    """argv that starts the PolyShield GUI, with `args` appended.

    Source: the windowed interpreter plus `src/ui/app.py`.
    Frozen: the running executable, which *is* the GUI.

    Used by the Explorer context menu, the elevated relaunch in the Windows
    Security view, and the launch-at-login shortcut -- three places that each
    hard-coded their own `pythonw.exe` + `app.py` pair.
    """
    if is_frozen():
        return [str(running_executable()), *args]
    # pythonw.exe unconditionally, matching the behaviour this replaced. An
    # exists() fallback to python.exe looks like an improvement and is out of
    # scope for this phase: it would swap a broken command for a console
    # window, which is a product decision, and the contract is pinned by
    # test_integration_edges.py. A frozen build has no interpreter at all, so
    # the question does not survive into 4b.
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    return [str(pythonw), str(resource_root() / "src" / "ui" / "app.py"), *args]


def script_launch_argv(script: str, *args: str) -> list[str]:
    """argv that runs a bundled helper script (`scheduled_scan.py`, the service).

    Frozen builds have no interpreter and no `.py` files, so each of these
    needs its own executable or a subcommand on the main one.  That is a Phase
    4b decision; until it is made this raises rather than returning a command
    that would be written into the Task Scheduler and fail months later.
    """
    if is_frozen():
        raise FrozenLaunchUndecided(
            f"no frozen launch target for {script}; Phase 4b must decide "
            "whether it ships as its own executable or as a subcommand")
    return [str(venv_python()), str(resource_root() / script), *args]


def bootstrap_sys_path() -> None:
    """Put the checkout and its `src/` on sys.path, in source mode only.

    A frozen build has its modules compiled in; there is no `src/` on disk to
    add, and inserting the extraction directory would only invite an import to
    resolve from a tree that is about to be deleted.
    """
    if is_frozen():
        return
    for p in (resource_root(), resource_root() / "src"):
        if str(p) not in sys.path:
            sys.path.insert(0, str(p))
