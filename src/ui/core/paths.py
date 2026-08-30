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
    state/service_events.json  (service-owned)
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

#: Placed beside a component that ships INSIDE a distribution but runs from
#: source.  See is_distribution().
DISTRIBUTION_MARKER = ".polyshield-distribution"


def is_frozen() -> bool:
    """True when running from a compiled build rather than a source checkout.

    Covers Nuitka (which injects ``__compiled__`` into every module) and the
    ``sys.frozen`` flag that PyInstaller and py2exe set, so the predicate does
    not have to be revisited if the packager changes.
    """
    if _FROZEN_OVERRIDE is not None:
        return _FROZEN_OVERRIDE
    return bool(getattr(sys, "frozen", False)) or "__compiled__" in globals()


def is_distribution() -> bool:
    """True when this process is part of a shipped product, compiled or not.

    A compiled build always is.  The reason this is not simply `is_frozen()` is
    the Windows service: pywin32 does not survive the Nuitka build (see
    docs/ARCHITECTURE.md), so the service ships as source beside a compiled
    GUI.  It is therefore *not* frozen -- and if it asked `is_frozen()` where
    its data lived it would answer "the directory I am installed in", while the
    GUI two folders away answered the user's LocalAppData.

    They must not disagree.  They read the same threat database, the same
    settings file and the same quarantine; a service writing detections
    somewhere the UI never looks is the whole failure this phase exists to
    prevent, and it would look exactly like a service that found nothing.

    A marker file beside the component is what says so.  Deliberately a file
    rather than an environment variable: a Windows service inherits almost
    nothing from the installing user's environment, and a marker survives the
    service being started by the SCM at boot, from services.msc, or by a
    developer from a shell.
    """
    if is_frozen():
        return True
    try:
        return (_MODULE_ROOT / DISTRIBUTION_MARKER).exists()
    except OSError:          # unreadable directory: assume a checkout
        return False


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


def install_root() -> Path:
    r"""The directory the shipped product is installed in.

    The third lifetime, and the one that only became necessary at ``--onefile``.
    DATA vs RESOURCE was enough while a build was a folder; onefile split
    RESOURCE in two:

        app_root()       durable, writable        %ProgramData%\PolyShield
        install_root()   durable, READ-ONLY       C:\Program Files\PolyShield
        resource_root()  DISPOSABLE, read-only    %TEMP%\ONEFIL~1\  (deleted)

    ``runtime\``, ``service\`` and the shipped ``k2.exe`` sit beside
    ``PolyShield.exe``.  They are reachable from neither of the other two:
    ``resource_root()`` is the temporary extraction directory that is deleted
    when the process exits, and ``app_root()`` is somewhere else entirely.

    The contract is spelled out for all four contexts on purpose, so that its
    meaning does not depend on which of them happens to ship today:

    ======================  ==========================  ====================
    context                 returns                     note
    ======================  ==========================  ====================
    frozen GUI              running_executable().parent NOT sys.executable
    frozen service          running_executable().parent not shipped today
    source-mode staged svc  resource_root().parent      its root is <install>\service
    source checkout         _MODULE_ROOT                unchanged
    ======================  ==========================  ====================

    The staged-service row is the one worth reading twice.  That component is a
    *distribution* but is not *frozen*, and its interpreter is the staged
    ``runtime\python.exe`` -- so ``running_executable().parent`` would answer
    ``<install>\runtime``, one directory to the side, and would do it silently.
    Its own ``_MODULE_ROOT`` is ``<install>\service`` (from
    ``service\src\ui\core\paths.py``), so the install root is one level up.

    **A frozen component must sit at the install root**, which is a real
    constraint on the build rather than an observation about it: a frozen
    service staged into ``<install>\service\`` would resolve its install root to
    itself.  Nothing does that today; ``tools/build_probe.py`` asserts it so
    that nothing starts to.
    """
    if is_frozen():
        return running_executable().parent
    if is_distribution():
        return resource_root().parent
    return _MODULE_ROOT


def runtime_python() -> Path:
    r"""The interpreter that runs a distribution's source-mode components.

    A distribution carries one, because the service does not survive the
    compiler (see docs/ARCHITECTURE.md) and therefore ships as source.  Whatever
    else needs an interpreter -- ``scheduled_scan.py`` -- shares it rather than
    shipping a second copy.

    Resolved from ``install_root()``, NOT from ``resource_root()``: under
    onefile the latter is the extraction directory, and a scheduled task
    pointing into a directory that is deleted when the process exits would fail
    at 02:00 some months later with nobody watching.
    """
    if is_distribution():
        return install_root() / "runtime" / "python.exe"
    return venv_python()


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
    r"""The durable writable application-data root.

    Deliberately *not* defined as ``Path(sys.executable).parent``.  A build
    installed under ``C:\Program Files\PolyShield`` cannot write beside itself
    without elevation, and PolyShield writes a threat database, a quarantine,
    logs and settings on an ordinary run — so a beside-the-exe definition
    produces a build that works from ``dist\`` and fails for every real
    installation.

    Resolution order:

      1. ``%POLYSHIELD_DATA_DIR%`` if set — the seam for an installer, a
         portable launcher, or a deployment that keeps data on another volume.
         It must be set MACHINE-WIDE to be useful: a service inherits nothing
         from the installing user's environment.
      2. Any part of a distribution -- compiled, or shipped-as-source beside a
         compiled component (see is_distribution()) -- ``%ProgramData%\PolyShield``.
      3. Source checkout: the project root, unchanged from before.

    Step 2 was ``%LOCALAPPDATA%\PolyShield`` until v1.16, and it was wrong in a
    way no test could see.  The service runs as ``NT AUTHORITY\LocalService``,
    whose profile is ``C:\Windows\ServiceProfiles\LocalService`` -- so the two
    components resolved two *different* directories:

        GUI           C:\Users\<user>\AppData\Local\PolyShield
        LocalService  C:\Windows\ServiceProfiles\LocalService\AppData\Local\PolyShield

    They must not diverge.  Both read the same threat database, the same
    settings file and the same quarantine -- and two of the files underneath
    are cross-process locks: ``config/ui_settings.json.lock`` (settings.py) and
    ``intelligence/.update.lock`` (intel_updater.py).  A lock file at a path
    each process resolves differently does not merely fail to protect; it hands
    BOTH processes the lock at once, silently, and what it guards is a SQLite
    write.

    A source checkout does not have the problem, because setup_service.bat
    grants LocalService Modify on the project root.  That is a permission fix,
    and it cannot be applied here: two different paths are not a permission
    problem.

    ``%ProgramData%`` is the machine-shared location the service was already
    using for ``service_token.txt`` and ``service.log``, and it resolves to one
    directory for both accounts.  It is deliberately NOT writable by ordinary
    users by default -- the installer creates the tree with explicit
    per-subtree ACLs.  See docs/ARCHITECTURE.md, "The privilege boundary".
    """
    override = os.environ.get(DATA_DIR_ENV, "").strip()
    if override:
        return Path(override).expanduser()

    if is_distribution():
        base = os.environ.get("PROGRAMDATA")
        if base:
            return Path(base) / "PolyShield"
        # A service account with a stripped environment. Derived rather than
        # hard-coded to C:, which is wrong on a machine booting another volume.
        system_drive = os.environ.get("SystemDrive")
        if system_drive:
            return Path(system_drive + "\\") / "ProgramData" / "PolyShield"
        # Nothing at all to go on. Beside the executable is a poor durable
        # root, but it is a real directory, and returning it beats returning
        # the extraction directory that is about to be deleted.
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


def state_dir() -> Path:
    r"""Service-owned runtime state: the IPC token, the service log, the events feed.

    Written by the service and only read by the UI, so the installer gives it
    LocalService:Modify and Users:Read.  Nothing the unelevated GUI writes may
    live here -- see docs/ARCHITECTURE.md, "The privilege boundary".

    Until v1.16 the token and the log were absolute ``C:\ProgramData`` literals
    in polyshield_service.py, outside this module entirely, and the events feed
    sat in config/ beside the user-writable settings file.  They are the same
    lifetime and they now resolve in one place.
    """
    return app_root() / "state"


def telemetry_dir() -> Path:
    """Per-pattern detection and ignore counts, and nothing else.

    Deliberately *outside* intelligence/.  It is written on every pattern match
    by whichever process is scanning -- including the unelevated GUI -- and it
    feeds a false-positive-rate label in Settings, never a detection decision.
    Keeping it out of the service-owned tree is precisely what allows
    intelligence/ to be read-only for ordinary users.
    """
    return app_root() / "telemetry"


def rules_dir() -> Path:
    """User rules and downloaded community generations both live here."""
    return app_root() / "rules"


def k2_rules_dir() -> Path:
    r"""The signature tree k2 owns, and the only one it may prune.

    ``k2 --update`` does **orphan detection**: it downloads a manifest
    (``update.cfg``), walks its rules directory, and deletes every file the
    manifest does not list (``kavcore/k2updater.py`` ->
    ``remove_orphan_files``).  That is reasonable for a directory k2 owns.

    It was not one.  ``config/.env`` -- generated by ``install.bat`` from
    ``config/.env.template`` -- set ``SYSTEM_RULES_BASE`` to PolyShield's own
    ``rules\``, which is also where ``download_yara_community()`` publishes the
    YARA Forge generations.  So every *Update Center -> K2 Engine Signatures*
    click deleted ``rules\community\``, ``.active`` included, and
    ``yara_engine`` then reported "no rules" with nothing to explain it.
    Measured twice, both times destroying a published generation.

    k2 finds this directory through ``%SYSTEM_RULES_BASE%``, which every
    invocation now sets explicitly (``scanner._k2_env()``).  Passing it in the
    environment rather than rewriting ``.env`` matters: ``load_dotenv`` is
    called with ``override=False``, so a value already in the environment wins
    -- which repairs existing installations without touching a generated file
    on disk, and works in a distribution that has no ``.env`` at all.

    Note this is *k2's* rules directory, not PolyShield's.  ``rules_dir()``
    keeps the community generations and the user's own rules, and nothing
    prunes it.
    """
    return app_root() / "k2" / "rules"


def guardian_dir() -> Path:
    """The separately cloned guardianai repository (development environment).

    Not shipped and not user data. `guardianai/data/known_bad.txt` *is* written
    at runtime, so the directory sits under the data root rather than the
    resource root -- but whether a distribution has one at all is a Phase 4b
    question.
    """
    return app_root() / "guardianai"


def k2_exe() -> Path:
    r"""The kicomav scanner binary.

    Distribution: ``<install>\runtime\Scripts\k2.exe``.  K2 is a setuptools
    console stub -- a zip with a launcher prepended -- so it cannot ship on its
    own: it needs the ``kicomav`` package and an interpreter.  It therefore
    rides the runtime that a distribution already carries for the source-mode
    service rather than shipping a second copy of Python beside it.

    Checkout: the development virtualenv, unchanged.

    Resolved from ``install_root()`` and not ``resource_root()`` -- under
    onefile the latter is the extraction directory, so this would name a binary
    that exists only until the process exits.

    ``scanner.is_available()`` still reports False when it is missing, so a
    build without a staged runtime degrades rather than breaks.
    """
    if is_distribution():
        return install_root() / "runtime" / "Scripts" / "k2.exe"
    return resource_root() / "kicomav_env" / "Scripts" / "k2.exe"


def k2_argv(*args: str) -> list[str]:
    r"""argv that runs the k2 scanner, with `args` appended.

    Distribution: ``<install>\runtime\python.exe -m kicomav.k2``.
    Checkout: the ``k2.exe`` console script in the development virtualenv.

    The module, not the console script, and the reason is measured rather than
    stylistic.  ``k2.exe`` is a setuptools stub that embeds the ABSOLUTE PATH of
    the interpreter it was pip-installed against.  Installing relocates the
    runtime -- from ``dist\runtime`` on the build machine to
    ``C:\Program Files\PolyShield\runtime`` on the user's -- and the stub then
    points at a directory that does not exist on that machine.

    It fails in the worst available way: **exit code 1, and nothing on stdout or
    stderr.**  Not an error message, not a traceback.  A caller that only
    counted results would read it as "scanned, found nothing", which is the
    exact shape of a clean scan.

    Found by the build gate on a real install, and then reproduced on the build
    machine by hiding the original ``dist\runtime``: the same relocated k2.exe
    that had just printed 23 signatures printed none.  It had been resolving the
    build machine's own path the whole time.

    ``-m`` has no embedded path -- the interpreter that runs it is named on the
    command line -- so it survives being moved.
    """
    if is_distribution():
        return [str(runtime_python()), "-m", "kicomav.k2", *args]
    return [str(k2_exe()), *args]


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

class StagedRuntimeMissing(RuntimeError):
    r"""A distribution needs its staged interpreter and does not have one.

    Deliberately loud.  The alternative -- returning a command built from a
    ``pythonw.exe`` and a ``.py`` file that a distribution does not contain --
    registers a scheduled task that fails silently at 02:00 some months later,
    with nobody watching.  That is the failure class this module exists to
    remove, so an unrunnable command is never returned in place of an error.

    Named ``FrozenLaunchUndecided`` until v1.16, when the decision it was named
    after was made: helper scripts run from the staged runtime beside the
    service.  The alias below keeps older callers working, but the condition is
    no longer "nobody has chosen" -- it is "the runtime was not staged", which
    is a build or installer fault and should read as one.
    """


#: Retained so an external caller importing the old name still resolves. The
#: condition it described no longer exists.
FrozenLaunchUndecided = StagedRuntimeMissing


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
    r"""argv that runs a bundled helper script (``scheduled_scan.py``).

    Distribution: the staged interpreter plus the script staged beside the
    service -- ``<install>\runtime\python.exe <install>\service\<script>``.
    Both are laid down by ``build.ps1``; the service already runs this way, and
    a scheduled scan sharing that runtime is why 4b.3 needed no second
    executable.

    Checkout: the virtualenv interpreter plus the script at the project root.

    Resolved through ``install_root()`` rather than ``resource_root()``: this
    command is written into the Windows Task Scheduler and has to still be
    valid months later, long after any onefile extraction directory is gone.

    Raises StagedRuntimeMissing when a distribution has no runtime -- a
    GUI-only build.  The caller (``scheduler.create_task``) is better off
    reporting that than registering a task that cannot run.
    """
    if is_distribution():
        interpreter = runtime_python()
        target = install_root() / "service" / script
        if not interpreter.exists():
            raise StagedRuntimeMissing(
                f"cannot run {script}: no interpreter at {interpreter}. "
                "The installer stages runtime\\ beside the executable; a build "
                "without one cannot run scheduled scans.")
        return [str(interpreter), str(target), *args]
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
