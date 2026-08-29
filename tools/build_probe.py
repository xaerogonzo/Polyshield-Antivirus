"""Print how a build resolves its paths — the packaged-build counterpart to test_paths.py.

tests/test_paths.py drives frozen behaviour by monkeypatching
`paths._FROZEN_OVERRIDE`. That covers the *policy* but not the *detection*:
nothing in the suite proves that `is_frozen()` actually returns True inside a
real compiled build, because the suite never runs inside one. The predicate
rests on `"__compiled__" in globals()`, which is a claim about Nuitka rather
than about this code, and a claim that is wrong would be invisible -- a frozen
build that believes it is a source checkout resolves `app_root()` to the
extraction directory and loses every byte the user writes.

So this is compiled with the same flags as the real entry points and run from
the build, where its answers are facts rather than fixtures:

    kicomav_env\\Scripts\\python.exe -m nuitka --standalone \\
        --include-package=ui --output-dir=dist tools/build_probe.py
    dist\\build_probe.dist\\build_probe.exe

Emits JSON so build.ps1 can gate on it. Exits non-zero when the build has
resolved something durable underneath the extraction directory, which is the
one outcome that must never ship.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# The probe is compiled with src/ on PYTHONPATH, exactly as the app is; when
# run from a checkout it needs the same bootstrap the entry points do.
_HERE = Path(__file__).resolve().parent
for _p in (_HERE.parent, _HERE.parent / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from ui.core import paths  # noqa: E402  (after bootstrap)


def collect() -> dict:
    # Report the paths the app actually uses, unresolved. resolve() is applied
    # only for the containment comparison below, because it follows reparse
    # points: under a packaged/virtualised host, %LOCALAPPDATA% resolves into a
    # per-app container (…\Packages\<id>\LocalCache\Local\…), and reporting the
    # resolved form beside the unresolved children makes one run look like it
    # disagrees with itself. Same directory, two names.
    app = paths.app_root()
    resource = paths.resource_root().resolve()
    named = {
        "intelligence": paths.intelligence_dir(),
        "quarantine": paths.quarantine_dir(),
        "logs": paths.logs_dir(),
        "config": paths.config_dir(),
        "rules": paths.rules_dir(),
    }
    # The invariant 4a exists to protect: nothing durable may live under the
    # directory a onefile build deletes on exit.
    #
    # Only meaningful when frozen. In a source checkout app_root() and
    # resource_root() are deliberately the SAME directory -- the project root --
    # so every data path is "under" the resource root by construction, and
    # checking it there reports a failure for the normal case.
    leaked = sorted(
        name for name, p in named.items()
        if resource == p.resolve() or resource in p.resolve().parents
    ) if paths.is_frozen() else []
    return {
        "frozen": paths.is_frozen(),
        "nuitka_compiled": "__compiled__" in globals(),
        "sys_frozen": bool(getattr(sys, "frozen", False)),
        "executable": sys.executable,
        "executable_exists": Path(sys.executable).exists(),
        "argv0": sys.argv[0],
        "argv0_exists": Path(sys.argv[0]).exists(),
        "compiled_attrs": sorted(
            a for a in dir(globals().get("__compiled__", object()))
            if not a.startswith("_")
        ),
        "containing_dir": getattr(globals().get("__compiled__", None),
                                  "containing_dir", None),
        "original_argv0": getattr(globals().get("__compiled__", None),
                                  "original_argv0", None),
        "app_root": str(app),
        "app_root_resolved": str(app.resolve()),
        "resource_root": str(resource),
        "data_dir_env": os.environ.get(paths.DATA_DIR_ENV, ""),
        "paths": {k: str(v) for k, v in named.items()},
        "leaked_under_resource_root": leaked,
    }


def main() -> int:
    info = collect()
    print(json.dumps(info, indent=2))

    if info["leaked_under_resource_root"]:
        print("FAIL: durable data resolves under the extraction directory: "
              + ", ".join(info["leaked_under_resource_root"]), file=sys.stderr)
        return 1

    # A compiled build that believes it is a source checkout is the failure
    # this probe exists to catch, and it is silent every other way.
    if info["nuitka_compiled"] and not info["frozen"]:
        print("FAIL: compiled by Nuitka but is_frozen() is False", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
