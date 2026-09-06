"""
CLI:  python tools\\uishot\\__main__.py [--only NAME] [--check | --update-golden]

    ... --list                  list the scenes
    ... --only intel-posture    capture one
    ... --update-golden         record the current look as expected
    ... --check                 fail if anything drifted from golden
    ... --probe                 exit 0 if capture works here, 2 if not

The argument parsing, capture loop and golden comparison live in
``polybedrock.ui.uishot.cli`` — none of it was PolyShield-specific. What this
file supplies is PolyShield's scene registry and a session wired to its entry
point.

Kept as a runnable file rather than a console script because
``tests/test_uishot.py`` invokes it through a subprocess: SetThreadDesktop fails
once the calling thread owns a window, and the rest of the suite holds a
session-scoped Tk root.
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[2]
if str(_HERE.parents[1]) not in sys.path:
    sys.path.insert(0, str(_HERE.parents[1]))

from polybedrock.ui.uishot import cli               # noqa: E402
from uishot.scenes import REGISTRY                  # noqa: E402
from uishot.session import TkSession                # noqa: E402


def main(argv: list[str] | None = None) -> int:
    return cli.run(
        argv,
        registry=REGISTRY,
        project_root=_PROJECT_ROOT,
        session_factory=lambda out_dir, root: TkSession(out_dir=out_dir,
                                                        project_root=root),
    )


if __name__ == "__main__":
    raise SystemExit(main())
