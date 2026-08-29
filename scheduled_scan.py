"""
Standalone script invoked by the Windows Task Scheduler.
Usage: python scheduled_scan.py <path_to_scan>
Runs k2.exe on the given path and saves a timestamped JSON report to logs/.
"""
import os
import sys
import subprocess
from datetime import datetime
from pathlib import Path

# Bootstrap before importing ui.core.paths -- see polyshield_service.py for why
# this is one of the three places still allowed to derive a root from __file__.
BASE_DIR = Path(__file__).resolve().parent
for _p in (BASE_DIR, BASE_DIR / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from ui.core import paths                    # noqa: E402  (after bootstrap)

K2_EXE = str(paths.k2_exe())
LOGS_DIR = paths.logs_dir()
LOGS_DIR.mkdir(parents=True, exist_ok=True)


def main():
    scan_path = sys.argv[1] if len(sys.argv) > 1 else str(Path.home())
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = str(LOGS_DIR / f"scheduled_{timestamp}.json")

    # k2_argv, not K2_EXE: a relocated console stub points at an interpreter
    # that is not on this machine and exits 1 with no output at all -- which a
    # scheduled scan would record as a clean result. See paths.k2_argv().
    cmd = paths.k2_argv(str(Path(scan_path).resolve()), "--no-color", "-I",
                        f"--report={report_path}")
    # k2 prunes %SYSTEM_RULES_BASE% against a downloaded manifest, deleting
    # what the manifest does not list. Pointed at PolyShield rules/ that
    # destroys the published YARA generation. See paths.k2_rules_dir().
    k2_rules = paths.k2_rules_dir()
    k2_rules.mkdir(parents=True, exist_ok=True)
    env = {**os.environ,
           "SYSTEM_RULES_BASE": str(k2_rules),
           "USER_RULES_BASE": str(paths.rules_dir() / "user_rules")}
    try:
        subprocess.run(cmd, check=False, env=env,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
