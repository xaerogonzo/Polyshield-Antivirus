"""
Standalone script invoked by the Windows Task Scheduler.
Usage: python scheduled_scan.py <path_to_scan>
Runs k2.exe on the given path and saves a timestamped JSON report to logs/.
"""
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

    cmd = [K2_EXE, scan_path, "--no-color", "-I", f"--report={report_path}"]
    try:
        subprocess.run(cmd, check=False,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
