"""
YARA rules engine for PolyShield.

Scans files against .yar rule files in two directories:
  - rules/user_rules/   — user-supplied custom rules
  - rules/community/    — YARA Forge community rules (downloaded from Update Center)

yara-python is already in requirements.txt — no extra install needed.
"""

import threading
from pathlib import Path

_USER_DIR      = Path(__file__).resolve().parents[3] / "rules" / "user_rules"
_COMMUNITY_DIR = Path(__file__).resolve().parents[3] / "rules" / "community"
_MAX_FILE_MB   = 50    # skip files larger than this to prevent hangs on huge binaries
_SCAN_TIMEOUT  = 10    # seconds per file before yara raises a TimeoutError


def _all_yar_files() -> list[Path]:
    """Collect .yar files from both user and community rule directories."""
    files: list[Path] = []
    for d in (_USER_DIR, _COMMUNITY_DIR):
        if d.is_dir():
            files.extend(d.rglob("*.yar"))
    return files


def is_available() -> bool:
    """True if yara-python is importable AND at least one .yar file exists."""
    try:
        import yara  # noqa: F401
    except ImportError:
        return False
    return any(_all_yar_files())


def get_rule_count() -> int:
    """Return the total number of .yar files found across all rule directories."""
    return len(_all_yar_files())


def _compile():
    """
    Compile all .yar files found in user and community rule directories.
    Returns a yara.Rules object, or None if no files exist or compilation fails.
    """
    try:
        import yara
        files = _all_yar_files()
        if not files:
            return None
        # yara.compile requires unique namespace keys — deduplicate stems that collide
        seen: dict[str, str] = {}
        for f in files:
            key = f.stem
            n = 1
            while key in seen:
                key = f"{f.stem}_{n}"
                n += 1
            seen[key] = str(f)
        return yara.compile(filepaths=seen)
    except Exception:
        return None


def scan_file(path: str, rules) -> tuple[bool, str]:
    """
    Scan a single file with pre-compiled rules.
    Returns (infected: bool, reason: str).
    Skips files over _MAX_FILE_MB to avoid hanging on huge binaries.
    """
    try:
        if Path(path).stat().st_size / 1_048_576 > _MAX_FILE_MB:
            return False, ""
        matches = rules.match(path, timeout=_SCAN_TIMEOUT)
        if matches:
            names = ", ".join(m.rule for m in matches)
            return True, f"YARA: {names}"
    except Exception:
        pass
    return False, ""


def scan_async(
    paths: list[str],
    on_result,         # fn(file_path: str, infected: bool, reason: str)
    on_done,           # fn(infected_count: int)
    on_progress=None,  # fn(done: int, total: int, current_file: str) | None
    cancel_event=None, # threading.Event | None
    pause_event=None,  # threading.Event | None — cleared while paused
) -> None:
    """
    Compile rules once, scan all paths in a daemon thread.
    Matches guardian_engine.scan_async() signature exactly.
    """
    def _run():
        rules = _compile()
        if rules is None:
            on_done(0)
            return

        count = 0
        total = len(paths)
        for i, path in enumerate(paths):
            if cancel_event and cancel_event.is_set():
                break
            if pause_event is not None:
                pause_event.wait()   # blocks while paused; instant if running
                if cancel_event and cancel_event.is_set():
                    break
            if on_progress:
                on_progress(i + 1, total, path)
            infected, reason = scan_file(path, rules)
            if infected:
                count += 1
            on_result(path, infected, reason)
        on_done(count)

    threading.Thread(target=_run, daemon=True).start()
