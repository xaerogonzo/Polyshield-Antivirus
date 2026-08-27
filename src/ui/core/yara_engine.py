"""
YARA rules engine for PolyShield.

Scans files against .yar rule files in two places:
  - rules/user_rules/   — user-supplied custom rules
  - the live community generation — YARA Forge rules, resolved through the
    rules/community/.active pointer (see active_community_dir below)

yara-python is already in requirements.txt — no extra install needed.
"""

import threading
from pathlib import Path

_USER_DIR      = Path(__file__).resolve().parents[3] / "rules" / "user_rules"
_COMMUNITY_DIR = Path(__file__).resolve().parents[3] / "rules" / "community"
_ACTIVE_PTR    = _COMMUNITY_DIR / ".active"
_MAX_FILE_MB   = 50    # skip files larger than this to prevent hangs on huge binaries
_SCAN_TIMEOUT  = 10    # seconds per file before yara raises a TimeoutError


def active_community_dir() -> Path | None:
    """Resolve the live community rule generation, or None if there is none.

    tools.update_intelligence.download_yara_community() publishes each download
    as an immutable generation directory and then flips the `.active` pointer
    with a single atomic file replace.  Reading the pointer here is what makes
    a rules update all-or-nothing for a scan: _compile() re-reads the directory
    on every scan, so resolving to a whole generation (never a directory being
    written into) is the invariant that matters.

    Installs predating the generation layout keep loose *.yar files directly in
    rules/community/ — that flat directory is the fallback.
    """
    try:
        if _ACTIVE_PTR.is_file():
            name = _ACTIVE_PTR.read_text(encoding="utf-8").strip()
            if name:
                gen = _COMMUNITY_DIR / name
                if gen.is_dir():
                    return gen
    except Exception:
        pass
    return _COMMUNITY_DIR if _COMMUNITY_DIR.is_dir() else None


def _all_yar_files() -> list[Path]:
    """Collect .yar files from the user rules and the live community generation.

    Only the resolved generation is globbed — never rules/community/ itself
    while a pointer is in use, or superseded generations would be compiled too.
    """
    files: list[Path] = []
    if _USER_DIR.is_dir():
        files.extend(_USER_DIR.rglob("*.yar"))
    community = active_community_dir()
    if community is not None:
        files.extend(community.rglob("*.yar"))
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

    Three outcomes, and a caller must be able to tell them apart:

        (True,  "YARA: <rules>")   matched
        (False, "")                scanned and clean, or skipped for size
        (False, "YARA error: …")   could not be scanned — NOT a clean verdict

    The third used to be spelled exactly like the second: one bare
    `except Exception: pass` swallowed a rule that threw, a file that could not
    be read, and the 10-second match timeout alike, and every one of them
    returned the clean tuple. An engine that could not answer must not answer
    "clean" — the watcher reserves that string for runs where every launched
    engine actually completed (see watcher._derive_status).

    Files over _MAX_FILE_MB are still reported as (False, "") rather than as a
    distinct "skipped" state; representing that properly would change
    on_result's shape across all three engines and every consumer.
    """
    try:
        if Path(path).stat().st_size / 1_048_576 > _MAX_FILE_MB:
            return False, ""
    except OSError as exc:
        return False, f"YARA error: {exc}"

    try:
        matches = rules.match(path, timeout=_SCAN_TIMEOUT)
    except Exception as exc:
        return False, f"YARA error: {exc}"

    if matches:
        names = ", ".join(m.rule for m in matches)
        return True, f"YARA: {names}"
    return False, ""


def _summarise(failures: list[str]) -> str:
    """Condense per-file failures into one message.

    Capped because the caller puts this in a status string, and a scan of a
    thousand unreadable files should not build a thousand-entry sentence.
    """
    head = "; ".join(failures[:3])
    if len(failures) > 3:
        head += f"; +{len(failures) - 3} more"
    return head


def scan_async(
    paths: list[str],
    on_result,         # fn(file_path: str, infected: bool, reason: str)
    on_done,           # fn(infected_count: int)
    on_progress=None,  # fn(done: int, total: int, current_file: str) | None
    cancel_event=None, # threading.Event | None
    pause_event=None,  # threading.Event | None — cleared while paused
    on_error=None,     # fn(message: str) | None — called at most once, before on_done
) -> None:
    """
    Compile rules once, scan all paths in a daemon thread.
    Matches guardian_engine.scan_async() signature exactly.

    on_error is additive: every pre-existing call site omits it and behaves
    exactly as it did before. It fires at most once, and always *before*
    on_done, because on_done is what releases the watcher's completion barrier
    — an error delivered afterwards would arrive to find the verdict already
    recorded and the status already derived.
    """
    def _run():
        failures: list[str] = []

        def _finish(count: int):
            if failures and on_error:
                on_error(_summarise(failures))
            on_done(count)

        rules = _compile()
        if rules is None:
            # Two very different states used to share this exit. No rule files
            # at all is a configuration the user chose. Rule files that will
            # not compile is an engine that has silently stopped contributing
            # while is_available() still reports it as available — the caller
            # sees on_done(0), logs "no rule matches", and derives "clean".
            if _all_yar_files():
                failures.append("rules are present but could not be compiled")
            _finish(0)
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
            elif reason:
                failures.append(f"{Path(path).name}: {reason}")
            on_result(path, infected, reason)
        _finish(count)

    threading.Thread(target=_run, daemon=True).start()
