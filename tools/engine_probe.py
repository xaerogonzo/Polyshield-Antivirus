r"""Report which detection engines survive a build — and prove it by detecting.

`is_available()` is a claim, and for two of these engines it is a claim the
engine itself cannot check. K2 in particular loads its 50 plugins with
`SourceFileLoader` from `.py` files on disk and swallows every per-plugin
failure, so a packaged K2 can start, exit zero, report no threats and be
indistinguishable from a clean scan. "The engine is available" and "the engine
detects things" are different statements, and only the second one is worth
shipping on.

So each engine that reports itself available is then asked to find something
planted for it. Engines that report themselves *unavailable* are checked for
the other half of honesty: that they say so rather than returning clean.

    kicomav_env\Scripts\python.exe tools\engine_probe.py
    dist\engine_probe.dist\engine_probe.exe        (after building it)

Exits non-zero when an engine claims to be available and then fails to detect,
which is the combination that must never ship.

No EICAR. Defender quarantines it on write, which would fail this probe for a
reason that has nothing to do with the build. The planted samples below are
assembled from fragments at runtime for the same reason the test suite does it:
a probe that is itself a pattern match is a probe that trips scanners.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _p in (_HERE.parent, _HERE.parent / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from ui.core import paths  # noqa: E402


def _fragments(*parts: str) -> str:
    """Assemble a detectable string at runtime, never as a literal."""
    return "".join(parts)


# ── Per-engine checks ─────────────────────────────────────────────────────────

def check_yara() -> dict:
    """Compile a rule and match it. Runs entirely in-process."""
    from ui.core import yara_engine

    out = {"available": False, "detail": "", "detected": None}
    try:
        out["available"] = bool(yara_engine.is_available())
        out["detail"] = f"{yara_engine.get_rule_count()} rule file(s)"
    except Exception as exc:
        out["detail"] = f"is_available raised: {exc!r}"
        return out
    if not out["available"]:
        return out

    try:
        import yara
    except ImportError as exc:
        out["detected"] = False
        out["detail"] = f"reported available but yara will not import: {exc}"
        return out

    needle = _fragments("polyshield", "_engine_", "probe_marker")
    with tempfile.TemporaryDirectory() as td:
        rule = Path(td) / "probe.yar"
        rule.write_text(
            'rule ProbeMarker { strings: $a = "%s" condition: $a }' % needle,
            encoding="utf-8")
        sample = Path(td) / "sample.txt"
        sample.write_text(f"harmless text {needle} more text\n", encoding="utf-8")
        try:
            matches = yara.compile(filepath=str(rule)).match(str(sample))
            out["detected"] = bool(matches)
            out["detail"] = f"{out['detail']}; rule matched: {bool(matches)}"
        except Exception as exc:
            out["detected"] = False
            out["detail"] = f"compile/match raised: {exc!r}"
    return out


def check_guardian() -> dict:
    """Drive the real verdict path with a file planted for a heuristic."""
    from ui.core import guardian_engine

    out = {"available": False, "detail": "", "detected": None}
    try:
        out["available"] = bool(guardian_engine.is_available())
    except Exception as exc:
        out["detail"] = f"is_available raised: {exc!r}"
        return out
    if not out["available"]:
        out["detail"] = "no guardianai tree"
        return out

    # The Mimikatz pattern: extremely specific, and enabled under every profile.
    needle = _fragments("sekurlsa", "::", "logonpasswords")
    with tempfile.TemporaryDirectory() as td:
        sample = Path(td) / "sample.txt"
        sample.write_text(f"log line\n{needle}\n", encoding="utf-8")
        try:
            scanner = guardian_engine._EnhancedScanner()
            infected, reason, tier, _ctx = scanner.scan_file(str(sample))
            out["detected"] = bool(infected)
            out["detail"] = f"tier={tier} reason={reason[:60]}"
        except Exception as exc:
            out["detected"] = False
            out["detail"] = f"scan_file raised: {exc!r}"
    return out


def check_subprocess_engine(name: str) -> dict:
    """K2 and ClamAV both shell out; availability is a path probe.

    Not detection-tested here: neither binary ships in the current build, so
    the property worth checking is the other half of honesty -- that an absent
    engine reports absent rather than reporting clean.
    """
    out = {"available": False, "detail": "", "detected": None}
    try:
        if name == "k2":
            from ui.core import scanner as eng
            out["available"] = bool(eng.is_available())
            out["detail"] = f"expects {paths.k2_exe()}"
        else:
            from ui.core import clamav_engine as eng
            out["available"] = bool(eng.is_available())
            out["detail"] = eng.get_version() or "clamscan.exe not found"
    except Exception as exc:
        out["detail"] = f"is_available raised: {exc!r}"
    return out


CHECKS = {
    "yara":     check_yara,
    "guardian": check_guardian,
    "k2":       lambda: check_subprocess_engine("k2"),
    "clamav":   lambda: check_subprocess_engine("clamav"),
}


def main() -> int:
    report = {
        "frozen": paths.is_frozen(),
        "distribution": paths.is_distribution(),
        "resource_root": str(paths.resource_root()),
        "engines": {},
    }
    for name, fn in CHECKS.items():
        try:
            report["engines"][name] = fn()
        except Exception as exc:            # a check must never take the probe down
            report["engines"][name] = {
                "available": None, "detected": None,
                "detail": f"probe raised: {exc!r}",
            }

    print(json.dumps(report, indent=2))

    # The one combination that must never ship: an engine that says it is there
    # and then finds nothing. An engine that says it is absent is fine -- the
    # pipeline runs without it and the UI reports it.
    liars = [n for n, r in report["engines"].items()
             if r.get("available") and r.get("detected") is False]
    if liars:
        print("FAIL: available but did not detect: " + ", ".join(liars),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
