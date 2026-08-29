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
import subprocess
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _p in (_HERE.parent, _HERE.parent / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from ui.core import paths  # noqa: E402


#: The floor distinguishes "the plugin tree survived the build" from "it
#: silently did not". It is deliberately LOW.
#:
#: Measured: k2 --vlist reports 23 signatures from the plugins alone and 1263
#: once its rules directory holds the YARA archives that `k2 --update`
#: downloads. So the large number is an INSTALL-time property, not a build-time
#: one -- a gate set at 100 can never pass on a clean build machine no matter
#: what the payload contains, because the frozen binary resolves that machine's
#: own (empty) data root. What the build can actually be held to is that the 51
#: plugin modules are present and loadable, and 20 is comfortably below the 23
#: they yield while being far above the 0 a lost plugin tree yields.
_K2_MIN_SIGNATURES = 20


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


def check_k2() -> dict:
    r"""K2 carries its signatures inside its plugins, and is asked to list them.

    K2 has no signature data file. Its ~1270 known virus names live in the 51
    modules under ``kicomav/plugins/``, and ``k2 --vlist`` prints each one with
    the plugin that knows it:

        Trojan.PDF.Generic        [kicomav.plugins.pdf]

    That listing is exactly the right question for a packaged build. K2 loads
    those plugins with ``SourceFileLoader`` from ``.py`` files on disk and
    **swallows every per-plugin failure**, so a build that lost them still
    starts, still exits zero, and still reports a clean scan -- identical, from
    the outside, to a machine with nothing wrong. A near-empty vlist is that
    failure made visible.

    Deliberately not detection-by-sample. EICAR is the obvious sample and
    Defender deletes it from disk between the write and the scan (measured --
    the file was gone by the time k2 opened it), which would fail this probe
    for a reason that has nothing to do with the build. See this module's
    header on why no sample here is ever a literal.

    ``k2 --update`` does NOT add signatures: it fetches ``whitelist.txt`` and
    two YARA archives, and prunes anything else out of %SYSTEM_RULES_BASE%.
    So a build ships whatever its plugins know, and this count is the whole of
    K2's detection capability.
    """
    from ui.core import scanner as eng

    out = {"available": False, "detail": "", "detected": None}
    try:
        out["available"] = bool(eng.is_available())
    except Exception as exc:
        out["detail"] = f"is_available raised: {exc!r}"
        return out
    if not out["available"]:
        out["detail"] = f"expects {paths.k2_exe()}"
        return out

    try:
        proc = subprocess.run(
            paths.k2_argv("--vlist", "--no-color"),
            capture_output=True, text=True, timeout=120,
            env=eng._k2_env(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        out["detected"] = False
        out["detail"] = f"reported available but --vlist would not run: {exc!r}"
        return out

    names = [ln for ln in proc.stdout.splitlines() if "[kicomav.plugins." in ln]
    # Reported separately from the verdict: whether the downloaded rule set is
    # present is the installer's business, and saying so here is what keeps the
    # low floor from reading as "23 is fine".
    seeded = (paths.k2_rules_dir() / "update.cfg").exists()
    out["rules_seeded"] = seeded
    out["detail"] = (f"{len(names)} signature(s) across the loaded plugins; "
                     f"rule archives {'present' if seeded else 'NOT yet downloaded'}")
    # A floor, not the exact number: the point is "the plugins loaded", and the
    # upstream signature count is free to move. Zero, or a handful, means
    # SourceFileLoader failed and K2 will report every scan clean.
    out["detected"] = len(names) >= _K2_MIN_SIGNATURES
    if not out["detected"]:
        out["detail"] += (f" -- fewer than {_K2_MIN_SIGNATURES}; the plugin "
                          "tree did not survive the build")
        # What k2 actually said. A bare count cannot distinguish "ran and
        # listed nothing" from "did not run", and those have different causes.
        head = (proc.stdout or "").strip().splitlines()[:6]
        err = (proc.stderr or "").strip().splitlines()[:4]
        out["stdout_head"] = head
        out["stderr_head"] = err
        out["returncode"] = proc.returncode
        out["k2_argv"] = paths.k2_argv()
        out["k2_exists"] = paths.k2_exe().exists()
    return out


def check_subprocess_engine(name: str) -> dict:
    """ClamAV shells out; availability is a path probe.

    Not detection-tested: clamscan does not ship in the build, so the property
    worth checking is the other half of honesty -- that an absent engine
    reports absent rather than reporting clean. K2 *does* ship as of 4c.2 and
    has its own check above.
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
    "k2":       check_k2,
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
