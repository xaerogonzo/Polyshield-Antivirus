import subprocess
import json
import threading
from datetime import datetime
from pathlib import Path

_NO_WINDOW = subprocess.CREATE_NO_WINDOW  # 0x08000000 — suppresses console flash

# MpCmdRun.exe location (Defender CLI, works without elevation for scan triggers)
_MPCMDRUN = Path(
    r"C:\Program Files\Windows Defender\MpCmdRun.exe"
)


def _run_ps(command: str, timeout: int = 20) -> tuple[bool, str]:
    """Run a PowerShell command and return (success, output).

    Uses Popen with stderr/stdin=DEVNULL to avoid the Windows pipe-hang bug:
    subprocess.run(capture_output=True) can block indefinitely when WMI child
    processes keep the stdout pipe handle open after proc.kill().
    """
    try:
        proc = subprocess.Popen(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command", command,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            text=True,
            creationflags=_NO_WINDOW,
        )
        try:
            stdout, _ = proc.communicate(timeout=timeout)
            return proc.returncode == 0, stdout.strip()
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                pass  # WMI child still holds pipe — OS will clean up
            return False, f"PowerShell timed out after {timeout}s"
    except Exception as exc:
        return False, str(exc)


def get_status() -> dict:
    """
    Return Windows Defender status.  Always returns a dict; on failure the
    'available' key is False and other keys hold safe defaults.
    """
    fields = (
        "RealTimeProtectionEnabled",
        "AntivirusEnabled",
        "AntispywareEnabled",
        "BehaviorMonitorEnabled",
        "IoavProtectionEnabled",
        "NISEnabled",
        "QuickScanAge",
        "FullScanAge",
        "AntivirusSignatureAge",
        "AntivirusSignatureLastUpdated",
    )
    ps = (
        f"Get-MpComputerStatus | "
        f"Select-Object {','.join(fields)} | "
        f"ConvertTo-Json -Compress"
    )
    ok, output = _run_ps(ps)
    if not ok or not output:
        return {"available": False}
    try:
        data = json.loads(output)
        data["available"] = True
        # Normalise the last-updated timestamp to a readable string
        raw_ts = data.get("AntivirusSignatureLastUpdated", "")
        if raw_ts:
            try:
                # PowerShell emits /Date(ms)/ or ISO strings
                if "/Date(" in str(raw_ts):
                    ms = int(str(raw_ts).split("(")[1].split(")")[0])
                    data["AntivirusSignatureLastUpdated"] = datetime.fromtimestamp(
                        ms / 1000
                    ).strftime("%Y-%m-%d %H:%M")
            except Exception:
                pass
        return data
    except json.JSONDecodeError:
        return {"available": False}


def get_threat_history(limit: int = 20) -> list[dict]:
    """Return recent Defender threat detections."""
    ps = (
        f"$t = Get-MpThreatDetection | Select-Object -First {limit} "
        f"-Property ThreatID,ActionSuccess,CurrentThreatExecutionStatusID,"
        f"DetectionSourceTypeID,DomainUser,InitialDetectionTime,LastThreatStatusChangeTime,"
        f"ProcessName,RemediationTime,ThreatStatusID; "
        f"$t | ConvertTo-Json -Depth 2 -Compress"
    )
    ok, output = _run_ps(ps)
    if not ok or not output:
        return []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except Exception:
        return []


def get_threat_names(limit: int = 20) -> list[dict]:
    """Return threat name info alongside detections."""
    ps = (
        f"Get-MpThreat | Select-Object -First {limit} "
        f"-Property ThreatID,ThreatName,SeverityID,CategoryID,IsActive "
        f"| ConvertTo-Json -Compress"
    )
    ok, output = _run_ps(ps)
    if not ok or not output:
        return []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except Exception:
        return []


def start_scan(scan_type: str = "QuickScan", path: str = "") -> tuple[bool, str]:
    """
    Trigger a Defender scan.
    scan_type: 'QuickScan' | 'FullScan' | 'CustomScan'
    path: only used for CustomScan
    Returns (success, message).

    Strategy:
      1. MpCmdRun.exe  — native Defender CLI, no PowerShell cold-start,
                         works without elevation for Quick/Custom scans.
      2. Start-MpScan  — PowerShell fallback if MpCmdRun is missing.
    """
    # ── Path 1: MpCmdRun.exe (preferred — faster, no PS cold-start) ──────────
    if _MPCMDRUN.exists():
        scan_map = {"QuickScan": "1", "FullScan": "2", "CustomScan": "3"}
        scan_num = scan_map.get(scan_type, "1")
        cmd = [str(_MPCMDRUN), "-Scan", "-ScanType", scan_num]
        if scan_type == "CustomScan" and path:
            cmd += ["-File", path]
        try:
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_NO_WINDOW,
            )
            return True, f"{scan_type} triggered via MpCmdRun."
        except Exception as exc:
            # Fall through to PowerShell
            pass

    # ── Path 2: PowerShell Start-MpScan (fallback) ───────────────────────────
    if scan_type == "CustomScan" and path:
        ps = f'Start-MpScan -ScanType CustomScan -ScanPath "{path}"'
    else:
        ps = f"Start-MpScan -ScanType {scan_type}"

    ok, output = _run_ps(ps, timeout=30)
    if ok:
        return True, f"{scan_type} triggered via PowerShell."
    return False, output or "Failed to start Defender scan (try running as Administrator)."


def is_mpcmdrun_available() -> bool:
    """True if MpCmdRun.exe is present on this system."""
    return _MPCMDRUN.exists()


def scan_paths_async(
    paths: list[str],
    on_result,           # fn(path: str, infected: bool, reason: str)
    on_done,             # fn(infected_count: int)
    on_progress=None,    # fn(done: int, total: int, current_path: str) | None
    cancel_event=None,   # threading.Event | None
) -> None:
    """
    Scan paths with Windows Defender using MpCmdRun.exe.
    Uses directory-level scans (fast) + threat-history diff to find flagged files.
    Individual file paths are scanned one at a time; directories are scanned as units.
    """
    import json as _json

    def _get_threat_ids() -> set[str]:
        ok, output = _run_ps(
            "Get-MpThreatDetection | Select-Object -ExpandProperty ThreatID",
            timeout=10)
        if not ok or not output:
            return set()
        return set(output.splitlines())

    def _get_new_detections(pre_ids: set[str]) -> list[str]:
        ok, output = _run_ps(
            "Get-MpThreatDetection | Select-Object ThreatID,Resources | "
            "ConvertTo-Json -Compress",
            timeout=10)
        if not ok or not output:
            return []
        try:
            data = _json.loads(output)
            if isinstance(data, dict):
                data = [data]
            flagged: list[str] = []
            for item in data:
                if str(item.get("ThreatID", "")) not in pre_ids:
                    res = item.get("Resources", "") or ""
                    # Resources is a string like "file:_C:\bad.exe" — strip prefix
                    fpath = res.replace("file:_", "").strip()
                    if fpath:
                        flagged.append(fpath)
            return flagged
        except Exception:
            return []

    def _run():
        if not _MPCMDRUN.exists():
            on_done(0)
            return

        pre_ids = _get_threat_ids()

        # Separate directories from individual files so we can scan dirs as units
        dirs   = [p for p in paths if Path(p).is_dir()]
        files  = [p for p in paths if Path(p).is_file()]
        scan_targets = dirs + files
        total = len(scan_targets)

        for i, target in enumerate(scan_targets):
            if cancel_event and cancel_event.is_set():
                break
            if on_progress:
                on_progress(i + 1, total, target)
            try:
                subprocess.run(
                    [str(_MPCMDRUN), "-Scan", "-ScanType", "3", "-File", target],
                    capture_output=True, timeout=300,
                    creationflags=_NO_WINDOW)
            except Exception:
                pass

        # Diff threat history to find what Defender actually flagged
        flagged_paths = _get_new_detections(pre_ids)
        count = len(flagged_paths)
        for fpath in flagged_paths:
            on_result(fpath, True, "Defender: threat detected")
        on_done(count)

    threading.Thread(target=_run, daemon=True).start()


def start_scan_async(scan_type: str, path: str, done_callback):
    """Trigger a Defender scan in a background thread."""
    def _run():
        ok, msg = start_scan(scan_type, path)
        done_callback(ok, msg)
    threading.Thread(target=_run, daemon=True).start()


def get_defender_exclusions() -> dict:
    """
    Return paths, extensions, and processes that Defender is configured to skip.
    These are potential blind spots — surfaces them in the Windows Security view.
    """
    ps = (
        "Get-MpPreference | "
        "Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess | "
        "ConvertTo-Json -Compress"
    )
    ok, output = _run_ps(ps, timeout=15)
    if not ok or not output:
        return {"available": False}
    try:
        data = json.loads(output)
        paths = data.get("ExclusionPath") or []
        exts  = data.get("ExclusionExtension") or []
        procs = data.get("ExclusionProcess") or []
        if isinstance(paths, str):
            paths = [paths]
        if isinstance(exts, str):
            exts = [exts]
        if isinstance(procs, str):
            procs = [procs]
        return {
            "available": True,
            "paths":     [p for p in paths if p],
            "extensions":[e for e in exts if e],
            "processes": [p for p in procs if p],
            "total":     len([x for x in (paths + exts + procs) if x]),
        }
    except Exception:
        return {"available": False}
