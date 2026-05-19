"""
emulate_engine.py
─────────────────
Wrapper around Mandiant's Speakeasy PE emulator.

Speakeasy traces Windows API calls, registry access, network activity, and
file-system operations for a PE file (.exe / .dll / shellcode) WITHOUT
actually executing it on the host OS.  Safe to run against suspected malware.

Install:
    kicomav_env\\Scripts\\pip.exe install speakeasy-emulator

Availability is checked at import time — all public functions degrade
gracefully if the package is not installed.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


# ── Availability ─────────────────────────────────────────────────────────────

def is_available() -> bool:
    """True if speakeasy-emulator is installed in the active venv."""
    try:
        import speakeasy  # noqa: F401
        return True
    except ImportError:
        return False


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class EmulationReport:
    """Structured output from a Speakeasy emulation run."""

    # Windows API calls captured during emulation
    # Each entry: {"api": str, "args": list, "ret": str|int}
    api_calls: list[dict] = field(default_factory=list)

    # IP addresses / hostnames / URLs contacted
    network: list[str] = field(default_factory=list)

    # Registry operations
    # Each entry: {"op": "read"|"write"|"delete", "key": str, "value": str}
    registry: list[dict] = field(default_factory=list)

    # File-system operations
    # Each entry: {"op": "create"|"write"|"delete"|"read", "path": str}
    file_ops: list[dict] = field(default_factory=list)

    # Raw Speakeasy report dict (full JSON output)
    raw: dict = field(default_factory=dict)

    # Set if emulation failed before completion
    error: str | None = None

    @property
    def threat_indicators(self) -> list[str]:
        """
        High-level threat indicators derived from the emulation trace.
        Returned as human-readable strings for display in the UI.
        """
        indicators: list[str] = []

        # Persistence / autorun
        _persist_keys = (
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        )
        for reg in self.registry:
            if reg.get("op") == "write" and any(
                    k.upper() in reg.get("key", "").upper() for k in _persist_keys):
                indicators.append(f"Persistence: writes Run key → {reg['key']}")

        # Network C2
        for url in self.network:
            indicators.append(f"Network: contacts {url}")

        # Process injection APIs
        _inject_apis = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                        "NtCreateThreadEx", "RtlCreateUserThread"}
        used_inject = {c["api"] for c in self.api_calls if c.get("api") in _inject_apis}
        if used_inject:
            indicators.append(f"Injection: uses {', '.join(sorted(used_inject))}")

        # Encryption / ransomware
        _crypt_apis = {"CryptEncrypt", "CryptGenKey", "BCryptEncrypt", "BCryptGenerateSymmetricKey"}
        used_crypt = {c["api"] for c in self.api_calls if c.get("api") in _crypt_apis}
        if used_crypt:
            indicators.append(f"Encryption: calls {', '.join(sorted(used_crypt))}")

        # Shadow copy deletion (ransomware)
        for c in self.api_calls:
            args_str = str(c.get("args", ""))
            if "vssadmin" in args_str.lower() or "shadowcopy" in args_str.lower():
                indicators.append("Ransomware: attempts shadow copy deletion")
                break

        return indicators


# ── Internal helpers ──────────────────────────────────────────────────────────

def _parse_report(raw: dict) -> EmulationReport:
    """Convert the raw Speakeasy JSON report into an EmulationReport."""
    report = EmulationReport(raw=raw)

    for entry in raw.get("entry_points", []):
        # API calls
        for api_info in entry.get("apis", []):
            call = {
                "api": api_info.get("api_name", "?"),
                "args": api_info.get("args", []),
                "ret": api_info.get("ret_val", ""),
            }
            report.api_calls.append(call)

            # Network: extract from Winsock / WinInet calls
            net_apis = {"connect", "WSAConnect", "InternetOpenUrl",
                        "InternetConnect", "HttpSendRequest", "URLDownloadToFile"}
            if call["api"] in net_apis:
                for arg in call["args"]:
                    val = str(arg.get("val", "")) if isinstance(arg, dict) else str(arg)
                    if val and val not in ("0", "None", ""):
                        report.network.append(val)
                        break

            # Registry
            reg_apis = {
                "RegSetValueEx": "write", "RegSetValue": "write",
                "RegQueryValueEx": "read", "RegQueryValue": "read",
                "RegDeleteValue": "delete", "RegDeleteKey": "delete",
            }
            if call["api"] in reg_apis:
                key_val = ""
                for arg in call["args"]:
                    val = str(arg.get("val", "")) if isinstance(arg, dict) else str(arg)
                    if "HKEY" in val.upper() or "SOFTWARE" in val.upper():
                        key_val = val
                        break
                report.registry.append({
                    "op": reg_apis[call["api"]],
                    "key": key_val or "unknown",
                    "value": "",
                })

            # File ops
            file_apis = {
                "CreateFileW": "create", "CreateFileA": "create",
                "WriteFile": "write", "DeleteFileW": "delete",
                "DeleteFileA": "delete", "ReadFile": "read",
            }
            if call["api"] in file_apis:
                path_val = ""
                for arg in call["args"]:
                    val = str(arg.get("val", "")) if isinstance(arg, dict) else str(arg)
                    if "\\" in val or "." in val:
                        path_val = val
                        break
                report.file_ops.append({
                    "op": file_apis[call["api"]],
                    "path": path_val or "unknown",
                })

        # Network block from Speakeasy's dedicated network section
        for net in entry.get("network_events", {}).get("traffic", []):
            server = net.get("server", "")
            if server and server not in report.network:
                report.network.append(server)

    return report


# ── Subprocess worker path + constants ───────────────────────────────────────

# Worker script lives alongside this module
_WORKER    = Path(__file__).parent / "_speakeasy_worker.py"
_NO_WINDOW = subprocess.CREATE_NO_WINDOW
_TIMEOUT   = 90   # seconds — complex PE files can take a while

# File types speakeasy cannot emulate (non-PE, non-shellcode)
_UNSUPPORTED = frozenset({
    ".py", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".txt",
    ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".zip", ".7z",
})


# ── Public API ────────────────────────────────────────────────────────────────

def emulate_async(
    path: str,
    on_done: Callable[[EmulationReport], None],
) -> None:
    """
    Emulate a PE file with Speakeasy, keeping the UI fully responsive.

    The emulation runs in a *subprocess* (not just a thread).  Speakeasy uses
    unicorn-engine, which calls Python hook functions from C on every emulated
    API call.  Each hook re-acquires the Python GIL and starves the
    CustomTkinter event loop if the work is only on a thread.  A subprocess has
    its own GIL — the main process is never contended.

    The background thread in *this* process waits on the subprocess and calls
    on_done(report) when it finishes.  Caller must marshal to the main thread
    via self.after(0, ...) before updating any UI widgets.

    Supports: .exe, .dll, raw shellcode (.bin / .sc).
    Does NOT support: scripts, Office documents, PDFs.
    """
    def _run():
        if not is_available():
            on_done(EmulationReport(
                error="speakeasy-emulator not installed.\n"
                      "Run: kicomav_env\\Scripts\\pip.exe install speakeasy-emulator"))
            return

        file_path = Path(path)
        if not file_path.exists():
            on_done(EmulationReport(error=f"File not found: {path}"))
            return

        ext = file_path.suffix.lower()
        if ext in _UNSUPPORTED:
            on_done(EmulationReport(
                error=f"Speakeasy emulates PE files only (.exe, .dll, shellcode).\n"
                      f"This file type ({ext}) cannot be emulated."))
            return

        mode = "dll" if ext == ".dll" else ("sc" if ext in (".bin", ".sc") else "exe")

        try:
            proc = subprocess.Popen(
                [sys.executable, str(_WORKER), path, mode],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=_NO_WINDOW,
            )
            try:
                stdout, _ = proc.communicate(timeout=_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                on_done(EmulationReport(
                    error=f"Emulation timed out after {_TIMEOUT} seconds.\n"
                          f"The PE may be too complex or contain an infinite loop."))
                return

            raw_text = stdout.decode("utf-8", errors="replace").strip()
            if not raw_text:
                on_done(EmulationReport(error="Worker produced no output (crash?)."))
                return

            try:
                data = json.loads(raw_text)
            except json.JSONDecodeError:
                on_done(EmulationReport(
                    error=f"Worker output was not valid JSON:\n{raw_text[:300]}"))
                return

            if "error" in data:
                on_done(EmulationReport(error=data["error"]))
            else:
                on_done(_parse_report(data.get("report", {})))

        except Exception as exc:
            on_done(EmulationReport(error=f"Emulation error: {str(exc)[:200]}"))

    threading.Thread(target=_run, daemon=True).start()
