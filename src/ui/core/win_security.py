"""
win_security.py
───────────────
Windows Security supplementary data layer.

Design rules:
  • Registry reads for simple on/off status (no subprocess overhead)
  • PowerShell only for structured/complex queries
  • Every function returns a safe default on failure — never raises
  • Elevation-aware: result dicts include needs_elevation=True when a query
    requires admin and the current process is not elevated
"""
from __future__ import annotations

import json
import subprocess
import threading
import winreg
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ui.core import ps_run

_NO_WINDOW = subprocess.CREATE_NO_WINDOW

# ── ASR rule GUID → human category mapping ───────────────────────────────────
_ASR_CATEGORIES: dict[str, tuple[str, str]] = {
    # (category_name, short_description)
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550": ("Office Macro Protections",  "Block executable content from email"),
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A": ("Office Macro Protections",  "Block Office child processes"),
    "3B576869-A4EC-4529-8536-B80A7769E899": ("Office Macro Protections",  "Block Office executable content creation"),
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84": ("Office Macro Protections",  "Block Office code injection"),
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B": ("Office Macro Protections",  "Block Win32 API calls from Office macros"),
    "26190899-1602-49E8-8B27-EB1D0A1CE869": ("Office Macro Protections",  "Block Office comm app child processes"),
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C": ("Office Macro Protections",  "Block Adobe Reader child processes"),
    "D3E037E1-3EB8-44C8-A917-57927947596D": ("Script Execution Blocks",   "Block JS/VBScript launching downloads"),
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC": ("Script Execution Blocks",   "Block obfuscated script execution"),
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C": ("Script Execution Blocks",   "Block PSExec/WMI process creation"),
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B0": ("Credential Theft Prevention","Block LSASS credential stealing"),
    "C1DB55AB-C21A-4637-BB3F-A12568109D35": ("Ransomware Protection",     "Advanced ransomware protection"),
    "56A863A9-875E-4185-98A7-B882C64B5CE5": ("Exploit Protection",        "Block exploited signed driver abuse"),
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4": ("Exploit Protection",        "Block unsigned USB processes"),
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B": ("Exploit Protection",        "Block WMI event subscription persistence"),
    "01443614-CD74-433A-B99E-2ECDC07BFC25": ("Prevalence / Trust Checks", "Block low-prevalence executables"),
}

# ── Registry helpers ──────────────────────────────────────────────────────────

def _reg_read(hive, subkey: str, value_name: str, default=None):
    """Read a single registry value; return default on any error."""
    try:
        with winreg.OpenKey(hive, subkey) as key:
            val, _ = winreg.QueryValueEx(key, value_name)
            return val
    except OSError:
        return default


def _reg_key_exists(hive, subkey: str) -> bool:
    try:
        winreg.OpenKey(hive, subkey).Close()
        return True
    except OSError:
        return False


# ── PowerShell helper (mirrors defender.py) ───────────────────────────────────

def _run_ps(command: str, timeout: int = 20) -> tuple[bool, str]:
    """Run a PowerShell command and return (success, output).

    Thin wrapper over the shared runner — see ui.core.ps_run for why the
    implementation has the shape it does. Kept as a module-local name so the
    eleven call sites below read unchanged.
    """
    return ps_run.run_ps(command, timeout)


def _is_elevated() -> bool:
    """Return True if the current process has admin rights."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 1. Firewall & Network
# ─────────────────────────────────────────────────────────────────────────────

_FW_BASE = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"

def get_firewall_profiles() -> dict:
    """
    Return firewall enabled state for Domain, Private, Public profiles.
    Uses registry (fast, no elevation needed).
    """
    profile_keys = {
        "Domain":  _FW_BASE + r"\DomainProfile",
        "Private": _FW_BASE + r"\StandardProfile",
        "Public":  _FW_BASE + r"\PublicProfile",
    }
    results = {}
    for name, subkey in profile_keys.items():
        enabled = _reg_read(winreg.HKEY_LOCAL_MACHINE, subkey, "EnableFirewall", default=None)
        default_in  = _reg_read(winreg.HKEY_LOCAL_MACHINE, subkey, "DefaultInboundAction", default=None)
        default_out = _reg_read(winreg.HKEY_LOCAL_MACHINE, subkey, "DefaultOutboundAction", default=None)
        results[name] = {
            "enabled":         bool(enabled) if enabled is not None else None,
            "default_inbound": "Block" if default_in == 1 else ("Allow" if default_in == 0 else "Unknown"),
            "default_outbound":"Block" if default_out == 1 else ("Allow" if default_out == 0 else "Unknown"),
        }
    return results


def get_firewall_rules_summary() -> dict:
    """
    Slow query — call only on section expand (lazy).
    Returns total rule counts by direction/action.
    """
    ps = (
        "Get-NetFirewallRule | "
        "Group-Object Direction,Action,Enabled | "
        "Select-Object Name,Count | "
        "ConvertTo-Json -Compress"
    )
    ok, output = _run_ps(ps, timeout=30)
    if not ok or not output:
        return {"available": False}
    try:
        rows = json.loads(output)
        if isinstance(rows, dict):
            rows = [rows]
        total = inbound_allow = outbound_allow = disabled = 0
        for r in rows:
            name = str(r.get("Name", ""))
            count = int(r.get("Count", 0))
            total += count
            if "Inbound, Allow" in name and "True" in name:
                inbound_allow += count
            if "Outbound, Allow" in name and "True" in name:
                outbound_allow += count
            if "False" in name:
                disabled += count
        return {
            "available": True,
            "total": total,
            "inbound_allow": inbound_allow,
            "outbound_allow": outbound_allow,
            "disabled": disabled,
        }
    except Exception:
        return {"available": False}


# PID → signature cache to avoid re-checking the same process on every refresh
_sig_cache: dict[int, bool] = {}   # pid → is_signed

def _is_process_signed(path: str) -> bool:
    """Return True if the exe at path has a valid Authenticode signature."""
    if not path:
        return True  # Unknown path → don't flag
    ps = f'(Get-AuthenticodeSignature "{path}").Status -eq "Valid"'
    ok, out = _run_ps(ps, timeout=8)
    return ok and out.strip().lower() == "true"


def get_network_connections(limit: int = 30) -> dict:
    """
    Returns established TCP connections with process attribution.
    Flags connections from unsigned processes to non-local remote IPs.
    Uses PID signature cache to avoid redundant checks.
    """
    ps = (
        "$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess; "
        "$procs = @{}; "
        "Get-Process | ForEach-Object { $procs[$_.Id] = $_.Path }; "
        "$out = $conns | ForEach-Object { "
        "  $pid = $_.OwningProcess; "
        "  $path = $procs[$pid]; "
        "  [PSCustomObject]@{ "
        "    local_port=$_.LocalPort; remote_addr=$_.RemoteAddress; "
        "    remote_port=$_.RemotePort; pid=$pid; process_path=$path "
        "  } "
        f"}} | Select-Object -First {limit}; "
        "$out | ConvertTo-Json -Compress"
    )
    ok, output = _run_ps(ps, timeout=20)
    if not ok or not output:
        return {"available": False, "connections": []}
    try:
        rows = json.loads(output)
        if isinstance(rows, dict):
            rows = [rows]
    except Exception:
        return {"available": False, "connections": []}

    _LOCAL_PREFIXES = ("127.", "::1", "0.", "169.254.", "10.", "192.168.", "172.")

    connections = []
    for r in rows:
        remote = str(r.get("remote_addr", ""))
        pid = int(r.get("pid", 0))
        path = r.get("process_path") or ""
        is_local = any(remote.startswith(p) for p in _LOCAL_PREFIXES)

        flagged = False
        if not is_local and path:
            if pid not in _sig_cache:
                _sig_cache[pid] = _is_process_signed(path)
            flagged = not _sig_cache[pid]

        connections.append({
            "local_port":   r.get("local_port"),
            "remote_addr":  remote,
            "remote_port":  r.get("remote_port"),
            "pid":          pid,
            "process_name": Path(path).name if path else f"PID {pid}",
            "process_path": path,
            "is_local":     is_local,
            "flagged":      flagged,
        })

    flagged_count = sum(1 for c in connections if c["flagged"])
    return {
        "available": True,
        "connections": connections,
        "total": len(connections),
        "flagged": flagged_count,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 2. Device Security
# ─────────────────────────────────────────────────────────────────────────────

def get_device_security() -> dict:
    r"""
    Queries Secure Boot, TPM, and Virtualization-Based Security.

    Registry reads run first for basic on/off state — they work without
    elevation because HKLM\SYSTEM has read access for standard users by default.
    PowerShell queries run additionally when elevated for richer detail (version,
    running services, Credential Guard).  needs_elevation flags are only set when
    BOTH the registry read AND the PowerShell query failed.
    """
    elevated = _is_elevated()
    result: dict[str, Any] = {"elevated": elevated}

    # ── Secure Boot ───────────────────────────────────────────────────────────
    # Registry: HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State
    #           UEFISecureBootEnabled DWORD — 1 = enabled, readable by all users
    sb_reg = _reg_read(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
        "UEFISecureBootEnabled",
    )
    if sb_reg is not None:
        result["secure_boot"] = bool(sb_reg)
    elif elevated:
        ok, out = _run_ps("Confirm-SecureBootUEFI -ErrorAction SilentlyContinue", timeout=10)
        if ok:
            result["secure_boot"] = out.strip().lower() == "true"
        else:
            result["secure_boot"] = None
            result["secure_boot_needs_elevation"] = True
    else:
        result["secure_boot"] = None
        result["secure_boot_needs_elevation"] = True

    # If elevated, also run PowerShell for confirmation (no-op if registry already set)
    if elevated and "secure_boot" in result and sb_reg is not None:
        pass  # registry value is authoritative; skip redundant PS call

    # ── TPM ───────────────────────────────────────────────────────────────────
    # Registry: HKLM\SYSTEM\CurrentControlSet\Services\TPM — key existence
    #           indicates the TPM driver is installed (TPM present)
    tpm_key_present = _reg_key_exists(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\TPM",
    )
    if tpm_key_present:
        result["tpm_present"] = True

    if elevated:
        ps = (
            "Get-Tpm -ErrorAction SilentlyContinue | "
            "Select-Object TpmPresent,TpmReady,ManufacturerId,TpmVersion | "
            "ConvertTo-Json -Compress"
        )
        ok, out = _run_ps(ps, timeout=10)
        parsed = False
        if ok and out:
            try:
                tpm = json.loads(out)
                result["tpm_present"] = bool(tpm.get("TpmPresent"))
                result["tpm_ready"]   = bool(tpm.get("TpmReady"))
                result["tpm_version"] = str(tpm.get("TpmVersion", ""))
                parsed = True
            except Exception:
                pass  # keep registry-derived tpm_present if set
        # A command that succeeded but returned something unparseable used to
        # land in the except above and fall out of this branch entirely, so
        # tpm_present was never assigned -- absent from the dict rather than
        # None. get_security_score() reads it with .get(), so absent charges
        # nothing at all, and a machine whose TPM state could not be read
        # scored exactly like one with a confirmed TPM.
        if not parsed and "tpm_present" not in result:
            result["tpm_present"] = None
            result["tpm_needs_elevation"] = True
    elif "tpm_present" not in result:
        result["tpm_present"] = None
        result["tpm_needs_elevation"] = True

    # ── Device Guard / VBS / Credential Guard ────────────────────────────────
    # Registry: HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard
    #           EnableVirtualizationBasedSecurity DWORD — 1 = enabled
    vbs_reg = _reg_read(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "EnableVirtualizationBasedSecurity",
    )
    if vbs_reg is not None:
        result["vbs_enabled"] = bool(vbs_reg)

    if elevated:
        ps = (
            "Get-CimInstance -ClassName Win32_DeviceGuard "
            "-Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "-ErrorAction SilentlyContinue | "
            "Select-Object VirtualizationBasedSecurityStatus,"
            "SecurityServicesRunning,RequiredSecurityProperties | "
            "ConvertTo-Json -Compress"
        )
        ok, out = _run_ps(ps, timeout=12)
        parsed = False
        if ok and out:
            try:
                dg = json.loads(out)
                vbs = dg.get("VirtualizationBasedSecurityStatus", 0)
                svc = dg.get("SecurityServicesRunning", []) or []
                result["vbs_enabled"]      = vbs == 2   # 2 = running
                result["credential_guard"] = 1 in (svc if isinstance(svc, list) else [svc])
                result["hvci"]             = 2 in (svc if isinstance(svc, list) else [svc])
                parsed = True
            except Exception:
                pass  # keep registry-derived vbs_enabled if set
        # Same shape as the TPM branch above: unparseable-but-successful used
        # to leave vbs_enabled unassigned rather than None, which scores as
        # though VBS were confirmed running.
        if not parsed and "vbs_enabled" not in result:
            result["vbs_enabled"] = None
            result["vbs_needs_elevation"] = True
    elif "vbs_enabled" not in result:
        result["vbs_enabled"] = None
        result["vbs_needs_elevation"] = True

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 3. Account Protection
# ─────────────────────────────────────────────────────────────────────────────

def get_local_accounts() -> dict:
    """
    List local user accounts with security-relevant properties.
    Flags admin accounts without recent logon or without password requirement.
    """
    ps = (
        "Get-LocalUser | Select-Object Name,Enabled,LastLogon,"
        "PasswordRequired,PasswordExpires,UserMayChangePassword | "
        "ConvertTo-Json -Compress"
    )
    ok, output = _run_ps(ps, timeout=15)
    if not ok or not output:
        return {"available": False, "accounts": []}
    try:
        rows = json.loads(output)
        if isinstance(rows, dict):
            rows = [rows]
    except Exception:
        return {"available": False, "accounts": []}

    # Determine which accounts are in Administrators group
    ok2, admins_out = _run_ps(
        "Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | "
        "Select-Object Name | ConvertTo-Json -Compress",
        timeout=12
    )
    admin_names: set[str] = set()
    if ok2 and admins_out:
        try:
            admins = json.loads(admins_out)
            if isinstance(admins, dict):
                admins = [admins]
            for a in admins:
                name = str(a.get("Name", ""))
                if "\\" in name:
                    name = name.split("\\")[-1]
                admin_names.add(name.lower())
        except Exception:
            pass

    accounts = []
    for r in rows:
        name = str(r.get("Name", ""))
        enabled = bool(r.get("Enabled", False))
        is_admin = name.lower() in admin_names
        pwd_required = bool(r.get("PasswordRequired", True))
        last_logon_raw = r.get("LastLogon")

        last_logon_str = "Never"
        stale = False
        if last_logon_raw:
            try:
                if "/Date(" in str(last_logon_raw):
                    ms = int(str(last_logon_raw).split("(")[1].split(")")[0])
                    dt = datetime.fromtimestamp(ms / 1000)
                    last_logon_str = dt.strftime("%Y-%m-%d")
                    stale = (datetime.now() - dt).days > 90
            except Exception:
                pass

        risk = []
        if is_admin and not pwd_required:
            risk.append("Admin without password")
        if is_admin and enabled and stale:
            risk.append("Admin — no login in 90+ days")

        accounts.append({
            "name": name,
            "enabled": enabled,
            "is_admin": is_admin,
            "password_required": pwd_required,
            "last_logon": last_logon_str,
            "risk": risk,
        })

    flagged = [a for a in accounts if a["risk"]]
    return {
        "available": True,
        "accounts": accounts,
        "admin_count": len([a for a in accounts if a["is_admin"] and a["enabled"]]),
        "flagged_count": len(flagged),
    }


def get_account_policy() -> dict:
    """
    Read account lockout policy via 'net accounts' (no elevation needed).
    """
    try:
        result = subprocess.run(
            ["net", "accounts"],
            capture_output=True, text=True, timeout=8,
            creationflags=_NO_WINDOW,
        )
        lines = result.stdout.strip().splitlines()
        policy: dict[str, Any] = {"available": True}
        for line in lines:
            if "Lockout threshold" in line:
                val = line.split(":")[-1].strip()
                policy["lockout_threshold"] = 0 if val.lower() == "never" else _safe_int(val)
            elif "Lockout duration" in line and "observation" not in line.lower():
                val = line.split(":")[-1].strip()
                policy["lockout_duration_min"] = _safe_int(val)
            elif "Lockout observation" in line:
                val = line.split(":")[-1].strip()
                policy["lockout_reset_min"] = _safe_int(val)
        return policy
    except Exception:
        return {"available": False}


def _safe_int(s: str, default: int = 0) -> int:
    try:
        return int(s)
    except (ValueError, TypeError):
        return default


# ─────────────────────────────────────────────────────────────────────────────
# 4. App & Browser Control
# ─────────────────────────────────────────────────────────────────────────────

_WD_EXPLOIT = r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard"

def get_app_browser_control() -> dict:
    """
    Read SmartScreen, Controlled Folder Access, and ASR rules.
    Registry-first for simple toggles; PowerShell for ASR rule details.
    """
    # SmartScreen — check policy key first, then user-facing key
    ss_policy = _reg_read(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\System",
        "EnableSmartScreen"
    )
    ss_explorer = _reg_read(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "SmartScreenEnabled"
    )
    if ss_policy is not None:
        smartscreen_on = bool(ss_policy)
        smartscreen_source = "policy"
    elif ss_explorer is not None:
        smartscreen_on = (str(ss_explorer).lower() != "off")
        smartscreen_source = "user"
    else:
        smartscreen_on = True   # Windows default is ON
        smartscreen_source = "default"

    # Controlled Folder Access
    cfa_val = _reg_read(
        winreg.HKEY_LOCAL_MACHINE,
        _WD_EXPLOIT + r"\Controlled Folder Access",
        "EnableControlledFolderAccess",
        default=0,
    )
    # 0=off, 1=enabled, 2=audit mode
    cfa_enabled = cfa_val == 1
    cfa_audit   = cfa_val == 2

    # ASR rules via PowerShell
    asr_rules: list[dict] = []
    ok, out = _run_ps(
        "Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids,"
        "AttackSurfaceReductionRules_Actions | ConvertTo-Json -Compress",
        timeout=15,
    )
    if ok and out:
        try:
            pref = json.loads(out)
            ids  = pref.get("AttackSurfaceReductionRules_Ids") or []
            acts = pref.get("AttackSurfaceReductionRules_Actions") or []
            if isinstance(ids, str):
                ids = [ids]
            if isinstance(acts, (int, str)):
                acts = [acts]
            for rule_id, action in zip(ids, acts):
                rule_id_up = str(rule_id).upper()
                cat, desc = _ASR_CATEGORIES.get(rule_id_up, ("Other", str(rule_id)))
                asr_rules.append({
                    "id": rule_id,
                    "category": cat,
                    "description": desc,
                    "action": _asr_action(int(action)),
                    "enabled": int(action) == 1,
                })
        except Exception:
            pass

    # Group by category
    categories: dict[str, list] = {}
    for rule in asr_rules:
        categories.setdefault(rule["category"], []).append(rule)

    return {
        "smartscreen_on":      smartscreen_on,
        "smartscreen_source":  smartscreen_source,
        "cfa_enabled":         cfa_enabled,
        "cfa_audit":           cfa_audit,
        "asr_rules":           asr_rules,
        "asr_active_count":    sum(1 for r in asr_rules if r["enabled"]),
        "asr_categories":      categories,
    }


def _asr_action(val: int) -> str:
    return {0: "Disabled", 1: "Block", 2: "Audit", 6: "Warn"}.get(val, f"Mode {val}")


# ─────────────────────────────────────────────────────────────────────────────
# 5. System Health (security-relevant)
# ─────────────────────────────────────────────────────────────────────────────

def get_system_health() -> dict:
    """
    Returns uptime, pending reboot flag, recent security patches, driver errors.
    Mix of registry (fast) and WMI/PowerShell for richer data.
    """
    # Pending reboot — registry key existence check
    pending_reboot = _reg_key_exists(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    )

    # System uptime via WMI
    uptime_days: int | None = None
    ok, out = _run_ps(
        "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime | "
        "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'",
        timeout=10,
    )
    if ok and out:
        try:
            boot_dt = datetime.strptime(out.strip(), "%Y-%m-%d %H:%M:%S")
            uptime_days = (datetime.now() - boot_dt).days
        except Exception:
            pass

    # Recent security patches (last 5 KB articles)
    recent_patches: list[dict] = []
    ok, out = _run_ps(
        "Get-CimInstance Win32_QuickFixEngineering | "
        "Sort-Object InstalledOn -Descending | "
        "Select-Object -First 5 HotFixID,InstalledOn | "
        "ConvertTo-Json -Compress",
        timeout=15,
    )
    if ok and out:
        try:
            patches = json.loads(out)
            if isinstance(patches, dict):
                patches = [patches]
            for p in patches:
                installed = p.get("InstalledOn")
                date_str = ""
                if installed:
                    try:
                        if "/Date(" in str(installed):
                            ms = int(str(installed).split("(")[1].split(")")[0])
                            date_str = datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d")
                        else:
                            date_str = str(installed)[:10]
                    except Exception:
                        pass
                recent_patches.append({"kb": p.get("HotFixID", ""), "installed_on": date_str})
        except Exception:
            pass

    # Driver errors
    driver_errors = 0
    ok, out = _run_ps(
        "(Get-PnpDevice | Where-Object Status -ne 'OK' -ErrorAction SilentlyContinue | Measure-Object).Count",
        timeout=12,
    )
    if ok and out:
        driver_errors = _safe_int(out.strip())

    return {
        "uptime_days":     uptime_days,
        "pending_reboot":  pending_reboot,
        "recent_patches":  recent_patches,
        "driver_errors":   driver_errors,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 6. Security Score
# ─────────────────────────────────────────────────────────────────────────────

def get_security_score(
    defender_status: dict | None = None,
    firewall_profiles: dict | None = None,
    device_sec: dict | None = None,
    account_data: dict | None = None,
    app_control: dict | None = None,
    sys_health: dict | None = None,
) -> dict:
    """
    Compute a 0–100 composite security score with per-category breakdown.
    All arguments are pre-fetched data dicts (so callers can reuse data).

    Passing None fetches live — **except for defender_status**, which is never
    fetched here. None for that one falls through to the unavailable branch and
    forfeits the full 25 points with the issue "Defender status unavailable".
    Both callers (dashboard_view._load and fetch_overview_async) pass it
    explicitly, so nothing scores wrong today; the asymmetry is pinned by
    test_security_score.py rather than changed, because fetching it here would
    be a behaviour change and not a documentation fix.

    Not quite pure even with all six supplied: the Account Security branch
    calls get_account_policy() live.

    Weights: Defender 25, Firewall 20, Device Security 20, Account Security 15,
    App & Browser Control 15, System Health 5. Each floors at 0 rather than
    going negative — two categories carry more penalty than they have points.
    """
    if firewall_profiles is None:
        firewall_profiles = get_firewall_profiles()
    if device_sec is None:
        device_sec = get_device_security()
    if account_data is None:
        account_data = get_local_accounts()
    if app_control is None:
        app_control = get_app_browser_control()
    if sys_health is None:
        sys_health = get_system_health()

    breakdown: dict[str, dict] = {}
    total_score = 0

    # ── Defender (25 pts) ─────────────────────────────────────────────────────
    dfn_score = 25
    dfn_issues: list[str] = []
    if defender_status and defender_status.get("available"):
        if not defender_status.get("RealTimeProtectionEnabled"):
            dfn_score -= 15
            dfn_issues.append("Real-time protection is OFF")
        if not defender_status.get("AntivirusEnabled"):
            dfn_score -= 10
            dfn_issues.append("Antivirus is disabled")
        sig_age = _safe_int(str(defender_status.get("AntivirusSignatureAge", 0)))
        if sig_age > 7:
            dfn_score -= 5
            dfn_issues.append(f"Signatures {sig_age}d old (>7d)")
    else:
        dfn_score = 0
        dfn_issues.append("Defender status unavailable")
    breakdown["Defender"] = {"score": max(0, dfn_score), "max": 25, "issues": dfn_issues}
    total_score += max(0, dfn_score)

    # ── Firewall (20 pts) ─────────────────────────────────────────────────────
    fw_score = 20
    fw_issues: list[str] = []
    for profile, state in firewall_profiles.items():
        if state.get("enabled") is False:
            fw_score -= 7
            fw_issues.append(f"{profile} firewall profile is OFF")
        elif state.get("enabled") is None:
            fw_score -= 2
            fw_issues.append(f"{profile} firewall state unknown")
    breakdown["Firewall"] = {"score": max(0, fw_score), "max": 20, "issues": fw_issues}
    total_score += max(0, fw_score)

    # ── Device Security (20 pts) ──────────────────────────────────────────────
    dv_score = 20
    dv_issues: list[str] = []
    if device_sec.get("secure_boot") is False:
        dv_score -= 7
        dv_issues.append("Secure Boot is disabled")
    elif device_sec.get("secure_boot_needs_elevation"):
        dv_score -= 3
        dv_issues.append("Secure Boot status unknown (requires admin)")
    if device_sec.get("tpm_present") is False:
        dv_score -= 7
        dv_issues.append("TPM not present")
    elif device_sec.get("tpm_needs_elevation"):
        dv_score -= 3
        dv_issues.append("TPM status unknown (requires admin)")
    if device_sec.get("vbs_enabled") is False:
        dv_score -= 6
        dv_issues.append("Virtualization-Based Security is off")
    elif device_sec.get("vbs_needs_elevation"):
        dv_score -= 2
        dv_issues.append("VBS status unknown (requires admin)")
    breakdown["Device Security"] = {"score": max(0, dv_score), "max": 20, "issues": dv_issues}
    total_score += max(0, dv_score)

    # ── Account Security (15 pts) ─────────────────────────────────────────────
    acc_score = 15
    acc_issues: list[str] = []
    if account_data.get("available"):
        flagged = account_data.get("flagged_count", 0)
        if flagged:
            acc_score -= min(10, flagged * 5)
            acc_issues.append(f"{flagged} account(s) with security risks")
        policy = get_account_policy()
        if policy.get("available"):
            threshold = policy.get("lockout_threshold", 0)
            if threshold == 0:
                acc_score -= 5
                acc_issues.append("Account lockout is not configured")
            elif threshold > 10:
                acc_score -= 2
                acc_issues.append(f"Lockout threshold is high ({threshold} attempts)")
    else:
        acc_score -= 5
        acc_issues.append("Account data unavailable")
    breakdown["Account Security"] = {"score": max(0, acc_score), "max": 15, "issues": acc_issues}
    total_score += max(0, acc_score)

    # ── App & Browser Control (15 pts) ────────────────────────────────────────
    app_score = 15
    app_issues: list[str] = []
    if not app_control.get("smartscreen_on", True):
        app_score -= 7
        app_issues.append("SmartScreen is disabled")
    if not app_control.get("cfa_enabled") and not app_control.get("cfa_audit"):
        app_score -= 5
        app_issues.append("Controlled Folder Access is off")
    elif app_control.get("cfa_audit"):
        app_score -= 2
        app_issues.append("Controlled Folder Access is in audit mode (not blocking)")
    asr_active = app_control.get("asr_active_count", 0)
    if asr_active == 0:
        app_score -= 3
        app_issues.append("No Attack Surface Reduction rules are active")
    breakdown["App & Browser Control"] = {"score": max(0, app_score), "max": 15, "issues": app_issues}
    total_score += max(0, app_score)

    # ── System Health (5 pts) ─────────────────────────────────────────────────
    hlth_score = 5
    hlth_issues: list[str] = []
    if sys_health.get("pending_reboot"):
        hlth_score -= 3
        hlth_issues.append("System restart pending (security patches waiting)")
    uptime = sys_health.get("uptime_days")
    if uptime is not None and uptime > 30:
        hlth_score -= 2
        hlth_issues.append(f"System uptime {uptime}d (reboot to apply patches)")
    if sys_health.get("driver_errors", 0) > 0:
        hlth_score -= 1
        hlth_issues.append(f"{sys_health['driver_errors']} driver(s) in error state")
    breakdown["System Health"] = {"score": max(0, hlth_score), "max": 5, "issues": hlth_issues}
    total_score += max(0, hlth_score)

    # Overall label
    if total_score >= 90:
        label = "Excellent"
    elif total_score >= 75:
        label = "Good"
    elif total_score >= 55:
        label = "Fair"
    else:
        label = "At Risk"

    # Collect all issues sorted by weight impact
    all_issues = [
        issue for cat in breakdown.values() for issue in cat["issues"]
    ]

    return {
        "score": total_score,
        "label": label,
        "breakdown": breakdown,
        "top_issue": all_issues[0] if all_issues else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Async wrappers
# ─────────────────────────────────────────────────────────────────────────────

def fetch_overview_async(defender_status: dict, callback):
    """
    Fetch lightweight overview data (registry-only) in a thread.
    callback(data: dict)
    """
    def _run():
        data = {
            "firewall":    get_firewall_profiles(),
            "app_control": get_app_browser_control(),
            "health":      {"pending_reboot": _reg_key_exists(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
            )},
        }
        data["score"] = get_security_score(
            defender_status=defender_status,
            firewall_profiles=data["firewall"],
            app_control=data["app_control"],
        )
        callback(data)
    threading.Thread(target=_run, daemon=True).start()


def fetch_detail_async(section: str, callback):
    """
    Fetch expensive detail data for a specific section on demand.
    section: 'firewall_rules' | 'network' | 'device' | 'accounts' | 'health'
    callback(data: dict)
    """
    def _run():
        if section == "firewall_rules":
            data = get_firewall_rules_summary()
        elif section == "network":
            data = get_network_connections()
        elif section == "device":
            data = get_device_security()
        elif section == "accounts":
            data = {
                "accounts": get_local_accounts(),
                "policy":   get_account_policy(),
            }
        elif section == "health":
            data = get_system_health()
        else:
            data = {}
        callback(data)
    threading.Thread(target=_run, daemon=True).start()
