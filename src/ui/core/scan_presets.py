import os
import subprocess
from pathlib import Path

_NO_WINDOW = subprocess.CREATE_NO_WINDOW

from ui.core import startup_scanner as ss

PRESETS = ["Custom", "Smart", "Quick", "Full", "Downloads", "Temp"]


def resolve(preset: str) -> tuple[list[str], str]:
    """
    Return (paths, description) for a named preset.
    Paths are deduplicated and guaranteed to exist on disk.
    """
    if preset == "Smart":
        return _smart()
    if preset == "Quick":
        return _quick()
    if preset == "Full":
        return _full()
    if preset == "Downloads":
        return _downloads()
    if preset == "Temp":
        return _temp()
    # Custom — caller supplies paths manually
    return [], "Drop files or folders here"


# ── Preset resolvers ──────────────────────────────────────────────────────────

def _smart() -> tuple[list[str], str]:
    paths = []

    # 1. Running process executables (malware runs as a process)
    paths += get_running_process_paths()

    # 2. Startup items: registry Run/RunOnce + startup folder shortcuts
    startup_items = ss.enumerate_startup_items()
    paths += ss.get_scannable_paths(startup_items)

    # 3. Temp folders (most malware's first drop point)
    paths += _expand_dirs([
        r"%TEMP%",
        r"%LOCALAPPDATA%\Temp",
        r"C:\Windows\Temp",
    ])

    # 4. Downloads (user-initiated installs land here)
    paths += _expand_dirs([r"%USERPROFILE%\Downloads"])

    # 5. Targeted AppData high-risk locations
    #    Replaces the old broad %APPDATA% / %LOCALAPPDATA% pass which caused
    #    full scans of Python venvs, pip caches, npm modules, etc.
    #    These specific subdirs are where malware actually hides:
    paths += _expand_dirs([
        # Browser extensions — primary home of adware, hijackers, cryptominers
        r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions",
        r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions",
        r"%APPDATA%\Mozilla\Firefox\Profiles",   # all FF profiles
        r"%APPDATA%\Mozilla\Extensions",
        # User-scoped app installs (winget / MSIX — malware poses as legitimate apps)
        r"%LOCALAPPDATA%\Programs",
        # PowerShell profile scripts — common dropper / persistence target
        r"%USERPROFILE%\Documents\WindowsPowerShell",
        r"%USERPROFILE%\Documents\PowerShell",
        # Windows execution alias shims (fake .exe placed here intercepts commands)
        r"%LOCALAPPDATA%\Microsoft\WindowsApps",
    ])

    unique = _dedup(paths)
    desc = f"Smart Scan — {len(unique)} target(s) across processes, startup & risk locations"
    return unique, desc


def _quick() -> tuple[list[str], str]:
    startup_items = ss.enumerate_startup_items()
    startup_paths = ss.get_scannable_paths(startup_items)

    dirs = _expand_dirs([
        r"%TEMP%",
        r"%LOCALAPPDATA%\Temp",
        r"%USERPROFILE%\Downloads",
    ])

    unique = _dedup(startup_paths + dirs)
    desc = f"Quick Scan — {len(unique)} target(s) across startup items & temp folders"
    return unique, desc


def _full() -> tuple[list[str], str]:
    profile = str(Path.home())
    desc = f"Full Scan — {profile}"
    return [profile], desc


def _downloads() -> tuple[list[str], str]:
    path = os.path.expandvars(r"%USERPROFILE%\Downloads")
    if Path(path).is_dir():
        return [path], f"Downloads Scan — {path}"
    return [], "Downloads folder not found"


def _temp() -> tuple[list[str], str]:
    dirs = _expand_dirs([
        r"%TEMP%",
        r"%LOCALAPPDATA%\Temp",
        r"C:\Windows\Temp",
    ])
    desc = f"Temp Scan — {len(dirs)} temp folder(s)"
    return dirs, desc


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_running_process_paths() -> list[str]:
    """
    Return unique executable paths of all running processes via PowerShell.
    Silently returns [] on any failure.
    """
    ps = (
        "Get-Process | Where-Object {$_.Path} "
        "| Select-Object -ExpandProperty Path "
        "| Sort-Object -Unique"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, text=True, timeout=10,
            creationflags=_NO_WINDOW,
        )
        if result.returncode != 0:
            return []
        paths = []
        for line in result.stdout.splitlines():
            p = line.strip()
            if p and Path(p).is_file():
                paths.append(p)
        return paths
    except Exception:
        return []


def _expand_dirs(raw: list[str]) -> list[str]:
    """Expand env vars, return only existing directories."""
    dirs = []
    for r in raw:
        expanded = os.path.expandvars(r)
        if Path(expanded).is_dir():
            dirs.append(expanded)
    return dirs


def _dedup(paths: list[str]) -> list[str]:
    seen, out = set(), []
    for p in paths:
        key = p.lower()
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out
