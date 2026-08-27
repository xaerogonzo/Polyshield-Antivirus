import os
import winreg
from pathlib import Path

_RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     "HKCU"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     "HKLM"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
     "HKLM (32-bit)"),
]

_STARTUP_FOLDERS = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
]


def enumerate_startup_items() -> list[dict]:
    """
    Return all startup entries from registry run keys and startup folders.
    Each entry: {name, raw_value, resolved_path, source, exists}
    """
    items = []

    # Registry run keys
    for hive, key_path, hive_label in _RUN_KEYS:
        try:
            with winreg.OpenKey(hive, key_path,
                                access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        resolved = _extract_path(str(value))
                        items.append({
                            "name": name,
                            "raw_value": str(value),
                            "resolved_path": resolved,
                            "source": f"Registry: {hive_label}\\...\\Run",
                            "exists": Path(resolved).exists() if resolved else False,
                        })
                        i += 1
                    except OSError:
                        break
        except OSError:
            pass

    # Startup folders
    for folder in _STARTUP_FOLDERS:
        if not os.path.isdir(folder):
            continue
        short_folder = folder.split("\\Programs\\")[1] if "\\Programs\\" in folder else folder
        for fname in os.listdir(folder):
            full = os.path.join(folder, fname)
            items.append({
                "name": fname,
                "raw_value": full,
                "resolved_path": full,
                "source": f"Startup folder ({short_folder})",
                "exists": os.path.exists(full),
            })

    return items


def get_scannable_paths(items: list[dict]) -> list[str]:
    """Extract unique, existing file paths from startup items for scanning."""
    seen = set()
    paths = []
    for item in items:
        p = item.get("resolved_path", "")
        if p and p not in seen and Path(p).is_file():
            seen.add(p)
            paths.append(p)
    return paths


# Extensions a Run key can launch directly through ShellExecute.  Used only to
# find where the executable ends and its arguments begin.
_EXE_SUFFIXES = (".exe", ".com", ".bat", ".cmd", ".scr", ".pif")


def _extract_path(value: str) -> str:
    r"""
    Pull a file path out of a registry value string.
    Values can be bare paths, quoted paths, or paths with arguments.

    Every mistake here has the same consequence, and it is a quiet one: the
    resolved path fails Path.exists(), the entry is dropped by
    get_scannable_paths(), and a startup executable is simply never scanned.
    Autoruns are where persistence lives, so a miss is not cosmetic.

    Three ways the previous form produced a wrong path:

      * `v.split(".exe", 1)` was case-sensitive.  Registry values preserve the
        case the installer wrote, and `.EXE` is common, so
        `C:\Program Files\App\app.EXE --flag` fell through to the
        first-token fallback and resolved to `C:\Program`.
      * It split on the first *substring* match rather than at a token
        boundary, so `C:\my.exe.tools\app.exe` resolved to `C:\my.exe`.
      * Environment variables were never expanded, so a perfectly ordinary
        `%ProgramFiles%\App\app.exe` never resolved to anything at all.
    """
    # Expand first: a quoted value can contain variables too.  expandvars
    # leaves an unknown %VAR% untouched, which resolves to "does not exist" --
    # the same outcome as before, so nothing regresses on a name we cannot map.
    v = os.path.expandvars(value.strip())
    if not v:
        return ""

    if v.startswith('"'):
        end = v.find('"', 1)
        return v[1:end] if end > 1 else v[1:]

    # Find the earliest executable extension that actually ENDS a token, so a
    # directory named "my.exe.tools" cannot be mistaken for the target.
    low = v.lower()
    cut = -1
    for suffix in _EXE_SUFFIXES:
        start = 0
        while True:
            idx = low.find(suffix, start)
            if idx == -1:
                break
            end = idx + len(suffix)
            if end == len(v) or v[end].isspace():
                if cut == -1 or end < cut:
                    cut = end
                break
            start = idx + 1          # a substring match; keep looking
    if cut != -1:
        return v[:cut].strip()

    # No recognisable extension — first whitespace-delimited token, as before.
    parts = v.split()
    return parts[0] if parts else ""
