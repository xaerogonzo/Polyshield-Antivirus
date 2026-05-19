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


def _extract_path(value: str) -> str:
    """
    Pull a file path out of a registry value string.
    Values can be bare paths, quoted paths, or paths with arguments.
    """
    v = value.strip()
    if v.startswith('"'):
        end = v.find('"', 1)
        return v[1:end] if end > 1 else v.strip('"')
    # Try to find where arguments start
    parts = v.split(".exe", 1)
    if len(parts) == 2:
        return (parts[0] + ".exe").strip()
    # Fallback: take first token
    return v.split()[0] if v else ""
