"""
shell_ext.py — Windows Explorer context-menu integration (HKCU, no admin required).

Registers "Scan with PolyShield" on files, folders, and drives using:
  HKCU\Software\Classes\*\shell\PolyShield\
  HKCU\Software\Classes\Directory\shell\PolyShield\
  HKCU\Software\Classes\Drive\shell\PolyShield\
"""
import sys
import winreg
from pathlib import Path

_MENU_LABEL = "Scan with PolyShield"
_ROOTS = ("*", "Directory", "Drive")
_HKCU = winreg.HKEY_CURRENT_USER


def _get_command() -> str:
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    app_py = Path(__file__).resolve().parents[3] / "src" / "ui" / "app.py"
    return f'"{pythonw}" "{app_py}" "--scan" "%1"'


def _shell_key(root: str) -> str:
    return rf"Software\Classes\{root}\shell\PolyShield"


def _old_shell_key(root: str) -> str:
    return rf"Software\Classes\{root}\shell\KicomAV"


def _remove_old_keys():
    """Remove legacy KicomAV context-menu keys if they exist (one-time migration)."""
    for root in _ROOTS:
        old_base = _old_shell_key(root)
        for sub in (old_base + r"\command", old_base):
            try:
                winreg.DeleteKey(_HKCU, sub)
            except FileNotFoundError:
                pass
            except Exception:
                pass


def register() -> tuple[bool, str]:
    """Write context-menu entries for files, folders, and drives.
    Also removes any legacy KicomAV entries from a previous installation."""
    _remove_old_keys()
    cmd = _get_command()
    try:
        for root in _ROOTS:
            key_path = _shell_key(root)
            with winreg.CreateKey(_HKCU, key_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, _MENU_LABEL)
                winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ,
                                  str(Path(sys.executable)))
            with winreg.CreateKey(_HKCU, key_path + r"\command") as cmd_key:
                winreg.SetValueEx(cmd_key, "", 0, winreg.REG_SZ, cmd)
        return True, "Context menu registered successfully."
    except Exception as exc:
        return False, f"Registration failed: {exc}"


def unregister() -> tuple[bool, str]:
    """Remove context-menu entries."""
    errors = []
    for root in _ROOTS:
        base = _shell_key(root)
        for sub in (base + r"\command", base):
            try:
                winreg.DeleteKey(_HKCU, sub)
            except FileNotFoundError:
                pass
            except Exception as exc:
                errors.append(str(exc))
    if errors:
        return False, "; ".join(errors)
    return True, "Context menu removed."


def is_registered() -> bool:
    """Return True if the *\shell\PolyShield key exists in HKCU."""
    try:
        with winreg.OpenKey(_HKCU, _shell_key("*")):
            return True
    except FileNotFoundError:
        return False
