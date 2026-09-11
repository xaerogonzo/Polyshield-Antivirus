r"""dev_install.py — the Add/Remove Programs entry for a source installation.

    HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\PolyShield

Third of the three modules that write PolyShield into a user's registry, and
built like the other two (``shell_ext.py``, ``autostart.py``): ``(ok, message)``
returns, absent-is-success on removal, and nothing that raises out of
``is_registered()``.

HKCU rather than HKLM.  It needs no elevation and it shows up in Settings > Apps
for the person who actually installed it, which is the right scope for something
registered against one user's checkout.

Two things here are load-bearing and easy to "tidy" into a bug:

**The DisplayName says "(development install)".**  This entry's Uninstall button
removes *registrations*: the service, the Explorer verb, the login entry, the
scheduled task and this key.  It does not remove the checkout, and it must not --
somebody is working in it.  A user who finds "PolyShield Security Suite" in
Settings > Apps and expects the folder to disappear has been misled by us.

**The UninstallString points at a self-elevating batch file, not at
``app.py --unregister``.**  Windows launches an uninstall string *unelevated*.
The first teardown step is the Windows service, which needs elevation -- so
without the wrapper, uninstalling from Settings would clear the HKCU entries,
fail on the service, write the partial result into a log nobody reads, and show
success in the Apps list.  Elevation belongs in the one wrapper Windows invokes;
plain ``--unregister`` keeps ordinary command-line semantics and never springs a
consent prompt on a script that did not ask for one.

Not written for a packaged build: Inno registers the real entry under its own
AppId, and two entries for one product is worse than none.
"""
from __future__ import annotations

import winreg

from ui.core import paths
from ui.version import __version__

_HKCU = winreg.HKEY_CURRENT_USER

_UNINSTALL_KEY = (
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall\PolyShield")

_DISPLAY_NAME = "PolyShield Security Suite (development install)"
_PUBLISHER = "Alexander L Corthell"

#: The script Windows runs for "Uninstall". Self-elevating; see the module
#: docstring for why it is not `app.py --unregister`.
_UNINSTALLER = ("scripts", "uninstall_dev.bat")


def uninstaller_path():
    """Where the self-elevating uninstaller lives, in this installation."""
    return paths.install_root().joinpath(*_UNINSTALLER)


def _uninstall_string() -> str:
    return f'"{uninstaller_path()}"'


def register() -> tuple[bool, str]:
    """Write the Add/Remove Programs entry. Idempotent.

    A no-op in a distribution, reported as success: Inno owns that entry, and
    a caller running the shared registration path in a packaged build has not
    done anything wrong.
    """
    if paths.is_distribution():
        return True, "packaged builds register their own uninstall entry"

    target = uninstaller_path()
    if not target.is_file():
        # Reported rather than written. An Apps & Features entry whose Uninstall
        # button runs a file that is not there is worse than no entry: the user
        # cannot remove it from the list either.
        return False, f"no uninstaller at {target}"

    values = {
        "DisplayName": _DISPLAY_NAME,
        "DisplayVersion": __version__,
        "Publisher": _PUBLISHER,
        "InstallLocation": str(paths.install_root()),
        "UninstallString": _uninstall_string(),
        "QuietUninstallString": _uninstall_string() + " /quiet",
    }
    # No DisplayIcon. There is no .ico in the checkout outside the virtualenvs,
    # and pointing it at pythonw.exe would put a Python logo next to PolyShield
    # in the user's app list -- worse than the generic one Windows supplies.
    try:
        with winreg.CreateKey(_HKCU, _UNINSTALL_KEY) as key:
            for name, value in values.items():
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            for name in ("NoModify", "NoRepair"):
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, 1)
        return True, "listed in Settings > Apps"
    except Exception as exc:
        return False, f"could not write the uninstall entry: {exc}"


def unregister() -> tuple[bool, str]:
    """Remove the entry. Already-absent is success.

    The whole key, unlike ``autostart``: this one is ours, created by us, and
    holds nothing else.
    """
    try:
        winreg.DeleteKey(_HKCU, _UNINSTALL_KEY)
        return True, "uninstall entry removed"
    except FileNotFoundError:
        return True, "no uninstall entry was registered"
    except OSError as exc:
        return False, f"could not remove the uninstall entry: {exc}"


def current_uninstall_string() -> str | None:
    """The UninstallString as it stands, or None if the entry is not there."""
    try:
        with winreg.OpenKey(_HKCU, _UNINSTALL_KEY) as key:
            value, _type = winreg.QueryValueEx(key, "UninstallString")
            return str(value)
    except OSError:
        return None


def is_registered() -> bool:
    """True if the entry exists. Every read failure reads as absent."""
    return current_uninstall_string() is not None


def is_current() -> bool:
    """True if the Uninstall button still runs a script that exists here.

    The same absolute-path problem ``autostart.is_current`` exists for, with a
    worse ending: a moved checkout leaves an entry in Settings > Apps whose
    Uninstall button does nothing at all, and Windows offers no way to clear it.
    Paired with the repair path so the answer is actionable rather than just
    true.
    """
    current = current_uninstall_string()
    if current is None:
        return False
    return current == _uninstall_string() and uninstaller_path().is_file()
