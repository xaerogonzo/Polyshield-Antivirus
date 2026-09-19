r"""autostart.py — the per-user login entry, in HKCU.

    HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PolyShield

Modelled on ``shell_ext.py`` on purpose: same ``(ok, message)`` returns, same
"absent is success" on removal, same refusal to raise out of ``is_registered()``.
The two are the only places PolyShield writes itself into a user's registry, and
they should read the same.

**Chosen over a Startup-folder shortcut and over a per-user scheduled task.**
The task is the only one of the three that can start elevated without a prompt,
which looks attractive next to the existing ``launch_as_admin`` setting -- but
PolyShield already has the right answer to "privileged work at boot", and it is
``PolyShieldService``.  The GUI is a tray client over an IPC socket; giving it
silent permanent elevation buys nothing the service does not already do, and
costs the user the ability to turn it off from Task Manager, which is where
people look.  A shortcut would mean the teardown step is a file deletion, which
``integration.py`` deliberately does not do.

Consequence worth saying out loud in the UI: with ``start_with_windows`` and
``launch_as_admin`` both on, **the login launch is not elevated**.  Only a
manual launch is.

Nothing here needs administrator rights.
"""
from __future__ import annotations

import winreg

from ui.core import paths

_HKCU = winreg.HKEY_CURRENT_USER

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_VALUE_NAME = "PolyShield"

#: Where Task Manager records the user switching a startup entry off.  It does
#: NOT delete the Run value when it does that, so the Run value alone cannot
#: answer "will this actually launch".
_APPROVED_KEY = (
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")

#: Bit 0 of the first byte.  **Measured, not assumed** -- an earlier draft of
#: this module had it as bit 1, which is the value most often repeated online.
#: Dumped from a live machine, where Discord and Voicemod had been switched off
#: in Task Manager and the rest had not::
#:
#:     OneDrive        02 00 00 00 00 00 00 00 00 00 00 00   enabled
#:     Steam           02 00 00 00 00 00 00 00 00 00 00 00   enabled
#:     SecurityHealth  06 00 00 00 00 00 00 00 00 00 00 00   enabled  (HKLM)
#:     Discord         03 00 00 00 d4 37 9b 21 e2 9e dc 01   DISABLED
#:     VoicemodV3      03 00 00 00 b4 9b 0a d0 ab e4 dc 01   DISABLED
#:
#: Two independent signals agree: bit 0 is set exactly for the disabled pair,
#: and the trailing eight bytes are a FILETIME recording when that happened,
#: zero for everything still enabled.
_DISABLED_BIT = 0x01

#: The three answers `startup_approval` gives.
ENABLED = "enabled"
DISABLED = "disabled"
UNKNOWN = "unknown"


def _get_command() -> str:
    r"""The command line Windows runs at login.

    ``--minimized`` is not decoration: without it the login launch opens a
    1200x760 window over whatever the user was about to do, every single time.

    Built from ``paths.app_launch_argv`` rather than from ``sys.executable``,
    for the reason ``shell_ext._get_command`` gives -- a Nuitka build reports an
    interpreter beside the real binary that does not exist, and this value has
    to still be valid months from now.  Every argument is quoted so an install
    directory containing spaces, an ampersand or parentheses still yields one
    parseable command line.
    """
    return " ".join(f'"{a}"' for a in paths.app_launch_argv("--minimized"))


def register() -> tuple[bool, str]:
    """Write the login entry. Idempotent -- re-registering refreshes the path."""
    try:
        with winreg.CreateKey(_HKCU, _RUN_KEY) as key:
            winreg.SetValueEx(key, _VALUE_NAME, 0, winreg.REG_SZ, _get_command())
        return True, "PolyShield will start when you sign in."
    except Exception as exc:
        return False, f"Could not add the startup entry: {exc}"


def unregister() -> tuple[bool, str]:
    """Remove the login entry. Already-absent is success.

    The value, not the key: ``...\\CurrentVersion\\Run`` belongs to Windows and
    holds every other application's entry.
    """
    try:
        with winreg.OpenKey(_HKCU, _RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, _VALUE_NAME)
        return True, "startup entry removed"
    except FileNotFoundError:
        return True, "no startup entry was registered"
    except OSError as exc:
        return False, f"could not remove the startup entry: {exc}"


def current_command() -> str | None:
    """The command as it stands in the registry, or None if there is not one."""
    try:
        with winreg.OpenKey(_HKCU, _RUN_KEY) as key:
            value, _type = winreg.QueryValueEx(key, _VALUE_NAME)
            return str(value)
    except OSError:
        return None


def is_registered() -> bool:
    r"""True if a PolyShield value exists under HKCU's Run key.

    Every failure to read reads as "not registered", matching
    ``shell_ext.is_registered`` -- whose docstring records that catching only
    ``FileNotFoundError`` let a ``PermissionError`` from a policy-locked hive
    propagate out of a view constructor and take a whole Settings page down.
    This is called from the same constructor.
    """
    return current_command() is not None


def is_current() -> bool:
    """True if the registered command still points at this installation.

    Worth having specifically because PolyShield is often run from a source
    checkout: the value embeds an absolute path, so renaming or moving the
    folder leaves an entry that fails silently at every login. Windows does not
    report it, and the switch in Settings would otherwise sit there reading ON.
    """
    current = current_command()
    return current is not None and current == _get_command()


def startup_approval() -> str:
    r"""Whether Task Manager has switched this entry off.

    Three states, not two.  ``StartupApproved\Run`` is an implementation detail
    of the Startup tab rather than a documented contract, so an unrecognised
    value degrades to :data:`UNKNOWN` -- never to :data:`DISABLED`.  Telling
    someone their startup entry is switched off because a registry blob changed
    shape in a future Windows build would be worse than admitting we cannot
    tell.

    An absent key or value means the entry has never been touched there, which
    is the normal case and means enabled.

    Never raises.
    """
    try:
        with winreg.OpenKey(_HKCU, _APPROVED_KEY) as key:
            value, value_type = winreg.QueryValueEx(key, _VALUE_NAME)
    except FileNotFoundError:
        return ENABLED
    except OSError:
        return UNKNOWN

    if value_type != winreg.REG_BINARY or not isinstance(value, (bytes, bytearray)):
        return UNKNOWN
    if len(value) < 4:
        return UNKNOWN
    return DISABLED if value[0] & _DISABLED_BIT else ENABLED


#: Status precedence for the Settings row, top-down, first match wins.
#: Deterministic on purpose: an entry can be both stale and switched off, and
#: reporting "path out of date" over a user's explicit "no" would offer a Repair
#: button that fixes something they did not ask about and leaves the entry
#: still not firing.
STATUS_NOT_REGISTERED = "not_registered"
STATUS_USER_DISABLED = "user_disabled"
STATUS_STALE = "stale"
STATUS_OK = "ok"


def status() -> str:
    """One word for what the login entry will actually do."""
    if not is_registered():
        return STATUS_NOT_REGISTERED
    if startup_approval() == DISABLED:
        return STATUS_USER_DISABLED
    if not is_current():
        return STATUS_STALE
    return STATUS_OK
