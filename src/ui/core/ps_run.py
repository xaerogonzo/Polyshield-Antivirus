"""
Shared PowerShell runner.

`defender.py` and `win_security.py` both shell out to PowerShell, and both
carried a byte-for-byte copy of this function across 19 call sites. The
duplication mattered more than duplication usually does, because the shape of
this function is not obvious and is not arbitrary:

`subprocess.run(capture_output=True)` can block indefinitely when a WMI child
process keeps the stdout pipe handle open after `proc.kill()`. That is what
used to hang the Defender and Windows Security views — not slowly, but forever,
on the thread that called them. The fix is the Popen form below, whose drain
after the kill has its own short bound so a child that will not let go costs
three seconds rather than the session.

Two copies of that meant two places to get it subtly wrong, and neither had a
test. `tests/test_ps_run.py` pins the contract and runs against this module and
both wrappers, so the guarantee is checked wherever it is reached from.
"""

import subprocess

_NO_WINDOW = subprocess.CREATE_NO_WINDOW  # 0x08000000 — suppresses console flash

_DEFAULT_TIMEOUT_MESSAGE = "timed out after {timeout}s"

# How long to wait for the pipes to drain after killing a timed-out process.
# Short on purpose: this is the guard against the original hang, not an attempt
# to actually collect the output, which is already lost by this point.
_DRAIN_TIMEOUT = 3


def run_ps(command: str, timeout: int = 20,
           timeout_message: str = _DEFAULT_TIMEOUT_MESSAGE) -> tuple[bool, str]:
    """Run a PowerShell command and return (success, output).

    success is `returncode == 0`; output is stdout, stripped. stderr goes to
    DEVNULL and is *discarded*, so a command that fails with a message on
    stderr and nothing on stdout returns (False, "") — a bare failure with no
    explanation. That is long-standing behaviour, pinned by test rather than
    changed here.

    Nothing raises. Every failure mode — a process that will not start, a
    decode error, a timeout, a child that holds the pipe open past the drain —
    comes back as (False, message), because the callers are view threads that
    treat the result as data.

    timeout_message is a format string taking {timeout}. It exists only to
    preserve the two wordings the two original copies used; no caller matches
    on the text.
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
                proc.communicate(timeout=_DRAIN_TIMEOUT)
            except subprocess.TimeoutExpired:
                pass  # WMI child still holds pipe — OS will clean up
            return False, timeout_message.format(timeout=timeout)
    except Exception as exc:
        return False, str(exc)
