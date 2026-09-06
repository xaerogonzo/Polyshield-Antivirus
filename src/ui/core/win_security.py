r"""PolyShield's Windows security-posture probes.

The implementation moved to ``polybedrock.win_security`` (PolyBedrock Stage 1);
PolyScour's dashboard consumes ``get_system_health()`` from the same module.
**This module *is* that module** -- see the note in ``ps_run.py`` for why the
alias is a module replacement rather than a re-export.

It matters more here than anywhere else in the extraction: the score tests
patch ``ws.get_account_policy`` and the probe tests patch ``ws._run_ps``,
``ws._is_elevated`` and ``ws.winreg``, then call ``get_security_score()`` and
expect it to observe those patches. That only holds while the patched object
and the reading object are the same module.
"""
import sys

from polybedrock import win_security as _impl

sys.modules[__name__] = _impl
