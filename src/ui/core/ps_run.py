r"""PolyShield's PowerShell runner.

The implementation moved to ``polybedrock.ps_run`` (PolyBedrock Stage 1) so that
PolyScour does not carry a second copy of it. **This module *is* that module**:
the assignment below replaces this module object in ``sys.modules``, so
``from ui.core import ps_run`` yields the shared module itself.

The replacement is deliberate rather than a re-export. ``test_ps_run.py`` does::

    monkeypatch.setattr(ps_run, "subprocess", shim, raising=False)

and expects ``run_ps()`` to read the patched name. A ``from polybedrock.ps_run
import run_ps`` re-export would bind the function object here while leaving it
reading ``polybedrock.ps_run``'s own globals -- so the patch would land on one
module and the code would read another, silently. Aliasing keeps one module
object, which is what every existing caller and test already assumes.
"""
import sys

from polybedrock import ps_run as _impl

sys.modules[__name__] = _impl
