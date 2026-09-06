"""PolyShield's hidden-desktop binding.

Moved to ``polybedrock.ui.uishot.desktop`` — PolyScour needs the same harness,
and the module never knew anything about PolyShield. **This module *is* that
module**; see ``src/ui/core/ps_run.py`` for why the alias is a module
replacement rather than a re-export.
"""
import sys

from polybedrock.ui.uishot import desktop as _impl

sys.modules[__name__] = _impl
