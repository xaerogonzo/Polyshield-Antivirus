"""PolyShield's window capture.

Moved to ``polybedrock.ui.uishot.capture``. **This module *is* that module** —
``tests/test_uishot.py`` does ``from uishot.capture import compare`` and the
alias keeps that working unchanged.
"""
import sys

from polybedrock.ui.uishot import capture as _impl

sys.modules[__name__] = _impl
