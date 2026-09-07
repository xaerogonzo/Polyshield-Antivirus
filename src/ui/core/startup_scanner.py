r"""PolyShield's view of what runs at startup.

The implementation moved to ``polybedrock.startup`` (PolyScour's Startup
Manager is the second consumer ADR 0003 was waiting for). **This module *is*
that module**: the assignment below replaces this module object in
``sys.modules``, so ``from ui.core import startup_scanner`` yields the shared
module itself.

Aliasing rather than re-exporting, and here it is forced rather than merely
tidy. ``tests/test_integration_edges.py`` does::

    monkeypatch.setattr(ss, "winreg", fake)
    monkeypatch.setattr(ss, "_RUN_KEYS", [...])
    monkeypatch.setattr(ss, "_STARTUP_FOLDERS", [str(folder)])

and expects ``enumerate_startup_items()`` to read all three. A re-export would
bind the function object here while leaving it reading ``polybedrock.startup``'s
globals, so every one of those patches would land on one module while the code
read another -- silently, with the tests passing against the real registry.

Because the alias moves the whole module, ``get_scannable_paths`` travelled with
it. That is a consequence of the module boundary rather than a function that
cleared the extraction gate on its own; ADR 0003 records it that way.
"""
import sys

from polybedrock import startup as _impl

sys.modules[__name__] = _impl
