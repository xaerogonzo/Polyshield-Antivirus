r"""PolyShield's fonts and colour palette.

The implementation moved to ``polybedrock.ui.theme`` (PolyBedrock Stage 1) so that the
Forge applications share one visual language rather than diverging palette by
palette. **This module *is* that module** -- see ``ui/core/ps_run.py`` for why
the alias is a module replacement rather than a re-export. Roughly a dozen views
do ``import ui.theme as theme``; none of them change.

Only one string here was ever product-specific: the "classic" preset is labelled
"Classic PolyShield" in the Display view. ``configure()`` supplies the name, so
PolyShield keeps the exact label it shipped and PolyScour does not inherit it.
"""
import sys

from polybedrock.ui import theme as _impl

_impl.configure("PolyShield")

sys.modules[__name__] = _impl
