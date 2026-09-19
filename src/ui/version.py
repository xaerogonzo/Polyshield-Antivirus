"""The product version, in one place.

`installer/polyshield.iss` declares it too -- Inno needs it at compile time and
cannot import Python -- so the two are kept in step by
`tests/test_integration_edges.py` rather than by hope.  Everything on the Python
side reads it from here.

Bumped deliberately, at release, as an act of declaring a release; not as a side
effect of a change that happens to be in flight.
"""

__version__ = "1.16.0"
