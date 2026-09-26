"""Stage 5 typed defensive operator algebra, frozen catalog and D3FEND adapter.

Deliberately empty of code: consumers import the leaf module
(``from pocketsec.stage5.operators.catalog import CATALOG``), which is the convention in
every existing runtime module. A re-export chain here would give a second name for the
one object whose identity is the security boundary.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
