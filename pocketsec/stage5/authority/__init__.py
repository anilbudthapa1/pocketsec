"""Stage 5 authority plane: grants, the §5 authority/autonomy tables and capability tokens.

Deliberately empty of code: consumers import the leaf module
(``from pocketsec.stage5.authority.tokens import TokenStore``). A re-export chain here
would widen the surface through which privilege is obtained, which is the one surface
that must stay narrow enough to read.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
