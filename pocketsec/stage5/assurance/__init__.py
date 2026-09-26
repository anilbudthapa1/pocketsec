"""Stage 5 assurance: the executor property table and its verification-language guard.

Deliberately empty of code: consumers import the leaf module
(``from pocketsec.stage5.assurance.properties import EXECUTOR_PROPERTIES``). A
re-export chain here would make the one table that records what is *not* proven
reachable under two names, and a claim with two names is a claim nobody audits twice.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
