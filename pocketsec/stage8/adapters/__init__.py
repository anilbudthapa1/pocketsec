"""D8.17 — the Stage 6 (outbound, the one door) and Stage 7 (inbound seeds) adapters.

Deliberately empty: consumers import the leaf module (``adapters.stage6``,
``adapters.stage7``), the house rule for every Stage 8 subsystem package (spec §2.1).
Nothing is re-exported, so the one module that may name Stage 6's gateway stays the only
name for it.
"""

from __future__ import annotations

__all__: list[str] = []
